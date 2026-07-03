import time
import uuid
import json
import logging
from typing import AsyncGenerator, Dict, Any, Tuple, List
from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse, JSONResponse
import httpx

from app.config import AppConfig
from app.interceptors.inbound import InboundInterceptor
from app.interceptors.outbound import OutboundInterceptor
from app.metrics import (
    GUARDRAIL_REQUESTS_TOTAL,
    GUARDRAIL_ATTACKS_TOTAL,
    GUARDRAIL_LATENCY_SECONDS,
    log_security_event
)

logger = logging.getLogger("guardrail.proxy")
router = APIRouter()

# Global proxy state initialized in main
inbound_interceptor: InboundInterceptor = None
outbound_interceptor: OutboundInterceptor = None
app_config: AppConfig = None
http_client: httpx.AsyncClient = None

def init_proxy(config: AppConfig, client: httpx.AsyncClient):
    global inbound_interceptor, outbound_interceptor, app_config, http_client
    app_config = config
    http_client = client
    inbound_interceptor = InboundInterceptor(config)
    outbound_interceptor = OutboundInterceptor(config)

def extract_prompt_from_body(body_bytes: bytes) -> str:
    """Extract human prompt content from various JSON formats."""
    if not body_bytes:
        return ""
    try:
        data = json.loads(body_bytes.decode("utf-8", errors="ignore"))
        
        # OpenAI / Anthropic messages list
        if "messages" in data and isinstance(data["messages"], list):
            contents = []
            for msg in data["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    content = msg["content"]
                    if isinstance(content, str):
                        contents.append(content)
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "text":
                                contents.append(part.get("text", ""))
            return "\n".join(contents)
            
        # Legacy/direct prompt field
        if "prompt" in data and isinstance(data["prompt"], str):
            return data["prompt"]
            
        # Fallback to scanning everything as string
        return json.dumps(data)
    except Exception:
        # Fallback to raw string decode
        return body_bytes.decode("utf-8", errors="ignore")

def check_if_streaming_request(body_bytes: bytes) -> bool:
    """Check if request asks for streaming."""
    try:
        data = json.loads(body_bytes.decode("utf-8", errors="ignore"))
        return bool(data.get("stream", False))
    except Exception:
        return False

def find_matches(text: str, outbound_interceptor) -> List[Tuple[int, int]]:
    matches = []
    if not text or not outbound_interceptor or not outbound_interceptor.enabled:
        return matches
        
    # 1. Regex rules
    for rule in outbound_interceptor.rules:
        for match in rule["pattern"].finditer(text):
            matches.append((match.start(), match.end()))
            
    # 2. Entropy scanner
    if outbound_interceptor.entropy_enabled:
        for match in outbound_interceptor.token_extractor.finditer(text):
            candidate = match.group()
            if len(candidate) >= outbound_interceptor.min_length:
                # Check if placeholder
                is_placeholder = False
                for rule in outbound_interceptor.rules:
                    if rule["placeholder"] in candidate or candidate in rule["placeholder"]:
                        is_placeholder = True
                        break
                if is_placeholder:
                    continue
                if outbound_interceptor.calculate_entropy(candidate) >= outbound_interceptor.entropy_threshold:
                    matches.append((match.start(), match.end()))
    return matches

async def process_stream(
    response_stream: httpx.Response,
    correlation_id: str,
    method: str,
    path: str,
    start_time: float
) -> AsyncGenerator[bytes, None]:
    """
    Process streaming SSE chunks, buffer them to handle token splits,
    apply redaction or block, and output clean SSE lines.
    """
    original_buffer = ""
    sent_redacted_len = 0
    triggered_rules_accum = set()
    line_buffer = b""
    received_chunks = []
    N = 150

    async def release_safe_chunks(is_final: bool = False) -> AsyncGenerator[bytes, None]:
        nonlocal sent_redacted_len, original_buffer
        if not received_chunks:
            return

        if is_final:
            chunks_to_release = list(received_chunks)
            received_chunks.clear()
        else:
            matches = find_matches(original_buffer, outbound_interceptor)
            target_send_len = max(0, len(original_buffer) - N)
            safe_len = target_send_len
            for start, end in matches:
                if end > safe_len and start < safe_len:
                    safe_len = start
            
            chunks_to_release = []
            while received_chunks and received_chunks[0]["abs_end"] <= safe_len:
                chunks_to_release.append(received_chunks.pop(0))

        if chunks_to_release:
            L_orig = chunks_to_release[-1]["abs_end"]
            redacted_prefix, is_blocked, triggered = outbound_interceptor.inspect_and_process(original_buffer[:L_orig])
            
            if is_blocked:
                latency = (time.perf_counter() - start_time) * 1000
                log_security_event(
                    correlation_id=correlation_id,
                    method=method,
                    endpoint=path,
                    latency_ms=latency,
                    verdict="block",
                    triggered_rules=triggered
                )
                GUARDRAIL_REQUESTS_TOTAL.labels(method=method, endpoint=path, verdict="block_outbound").inc()
                for rule in triggered:
                    GUARDRAIL_ATTACKS_TOTAL.labels(type="data_exfiltration", rule_name=rule).inc()

                err_resp = {
                    "error": {
                        "message": "Stream blocked by GuardRail-LLM security policy.",
                        "type": "guardrail_security_block",
                        "code": 403,
                        "correlation_id": correlation_id
                    }
                }
                yield f"data: {json.dumps(err_resp)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"
                raise RuntimeError("blocked")

            if triggered:
                triggered_rules_accum.update(triggered)

            new_redacted_text = redacted_prefix[sent_redacted_len:]
            sent_redacted_len = len(redacted_prefix)

            first_chunk = chunks_to_release[0]
            curr = first_chunk["data_json"]
            for key in first_chunk["path_to_replace"][:-1]:
                curr = curr[key]
            curr[first_chunk["path_to_replace"][-1]] = new_redacted_text
            yield f"data: {json.dumps(first_chunk['data_json'])}\n\n".encode("utf-8")

            for chunk in chunks_to_release[1:]:
                curr = chunk["data_json"]
                for key in chunk["path_to_replace"][:-1]:
                    curr = curr[key]
                curr[chunk["path_to_replace"][-1]] = ""
                yield f"data: {json.dumps(chunk['data_json'])}\n\n".encode("utf-8")

    try:
        async for chunk in response_stream.aiter_bytes():
            line_buffer += chunk
            while b"\n" in line_buffer:
                line, line_buffer = line_buffer.split(b"\n", 1)
                line_str = line.decode("utf-8", errors="ignore").strip()

                if not line_str:
                    yield line + b"\n"
                    continue

                if line_str.startswith("data:"):
                    data_content = line_str[5:].strip()
                    if data_content == "[DONE]":
                        try:
                            async for val in release_safe_chunks(is_final=True):
                                yield val
                        except RuntimeError as e:
                            if str(e) == "blocked":
                                return
                        yield line + b"\n"
                        continue

                    try:
                        data_json = json.loads(data_content)
                        delta_text = None
                        path_to_replace = None

                        if "choices" in data_json and isinstance(data_json["choices"], list) and len(data_json["choices"]) > 0:
                            choice = data_json["choices"][0]
                            if "delta" in choice and "content" in choice["delta"]:
                                delta_text = choice["delta"]["content"]
                                path_to_replace = ["choices", 0, "delta", "content"]
                            elif "text" in choice:
                                delta_text = choice["text"]
                                path_to_replace = ["choices", 0, "text"]

                        elif "delta" in data_json and isinstance(data_json["delta"], dict) and "text" in data_json["delta"]:
                            delta_text = data_json["delta"]["text"]
                            path_to_replace = ["delta", "text"]
                        elif "content_block" in data_json and isinstance(data_json["content_block"], dict) and "text" in data_json["content_block"]:
                            delta_text = data_json["content_block"]["text"]
                            path_to_replace = ["content_block", "text"]

                        if delta_text is not None and path_to_replace:
                            original_buffer += delta_text
                            received_chunks.append({
                                "data_json": data_json,
                                "path_to_replace": path_to_replace,
                                "abs_end": len(original_buffer)
                            })
                            try:
                                async for val in release_safe_chunks(is_final=False):
                                    yield val
                            except RuntimeError as e:
                                if str(e) == "blocked":
                                    return
                        else:
                            yield line + b"\n"
                    except Exception:
                        yield line + b"\n"
                else:
                    yield line + b"\n"

        try:
            async for val in release_safe_chunks(is_final=True):
                yield val
        except RuntimeError as e:
            if str(e) == "blocked":
                return

    except Exception as e:
        logger.error(f"Error during streaming response proxying: {e}")
        yield b"data: {\"error\": \"Internal proxy streaming error\"}\n\n"
        return

    latency = (time.perf_counter() - start_time) * 1000
    verdict = "redact" if triggered_rules_accum else "allow"
    
    log_security_event(
        correlation_id=correlation_id,
        method=method,
        endpoint=path,
        latency_ms=latency,
        verdict=verdict,
        triggered_rules=list(triggered_rules_accum)
    )
    GUARDRAIL_REQUESTS_TOTAL.labels(method=method, endpoint=path, verdict=verdict).inc()
    GUARDRAIL_LATENCY_SECONDS.labels(endpoint=path, verdict=verdict).observe(latency / 1000)
    for rule in triggered_rules_accum:
        GUARDRAIL_ATTACKS_TOTAL.labels(type="data_exfiltration", rule_name=rule).inc()


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def proxy_request(request: Request, path: str):
    """General catch-all reverse proxy handler."""
    correlation_id = str(uuid.uuid4())
    start_time = time.perf_counter()
    method = request.method
    
    # 1. Capture and clone request body
    body_bytes = await request.body()
    
    # 2. Module A: Inbound Inspection (Prompt Injection Check)
    if method in ["POST", "PUT", "PATCH"]:
        prompt = extract_prompt_from_body(body_bytes)
        if prompt:
            is_blocked, score, triggered_rules = inbound_interceptor.inspect(prompt)
            if is_blocked:
                latency = (time.perf_counter() - start_time) * 1000
                
                # Structured JSON Audit Log
                log_security_event(
                    correlation_id=correlation_id,
                    method=method,
                    endpoint=f"/{path}",
                    latency_ms=latency,
                    verdict="block",
                    triggered_rules=triggered_rules,
                    details={"prompt_preview": prompt[:150] + "..." if len(prompt) > 150 else prompt, "score": score}
                )
                
                # Update Metrics
                GUARDRAIL_REQUESTS_TOTAL.labels(method=method, endpoint=f"/{path}", verdict="block_inbound").inc()
                GUARDRAIL_LATENCY_SECONDS.labels(endpoint=f"/{path}", verdict="block_inbound").observe(latency / 1000)
                for rule in triggered_rules:
                    GUARDRAIL_ATTACKS_TOTAL.labels(type="prompt_injection", rule_name=rule).inc()
                
                # Return standard 403
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": "Request blocked by GuardRail-LLM security policy due to prompt safety violations.",
                            "type": "guardrail_security_block",
                            "code": 403,
                            "correlation_id": correlation_id,
                            "triggered_rules": triggered_rules
                        }
                    }
                )

    # 3. Request Forwarding to Upstream
    upstream_target = f"{app_config.server.upstream_url}/{path}"
    
    # Copy headers, excluding Host header to prevent signature mismatches or SSL host issues
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length"]}
    params = dict(request.query_params)

    # Send client request to upstream LLM
    try:
        # Build proxy request
        proxy_req = http_client.build_request(
            method=method,
            url=upstream_target,
            headers=headers,
            params=params,
            content=body_bytes
        )
        
        # Check if streaming response is expected
        is_stream = check_if_streaming_request(body_bytes) or "text/event-stream" in headers.get("accept", "")
        
        if is_stream:
            upstream_resp = await http_client.send(proxy_req, stream=True)
            # Return streaming response
            return StreamingResponse(
                process_stream(upstream_resp, correlation_id, method, f"/{path}", start_time),
                status_code=upstream_resp.status_code,
                headers={k: v for k, v in upstream_resp.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding", "content-length"]}
            )
        else:
            upstream_resp = await http_client.send(proxy_req)
            resp_bytes = await upstream_resp.aread()
            
            # Module B: Outbound Exfiltration Check (Non-streaming)
            resp_content_type = upstream_resp.headers.get("content-type", "")
            
            # Perform deep outbound scanning only if response looks like text/json
            if "application/json" in resp_content_type or "text/" in resp_content_type:
                resp_text = resp_bytes.decode("utf-8", errors="ignore")
                
                # Extract clean assistant response if possible, else inspect entire content
                assistant_text = ""
                path_to_replace = None
                try:
                    data_json = json.loads(resp_text)
                    if "choices" in data_json and isinstance(data_json["choices"], list) and len(data_json["choices"]) > 0:
                        choice = data_json["choices"][0]
                        if "message" in choice and "content" in choice["message"] and isinstance(choice["message"]["content"], str):
                            assistant_text = choice["message"]["content"]
                            path_to_replace = ["choices", 0, "message", "content"]
                    elif "content" in data_json and isinstance(data_json["content"], list):
                        # Anthropic non-streaming structure
                        for part in data_json["content"]:
                            if isinstance(part, dict) and part.get("type") == "text":
                                assistant_text = part.get("text", "")
                                path_to_replace = ["content", data_json["content"].index(part), "text"]
                                break
                except Exception:
                    pass
                
                # If we parsed structured content, check that. Otherwise, inspect the whole response string.
                text_to_scan = assistant_text if assistant_text else resp_text
                
                redacted_scan, is_blocked, triggered = outbound_interceptor.inspect_and_process(text_to_scan)
                
                if is_blocked:
                    latency = (time.perf_counter() - start_time) * 1000
                    log_security_event(
                        correlation_id=correlation_id,
                        method=method,
                        endpoint=f"/{path}",
                        latency_ms=latency,
                        verdict="block",
                        triggered_rules=triggered
                    )
                    GUARDRAIL_REQUESTS_TOTAL.labels(method=method, endpoint=f"/{path}", verdict="block_outbound").inc()
                    GUARDRAIL_LATENCY_SECONDS.labels(endpoint=f"/{path}", verdict="block_outbound").observe(latency / 1000)
                    for rule in triggered:
                        GUARDRAIL_ATTACKS_TOTAL.labels(type="data_exfiltration", rule_name=rule).inc()
                        
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": {
                                "message": "Response blocked by GuardRail-LLM security policy due to sensitive data leakage.",
                                "type": "guardrail_security_block",
                                "code": 403,
                                "correlation_id": correlation_id,
                                "triggered_rules": triggered
                            }
                        }
                    )
                
                if triggered:
                    # Redaction mode
                    if path_to_replace:
                        # Put back redacted assistant text
                        data_json = json.loads(resp_text)
                        curr = data_json
                        for key in path_to_replace[:-1]:
                            curr = curr[key]
                        curr[path_to_replace[-1]] = redacted_scan
                        resp_bytes = json.dumps(data_json).encode("utf-8")
                    else:
                        resp_bytes = redacted_scan.encode("utf-8")
                        
                verdict = "redact" if triggered else "allow"
            else:
                verdict = "allow"
                triggered = []
                
            latency = (time.perf_counter() - start_time) * 1000
            
            # Log final response events
            log_security_event(
                correlation_id=correlation_id,
                method=method,
                endpoint=f"/{path}",
                latency_ms=latency,
                verdict=verdict,
                triggered_rules=triggered
            )
            
            GUARDRAIL_REQUESTS_TOTAL.labels(method=method, endpoint=f"/{path}", verdict=verdict).inc()
            GUARDRAIL_LATENCY_SECONDS.labels(endpoint=f"/{path}", verdict=verdict).observe(latency / 1000)
            for rule in triggered:
                GUARDRAIL_ATTACKS_TOTAL.labels(type="data_exfiltration", rule_name=rule).inc()
                
            return Response(
                content=resp_bytes,
                status_code=upstream_resp.status_code,
                headers={k: v for k, v in upstream_resp.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding", "content-length"]}
            )
            
    except httpx.RequestError as exc:
        logger.error(f"Error occurred while forwarding request to upstream: {exc}")
        return JSONResponse(
            status_code=502,
            content={"error": f"Bad Gateway: Failed to connect to upstream server: {exc}"}
        )
