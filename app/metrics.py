import json
import time
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from prometheus_client import Counter, Histogram, make_asgi_app

# Structured JSON Logger Setup
logger = logging.getLogger("guardrail.security")
logger.setLevel(logging.INFO)

# Avoid adding duplicate handlers if re-imported
if not logger.handlers:
    stream_handler = logging.StreamHandler()
    
    # Custom Formatter to write clean JSON logs
    class JSONFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            # We construct a custom JSON payload
            log_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage()
            }
            if hasattr(record, "security_event"):
                log_record.update(record.security_event)
            return json.dumps(log_record)

    stream_handler.setFormatter(JSONFormatter())
    logger.addHandler(stream_handler)


# Prometheus Metrics Definition
GUARDRAIL_REQUESTS_TOTAL = Counter(
    "guardrail_requests_total",
    "Total number of intercepted/proxied requests.",
    labelnames=["method", "endpoint", "verdict"]
)

GUARDRAIL_ATTACKS_TOTAL = Counter(
    "guardrail_attacks_total",
    "Total number of intercepted security events by threat type.",
    labelnames=["type", "rule_name"]
)

GUARDRAIL_LATENCY_SECONDS = Histogram(
    "guardrail_latency_seconds",
    "Latencies of LLM proxy requests in seconds.",
    labelnames=["endpoint", "verdict"],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf")]
)

def log_security_event(
    correlation_id: str,
    method: str,
    endpoint: str,
    latency_ms: float,
    verdict: str,
    triggered_rules: List[str],
    details: Optional[Dict[str, Any]] = None
):
    """Log a structured JSON security alert for security auditing and compliance."""
    event = {
        "correlation_id": correlation_id,
        "method": method,
        "endpoint": endpoint,
        "latency_ms": latency_ms,
        "verdict": verdict,
        "triggered_rules": triggered_rules,
        "details": details or {}
    }
    logger.info(
        f"GuardRail Security Event: {verdict} for {method} {endpoint}",
        extra={"security_event": event}
    )

# Expose asgi middleware compatible application for prometheus exposition
metrics_app = make_asgi_app()
