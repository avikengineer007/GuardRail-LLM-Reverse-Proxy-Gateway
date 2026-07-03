# GuardRail-LLM Reverse Proxy Gateway

**GuardRail-LLM** is a high-performance security reverse proxy gateway designed to shield Large Language Models (LLMs) from Prompt Injection (inbound) and Data Exfiltration/Sensitive Data Leakage (outbound). 

It intercepts requests to upstream LLMs (such as OpenAI, Anthropic, or Hugging Face), applies real-time inbound & outbound inspection rules, and handles both standard and streaming server-sent events (SSE) dynamically.

---

## Features

### 🛡️ Inbound Inspection (Prompt Injection Protection)
- **Heuristic Scanning**: Pre-compiled regex patterns scoring prompt inputs (e.g. system override attempts, DAN-style role-plays).
- **Semantic Vector Scanning**: Uses local SentenceTransformers (`all-MiniLM-L6-v2`) to compare prompts against known jailbreak vectors with cosine similarity.
- **Auto Fallback**: Gracefully falls back to a Jaccard token-similarity scanner if hardware resources prevent loading PyTorch/Transformers.

### 🔒 Outbound Inspection (Exfiltration & Leakage Protection)
- **Regex PII / API Scan**: High-performance detection & mitigation of standard PII, including SSNs, credit cards, AWS keys, OpenAI keys, and generic credential strings.
- **Shannon Entropy Scanner**: Automatically detects random or high-entropy tokens (e.g. database passwords, API tokens, hashed keys).
- **Streaming Redaction Buffer**: Custom sliding-window queue (`N = 150` characters) that safely buffers stream deltas to check and redact tokens *before* they are output to the user, avoiding any leakage of partial prefixes.
- **Action Modes**: 
  - `redact`: Masks matches on-the-fly with placeholders (e.g., `[REDACTED_OPENAI_KEY]`).
  - `block`: Immediately aborts the request and returns a `403 Forbidden` response (or injects an SSE error chunk mid-stream).

### 📊 Security Auditing & Metrics
- **Prometheus Metrics**: Exposes ASGI-compatible `/metrics` endpoint with counts for requests, security blocks, exfiltration events, and latency tracking.
- **Structured JSON Logging**: Logs audit-trail JSON events representing system operations and blocked security alerts.

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- `pip` package manager

### 1. Clone the Repository
```bash
git clone https://github.com/avikengineer007/GuardRail-LLM-Reverse-Proxy-Gateway.git
cd GuardRail-LLM-Reverse-Proxy-Gateway
```

### 2. Install Dependencies
Install all required gateway dependencies:
```bash
pip install fastapi uvicorn PyYAML httpx prometheus_client sentence-transformers torch
```

---

## Configuration

The system is configured using `config.yaml`. The key parameters are:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  upstream_url: "https://api.openai.com" # Upstream LLM Provider

inbound_inspection:
  enabled: true
  heuristic_rules:
    threshold_score: 1.0
  semantic_inspection:
    enabled: true
    threshold_similarity: 0.78
    model_name: "all-MiniLM-L6-v2"

outbound_inspection:
  enabled: true
  action: "redact" # "redact" or "block"
  entropy_scanner:
    enabled: true
    min_length: 20
    entropy_threshold: 4.5
```

---

## Testing & Verification

We supply comprehensive unit and integration suites to verify the proxy.

### 1. Run Unit Tests (Local)
Validates interceptor engines in isolation:
```bash
python -m pytest
```

### 2. Run Adversarial Integration Tests
Spins up a mock upstream host, launches the proxy, and runs client request flows simulating both prompt injection and secret leaking:
```bash
python tests/run_adversarial_tests.py
```

### 3. Run Live Request Test (OpenAI)
Start the proxy in one terminal:
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
```
In a new terminal window, configure your API key and query the live gateway:
```bash
$env:OPENAI_API_KEY="your-real-openai-key-here"
python test_live.py
```