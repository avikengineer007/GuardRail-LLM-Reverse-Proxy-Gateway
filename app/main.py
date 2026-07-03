import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
import httpx

from app.config import load_config
from app.proxy import router as proxy_router, init_proxy
from app.metrics import metrics_app

# Base logger setup for application general outputs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardrail.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    logger.info("Initializing GuardRail-LLM Reverse Proxy...")
    config = load_config()
    
    # Configure high-throughput, low-latency connection pool
    limits = httpx.Limits(
        max_keepalive_connections=200,
        max_connections=1000,
        keepalive_expiry=30.0
    )
    # Using async client to proxy requests efficiently
    client = httpx.AsyncClient(limits=limits, timeout=60.0)
    
    # Pass dependencies to proxy state
    init_proxy(config, client)
    logger.info(f"GuardRail-LLM initialized successfully. Target Upstream: {config.server.upstream_url}")
    
    yield
    
    # --- Shutdown ---
    logger.info("Shutting down GuardRail-LLM, closing connections...")
    await client.aclose()
    logger.info("GuardRail-LLM shutdown complete.")

# Initialize the core FastAPI Application
app = FastAPI(
    title="GuardRail-LLM Reverse Proxy Gateway",
    description="High-performance security proxy shielding LLMs from Prompt Injection and Data Exfiltration",
    version="1.0.0",
    lifespan=lifespan
)

# Mount Prometheus ASGI handler to expose standard metrics
app.mount("/metrics", metrics_app)

# Include the Reverse Proxy Router (catch-all)
app.include_router(proxy_router)
