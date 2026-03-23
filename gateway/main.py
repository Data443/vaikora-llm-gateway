"""
Data443 LLM Gateway - FastAPI Server Entry Point

Main FastAPI application that intercepts LLM API requests,
evaluates security policy, and forwards to target endpoint.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import uvicorn

from loguru import logger

from gateway.core.config import settings
from gateway.core.logging import configure_logging
from gateway.integrations.cache import cache
from gateway.integrations.audit import audit_logger
from gateway.integrations.cyren_client import cyren_client
from gateway.policy.store import policy_store
from gateway.services.policy_service import init_policy_engine
from gateway.services.proxy_service import init_proxy_handler
from gateway.api.admin import get_admin_router
from gateway.api.public import public_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Data443 LLM Gateway...")

    # Connect to cache
    await cache.connect()

    # Connect to audit logger
    await audit_logger.connect()

    # Initialize persistent policy/entitlement cache
    await policy_store.initialize(audit_logger)

    # Initialize policy engine
    policy_engine = init_policy_engine(cyren_client, audit_logger)

    # Initialize proxy handler
    proxy_handler = init_proxy_handler(policy_engine)

    # Store in app state
    app.state.proxy_handler = proxy_handler

    logger.info("Data443 LLM Gateway started successfully")

    yield

    # Cleanup
    logger.info("Shutting down Data443 LLM Gateway...")
    await cache.disconnect()
    await audit_logger.disconnect()
    logger.info("Shutdown complete")


configure_logging(settings.log_level)

# Create FastAPI app
app = FastAPI(
    title="Data443 LLM Security Gateway",
    description="Reverse proxy security gateway for LLM endpoints with Cyren threat intelligence",
    version="1.0.0",
    lifespan=lifespan,
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include API routers
admin_router = get_admin_router()
app.include_router(admin_router)
app.include_router(public_router)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.detail,
                "type": "http_error",
                "code": exc.status_code,
            }
        }
    )


def main():
    """Run server."""
    logger.info(f"Starting Data443 LLM Gateway on {settings.host}:{settings.port}")
    uvicorn.run(
        "gateway.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()

