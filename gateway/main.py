"""
Data443 LLM Gateway - FastAPI Server Entry Point

Main FastAPI application that intercepts LLM API requests,
evaluates security policy, and forwards to target endpoint.
"""

import asyncio
from contextlib import asynccontextmanager
from contextlib import suppress
from typing import List

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from gateway.api.admin import get_admin_router
from gateway.api.agent_control import agent_control_router
from gateway.api.public import public_router
from gateway.core.config import settings
from gateway.core.logging import configure_logging
from gateway.core.startup_validation import validate_startup_settings
from gateway.integrations.audit import audit_logger
from gateway.integrations.cache import cache
from gateway.integrations.cyren_client import cyren_client
from gateway.integrations.otel import initialize_otel, shutdown_otel
from gateway.middleware.rate_limit import RateLimitMiddleware
from gateway.policy.store import policy_store
from gateway.services.agent_registry import agent_registry
from gateway.services.policy_service import init_policy_engine
from gateway.services.proxy_service import init_proxy_handler
from gateway.integrations.control_plane import control_plane_client


class RequestBodyLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured maximum."""

    async def dispatch(self, request: Request, call_next):
        max_bytes = settings.max_request_body_bytes
        if max_bytes and max_bytes > 0:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > max_bytes:
                return StarletteResponse(
                    content='{"error":{"message":"Request body too large","type":"request_too_large","code":"body_limit_exceeded"}}',
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    media_type="application/json",
                )
        return await call_next(request)


async def _retention_purge_loop(stop_event: asyncio.Event) -> None:
    """Periodic retention purge task."""
    interval = max(60, int(settings.audit_purge_interval_seconds))
    while not stop_event.is_set():
        try:
            await audit_logger.purge_expired_records()
        except Exception as exc:
            logger.warning(f"Retention purge loop error: {exc}")

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Data443 LLM Gateway...")
    validate_startup_settings(strict=settings.strict_startup_validation)

    # Initialize OpenTelemetry hooks (optional)
    initialize_otel()

    # Connect to cache
    await cache.connect()

    # Connect to audit logger
    await audit_logger.connect()

    retention_stop_event: asyncio.Event | None = None
    retention_task: asyncio.Task | None = None
    if settings.audit_purge_enabled:
        retention_stop_event = asyncio.Event()
        await audit_logger.purge_expired_records()
        retention_task = asyncio.create_task(_retention_purge_loop(retention_stop_event))
        app.state.retention_stop_event = retention_stop_event
        app.state.retention_task = retention_task

    # Initialize persistent policy/entitlement cache
    await policy_store.initialize(audit_logger)
    await agent_registry.initialize(audit_logger)

    # Initialize policy engine
    policy_engine = init_policy_engine(cyren_client, audit_logger)

    # Initialize proxy handler
    proxy_handler = init_proxy_handler(policy_engine)

    # Store in app state
    app.state.proxy_handler = proxy_handler

    # Start control plane integration (policy sync, audit federation, HITL)
    if audit_logger.pool:
        control_plane_client.set_db_pool(audit_logger.pool)
    await control_plane_client.start()

    logger.info("Data443 LLM Gateway started successfully")

    yield

    # Cleanup
    logger.info("Shutting down Data443 LLM Gateway...")
    retention_stop_event = getattr(app.state, "retention_stop_event", None)
    retention_task = getattr(app.state, "retention_task", None)
    if retention_stop_event is not None:
        retention_stop_event.set()
    if retention_task is not None:
        retention_task.cancel()
        with suppress(asyncio.CancelledError):
            await retention_task
    await control_plane_client.stop()
    if proxy_handler is not None:
        await proxy_handler.close()
    await cache.disconnect()
    await audit_logger.disconnect()
    shutdown_otel()
    logger.info("Shutdown complete")


configure_logging(settings.log_level, settings.log_format)


def _split_csv(value: str) -> List[str]:
    """Split comma-separated configuration into a normalized list."""
    return [item.strip() for item in value.split(",") if item.strip()]


# Create FastAPI app
app = FastAPI(
    title="Data443 LLM Security Gateway",
    description="Reverse proxy security gateway for LLM endpoints with Cyren threat intelligence",
    version="1.0.0",
    lifespan=lifespan,
)

# Add middleware
cors_origins = _split_csv(settings.cors_allowed_origins)
cors_methods = _split_csv(settings.cors_allowed_methods)
cors_headers = _split_csv(settings.cors_allowed_headers)
cors_allow_credentials = settings.cors_allow_credentials

# Browsers reject wildcard origins with credentials, so force-safe behavior.
if cors_allow_credentials and "*" in cors_origins:
    logger.warning(
        "CORS misconfiguration detected: CORS_ALLOW_CREDENTIALS=true with wildcard origin; "
        "forcing allow_credentials=false"
    )
    cors_allow_credentials = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["http://localhost", "http://127.0.0.1"],
    allow_credentials=cors_allow_credentials,
    allow_methods=cors_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=cors_headers or ["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(RateLimitMiddleware)

# Include API routers
admin_router = get_admin_router()
app.include_router(admin_router)
app.include_router(agent_control_router)
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
        },
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
