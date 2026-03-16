"""
Data443 LLM Gateway - FastAPI Server Entry Point

Main FastAPI application that intercepts LLM API requests,
evaluates security policy, and forwards to target endpoint.
"""

from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import uvicorn

from loguru import logger
import sys

# Configure loguru
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO"
)

from config.settings import settings
from gateway.cache import cache
from gateway.audit import audit_logger
from gateway.cyren_client import cyren_client
from gateway.policy import init_policy_engine
from gateway.proxy import init_proxy_handler, ProxyHandler


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Data443 LLM Gateway...")

    # Connect to cache
    await cache.connect()

    # Connect to audit logger
    await audit_logger.connect()

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


@app.get("/health")
async def health_check(request: Request) -> Dict[str, Any]:
    """
    Health check endpoint.

    Returns gateway status and component health.
    """
    proxy_handler = request.app.state.proxy_handler
    return await proxy_handler.health_check()


@app.get("/")
async def root() -> Dict[str, Any]:
    """Root endpoint with gateway information."""
    return {
        "name": "Data443 LLM Security Gateway",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "proxy": "/{path}",
            "audit": "/audit/log",
        }
    }


@app.get("/audit/log")
async def get_audit_log(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    decision: str = None,
    ip: str = None,
) -> JSONResponse:
    """
    Query the audit log.

    Query parameters:
    - limit: Number of entries to return (default: 100)
    - offset: Offset for pagination (default: 0)
    - decision: Filter by decision type (ALLOW, BLOCK, CONSTRAIN)
    - ip: Filter by IP address
    """
    from gateway.audit import Decision

    decision_filter = Decision[decision] if decision else None
    logs = await audit_logger.query_audit_log(
        limit=limit,
        offset=offset,
        decision=decision_filter,
        ip_address=ip,
    )

    return JSONResponse(content={
        "total": len(logs),
        "limit": limit,
        "offset": offset,
        "logs": logs
    })


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(request: Request, path: str) -> Response:
    """
    Proxy all requests to the target LLM endpoint.

    This is the main entry point for all LLM API requests.
    """
    proxy_handler = request.app.state.proxy_handler

    try:
        return await proxy_handler.handle_request(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error handling request: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


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
    """Run the server."""
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
