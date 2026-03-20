"""
Public API routes for the Data443 LLM Gateway.
"""

from typing import Dict, Any

from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from loguru import logger

from gateway.core.types import Decision
from gateway.integrations.audit import audit_logger


public_router = APIRouter()


@public_router.get("/health")
async def health_check(request: Request) -> Dict[str, Any]:
    """
    Health check endpoint.

    Returns gateway status and component health.
    """
    proxy_handler = request.app.state.proxy_handler
    return await proxy_handler.health_check()


@public_router.get("/")
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
        },
    }


@public_router.get("/audit/log")
async def get_audit_log(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    decision: str = None,
    ip: str = None,
) -> JSONResponse:
    """
    Query audit log.

    Query parameters:
    - limit: Number of entries to return (default: 100)
    - offset: Offset for pagination (default: 0)
    - decision: Filter by decision type (ALLOW, BLOCK, CONSTRAIN)
    - ip: Filter by IP address
    """
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
        "logs": logs,
    })


@public_router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(request: Request, path: str) -> Response:
    """
    Proxy all requests to target LLM endpoint.

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
            detail="Internal server error",
        )
