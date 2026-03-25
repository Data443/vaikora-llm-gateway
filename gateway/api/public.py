"""
Public API routes for the Data443 LLM Gateway.
"""

from typing import Dict, Any, Optional

from fastapi import APIRouter, Request, Response, HTTPException, status, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from loguru import logger

from gateway.core.types import Decision
from gateway.api.auth import require_admin_auth
from gateway.integrations.audit import audit_logger
from gateway.integrations.telemetry import telemetry_metrics


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
            "events": "/audit/events",
            "metrics": "/audit/metrics",
        },
    }


@public_router.get("/audit/log")
async def get_audit_log(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    decision: Optional[str] = None,
    ip: Optional[str] = None,
) -> JSONResponse:
    """
    Query audit log.

    Query parameters:
    - limit: Number of entries to return (default: 100)
    - offset: Offset for pagination (default: 0)
    - decision: Filter by decision type (ALLOW, BLOCK, CONSTRAIN)
    - ip: Filter by IP address
    """
    await require_admin_auth(request)

    decision_filter = None
    if decision:
        try:
            decision_filter = Decision[decision.upper()]
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid decision value: {decision}",
            ) from exc
    logs = await audit_logger.query_audit_log(
        limit=limit,
        offset=offset,
        decision=decision_filter,
        ip_address=ip,
    )

    return JSONResponse(content=jsonable_encoder({
        "total": len(logs),
        "limit": limit,
        "offset": offset,
        "logs": logs,
    }))


@public_router.get("/audit/events")
async def get_gateway_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    decision: Optional[str] = None,
    request_id: Optional[str] = None,
) -> JSONResponse:
    """
    Query structured gateway event stream.

    Query parameters:
    - limit: Number of entries to return (default: 100)
    - offset: Offset for pagination (default: 0)
    - decision: Filter by decision value
    - request_id: Filter by request id
    """
    await require_admin_auth(request)

    events = await audit_logger.query_gateway_events(
        limit=limit,
        offset=offset,
        decision=decision,
        request_id=request_id,
    )
    return JSONResponse(content=jsonable_encoder({
        "total": len(events),
        "limit": limit,
        "offset": offset,
        "events": events,
    }))


@public_router.get("/audit/metrics")
async def get_gateway_metrics(request: Request) -> JSONResponse:
    """Get process-local telemetry counters and latency aggregates."""
    await require_admin_auth(request)
    return JSONResponse(content=jsonable_encoder({
        "success": True,
        "message": "Gateway telemetry metrics",
        "metrics": telemetry_metrics.snapshot(),
    }))


@public_router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
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
