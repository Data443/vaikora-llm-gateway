"""Admin API authentication dependencies."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

from gateway.core.config import settings


async def require_admin_auth(request: Request) -> None:
    """
    Validate optional admin API authentication.

    When `ADMIN_AUTH_ENABLED=false`, admin routes remain open (current default).
    When enabled, requests must provide `x-admin-key` matching `ADMIN_API_KEY`.
    """
    if not settings.admin_auth_enabled:
        return

    expected = settings.admin_api_key.strip()
    provided = request.headers.get("x-admin-key", "").strip()

    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin auth is enabled but ADMIN_API_KEY is not configured",
        )

    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API key",
        )
