"""Admin API authentication dependencies."""

from __future__ import annotations

import hmac
import ipaddress
from typing import Iterable

from fastapi import HTTPException, Request, status

from gateway.core.config import settings
from gateway.services.jwt_auth import JWTAuth, get_current_user_from_request


_VALID_ADMIN_AUTH_MODES = {"api_key", "jwt", "api_key_or_jwt"}


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _extract_client_ip(request: Request) -> str:
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "").strip()
        if forwarded:
            return forwarded.split(",")[0].strip() or "unknown"
        real_ip = request.headers.get("x-real-ip", "").strip()
        if real_ip:
            return real_ip
        cf_ip = request.headers.get("cf-connecting-ip", "").strip()
        if cf_ip:
            return cf_ip

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _ip_in_allowlist(client_ip: str, allow_entries: Iterable[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        # Unknown or malformed client IP; fall back to exact string comparison.
        return client_ip in set(allow_entries)

    for entry in allow_entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if ip_obj in network:
                return True
        except ValueError:
            # Treat plain values as exact-match fallback.
            if client_ip == entry:
                return True
    return False


def _validate_admin_api_key(request: Request) -> bool:
    expected = settings.admin_api_key.strip()
    provided = request.headers.get("x-admin-key", "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin auth is enabled but ADMIN_API_KEY is not configured",
        )
    return bool(provided and hmac.compare_digest(provided, expected))


async def _validate_admin_jwt(request: Request) -> bool:
    jwt_secret = (settings.jwt_secret or "").strip()
    if not jwt_secret:
        return False

    jwt_auth = JWTAuth(
        secret=jwt_secret,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )

    try:
        await get_current_user_from_request(request, jwt_auth)
        return True
    except HTTPException:
        return False


async def require_admin_auth(request: Request) -> None:
    """
    Validate optional admin API authentication.

    When `ADMIN_AUTH_ENABLED=false`, admin routes remain open.
    When enabled, auth mode is controlled by `ADMIN_AUTH_MODE`:
    - api_key: requires valid x-admin-key
    - jwt: requires valid Bearer JWT
    - api_key_or_jwt: accepts either
    """
    if not settings.admin_auth_enabled:
        return

    mode = (settings.admin_auth_mode or "api_key").strip().lower()
    if mode not in _VALID_ADMIN_AUTH_MODES:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Invalid ADMIN_AUTH_MODE: '{mode}'",
        )

    allowlist = _split_csv(settings.admin_allowed_ips)
    if allowlist:
        client_ip = _extract_client_ip(request)
        if not _ip_in_allowlist(client_ip, allowlist):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access denied for client IP",
            )

    api_key_ok = False
    jwt_ok = False

    if mode in {"api_key", "api_key_or_jwt"}:
        api_key_ok = _validate_admin_api_key(request)

    if mode in {"jwt", "api_key_or_jwt"}:
        jwt_ok = await _validate_admin_jwt(request)
        if mode == "jwt" and not (settings.jwt_secret or "").strip():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="ADMIN_AUTH_MODE=jwt but JWT_SECRET is not configured",
            )

    if mode == "api_key" and api_key_ok:
        return
    if mode == "jwt" and jwt_ok:
        return
    if mode == "api_key_or_jwt" and (api_key_ok or jwt_ok):
        return

    if mode == "jwt":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin Bearer token",
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid admin credentials",
    )
