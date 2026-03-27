"""Admin auth hardening tests."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from gateway.api.auth import require_admin_auth
from gateway.core.config import settings
from gateway.services.jwt_auth import JWTAuth


def _build_request(
    headers: dict[str, str] | None = None,
    client_ip: str = "127.0.0.1",
) -> Request:
    raw_headers = []
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode("utf-8"), value.encode("utf-8")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/admin/policies",
        "raw_path": b"/admin/policies",
        "query_string": b"",
        "headers": raw_headers,
        "client": (client_ip, 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_admin_auth_api_key_or_jwt_accepts_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "admin_auth_enabled", True)
    monkeypatch.setattr(settings, "admin_auth_mode", "api_key_or_jwt")
    monkeypatch.setattr(settings, "admin_api_key", "super-admin-key")
    monkeypatch.setattr(settings, "admin_allowed_ips", "")
    monkeypatch.setattr(settings, "jwt_secret", "")

    request = _build_request(headers={"x-admin-key": "super-admin-key"})
    await require_admin_auth(request)


@pytest.mark.asyncio
async def test_admin_auth_jwt_mode_accepts_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "admin_auth_enabled", True)
    monkeypatch.setattr(settings, "admin_auth_mode", "jwt")
    monkeypatch.setattr(settings, "admin_api_key", "unused")
    monkeypatch.setattr(settings, "admin_allowed_ips", "")
    monkeypatch.setattr(settings, "jwt_secret", "jwt-secret")
    monkeypatch.setattr(settings, "jwt_issuer", "data443-gateway")
    monkeypatch.setattr(settings, "jwt_audience", "data443-gateway")

    token = JWTAuth(secret="jwt-secret", issuer="data443-gateway", audience="data443-gateway").create_token(
        "admin-user"
    )
    request = _build_request(headers={"authorization": f"Bearer {token}"})
    await require_admin_auth(request)


@pytest.mark.asyncio
async def test_admin_allowlist_blocks_non_matching_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "admin_auth_enabled", True)
    monkeypatch.setattr(settings, "admin_auth_mode", "api_key")
    monkeypatch.setattr(settings, "admin_api_key", "super-admin-key")
    monkeypatch.setattr(settings, "admin_allowed_ips", "10.0.0.0/8")

    request = _build_request(
        headers={"x-admin-key": "super-admin-key"},
        client_ip="203.0.113.10",
    )
    with pytest.raises(HTTPException) as exc_info:
        await require_admin_auth(request)

    assert exc_info.value.status_code == 403
