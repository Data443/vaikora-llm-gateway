"""Security hardening regression tests for production behavior."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from gateway.api import admin as admin_api
from gateway.api import public as public_api
from gateway.core.config import settings
from gateway.services.content_filter import ContentFilter
from gateway.services.jwt_auth import JWTAuth


def _build_request(headers: dict[str, str] | None = None) -> Request:
    """Create a lightweight Request object for dependency tests."""
    header_items = []
    for key, value in (headers or {}).items():
        header_items.append((key.lower().encode("utf-8"), value.encode("utf-8")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": header_items,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_get_jwt_policy_redacts_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """JWT policy read endpoint must not return raw secret values."""
    monkeypatch.setattr(
        admin_api.policy_store,
        "get_policy_with_version",
        AsyncMock(
            return_value=(
                {
                    "enabled": True,
                    "secret": "super-secret-value",
                    "issuer": "data443",
                    "audience": "gateway",
                },
                9,
            )
        ),
    )

    response = await admin_api.get_jwt_policy()
    assert response.success is True
    assert response.policy["secret"] == "***REDACTED***"


@pytest.mark.asyncio
async def test_audit_endpoints_require_admin_key_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public audit endpoint should enforce admin auth when toggle is enabled."""
    monkeypatch.setattr(settings, "admin_auth_enabled", True)
    monkeypatch.setattr(settings, "admin_api_key", "test-admin-key")
    monkeypatch.setattr(public_api.audit_logger, "query_audit_log", AsyncMock(return_value=[]))

    with pytest.raises(HTTPException) as exc:
        await public_api.get_audit_log(_build_request(), limit=10, offset=0)
    assert exc.value.status_code == 401

    ok_request = _build_request(headers={"x-admin-key": "test-admin-key"})
    response = await public_api.get_audit_log(ok_request, limit=10, offset=0)
    assert response.status_code == 200


def test_jwt_auth_fails_without_secret() -> None:
    """JWT token creation should fail when no secret is configured."""
    auth = JWTAuth(secret="")

    with pytest.raises(ValueError):
        auth.create_token("user-1")

    assert auth.verify_token("invalid") is None


def test_content_filter_reduces_false_positive_short_phone() -> None:
    """Partial phone-like fragments should not trigger PHONE_US detection."""
    filter_engine = ContentFilter()
    detections = filter_engine.check_pii("Ref number is 123-456 and not a phone.")
    assert not any(item["type"] == "PHONE_US" for item in detections)


def test_content_filter_credit_card_uses_luhn() -> None:
    """Credit card detection should reject invalid checksum and accept valid card."""
    filter_engine = ContentFilter()

    invalid = filter_engine.check_pii("Card 4111 1111 1111 1112")
    assert not any(item["type"] == "CREDIT_CARD" for item in invalid)

    valid = filter_engine.check_pii("Card 4111 1111 1111 1111")
    assert any(item["type"] == "CREDIT_CARD" for item in valid)
