"""Production startup validation and readiness endpoint tests."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.api.public import public_router
from gateway.core.config import settings
from gateway.core.startup_validation import (
    collect_startup_validation_errors,
    validate_startup_settings,
)


class _ProxyHandlerStub:
    def __init__(self, *, ready: bool) -> None:
        self._ready = ready

    async def health_check(self):
        return {"status": "healthy"}

    async def readiness_check(self):
        return {
            "ready": self._ready,
            "status": "ready" if self._ready else "not_ready",
            "components": {"redis_cache": "connected"},
        }


def _build_public_app(*, ready: bool) -> FastAPI:
    app = FastAPI()
    app.include_router(public_router)
    app.state.proxy_handler = _ProxyHandlerStub(ready=ready)
    return app


def test_ready_endpoint_returns_200_when_ready() -> None:
    client = TestClient(_build_public_app(ready=True))

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json()["ready"] is True


def test_ready_endpoint_returns_503_when_not_ready() -> None:
    client = TestClient(_build_public_app(ready=False))

    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json()["ready"] is False


def test_root_lists_ready_endpoint() -> None:
    client = TestClient(_build_public_app(ready=True))

    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["endpoints"]["ready"] == "/ready"


def test_startup_validation_flags_proxy_key_placeholder(monkeypatch) -> None:
    monkeypatch.setattr(settings, "proxy_api_key_enabled", True)
    monkeypatch.setattr(settings, "proxy_api_key", "changeme_proxy_key")

    errors = collect_startup_validation_errors(strict=True)

    assert any("placeholder" in error and "PROXY_API_KEY" in error for error in errors)


def test_startup_validation_flags_invalid_admin_mode(monkeypatch) -> None:
    monkeypatch.setattr(settings, "admin_auth_enabled", True)
    monkeypatch.setattr(settings, "admin_auth_mode", "invalid-mode")

    errors = collect_startup_validation_errors(strict=True)

    assert any("ADMIN_AUTH_MODE" in error and "invalid" in error for error in errors)


def test_startup_validation_requires_admin_credentials_for_api_key_or_jwt(monkeypatch) -> None:
    monkeypatch.setattr(settings, "admin_auth_enabled", True)
    monkeypatch.setattr(settings, "admin_auth_mode", "api_key_or_jwt")
    monkeypatch.setattr(settings, "admin_api_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "")

    errors = collect_startup_validation_errors(strict=True)

    assert any("api_key_or_jwt" in error for error in errors)


def test_startup_validation_flags_control_plane_missing_config(monkeypatch) -> None:
    monkeypatch.setattr(settings, "control_plane_enabled", True)
    monkeypatch.setattr(settings, "control_plane_url", "")
    monkeypatch.setattr(settings, "control_plane_api_key", "")

    errors = collect_startup_validation_errors(strict=True)

    assert any("CONTROL_PLANE_URL" in error for error in errors)
    assert any("CONTROL_PLANE_API_KEY" in error for error in errors)


def test_validate_startup_settings_raises_for_invalid_state(monkeypatch) -> None:
    monkeypatch.setattr(settings, "proxy_api_key_enabled", True)
    monkeypatch.setattr(settings, "proxy_api_key", "")

    try:
        validate_startup_settings(strict=True)
        assert False, "Expected startup validation to raise RuntimeError"
    except RuntimeError as exc:
        assert "Startup configuration validation failed" in str(exc)


def test_validate_startup_settings_allows_valid_critical_auth_config(monkeypatch) -> None:
    monkeypatch.setattr(settings, "proxy_api_key_enabled", True)
    monkeypatch.setattr(settings, "proxy_api_key", "proxy-prod-key")
    monkeypatch.setattr(settings, "admin_auth_enabled", True)
    monkeypatch.setattr(settings, "admin_auth_mode", "api_key")
    monkeypatch.setattr(settings, "admin_api_key", "admin-prod-key")
    monkeypatch.setattr(settings, "jwt_enabled", False)
    monkeypatch.setattr(settings, "control_plane_enabled", False)

    validate_startup_settings(strict=True)


def test_non_strict_mode_allows_proxy_placeholder(monkeypatch) -> None:
    monkeypatch.setattr(settings, "proxy_api_key_enabled", True)
    monkeypatch.setattr(settings, "proxy_api_key", "changeme_proxy_key")

    errors = collect_startup_validation_errors(strict=False)

    assert not any("placeholder" in error and "PROXY_API_KEY" in error for error in errors)
