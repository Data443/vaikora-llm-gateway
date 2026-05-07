"""Startup configuration validation for production safety."""

from __future__ import annotations

from typing import List

from gateway.core.config import settings


_VALID_ADMIN_AUTH_MODES = {"api_key", "jwt", "api_key_or_jwt"}
_PLACEHOLDER_ADMIN_KEYS = {
    "change_me_admin_key",
    "changeme_admin_key",
    "admin_api_key_here",
    "your_admin_api_key_here",
}
_PLACEHOLDER_PROXY_KEYS = {
    "changeme_proxy_key",
    "change_me_proxy_key",
    "proxy_api_key_here",
    "your_proxy_api_key_here",
}
_PLACEHOLDER_JWT_SECRETS = {
    "change_me_jwt_secret",
    "changeme_jwt_secret",
    "jwt_secret_here",
    "your_jwt_secret_here",
}


def _looks_missing_or_placeholder(value: str, placeholders: set[str]) -> bool:
    normalized = (value or "").strip().lower()
    if not normalized:
        return True
    return normalized in placeholders


def collect_startup_validation_errors(*, strict: bool = False) -> List[str]:
    """Collect startup configuration errors that should block startup."""
    errors: List[str] = []

    if settings.upstream_timeout_seconds <= 0:
        errors.append("UPSTREAM_TIMEOUT_SECONDS must be > 0")

    if settings.max_request_body_bytes < 0:
        errors.append("MAX_REQUEST_BODY_BYTES must be >= 0")

    if settings.rate_limit_enabled:
        if settings.rate_limit_window_seconds <= 0:
            errors.append("RATE_LIMIT_WINDOW_SECONDS must be > 0 when rate limiting is enabled")
        if settings.rate_limit_proxy_requests <= 0:
            errors.append("RATE_LIMIT_PROXY_REQUESTS must be > 0 when rate limiting is enabled")
        if settings.rate_limit_admin_requests <= 0:
            errors.append("RATE_LIMIT_ADMIN_REQUESTS must be > 0 when rate limiting is enabled")
        if settings.rate_limit_audit_requests <= 0:
            errors.append("RATE_LIMIT_AUDIT_REQUESTS must be > 0 when rate limiting is enabled")

    if settings.proxy_api_key_enabled:
        if not (settings.proxy_api_key or "").strip():
            errors.append("PROXY_API_KEY_ENABLED=true but PROXY_API_KEY is not configured")
        elif strict and _looks_missing_or_placeholder(
            settings.proxy_api_key,
            _PLACEHOLDER_PROXY_KEYS,
        ):
            errors.append(
                "PROXY_API_KEY_ENABLED=true but PROXY_API_KEY is still set to a placeholder"
            )

    mode = (settings.admin_auth_mode or "").strip().lower()
    if settings.admin_auth_enabled:
        if mode not in _VALID_ADMIN_AUTH_MODES:
            errors.append(
                f"ADMIN_AUTH_MODE '{settings.admin_auth_mode}' is invalid "
                "(must be api_key, jwt, or api_key_or_jwt)"
            )

        has_admin_key = bool((settings.admin_api_key or "").strip())
        has_jwt_secret = bool((settings.jwt_secret or "").strip())

        if mode == "api_key" and not has_admin_key:
            errors.append(
                "ADMIN_AUTH_MODE=api_key requires ADMIN_API_KEY to be configured"
            )
        elif mode == "jwt" and not has_jwt_secret:
            errors.append(
                "ADMIN_AUTH_MODE=jwt requires JWT_SECRET to be configured"
            )
        elif mode == "api_key_or_jwt" and not (has_admin_key or has_jwt_secret):
            errors.append(
                "ADMIN_AUTH_MODE=api_key_or_jwt requires either ADMIN_API_KEY or JWT_SECRET "
                "to be configured"
            )

        if strict and mode in {"api_key", "api_key_or_jwt"} and has_admin_key and _looks_missing_or_placeholder(
            settings.admin_api_key,
            _PLACEHOLDER_ADMIN_KEYS,
        ):
            errors.append(
                "ADMIN_API_KEY is still set to a placeholder while strict startup validation is enabled"
            )
        if strict and mode in {"jwt", "api_key_or_jwt"} and has_jwt_secret and _looks_missing_or_placeholder(
            settings.jwt_secret,
            _PLACEHOLDER_JWT_SECRETS,
        ):
            errors.append(
                "JWT_SECRET is still set to a placeholder while strict startup validation is enabled"
            )

    if settings.jwt_enabled:
        if not (settings.jwt_secret or "").strip():
            errors.append("JWT_ENABLED=true but JWT_SECRET is not configured")
        elif strict and _looks_missing_or_placeholder(
            settings.jwt_secret,
            _PLACEHOLDER_JWT_SECRETS,
        ):
            errors.append(
                "JWT_ENABLED=true but JWT_SECRET is still set to a placeholder"
            )

    if settings.control_plane_enabled:
        control_plane_url = (settings.control_plane_url or "").strip()
        if not control_plane_url:
            errors.append("CONTROL_PLANE_ENABLED=true but CONTROL_PLANE_URL is not configured")
        elif not (
            control_plane_url.startswith("http://")
            or control_plane_url.startswith("https://")
        ):
            errors.append("CONTROL_PLANE_URL must start with http:// or https://")

        if not (settings.control_plane_api_key or "").strip():
            errors.append("CONTROL_PLANE_ENABLED=true but CONTROL_PLANE_API_KEY is not configured")

        if settings.control_plane_policy_sync_interval <= 0:
            errors.append("CONTROL_PLANE_POLICY_SYNC_INTERVAL must be > 0")
        if settings.control_plane_audit_push_interval <= 0:
            errors.append("CONTROL_PLANE_AUDIT_PUSH_INTERVAL must be > 0")
        if settings.control_plane_audit_batch_size <= 0:
            errors.append("CONTROL_PLANE_AUDIT_BATCH_SIZE must be > 0")
        if settings.control_plane_hitl_poll_interval <= 0:
            errors.append("CONTROL_PLANE_HITL_POLL_INTERVAL must be > 0")
        if settings.control_plane_hitl_timeout <= 0:
            errors.append("CONTROL_PLANE_HITL_TIMEOUT must be > 0")
        if settings.control_plane_hitl_continuation_ttl_seconds <= 0:
            errors.append("CONTROL_PLANE_HITL_CONTINUATION_TTL_SECONDS must be > 0")
        if settings.control_plane_request_timeout <= 0:
            errors.append("CONTROL_PLANE_REQUEST_TIMEOUT must be > 0")
        if strict and not (settings.control_plane_hitl_continuation_secret or "").strip():
            errors.append(
                "CONTROL_PLANE_ENABLED=true with STRICT_STARTUP_VALIDATION=true requires "
                "CONTROL_PLANE_HITL_CONTINUATION_SECRET to be configured (async HITL continuation)"
            )

    if settings.audit_retention_days < 0:
        errors.append("AUDIT_RETENTION_DAYS must be >= 0")
    if settings.audit_max_string_length < 0:
        errors.append("AUDIT_MAX_STRING_LENGTH must be >= 0")
    if settings.audit_purge_interval_seconds <= 0:
        errors.append("AUDIT_PURGE_INTERVAL_SECONDS must be > 0")

    return errors


def validate_startup_settings(*, strict: bool = False) -> None:
    """Raise RuntimeError when startup configuration is unsafe or invalid."""
    errors = collect_startup_validation_errors(strict=strict)
    if not errors:
        return
    formatted = "\n".join(f"- {item}" for item in errors)
    raise RuntimeError(f"Startup configuration validation failed:\n{formatted}")
