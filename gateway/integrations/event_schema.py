"""Gateway event schema helpers for stable analytics payloads."""

from __future__ import annotations

from typing import Any, Dict, Optional


def _json_safe(value: Any) -> Any:
    """Normalize values into JSON-serializable primitives."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return str(value)


def build_gateway_event_attributes(
    *,
    request_method: str,
    request_path: str,
    provider: str,
    request_body: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a stable event attributes payload for audit/event ingestion."""
    base: Dict[str, Any] = {
        "request_method": request_method,
        "request_path": request_path,
        "provider": provider,
        "request_body": request_body or {},
    }
    merged = {**base, **(extra or {})}
    return _json_safe(merged)
