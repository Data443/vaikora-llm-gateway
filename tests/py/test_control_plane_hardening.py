from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Request

from gateway.core.config import settings
from gateway.integrations.control_plane import ControlPlaneClient
from gateway.integrations.telemetry import telemetry_metrics
from gateway.services.proxy_service import ProxyHandler


class _AcquireContext:
    def __init__(self, conn) -> None:
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _PoolStub:
    def __init__(self, row) -> None:
        self.conn = SimpleNamespace(
            fetchrow=AsyncMock(return_value=row),
            execute=AsyncMock(),
        )

    def acquire(self):
        return _AcquireContext(self.conn)


def _build_request(path: str = "/v1/chat/completions") -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_queue_audit_event_sanitizes_and_drops_when_buffer_full() -> None:
    telemetry_metrics.reset()
    client = ControlPlaneClient()
    client._audit_buffer_max_size = 1

    client.queue_audit_event(
        {
            "event_id": "evt-1",
            "metadata": {
                "content": "secret body",
                "message_length": 42,
            },
            "request_body": {
                "messages": [{"role": "user", "content": "my ssn is 123-45-6789"}],
            },
        }
    )
    client.queue_audit_event({"event_id": "evt-2"})

    queued = list(client._audit_buffer)
    assert len(queued) == 1
    assert queued[0]["metadata"]["content"] == "[REDACTED]"
    assert queued[0]["metadata"]["message_length"] == 42
    assert queued[0]["request_body"] == "[REDACTED]"
    assert client._dropped_audit_events == 1

    snap = telemetry_metrics.snapshot()
    assert snap["control_plane_counts"]["audit_queue|queued"] == 1
    assert snap["control_plane_counts"]["audit_queue|dropped"] == 1


@pytest.mark.asyncio
async def test_sync_policies_falls_back_to_db_when_remote_sync_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    telemetry_metrics.reset()
    monkeypatch.setattr(settings, "control_plane_enabled", True)

    client = ControlPlaneClient()
    client._base_url = "http://control-plane.local"
    client._http = SimpleNamespace(request=AsyncMock(side_effect=RuntimeError("network down")))
    client.set_db_pool(
        _PoolStub(
            {
                "policies": json.dumps([{"id": "policy-1", "action": "require_approval"}]),
                "synced_at": datetime(2026, 4, 9, tzinfo=timezone.utc),
            }
        )
    )

    result = await client._sync_policies_once()

    assert result is False
    assert client.synced_policies == [{"id": "policy-1", "action": "require_approval"}]
    assert client.health_snapshot()["last_policy_sync_status"] == "failed"

    snap = telemetry_metrics.snapshot()
    assert snap["control_plane_counts"]["policy_sync|failure"] == 1
    assert snap["control_plane_counts"]["policy_sync|cache_loaded"] == 1


@pytest.mark.asyncio
async def test_request_opens_circuit_after_repeated_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    telemetry_metrics.reset()
    monkeypatch.setattr(settings, "control_plane_circuit_breaker_failure_threshold", 2)
    monkeypatch.setattr(settings, "control_plane_circuit_breaker_recovery_timeout", 30)

    client = ControlPlaneClient()
    client._base_url = "http://control-plane.local"
    client._http = SimpleNamespace(request=AsyncMock(side_effect=RuntimeError("boom")))

    with pytest.raises(RuntimeError):
        await client._request("GET", "/api/v1/integration/policies", operation="policy_sync")
    assert client._is_circuit_open() is False

    with pytest.raises(RuntimeError):
        await client._request("GET", "/api/v1/integration/policies", operation="policy_sync")
    assert client._is_circuit_open() is True

    snap = telemetry_metrics.snapshot()
    assert snap["control_plane_counts"]["policy_sync|failure"] == 2
    assert snap["control_plane_counts"]["policy_sync|circuit_opened"] == 1


@pytest.mark.asyncio
async def test_hitl_policy_fails_closed_when_approval_request_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gateway.services.proxy_service as proxy_mod

    stub_control_plane = SimpleNamespace(
        is_connected=True,
        get_require_approval_policies=lambda: [
            {
                "id": "policy-1",
                "name": "hitl-sensitive-requests",
                "action": "require_approval",
                "rules": {
                    "action_type": "llm.chat.completion",
                    "blocked_keywords": ["transfer money"],
                },
            }
        ],
        create_hitl_request=AsyncMock(return_value=None),
        health_snapshot=lambda: {"enabled": True, "status": "healthy"},
    )
    monkeypatch.setattr(proxy_mod, "control_plane_client", stub_control_plane)

    policy_engine = Mock()
    policy_engine.cyren_client = Mock(get_circuit_breaker_state=Mock(return_value="closed"))
    policy_engine.audit_logger = Mock(connected=True)

    handler = ProxyHandler(policy_engine=policy_engine)
    handler._emit_gateway_event = AsyncMock()  # type: ignore[method-assign]

    response = await handler._check_control_plane_hitl(
        request=_build_request(),
        request_id="req-hitl-1",
        request_body={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "please transfer money now"}],
        },
        model_name="gpt-4o-mini",
        provider_name="openai",
        org_id=None,
        user_id=None,
    )

    assert response is not None
    assert response.status_code == 503
    body = json.loads(response.body.decode("utf-8"))
    assert body["error"]["type"] == "approval_service_unavailable"
    assert body["error"]["code"] == "hitl_unavailable"


@pytest.mark.asyncio
async def test_health_check_surfaces_control_plane_status(monkeypatch: pytest.MonkeyPatch) -> None:
    import gateway.services.proxy_service as proxy_mod

    monkeypatch.setattr(settings, "control_plane_enabled", True)
    monkeypatch.setattr(proxy_mod.cache.l2, "connected", True)

    stub_control_plane = SimpleNamespace(
        health_snapshot=lambda: {"enabled": True, "status": "degraded", "policy_count": 0},
    )
    monkeypatch.setattr(proxy_mod, "control_plane_client", stub_control_plane)

    policy_engine = Mock()
    policy_engine.cyren_client = Mock(get_circuit_breaker_state=Mock(return_value="closed"))
    policy_engine.audit_logger = Mock(connected=True)

    handler = ProxyHandler(policy_engine=policy_engine)
    health = await handler.health_check()

    assert health["status"] == "degraded"
    assert health["components"]["control_plane"]["status"] == "degraded"
