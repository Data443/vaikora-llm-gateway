"""Managed-agent proxy path tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from gateway.api.public import public_router
from gateway.core.types import Decision
from gateway.providers.base import NormalizedProviderResponse, PreparedProviderRequest
from gateway.services.agent_registry import agent_registry
from gateway.services.content_filter import SecurityAction
from gateway.services.policy_service import PolicyDecision
from gateway.services.proxy_service import ProxyHandler


class _ProxyHandlerStub:
    async def handle_request(self, request):
        return JSONResponse(
            {
                "ok": True,
                "agent_context": getattr(request.state, "agent_context", {}),
            }
        )


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(public_router)
    app.state.proxy_handler = _ProxyHandlerStub()
    return app


@pytest.mark.asyncio
async def test_managed_agent_proxy_requires_registered_agent(monkeypatch) -> None:
    app = _build_app()
    monkeypatch.setattr(agent_registry, "get_agent", AsyncMock(return_value=None))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/agents/missing-agent/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_managed_agent_proxy_sets_agent_context(monkeypatch) -> None:
    app = _build_app()
    monkeypatch.setattr(
        agent_registry,
        "get_agent",
        AsyncMock(
            return_value={
                "agent_id": "agent-1",
                "agent_type": "assistant",
                "status": "ACTIVE",
                "wrapped": True,
            }
        ),
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/agents/agent-1/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["agent_context"]["agent_id"] == "agent-1"
    assert payload["agent_context"]["agent_type"] == "assistant"
    assert payload["agent_context"]["agent_wrapped"] is True


def test_proxy_handler_chat_path_detection_supports_managed_agent() -> None:
    handler = ProxyHandler(policy_engine=Mock())

    assert handler._is_chat_completions_path("/v1/chat/completions")
    assert handler._is_chat_completions_path("/agents/agent-1/v1/chat/completions")
    assert handler._is_chat_completions_path("/agents/agent-1/v1/chat/completions/")
    assert not handler._is_chat_completions_path("/v1/models")


@pytest.mark.asyncio
async def test_forward_request_uses_chat_adapter_for_managed_agent_path(monkeypatch) -> None:
    policy_engine = Mock()
    policy_engine.cyren_client = Mock(get_circuit_breaker_state=Mock(return_value="closed"))
    policy_engine.audit_logger = Mock(connected=False)

    handler = ProxyHandler(policy_engine=policy_engine)
    handler._emit_gateway_event = AsyncMock()  # type: ignore[method-assign]

    prepared = PreparedProviderRequest(
        url="https://api.openai.com/v1/chat/completions",
        headers={"authorization": "Bearer test"},
        json_body={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        params={},
    )
    normalized_payload = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    handler.provider_router.prepare_chat_completion = Mock(return_value=prepared)
    handler.provider_router.normalize_chat_completion = Mock(
        return_value=NormalizedProviderResponse(status_code=200, payload=normalized_payload)
    )

    captured_requests = []

    class _UpstreamResponse:
        status_code = 200
        headers = {"content-type": "application/json"}
        content = b'{"ok":true}'

        def json(self):
            return {"id": "provider-raw"}

    class _DummyAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, **kwargs):
            captured_requests.append(kwargs)
            return _UpstreamResponse()

    monkeypatch.setattr("gateway.services.proxy_service.AsyncClient", _DummyAsyncClient)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/agents/agent-1/v1/chat/completions",
        "raw_path": b"/agents/agent-1/v1/chat/completions",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    request = Request(scope)

    response = await handler._forward_request(
        request=request,
        request_id="req-test",
        final_decision=PolicyDecision(decision=Decision.ALLOW_LOG, risk_score=70, reason="test"),
        request_body={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        content_security={"action": SecurityAction.PASS, "counts": {}},
        user_id=None,
        org_id=None,
        model_name="gpt-4o-mini",
        provider_name="openai",
        constrained=False,
    )

    assert response.status_code == 200
    assert captured_requests
    assert captured_requests[0]["url"] == "https://api.openai.com/v1/chat/completions"
    handler.provider_router.prepare_chat_completion.assert_called_once()
    handler.provider_router.normalize_chat_completion.assert_called_once()
