"""Prometheus LLM-execution metrics (llm-observability CONTRACT.md).

Covers infra_class resolution, caller/model label sanitisation, token extraction,
the proxy request path (one execution per upstream call, blocked requests counted
separately), the unauthenticated /metrics route, and prometheus_client multiprocess
aggregation across worker processes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Optional
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import HTTPException, Request

from gateway.core.config import settings
from gateway.core.types import Decision
from gateway.integrations import llm_metrics
from gateway.services.content_filter import SecurityAction
from gateway.services.policy_service import PolicyDecision
from gateway.services.proxy_service import ProxyHandler

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _sample(name: str, labels: Dict[str, str]) -> float:
    value = llm_metrics.REGISTRY.get_sample_value(name, labels)
    return float(value or 0.0)


def _total(name: str) -> float:
    total = 0.0
    for metric in llm_metrics.REGISTRY.collect():
        for sample in metric.samples:
            if sample.name == name:
                total += sample.value
    return total


def _build_request(
    path: str = "/v1/chat/completions",
    body: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Request:
    raw_body = json.dumps(body if body is not None else {}).encode("utf-8")
    header_list = [(b"content-type", b"application/json")]
    for key, value in (headers or {}).items():
        header_list.append((key.lower().encode("latin-1"), value.encode("latin-1")))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": header_list,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    sent = {"done": False}

    async def receive():
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": raw_body, "more_body": False}

    return Request(scope, receive)


_CHAT_BODY = {
    "model": "Qwen3.6-35B-A3B",
    "messages": [{"role": "user", "content": "hello"}],
}


@pytest.fixture()
def proxy_env(monkeypatch: pytest.MonkeyPatch):
    """A ProxyHandler wired to an in-memory upstream with every gate set to pass."""
    import gateway.services.proxy_service as proxy_mod

    monkeypatch.setattr(settings, "proxy_api_key_enabled", False)
    monkeypatch.setattr(settings, "llm_provider", "openai")
    monkeypatch.setattr(settings, "openai_endpoint", "http://10.40.5.106:8080")
    monkeypatch.setattr(settings, "openai_api_key", "infra-key")
    monkeypatch.setattr(settings, "openai_prefer_configured_key", True)
    monkeypatch.delenv("LLM_INFRA_CLASS_MAP", raising=False)

    monkeypatch.setattr(proxy_mod, "get_policy", lambda name: {"enabled": False})
    monkeypatch.setattr(
        proxy_mod,
        "policy_store",
        SimpleNamespace(
            is_provider_enabled=lambda name: True,
            get_allowed_models=lambda: [],
            get_entitlements=lambda: {"limits": {}},
        ),
    )
    content_filter = SimpleNamespace(
        check_request=Mock(return_value={"action": SecurityAction.PASS, "counts": {}, "detected": []}),
        check_response=Mock(return_value={"action": SecurityAction.PASS}),
    )
    monkeypatch.setattr(proxy_mod, "get_content_filter", lambda: content_filter)
    monkeypatch.setattr(
        proxy_mod,
        "control_plane_client",
        SimpleNamespace(is_connected=False, get_require_approval_policies=lambda: []),
    )
    monkeypatch.setattr(proxy_mod.audit_logger, "log_gateway_event", AsyncMock())

    policy_engine = Mock()
    policy_engine.cyren_client = Mock(get_circuit_breaker_state=Mock(return_value="closed"))
    policy_engine.audit_logger = Mock(connected=False)
    policy_engine.evaluate_request = AsyncMock(
        return_value=PolicyDecision(decision=Decision.ALLOW, risk_score=95, reason="ok")
    )
    handler = ProxyHandler(policy_engine=policy_engine)

    state = SimpleNamespace(handler=handler, content_filter=content_filter, upstream_calls=[])

    def set_upstream(fn):
        def _wrapped(req: httpx.Request) -> httpx.Response:
            state.upstream_calls.append(req)
            return fn(req)

        handler._http_client = httpx.AsyncClient(transport=httpx.MockTransport(_wrapped))

    state.set_upstream = set_upstream
    return state


# ---------------------------------------------------------------------------
# infra_class resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://10.40.5.106:8080", "cpu_local"),
        ("http://10.40.5.106:8080/v1/chat/completions", "cpu_local"),
        ("https://llm-gateway.data443.io/v1", "cpu_local"),
        ("http://inference-01:8080", "cpu_local"),
        ("https://abc123-8000.proxy.runpod.net", "gpu_offprem"),
        ("https://api.runpod.ai/v2/x", "gpu_offprem"),
        ("https://api.openai.com", "api_thirdparty"),
        ("https://api.anthropic.com/v1/messages", "api_thirdparty"),
        ("https://generativelanguage.googleapis.com", "api_thirdparty"),
        ("https://openrouter.ai/api/v1", "api_thirdparty"),
        ("https://API.OpenAI.com", "api_thirdparty"),
        ("10.40.5.106", "cpu_local"),
    ],
)
def test_infra_class_defaults(monkeypatch: pytest.MonkeyPatch, url: str, expected: str) -> None:
    monkeypatch.delenv("LLM_INFRA_CLASS_MAP", raising=False)
    assert llm_metrics.resolve_infra_class(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://10.40.9.9:8000",
        "https://example.com",
        "https://api.openai.com.attacker.net",
        "https://notapi.openai.com",
        "http://110.40.5.106:8080",
        "",
        None,
    ],
)
def test_infra_class_unknown(monkeypatch: pytest.MonkeyPatch, url) -> None:
    monkeypatch.delenv("LLM_INFRA_CLASS_MAP", raising=False)
    assert llm_metrics.resolve_infra_class(url) == "unknown"


def test_infra_class_env_map_overrides_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_INFRA_CLASS_MAP", "10.40.5.106=gpu_local, gpu-01.data443.net=gpu_local")
    assert llm_metrics.resolve_infra_class("http://10.40.5.106:8080") == "gpu_local"
    assert llm_metrics.resolve_infra_class("http://gpu-01.data443.net:8000") == "gpu_local"
    # Hosts not in the map still fall through to the built-in defaults.
    assert llm_metrics.resolve_infra_class("https://api.openai.com") == "api_thirdparty"


def test_infra_class_env_map_longest_suffix_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "LLM_INFRA_CLASS_MAP",
        "runpod.net=gpu_offprem,special.runpod.net=gpu_local",
    )
    assert llm_metrics.resolve_infra_class("https://x.special.runpod.net") == "gpu_local"
    assert llm_metrics.resolve_infra_class("https://x.other.runpod.net") == "gpu_offprem"


def test_infra_class_env_map_ignores_bad_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_INFRA_CLASS_MAP", "foo.example=bogus,,=cpu_local,novalue,bar.example=CPU_LOCAL")
    assert llm_metrics.resolve_infra_class("https://foo.example") == "unknown"
    assert llm_metrics.resolve_infra_class("https://bar.example") == "cpu_local"


# ---------------------------------------------------------------------------
# label sanitisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("awx-agent", "awx-agent"),
        ("AWX-Agent", "awx-agent"),
        ("AWX Agent!", "awx_agent"),
        ("svc.convaa_01", "svc.convaa_01"),
        ("a" * 60, "a" * 40),
        ("", "anonymous"),
        ("   ", "anonymous"),
        ("!!!", "anonymous"),
        (None, "anonymous"),
    ],
)
def test_sanitize_caller(raw, expected: str) -> None:
    assert llm_metrics.sanitize_caller(raw) == expected


def test_resolve_caller_precedence() -> None:
    assert llm_metrics.resolve_caller({"x-caller": "AWX", "x-agent-id": "agent-1"}, {"agent_id": "agent-1"}) == "awx"
    assert llm_metrics.resolve_caller({}, {"agent_id": "Agent-7"}) == "agent-7"
    assert llm_metrics.resolve_caller({}, {}) == "anonymous"


def test_model_label_is_lowercased_and_bounded() -> None:
    assert llm_metrics.sanitize_model("Qwen3.6-35B-A3B") == "qwen3.6-35b-a3b"
    assert llm_metrics.sanitize_model("anthropic/claude-sonnet-4.5") == "anthropic/claude-sonnet-4.5"
    assert llm_metrics.sanitize_model(None) == "unknown"
    assert llm_metrics.sanitize_model("") == "unknown"
    assert len(llm_metrics.sanitize_model("m" * 300)) <= 80


def test_bounded_label_overflows_to_other() -> None:
    bounded = llm_metrics.BoundedLabel(limit=2)
    assert bounded("a") == "a"
    assert bounded("b") == "b"
    assert bounded("a") == "a"
    assert bounded("c") == "other"


@pytest.mark.parametrize(
    "decision,attributes,expected",
    [
        ("BLOCK", {"block_type": "proxy_auth"}, "auth"),
        ("BLOCK", {"block_type": "auth"}, "auth"),
        ("ERROR", {"block_type": "auth_configuration"}, "config_error"),
        ("BLOCK", {"block_type": "entitlement_model"}, "entitlement"),
        ("BLOCK", {"block_type": "entitlement_limits"}, "entitlement"),
        ("BLOCK", {"block_type": "content_filter"}, "content_filter"),
        ("PENDING_APPROVAL", {"block_type": "hitl_approval"}, "hitl"),
        ("ERROR", {"block_type": "hitl_continuation"}, "hitl"),
        ("BLOCK", {"ip_risk_score": 5}, "policy"),
        ("ERROR", {"exception": "provider_configuration_error"}, "config_error"),
        ("ERROR", {"block_type": "something_new"}, "other"),
    ],
)
def test_block_reason_mapping(decision: str, attributes: dict, expected: str) -> None:
    assert llm_metrics.block_reason_for(decision, attributes) == expected
    assert expected in llm_metrics.BLOCK_REASONS


# ---------------------------------------------------------------------------
# token extraction
# ---------------------------------------------------------------------------


def test_extract_usage_openai_with_cache() -> None:
    usage = llm_metrics.extract_token_usage(
        {"usage": {"prompt_tokens": 100, "completion_tokens": 20, "prompt_tokens_details": {"cached_tokens": 30}}}
    )
    assert usage == {"input": 70, "output": 20, "cache_read": 30}


def test_extract_usage_anthropic_and_gemini() -> None:
    assert llm_metrics.extract_token_usage(
        {
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_read_input_tokens": 7,
                "cache_creation_input_tokens": 3,
            }
        }
    ) == {"input": 10, "output": 5, "cache_read": 7, "cache_write": 3}
    assert llm_metrics.extract_token_usage(
        {"usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 4, "cachedContentTokenCount": 2}}
    ) == {"input": 10, "output": 4, "cache_read": 2}
    assert llm_metrics.extract_token_usage({"choices": []}) == {}
    assert llm_metrics.extract_token_usage(None) == {}


def test_extract_usage_from_sse_stream() -> None:
    stream = (
        b'data: {"choices":[{"delta":{"content":"hi"}}],"usage":null}\n\n'
        b'data: {"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":3}}\n\n'
        b"data: [DONE]\n\n"
    )
    assert llm_metrics.extract_sse_usage(stream) == {"input": 9, "output": 3}

    anthropic_stream = (
        b"event: message_start\n"
        b'data: {"type":"message_start","message":{"usage":{"input_tokens":11,"output_tokens":1}}}\n\n'
        b"event: message_delta\n"
        b'data: {"type":"message_delta","usage":{"output_tokens":42}}\n\n'
    )
    assert llm_metrics.extract_sse_usage(anthropic_stream) == {"input": 11, "output": 42}
    assert llm_metrics.extract_sse_usage(b"data: not-json\n\n") == {}


# ---------------------------------------------------------------------------
# proxy request path
# ---------------------------------------------------------------------------


_LABELS_OK = {
    "product": "llm-gateway",
    "feature": "proxy",
    "infra_class": "cpu_local",
    "provider": "openai",
    "model": "qwen3.6-35b-a3b",
}


@pytest.mark.asyncio
async def test_successful_proxy_request_counts_one_execution_with_tokens(proxy_env) -> None:
    proxy_env.set_upstream(
        lambda req: httpx.Response(
            200,
            json={
                "id": "chatcmpl-1",
                "model": "qwen",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17},
            },
        )
    )
    labels = {**_LABELS_OK, "status": "ok", "caller": "awx-agent"}
    token_labels = {k: v for k, v in _LABELS_OK.items() if k != "feature"}
    hist_labels = dict(token_labels)

    before_req = _sample("llm_requests_total", labels)
    before_all = _total("llm_requests_total")
    before_in = _sample("llm_tokens_total", {**token_labels, "type": "input"})
    before_out = _sample("llm_tokens_total", {**token_labels, "type": "output"})
    before_hist = _sample("llm_request_duration_seconds_count", hist_labels)
    before_blocked = _total("llm_gateway_blocked_total")

    response = await proxy_env.handler.handle_request(
        _build_request(body=_CHAT_BODY, headers={"x-caller": "AWX-Agent"})
    )

    assert response.status_code == 200
    assert len(proxy_env.upstream_calls) == 1
    assert str(proxy_env.upstream_calls[0].url).startswith("http://10.40.5.106:8080/")
    assert _sample("llm_requests_total", labels) == before_req + 1
    assert _total("llm_requests_total") == before_all + 1
    assert _sample("llm_tokens_total", {**token_labels, "type": "input"}) == before_in + 12
    assert _sample("llm_tokens_total", {**token_labels, "type": "output"}) == before_out + 5
    assert _sample("llm_request_duration_seconds_count", hist_labels) == before_hist + 1
    assert _total("llm_gateway_blocked_total") == before_blocked
    assert _sample("llm_inflight_requests", {"product": "llm-gateway", "infra_class": "cpu_local"}) == 0


@pytest.mark.asyncio
async def test_agent_id_header_is_caller_fallback(proxy_env) -> None:
    proxy_env.set_upstream(lambda req: httpx.Response(200, json={"choices": [], "usage": {}}))
    labels = {**_LABELS_OK, "status": "ok", "caller": "agent-42"}
    before = _sample("llm_requests_total", labels)

    await proxy_env.handler.handle_request(_build_request(body=_CHAT_BODY, headers={"x-agent-id": "Agent-42"}))

    assert _sample("llm_requests_total", labels) == before + 1


@pytest.mark.asyncio
async def test_upstream_error_status_is_error(proxy_env) -> None:
    proxy_env.set_upstream(
        lambda req: httpx.Response(500, json={"error": {"message": "boom", "type": "server_error"}})
    )
    labels = {**_LABELS_OK, "status": "error", "caller": "anonymous"}
    before = _sample("llm_requests_total", labels)
    before_all = _total("llm_requests_total")
    before_blocked = _total("llm_gateway_blocked_total")

    response = await proxy_env.handler.handle_request(_build_request(body=_CHAT_BODY))

    assert response.status_code == 500
    assert _sample("llm_requests_total", labels) == before + 1
    assert _total("llm_requests_total") == before_all + 1
    assert _total("llm_gateway_blocked_total") == before_blocked


@pytest.mark.asyncio
async def test_upstream_connect_failure_is_error(proxy_env) -> None:
    def _refuse(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=req)

    proxy_env.set_upstream(_refuse)
    labels = {**_LABELS_OK, "status": "error", "caller": "anonymous"}
    before = _sample("llm_requests_total", labels)

    with pytest.raises(HTTPException) as exc_info:
        await proxy_env.handler.handle_request(_build_request(body=_CHAT_BODY))

    assert exc_info.value.status_code == 502
    assert _sample("llm_requests_total", labels) == before + 1


@pytest.mark.asyncio
async def test_upstream_timeout_status_is_timeout(proxy_env) -> None:
    def _timeout(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=req)

    proxy_env.set_upstream(_timeout)
    labels = {**_LABELS_OK, "status": "timeout", "caller": "anonymous"}
    hist_labels = {k: v for k, v in _LABELS_OK.items() if k != "feature"}
    before = _sample("llm_requests_total", labels)
    before_all = _total("llm_requests_total")
    before_hist = _sample("llm_request_duration_seconds_count", hist_labels)

    with pytest.raises(HTTPException):
        await proxy_env.handler.handle_request(_build_request(body=_CHAT_BODY))

    assert _sample("llm_requests_total", labels) == before + 1
    assert _total("llm_requests_total") == before_all + 1
    assert _sample("llm_request_duration_seconds_count", hist_labels) == before_hist + 1
    assert _sample("llm_inflight_requests", {"product": "llm-gateway", "infra_class": "cpu_local"}) == 0


@pytest.mark.asyncio
async def test_content_filter_block_counts_only_blocked(proxy_env) -> None:
    proxy_env.content_filter.check_request.return_value = {
        "action": SecurityAction.BLOCK,
        "reason": "PII",
        "counts": {"pii": 1},
        "detected": [{"type": "PII"}],
    }
    proxy_env.set_upstream(lambda req: httpx.Response(200, json={}))
    before_all = _total("llm_requests_total")
    before_blocked = _sample("llm_gateway_blocked_total", {"reason": "content_filter"})

    response = await proxy_env.handler.handle_request(_build_request(body=_CHAT_BODY))

    assert response.status_code == 403
    assert proxy_env.upstream_calls == []
    assert _total("llm_requests_total") == before_all
    assert _sample("llm_gateway_blocked_total", {"reason": "content_filter"}) == before_blocked + 1


@pytest.mark.asyncio
async def test_policy_block_counts_only_blocked(proxy_env) -> None:
    proxy_env.handler.policy_engine.evaluate_request = AsyncMock(
        return_value=PolicyDecision(decision=Decision.BLOCK, risk_score=5, reason="bad ip", ip_risk_score=5)
    )
    proxy_env.set_upstream(lambda req: httpx.Response(200, json={}))
    before_all = _total("llm_requests_total")
    before_blocked = _sample("llm_gateway_blocked_total", {"reason": "policy"})

    response = await proxy_env.handler.handle_request(_build_request(body=_CHAT_BODY))

    assert response.status_code == 403
    assert proxy_env.upstream_calls == []
    assert _total("llm_requests_total") == before_all
    assert _sample("llm_gateway_blocked_total", {"reason": "policy"}) == before_blocked + 1


@pytest.mark.asyncio
async def test_bad_api_key_counts_blocked_auth(proxy_env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "proxy_api_key_enabled", True)
    monkeypatch.setattr(settings, "proxy_api_key", "right-key")
    proxy_env.set_upstream(lambda req: httpx.Response(200, json={}))
    before_all = _total("llm_requests_total")
    before_blocked = _sample("llm_gateway_blocked_total", {"reason": "auth"})

    response = await proxy_env.handler.handle_request(
        _build_request(body=_CHAT_BODY, headers={"x-api-key": "wrong"})
    )

    assert response.status_code == 401
    assert _total("llm_requests_total") == before_all
    assert _sample("llm_gateway_blocked_total", {"reason": "auth"}) == before_blocked + 1


@pytest.mark.asyncio
async def test_sse_stream_counts_tokens_from_final_usage_chunk(proxy_env) -> None:
    stream = (
        b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
        b'data: {"choices":[],"usage":{"prompt_tokens":8,"completion_tokens":2}}\n\n'
        b"data: [DONE]\n\n"
    )
    proxy_env.set_upstream(
        lambda req: httpx.Response(200, content=stream, headers={"content-type": "text/event-stream"})
    )
    token_labels = {k: v for k, v in _LABELS_OK.items() if k != "feature"}
    before_out = _sample("llm_tokens_total", {**token_labels, "type": "output"})
    before_req = _sample("llm_requests_total", {**_LABELS_OK, "status": "ok", "caller": "anonymous"})

    await proxy_env.handler.handle_request(_build_request(body={**_CHAT_BODY, "stream": True}))

    assert _sample("llm_requests_total", {**_LABELS_OK, "status": "ok", "caller": "anonymous"}) == before_req + 1
    assert _sample("llm_tokens_total", {**token_labels, "type": "output"}) == before_out + 2


# ---------------------------------------------------------------------------
# /metrics route
# ---------------------------------------------------------------------------


def test_metrics_route_registered_before_catchall() -> None:
    os.environ.setdefault("ADMIN_API_KEY", "regression_test_key")
    os.environ.setdefault("POSTGRES_PASSWORD", "postgres")
    from gateway.main import app

    paths = [getattr(route, "path", None) for route in app.router.routes]
    assert "/metrics" in paths
    assert paths.index("/metrics") < paths.index("/{path:path}")


def test_metrics_endpoint_serves_prometheus_text_and_is_not_proxied() -> None:
    from fastapi.testclient import TestClient

    os.environ.setdefault("ADMIN_API_KEY", "regression_test_key")
    os.environ.setdefault("POSTGRES_PASSWORD", "postgres")
    from gateway.main import app

    fake_proxy = SimpleNamespace(handle_request=AsyncMock())
    previous = getattr(app.state, "proxy_handler", None)
    app.state.proxy_handler = fake_proxy
    try:
        response = TestClient(app).get("/metrics")
    finally:
        app.state.proxy_handler = previous

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "# TYPE llm_requests_total counter" in response.text
    assert "# TYPE llm_gateway_blocked_total counter" in response.text
    fake_proxy.handle_request.assert_not_called()


def test_rate_limiter_does_not_classify_metrics_as_proxy_traffic() -> None:
    from gateway.middleware.rate_limit import RateLimitMiddleware

    middleware = RateLimitMiddleware(app=Mock())
    assert middleware._classify_path("/metrics") is None
    assert middleware._classify_path("/metrics", "HEAD") is None
    # Variants that the catch-all proxies upstream stay rate limited.
    assert middleware._classify_path("/metrics/") == "proxy"
    assert middleware._classify_path("/metrics", "POST") == "proxy"


# ---------------------------------------------------------------------------
# multiprocess mode
# ---------------------------------------------------------------------------


def _run_py(code: str, multiproc_dir: Path) -> str:
    env = {
        **os.environ,
        "PROMETHEUS_MULTIPROC_DIR": str(multiproc_dir),
        "PYTHONPATH": str(REPO_ROOT),
    }
    env.pop("LLM_INFRA_CLASS_MAP", None)
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        env=env,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_multiprocess_mode_aggregates_workers_and_reaps_dead_gauges(tmp_path: Path) -> None:
    worker = """
        from gateway.integrations import llm_metrics
        ex = llm_metrics.LLMExecution(
            target_url="http://10.40.5.106:8080/v1/chat/completions",
            provider="openai", model="qwen", caller="awx",
        )
        ex.mark_response(200)
        ex.usage = {"input": 10, "output": 2}
        ex.finish()
        # A second execution that never finishes: this process dies with inflight=1.
        llm_metrics.LLMExecution(
            target_url="http://10.40.5.106:8080/v1/chat/completions",
            provider="openai", model="qwen", caller="awx",
        )
    """
    _run_py(worker, tmp_path)
    _run_py(worker, tmp_path)

    scrape = """
        from gateway.integrations import llm_metrics
        body, content_type = llm_metrics.render_metrics()
        print(body.decode())
    """
    text = _run_py(scrape, tmp_path)

    assert (
        'llm_requests_total{caller="awx",feature="proxy",infra_class="cpu_local",'
        'model="qwen",product="llm-gateway",provider="openai",status="ok"} 2.0'
    ) in text
    assert (
        'llm_tokens_total{infra_class="cpu_local",model="qwen",product="llm-gateway",'
        'provider="openai",type="input"} 20.0'
    ) in text
    # Both writer processes are dead, so their livesum gauge files are reaped on scrape.
    assert 'llm_inflight_requests{infra_class="cpu_local",product="llm-gateway"} 1.0' not in text
    assert 'llm_inflight_requests{infra_class="cpu_local",product="llm-gateway"} 2.0' not in text
    assert not list(tmp_path.glob("gauge_livesum_*.db"))


def test_prepare_multiproc_dir_wipes_stale_files(tmp_path: Path) -> None:
    stale = tmp_path / "counter_12345.db"
    stale.write_bytes(b"stale")
    llm_metrics.prepare_multiproc_dir(str(tmp_path))
    assert tmp_path.exists()
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# review hardening: label bounds, blocked accounting, /metrics exposure
# ---------------------------------------------------------------------------


def test_upstream_rejected_model_does_not_mint_a_label(proxy_env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm_metrics, "_model_bound", llm_metrics.BoundedLabel(limit=32))
    ex = llm_metrics.LLMExecution(
        target_url="http://10.40.5.106:8080", provider="openai", model="Junk-Model-1", caller=None
    )
    ex.mark_response(404)
    ex.finish()
    rejected = {**_LABELS_OK, "model": "other", "status": "error", "caller": "anonymous"}
    assert _sample("llm_requests_total", rejected) >= 1
    assert _sample("llm_requests_total", {**rejected, "model": "junk-model-1"}) == 0
    assert llm_metrics._model_bound("junk-model-1", admit=False) == "other"


def test_caller_model_pairs_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm_metrics, "_caller_bound", llm_metrics.BoundedLabel(limit=64))
    monkeypatch.setattr(llm_metrics, "_caller_model_pair_bound", llm_metrics.BoundedLabel(limit=1))
    labels = {**_LABELS_OK, "model": "pair-cap-model", "status": "ok"}
    for caller in ("pair-a", "pair-b"):
        ex = llm_metrics.LLMExecution(
            target_url="http://10.40.5.106:8080", provider="openai", model="pair-cap-model", caller=caller
        )
        ex.mark_response(200)
        ex.finish()
    assert _sample("llm_requests_total", {**labels, "caller": "pair-a"}) == 1
    assert _sample("llm_requests_total", {**labels, "caller": "pair-b"}) == 0
    assert _sample("llm_requests_total", {**labels, "caller": "other"}) == 1


def test_inflight_released_when_upstream_responds() -> None:
    gauge = {"product": "llm-gateway", "infra_class": "gpu_offprem"}
    ex = llm_metrics.LLMExecution(
        target_url="https://x.proxy.runpod.net", provider="vllm", model="m", caller=None
    )
    assert _sample("llm_inflight_requests", gauge) == 1
    ex.mark_response(200)
    assert _sample("llm_inflight_requests", gauge) == 0  # before gateway post-processing
    ex.finish()
    assert _sample("llm_inflight_requests", gauge) == 0


@pytest.mark.asyncio
async def test_verified_agent_id_beats_agent_header_for_caller(proxy_env) -> None:
    proxy_env.set_upstream(lambda req: httpx.Response(200, json={"choices": [], "usage": {}}))
    labels = {**_LABELS_OK, "status": "ok"}
    before_verified = _sample("llm_requests_total", {**labels, "caller": "agent-verified"})
    before_spoofed = _sample("llm_requests_total", {**labels, "caller": "agent-spoofed"})

    request = _build_request(body=_CHAT_BODY, headers={"x-agent-id": "agent-spoofed"})
    request.state.agent_context = {"agent_id": "agent-verified"}
    await proxy_env.handler.handle_request(request)

    assert _sample("llm_requests_total", {**labels, "caller": "agent-verified"}) == before_verified + 1
    assert _sample("llm_requests_total", {**labels, "caller": "agent-spoofed"}) == before_spoofed


@pytest.mark.asyncio
async def test_non_post_refusal_is_not_counted_as_blocked(proxy_env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "proxy_api_key_enabled", True)
    monkeypatch.setattr(settings, "proxy_api_key", "right-key")
    request = _build_request(path="/v1/models", headers={"x-api-key": "wrong"})
    request.scope["method"] = "GET"
    before_blocked = _total("llm_gateway_blocked_total")

    response = await proxy_env.handler.handle_request(request)

    assert response.status_code == 401
    assert _total("llm_gateway_blocked_total") == before_blocked


@pytest.mark.asyncio
async def test_internal_error_before_upstream_is_not_counted_as_blocked(proxy_env) -> None:
    proxy_env.handler.policy_engine.evaluate_request = AsyncMock(side_effect=RuntimeError("redis down"))
    before_blocked = _total("llm_gateway_blocked_total")

    with pytest.raises(RuntimeError):
        await proxy_env.handler.handle_request(_build_request(body=_CHAT_BODY))

    assert _total("llm_gateway_blocked_total") == before_blocked


def test_rate_limited_get_is_not_counted_as_llm_block(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from gateway.middleware.rate_limit import RateLimitMiddleware

    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)
    monkeypatch.setattr(settings, "rate_limit_proxy_requests", 1)
    app = FastAPI()

    @app.api_route("/v1/models", methods=["GET", "POST"])
    async def models() -> dict:
        return {"ok": True}

    app.add_middleware(RateLimitMiddleware)
    client = TestClient(app)
    before = _sample("llm_gateway_blocked_total", {"reason": "rate_limit"})

    assert client.get("/v1/models").status_code == 200
    assert client.get("/v1/models").status_code == 429
    assert _sample("llm_gateway_blocked_total", {"reason": "rate_limit"}) == before
    assert client.post("/v1/models", json={}).status_code == 429
    assert _sample("llm_gateway_blocked_total", {"reason": "rate_limit"}) == before + 1


@pytest.mark.parametrize("header", ["x-forwarded-for", "x-real-ip", "forwarded", "cf-connecting-ip"])
def test_metrics_refused_when_reached_through_a_proxy(header: str) -> None:
    from fastapi.testclient import TestClient

    os.environ.setdefault("ADMIN_API_KEY", "regression_test_key")
    os.environ.setdefault("POSTGRES_PASSWORD", "postgres")
    from gateway.main import app

    fake_proxy = SimpleNamespace(handle_request=AsyncMock())
    previous = getattr(app.state, "proxy_handler", None)
    app.state.proxy_handler = fake_proxy
    try:
        response = TestClient(app).get("/metrics", headers={header: "203.0.113.7"})
    finally:
        app.state.proxy_handler = previous

    assert response.status_code == 404
    assert "llm_requests_total" not in response.text
    fake_proxy.handle_request.assert_not_called()


def test_gemini_thinking_tokens_count_as_output() -> None:
    assert llm_metrics.extract_token_usage(
        {"usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 200, "thoughtsTokenCount": 2000}}
    ) == {"input": 10, "output": 2200}


def test_sse_null_usage_chunks_are_not_json_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    real_loads = json.loads
    monkeypatch.setattr(llm_metrics.json, "loads", lambda data: calls.append(data) or real_loads(data))
    stream = b"".join(
        b'data: {"choices":[{"delta":{"content":"x"}}],"usage": null}\n\n' for _ in range(50)
    ) + b'data: {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":1}}\n\n'

    assert llm_metrics.extract_sse_usage(stream) == {"input": 4, "output": 1}
    assert len(calls) == 1


def test_unwritable_multiproc_dir_does_not_break_import(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    out = _run_py(
        """
        from gateway.integrations import llm_metrics
        print("imported")
        """,
        blocker / "sub",
    )
    assert "imported" in out
