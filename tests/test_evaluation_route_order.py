"""Regression tests for the evaluation router's route resolution order.

The original PR #3 mounted evaluation_router AFTER public_router. Because
public_router declares `/{path:path}` as a generic upstream-LLM proxy, every
/v1/evaluate, /v1/modules/check, /v1/policies, /v1/audit request was being
swallowed by the catch-all and forwarded to OpenAI (which 404s).

These tests load the real `gateway.main:app` and verify that the four
evaluation routes resolve to the evaluation_router handlers, not the
proxy catch-all. They also assert the response shapes are sane so that
silent route swallowing is caught at unit-test time, not at deployment.
"""

from __future__ import annotations

import os
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def app_with_routers():
    # Ensure required env so settings don't fail to load.
    os.environ.setdefault("ADMIN_API_KEY", "regression_test_key")
    os.environ.setdefault("POSTGRES_PASSWORD", "postgres")
    from gateway.main import app  # noqa: WPS433 (intentional lazy import)
    return app


@pytest.fixture()
def client(app_with_routers) -> TestClient:
    return TestClient(app_with_routers)


def _route_paths(app) -> list[str]:
    paths: list[str] = []
    for route in app.router.routes:
        path = getattr(route, "path", None)
        if path:
            paths.append(path)
    return paths


def test_evaluation_routes_registered_before_catchall(app_with_routers) -> None:
    """The four /v1 routes must precede the proxy catch-all so they resolve first."""
    paths = _route_paths(app_with_routers)

    catch_all_index = next(
        (i for i, p in enumerate(paths) if p == "/{path:path}"),
        None,
    )
    assert catch_all_index is not None, "public_router catch-all not found"

    for required in ("/v1/evaluate", "/v1/modules/check", "/v1/policies", "/v1/audit"):
        idx = next((i for i, p in enumerate(paths) if p == required), None)
        assert idx is not None, f"{required} route not registered"
        assert idx < catch_all_index, (
            f"{required} must register BEFORE /{{path:path}} or it gets swallowed "
            f"by the upstream-LLM proxy"
        )


def test_post_v1_evaluate_does_not_proxy_to_upstream(client: TestClient) -> None:
    """Direct hit on /v1/evaluate should never produce a Cloudflare 404
    from an upstream OpenAI/Anthropic provider. If it does, the route is
    being caught by /{path:path} instead of evaluation_router."""
    resp = client.post(
        "/v1/evaluate",
        json={"action": "list files", "context": {"agent_id": "regression"}},
    )
    # Real handler returns 200 with EnforcementResult.
    # Proxy catch-all forwards to OpenAI, gets 404, and bubbles back as 404
    # or 500 with an OpenAI/Cloudflare error body.
    assert resp.status_code == 200, (
        f"Expected 200 from evaluation_router; got {resp.status_code}. "
        f"Body: {resp.text[:300]}"
    )
    body: Dict[str, Any] = resp.json()
    assert "decision" in body, "Response shape does not match EnforcementResult"
    assert "receipt_id" in body
    assert body["receipt_id"].startswith("sha256:")


def test_get_v1_policies_returns_combined_config(client: TestClient) -> None:
    """Regression: get_policies previously called a non-existent get_version()."""
    resp = client.get("/v1/policies")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "policies" in body
    assert "entitlements" in body
    assert isinstance(body.get("version"), int)


def test_post_v1_audit_accepts_valid_payload(client: TestClient) -> None:
    """Regression: write_audit previously bound require_admin_auth as a
    default value (without Depends()), turning `_` into a required query
    parameter and breaking every POST."""
    resp = client.post(
        "/v1/audit",
        json={
            "action": "regression_test",
            "decision": "ALLOW",
            "receipt_id": "sha256:regression_test_001",
            "metadata": {"source": "pytest"},
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body.get("stored") is True
    assert body.get("receipt_id") == "sha256:regression_test_001"
