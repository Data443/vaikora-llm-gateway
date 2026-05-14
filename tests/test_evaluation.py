"""Tests for the /v1/evaluate, /v1/modules/check, /v1/policies, /v1/audit endpoints."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.api.evaluation import evaluation_router
from gateway.services.content_filter import SecurityAction


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.include_router(evaluation_router)
    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _stub_audit_logger():
    with patch("gateway.api.evaluation.audit_logger") as mock_logger:
        mock_logger.log_decision = AsyncMock(return_value=None)
        yield mock_logger


def _stub_check_request(detections: List[Dict[str, Any]], action: SecurityAction) -> Dict[str, Any]:
    return {"action": action, "detected": detections, "reason": "stubbed"}


def test_evaluate_allows_clean_action(client: TestClient) -> None:
    with patch("gateway.api.evaluation.get_content_filter") as mock_get:
        mock_get.return_value.check_request.return_value = _stub_check_request(
            [], SecurityAction.PASS
        )
        response = client.post("/v1/evaluate", json={"action": "list files"})

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["outcome"] == "ALLOW"
    assert body["pipeline"] == []
    assert body["receipt_id"].startswith("sha256:")
    assert body["latency_ms"] >= 0


def test_evaluate_blocks_on_pii(client: TestClient) -> None:
    detection = {
        "action": SecurityAction.BLOCK,
        "type": "ssn_detected",
        "reason": "ssn_detected",
        "policy": "pii_detection",
        "module": "pii_detection",
        "severity": "HIGH",
    }
    with patch("gateway.api.evaluation.get_content_filter") as mock_get:
        mock_get.return_value.check_request.return_value = _stub_check_request(
            [detection], SecurityAction.BLOCK
        )
        response = client.post("/v1/evaluate", json={"action": "email SSN 123-45-6789 to acme"})

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["outcome"] == "BLOCK"
    assert body["decision"]["matched_policy"] == "pii_detection"
    assert body["decision"]["severity"] == "HIGH"
    assert len(body["pipeline"]) == 1


def test_evaluate_returns_constraint(client: TestClient) -> None:
    detection = {
        "action": SecurityAction.CONSTRAIN,
        "reason": "redact_ssn",
        "policy": "pii_detection",
        "severity": "MEDIUM",
        "constraint": {"redact": ["SSN"]},
    }
    with patch("gateway.api.evaluation.get_content_filter") as mock_get:
        mock_get.return_value.check_request.return_value = _stub_check_request(
            [detection], SecurityAction.CONSTRAIN
        )
        response = client.post("/v1/evaluate", json={"action": "summarize this"})

    body = response.json()
    assert body["decision"]["outcome"] == "CONSTRAIN"
    assert body["decision"]["constraint"] == {"redact": ["SSN"]}


def test_evaluate_rejects_empty_action(client: TestClient) -> None:
    response = client.post("/v1/evaluate", json={"action": ""})
    assert response.status_code == 422


def test_modules_check_pii_module(client: TestClient) -> None:
    detection = {
        "action": SecurityAction.BLOCK,
        "type": "ssn_detected",
        "reason": "ssn_detected",
        "severity": "HIGH",
    }
    with patch("gateway.api.evaluation.get_content_filter") as mock_get:
        mock_get.return_value.check_pii.return_value = [detection]
        response = client.post(
            "/v1/modules/check",
            json={"module": "pii_detection", "text": "SSN 123-45-6789"},
        )

    body = response.json()
    assert response.status_code == 200
    assert body["decision"]["outcome"] == "BLOCK"
    assert body["decision"]["matched_policy"] == "pii_detection"


def test_modules_check_returns_allow_when_no_signal(client: TestClient) -> None:
    with patch("gateway.api.evaluation.get_content_filter") as mock_get:
        mock_get.return_value.check_jailbreak_attempts.return_value = []
        response = client.post(
            "/v1/modules/check",
            json={"module": "jailbreak_detection", "text": "what is the weather"},
        )

    body = response.json()
    assert response.status_code == 200
    assert body["decision"]["outcome"] == "ALLOW"
    assert body["decision"]["matched_policy"] == "jailbreak_detection"


def test_modules_check_rejects_unknown_module(client: TestClient) -> None:
    response = client.post(
        "/v1/modules/check",
        json={"module": "magic_module", "text": "hello"},
    )
    assert response.status_code == 422  # Literal field rejects unknown values


def test_get_policies_returns_combined_config(client: TestClient) -> None:
    with patch("gateway.api.evaluation.policy_store") as mock_store:
        mock_store.list_policies.return_value = [
            {
                "name": "pii_detection",
                "enabled": True,
                "config": {"enabled": True, "action_on_detect": "BLOCK"},
            }
        ]
        mock_store.get_entitlements.return_value = {"providers": {"openai": True}}
        mock_store.get_entitlements_version = AsyncMock(return_value=7)
        response = client.get("/v1/policies")

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == 7
    assert body["policies"]["pii_detection"]["enabled"] is True


def test_audit_write_requires_admin(client: TestClient) -> None:
    # Explicitly enable admin auth so require_admin_auth rejects unauthenticated calls.
    # Pre-fix this test relied on a parameter-binding bug (require_admin_auth bound
    # as default value instead of Depends()), which made `_` a required query param
    # and returned 422. Now that Depends() is wired correctly, the test needs to
    # enable admin auth in settings to exercise the rejection path.
    from gateway.core.config import settings as gw_settings
    with patch.object(gw_settings, "admin_auth_enabled", True), \
         patch.object(gw_settings, "admin_auth_mode", "api_key"), \
         patch.object(gw_settings, "admin_api_key", "valid_admin_key_for_test"):
        response = client.post(
            "/v1/audit",
            json={
                "action": "rotate api key",
                "decision": "ALLOW",
                "receipt_id": "sha256:abc",
            },
        )
    assert response.status_code in (401, 403)
