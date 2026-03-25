"""Admin domain-risk and email-classification policy endpoint tests."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gateway.api import admin as admin_api


@pytest.mark.asyncio
async def test_get_domain_risk_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        admin_api.policy_store,
        "get_policy_with_version",
        AsyncMock(
            return_value=(
                {"enabled": True, "action_on_detect": "BLOCK", "severity_threshold": "MEDIUM"},
                2,
            )
        ),
    )

    response = await admin_api.get_domain_risk_policy()
    assert response.success is True
    assert response.version == 2


@pytest.mark.asyncio
async def test_update_domain_risk_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        admin_api.policy_store,
        "update_policy",
        AsyncMock(
            return_value=(
                {"enabled": True, "action_on_detect": "LOG_ONLY", "severity_threshold": "LOW"},
                3,
            )
        ),
    )

    response = await admin_api.update_domain_risk_policy(admin_api.PolicyUpdate(action="LOG_ONLY"))
    assert response.success is True
    assert response.version == 3


@pytest.mark.asyncio
async def test_get_email_classification_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        admin_api.policy_store,
        "get_policy_with_version",
        AsyncMock(
            return_value=(
                {"enabled": False, "action_on_detect": "LOG_ONLY", "severity_threshold": "MEDIUM"},
                1,
            )
        ),
    )

    response = await admin_api.get_email_classification_policy()
    assert response.success is True
    assert response.version == 1


@pytest.mark.asyncio
async def test_update_email_classification_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        admin_api.policy_store,
        "update_policy",
        AsyncMock(
            return_value=(
                {"enabled": True, "action_on_detect": "BLOCK", "severity_threshold": "LOW"},
                4,
            )
        ),
    )

    response = await admin_api.update_email_classification_policy(admin_api.PolicyUpdate(action="BLOCK"))
    assert response.success is True
    assert response.version == 4
