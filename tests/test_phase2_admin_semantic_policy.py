"""Admin semantic policy endpoint tests."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gateway.api import admin as admin_api


@pytest.mark.asyncio
async def test_get_semantic_policy_returns_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        admin_api.policy_store,
        "get_policy_with_version",
        AsyncMock(
            return_value=(
                {
                    "enabled": True,
                    "action_on_detect": "CONSTRAIN",
                    "severity_threshold": "MEDIUM",
                },
                3,
            )
        ),
    )

    response = await admin_api.get_semantic_policy()
    assert response.success is True
    assert response.version == 3
    assert response.policy["action_on_detect"] == "CONSTRAIN"


@pytest.mark.asyncio
async def test_update_semantic_policy_calls_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        admin_api.policy_store,
        "update_policy",
        AsyncMock(
            return_value=(
                {
                    "enabled": True,
                    "action_on_detect": "LOG_ONLY",
                    "severity_threshold": "LOW",
                },
                4,
            )
        ),
    )

    payload = admin_api.PolicyUpdate(action="LOG_ONLY", severity_threshold="low")
    response = await admin_api.update_semantic_policy(payload)

    assert response.success is True
    assert response.version == 4
    assert response.policy["action_on_detect"] == "LOG_ONLY"
