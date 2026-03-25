"""Phase 3 agent-control API unit tests."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from gateway.api import agent_control as agent_api


def _agent_record(agent_id: str = "agent-1") -> dict:
    return {
        "agent_id": agent_id,
        "display_name": "Agent One",
        "agent_type": "assistant",
        "status": "ACTIVE",
        "wrapped": False,
        "metadata": {"source": "test"},
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "created_by": "tester",
        "updated_by": "tester",
    }


@pytest.mark.asyncio
async def test_create_agent_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent_api.agent_registry,
        "create_or_wrap_agent",
        AsyncMock(return_value=_agent_record("agent-1")),
    )

    response = await agent_api.create_agent(
        agent_api.AgentUpsertRequest(
            agent_id="agent-1",
            display_name="Agent One",
            agent_type="assistant",
            wrapped=False,
            status="ACTIVE",
        )
    )

    assert response.success is True
    assert response.agent.agent_id == "agent-1"
    assert response.agent.status == "ACTIVE"


@pytest.mark.asyncio
async def test_get_agent_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_api.agent_registry, "get_agent", AsyncMock(return_value=None))

    with pytest.raises(HTTPException) as exc:
        await agent_api.get_agent("missing-agent")

    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_upsert_agent_link_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent_api.agent_registry,
        "upsert_link",
        AsyncMock(
            return_value={
                "source_agent_id": "agent-1",
                "target_agent_id": "agent-2",
                "protocol": "A2A",
                "status": "ACTIVE",
                "metadata": {"source": "test"},
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                "created_by": "tester",
                "updated_by": "tester",
            }
        ),
    )

    response = await agent_api.upsert_agent_link(
        agent_api.AgentLinkRequest(
            source_agent_id="agent-1",
            target_agent_id="agent-2",
            protocol="A2A",
            status="ACTIVE",
        )
    )

    assert response.success is True
    assert response.link.source_agent_id == "agent-1"
    assert response.link.target_agent_id == "agent-2"


@pytest.mark.asyncio
async def test_create_and_approve_a2a_interaction(monkeypatch: pytest.MonkeyPatch) -> None:
    created = {
        "interaction_id": "int-123",
        "source_agent_id": "agent-1",
        "target_agent_id": "agent-2",
        "review_status": "PENDING",
        "payload": {"intent": "handoff"},
        "metadata": {"source": "test"},
        "decision_reason": None,
        "reviewed_by": "tester",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    approved = {
        **created,
        "review_status": "APPROVED",
        "decision_reason": "looks safe",
        "reviewed_by": "reviewer",
    }

    monkeypatch.setattr(
        agent_api.agent_registry,
        "create_interaction",
        AsyncMock(return_value=created),
    )
    monkeypatch.setattr(
        agent_api.agent_registry,
        "review_interaction",
        AsyncMock(return_value=approved),
    )

    create_response = await agent_api.create_a2a_interaction(
        agent_api.A2AInteractionCreateRequest(
            source_agent_id="agent-1",
            target_agent_id="agent-2",
            payload={"intent": "handoff"},
        )
    )
    assert create_response.success is True
    assert create_response.interaction.review_status == "PENDING"

    approve_response = await agent_api.approve_a2a_interaction(
        "int-123",
        agent_api.A2AInteractionReviewRequest(
            reviewed_by="reviewer",
            reason="looks safe",
        ),
    )
    assert approve_response.success is True
    assert approve_response.interaction.review_status == "APPROVED"