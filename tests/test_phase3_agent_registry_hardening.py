"""Agent registry governance hardening tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from gateway.core.config import settings
from gateway.services.agent_registry import AgentRegistry, _utc_now


@pytest.mark.asyncio
async def test_create_interaction_requires_active_link(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = AgentRegistry()

    monkeypatch.setattr(settings, "agent_link_enforcement_enabled", True)

    await registry.create_or_wrap_agent(
        agent_id="agent-source",
        display_name="Source",
        agent_type="assistant",
        wrapped=False,
        status="ACTIVE",
    )
    await registry.create_or_wrap_agent(
        agent_id="agent-target",
        display_name="Target",
        agent_type="assistant",
        wrapped=False,
        status="ACTIVE",
    )

    with pytest.raises(ValueError) as exc:
        await registry.create_interaction(
            source_agent_id="agent-source",
            target_agent_id="agent-target",
            payload={"intent": "handoff"},
        )
    assert "No active A2A link approved" in str(exc.value)

    await registry.upsert_link(
        source_agent_id="agent-source",
        target_agent_id="agent-target",
        protocol="A2A",
        status="ACTIVE",
    )

    record = await registry.create_interaction(
        source_agent_id="agent-source",
        target_agent_id="agent-target",
        payload={"intent": "handoff"},
    )
    assert record["review_status"] == "PENDING"


@pytest.mark.asyncio
async def test_create_interaction_enforces_agent_metadata_constraints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = AgentRegistry()

    monkeypatch.setattr(settings, "agent_link_enforcement_enabled", True)

    await registry.create_or_wrap_agent(
        agent_id="agent-source",
        display_name="Source",
        agent_type="assistant",
        wrapped=False,
        status="ACTIVE",
        metadata={"allowed_target_agent_types": ["assistant"]},
    )
    await registry.create_or_wrap_agent(
        agent_id="agent-target",
        display_name="Target",
        agent_type="researcher",
        wrapped=False,
        status="ACTIVE",
    )
    await registry.upsert_link(
        source_agent_id="agent-source",
        target_agent_id="agent-target",
        protocol="A2A",
        status="ACTIVE",
    )

    with pytest.raises(ValueError) as exc:
        await registry.create_interaction(
            source_agent_id="agent-source",
            target_agent_id="agent-target",
            payload={"intent": "handoff"},
        )

    assert "Interaction denied by source agent type policy" in str(exc.value)


@pytest.mark.asyncio
async def test_list_interactions_applies_retention_and_agent_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = AgentRegistry()

    monkeypatch.setattr(settings, "agent_link_enforcement_enabled", True)
    monkeypatch.setattr(settings, "agent_interaction_retention_days", 1)

    await registry.create_or_wrap_agent(
        agent_id="agent-source",
        display_name="Source",
        agent_type="assistant",
        wrapped=False,
        status="ACTIVE",
    )
    await registry.create_or_wrap_agent(
        agent_id="agent-target",
        display_name="Target",
        agent_type="assistant",
        wrapped=False,
        status="ACTIVE",
    )
    await registry.upsert_link(
        source_agent_id="agent-source",
        target_agent_id="agent-target",
        protocol="A2A",
        status="ACTIVE",
    )

    recent = await registry.create_interaction(
        source_agent_id="agent-source",
        target_agent_id="agent-target",
        payload={"intent": "recent"},
    )

    old_id = "interaction-old"
    registry._interactions[old_id] = {
        "interaction_id": old_id,
        "source_agent_id": "agent-source",
        "target_agent_id": "agent-target",
        "review_status": "PENDING",
        "payload": {"intent": "old"},
        "metadata": {},
        "decision_reason": None,
        "reviewed_by": "tester",
        "created_at": _utc_now() - timedelta(days=3),
        "updated_at": _utc_now() - timedelta(days=3),
    }

    items = await registry.list_interactions(agent_id="agent-source", limit=20, offset=0)
    ids = {item["interaction_id"] for item in items}

    assert recent["interaction_id"] in ids
    assert old_id not in ids
