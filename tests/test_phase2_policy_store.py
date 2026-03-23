"""Phase 2 policy/entitlement store tests."""

import pytest

from gateway.policy.store import PolicyStore


@pytest.mark.asyncio
async def test_default_policy_presence() -> None:
    store = PolicyStore()
    pii_policy = store.get_policy("pii_detection")
    assert pii_policy["enabled"] is True
    assert pii_policy["action_on_detect"] == "BLOCK"


@pytest.mark.asyncio
async def test_policy_update_fallback_versioning() -> None:
    store = PolicyStore()
    updated, version = await store.update_policy(
        name="pii_detection",
        updates={"action_on_detect": "LOG_ONLY"},
        changed_by="test",
        change_note="unit update",
    )
    assert version >= 2
    assert updated["action_on_detect"] == "LOG_ONLY"


@pytest.mark.asyncio
async def test_entitlement_deep_merge() -> None:
    store = PolicyStore()
    entitlements, version = await store.update_entitlements(
        updates={"providers": {"openai": True, "anthropic": True}},
        changed_by="test",
        change_note="enable anthropic",
    )
    assert version >= 2
    assert entitlements["providers"]["openai"] is True
    assert entitlements["providers"]["anthropic"] is True
    assert entitlements["modules"]["pii_detection"] is True


@pytest.mark.asyncio
async def test_provider_entitlement_gate() -> None:
    store = PolicyStore()
    assert store.is_provider_enabled("openai") is True
    assert store.is_provider_enabled("anthropic") is False
