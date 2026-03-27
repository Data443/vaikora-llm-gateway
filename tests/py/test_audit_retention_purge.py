"""Retention purge helper tests."""

from __future__ import annotations

import pytest

from gateway.integrations.audit import AuditLogger


def test_rows_affected_parsing() -> None:
    assert AuditLogger._rows_affected("DELETE 42") == 42
    assert AuditLogger._rows_affected("UPDATE 0") == 0
    assert AuditLogger._rows_affected("BAD") == 0


@pytest.mark.asyncio
async def test_purge_returns_zero_when_not_connected() -> None:
    logger = AuditLogger()
    logger.connected = False

    result = await logger.purge_expired_records()

    assert result == {
        "audit_log_deleted": 0,
        "events_deleted": 0,
        "interaction_reviews_deleted": 0,
        "agent_interactions_deleted": 0,
    }
