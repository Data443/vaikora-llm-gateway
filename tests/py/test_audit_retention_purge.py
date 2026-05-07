"""Retention purge helper tests."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.core.config import settings
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


class _AcquireContext:
    def __init__(self, conn) -> None:
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _TransactionContext:
    async def __aenter__(self):
        return None

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_purge_uses_integer_day_intervals(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = AuditLogger()
    logger.connected = True

    execute = AsyncMock(side_effect=["DELETE 1", "DELETE 2", "DELETE 3", "DELETE 4"])
    conn = SimpleNamespace(
        execute=execute,
        transaction=lambda: _TransactionContext(),
    )
    logger.pool = SimpleNamespace(acquire=lambda: _AcquireContext(conn))

    monkeypatch.setattr(settings, "audit_retention_days", 30)
    monkeypatch.setattr(settings, "agent_interaction_retention_days", 14)

    result = await logger.purge_expired_records()

    assert result == {
        "audit_log_deleted": 1,
        "events_deleted": 2,
        "interaction_reviews_deleted": 3,
        "agent_interactions_deleted": 4,
    }
    first_query = execute.await_args_list[0].args[0]
    assert "make_interval(days => $1::int)" in first_query
    assert execute.await_args_list[0].args[1] == 30
