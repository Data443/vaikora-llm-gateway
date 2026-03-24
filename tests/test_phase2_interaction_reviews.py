"""Phase 2 interaction review endpoint tests."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from gateway.api import admin as admin_api


@pytest.mark.asyncio
async def test_approve_interaction_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Approve endpoint should persist and return review status."""
    monkeypatch.setattr(admin_api.audit_logger, "connected", True)
    monkeypatch.setattr(
        admin_api.audit_logger,
        "get_latest_gateway_event_by_request_id",
        AsyncMock(return_value={"id": 11, "request_id": "req-123", "decision": "ALLOW_LOG", "risk_score": 70}),
    )
    monkeypatch.setattr(
        admin_api.audit_logger,
        "upsert_interaction_review",
        AsyncMock(
            return_value={
                "request_id": "req-123",
                "review_status": "APPROVED",
                "reviewed_at": datetime.now(timezone.utc),
                "reviewed_by": "qa-user",
                "reason": "validated as safe",
                "source_event_id": 11,
                "source_decision": "ALLOW_LOG",
                "source_risk_score": 70,
                "metadata": {"ticket": "SEC-42"},
            }
        ),
    )

    response = await admin_api.approve_interaction(
        "req-123",
        admin_api.InteractionReviewRequest(
            reviewed_by="qa-user",
            reason="validated as safe",
            metadata={"ticket": "SEC-42"},
        ),
    )

    assert response.success is True
    assert response.request_id == "req-123"
    assert response.review.review_status == "APPROVED"
    assert response.review.source_event_id == 11
    assert response.review.metadata["ticket"] == "SEC-42"


@pytest.mark.asyncio
async def test_block_interaction_missing_event_returns_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Block endpoint should return 404 when request id does not exist in events."""
    monkeypatch.setattr(admin_api.audit_logger, "connected", True)
    monkeypatch.setattr(
        admin_api.audit_logger,
        "get_latest_gateway_event_by_request_id",
        AsyncMock(return_value=None),
    )

    with pytest.raises(HTTPException) as exc:
        await admin_api.block_interaction(
            "missing-request-id",
            admin_api.InteractionReviewRequest(reviewed_by="admin", reason="manual block"),
        )

    assert exc.value.status_code == 404
    assert "No gateway event found" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_get_interaction_review_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Get interaction review should return the stored review payload."""
    monkeypatch.setattr(admin_api.audit_logger, "connected", True)
    monkeypatch.setattr(
        admin_api.audit_logger,
        "get_interaction_review",
        AsyncMock(
            return_value={
                "request_id": "req-999",
                "review_status": "BLOCKED",
                "reviewed_at": datetime.now(timezone.utc),
                "reviewed_by": "security-admin",
                "reason": "policy override",
                "source_event_id": 7,
                "source_decision": "ALLOW_LOG",
                "source_risk_score": 60,
                "metadata": {"reason_code": "manual_override"},
            }
        ),
    )

    response = await admin_api.get_interaction_review("req-999")

    assert response.success is True
    assert response.request_id == "req-999"
    assert response.review.review_status == "BLOCKED"
    assert response.review.reviewed_by == "security-admin"


@pytest.mark.asyncio
async def test_interaction_review_store_unavailable_returns_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Endpoints should return 503 when interaction review store is unavailable."""
    monkeypatch.setattr(admin_api.audit_logger, "connected", False)

    with pytest.raises(HTTPException) as exc:
        await admin_api.get_interaction_review("req-any")

    assert exc.value.status_code == 503
