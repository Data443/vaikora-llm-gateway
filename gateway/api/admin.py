"""
Data443 LLM Gateway - Admin API for Policy and Entitlement Management.

All policy updates are versioned and persisted when PostgreSQL is available.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from loguru import logger

from gateway.core.config import settings
from gateway.api.auth import require_admin_auth
from gateway.integrations.audit import audit_logger
from gateway.policy.store import policy_store


admin_router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin_auth)],
)


_REDACTED_VALUE = "***REDACTED***"
_SENSITIVE_EXACT_KEYS = {"secret", "password", "api_key", "apikey", "token"}


class PolicyUpdate(BaseModel):
    """Request to update a policy."""
    enabled: Optional[bool] = None
    action: Optional[str] = None
    action_on_detect: Optional[str] = None
    severity_threshold: Optional[str] = None
    max_attempts: Optional[int] = None
    secret: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    changed_by: Optional[str] = "admin"
    change_note: Optional[str] = "policy update"


class PolicyResponse(BaseModel):
    """Policy update response."""
    success: bool
    message: str
    policy: Optional[Dict[str, Any]] = None
    version: Optional[int] = None


class PolicyListItem(BaseModel):
    """Policy item in list."""
    name: str
    enabled: bool
    config: Dict[str, Any]


class PolicyListResponse(BaseModel):
    """List all policies response."""
    policies: List[PolicyListItem]


class PolicyVersionItem(BaseModel):
    """Single policy version record."""
    policy_name: str
    version: int
    config: Dict[str, Any]
    created_at: Optional[datetime] = None
    created_by: Optional[str] = None
    change_note: Optional[str] = None


class PolicyVersionsResponse(BaseModel):
    """Policy version list response."""
    success: bool
    policy_name: str
    versions: List[PolicyVersionItem]


class PolicyRollbackRequest(BaseModel):
    """Rollback request payload."""
    version: int = Field(..., ge=1)
    changed_by: Optional[str] = "admin"


class EntitlementsResponse(BaseModel):
    """Entitlement response payload."""
    success: bool
    message: str
    entitlements: Dict[str, Any]
    version: Optional[int] = None


class EntitlementsUpdateRequest(BaseModel):
    """Entitlement update payload."""
    modules: Optional[Dict[str, bool]] = None
    providers: Optional[Dict[str, bool]] = None
    limits: Optional[Dict[str, Any]] = None
    changed_by: Optional[str] = "admin"
    change_note: Optional[str] = "entitlement update"


class InteractionReviewRequest(BaseModel):
    """Interaction review update payload."""
    reviewed_by: Optional[str] = "admin"
    reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class InteractionReviewRecord(BaseModel):
    """Interaction review record."""
    request_id: str
    review_status: str
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    reason: Optional[str] = None
    source_event_id: Optional[int] = None
    source_decision: Optional[str] = None
    source_risk_score: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InteractionReviewResponse(BaseModel):
    """Interaction review response."""
    success: bool
    message: str
    request_id: str
    review: InteractionReviewRecord


def _is_sensitive_key(key: str) -> bool:
    """Detect whether a key should be redacted in API responses."""
    normalized = key.lower()
    if normalized in _SENSITIVE_EXACT_KEYS:
        return True
    return (
        normalized.endswith("_secret")
        or normalized.endswith("_password")
        or normalized.endswith("_api_key")
        or normalized.endswith("_token")
    )


def _redact_sensitive(data: Any) -> Any:
    """Recursively redact secret-like keys from response payloads."""
    if isinstance(data, dict):
        redacted: Dict[str, Any] = {}
        for key, value in data.items():
            normalized = str(key).lower()
            if _is_sensitive_key(normalized):
                redacted[key] = _REDACTED_VALUE if value not in (None, "") else ""
            else:
                redacted[key] = _redact_sensitive(value)
        return redacted
    if isinstance(data, list):
        return [_redact_sensitive(item) for item in data]
    return data


def _resolve_action(request: PolicyUpdate) -> Optional[str]:
    """Support both action and action_on_detect payload fields."""
    return request.action_on_detect or request.action


def _build_policy_updates(request: PolicyUpdate) -> Dict[str, Any]:
    """Build policy update dictionary from request model."""
    updates: Dict[str, Any] = {}
    if request.enabled is not None:
        updates["enabled"] = request.enabled
    action = _resolve_action(request)
    if action is not None:
        updates["action_on_detect"] = action.upper()
    if request.severity_threshold is not None:
        updates["severity_threshold"] = request.severity_threshold.upper()
    if request.max_attempts is not None:
        updates["max_attempts"] = int(request.max_attempts)
    if request.secret is not None:
        updates["secret"] = request.secret
    if request.issuer is not None:
        updates["issuer"] = request.issuer
    if request.audience is not None:
        updates["audience"] = request.audience
    return updates


async def _update_policy(policy_name: str, request: PolicyUpdate, message: str) -> PolicyResponse:
    """Shared policy update operation."""
    try:
        updated, version = await policy_store.update_policy(
            name=policy_name,
            updates=_build_policy_updates(request),
            changed_by=request.changed_by or "admin",
            change_note=request.change_note or "policy update",
        )
        logger.info(f"{policy_name} updated to version {version}")
        return PolicyResponse(
            success=True,
            message=message,
            policy=_redact_sensitive(updated),
            version=version,
        )
    except Exception as exc:
        logger.error(f"Failed to update {policy_name}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update policy '{policy_name}'",
        ) from exc


@admin_router.get("/policies", response_model=PolicyListResponse)
async def list_policies() -> PolicyListResponse:
    """List all security policies."""
    items = [
        PolicyListItem(
            name=item["name"],
            enabled=item["enabled"],
            config=_redact_sensitive(item["config"]),
        )
        for item in policy_store.list_policies()
    ]
    return PolicyListResponse(policies=items)


@admin_router.get("/policies/pii", response_model=PolicyResponse)
async def get_pii_policy() -> PolicyResponse:
    """Get PII detection policy."""
    policy, version = await policy_store.get_policy_with_version("pii_detection")
    return PolicyResponse(
        success=True,
        message="PII detection policy",
        policy=_redact_sensitive(policy),
        version=version,
    )


@admin_router.put("/policies/pii", response_model=PolicyResponse)
async def update_pii_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update PII detection policy."""
    return await _update_policy("pii_detection", request, "PII detection policy updated")


@admin_router.get("/policies/jailbreak", response_model=PolicyResponse)
async def get_jailbreak_policy() -> PolicyResponse:
    """Get jailbreak detection policy."""
    policy, version = await policy_store.get_policy_with_version("jailbreak_detection")
    return PolicyResponse(
        success=True,
        message="Jailbreak detection policy",
        policy=_redact_sensitive(policy),
        version=version,
    )


@admin_router.put("/policies/jailbreak", response_model=PolicyResponse)
async def update_jailbreak_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update jailbreak detection policy."""
    return await _update_policy("jailbreak_detection", request, "Jailbreak detection policy updated")


@admin_router.get("/policies/injection", response_model=PolicyResponse)
async def get_injection_policy() -> PolicyResponse:
    """Get injection detection policy."""
    policy, version = await policy_store.get_policy_with_version("injection_detection")
    return PolicyResponse(
        success=True,
        message="Injection detection policy",
        policy=_redact_sensitive(policy),
        version=version,
    )


@admin_router.put("/policies/injection", response_model=PolicyResponse)
async def update_injection_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update injection detection policy."""
    return await _update_policy("injection_detection", request, "Injection detection policy updated")


@admin_router.get("/policies/jwt", response_model=PolicyResponse)
async def get_jwt_policy() -> PolicyResponse:
    """Get JWT authentication policy."""
    jwt_policy, version = await policy_store.get_policy_with_version("jwt_auth")
    if not jwt_policy:
        jwt_policy = {
            "enabled": settings.jwt_enabled,
            "secret": settings.jwt_secret,
            "issuer": settings.jwt_issuer,
            "audience": settings.jwt_audience,
        }
        version = None
    return PolicyResponse(
        success=True,
        message="JWT authentication policy",
        policy=_redact_sensitive(jwt_policy),
        version=version,
    )


@admin_router.put("/policies/jwt", response_model=PolicyResponse)
async def update_jwt_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update JWT authentication policy."""
    return await _update_policy("jwt_auth", request, "JWT authentication policy updated")


@admin_router.get("/policies/{policy_name}/versions", response_model=PolicyVersionsResponse)
async def get_policy_versions(policy_name: str, limit: int = 20) -> PolicyVersionsResponse:
    """Get policy version history."""
    versions = await policy_store.list_policy_versions(policy_name, limit=limit)
    return PolicyVersionsResponse(
        success=True,
        policy_name=policy_name,
        versions=[
            PolicyVersionItem(
                policy_name=item["policy_name"],
                version=item["version"],
                config=_redact_sensitive(item.get("config", {})),
                created_at=item.get("created_at"),
                created_by=item.get("created_by"),
                change_note=item.get("change_note"),
            )
            for item in versions
        ],
    )


@admin_router.post("/policies/{policy_name}/rollback", response_model=PolicyResponse)
async def rollback_policy(policy_name: str, request: PolicyRollbackRequest) -> PolicyResponse:
    """Rollback policy to a previous version and create a new version entry."""
    try:
        policy, version = await policy_store.rollback_policy(
            name=policy_name,
            target_version=request.version,
            changed_by=request.changed_by or "admin",
        )
        return PolicyResponse(
            success=True,
            message=f"Policy '{policy_name}' rolled back to version {request.version}",
            policy=_redact_sensitive(policy),
            version=version,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error(f"Policy rollback failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to rollback policy '{policy_name}'",
        ) from exc


@admin_router.delete("/policies/{policy_name}", response_model=PolicyResponse)
async def delete_policy(policy_name: str) -> PolicyResponse:
    """Soft-delete a policy by disabling it."""
    try:
        policy = await policy_store.delete_policy(policy_name)
        return PolicyResponse(
            success=True,
            message=f"Policy '{policy_name}' deleted",
            policy=_redact_sensitive(policy),
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_name}' not found",
        )


@admin_router.post("/policies/reset", response_model=PolicyResponse)
async def reset_policies() -> PolicyResponse:
    """Reset all policies to defaults."""
    await policy_store.reset_policies()
    return PolicyResponse(
        success=True,
        message="All policies reset to defaults",
        policy=None,
    )


@admin_router.get("/entitlements", response_model=EntitlementsResponse)
async def get_entitlements() -> EntitlementsResponse:
    """Get current entitlement configuration."""
    entitlements, version = await policy_store.get_entitlements_with_version()
    return EntitlementsResponse(
        success=True,
        message="Current entitlements",
        entitlements=entitlements,
        version=version,
    )


@admin_router.put("/entitlements", response_model=EntitlementsResponse)
async def update_entitlements(request: EntitlementsUpdateRequest) -> EntitlementsResponse:
    """Update entitlement configuration and create a version entry."""
    updates: Dict[str, Any] = {}
    if request.modules is not None:
        updates["modules"] = request.modules
    if request.providers is not None:
        updates["providers"] = request.providers
    if request.limits is not None:
        updates["limits"] = request.limits

    entitlements, version = await policy_store.update_entitlements(
        updates=updates,
        changed_by=request.changed_by or "admin",
        change_note=request.change_note or "entitlement update",
    )
    return EntitlementsResponse(
        success=True,
        message="Entitlements updated",
        entitlements=entitlements,
        version=version,
    )


async def _set_interaction_review(
    request_id: str,
    review_status: str,
    payload: InteractionReviewRequest,
) -> InteractionReviewResponse:
    """Create/update interaction review decision for a gateway request id."""
    normalized_status = review_status.upper()
    if normalized_status not in {"APPROVED", "BLOCKED"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid interaction review status: {review_status}",
        )

    if not audit_logger.connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Interaction review store is not available",
        )

    source_event = await audit_logger.get_latest_gateway_event_by_request_id(request_id)
    if not source_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No gateway event found for request_id '{request_id}'",
        )

    review = await audit_logger.upsert_interaction_review(
        request_id=request_id,
        review_status=normalized_status,
        reviewed_by=payload.reviewed_by or "admin",
        reason=payload.reason,
        source_event_id=source_event.get("id"),
        source_decision=source_event.get("decision"),
        source_risk_score=source_event.get("risk_score"),
        metadata=payload.metadata or {},
    )
    if not review:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist interaction review for request_id '{request_id}'",
        )

    return InteractionReviewResponse(
        success=True,
        message=f"Interaction '{request_id}' marked as {normalized_status}",
        request_id=request_id,
        review=InteractionReviewRecord(**review),
    )


@admin_router.post("/interactions/{request_id}/approve", response_model=InteractionReviewResponse)
async def approve_interaction(
    request_id: str,
    payload: InteractionReviewRequest,
) -> InteractionReviewResponse:
    """Mark an interaction as approved."""
    return await _set_interaction_review(request_id, "APPROVED", payload)


@admin_router.post("/interactions/{request_id}/block", response_model=InteractionReviewResponse)
async def block_interaction(
    request_id: str,
    payload: InteractionReviewRequest,
) -> InteractionReviewResponse:
    """Mark an interaction as blocked."""
    return await _set_interaction_review(request_id, "BLOCKED", payload)


@admin_router.get("/interactions/{request_id}", response_model=InteractionReviewResponse)
async def get_interaction_review(request_id: str) -> InteractionReviewResponse:
    """Get interaction review status by request id."""
    if not audit_logger.connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Interaction review store is not available",
        )

    review = await audit_logger.get_interaction_review(request_id)
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No interaction review found for request_id '{request_id}'",
        )

    return InteractionReviewResponse(
        success=True,
        message=f"Interaction review for '{request_id}'",
        request_id=request_id,
        review=InteractionReviewRecord(**review),
    )


def get_admin_router() -> APIRouter:
    """Get admin API router."""
    return admin_router


def get_policy(name: str) -> Dict[str, Any]:
    """Fast-path policy getter used by request pipeline."""
    return policy_store.get_policy(name)
