"""
Data443 LLM Gateway - Admin API for Policy Management

REST API for managing security policies without gateway restart.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from loguru import logger

from config.settings import settings


# Admin API router
admin_router = APIRouter(prefix="/admin", tags=["admin"])


# Policy storage (in production, use database or Redis)
_policies = {
    "pii_detection": {
        "enabled": True,
        "action_on_detect": "BLOCK",  # BLOCK, CONSTRAIN, LOG_ONLY, PASS
        "severity_threshold": "LOW"  # LOW, MEDIUM, HIGH
    },
    "jailbreak_detection": {
        "enabled": True,
        "action_on_detect": "BLOCK",
        "max_attempts": 3,
    },
    "injection_detection": {
        "enabled": True,
        "action_on_detect": "BLOCK",
    },
    "jwt_auth": {
        "enabled": False,  # Disabled by default
        "secret": "",
        "issuer": settings.jwt_issuer,
        "audience": settings.jwt_audience,
    },
}


# Pydantic models for request/response
class PolicyUpdate(BaseModel):
    """Request to update a policy."""
    policy_name: str
    enabled: Optional[bool] = None
    action: Optional[str] = None
    severity_threshold: Optional[str] = None
    max_attempts: Optional[int] = None


class PolicyResponse(BaseModel):
    """Policy update response."""
    success: bool
    message: str
    policy: Optional[Dict[str, Any]] = None


class PolicyListItem(BaseModel):
    """Policy item in list."""
    name: str
    enabled: bool
    config: Dict[str, Any]


class PolicyListResponse(BaseModel):
    """List all policies response."""
    policies: List[PolicyListItem]


# ============= PII Detection Policy =============

@admin_router.get("/policies/pii", response_model=PolicyResponse)
async def get_pii_policy() -> PolicyResponse:
    """Get PII detection policy."""
    policy = _policies.get("pii_detection", {})
    return PolicyResponse(
        success=True,
        message="PII detection policy",
        policy=policy
    )


@admin_router.put("/policies/pii", response_model=PolicyResponse)
async def update_pii_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update PII detection policy."""
    if "pii_detection" not in _policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PII detection policy not found"
        )

    current = _policies["pii_detection"]

    if request.enabled is not None:
        current["enabled"] = request.enabled
    if request.action is not None:
        current["action_on_detect"] = request.action.upper()
    if request.severity_threshold is not None:
        current["severity_threshold"] = request.severity_threshold.upper()

    logger.info(f"PII policy updated: {current}")
    return PolicyResponse(
        success=True,
        message="PII detection policy updated",
        policy=current
    )


# ============= Jailbreak Detection Policy =============

@admin_router.get("/policies/jailbreak", response_model=PolicyResponse)
async def get_jailbreak_policy() -> PolicyResponse:
    """Get jailbreak detection policy."""
    policy = _policies.get("jailbreak_detection", {})
    return PolicyResponse(
        success=True,
        message="Jailbreak detection policy",
        policy=policy
    )


@admin_router.put("/policies/jailbreak", response_model=PolicyResponse)
async def update_jailbreak_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update jailbreak detection policy."""
    if "jailbreak_detection" not in _policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Jailbreak detection policy not found"
        )

    current = _policies["jailbreak_detection"]

    if request.enabled is not None:
        current["enabled"] = request.enabled
    if request.action is not None:
        current["action_on_detect"] = request.action.upper()
    if request.max_attempts is not None:
        current["max_attempts"] = request.max_attempts

    logger.info(f"Jailbreak policy updated: {current}")
    return PolicyResponse(
        success=True,
        message="Jailbreak detection policy updated",
        policy=current
    )


# ============= Injection Detection Policy =============

@admin_router.get("/policies/injection", response_model=PolicyResponse)
async def get_injection_policy() -> PolicyResponse:
    """Get injection detection policy."""
    policy = _policies.get("injection_detection", {})
    return PolicyResponse(
        success=True,
        message="Injection detection policy",
        policy=policy
    )


@admin_router.put("/policies/injection", response_model=PolicyResponse)
async def update_injection_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update injection detection policy."""
    if "injection_detection" not in _policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Injection detection policy not found"
        )

    current = _policies["injection_detection"]

    if request.enabled is not None:
        current["enabled"] = request.enabled
    if request.action is not None:
        current["action_on_detect"] = request.action.upper()

    logger.info(f"Injection policy updated: {current}")
    return PolicyResponse(
        success=True,
        message="Injection detection policy updated",
        policy=current
    )


# ============= JWT Auth Policy =============

@admin_router.get("/policies/jwt", response_model=PolicyResponse)
async def get_jwt_policy() -> PolicyResponse:
    """Get JWT authentication policy."""
    policy = _policies.get("jwt_auth", {})
    return PolicyResponse(
        success=True,
        message="JWT authentication policy",
        policy=policy
    )


@admin_router.put("/policies/jwt", response_model=PolicyResponse)
async def update_jwt_policy(request: PolicyUpdate) -> PolicyResponse:
    """Update JWT authentication policy."""
    if "jwt_auth" not in _policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="JWT authentication policy not found"
        )

    current = _policies["jwt_auth"]

    if request.enabled is not None:
        current["enabled"] = request.enabled

    logger.info(f"JWT policy updated: {current}")
    return PolicyResponse(
        success=True,
        message="JWT authentication policy updated",
        policy=current
    )


# ============= List All Policies =============

@admin_router.get("/policies", response_model=PolicyListResponse)
async def list_policies() -> PolicyListResponse:
    """List all security policies."""
    policies_list = []

    for name, policy in _policies.items():
        policies_list.append(PolicyListItem(
            name=name,
            enabled=policy.get("enabled", False),
            config=policy
        ))

    return PolicyListResponse(policies=policies_list)


# ============= Delete Policy =============

@admin_router.delete("/policies/{policy_name}", response_model=PolicyResponse)
async def delete_policy(policy_name: str) -> PolicyResponse:
    """Delete a policy by name."""
    if policy_name not in _policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_name}' not found"
        )

    del _policies[policy_name]

    logger.info(f"Policy deleted: {policy_name}")
    return PolicyResponse(
        success=True,
        message=f"Policy '{policy_name}' deleted",
        policy=None
    )


# ============= Reset Policies =============

@admin_router.post("/policies/reset", response_model=PolicyResponse)
async def reset_policies() -> PolicyResponse:
    """Reset all policies to defaults."""
    global _policies
    _policies = {
        "pii_detection": {
            "enabled": True,
            "action_on_detect": "BLOCK",
            "severity_threshold": "LOW",
        },
        "jailbreak_detection": {
            "enabled": True,
            "action_on_detect": "BLOCK",
            "max_attempts": 3,
        },
        "injection_detection": {
            "enabled": True,
            "action_on_detect": "BLOCK",
        },
        "jwt_auth": {
            "enabled": False,
            "secret": "",
            "issuer": settings.jwt_issuer,
            "audience": settings.jwt_audience,
        },
    }

    logger.info("All policies reset to defaults")
    return PolicyResponse(
        success=True,
        message="All policies reset to defaults",
        policy=None
    )


def get_admin_router() -> APIRouter:
    """Get the admin API router."""
    return admin_router
