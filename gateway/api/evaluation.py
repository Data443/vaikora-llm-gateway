"""Evaluation API routes for the Data443 LLM Gateway.

Adds a standalone policy-evaluation surface that does NOT proxy to any
upstream LLM provider. The existing chat-completion proxy embeds the policy
pipeline inside the request flow; these endpoints expose the same pipeline
on its own so external clients (such as the Vaikora Guard MCP server) can
evaluate AI agent actions without synthesizing a fake chat completion.

Endpoints
---------

POST /v1/evaluate
    Run a free-form action description through the full policy pipeline
    (PII, jailbreak, injection, semantic, domain risk, email classification)
    and return a decision + audit receipt.

POST /v1/modules/check
    Run a single content module against a piece of text. Useful when a
    caller only needs one signal (e.g. PII detection) instead of the full
    pipeline.

GET  /v1/policies
    Return the active policy and entitlement configuration in a single
    response. Replaces the per-module GET calls when callers only need a
    snapshot.

POST /v1/audit
    Append an entry to the audit log. The chat-completion proxy already
    writes audit entries automatically; this endpoint lets non-proxy clients
    record decisions they made externally with the same receipt format.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Request, status
from loguru import logger
from pydantic import BaseModel, Field

from gateway.api.auth import require_admin_auth
from gateway.core.types import Decision
from gateway.integrations.audit import audit_logger
from gateway.policy.store import policy_store
from gateway.services.content_filter import SecurityAction, get_content_filter


evaluation_router = APIRouter(prefix="/v1")


MODULE_NAMES = (
    "pii_detection",
    "jailbreak_detection",
    "injection_detection",
    "semantic_detection",
    "domain_risk_scoring",
    "email_classification",
)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class EvaluateRequest(BaseModel):
    action: str = Field(
        ...,
        min_length=1,
        max_length=32000,
        description="Free-form description of the action to evaluate.",
    )
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional structured context (target system, user, parameters).",
    )


class ModuleCheckRequest(BaseModel):
    module: Literal[
        "pii_detection",
        "jailbreak_detection",
        "injection_detection",
        "semantic_detection",
        "domain_risk_scoring",
        "email_classification",
    ] = Field(..., description="Module to invoke.")
    text: str = Field(..., min_length=1, max_length=32000)


class AuditWriteRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=4000)
    decision: Literal["ALLOW", "ALLOW_LOG", "CONSTRAIN", "BLOCK", "ERROR"]
    receipt_id: str = Field(..., min_length=1, max_length=128)
    metadata: Optional[Dict[str, Any]] = Field(default=None)


class DecisionPayload(BaseModel):
    outcome: Literal["ALLOW", "ALLOW_LOG", "CONSTRAIN", "BLOCK", "ERROR"]
    reason: str
    matched_policy: Optional[str] = None
    severity: Optional[str] = None
    constraint: Optional[Dict[str, Any]] = None


class EnforcementResult(BaseModel):
    decision: DecisionPayload
    receipt_id: str
    pipeline: List[DecisionPayload] = Field(default_factory=list)
    latency_ms: int


class PolicyConfigPayload(BaseModel):
    policies: Dict[str, Dict[str, Any]]
    entitlements: Dict[str, Any]
    version: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SECURITY_ACTION_TO_OUTCOME: Dict[SecurityAction, str] = {
    SecurityAction.PASS: "ALLOW",
    SecurityAction.LOG_ONLY: "ALLOW_LOG",
    SecurityAction.CONSTRAIN: "CONSTRAIN",
    SecurityAction.BLOCK: "BLOCK",
}


def _outcome_from_action(action: SecurityAction) -> str:
    return _SECURITY_ACTION_TO_OUTCOME.get(action, "ERROR")


def _build_receipt(action: str, decision_outcome: str) -> str:
    """SHA-256 receipt over (action, outcome, monotonic_now, salt)."""
    salt = uuid.uuid4().hex
    digest = hashlib.sha256(
        f"{action}|{decision_outcome}|{time.time_ns()}|{salt}".encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def _detection_to_decision(detection: Dict[str, Any]) -> DecisionPayload:
    """Map a single ContentFilter detection dict to a DecisionPayload."""
    outcome = detection.get("action", "BLOCK")
    if isinstance(outcome, SecurityAction):
        outcome = _outcome_from_action(outcome)
    elif outcome in _SECURITY_ACTION_TO_OUTCOME.values() or outcome == "ERROR":
        outcome = str(outcome)
    else:
        outcome = "BLOCK"
    return DecisionPayload(
        outcome=outcome,
        reason=detection.get("reason") or detection.get("type") or "policy_violation",
        matched_policy=detection.get("policy") or detection.get("module"),
        severity=detection.get("severity"),
        constraint=detection.get("constraint"),
    )


def _aggregate_decision(
    detections: List[Dict[str, Any]],
    overall_action: SecurityAction,
    reason: str,
) -> DecisionPayload:
    """Build the top-level decision from the worst-severity detection."""
    if not detections:
        return DecisionPayload(
            outcome=_outcome_from_action(overall_action),
            reason=reason,
        )
    # ContentFilter already orders detections by severity in check_request,
    # so the first non-PASS detection is representative. If none, fall back
    # to the overall action.
    top = detections[0]
    return DecisionPayload(
        outcome=_outcome_from_action(overall_action),
        reason=top.get("reason") or top.get("type") or reason,
        matched_policy=top.get("policy") or top.get("module"),
        severity=top.get("severity"),
        constraint=top.get("constraint"),
    )


async def _log_audit(
    *,
    request_id: str,
    action_text: str,
    decision: DecisionPayload,
    receipt_id: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Best-effort write to the gateway audit log."""
    try:
        await audit_logger.log_decision(
            request_id=request_id,
            decision=decision.outcome,
            reason=decision.reason,
            matched_policy=decision.matched_policy,
            severity=decision.severity,
            metadata={
                "source": "v1_evaluate",
                "receipt_id": receipt_id,
                "action_text": action_text,
                **(metadata or {}),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Audit logging failed for {}: {}", receipt_id, exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@evaluation_router.post("/evaluate", response_model=EnforcementResult)
async def evaluate_action(payload: EvaluateRequest, request: Request) -> EnforcementResult:
    """Run an action through the full enforcement pipeline."""
    start = time.monotonic()
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex

    content_filter = get_content_filter()
    raw_result = content_filter.check_request(content=payload.action)
    detections: List[Dict[str, Any]] = list(raw_result.get("detected", []))
    overall_action: SecurityAction = raw_result.get("action", SecurityAction.PASS)
    reason: str = raw_result.get("reason") or "no_policy_matched"

    decision = _aggregate_decision(detections, overall_action, reason)
    pipeline = [_detection_to_decision(d) for d in detections]
    receipt_id = _build_receipt(payload.action, decision.outcome)
    latency_ms = int((time.monotonic() - start) * 1000)

    await _log_audit(
        request_id=request_id,
        action_text=payload.action,
        decision=decision,
        receipt_id=receipt_id,
        metadata={"context": payload.context} if payload.context else None,
    )

    return EnforcementResult(
        decision=decision,
        receipt_id=receipt_id,
        pipeline=pipeline,
        latency_ms=latency_ms,
    )


@evaluation_router.post("/modules/check", response_model=EnforcementResult)
async def check_module(payload: ModuleCheckRequest, request: Request) -> EnforcementResult:
    """Run a single content module against text."""
    start = time.monotonic()
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    content_filter = get_content_filter()

    module_to_method = {
        "pii_detection": content_filter.check_pii,
        "jailbreak_detection": content_filter.check_jailbreak_attempts,
        "injection_detection": content_filter.check_injection_attempts,
        "semantic_detection": lambda t: _semantic_detect(t),
        "domain_risk_scoring": content_filter.check_domain_risk,
        "email_classification": content_filter.check_email_classification,
    }
    runner = module_to_method.get(payload.module)
    if runner is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown module: {payload.module}",
        )

    detections: List[Dict[str, Any]] = runner(payload.text) or []

    # Module-only call uses the worst severity to decide top-level outcome.
    if detections:
        top = detections[0]
        top_outcome_raw = top.get("action", SecurityAction.BLOCK)
        if isinstance(top_outcome_raw, SecurityAction):
            top_outcome = _outcome_from_action(top_outcome_raw)
        else:
            top_outcome = str(top_outcome_raw)
        decision = DecisionPayload(
            outcome=top_outcome,
            reason=top.get("reason") or top.get("type") or "module_violation",
            matched_policy=payload.module,
            severity=top.get("severity"),
            constraint=top.get("constraint"),
        )
    else:
        decision = DecisionPayload(
            outcome="ALLOW",
            reason="no_signal",
            matched_policy=payload.module,
        )

    pipeline = [_detection_to_decision(d) for d in detections]
    receipt_id = _build_receipt(payload.text, decision.outcome)
    latency_ms = int((time.monotonic() - start) * 1000)

    await _log_audit(
        request_id=request_id,
        action_text=payload.text,
        decision=decision,
        receipt_id=receipt_id,
        metadata={"module": payload.module},
    )

    return EnforcementResult(
        decision=decision,
        receipt_id=receipt_id,
        pipeline=pipeline,
        latency_ms=latency_ms,
    )


@evaluation_router.get("/policies", response_model=PolicyConfigPayload)
async def get_policies() -> PolicyConfigPayload:
    """Return the active policy + entitlement configuration."""
    policies = policy_store.list_policies()
    entitlements = policy_store.get_entitlements()
    version = policy_store.get_version()
    return PolicyConfigPayload(
        policies=policies,
        entitlements=entitlements,
        version=version,
    )


@evaluation_router.post("/audit", status_code=status.HTTP_201_CREATED)
async def write_audit(
    payload: AuditWriteRequest,
    request: Request,
    _: None = require_admin_auth,
) -> Dict[str, Any]:
    """Append an entry to the gateway audit log.

    Requires admin auth so that external clients cannot pollute the log
    with arbitrary entries. The MCP server passes its admin token through
    when it needs to record agent-side decisions.
    """
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    decision = DecisionPayload(
        outcome=payload.decision,
        reason="external_audit_write",
        matched_policy=None,
    )
    await _log_audit(
        request_id=request_id,
        action_text=payload.action,
        decision=decision,
        receipt_id=payload.receipt_id,
        metadata=payload.metadata,
    )
    return {"stored": True, "receipt_id": payload.receipt_id, "request_id": request_id}


# ---------------------------------------------------------------------------
# Module-specific helpers
# ---------------------------------------------------------------------------


def _semantic_detect(text: str) -> List[Dict[str, Any]]:
    """Invoke the semantic detector singleton; isolated for ease of testing."""
    from gateway.services.semantic_detector import semantic_detector  # local import

    return semantic_detector.detect(text)
