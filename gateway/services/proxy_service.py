"""
Data443 LLM Gateway - Request Interception Layer

Intercepts LLM API requests, evaluates policy, enforces entitlements,
and forwards to target endpoint.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Optional, Dict, Any

from fastapi import Request, Response, HTTPException, status
from httpx import AsyncClient, Timeout
from loguru import logger

from gateway.core.config import settings
from gateway.core.types import Decision
from gateway.services.policy_service import PolicyEngine, PolicyDecision
from gateway.integrations.audit import audit_logger
from gateway.integrations.cache import cache
from gateway.services.jwt_auth import JWTAuth, get_current_user_from_request
from gateway.services.content_filter import get_content_filter, SecurityAction
from gateway.api.admin import get_policy
from gateway.policy.store import policy_store


class ProxyHandler:
    """Handler for proxying LLM API requests with policy evaluation."""

    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.llm_endpoint = settings.llm_endpoint.rstrip("/")
        self.timeout = Timeout(60.0)

    async def handle_request(self, request: Request) -> Response:
        """
        Handle incoming LLM API request.

        Runtime flow:
        1. JWT authentication (optional)
        2. Entitlement guardrails (provider/model)
        3. Content filter
        4. Threat intelligence policy evaluation
        5. Forward request for allowed/constrained decisions
        """
        request_id = str(uuid.uuid4())
        client_ip = self._get_client_ip(request)
        request_url = str(request.url)
        user_agent = request.headers.get("user-agent", "")
        user_id: Optional[str] = None
        org_id: Optional[str] = request.headers.get("x-org-id")

        try:
            request_body = await request.json()
        except Exception:
            request_body = None

        model_name = self._extract_model(request_body)
        provider_name = self._provider_name_from_endpoint(self.llm_endpoint)

        logger.info(f"Request {request_id} from {client_ip}: {request.method} {request.url.path}")

        # STEP 1: JWT Authentication (if enabled)
        jwt_policy = get_policy("jwt_auth")
        jwt_enabled = jwt_policy.get("enabled", settings.jwt_enabled)
        if jwt_enabled:
            try:
                jwt_auth = JWTAuth(
                    secret=jwt_policy.get("secret") or settings.jwt_secret,
                    issuer=jwt_policy.get("issuer") or settings.jwt_issuer,
                    audience=jwt_policy.get("audience") or settings.jwt_audience,
                )
                user_id = await get_current_user_from_request(request, jwt_auth)
            except HTTPException:
                await self._emit_gateway_event(
                    request_id=request_id,
                    decision="BLOCK",
                    request=request,
                    request_body=request_body,
                    model_name=model_name,
                    org_id=org_id,
                    user_id=user_id,
                    response_status=status.HTTP_401_UNAUTHORIZED,
                    reason="Authentication required",
                    attributes={"block_type": "auth"},
                )
                return Response(
                    content=json.dumps({
                        "error": {
                            "message": "Authentication required",
                            "type": "auth_required",
                            "code": "unauthorized",
                        }
                    }),
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    media_type="application/json",
                )

        # STEP 2: Entitlement enforcement
        if not policy_store.is_provider_enabled(provider_name):
            reason = f"Provider '{provider_name}' is not enabled for this deployment"
            await self._emit_gateway_event(
                request_id=request_id,
                decision="BLOCK",
                request=request,
                request_body=request_body,
                model_name=model_name,
                org_id=org_id,
                user_id=user_id,
                response_status=status.HTTP_403_FORBIDDEN,
                reason=reason,
                attributes={"block_type": "entitlement_provider", "provider": provider_name},
            )
            return self._json_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                message=reason,
                error_type="entitlement_blocked",
                code="provider_not_enabled",
            )

        allowed_models = policy_store.get_allowed_models()
        if allowed_models and model_name and model_name not in allowed_models:
            reason = f"Model '{model_name}' is not allowed by entitlement policy"
            await self._emit_gateway_event(
                request_id=request_id,
                decision="BLOCK",
                request=request,
                request_body=request_body,
                model_name=model_name,
                org_id=org_id,
                user_id=user_id,
                response_status=status.HTTP_403_FORBIDDEN,
                reason=reason,
                attributes={
                    "block_type": "entitlement_model",
                    "allowed_models": allowed_models,
                },
            )
            return self._json_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                message=reason,
                error_type="entitlement_blocked",
                code="model_not_allowed",
            )

        # STEP 3: Content security filtering
        content_filter = get_content_filter()
        content_security = content_filter.check_request(request_body)

        if content_security["action"] == SecurityAction.BLOCK:
            reason = f"Request blocked: {content_security['reason']}"
            await self._emit_gateway_event(
                request_id=request_id,
                decision="BLOCK",
                request=request,
                request_body=request_body,
                model_name=model_name,
                org_id=org_id,
                user_id=user_id,
                response_status=status.HTTP_403_FORBIDDEN,
                reason=reason,
                attributes={
                    "block_type": "content_filter",
                    "detected": content_security.get("detected", []),
                    "counts": content_security.get("counts", {}),
                },
            )
            return Response(
                content=json.dumps({
                    "error": {
                        "message": reason,
                        "type": "content_blocked",
                        "code": "policy_violation",
                        "detected": content_security["detected"],
                    }
                }),
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json",
            )

        if content_security["action"] in (SecurityAction.CONSTRAIN, SecurityAction.LOG_ONLY):
            logger.warning(f"Request {request_id} flagged by content filter: {content_security['reason']}")

        # STEP 4: Evaluate policy
        decision = await self.policy_engine.evaluate_request(
            ip_address=client_ip,
            url=request_url,
            user_agent=user_agent,
            request_id=request_id,
            request_method=request.method,
            request_path=request.url.path,
            request_body=request_body,
        )

        if decision.decision == Decision.BLOCK:
            await self._emit_gateway_event(
                request_id=request_id,
                decision=decision.decision.value,
                request=request,
                request_body=request_body,
                model_name=model_name,
                org_id=org_id,
                user_id=user_id,
                risk_score=decision.risk_score,
                response_status=status.HTTP_403_FORBIDDEN,
                reason=decision.reason,
                attributes={
                    "ip_risk_score": decision.ip_risk_score,
                    "url_category": decision.url_category,
                    "cyren_ref_id": decision.cyren_ref_id,
                },
            )
            return self._block_response(decision)

        if decision.decision == Decision.CONSTRAIN:
            logger.warning(f"Request {request_id} CONSTRAINED: {decision.reason}")
            return await self._forward_request(
                request=request,
                request_id=request_id,
                final_decision=decision,
                request_body=request_body,
                content_security=content_security,
                user_id=user_id,
                org_id=org_id,
                model_name=model_name,
                constrained=True,
            )

        # ALLOW / ALLOW_LOG
        return await self._forward_request(
            request=request,
            request_id=request_id,
            final_decision=decision,
            request_body=request_body,
            content_security=content_security,
            user_id=user_id,
            org_id=org_id,
            model_name=model_name,
            constrained=False,
        )

    async def _forward_request(
        self,
        request: Request,
        request_id: str,
        final_decision: PolicyDecision,
        request_body: Optional[Dict[str, Any]],
        content_security: Dict[str, Any],
        user_id: Optional[str],
        org_id: Optional[str],
        model_name: Optional[str],
        constrained: bool = False,
    ) -> Response:
        """
        Forward request to target LLM endpoint and inspect response.
        """
        start_time = time.time()

        path = request.url.path
        query = request.url.query
        target_url = f"{self.llm_endpoint}{path}"
        if query:
            target_url += f"?{query}"

        headers = dict(request.headers)
        for h in ["host", "content-length", "transfer-encoding"]:
            headers.pop(h, None)

        if "authorization" not in headers and settings.llm_api_key:
            headers["authorization"] = f"Bearer {settings.llm_api_key}"

        try:
            async with AsyncClient(timeout=self.timeout) as client:
                upstream_response = await client.request(
                    method=request.method,
                    url=target_url,
                    json=request_body,
                    headers=headers,
                )

                response_time_ms = int((time.time() - start_time) * 1000)
                logger.info(
                    f"Request {request_id} completed: "
                    f"status={upstream_response.status_code}, time={response_time_ms}ms"
                )

                response_body = None
                content_type = upstream_response.headers.get("content-type", "")
                if "application/json" in content_type.lower():
                    try:
                        response_body = upstream_response.json()
                    except Exception:
                        response_body = None

                # Response inspection
                if response_body is not None:
                    response_security = get_content_filter().check_response(response_body)
                    if response_security["action"] == SecurityAction.BLOCK:
                        reason = f"Response blocked: {response_security['reason']}"
                        await self._emit_gateway_event(
                            request_id=request_id,
                            decision="BLOCK",
                            request=request,
                            request_body=request_body,
                            model_name=model_name,
                            org_id=org_id,
                            user_id=user_id,
                            risk_score=final_decision.risk_score,
                            response_status=status.HTTP_403_FORBIDDEN,
                            response_time_ms=response_time_ms,
                            reason=reason,
                            attributes={
                                "block_type": "response_filter",
                                "request_decision": final_decision.decision.value,
                                "request_content_counts": content_security.get("counts", {}),
                                "response_detected": response_security.get("detected", []),
                            },
                        )
                        return Response(
                            content=json.dumps({
                                "error": {
                                    "message": reason,
                                    "type": "content_blocked",
                                    "code": "policy_violation",
                                    "detected": response_security.get("detected", []),
                                }
                            }),
                            status_code=status.HTTP_403_FORBIDDEN,
                            media_type="application/json",
                        )

                    if response_security["action"] in (SecurityAction.CONSTRAIN, SecurityAction.LOG_ONLY):
                        logger.warning(
                            f"Response {request_id} flagged by content filter: {response_security['reason']}"
                        )

                await self._emit_gateway_event(
                    request_id=request_id,
                    decision=final_decision.decision.value,
                    request=request,
                    request_body=request_body,
                    model_name=model_name,
                    org_id=org_id,
                    user_id=user_id,
                    risk_score=final_decision.risk_score,
                    response_status=upstream_response.status_code,
                    response_time_ms=response_time_ms,
                    reason=final_decision.reason,
                    attributes={
                        "constrained": constrained,
                        "request_content_action": str(content_security.get("action", "PASS")),
                        "request_content_counts": content_security.get("counts", {}),
                        "ip_risk_score": final_decision.ip_risk_score,
                        "url_category": final_decision.url_category,
                        "cyren_ref_id": final_decision.cyren_ref_id,
                    },
                )

                response_headers = dict(upstream_response.headers)
                for h in ["content-encoding", "transfer-encoding", "content-length", "connection"]:
                    response_headers.pop(h, None)

                return Response(
                    content=upstream_response.content,
                    status_code=upstream_response.status_code,
                    headers=response_headers,
                )

        except Exception as exc:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"Request {request_id} failed: {exc}")
            await self._emit_gateway_event(
                request_id=request_id,
                decision="ERROR",
                request=request,
                request_body=request_body,
                model_name=model_name,
                org_id=org_id,
                user_id=user_id,
                risk_score=final_decision.risk_score,
                response_status=status.HTTP_502_BAD_GATEWAY,
                response_time_ms=response_time_ms,
                reason=f"Upstream request failed: {exc}",
                attributes={"exception": str(exc)},
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to reach LLM endpoint: {str(exc)}",
            ) from exc

    def _block_response(self, decision: PolicyDecision) -> Response:
        """Return block response payload."""
        block_body = {
            "error": {
                "message": f"Request blocked by security policy: {decision.reason}",
                "type": "security_blocked",
                "code": "policy_violation",
                "risk_score": decision.risk_score,
            }
        }
        return Response(
            content=json.dumps(block_body),
            status_code=status.HTTP_403_FORBIDDEN,
            media_type="application/json",
        )

    async def _emit_gateway_event(
        self,
        request_id: str,
        decision: str,
        request: Request,
        request_body: Optional[Dict[str, Any]],
        model_name: Optional[str],
        org_id: Optional[str],
        user_id: Optional[str],
        risk_score: Optional[int] = None,
        response_status: Optional[int] = None,
        response_time_ms: Optional[int] = None,
        reason: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist structured event row for analytics and forensic use."""
        await audit_logger.log_gateway_event(
            request_id=request_id,
            decision=decision,
            risk_score=risk_score,
            ip_address=self._get_client_ip(request),
            url=str(request.url),
            model=model_name,
            org_id=org_id,
            user_id=user_id,
            response_status=response_status,
            response_time_ms=response_time_ms,
            reason=reason,
            attributes={
                "request_method": request.method,
                "request_path": request.url.path,
                "provider": self._provider_name_from_endpoint(self.llm_endpoint),
                "request_body": request_body,
                **(attributes or {}),
            },
        )

    def _json_error_response(
        self,
        status_code: int,
        message: str,
        error_type: str,
        code: str,
    ) -> Response:
        """Build standardized JSON error response."""
        return Response(
            content=json.dumps({
                "error": {
                    "message": message,
                    "type": error_type,
                    "code": code,
                }
            }),
            status_code=status_code,
            media_type="application/json",
        )

    def _extract_model(self, request_body: Optional[Dict[str, Any]]) -> Optional[str]:
        """Extract model from OpenAI-compatible request body."""
        if not isinstance(request_body, dict):
            return None
        model = request_body.get("model")
        if model is None:
            return None
        return str(model)

    def _provider_name_from_endpoint(self, endpoint: str) -> str:
        """Infer provider key from configured upstream endpoint."""
        lower = endpoint.lower()
        if "openai" in lower:
            return "openai"
        if "anthropic" in lower:
            return "anthropic"
        if "gemini" in lower or "googleapis" in lower:
            return "gemini"
        if "openrouter" in lower:
            return "openrouter"
        return "unknown"

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        headers = request.headers
        for header in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]:
            if header in headers:
                ip = headers[header].split(",")[0].strip()
                if ip:
                    return ip
        return request.client.host if request.client else "unknown"

    async def health_check(self) -> Dict[str, Any]:
        """Return gateway health status."""
        return {
            "status": "healthy",
            "circuit_breaker": self.policy_engine.cyren_client.get_circuit_breaker_state(),
            "cache_connected": cache.l2.connected,
            "audit_connected": self.policy_engine.audit_logger.connected,
        }


proxy_handler: Optional[ProxyHandler] = None


def init_proxy_handler(policy_engine: PolicyEngine) -> ProxyHandler:
    """Initialize global proxy handler."""
    global proxy_handler
    proxy_handler = ProxyHandler(policy_engine)
    return proxy_handler