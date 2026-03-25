"""
Data443 LLM Gateway - Request Interception Layer.

Intercepts LLM API requests, evaluates policy, enforces entitlements,
and forwards to target provider endpoint.
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
from gateway.integrations.telemetry import telemetry_metrics
from gateway.services.jwt_auth import JWTAuth, get_current_user_from_request
from gateway.services.content_filter import get_content_filter, SecurityAction
from gateway.api.admin import get_policy
from gateway.policy.store import policy_store
from gateway.providers.base import ProviderConfigurationError, extract_text
from gateway.providers.router import ProviderRouter


class ProxyHandler:
    """Handler for proxying LLM API requests with policy evaluation."""

    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.llm_endpoint = settings.llm_endpoint.rstrip("/")
        self.timeout = Timeout(settings.upstream_timeout_seconds)
        self.provider_router = ProviderRouter()

    def _is_chat_completions_path(self, path: str) -> bool:
        """Return True for native and managed-agent chat-completions routes."""
        normalized = (path or "").rstrip("/")
        return normalized == "/v1/chat/completions" or normalized.endswith("/v1/chat/completions")

    async def handle_request(self, request: Request) -> Response:
        """
        Handle incoming LLM API request.

        Runtime flow:
        1. JWT authentication (optional)
        2. Entitlement guardrails (provider/model/limits)
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
        provider_name = self.provider_router.resolve_provider(request_body)

        logger.info(
            f"Request {request_id} from {client_ip}: {request.method} {request.url.path}"
        )

        # STEP 1: JWT Authentication (if enabled)
        jwt_policy = get_policy("jwt_auth")
        jwt_enabled = jwt_policy.get("enabled", settings.jwt_enabled)
        if jwt_enabled:
            try:
                jwt_secret = str(jwt_policy.get("secret") or settings.jwt_secret or "").strip()
                if not jwt_secret:
                    reason = "JWT auth is enabled but JWT secret is not configured"
                    await self._emit_gateway_event(
                        request_id=request_id,
                        decision="ERROR",
                        request=request,
                        request_body=request_body,
                        model_name=model_name,
                        provider_name=provider_name,
                        org_id=org_id,
                        user_id=user_id,
                        response_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        reason=reason,
                        attributes={"block_type": "auth_configuration"},
                    )
                    return self._json_error_response(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        message=reason,
                        error_type="auth_configuration_error",
                        code="jwt_secret_missing",
                    )

                jwt_auth = JWTAuth(
                    secret=jwt_secret,
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
                    provider_name=provider_name,
                    org_id=org_id,
                    user_id=user_id,
                    response_status=status.HTTP_401_UNAUTHORIZED,
                    reason="Authentication required",
                    attributes={"block_type": "auth"},
                )
                return self._json_error_response(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    message="Authentication required",
                    error_type="auth_required",
                    code="unauthorized",
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
                provider_name=provider_name,
                org_id=org_id,
                user_id=user_id,
                response_status=status.HTTP_403_FORBIDDEN,
                reason=reason,
                attributes={"block_type": "entitlement_provider"},
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
                provider_name=provider_name,
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

        limit_violation = self._check_entitlement_limits(request_body)
        if limit_violation:
            await self._emit_gateway_event(
                request_id=request_id,
                decision="BLOCK",
                request=request,
                request_body=request_body,
                model_name=model_name,
                provider_name=provider_name,
                org_id=org_id,
                user_id=user_id,
                response_status=limit_violation["status_code"],
                reason=limit_violation["message"],
                attributes=limit_violation.get("attributes", {}),
            )
            return self._json_error_response(
                status_code=limit_violation["status_code"],
                message=limit_violation["message"],
                error_type="entitlement_blocked",
                code=limit_violation["code"],
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
                provider_name=provider_name,
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
                content=json.dumps(
                    {
                        "error": {
                            "message": reason,
                            "type": "content_blocked",
                            "code": "policy_violation",
                            "detected": content_security["detected"],
                        }
                    }
                ),
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json",
            )

        if content_security["action"] in (SecurityAction.CONSTRAIN, SecurityAction.LOG_ONLY):
            logger.warning(
                f"Request {request_id} flagged by content filter: {content_security['reason']}"
            )

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
                provider_name=provider_name,
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
                provider_name=provider_name,
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
            provider_name=provider_name,
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
        provider_name: str,
        constrained: bool = False,
    ) -> Response:
        """Forward request to selected provider and inspect response."""
        start_time = time.time()
        path = request.url.path
        query = request.url.query
        is_chat_completions = self._is_chat_completions_path(path)

        try:
            incoming_headers = dict(request.headers)
            if is_chat_completions and isinstance(request_body, dict):
                prepared = self.provider_router.prepare_chat_completion(
                    provider_name=provider_name,
                    request_body=request_body,
                    incoming_headers=incoming_headers,
                )
                target_url = prepared.url
                outbound_headers = prepared.headers
                outbound_json = prepared.json_body
                outbound_params = prepared.params
            else:
                target_url = self._build_passthrough_url(provider_name, path, query)
                outbound_headers = self._build_passthrough_headers(
                    provider_name=provider_name,
                    incoming_headers=incoming_headers,
                )
                outbound_json = request_body
                outbound_params = {}

            async with AsyncClient(timeout=self.timeout) as client:
                upstream_response = await client.request(
                    method=request.method,
                    url=target_url,
                    params=outbound_params or None,
                    json=outbound_json,
                    headers=outbound_headers,
                )

            response_time_ms = int((time.time() - start_time) * 1000)
            logger.info(
                f"Request {request_id} completed: "
                f"provider={provider_name}, status={upstream_response.status_code}, "
                f"time={response_time_ms}ms"
            )

            final_status = upstream_response.status_code
            final_content = upstream_response.content
            final_headers = dict(upstream_response.headers)
            response_body_for_filter: Optional[Dict[str, Any]] = None

            content_type = upstream_response.headers.get("content-type", "")
            if "application/json" in content_type.lower():
                try:
                    raw_payload = upstream_response.json()
                except Exception:
                    raw_payload = {}

                if is_chat_completions:
                    normalized = self.provider_router.normalize_chat_completion(
                        provider_name=provider_name,
                        status_code=upstream_response.status_code,
                        payload=raw_payload if isinstance(raw_payload, dict) else {},
                    )
                    final_status = normalized.status_code
                    response_body_for_filter = normalized.payload
                    final_content = json.dumps(normalized.payload).encode("utf-8")
                    final_headers = {"content-type": "application/json"}
                elif isinstance(raw_payload, dict):
                    response_body_for_filter = raw_payload

            # Response content filtering
            if response_body_for_filter is not None:
                response_security = get_content_filter().check_response(response_body_for_filter)
                if response_security["action"] == SecurityAction.BLOCK:
                    reason = f"Response blocked: {response_security['reason']}"
                    await self._emit_gateway_event(
                        request_id=request_id,
                        decision="BLOCK",
                        request=request,
                        request_body=request_body,
                        model_name=model_name,
                        provider_name=provider_name,
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
                    return self._json_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        message=reason,
                        error_type="content_blocked",
                        code="policy_violation",
                    )

                if response_security["action"] in (
                    SecurityAction.CONSTRAIN,
                    SecurityAction.LOG_ONLY,
                ):
                    logger.warning(
                        f"Response {request_id} flagged by content filter: "
                        f"{response_security['reason']}"
                    )

            await self._emit_gateway_event(
                request_id=request_id,
                decision=final_decision.decision.value,
                request=request,
                request_body=request_body,
                model_name=model_name,
                provider_name=provider_name,
                org_id=org_id,
                user_id=user_id,
                risk_score=final_decision.risk_score,
                response_status=final_status,
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

            for h in ["content-encoding", "transfer-encoding", "content-length", "connection"]:
                final_headers.pop(h, None)

            return Response(
                content=final_content,
                status_code=final_status,
                headers=final_headers,
            )

        except ProviderConfigurationError as exc:
            response_time_ms = int((time.time() - start_time) * 1000)
            reason = str(exc)
            logger.error(f"Request {request_id} provider configuration error: {reason}")
            await self._emit_gateway_event(
                request_id=request_id,
                decision="ERROR",
                request=request,
                request_body=request_body,
                model_name=model_name,
                provider_name=provider_name,
                org_id=org_id,
                user_id=user_id,
                risk_score=final_decision.risk_score,
                response_status=status.HTTP_503_SERVICE_UNAVAILABLE,
                response_time_ms=response_time_ms,
                reason=reason,
                attributes={"exception": "provider_configuration_error"},
            )
            return self._json_error_response(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                message=reason,
                error_type="provider_configuration_error",
                code="provider_not_configured",
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
                provider_name=provider_name,
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
                detail="Failed to reach provider endpoint",
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
        provider_name: str,
        org_id: Optional[str],
        user_id: Optional[str],
        risk_score: Optional[int] = None,
        response_status: Optional[int] = None,
        response_time_ms: Optional[int] = None,
        reason: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist structured event row for analytics and forensic use."""
        agent_context = self._extract_agent_context(request)
        merged_attributes = {
            **(attributes or {}),
            **agent_context,
        }
        telemetry_metrics.record_event(
            decision=decision,
            provider=provider_name,
            response_time_ms=response_time_ms,
            attributes=merged_attributes,
            reason=reason,
        )
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
                "provider": provider_name,
                "request_body": request_body,
                **merged_attributes,
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
            content=json.dumps(
                {
                    "error": {
                        "message": message,
                        "type": error_type,
                        "code": code,
                    }
                }
            ),
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

    def _check_entitlement_limits(
        self,
        request_body: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Validate configurable entitlement limits for input and output sizing."""
        if not isinstance(request_body, dict):
            return None

        limits = policy_store.get_entitlements().get("limits", {})
        if not isinstance(limits, dict):
            return None

        max_input_chars = limits.get("max_input_chars")
        if isinstance(max_input_chars, int) and max_input_chars > 0:
            input_chars = self._estimate_input_chars(request_body)
            if input_chars > max_input_chars:
                return {
                    "status_code": status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    "message": (
                        f"Input exceeds entitlement limit ({input_chars} > "
                        f"{max_input_chars} characters)"
                    ),
                    "code": "max_input_chars_exceeded",
                    "attributes": {
                        "block_type": "entitlement_limits",
                        "input_chars": input_chars,
                        "max_input_chars": max_input_chars,
                    },
                }

        max_output_tokens = limits.get("max_output_tokens")
        if isinstance(max_output_tokens, int) and max_output_tokens > 0:
            requested_tokens = request_body.get("max_tokens")
            if requested_tokens is not None:
                try:
                    requested = int(requested_tokens)
                except (TypeError, ValueError):
                    requested = 0
                if requested > max_output_tokens:
                    return {
                        "status_code": status.HTTP_403_FORBIDDEN,
                        "message": (
                            f"Requested max_tokens exceeds entitlement limit "
                            f"({requested} > {max_output_tokens})"
                        ),
                        "code": "max_output_tokens_exceeded",
                        "attributes": {
                            "block_type": "entitlement_limits",
                            "requested_max_tokens": requested,
                            "max_output_tokens": max_output_tokens,
                        },
                    }

        return None

    def _estimate_input_chars(self, request_body: Dict[str, Any]) -> int:
        """Estimate total inbound prompt characters from chat payload."""
        chars = 0
        system_field = request_body.get("system")
        if isinstance(system_field, str):
            chars += len(system_field)

        messages = request_body.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                chars += len(extract_text(msg.get("content")))
        return chars

    def _provider_endpoint(self, provider_name: str) -> str:
        """Get configured provider endpoint."""
        provider = provider_name.lower()
        if provider == "openai":
            return (settings.openai_endpoint or settings.llm_endpoint).rstrip("/")
        if provider == "anthropic":
            return settings.anthropic_endpoint.rstrip("/")
        if provider == "gemini":
            return settings.gemini_endpoint.rstrip("/")
        if provider == "openrouter":
            return settings.openrouter_endpoint.rstrip("/")
        return settings.llm_endpoint.rstrip("/")

    def _provider_api_key(self, provider_name: str) -> str:
        """Get configured provider API key."""
        provider = provider_name.lower()
        if provider == "openai":
            return (settings.openai_api_key or settings.llm_api_key).strip()
        if provider == "anthropic":
            return (settings.anthropic_api_key or settings.llm_api_key).strip()
        if provider == "gemini":
            return (settings.gemini_api_key or settings.llm_api_key).strip()
        if provider == "openrouter":
            return (settings.openrouter_api_key or settings.llm_api_key).strip()
        return settings.llm_api_key.strip()

    def _build_passthrough_url(self, provider_name: str, path: str, query: str) -> str:
        """Build upstream URL for non-chat-completions passthrough routes."""
        base = self._provider_endpoint(provider_name)
        normalized_path = path
        if normalized_path.startswith("/v1/") and base.endswith("/v1"):
            normalized_path = normalized_path[3:]
        target_url = f"{base}{normalized_path}"
        if query:
            target_url += f"?{query}"
        return target_url

    def _build_passthrough_headers(
        self,
        provider_name: str,
        incoming_headers: Dict[str, str],
    ) -> Dict[str, str]:
        """Build passthrough headers with provider-specific authentication defaults."""
        headers = dict(incoming_headers)
        for h in [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "x-admin-key",
            "x-forwarded-for",
            "x-real-ip",
            "cf-connecting-ip",
        ]:
            headers.pop(h, None)

        provider_key = self._provider_api_key(provider_name)
        if provider_name in {"openai", "openrouter"}:
            if "authorization" not in headers and provider_key:
                headers["authorization"] = f"Bearer {provider_key}"
        elif provider_name == "anthropic":
            if "x-api-key" not in headers and provider_key:
                headers["x-api-key"] = provider_key
            if "anthropic-version" not in headers:
                headers["anthropic-version"] = settings.anthropic_api_version

        return headers

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        if settings.trust_proxy_headers:
            headers = request.headers
            for header in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]:
                if header in headers:
                    ip = headers[header].split(",")[0].strip()
                    if ip:
                        return ip
        return request.client.host if request.client else "unknown"

    def _extract_agent_context(self, request: Request) -> Dict[str, Any]:
        """Extract managed-agent context for audit/event attributes."""
        context: Dict[str, Any] = {}

        state_context = getattr(request.state, "agent_context", None)
        if isinstance(state_context, dict):
            for key in ("agent_id", "agent_type", "agent_wrapped", "a2a_interaction_id"):
                if key in state_context:
                    context[key] = state_context[key]

        headers = request.headers
        for header, key in (
            ("x-agent-id", "agent_id"),
            ("x-agent-type", "agent_type"),
            ("x-agent-session-id", "agent_session_id"),
            ("x-a2a-interaction-id", "a2a_interaction_id"),
        ):
            value = headers.get(header)
            if value:
                context[key] = value

        return context

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
