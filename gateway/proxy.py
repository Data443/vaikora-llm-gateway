"""
Data443 LLM Gateway - Request Interception Layer

Intercepts LLM API requests, evaluates policy, and forwards to target endpoint.
Supports OpenAI-compatible APIs.
"""

import json
import uuid
from typing import Optional, Dict, Any

from fastapi import Request, Response, HTTPException, status
from httpx import AsyncClient, Timeout
from loguru import logger

from config.settings import settings
from gateway.policy import PolicyEngine, PolicyDecision, Decision
from gateway.cache import cache


class ProxyHandler:
    """Handler for proxying LLM API requests with policy evaluation."""

    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.llm_endpoint = settings.llm_endpoint
        self.timeout = Timeout(60.0)  # Long timeout for LLM requests

    async def handle_request(self, request: Request) -> Response:
        """
        Handle incoming LLM API request.

        1. Extract request details (IP, URL, headers, body)
        2. Evaluate policy using threat intelligence
        3. Forward request if ALLOWED, return error if BLOCKED
        4. Log all decisions
        """
        # Extract client information
        client_ip = self._get_client_ip(request)
        request_id = str(uuid.uuid4())

        # Parse request URL for classification
        request_url = str(request.url)

        # Read request body
        try:
            request_body = await request.json()
        except Exception:
            request_body = None

        # Get user agent
        user_agent = request.headers.get("user-agent", "")

        logger.info(f"Request {request_id} from {client_ip}: {request.method} {request.url.path}")

        # Evaluate policy
        decision = await self.policy_engine.evaluate_request(
            ip_address=client_ip,
            url=request_url,
            user_agent=user_agent,
            request_id=request_id,
            request_method=request.method,
            request_path=request.url.path,
            request_body=request_body,
        )

        # Handle decision
        if decision.decision == Decision.BLOCK:
            logger.warning(f"Request {request_id} BLOCKED: {decision.reason}")
            return self._block_response(decision)

        if decision.decision == Decision.CONSTRAIN:
            logger.warning(f"Request {request_id} CONSTRAINED: {decision.reason}")
            # For CONSTRAIN, we could apply rate limiting, token limits, etc.
            # For now, we'll allow but log heavily
            return await self._forward_request(request, request_id, constrained=True)

        # ALLOW or ALLOW_LOG - forward the request
        return await self._forward_request(request, request_id)

    async def _forward_request(
        self,
        request: Request,
        request_id: str,
        constrained: bool = False,
    ) -> Response:
        """
        Forward request to target LLM endpoint.

        Args:
            request: Original request
            request_id: Request identifier
            constrained: Whether request was constrained

        Returns:
            Response from LLM endpoint
        """
        import time
        start_time = time.time()

        # Build target URL
        path = request.url.path
        query = request.url.query
        target_url = f"{self.llm_endpoint}{path}"
        if query:
            target_url += f"?{query}"

        # Get request body
        try:
            body = await request.json()
        except Exception:
            body = None

        # Prepare headers (exclude hop-by-hop headers)
        headers = dict(request.headers)
        headers_to_remove = ["host", "content-length", "transfer-encoding"]
        for h in headers_to_remove:
            headers.pop(h, None)

        # Add authorization if not present and settings has key
        if "authorization" not in headers and settings.llm_api_key:
            headers["authorization"] = f"Bearer {settings.llm_api_key}"

        # Forward request
        try:
            async with AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method=request.method,
                    url=target_url,
                    json=body,
                    headers=headers,
                )

                response_time_ms = int((time.time() - start_time) * 1000)

                logger.info(
                    f"Request {request_id} completed: "
                    f"status={response.status_code}, "
                    f"time={response_time_ms}ms"
                )

                # Return response
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                )

        except Exception as e:
            logger.error(f"Request {request_id} failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to reach LLM endpoint: {str(e)}"
            )

    def _block_response(self, decision: PolicyDecision) -> Response:
        """
        Return block response.

        Args:
            decision: Policy decision that caused the block

        Returns:
            HTTP 403 Forbidden response
        """
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

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.

        Checks multiple headers for proxy-forwarded requests.
        """
        headers = request.headers

        # Check for forwarded headers
        for header in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]:
            if header in headers:
                ip = headers[header].split(",")[0].strip()
                if ip:
                    return ip

        # Fall back to direct connection
        return request.client.host if request.client else "unknown"

    async def health_check(self) -> Dict[str, Any]:
        """
        Health check endpoint.

        Returns gateway status and component health.
        """
        return {
            "status": "healthy",
            "circuit_breaker": self.policy_engine.cyren_client.get_circuit_breaker_state(),
            "cache_connected": cache.l2.connected,
            "audit_connected": self.policy_engine.audit_logger.connected,
        }


# Global proxy handler
proxy_handler = None


def init_proxy_handler(policy_engine: PolicyEngine) -> ProxyHandler:
    """Initialize the global proxy handler."""
    global proxy_handler
    proxy_handler = ProxyHandler(policy_engine)
    return proxy_handler
