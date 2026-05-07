"""
Data443 LLM Gateway - Control Plane Integration

Connects the self-hosted proxy to a remote Vaikora control plane for:
- Policy sync: periodically pulls active policies and caches locally
- Audit federation: batches and pushes audit metadata (no message content)
- HITL: creates approval requests and polls for resolution

All HTTP calls use the X-Proxy-Api-Key header for authentication.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger

from gateway.core.config import settings
from gateway.integrations.telemetry import telemetry_metrics


_REDACTED = "[REDACTED]"
_CONTENT_KEYS = {
    "content",
    "prompt",
    "input",
    "messages",
    "message_preview",
    "request_body",
    "response_body",
    "response_content",
    "system_prompt",
}


class ControlPlaneClient:
    """
    Client for communicating with the Vaikora control plane.

    Lifecycle:
        client = ControlPlaneClient()
        await client.start()    # begins background sync loops
        ...
        await client.stop()     # cancels loops, closes HTTP client
    """

    def __init__(self) -> None:
        self._http: Optional[httpx.AsyncClient] = None
        self._base_url: str = ""
        self._api_key: str = ""

        # Cached policies from the control plane
        self._policies: List[Dict[str, Any]] = []
        self._policies_synced_at: Optional[float] = None

        # Audit event buffer (pushed in batches)
        self._audit_buffer: deque[Dict[str, Any]] = deque()
        self._audit_buffer_max_size = int(settings.control_plane_audit_buffer_size)
        self._dropped_audit_events = 0

        # Background task handles
        self._policy_sync_task: Optional[asyncio.Task] = None
        self._audit_push_task: Optional[asyncio.Task] = None

        # Local DB pool for persistent policy cache (set externally)
        self._db_pool = None

        self._started = False

        # Request/circuit state
        self._consecutive_failures = 0
        self._circuit_open_until: Optional[float] = None

        # Policy sync state
        self._last_policy_sync_attempt_at: Optional[float] = None
        self._last_policy_sync_success_at: Optional[float] = None
        self._last_policy_sync_status = "never"
        self._last_policy_sync_error: Optional[str] = None

        # Audit push state
        self._last_audit_push_attempt_at: Optional[float] = None
        self._last_audit_push_success_at: Optional[float] = None
        self._last_audit_push_status = "never"
        self._last_audit_push_error: Optional[str] = None

        # HITL state
        self._last_hitl_request_at: Optional[float] = None
        self._last_hitl_status = "never"
        self._last_hitl_error: Optional[str] = None

    def set_db_pool(self, pool) -> None:
        """Inject the gateway's asyncpg pool for persistent caching."""
        self._db_pool = pool

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Initialize HTTP client and start background sync loops."""
        if not settings.control_plane_enabled:
            logger.info("Control plane integration disabled")
            return

        self._base_url = settings.control_plane_url.rstrip("/")
        self._api_key = settings.control_plane_api_key

        if not self._base_url or not self._api_key:
            logger.warning(
                "Control plane enabled but URL or API key not configured - skipping"
            )
            return

        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.control_plane_request_timeout),
            headers={"X-Proxy-Api-Key": self._api_key},
        )

        max_retries = max(1, int(settings.control_plane_startup_sync_retries))
        sync_succeeded = False
        for attempt in range(1, max_retries + 1):
            sync_succeeded = await self._sync_policies_once()
            if sync_succeeded:
                break
            if attempt < max_retries:
                wait_seconds = 2 ** attempt
                logger.warning(
                    "Initial policy sync failed (attempt {}/{}) - retrying in {}s",
                    attempt,
                    max_retries,
                    wait_seconds,
                )
                await asyncio.sleep(wait_seconds)

        if not sync_succeeded and not self._policies:
            loaded = await self._load_policies_from_db()
            if not loaded:
                logger.warning(
                    "Starting with empty policy cache - proxy will use local-only "
                    "policies until the next successful sync"
                )

        self._policy_sync_task = asyncio.create_task(
            self._policy_sync_loop(),
            name="control_plane_policy_sync",
        )
        self._audit_push_task = asyncio.create_task(
            self._audit_push_loop(),
            name="control_plane_audit_push",
        )

        self._started = True
        logger.info("Control plane client started - {}", self._base_url)

    async def stop(self) -> None:
        """Cancel background tasks and close HTTP client."""
        for task in (self._policy_sync_task, self._audit_push_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        if self._http and self._audit_buffer:
            remaining_batches = 3
            while self._audit_buffer and remaining_batches > 0:
                before = len(self._audit_buffer)
                await self._push_audit_batch()
                after = len(self._audit_buffer)
                remaining_batches -= 1
                if after >= before:
                    break

        if self._http:
            await self._http.aclose()
            self._http = None

        self._started = False
        logger.info("Control plane client stopped")

    @property
    def is_connected(self) -> bool:
        return self._started and self._http is not None

    # ------------------------------------------------------------------
    # Request / circuit state
    # ------------------------------------------------------------------

    def _current_time(self) -> float:
        return time.time()

    def _reset_circuit(self) -> None:
        if self._consecutive_failures or self._circuit_open_until:
            logger.info("Control plane connectivity recovered")
        self._consecutive_failures = 0
        self._circuit_open_until = None

    def _is_circuit_open(self) -> bool:
        if self._circuit_open_until is None:
            return False

        now = self._current_time()
        if now >= self._circuit_open_until:
            self._reset_circuit()
            return False
        return True

    def _parse_retry_after(self, response: httpx.Response) -> Optional[int]:
        header_value = response.headers.get("Retry-After")
        if not header_value:
            return None
        try:
            return max(1, int(header_value))
        except (TypeError, ValueError):
            return None

    def _register_failure(
        self,
        *,
        operation: str,
        rate_limited: bool = False,
        retry_after: Optional[int] = None,
    ) -> None:
        self._consecutive_failures += 1
        telemetry_metrics.record_control_plane_event(
            operation=operation,
            outcome="rate_limited" if rate_limited else "failure",
        )

        if rate_limited:
            cooldown = retry_after or settings.control_plane_circuit_breaker_recovery_timeout
            self._circuit_open_until = self._current_time() + max(1, int(cooldown))
            telemetry_metrics.record_control_plane_event(
                operation=operation,
                outcome="circuit_opened",
            )
            logger.warning(
                "Control plane rate limited {} requests - backing off for {}s",
                operation,
                int(cooldown),
            )
            return

        threshold = max(1, int(settings.control_plane_circuit_breaker_failure_threshold))
        if self._consecutive_failures >= threshold:
            cooldown = max(1, int(settings.control_plane_circuit_breaker_recovery_timeout))
            self._circuit_open_until = self._current_time() + cooldown
            telemetry_metrics.record_control_plane_event(
                operation=operation,
                outcome="circuit_opened",
            )
            logger.warning(
                "Control plane circuit opened after {} consecutive failures; retrying in {}s",
                self._consecutive_failures,
                cooldown,
            )

    async def _request(self, method: str, path: str, *, operation: str, **kwargs) -> httpx.Response:
        if not self._http:
            raise RuntimeError("control plane client is not connected")

        if self._is_circuit_open():
            telemetry_metrics.record_control_plane_event(
                operation=operation,
                outcome="circuit_open",
            )
            raise RuntimeError("control plane circuit is open")

        failure_recorded = False
        try:
            response = await self._http.request(method, f"{self._base_url}{path}", **kwargs)
            if response.status_code == 429:
                retry_after = self._parse_retry_after(response)
                self._register_failure(
                    operation=operation,
                    rate_limited=True,
                    retry_after=retry_after,
                )
                failure_recorded = True
                response.raise_for_status()

            response.raise_for_status()
            self._reset_circuit()
            telemetry_metrics.record_control_plane_event(
                operation=operation,
                outcome="success",
            )
            return response
        except httpx.HTTPStatusError:
            if not failure_recorded:
                self._register_failure(operation=operation)
            raise
        except Exception:
            if not failure_recorded:
                self._register_failure(operation=operation)
            raise

    def _timestamp_to_iso(self, value: Optional[float]) -> Optional[str]:
        if value is None:
            return None
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))

    def _policy_cache_age_seconds(self) -> Optional[int]:
        if self._policies_synced_at is None:
            return None
        return max(0, int(self._current_time() - self._policies_synced_at))

    def health_snapshot(self) -> Dict[str, Any]:
        """Return control-plane health details for /health and ops visibility."""
        if not settings.control_plane_enabled:
            return {
                "enabled": False,
                "status": "disabled",
            }

        cache_age_seconds = self._policy_cache_age_seconds()
        stale_after = int(settings.control_plane_policy_stale_after_seconds)
        cache_stale = bool(
            stale_after > 0
            and cache_age_seconds is not None
            and cache_age_seconds > stale_after
        )

        status = "healthy"
        if not self.is_connected or self._is_circuit_open():
            status = "degraded"
        if self._last_policy_sync_status == "failed" and not self._policies:
            status = "degraded"
        if cache_stale:
            status = "degraded"

        return {
            "enabled": True,
            "status": status,
            "base_url": self._base_url or None,
            "circuit_state": "open" if self._is_circuit_open() else "closed",
            "policy_count": len(self._policies),
            "policy_cache_age_seconds": cache_age_seconds,
            "policy_cache_stale": cache_stale,
            "policies_synced_at": self._timestamp_to_iso(self._policies_synced_at),
            "last_policy_sync_status": self._last_policy_sync_status,
            "last_policy_sync_error": self._last_policy_sync_error,
            "last_policy_sync_attempt_at": self._timestamp_to_iso(self._last_policy_sync_attempt_at),
            "last_policy_sync_success_at": self._timestamp_to_iso(self._last_policy_sync_success_at),
            "last_audit_push_status": self._last_audit_push_status,
            "last_audit_push_error": self._last_audit_push_error,
            "last_audit_push_attempt_at": self._timestamp_to_iso(self._last_audit_push_attempt_at),
            "last_audit_push_success_at": self._timestamp_to_iso(self._last_audit_push_success_at),
            "audit_buffer_depth": len(self._audit_buffer),
            "audit_buffer_capacity": self._audit_buffer_max_size,
            "audit_events_dropped": self._dropped_audit_events,
            "last_hitl_status": self._last_hitl_status,
            "last_hitl_error": self._last_hitl_error,
            "last_hitl_request_at": self._timestamp_to_iso(self._last_hitl_request_at),
        }

    # ------------------------------------------------------------------
    # Policy Sync
    # ------------------------------------------------------------------

    @property
    def synced_policies(self) -> List[Dict[str, Any]]:
        """Return the last-synced policy list (read-only)."""
        return list(self._policies)

    def get_require_approval_policies(self) -> List[Dict[str, Any]]:
        """Return only policies whose action is 'require_approval'."""
        return [
            policy
            for policy in self._policies
            if policy.get("action") == "require_approval"
        ]

    async def _save_policies_to_db(self) -> None:
        """Persist the current policy cache to local PostgreSQL."""
        if not self._db_pool or not self._policies:
            return

        try:
            async with self._db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO control_plane_policy_cache
                        (organization_id, policies, synced_at, source_url)
                    VALUES ($1, $2, NOW(), $3)
                    """,
                    "",
                    json.dumps(self._policies),
                    self._base_url,
                )
            logger.debug("Saved {} policies to local cache", len(self._policies))
        except Exception as exc:
            logger.warning("Failed to save policies to local DB: {}", exc)

    async def _load_policies_from_db(self) -> bool:
        """
        Load policies from local PostgreSQL cache.

        Returns True if policies were loaded, False otherwise.
        """
        if not self._db_pool:
            return False

        try:
            async with self._db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT policies, synced_at
                    FROM control_plane_policy_cache
                    ORDER BY synced_at DESC
                    LIMIT 1
                    """
                )
            if row and row["policies"]:
                self._policies = json.loads(row["policies"])
                self._policies_synced_at = row["synced_at"].timestamp()
                logger.info(
                    "Loaded {} policies from local cache (synced at {})",
                    len(self._policies),
                    row["synced_at"].isoformat(),
                )
                telemetry_metrics.record_control_plane_event(
                    operation="policy_sync",
                    outcome="cache_loaded",
                )
                return True
        except Exception as exc:
            logger.warning("Failed to load policies from local DB: {}", exc)
        return False

    async def _sync_policies_once(self) -> bool:
        """Pull policies from the control plane and update local cache."""
        self._last_policy_sync_attempt_at = self._current_time()
        try:
            response = await self._request(
                "GET",
                "/api/v1/integration/policies",
                operation="policy_sync",
            )
            data = response.json()
            policies = data.get("policies", [])
            if not isinstance(policies, list):
                raise ValueError("control plane policies payload is not a list")

            self._policies = policies
            self._policies_synced_at = self._current_time()
            self._last_policy_sync_success_at = self._policies_synced_at
            self._last_policy_sync_status = "success"
            self._last_policy_sync_error = None

            logger.info("Policy sync complete - {} policies loaded", len(self._policies))
            await self._save_policies_to_db()
            return True
        except Exception as exc:
            self._last_policy_sync_status = "failed"
            self._last_policy_sync_error = str(exc)
            logger.warning("Policy sync failed: {}", exc)

            if not self._policies:
                await self._load_policies_from_db()
            return False

    async def _policy_sync_loop(self) -> None:
        """Background loop that periodically syncs policies."""
        interval = max(1, int(settings.control_plane_policy_sync_interval))
        while True:
            await asyncio.sleep(interval)
            await self._sync_policies_once()

    # ------------------------------------------------------------------
    # Audit Federation
    # ------------------------------------------------------------------

    def _sanitize_outbound_payload(self, value: Any, *, parent_key: Optional[str] = None) -> Any:
        """Remove prompt/message content from outbound control-plane payloads."""
        if isinstance(value, dict):
            sanitized: Dict[str, Any] = {}
            for key, item in value.items():
                normalized_key = str(key).strip().lower()
                if normalized_key in _CONTENT_KEYS or normalized_key.endswith("_body"):
                    sanitized[str(key)] = _REDACTED
                    continue
                sanitized[str(key)] = self._sanitize_outbound_payload(
                    item,
                    parent_key=normalized_key,
                )
            return sanitized
        if isinstance(value, list):
            if parent_key in {"messages"}:
                return _REDACTED
            return [self._sanitize_outbound_payload(item, parent_key=parent_key) for item in value]
        return value

    def queue_audit_event(self, event: Dict[str, Any]) -> None:
        """
        Add an audit event to the outbound buffer.

        The event dict should contain only metadata - no message content.
        Expected keys: event_id, timestamp, agent_key, action_type,
        decision, risk_score, threats_detected, execution_time_ms, etc.
        """
        sanitized_event = self._sanitize_outbound_payload(event)

        if len(self._audit_buffer) >= self._audit_buffer_max_size:
            self._dropped_audit_events += 1
            telemetry_metrics.record_control_plane_event(
                operation="audit_queue",
                outcome="dropped",
            )
            if self._dropped_audit_events in {1, 10} or self._dropped_audit_events % 100 == 0:
                logger.warning(
                    "Control plane audit buffer full - dropped {} event(s)",
                    self._dropped_audit_events,
                )
            return

        self._audit_buffer.append(sanitized_event)
        telemetry_metrics.record_control_plane_event(
            operation="audit_queue",
            outcome="queued",
        )

    def _requeue_failed_batch(self, batch: List[Dict[str, Any]]) -> None:
        for item in reversed(batch):
            if len(self._audit_buffer) >= self._audit_buffer_max_size:
                self._dropped_audit_events += 1
                telemetry_metrics.record_control_plane_event(
                    operation="audit_queue",
                    outcome="dropped",
                )
                continue
            self._audit_buffer.appendleft(item)

    async def _push_audit_batch(self) -> None:
        """Push a batch of buffered audit events to the control plane."""
        if not self._audit_buffer:
            return

        self._last_audit_push_attempt_at = self._current_time()
        batch_size = max(1, int(settings.control_plane_audit_batch_size))
        batch: List[Dict[str, Any]] = []
        while self._audit_buffer and len(batch) < batch_size:
            batch.append(self._audit_buffer.popleft())

        try:
            response = await self._request(
                "POST",
                "/api/v1/integration/audit",
                operation="audit_push",
                json={"events": batch},
            )
            result = response.json()
            self._last_audit_push_success_at = self._current_time()
            self._last_audit_push_status = "success"
            self._last_audit_push_error = None
            logger.debug(
                "Audit push: {} accepted, {} errors",
                result.get("accepted", 0),
                result.get("errors", 0),
            )
        except Exception as exc:
            self._last_audit_push_status = "failed"
            self._last_audit_push_error = str(exc)
            logger.warning("Audit push failed ({} events): {}", len(batch), exc)
            self._requeue_failed_batch(batch)

    async def _audit_push_loop(self) -> None:
        """Background loop that periodically pushes audit batches."""
        interval = max(1, int(settings.control_plane_audit_push_interval))
        while True:
            await asyncio.sleep(interval)
            await self._push_audit_batch()

    # ------------------------------------------------------------------
    # HITL (Human-in-the-Loop)
    # ------------------------------------------------------------------

    async def create_hitl_request(
        self,
        agent_key: str,
        action_type: str,
        action_details: Dict[str, Any],
        policy_id: Optional[str] = None,
        risk_score: float = 0.0,
        proxy_request_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Create an approval request on the control plane.

        Returns the response dict with approval_id, action_log_id,
        poll_url, and expires_at - or None on failure.
        """
        if not self._http:
            logger.warning("Cannot create HITL request - control plane not connected")
            self._last_hitl_status = "unavailable"
            self._last_hitl_error = "control plane not connected"
            telemetry_metrics.record_control_plane_event(
                operation="hitl_create",
                outcome="unavailable",
            )
            return None

        self._last_hitl_request_at = self._current_time()
        payload = {
            "agent_key": agent_key,
            "action_type": action_type,
            "action_details": self._sanitize_outbound_payload(action_details),
            "policy_id": policy_id,
            "risk_score": risk_score,
            "proxy_request_id": proxy_request_id,
        }

        try:
            response = await self._request(
                "POST",
                "/api/v1/integration/hitl/request",
                operation="hitl_create",
                json=payload,
            )
            result = response.json()
            self._last_hitl_status = "success"
            self._last_hitl_error = None
            logger.info("HITL request created - approval_id={}", result.get("approval_id"))
            return result
        except Exception as exc:
            self._last_hitl_status = "failed"
            self._last_hitl_error = str(exc)
            logger.error("HITL request creation failed: {}", exc)
            return None

    async def poll_hitl_status(self, action_log_id: str) -> Optional[str]:
        """
        Poll the control plane for the approval status of a HITL request.

        Returns the status string (pending, approved, denied, expired)
        or None on failure.
        """
        if not self._http:
            telemetry_metrics.record_control_plane_event(
                operation="hitl_poll",
                outcome="unavailable",
            )
            return None

        try:
            response = await self._request(
                "GET",
                f"/api/v1/integration/hitl/status/{action_log_id}",
                operation="hitl_poll",
            )
            data = response.json()
            self._last_hitl_status = "success"
            self._last_hitl_error = None
            return data.get("status")
        except Exception as exc:
            self._last_hitl_status = "failed"
            self._last_hitl_error = str(exc)
            logger.warning("HITL status poll failed: {}", exc)
            return None

    async def wait_for_hitl_approval(self, action_log_id: str) -> str:
        """
        Block until the HITL request is resolved or times out.

        Returns: 'approved', 'denied', 'expired', or 'timeout'.
        """
        poll_interval = max(1, int(settings.control_plane_hitl_poll_interval))
        timeout = max(1, int(settings.control_plane_hitl_timeout))
        deadline = self._current_time() + timeout

        while self._current_time() < deadline:
            status = await self.poll_hitl_status(action_log_id)
            if status and status != "pending":
                return status
            await asyncio.sleep(poll_interval)

        logger.warning(
            "HITL approval timed out after {}s - action_log_id={}",
            timeout,
            action_log_id,
        )
        self._last_hitl_status = "timeout"
        self._last_hitl_error = None
        telemetry_metrics.record_control_plane_event(
            operation="hitl_poll",
            outcome="timeout",
        )
        return "timeout"


# Module-level singleton
control_plane_client = ControlPlaneClient()