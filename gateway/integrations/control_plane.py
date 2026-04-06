"""
Data443 LLM Gateway — Control Plane Integration

Connects the self-hosted proxy to a remote Vaikora control plane for:
- Policy sync: periodically pulls active policies and caches locally
- Audit federation: batches and pushes audit metadata (no message content)
- HITL: creates approval requests and polls for resolution

All HTTP calls use the X-Proxy-Api-Key header for authentication.
"""

import asyncio
import time
from collections import deque
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger

from gateway.core.config import settings


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
        self._audit_buffer: deque = deque(maxlen=5000)

        # Background task handles
        self._policy_sync_task: Optional[asyncio.Task] = None
        self._audit_push_task: Optional[asyncio.Task] = None

        self._started = False

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
                "Control plane enabled but URL or API key not configured — skipping"
            )
            return

        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.control_plane_request_timeout),
            headers={"X-Proxy-Api-Key": self._api_key},
        )

        # Initial policy sync with retry — the proxy should not start
        # with an empty policy cache if the control plane is just slow.
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            await self._sync_policies_once()
            if self._policies:
                break
            if attempt < max_retries:
                wait = 2 ** attempt
                logger.warning(
                    f"Initial policy sync returned empty "
                    f"(attempt {attempt}/{max_retries}), retrying in {wait}s"
                )
                await asyncio.sleep(wait)

        if not self._policies:
            logger.warning(
                "Starting with empty policy cache — proxy will use "
                "local-only policies until the next successful sync"
            )

        self._policy_sync_task = asyncio.create_task(
            self._policy_sync_loop(), name="control_plane_policy_sync"
        )
        self._audit_push_task = asyncio.create_task(
            self._audit_push_loop(), name="control_plane_audit_push"
        )

        self._started = True
        logger.info(f"Control plane client started — {self._base_url}")

    async def stop(self) -> None:
        """Cancel background tasks and close HTTP client."""
        for task in (self._policy_sync_task, self._audit_push_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Flush remaining audit events before shutdown
        if self._audit_buffer and self._http:
            await self._push_audit_batch()

        if self._http:
            await self._http.aclose()
            self._http = None

        self._started = False
        logger.info("Control plane client stopped")

    @property
    def is_connected(self) -> bool:
        return self._started and self._http is not None

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
            p for p in self._policies
            if p.get("action") == "require_approval"
        ]

    async def _sync_policies_once(self) -> None:
        """Pull policies from the control plane and update local cache."""
        try:
            resp = await self._http.get(
                f"{self._base_url}/api/v1/integration/policies"
            )
            resp.raise_for_status()
            data = resp.json()

            self._policies = data.get("policies", [])
            self._policies_synced_at = time.time()

            logger.info(
                f"Policy sync complete — {len(self._policies)} policies loaded"
            )
        except httpx.HTTPStatusError as e:
            logger.warning(f"Policy sync HTTP error: {e.response.status_code}")
        except Exception as e:
            logger.warning(f"Policy sync failed: {e}")

    async def _policy_sync_loop(self) -> None:
        """Background loop that periodically syncs policies."""
        interval = settings.control_plane_policy_sync_interval
        while True:
            await asyncio.sleep(interval)
            await self._sync_policies_once()

    # ------------------------------------------------------------------
    # Audit Federation
    # ------------------------------------------------------------------

    def queue_audit_event(self, event: Dict[str, Any]) -> None:
        """
        Add an audit event to the outbound buffer.

        The event dict should contain only metadata — no message content.
        Expected keys: event_id, timestamp, agent_key, action_type,
        decision, risk_score, threats_detected, execution_time_ms, etc.
        """
        self._audit_buffer.append(event)

    async def _push_audit_batch(self) -> None:
        """Push a batch of buffered audit events to the control plane."""
        if not self._audit_buffer:
            return

        batch_size = settings.control_plane_audit_batch_size
        batch: List[Dict[str, Any]] = []
        while self._audit_buffer and len(batch) < batch_size:
            batch.append(self._audit_buffer.popleft())

        try:
            resp = await self._http.post(
                f"{self._base_url}/api/v1/integration/audit",
                json={"events": batch},
            )
            resp.raise_for_status()
            result = resp.json()
            logger.debug(
                f"Audit push: {result.get('accepted', 0)} accepted, "
                f"{result.get('errors', 0)} errors"
            )
        except Exception as e:
            logger.warning(f"Audit push failed ({len(batch)} events): {e}")
            # Re-queue the failed batch (prepend so they go first next time)
            for item in reversed(batch):
                self._audit_buffer.appendleft(item)

    async def _audit_push_loop(self) -> None:
        """Background loop that periodically pushes audit batches."""
        interval = settings.control_plane_audit_push_interval
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
        poll_url, and expires_at — or None on failure.
        """
        if not self._http:
            logger.warning("Cannot create HITL request — control plane not connected")
            return None

        payload = {
            "agent_key": agent_key,
            "action_type": action_type,
            "action_details": action_details,
            "policy_id": policy_id,
            "risk_score": risk_score,
            "proxy_request_id": proxy_request_id,
        }

        try:
            resp = await self._http.post(
                f"{self._base_url}/api/v1/integration/hitl/request",
                json=payload,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                f"HITL request created — approval_id={result.get('approval_id')}"
            )
            return result
        except Exception as e:
            logger.error(f"HITL request creation failed: {e}")
            return None

    async def poll_hitl_status(
        self, action_log_id: str
    ) -> Optional[str]:
        """
        Poll the control plane for the approval status of a HITL request.

        Returns the status string (pending, approved, denied, expired)
        or None on failure.
        """
        if not self._http:
            return None

        try:
            resp = await self._http.get(
                f"{self._base_url}/api/v1/integration/hitl/status/{action_log_id}"
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("status")
        except Exception as e:
            logger.warning(f"HITL status poll failed: {e}")
            return None

    async def wait_for_hitl_approval(
        self, action_log_id: str
    ) -> str:
        """
        Block until the HITL request is resolved or times out.

        Returns: 'approved', 'denied', 'expired', or 'timeout'.
        """
        poll_interval = settings.control_plane_hitl_poll_interval
        timeout = settings.control_plane_hitl_timeout
        deadline = time.time() + timeout

        while time.time() < deadline:
            status = await self.poll_hitl_status(action_log_id)
            if status and status != "pending":
                return status
            await asyncio.sleep(poll_interval)

        logger.warning(
            f"HITL approval timed out after {timeout}s — action_log_id={action_log_id}"
        )
        return "timeout"


# Module-level singleton
control_plane_client = ControlPlaneClient()
