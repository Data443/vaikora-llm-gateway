"""Agent management and A2A interaction registry."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from loguru import logger

from gateway.integrations.audit import AuditLogger


_VALID_AGENT_STATUS = {"ACTIVE", "INACTIVE", "SUSPENDED"}
_VALID_INTERACTION_STATUS = {"PENDING", "APPROVED", "BLOCKED"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AgentRegistry:
    """Registry for managed agents and A2A interaction state."""

    def __init__(self) -> None:
        self._audit_logger: Optional[AuditLogger] = None
        self._agents: Dict[str, Dict[str, Any]] = {}
        self._links: Dict[str, Dict[str, Any]] = {}
        self._interactions: Dict[str, Dict[str, Any]] = {}

    async def initialize(self, audit_logger: AuditLogger) -> None:
        """Initialize optional persistent backing store."""
        self._audit_logger = audit_logger
        if not audit_logger.connected:
            logger.warning("Agent registry running in fallback mode (no PostgreSQL)")
            return

        try:
            agents = await audit_logger.list_managed_agents(limit=1000, offset=0)
            for item in agents:
                normalized = self._normalize_agent(item)
                self._agents[normalized["agent_id"]] = normalized

            links = await audit_logger.list_agent_links(limit=2000, offset=0)
            for item in links:
                normalized = self._normalize_link(item)
                key = self._link_key(
                    normalized["source_agent_id"],
                    normalized["target_agent_id"],
                    normalized["protocol"],
                )
                self._links[key] = normalized
        except Exception as exc:
            logger.warning(f"Agent registry init load failed; using fallback cache only: {exc}")

    async def create_or_wrap_agent(
        self,
        *,
        agent_id: Optional[str],
        display_name: str,
        agent_type: str,
        wrapped: bool,
        status: str = "ACTIVE",
        metadata: Optional[Dict[str, Any]] = None,
        changed_by: str = "admin",
    ) -> Dict[str, Any]:
        """Create or wrap an agent record."""
        resolved_id = (agent_id or str(uuid.uuid4())).strip()
        if not resolved_id:
            raise ValueError("agent_id is required")

        normalized_status = status.strip().upper()
        if normalized_status not in _VALID_AGENT_STATUS:
            raise ValueError(f"Invalid agent status: {status}")

        payload = {
            "agent_id": resolved_id,
            "display_name": display_name.strip(),
            "agent_type": agent_type.strip(),
            "wrapped": bool(wrapped),
            "status": normalized_status,
            "metadata": metadata or {},
        }

        if self._audit_logger and self._audit_logger.connected:
            row = await self._audit_logger.upsert_managed_agent(
                agent_id=payload["agent_id"],
                display_name=payload["display_name"],
                agent_type=payload["agent_type"],
                wrapped=payload["wrapped"],
                status=payload["status"],
                metadata=payload["metadata"],
                changed_by=changed_by,
            )
            if row:
                normalized = self._normalize_agent(row)
                self._agents[normalized["agent_id"]] = normalized
                return deepcopy(normalized)

        now = _utc_now()
        existing = self._agents.get(payload["agent_id"], {})
        record = {
            **payload,
            "created_at": existing.get("created_at", now),
            "updated_at": now,
            "created_by": existing.get("created_by", changed_by),
            "updated_by": changed_by,
        }
        self._agents[payload["agent_id"]] = record
        return deepcopy(record)

    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get a managed agent by id."""
        key = agent_id.strip()
        if not key:
            return None

        if self._audit_logger and self._audit_logger.connected:
            row = await self._audit_logger.get_managed_agent(key)
            if row:
                normalized = self._normalize_agent(row)
                self._agents[normalized["agent_id"]] = normalized
                return deepcopy(normalized)

        item = self._agents.get(key)
        return deepcopy(item) if item else None

    async def list_agents(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List managed agents."""
        normalized_status = status.strip().upper() if status else None
        if normalized_status and normalized_status not in _VALID_AGENT_STATUS:
            raise ValueError(f"Invalid agent status filter: {status}")

        if self._audit_logger and self._audit_logger.connected:
            rows = await self._audit_logger.list_managed_agents(
                limit=limit,
                offset=offset,
                status=normalized_status,
            )
            items: List[Dict[str, Any]] = []
            for row in rows:
                normalized = self._normalize_agent(row)
                self._agents[normalized["agent_id"]] = normalized
                items.append(deepcopy(normalized))
            return items

        items = list(self._agents.values())
        if normalized_status:
            items = [item for item in items if item.get("status") == normalized_status]
        return [deepcopy(item) for item in items[offset: offset + limit]]

    async def upsert_link(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        protocol: str = "A2A",
        status: str = "ACTIVE",
        metadata: Optional[Dict[str, Any]] = None,
        changed_by: str = "admin",
    ) -> Dict[str, Any]:
        """Create/update an A2A link between two managed agents."""
        source = source_agent_id.strip()
        target = target_agent_id.strip()
        if not source or not target:
            raise ValueError("source_agent_id and target_agent_id are required")
        if source == target:
            raise ValueError("source_agent_id and target_agent_id must be different")

        normalized_status = status.strip().upper()
        if normalized_status not in _VALID_AGENT_STATUS:
            raise ValueError(f"Invalid link status: {status}")

        normalized_protocol = protocol.strip().upper() or "A2A"
        key = self._link_key(source, target, normalized_protocol)

        if self._audit_logger and self._audit_logger.connected:
            row = await self._audit_logger.upsert_agent_link(
                source_agent_id=source,
                target_agent_id=target,
                protocol=normalized_protocol,
                status=normalized_status,
                metadata=metadata or {},
                changed_by=changed_by,
            )
            if row:
                normalized = self._normalize_link(row)
                self._links[key] = normalized
                return deepcopy(normalized)

        now = _utc_now()
        existing = self._links.get(key, {})
        record = {
            "source_agent_id": source,
            "target_agent_id": target,
            "protocol": normalized_protocol,
            "status": normalized_status,
            "metadata": metadata or {},
            "created_at": existing.get("created_at", now),
            "updated_at": now,
            "created_by": existing.get("created_by", changed_by),
            "updated_by": changed_by,
        }
        self._links[key] = record
        return deepcopy(record)

    async def list_links(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source_agent_id: Optional[str] = None,
        target_agent_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List A2A links."""
        source = source_agent_id.strip() if source_agent_id else None
        target = target_agent_id.strip() if target_agent_id else None

        if self._audit_logger and self._audit_logger.connected:
            rows = await self._audit_logger.list_agent_links(
                limit=limit,
                offset=offset,
                source_agent_id=source,
                target_agent_id=target,
            )
            items: List[Dict[str, Any]] = []
            for row in rows:
                normalized = self._normalize_link(row)
                key = self._link_key(
                    normalized["source_agent_id"],
                    normalized["target_agent_id"],
                    normalized["protocol"],
                )
                self._links[key] = normalized
                items.append(deepcopy(normalized))
            return items

        items = list(self._links.values())
        if source:
            items = [item for item in items if item.get("source_agent_id") == source]
        if target:
            items = [item for item in items if item.get("target_agent_id") == target]
        return [deepcopy(item) for item in items[offset: offset + limit]]

    async def create_interaction(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        payload: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        created_by: str = "admin",
    ) -> Dict[str, Any]:
        """Create an A2A interaction record (pending review by default)."""
        source = source_agent_id.strip()
        target = target_agent_id.strip()
        if not source or not target:
            raise ValueError("source_agent_id and target_agent_id are required")

        interaction_id = str(uuid.uuid4())
        review_status = "PENDING"

        if self._audit_logger and self._audit_logger.connected:
            row = await self._audit_logger.create_agent_interaction(
                interaction_id=interaction_id,
                source_agent_id=source,
                target_agent_id=target,
                review_status=review_status,
                payload=payload or {},
                metadata=metadata or {},
                decision_reason=None,
                reviewed_by=created_by,
            )
            if row:
                normalized = self._normalize_interaction(row)
                self._interactions[interaction_id] = normalized
                return deepcopy(normalized)

        now = _utc_now()
        record = {
            "interaction_id": interaction_id,
            "source_agent_id": source,
            "target_agent_id": target,
            "review_status": review_status,
            "payload": payload or {},
            "metadata": metadata or {},
            "decision_reason": None,
            "reviewed_by": created_by,
            "created_at": now,
            "updated_at": now,
        }
        self._interactions[interaction_id] = record
        return deepcopy(record)

    async def review_interaction(
        self,
        *,
        interaction_id: str,
        review_status: str,
        reviewed_by: str = "admin",
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Approve or block an A2A interaction."""
        normalized_status = review_status.strip().upper()
        if normalized_status not in {"APPROVED", "BLOCKED"}:
            raise ValueError(f"Invalid interaction review status: {review_status}")

        key = interaction_id.strip()
        if not key:
            return None

        if self._audit_logger and self._audit_logger.connected:
            row = await self._audit_logger.update_agent_interaction_review(
                interaction_id=key,
                review_status=normalized_status,
                decision_reason=reason,
                reviewed_by=reviewed_by,
                metadata=metadata or {},
            )
            if row:
                normalized = self._normalize_interaction(row)
                self._interactions[key] = normalized
                return deepcopy(normalized)
            return None

        existing = self._interactions.get(key)
        if not existing:
            return None
        updated = {
            **existing,
            "review_status": normalized_status,
            "decision_reason": reason,
            "reviewed_by": reviewed_by,
            "metadata": {**(existing.get("metadata") or {}), **(metadata or {})},
            "updated_at": _utc_now(),
        }
        self._interactions[key] = updated
        return deepcopy(updated)

    async def get_interaction(self, interaction_id: str) -> Optional[Dict[str, Any]]:
        """Get a2a interaction record by id."""
        key = interaction_id.strip()
        if not key:
            return None

        if self._audit_logger and self._audit_logger.connected:
            row = await self._audit_logger.get_agent_interaction(key)
            if row:
                normalized = self._normalize_interaction(row)
                self._interactions[key] = normalized
                return deepcopy(normalized)

        item = self._interactions.get(key)
        return deepcopy(item) if item else None

    async def list_interactions(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source_agent_id: Optional[str] = None,
        target_agent_id: Optional[str] = None,
        review_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List A2A interactions."""
        normalized_status = review_status.strip().upper() if review_status else None
        if normalized_status and normalized_status not in _VALID_INTERACTION_STATUS:
            raise ValueError(f"Invalid interaction status filter: {review_status}")

        source = source_agent_id.strip() if source_agent_id else None
        target = target_agent_id.strip() if target_agent_id else None

        if self._audit_logger and self._audit_logger.connected:
            rows = await self._audit_logger.list_agent_interactions(
                limit=limit,
                offset=offset,
                source_agent_id=source,
                target_agent_id=target,
                review_status=normalized_status,
            )
            items: List[Dict[str, Any]] = []
            for row in rows:
                normalized = self._normalize_interaction(row)
                self._interactions[normalized["interaction_id"]] = normalized
                items.append(deepcopy(normalized))
            return items

        items = list(self._interactions.values())
        if source:
            items = [item for item in items if item.get("source_agent_id") == source]
        if target:
            items = [item for item in items if item.get("target_agent_id") == target]
        if normalized_status:
            items = [item for item in items if item.get("review_status") == normalized_status]
        return [deepcopy(item) for item in items[offset: offset + limit]]

    def _normalize_agent(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "agent_id": str(row.get("agent_id", "")).strip(),
            "display_name": str(row.get("display_name", "")).strip(),
            "agent_type": str(row.get("agent_type", "")).strip(),
            "status": str(row.get("status", "ACTIVE")).strip().upper(),
            "wrapped": bool(row.get("wrapped", False)),
            "metadata": deepcopy(row.get("metadata", {})),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "created_by": row.get("created_by"),
            "updated_by": row.get("updated_by"),
        }

    def _normalize_link(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source_agent_id": str(row.get("source_agent_id", "")).strip(),
            "target_agent_id": str(row.get("target_agent_id", "")).strip(),
            "protocol": str(row.get("protocol", "A2A")).strip().upper(),
            "status": str(row.get("status", "ACTIVE")).strip().upper(),
            "metadata": deepcopy(row.get("metadata", {})),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "created_by": row.get("created_by"),
            "updated_by": row.get("updated_by"),
        }

    def _normalize_interaction(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "interaction_id": str(row.get("interaction_id", "")).strip(),
            "source_agent_id": str(row.get("source_agent_id", "")).strip(),
            "target_agent_id": str(row.get("target_agent_id", "")).strip(),
            "review_status": str(row.get("review_status", "PENDING")).strip().upper(),
            "payload": deepcopy(row.get("payload", {})),
            "metadata": deepcopy(row.get("metadata", {})),
            "decision_reason": row.get("decision_reason"),
            "reviewed_by": row.get("reviewed_by"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }

    def _link_key(self, source_agent_id: str, target_agent_id: str, protocol: str) -> str:
        return f"{source_agent_id}::{target_agent_id}::{protocol}"


agent_registry = AgentRegistry()

