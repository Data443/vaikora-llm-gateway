"""Agent management and A2A interaction registry."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
import uuid

from loguru import logger

from gateway.core.config import settings
from gateway.integrations.audit import AuditLogger
from gateway.integrations.telemetry import telemetry_metrics


_VALID_AGENT_STATUS = {"ACTIVE", "INACTIVE", "SUSPENDED"}
_VALID_LINK_STATUS = {"ACTIVE", "INACTIVE", "BLOCKED", "PENDING"}
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
        existing = self._agents.get(payload["agent_id"], {})
        is_new = not bool(existing)
        lifecycle_event = "agent_wrapped" if payload["wrapped"] else ("agent_created" if is_new else "agent_updated")

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
                telemetry_metrics.record_agent_lifecycle(
                    event=lifecycle_event,
                    agent_type=normalized.get("agent_type"),
                )
                return deepcopy(normalized)

        now = _utc_now()
        record = {
            **payload,
            "created_at": existing.get("created_at", now),
            "updated_at": now,
            "created_by": existing.get("created_by", changed_by),
            "updated_by": changed_by,
        }
        self._agents[payload["agent_id"]] = record
        telemetry_metrics.record_agent_lifecycle(
            event=lifecycle_event,
            agent_type=record.get("agent_type"),
        )
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
        if normalized_status not in _VALID_LINK_STATUS:
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
                telemetry_metrics.record_agent_lifecycle(
                    event="a2a_link_upserted",
                    agent_type=None,
                )
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
        telemetry_metrics.record_agent_lifecycle(
            event="a2a_link_upserted",
            agent_type=None,
        )
        return deepcopy(record)

    async def list_links(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source_agent_id: Optional[str] = None,
        target_agent_id: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List A2A links."""
        source = source_agent_id.strip() if source_agent_id else None
        target = target_agent_id.strip() if target_agent_id else None
        normalized_protocol = protocol.strip().upper() if protocol else None

        if self._audit_logger and self._audit_logger.connected:
            rows = await self._audit_logger.list_agent_links(
                limit=limit,
                offset=offset,
                source_agent_id=source,
                target_agent_id=target,
                protocol=normalized_protocol,
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
        if normalized_protocol:
            items = [item for item in items if item.get("protocol") == normalized_protocol]
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
        if source == target:
            raise ValueError("source_agent_id and target_agent_id must be different")

        source_agent = await self.get_agent(source)
        target_agent = await self.get_agent(target)
        if not source_agent:
            raise ValueError(f"Source agent '{source}' not found")
        if not target_agent:
            raise ValueError(f"Target agent '{target}' not found")
        if str(source_agent.get("status", "")).upper() != "ACTIVE":
            raise ValueError(f"Source agent '{source}' is not ACTIVE")
        if str(target_agent.get("status", "")).upper() != "ACTIVE":
            raise ValueError(f"Target agent '{target}' is not ACTIVE")

        if settings.agent_link_enforcement_enabled:
            link = await self._get_link(source, target, "A2A")
            if not link or str(link.get("status", "")).upper() != "ACTIVE":
                raise ValueError(
                    f"No active A2A link approved from '{source}' to '{target}'"
                )

        self._enforce_agent_constraints(source_agent, target_agent)

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
                telemetry_metrics.record_a2a_interaction(event="interaction_created")
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
        telemetry_metrics.record_a2a_interaction(event="interaction_created")
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
                telemetry_metrics.record_a2a_review(status=normalized_status)
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
        telemetry_metrics.record_a2a_review(status=normalized_status)
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
        agent_id: Optional[str] = None,
        source_agent_id: Optional[str] = None,
        target_agent_id: Optional[str] = None,
        review_status: Optional[str] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """List A2A interactions."""
        normalized_status = review_status.strip().upper() if review_status else None
        if normalized_status and normalized_status not in _VALID_INTERACTION_STATUS:
            raise ValueError(f"Invalid interaction status filter: {review_status}")

        any_agent = agent_id.strip() if agent_id else None
        source = source_agent_id.strip() if source_agent_id else None
        target = target_agent_id.strip() if target_agent_id else None

        if self._audit_logger and self._audit_logger.connected:
            rows = await self._audit_logger.list_agent_interactions(
                limit=limit,
                offset=offset,
                agent_id=any_agent,
                source_agent_id=source,
                target_agent_id=target,
                review_status=normalized_status,
                created_after=created_after,
                created_before=created_before,
                retention_days=int(settings.agent_interaction_retention_days),
            )
            items: List[Dict[str, Any]] = []
            for row in rows:
                normalized = self._normalize_interaction(row)
                self._interactions[normalized["interaction_id"]] = normalized
                items.append(deepcopy(normalized))
            return items

        items = list(self._interactions.values())
        retention_days = int(settings.agent_interaction_retention_days)
        if retention_days > 0:
            cutoff = _utc_now() - timedelta(days=retention_days)
            items = [
                item for item in items
                if self._normalize_datetime(item.get("created_at")) >= cutoff
            ]
        if any_agent:
            items = [
                item for item in items
                if item.get("source_agent_id") == any_agent or item.get("target_agent_id") == any_agent
            ]
        if source:
            items = [item for item in items if item.get("source_agent_id") == source]
        if target:
            items = [item for item in items if item.get("target_agent_id") == target]
        if normalized_status:
            items = [item for item in items if item.get("review_status") == normalized_status]
        if created_after:
            after = self._normalize_datetime(created_after)
            items = [
                item for item in items
                if self._normalize_datetime(item.get("created_at")) >= after
            ]
        if created_before:
            before = self._normalize_datetime(created_before)
            items = [
                item for item in items
                if self._normalize_datetime(item.get("created_at")) <= before
            ]
        return [deepcopy(item) for item in items[offset: offset + limit]]

    async def _get_link(
        self,
        source_agent_id: str,
        target_agent_id: str,
        protocol: str = "A2A",
    ) -> Optional[Dict[str, Any]]:
        """Get link by source/target/protocol from persistence/cache."""
        normalized_protocol = protocol.strip().upper() or "A2A"
        key = self._link_key(source_agent_id, target_agent_id, normalized_protocol)

        if self._audit_logger and self._audit_logger.connected:
            rows = await self._audit_logger.list_agent_links(
                limit=1,
                offset=0,
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                protocol=normalized_protocol,
            )
            if rows:
                normalized = self._normalize_link(rows[0])
                self._links[key] = normalized
                return deepcopy(normalized)

        item = self._links.get(key)
        return deepcopy(item) if item else None

    def _enforce_agent_constraints(
        self,
        source_agent: Dict[str, Any],
        target_agent: Dict[str, Any],
    ) -> None:
        """Apply policy-level source->target constraints from agent metadata."""
        source_meta = source_agent.get("metadata") or {}
        target_meta = target_agent.get("metadata") or {}

        source_type = str(source_agent.get("agent_type", "")).strip().lower()
        target_type = str(target_agent.get("agent_type", "")).strip().lower()
        source_role = str(source_meta.get("role", "")).strip().lower()
        target_role = str(target_meta.get("role", "")).strip().lower()

        allowed_target_types = self._metadata_string_set(
            source_meta,
            ("allowed_target_agent_types", "allowed_target_types"),
        )
        blocked_target_types = self._metadata_string_set(
            source_meta,
            ("blocked_target_agent_types", "blocked_target_types"),
        )
        if allowed_target_types and target_type not in allowed_target_types:
            raise ValueError(
                f"Interaction denied by source agent type policy: "
                f"'{source_type or 'unknown'}' cannot target '{target_type or 'unknown'}'"
            )
        if target_type and target_type in blocked_target_types:
            raise ValueError(
                f"Interaction denied by source blocked target type policy: '{target_type}'"
            )

        allowed_target_roles = self._metadata_string_set(
            source_meta,
            ("allowed_target_roles",),
        )
        blocked_target_roles = self._metadata_string_set(
            source_meta,
            ("blocked_target_roles",),
        )
        if allowed_target_roles and target_role and target_role not in allowed_target_roles:
            raise ValueError(
                f"Interaction denied by source role policy: "
                f"'{source_role or 'unknown'}' cannot target role '{target_role}'"
            )
        if target_role and target_role in blocked_target_roles:
            raise ValueError(
                f"Interaction denied by source blocked target role policy: '{target_role}'"
            )

        wrapped_only = bool(source_meta.get("allow_wrapped_targets_only", False))
        if wrapped_only and not bool(target_agent.get("wrapped", False)):
            raise ValueError("Interaction denied: source requires wrapped targets only")

    def _metadata_string_set(
        self,
        metadata: Dict[str, Any],
        keys: tuple[str, ...],
    ) -> set[str]:
        """Extract normalized string values from metadata keys."""
        values: set[str] = set()
        for key in keys:
            raw = metadata.get(key)
            if isinstance(raw, str):
                value = raw.strip().lower()
                if value:
                    values.add(value)
            elif isinstance(raw, list):
                for item in raw:
                    if isinstance(item, str):
                        value = item.strip().lower()
                        if value:
                            values.add(value)
        return values

    def _normalize_datetime(self, value: Any) -> datetime:
        """Normalize datetime-like values into timezone-aware UTC datetimes."""
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except Exception:
                pass
        return datetime.min.replace(tzinfo=timezone.utc)

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
