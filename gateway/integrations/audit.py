"""
Data443 LLM Gateway - PostgreSQL Audit Logging

Immutable audit log for all gateway decisions.
Every ALLOW/BLOCK/CONSTRAIN decision is logged with full context.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
import json

import asyncpg
from loguru import logger

from gateway.core.config import settings
from gateway.core.types import Decision


_REDACTED_VALUE = "***REDACTED***"
_SENSITIVE_EXACT_KEYS = {"password", "secret", "token", "api_key", "apikey", "authorization"}
_SENSITIVE_KEY_FRAGMENTS = ("password", "secret", "token", "api_key", "apikey")
_MESSAGE_CONTENT_KEYS = {"content", "prompt", "input", "system"}


class AuditLogger:
    """Immutable audit logger for PostgreSQL."""

    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self.connected = False

    async def connect(self) -> None:
        """Connect to PostgreSQL."""
        try:
            self.pool = await asyncpg.create_pool(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password if settings.postgres_password else None,
                min_size=5,
                max_size=20,
            )
            self.connected = True
            logger.info("Connected to PostgreSQL (audit log)")

            # Create table if not exists
            await self._create_table()
        except Exception as e:
            logger.warning(f"Failed to connect to PostgreSQL: {e}")
            self.connected = False

    async def disconnect(self) -> None:
        """Disconnect from PostgreSQL."""
        if self.pool:
            await self.pool.close()
            self.connected = False
            logger.info("Disconnected from PostgreSQL")

    async def _create_table(self) -> None:
        """Create audit log table if not exists."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    decision VARCHAR(20) NOT NULL,
                    ip_address INET,
                    url TEXT,
                    risk_score INTEGER,
                    ip_risk_score INTEGER,
                    url_category INTEGER,
                    user_agent TEXT,
                    request_id TEXT,
                    request_method TEXT,
                    request_path TEXT,
                    request_body JSONB,
                    response_status INTEGER,
                    response_time_ms INTEGER,
                    reason TEXT,
                    cyren_ref_id TEXT,
                    CONSTRAINT valid_decision CHECK (decision IN ('ALLOW', 'ALLOW_LOG', 'CONSTRAIN', 'BLOCK', 'ERROR'))
                );

                CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_log_decision ON audit_log(decision);
                CREATE INDEX IF NOT EXISTS idx_audit_log_ip_address ON audit_log(ip_address);
                CREATE INDEX IF NOT EXISTS idx_audit_log_url ON audit_log USING HASH(url);

                CREATE TABLE IF NOT EXISTS policy_versions (
                    id BIGSERIAL PRIMARY KEY,
                    policy_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    config JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_by TEXT,
                    change_note TEXT,
                    UNIQUE(policy_name, version)
                );

                CREATE INDEX IF NOT EXISTS idx_policy_versions_name_version
                    ON policy_versions(policy_name, version DESC);

                CREATE TABLE IF NOT EXISTS entitlement_versions (
                    id BIGSERIAL PRIMARY KEY,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    version INTEGER NOT NULL,
                    entitlements JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_by TEXT,
                    change_note TEXT,
                    UNIQUE(tenant_id, version)
                );

                CREATE INDEX IF NOT EXISTS idx_entitlement_versions_tenant_version
                    ON entitlement_versions(tenant_id, version DESC);

                CREATE TABLE IF NOT EXISTS llm_gateway_events (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    request_id TEXT NOT NULL,
                    decision VARCHAR(20) NOT NULL,
                    risk_score INTEGER,
                    ip_address INET,
                    url TEXT,
                    model TEXT,
                    org_id TEXT,
                    user_id TEXT,
                    response_status INTEGER,
                    response_time_ms INTEGER,
                    reason TEXT,
                    attributes JSONB NOT NULL DEFAULT '{}'::jsonb
                );

                CREATE INDEX IF NOT EXISTS idx_gateway_events_timestamp
                    ON llm_gateway_events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_gateway_events_request_id
                    ON llm_gateway_events(request_id);
                CREATE INDEX IF NOT EXISTS idx_gateway_events_decision
                    ON llm_gateway_events(decision);

                CREATE TABLE IF NOT EXISTS interaction_reviews (
                    id BIGSERIAL PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    review_status VARCHAR(20) NOT NULL,
                    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    reviewed_by TEXT,
                    reason TEXT,
                    source_event_id BIGINT,
                    source_decision VARCHAR(20),
                    source_risk_score INTEGER,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    CONSTRAINT valid_review_status CHECK (review_status IN ('APPROVED', 'BLOCKED'))
                );

                CREATE INDEX IF NOT EXISTS idx_interaction_reviews_reviewed_at
                    ON interaction_reviews(reviewed_at DESC);

                CREATE TABLE IF NOT EXISTS managed_agents (
                    id BIGSERIAL PRIMARY KEY,
                    agent_id TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
                    wrapped BOOLEAN NOT NULL DEFAULT FALSE,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_by TEXT,
                    updated_by TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_managed_agents_status
                    ON managed_agents(status);

                CREATE TABLE IF NOT EXISTS agent_links (
                    id BIGSERIAL PRIMARY KEY,
                    source_agent_id TEXT NOT NULL,
                    target_agent_id TEXT NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'A2A',
                    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_by TEXT,
                    updated_by TEXT,
                    UNIQUE(source_agent_id, target_agent_id, protocol)
                );

                CREATE INDEX IF NOT EXISTS idx_agent_links_source
                    ON agent_links(source_agent_id);
                CREATE INDEX IF NOT EXISTS idx_agent_links_target
                    ON agent_links(target_agent_id);

                CREATE TABLE IF NOT EXISTS agent_interactions (
                    id BIGSERIAL PRIMARY KEY,
                    interaction_id TEXT NOT NULL UNIQUE,
                    source_agent_id TEXT NOT NULL,
                    target_agent_id TEXT NOT NULL,
                    review_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    decision_reason TEXT,
                    reviewed_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT valid_agent_interaction_review_status
                        CHECK (review_status IN ('PENDING', 'APPROVED', 'BLOCKED'))
                );

                CREATE INDEX IF NOT EXISTS idx_agent_interactions_source
                    ON agent_interactions(source_agent_id);
                CREATE INDEX IF NOT EXISTS idx_agent_interactions_target
                    ON agent_interactions(target_agent_id);
                CREATE INDEX IF NOT EXISTS idx_agent_interactions_status
                    ON agent_interactions(review_status);
            """)
            logger.info("Audit log table verified")

    async def log_decision(
        self,
        decision: Decision,
        ip_address: Optional[str] = None,
        url: Optional[str] = None,
        risk_score: Optional[int] = None,
        ip_risk_score: Optional[int] = None,
        url_category: Optional[int] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        request_body: Optional[dict] = None,
        response_status: Optional[int] = None,
        response_time_ms: Optional[int] = None,
        reason: Optional[str] = None,
        cyren_ref_id: Optional[str] = None,
    ) -> None:
        """Log a gateway decision to audit log."""
        if not self.connected:
            logger.warning("Audit log not connected, skipping")
            return

        try:
            async with self.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO audit_log (
                        decision, ip_address, url, risk_score, ip_risk_score, url_category,
                        user_agent, request_id, request_method, request_path, request_body,
                        response_status, response_time_ms, reason, cyren_ref_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                """,
                    decision.value,
                    ip_address,
                    url,
                    risk_score,
                    ip_risk_score,
                    url_category,
                    user_agent,
                    request_id,
                    request_method,
                    request_path,
                    self._encode_json_field(request_body),
                    response_status,
                    response_time_ms,
                    reason,
                    cyren_ref_id,
                )
                logger.debug(f"Audit log: {decision.value} for {ip_address} / {url}")
        except Exception as e:
            logger.error(f"Failed to log audit entry: {e}")

    async def query_audit_log(
        self,
        limit: int = 100,
        offset: int = 0,
        decision: Optional[Decision] = None,
        ip_address: Optional[str] = None,
    ) -> list[dict]:
        """Query audit log."""
        if not self.connected:
            return []

        try:
            async with self.pool.acquire() as conn:
                query = "SELECT * FROM audit_log WHERE 1=1"
                params = []
                param_idx = 1

                if decision:
                    query += f" AND decision = ${param_idx}"
                    params.append(decision.value)
                    param_idx += 1

                if ip_address:
                    query += f" AND ip_address = ${param_idx}"
                    params.append(ip_address)
                    param_idx += 1

                retention_days = int(settings.audit_retention_days)
                if retention_days > 0:
                    query += f" AND timestamp >= NOW() - (${param_idx} * INTERVAL '1 day')"
                    params.append(retention_days)
                    param_idx += 1

                query += f" ORDER BY timestamp DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)
                normalized: list[dict] = []
                for row in rows:
                    item = dict(row)
                    item["request_body"] = self._sanitize_payload(
                        self._decode_json_field(item.get("request_body")),
                    )
                    normalized.append(item)
                return normalized
        except Exception as e:
            logger.error(f"Failed to query audit log: {e}")
            return []

    async def insert_policy_version(
        self,
        policy_name: str,
        config: Dict[str, Any],
        created_by: str = "system",
        change_note: Optional[str] = None,
    ) -> int:
        """Insert a policy version and return the new version number."""
        if not self.connected:
            raise RuntimeError("Audit logger is not connected")

        async with self.pool.acquire() as conn:
            next_version = await conn.fetchval(
                """
                SELECT COALESCE(MAX(version), 0) + 1
                FROM policy_versions
                WHERE policy_name = $1
                """,
                policy_name,
            )
            await conn.execute(
                """
                INSERT INTO policy_versions (
                    policy_name, version, config, created_by, change_note
                ) VALUES ($1, $2, $3::jsonb, $4, $5)
                """,
                policy_name,
                next_version,
                json.dumps(config),
                created_by,
                change_note,
            )
            return int(next_version)

    async def get_latest_policy(self, policy_name: str) -> Optional[Dict[str, Any]]:
        """Get the latest policy version record for a policy name."""
        if not self.connected:
            return None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT policy_name, version, config, created_at, created_by, change_note
                FROM policy_versions
                WHERE policy_name = $1
                ORDER BY version DESC
                LIMIT 1
                """,
                policy_name,
            )
            return dict(row) if row else None

    async def get_latest_policies(self) -> List[Dict[str, Any]]:
        """Get latest versions for all policies."""
        if not self.connected:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT ON (policy_name)
                    policy_name, version, config, created_at, created_by, change_note
                FROM policy_versions
                ORDER BY policy_name, version DESC
                """
            )
            return [dict(row) for row in rows]

    async def list_policy_versions(self, policy_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """List policy version history for a policy name."""
        if not self.connected:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT policy_name, version, config, created_at, created_by, change_note
                FROM policy_versions
                WHERE policy_name = $1
                ORDER BY version DESC
                LIMIT $2
                """,
                policy_name,
                limit,
            )
            return [dict(row) for row in rows]

    async def get_policy_version(self, policy_name: str, version: int) -> Optional[Dict[str, Any]]:
        """Get a specific policy version."""
        if not self.connected:
            return None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT policy_name, version, config, created_at, created_by, change_note
                FROM policy_versions
                WHERE policy_name = $1 AND version = $2
                LIMIT 1
                """,
                policy_name,
                version,
            )
            return dict(row) if row else None

    async def insert_entitlement_version(
        self,
        entitlements: Dict[str, Any],
        tenant_id: str = "default",
        created_by: str = "system",
        change_note: Optional[str] = None,
    ) -> int:
        """Insert an entitlement version and return new version."""
        if not self.connected:
            raise RuntimeError("Audit logger is not connected")

        async with self.pool.acquire() as conn:
            next_version = await conn.fetchval(
                """
                SELECT COALESCE(MAX(version), 0) + 1
                FROM entitlement_versions
                WHERE tenant_id = $1
                """,
                tenant_id,
            )
            await conn.execute(
                """
                INSERT INTO entitlement_versions (
                    tenant_id, version, entitlements, created_by, change_note
                ) VALUES ($1, $2, $3::jsonb, $4, $5)
                """,
                tenant_id,
                next_version,
                json.dumps(entitlements),
                created_by,
                change_note,
            )
            return int(next_version)

    async def get_latest_entitlements(self, tenant_id: str = "default") -> Optional[Dict[str, Any]]:
        """Get latest entitlement set for tenant."""
        if not self.connected:
            return None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT tenant_id, version, entitlements, created_at, created_by, change_note
                FROM entitlement_versions
                WHERE tenant_id = $1
                ORDER BY version DESC
                LIMIT 1
                """,
                tenant_id,
            )
            return dict(row) if row else None

    async def log_gateway_event(
        self,
        request_id: str,
        decision: str,
        risk_score: Optional[int] = None,
        ip_address: Optional[str] = None,
        url: Optional[str] = None,
        model: Optional[str] = None,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        response_status: Optional[int] = None,
        response_time_ms: Optional[int] = None,
        reason: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write a structured gateway event for analytics and data lake export."""
        if not self.connected:
            logger.warning("Gateway event store not connected, skipping")
            return
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO llm_gateway_events (
                        request_id, decision, risk_score, ip_address, url, model, org_id, user_id,
                        response_status, response_time_ms, reason, attributes
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8,
                        $9, $10, $11, $12::jsonb
                    )
                    """,
                    request_id,
                    decision,
                    risk_score,
                    ip_address,
                    url,
                    model,
                    org_id,
                    user_id,
                    response_status,
                    response_time_ms,
                    reason,
                    self._encode_json_field(attributes or {}),
                )
        except Exception as exc:
            logger.error(f"Failed to write gateway event: {exc}")

    async def query_gateway_events(
        self,
        limit: int = 100,
        offset: int = 0,
        decision: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query structured gateway events."""
        if not self.connected:
            return []
        try:
            async with self.pool.acquire() as conn:
                query = "SELECT * FROM llm_gateway_events WHERE 1=1"
                params: List[Any] = []
                param_idx = 1

                if decision:
                    query += f" AND decision = ${param_idx}"
                    params.append(decision)
                    param_idx += 1

                if request_id:
                    query += f" AND request_id = ${param_idx}"
                    params.append(request_id)
                    param_idx += 1

                retention_days = int(settings.audit_retention_days)
                if retention_days > 0:
                    query += f" AND timestamp >= NOW() - (${param_idx} * INTERVAL '1 day')"
                    params.append(retention_days)
                    param_idx += 1

                query += f" ORDER BY timestamp DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)
                normalized: List[Dict[str, Any]] = []
                for row in rows:
                    item = dict(row)
                    item["attributes"] = self._sanitize_payload(
                        self._decode_json_field(item.get("attributes")),
                    )
                    normalized.append(item)
                return normalized
        except Exception as exc:
            logger.error(f"Failed to query gateway events: {exc}")
            return []

    async def get_latest_gateway_event_by_request_id(
        self,
        request_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get the most recent gateway event row for a request id."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT *
                    FROM llm_gateway_events
                    WHERE request_id = $1
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    request_id,
                )
                if not row:
                    return None
                item = dict(row)
                item["attributes"] = self._sanitize_payload(
                    self._decode_json_field(item.get("attributes")),
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to fetch gateway event by request_id={request_id}: {exc}")
            return None

    async def upsert_interaction_review(
        self,
        request_id: str,
        review_status: str,
        reviewed_by: str = "admin",
        reason: Optional[str] = None,
        source_event_id: Optional[int] = None,
        source_decision: Optional[str] = None,
        source_risk_score: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create or update interaction review status for a request id."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO interaction_reviews (
                        request_id, review_status, reviewed_by, reason,
                        source_event_id, source_decision, source_risk_score, metadata
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8::jsonb
                    )
                    ON CONFLICT (request_id)
                    DO UPDATE SET
                        review_status = EXCLUDED.review_status,
                        reviewed_at = NOW(),
                        reviewed_by = EXCLUDED.reviewed_by,
                        reason = EXCLUDED.reason,
                        source_event_id = EXCLUDED.source_event_id,
                        source_decision = EXCLUDED.source_decision,
                        source_risk_score = EXCLUDED.source_risk_score,
                        metadata = EXCLUDED.metadata
                    RETURNING
                        request_id, review_status, reviewed_at, reviewed_by, reason,
                        source_event_id, source_decision, source_risk_score, metadata
                    """,
                    request_id,
                    review_status,
                    reviewed_by,
                    reason,
                    source_event_id,
                    source_decision,
                    source_risk_score,
                    self._encode_json_field(metadata or {}),
                )
                if not row:
                    return None
                item = dict(row)
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to upsert interaction review for request_id={request_id}: {exc}")
            return None

    async def get_interaction_review(
        self,
        request_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch interaction review status by request id."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        request_id, review_status, reviewed_at, reviewed_by, reason,
                        source_event_id, source_decision, source_risk_score, metadata
                    FROM interaction_reviews
                    WHERE request_id = $1
                    LIMIT 1
                    """,
                    request_id,
                )
                if not row:
                    return None
                item = dict(row)
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to fetch interaction review for request_id={request_id}: {exc}")
            return None

    async def upsert_managed_agent(
        self,
        *,
        agent_id: str,
        display_name: str,
        agent_type: str,
        status: str,
        wrapped: bool,
        metadata: Optional[Dict[str, Any]] = None,
        changed_by: str = "admin",
    ) -> Optional[Dict[str, Any]]:
        """Create or update a managed agent definition."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO managed_agents (
                        agent_id, display_name, agent_type, status, wrapped, metadata, created_by, updated_by
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6::jsonb, $7, $7
                    )
                    ON CONFLICT (agent_id)
                    DO UPDATE SET
                        display_name = EXCLUDED.display_name,
                        agent_type = EXCLUDED.agent_type,
                        status = EXCLUDED.status,
                        wrapped = EXCLUDED.wrapped,
                        metadata = EXCLUDED.metadata,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = NOW()
                    RETURNING
                        agent_id, display_name, agent_type, status, wrapped, metadata,
                        created_at, updated_at, created_by, updated_by
                    """,
                    agent_id,
                    display_name,
                    agent_type,
                    status,
                    wrapped,
                    self._encode_json_field(metadata or {}),
                    changed_by,
                )
                if not row:
                    return None
                item = dict(row)
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to upsert managed agent '{agent_id}': {exc}")
            return None

    async def get_managed_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Fetch managed agent by agent id."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        agent_id, display_name, agent_type, status, wrapped, metadata,
                        created_at, updated_at, created_by, updated_by
                    FROM managed_agents
                    WHERE agent_id = $1
                    LIMIT 1
                    """,
                    agent_id,
                )
                if not row:
                    return None
                item = dict(row)
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to fetch managed agent '{agent_id}': {exc}")
            return None

    async def list_managed_agents(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List managed agents."""
        if not self.connected:
            return []
        try:
            async with self.pool.acquire() as conn:
                query = """
                    SELECT
                        agent_id, display_name, agent_type, status, wrapped, metadata,
                        created_at, updated_at, created_by, updated_by
                    FROM managed_agents
                    WHERE 1=1
                """
                params: List[Any] = []
                idx = 1
                if status:
                    query += f" AND status = ${idx}"
                    params.append(status)
                    idx += 1

                query += f" ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx + 1}"
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)
                output: List[Dict[str, Any]] = []
                for row in rows:
                    item = dict(row)
                    item["metadata"] = self._sanitize_payload(
                        self._decode_json_field(item.get("metadata")) or {},
                    )
                    output.append(item)
                return output
        except Exception as exc:
            logger.error(f"Failed to list managed agents: {exc}")
            return []

    async def upsert_agent_link(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        protocol: str = "A2A",
        status: str = "ACTIVE",
        metadata: Optional[Dict[str, Any]] = None,
        changed_by: str = "admin",
    ) -> Optional[Dict[str, Any]]:
        """Create or update an A2A link between two agents."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO agent_links (
                        source_agent_id, target_agent_id, protocol, status, metadata, created_by, updated_by
                    ) VALUES (
                        $1, $2, $3, $4, $5::jsonb, $6, $6
                    )
                    ON CONFLICT (source_agent_id, target_agent_id, protocol)
                    DO UPDATE SET
                        status = EXCLUDED.status,
                        metadata = EXCLUDED.metadata,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = NOW()
                    RETURNING
                        source_agent_id, target_agent_id, protocol, status, metadata,
                        created_at, updated_at, created_by, updated_by
                    """,
                    source_agent_id,
                    target_agent_id,
                    protocol,
                    status,
                    self._encode_json_field(metadata or {}),
                    changed_by,
                )
                if not row:
                    return None
                item = dict(row)
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(
                f"Failed to upsert agent link {source_agent_id}->{target_agent_id} ({protocol}): {exc}"
            )
            return None

    async def list_agent_links(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source_agent_id: Optional[str] = None,
        target_agent_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List A2A links."""
        if not self.connected:
            return []
        try:
            async with self.pool.acquire() as conn:
                query = """
                    SELECT
                        source_agent_id, target_agent_id, protocol, status, metadata,
                        created_at, updated_at, created_by, updated_by
                    FROM agent_links
                    WHERE 1=1
                """
                params: List[Any] = []
                idx = 1

                if source_agent_id:
                    query += f" AND source_agent_id = ${idx}"
                    params.append(source_agent_id)
                    idx += 1

                if target_agent_id:
                    query += f" AND target_agent_id = ${idx}"
                    params.append(target_agent_id)
                    idx += 1

                query += f" ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx + 1}"
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)
                output: List[Dict[str, Any]] = []
                for row in rows:
                    item = dict(row)
                    item["metadata"] = self._sanitize_payload(
                        self._decode_json_field(item.get("metadata")) or {},
                    )
                    output.append(item)
                return output
        except Exception as exc:
            logger.error(f"Failed to list agent links: {exc}")
            return []

    async def create_agent_interaction(
        self,
        *,
        interaction_id: str,
        source_agent_id: str,
        target_agent_id: str,
        review_status: str = "PENDING",
        payload: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        decision_reason: Optional[str] = None,
        reviewed_by: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a new agent interaction review record."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO agent_interactions (
                        interaction_id, source_agent_id, target_agent_id, review_status,
                        payload, metadata, decision_reason, reviewed_by
                    ) VALUES (
                        $1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8
                    )
                    RETURNING
                        interaction_id, source_agent_id, target_agent_id, review_status,
                        payload, metadata, decision_reason, reviewed_by, created_at, updated_at
                    """,
                    interaction_id,
                    source_agent_id,
                    target_agent_id,
                    review_status,
                    self._encode_json_field(payload or {}),
                    self._encode_json_field(metadata or {}),
                    decision_reason,
                    reviewed_by,
                )
                if not row:
                    return None
                item = dict(row)
                item["payload"] = self._sanitize_payload(
                    self._decode_json_field(item.get("payload")) or {},
                )
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to create agent interaction '{interaction_id}': {exc}")
            return None

    async def update_agent_interaction_review(
        self,
        *,
        interaction_id: str,
        review_status: str,
        decision_reason: Optional[str] = None,
        reviewed_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update review state for an existing agent interaction."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    UPDATE agent_interactions
                    SET
                        review_status = $2,
                        decision_reason = $3,
                        reviewed_by = $4,
                        metadata = COALESCE(metadata, '{}'::jsonb) || $5::jsonb,
                        updated_at = NOW()
                    WHERE interaction_id = $1
                    RETURNING
                        interaction_id, source_agent_id, target_agent_id, review_status,
                        payload, metadata, decision_reason, reviewed_by, created_at, updated_at
                    """,
                    interaction_id,
                    review_status,
                    decision_reason,
                    reviewed_by,
                    self._encode_json_field(metadata or {}),
                )
                if not row:
                    return None
                item = dict(row)
                item["payload"] = self._sanitize_payload(
                    self._decode_json_field(item.get("payload")) or {},
                )
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to update agent interaction '{interaction_id}': {exc}")
            return None

    async def get_agent_interaction(self, interaction_id: str) -> Optional[Dict[str, Any]]:
        """Get an agent interaction by id."""
        if not self.connected:
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        interaction_id, source_agent_id, target_agent_id, review_status,
                        payload, metadata, decision_reason, reviewed_by, created_at, updated_at
                    FROM agent_interactions
                    WHERE interaction_id = $1
                    LIMIT 1
                    """,
                    interaction_id,
                )
                if not row:
                    return None
                item = dict(row)
                item["payload"] = self._sanitize_payload(
                    self._decode_json_field(item.get("payload")) or {},
                )
                item["metadata"] = self._sanitize_payload(
                    self._decode_json_field(item.get("metadata")) or {},
                )
                return item
        except Exception as exc:
            logger.error(f"Failed to fetch agent interaction '{interaction_id}': {exc}")
            return None

    async def list_agent_interactions(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source_agent_id: Optional[str] = None,
        target_agent_id: Optional[str] = None,
        review_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List agent interactions."""
        if not self.connected:
            return []
        try:
            async with self.pool.acquire() as conn:
                query = """
                    SELECT
                        interaction_id, source_agent_id, target_agent_id, review_status,
                        payload, metadata, decision_reason, reviewed_by, created_at, updated_at
                    FROM agent_interactions
                    WHERE 1=1
                """
                params: List[Any] = []
                idx = 1

                if source_agent_id:
                    query += f" AND source_agent_id = ${idx}"
                    params.append(source_agent_id)
                    idx += 1

                if target_agent_id:
                    query += f" AND target_agent_id = ${idx}"
                    params.append(target_agent_id)
                    idx += 1

                if review_status:
                    query += f" AND review_status = ${idx}"
                    params.append(review_status)
                    idx += 1

                query += f" ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx + 1}"
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)
                output: List[Dict[str, Any]] = []
                for row in rows:
                    item = dict(row)
                    item["payload"] = self._sanitize_payload(
                        self._decode_json_field(item.get("payload")) or {},
                    )
                    item["metadata"] = self._sanitize_payload(
                        self._decode_json_field(item.get("metadata")) or {},
                    )
                    output.append(item)
                return output
        except Exception as exc:
            logger.error(f"Failed to list agent interactions: {exc}")
            return []

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if key should be redacted in returned audit payloads."""
        normalized = key.strip().lower()
        if normalized in _SENSITIVE_EXACT_KEYS:
            return True
        for fragment in _SENSITIVE_KEY_FRAGMENTS:
            if fragment in normalized:
                return True
        return False

    def _sanitize_payload(self, value: Any, parent_key: str = "") -> Any:
        """Apply optional masking/redaction to returned audit/event payloads."""
        if value is None:
            return None

        if isinstance(value, dict):
            output: Dict[str, Any] = {}
            for key, item in value.items():
                normalized = str(key).strip().lower()
                if settings.audit_mask_sensitive_fields and self._is_sensitive_key(normalized):
                    output[key] = _REDACTED_VALUE if item not in (None, "") else ""
                    continue

                if (
                    settings.audit_redact_message_content
                    and normalized in _MESSAGE_CONTENT_KEYS
                    and isinstance(item, str)
                ):
                    output[key] = "[REDACTED]"
                    continue

                output[key] = self._sanitize_payload(item, normalized)
            return output

        if isinstance(value, list):
            return [self._sanitize_payload(item, parent_key) for item in value]

        if isinstance(value, str):
            max_len = int(settings.audit_max_string_length)
            if max_len > 0 and len(value) > max_len:
                return value[:max_len] + "...<truncated>"
            return value

        return value

    def _decode_json_field(self, value: Any) -> Any:
        """Decode JSON-like string fields for backward-compatible reads."""
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if (raw.startswith("{") and raw.endswith("}")) or (
                raw.startswith("[") and raw.endswith("]")
            ):
                try:
                    return json.loads(raw)
                except Exception:
                    return value
        return value

    def _encode_json_field(self, value: Any) -> Optional[str]:
        """Encode dict/list payloads for asyncpg JSON/JSONB parameters."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=True)
        except Exception:
            return json.dumps(str(value), ensure_ascii=True)


# Global audit logger instance
audit_logger = AuditLogger()

