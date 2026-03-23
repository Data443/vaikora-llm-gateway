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
                    json.dumps(request_body) if request_body else None,
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

                query += f" ORDER BY timestamp DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
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
                    json.dumps(attributes or {}),
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

                query += f" ORDER BY timestamp DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
                params.extend([limit, offset])

                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
        except Exception as exc:
            logger.error(f"Failed to query gateway events: {exc}")
            return []


# Global audit logger instance
audit_logger = AuditLogger()

