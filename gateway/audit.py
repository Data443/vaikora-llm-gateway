"""
Data443 LLM Gateway - PostgreSQL Audit Logging

Immutable audit log for all gateway decisions.
Every ALLOW/BLOCK/CONSTRAIN decision is logged with full context.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
import json

import asyncpg
from loguru import logger

from config.settings import settings


class Decision(str, Enum):
    """Gateway decision types."""
    ALLOW = "ALLOW"
    ALLOW_LOG = "ALLOW_LOG"
    CONSTRAIN = "CONSTRAIN"
    BLOCK = "BLOCK"
    ERROR = "ERROR"


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
        """Log a gateway decision to the audit log."""
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
        """Query the audit log."""
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


# Global audit logger instance
audit_logger = AuditLogger()
