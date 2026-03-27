"""Lightweight SQL migration runner for PostgreSQL."""

from __future__ import annotations

from pathlib import Path
from typing import List

import asyncpg
from loguru import logger


MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def _list_migration_files() -> List[Path]:
    if not MIGRATIONS_DIR.exists():
        return []
    return sorted(
        path for path in MIGRATIONS_DIR.iterdir()
        if path.is_file() and path.suffix.lower() == ".sql"
    )


async def apply_migrations(pool: asyncpg.Pool) -> None:
    """Apply unapplied SQL migrations in filename order."""
    migration_files = _list_migration_files()
    if not migration_files:
        logger.info("No SQL migrations found at {}", MIGRATIONS_DIR)
        return

    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id BIGSERIAL PRIMARY KEY,
                filename TEXT NOT NULL UNIQUE,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """
        )

        for migration in migration_files:
            already_applied = await conn.fetchval(
                "SELECT 1 FROM schema_migrations WHERE filename = $1",
                migration.name,
            )
            if already_applied:
                continue

            sql = migration.read_text(encoding="utf-8")
            logger.info("Applying migration {}", migration.name)
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations(filename) VALUES($1)",
                    migration.name,
                )

    logger.info("Migrations complete ({} file(s) discovered)", len(migration_files))
