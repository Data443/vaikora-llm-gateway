"""
Persistent policy and entitlement store.

Provides:
- Runtime in-memory policy cache for fast synchronous reads
- Versioned persistence in PostgreSQL when available
- Rollback support via policy versions
"""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any, Dict, List, Optional

from loguru import logger

from gateway.integrations.audit import AuditLogger


DEFAULT_POLICIES: Dict[str, Dict[str, Any]] = {
    "pii_detection": {
        "enabled": True,
        "action_on_detect": "BLOCK",
        "severity_threshold": "LOW",
    },
    "jailbreak_detection": {
        "enabled": True,
        "action_on_detect": "BLOCK",
        "max_attempts": 3,
    },
    "injection_detection": {
        "enabled": True,
        "action_on_detect": "BLOCK",
    },
    "semantic_detection": {
        "enabled": True,
        "action_on_detect": "BLOCK",
        "severity_threshold": "HIGH",
    },
    "domain_risk_scoring": {
        "enabled": True,
        "action_on_detect": "BLOCK",
        "severity_threshold": "MEDIUM",
    },
    "email_classification": {
        "enabled": True,
        "action_on_detect": "BLOCK",
        "severity_threshold": "MEDIUM",
    },
    "jwt_auth": {
        "enabled": False,
    },
}

DEFAULT_ENTITLEMENTS: Dict[str, Any] = {
    "modules": {
        "pii_detection": True,
        "jailbreak_detection": True,
        "injection_detection": True,
        "semantic_detection": True,
        "domain_risk_scoring": True,
        "email_classification": True,
    },
    "providers": {
        "openai": True,
        "anthropic": False,
        "gemini": False,
        "openrouter": False,
    },
    "limits": {
        "max_input_chars": 32000,
        "max_output_tokens": 4096,
    },
}


def _deep_merge(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge dictionary values."""
    merged = deepcopy(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class PolicyStore:
    """Policy cache + persistence manager."""

    def __init__(self) -> None:
        self._policies: Dict[str, Dict[str, Any]] = deepcopy(DEFAULT_POLICIES)
        self._entitlements: Dict[str, Any] = deepcopy(DEFAULT_ENTITLEMENTS)
        self._audit_logger: Optional[AuditLogger] = None
        self._initialized = False
        self._fallback_versions: Dict[str, int] = {name: 1 for name in DEFAULT_POLICIES}
        self._fallback_entitlement_version = 1

    async def initialize(self, audit_logger: AuditLogger) -> None:
        """Initialize cache from persistent storage and seed defaults if needed."""
        self._audit_logger = audit_logger

        if not audit_logger.connected:
            logger.warning("Policy store running without PostgreSQL persistence")
            self._initialized = True
            return

        await self._seed_defaults_if_missing()
        await self._load_from_db()
        self._initialized = True
        logger.info("Policy store initialized")

    async def _seed_defaults_if_missing(self) -> None:
        """Seed default policy/entitlement versions when DB is empty."""
        if not self._audit_logger or not self._audit_logger.connected:
            return

        for policy_name, config in DEFAULT_POLICIES.items():
            existing = await self._audit_logger.get_latest_policy(policy_name)
            if existing is None:
                await self._audit_logger.insert_policy_version(
                    policy_name=policy_name,
                    config=config,
                    created_by="system",
                    change_note="initial seed",
                )

        existing_entitlements = await self._audit_logger.get_latest_entitlements()
        if existing_entitlements is None:
            await self._audit_logger.insert_entitlement_version(
                entitlements=DEFAULT_ENTITLEMENTS,
                created_by="system",
                change_note="initial seed",
            )

    async def _load_from_db(self) -> None:
        """Load latest policy and entitlement records into runtime cache."""
        if not self._audit_logger or not self._audit_logger.connected:
            return

        latest_policies = await self._audit_logger.get_latest_policies()
        if latest_policies:
            loaded = {}
            for row in latest_policies:
                loaded[row["policy_name"]] = self._json_to_dict(row["config"])
            self._policies = loaded

        latest_entitlements = await self._audit_logger.get_latest_entitlements()
        if latest_entitlements and latest_entitlements.get("entitlements"):
            self._entitlements = self._json_to_dict(latest_entitlements["entitlements"])

    def get_policy(self, name: str) -> Dict[str, Any]:
        """Get policy config copy by name."""
        return deepcopy(self._policies.get(name, {}))

    async def get_policy_with_version(self, name: str) -> tuple[Dict[str, Any], Optional[int]]:
        """Get current policy config and latest version number."""
        policy = self.get_policy(name)
        version = await self.get_policy_version(name)
        return policy, version

    async def get_policy_version(self, name: str) -> Optional[int]:
        """Get latest policy version for a policy name."""
        if self._audit_logger and self._audit_logger.connected:
            latest = await self._audit_logger.get_latest_policy(name)
            if latest and latest.get("version") is not None:
                return int(latest["version"])
            return None
        if name in self._policies:
            return int(self._fallback_versions.get(name, 1))
        return None

    def list_policies(self) -> List[Dict[str, Any]]:
        """List all policies from runtime cache."""
        return [
            {
                "name": name,
                "enabled": bool(policy.get("enabled", False)),
                "config": deepcopy(policy),
            }
            for name, policy in self._policies.items()
        ]

    async def update_policy(
        self,
        name: str,
        updates: Dict[str, Any],
        changed_by: str = "admin",
        change_note: str = "policy update",
    ) -> tuple[Dict[str, Any], int]:
        """Update policy and create a new version entry."""
        current = self._policies.get(name, {})
        merged = _deep_merge(current, updates)

        # Normalize common enum-like fields
        if "action_on_detect" in merged and isinstance(merged["action_on_detect"], str):
            merged["action_on_detect"] = merged["action_on_detect"].upper()
        if "severity_threshold" in merged and isinstance(merged["severity_threshold"], str):
            merged["severity_threshold"] = merged["severity_threshold"].upper()

        version = await self._persist_policy_version(name, merged, changed_by, change_note)
        self._policies[name] = merged
        return deepcopy(merged), version

    async def list_policy_versions(self, name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get policy version history."""
        if self._audit_logger and self._audit_logger.connected:
            rows = await self._audit_logger.list_policy_versions(name, limit)
            versions: List[Dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["config"] = self._json_to_dict(item.get("config", {}))
                versions.append(item)
            return versions

        # Fallback mode only has current state
        if name in self._policies:
            return [{
                "policy_name": name,
                "version": self._fallback_versions.get(name, 1),
                "config": deepcopy(self._policies[name]),
                "created_by": "fallback",
                "change_note": "runtime fallback",
            }]
        return []

    async def rollback_policy(
        self,
        name: str,
        target_version: int,
        changed_by: str = "admin",
    ) -> tuple[Dict[str, Any], int]:
        """Rollback policy to a specific version by creating a new version."""
        if self._audit_logger and self._audit_logger.connected:
            record = await self._audit_logger.get_policy_version(name, target_version)
            if not record:
                raise ValueError(f"Policy version not found: {name}@{target_version}")
            config = self._json_to_dict(record["config"])
            version = await self._persist_policy_version(
                name=name,
                config=config,
                changed_by=changed_by,
                change_note=f"rollback to version {target_version}",
            )
            self._policies[name] = config
            return deepcopy(config), version

        # Fallback mode does not keep historical versions
        if name not in self._policies:
            raise ValueError(f"Policy not found: {name}")
        version = self._fallback_versions.get(name, 1)
        return deepcopy(self._policies[name]), version

    async def delete_policy(self, name: str, changed_by: str = "admin") -> Dict[str, Any]:
        """
        Soft-delete a policy by disabling it and marking deleted.

        Soft-delete keeps audit/version history and avoids hard state loss.
        """
        if name not in self._policies:
            raise KeyError(name)

        deleted_config = deepcopy(self._policies[name])
        deleted_config["enabled"] = False
        deleted_config["deleted"] = True

        await self._persist_policy_version(
            name=name,
            config=deleted_config,
            changed_by=changed_by,
            change_note="soft delete",
        )
        self._policies[name] = deleted_config
        return deepcopy(deleted_config)

    async def reset_policies(self, changed_by: str = "admin") -> None:
        """Reset all policies to defaults and version each reset."""
        for name, config in DEFAULT_POLICIES.items():
            await self._persist_policy_version(
                name=name,
                config=config,
                changed_by=changed_by,
                change_note="reset to defaults",
            )
        self._policies = deepcopy(DEFAULT_POLICIES)

    def get_entitlements(self) -> Dict[str, Any]:
        """Get entitlement set copy."""
        return deepcopy(self._entitlements)

    async def get_entitlements_with_version(self) -> tuple[Dict[str, Any], Optional[int]]:
        """Get current entitlement set with latest version number."""
        entitlements = self.get_entitlements()
        version = await self.get_entitlements_version()
        return entitlements, version

    async def get_entitlements_version(self) -> Optional[int]:
        """Get latest entitlement version."""
        if self._audit_logger and self._audit_logger.connected:
            latest = await self._audit_logger.get_latest_entitlements()
            if latest and latest.get("version") is not None:
                return int(latest["version"])
            return None
        return int(self._fallback_entitlement_version)

    async def update_entitlements(
        self,
        updates: Dict[str, Any],
        changed_by: str = "admin",
        change_note: str = "entitlement update",
    ) -> tuple[Dict[str, Any], int]:
        """Update entitlement set and create a new version entry."""
        merged = _deep_merge(self._entitlements, updates)
        version = await self._persist_entitlement_version(
            entitlements=merged,
            changed_by=changed_by,
            change_note=change_note,
        )
        self._entitlements = merged
        return deepcopy(merged), version

    async def _persist_policy_version(
        self,
        name: str,
        config: Dict[str, Any],
        changed_by: str,
        change_note: str,
    ) -> int:
        """Persist policy version in DB, with fallback if DB is unavailable."""
        if self._audit_logger and self._audit_logger.connected:
            return await self._audit_logger.insert_policy_version(
                policy_name=name,
                config=config,
                created_by=changed_by,
                change_note=change_note,
            )

        next_version = self._fallback_versions.get(name, 1) + 1
        self._fallback_versions[name] = next_version
        logger.warning(f"Policy version persisted in fallback mode: {name}@{next_version}")
        return next_version

    async def _persist_entitlement_version(
        self,
        entitlements: Dict[str, Any],
        changed_by: str,
        change_note: str,
    ) -> int:
        """Persist entitlement version in DB, with fallback if DB is unavailable."""
        if self._audit_logger and self._audit_logger.connected:
            return await self._audit_logger.insert_entitlement_version(
                entitlements=entitlements,
                created_by=changed_by,
                change_note=change_note,
            )

        self._fallback_entitlement_version += 1
        logger.warning(
            f"Entitlement version persisted in fallback mode: v{self._fallback_entitlement_version}"
        )
        return self._fallback_entitlement_version

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if entitlement allows a module."""
        modules = self._entitlements.get("modules", {})
        return bool(modules.get(module_name, True))

    def is_provider_enabled(self, provider_name: str) -> bool:
        """Check if entitlement allows a model provider."""
        providers = self._entitlements.get("providers", {})
        return bool(providers.get(provider_name, True))

    def get_allowed_models(self) -> List[str]:
        """Get explicitly allowed model list from entitlements."""
        limits = self._entitlements.get("limits", {})
        allowed_models = limits.get("allowed_models", [])
        if isinstance(allowed_models, list):
            return [str(item) for item in allowed_models]
        return []

    def _json_to_dict(self, value: Any) -> Dict[str, Any]:
        """Normalize DB JSON values into dictionaries."""
        if isinstance(value, dict):
            return deepcopy(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {}
        return {}


policy_store = PolicyStore()


def get_policy(name: str) -> Dict[str, Any]:
    """Synchronous helper for fast-path policy reads."""
    return policy_store.get_policy(name)
