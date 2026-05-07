"""
Data443 LLM Gateway - Redis L1/L2 Caching

Two-level caching strategy:
- L1: In-memory cache (fastest, per-instance)
- L2: Redis cache (shared across instances, persistent)
"""

from datetime import timedelta
from typing import Optional, Any
import time

import redis.asyncio as redis
from redis.asyncio import Redis
from loguru import logger

from gateway.core.config import settings
from gateway.integrations.telemetry import telemetry_metrics


_L1_MAX_ENTRIES = 10_000


class L1Cache:
    """In-memory cache (L1 level) with size bound."""

    def __init__(self, ttl: int = 300, max_entries: int = _L1_MAX_ENTRIES):
        self.ttl = ttl
        self.max_entries = max_entries
        self.cache: dict[str, tuple[float, Any]] = {}

    def _evict_expired(self) -> None:
        """Remove all expired entries."""
        now = time.time()
        expired_keys = [k for k, (exp, _) in self.cache.items() if now >= exp]
        for k in expired_keys:
            del self.cache[k]

    def _evict_oldest(self) -> None:
        """Drop oldest entries when over capacity."""
        if len(self.cache) <= self.max_entries:
            return
        sorted_keys = sorted(self.cache, key=lambda k: self.cache[k][0])
        to_remove = len(self.cache) - self.max_entries
        for k in sorted_keys[:to_remove]:
            del self.cache[k]

    def get(self, key: str) -> Optional[Any]:
        """Get value from L1 cache if not expired."""
        if key in self.cache:
            expiry, value = self.cache[key]
            if time.time() < expiry:
                logger.debug(f"L1 cache HIT: {key}")
                telemetry_metrics.record_cache_event(layer="l1", outcome="hit")
                return value
            else:
                del self.cache[key]
        logger.debug(f"L1 cache MISS: {key}")
        telemetry_metrics.record_cache_event(layer="l1", outcome="miss")
        return None

    def set(self, key: str, value: Any) -> None:
        """Set value in L1 cache."""
        if len(self.cache) >= self.max_entries:
            self._evict_expired()
        if len(self.cache) >= self.max_entries:
            self._evict_oldest()
        expiry = time.time() + self.ttl
        self.cache[key] = (expiry, value)
        logger.debug(f"L1 cache SET: {key}")

    def delete(self, key: str) -> None:
        """Delete from L1 cache."""
        self.cache.pop(key, None)

    def clear(self) -> None:
        """Clear L1 cache."""
        self.cache.clear()


class L2Cache:
    """Redis cache (L2 level)."""

    def __init__(self):
        self.redis: Optional[Redis] = None
        self.connected = False

    async def connect(self) -> None:
        """Connect to Redis."""
        try:
            # redis.from_url returns a client instance immediately; do not await it.
            self.redis = redis.from_url(
                f"redis://{settings.redis_host}:{settings.redis_port}/{settings.redis_db}",
                password=settings.redis_password if settings.redis_password else None,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            await self.redis.ping()
            self.connected = True
            logger.info("Connected to Redis (L2 cache)")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            self.connected = False

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            self.connected = False
            logger.info("Disconnected from Redis")

    async def get(self, key: str) -> Optional[str]:
        """Get value from L2 cache."""
        if not self.connected:
            telemetry_metrics.record_cache_event(layer="l2", outcome="disconnected")
            return None
        try:
            value = await self.redis.get(key)
            if value:
                logger.debug(f"L2 cache HIT: {key}")
                telemetry_metrics.record_cache_event(layer="l2", outcome="hit")
                return value
            logger.debug(f"L2 cache MISS: {key}")
            telemetry_metrics.record_cache_event(layer="l2", outcome="miss")
            return None
        except Exception as e:
            logger.warning(f"Redis GET error: {e}")
            telemetry_metrics.record_cache_event(layer="l2", outcome="error")
            return None

    async def set(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Set value in L2 cache."""
        if not self.connected:
            telemetry_metrics.record_cache_event(layer="l2", outcome="disconnected")
            return False
        try:
            if ttl is None:
                ttl = settings.redis_l2_ttl
            await self.redis.setex(key, ttl, value)
            logger.debug(f"L2 cache SET: {key} (TTL: {ttl}s)")
            telemetry_metrics.record_cache_event(layer="l2", outcome="set")
            return True
        except Exception as e:
            logger.warning(f"Redis SET error: {e}")
            telemetry_metrics.record_cache_event(layer="l2", outcome="error")
            return False

    async def delete(self, key: str) -> None:
        """Delete from L2 cache."""
        if not self.connected:
            return
        try:
            await self.redis.delete(key)
            logger.debug(f"L2 cache DELETE: {key}")
        except Exception as e:
            logger.warning(f"Redis DELETE error: {e}")

    async def clear(self) -> None:
        """Clear L2 cache."""
        if not self.connected:
            return
        try:
            await self.redis.flushdb()
            logger.info("L2 cache cleared")
        except Exception as e:
            logger.warning(f"Redis CLEAR error: {e}")


class TwoLevelCache:
    """Two-level cache manager (L1 + L2)."""

    def __init__(self):
        self.l1 = L1Cache(ttl=settings.redis_l1_ttl)
        self.l2 = L2Cache()

    async def connect(self) -> None:
        """Connect to L2 cache (Redis)."""
        await self.l2.connect()

    async def disconnect(self) -> None:
        """Disconnect from L2 cache (Redis)."""
        await self.l2.disconnect()

    async def get(self, key: str) -> Optional[Any]:
        """Get from L1, fallback to L2."""
        # Try L1 first
        value = self.l1.get(key)
        if value is not None:
            return value

        # Try L2
        l2_value = await self.l2.get(key)
        if l2_value is not None:
            # Populate L1
            self.l1.set(key, l2_value)
            return l2_value

        return None

    async def set(self, key: str, value: Any) -> None:
        """Set in both L1 and L2."""
        self.l1.set(key, value)
        await self.l2.set(key, value)

    async def delete(self, key: str) -> None:
        """Delete from both L1 and L2."""
        self.l1.delete(key)
        await self.l2.delete(key)

    async def clear(self) -> None:
        """Clear both L1 and L2."""
        self.l1.clear()
        await self.l2.clear()


# Global cache instance
cache = TwoLevelCache()

