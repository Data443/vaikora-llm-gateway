"""Gateway request rate limiting middleware."""

from __future__ import annotations

import time
from threading import Lock
from typing import Dict, Optional, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.core.config import settings
from gateway.integrations.cache import cache


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window rate limiter with Redis support and in-memory fallback."""

    def __init__(self, app):
        super().__init__(app)
        self.window_seconds = max(1, int(settings.rate_limit_window_seconds))
        self.storage = (settings.rate_limit_storage or "auto").strip().lower()
        self.redis_prefix = (settings.rate_limit_redis_prefix or "gw:ratelimit").strip()
        self.proxy_limit = max(1, int(settings.rate_limit_proxy_requests))
        self.admin_limit = max(1, int(settings.rate_limit_admin_requests))
        self.audit_limit = max(1, int(settings.rate_limit_audit_requests))

        # Memory fallback when Redis is unavailable.
        self._entries: Dict[str, Tuple[float, int]] = {}
        self._lock = Lock()
        self._gc_counter = 0
        self._gc_interval = 1000

    async def dispatch(self, request: Request, call_next) -> Response:
        if not settings.rate_limit_enabled:
            return await call_next(request)

        category = self._classify_path(request.url.path)
        if category is None:
            return await call_next(request)

        limit = self._limit_for_category(category)
        client_id = self._client_identifier(request)
        count, reset_seconds = await self._increment_counter(
            category=category,
            client_id=client_id,
        )
        remaining = max(0, limit - count)

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_seconds),
        }

        if count > limit:
            logger.warning(
                "Rate limit exceeded: category={} key={} count={} limit={}",
                category,
                f"{category}:{client_id}",
                count,
                limit,
            )
            headers["Retry-After"] = str(reset_seconds)
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "message": f"Rate limit exceeded for {category} traffic",
                        "type": "rate_limited",
                        "code": "too_many_requests",
                    }
                },
                headers=headers,
            )

        response = await call_next(request)
        for name, value in headers.items():
            response.headers[name] = value
        return response

    async def _increment_counter(self, category: str, client_id: str) -> Tuple[int, int]:
        if self._should_use_redis():
            redis_result = await self._increment_counter_redis(category, client_id)
            if redis_result is not None:
                return redis_result

        return self._increment_counter_memory(category, client_id)

    def _should_use_redis(self) -> bool:
        if self.storage not in {"auto", "redis", "memory"}:
            logger.warning(
                "Invalid RATE_LIMIT_STORAGE='{}'; falling back to auto",
                self.storage,
            )
            self.storage = "auto"

        if self.storage == "memory":
            return False

        redis_ready = bool(cache.l2.connected and cache.l2.redis)
        if self.storage == "redis" and not redis_ready:
            logger.warning(
                "RATE_LIMIT_STORAGE=redis but Redis is unavailable; using in-memory fallback",
            )
            return False
        return redis_ready

    async def _increment_counter_redis(
        self,
        category: str,
        client_id: str,
    ) -> Optional[Tuple[int, int]]:
        if not cache.l2.redis:
            return None

        now = int(time.time())
        window_id = now // self.window_seconds
        key = f"{self.redis_prefix}:{category}:{client_id}:{window_id}"

        try:
            count = await cache.l2.redis.incr(key)
            ttl = await cache.l2.redis.ttl(key)

            if ttl is None or ttl <= 0:
                await cache.l2.redis.expire(key, self.window_seconds)
                ttl = self.window_seconds

            return int(count), max(1, int(ttl))
        except Exception as exc:
            logger.warning("Redis rate-limit fallback to memory: {}", exc)
            return None

    def _increment_counter_memory(self, category: str, client_id: str) -> Tuple[int, int]:
        key = f"{category}:{client_id}"
        now = time.monotonic()

        with self._lock:
            window_start, count = self._entries.get(key, (now, 0))
            if now - window_start >= self.window_seconds:
                window_start, count = now, 0

            count += 1
            self._entries[key] = (window_start, count)
            reset_seconds = max(1, int(self.window_seconds - (now - window_start)))

            self._gc_counter += 1
            if self._gc_counter >= self._gc_interval:
                self._cleanup(now)
                self._gc_counter = 0

        return count, reset_seconds

    def _cleanup(self, now: float) -> None:
        expired = [
            key
            for key, (window_start, _count) in self._entries.items()
            if now - window_start >= self.window_seconds
        ]
        for key in expired:
            self._entries.pop(key, None)

    def _limit_for_category(self, category: str) -> int:
        if category == "admin":
            return self.admin_limit
        if category == "audit":
            return self.audit_limit
        return self.proxy_limit

    def _classify_path(self, path: str) -> Optional[str]:
        normalized = (path or "").rstrip("/") or "/"

        if normalized in {"/", "/health"}:
            return None

        if normalized.startswith("/admin/"):
            return "admin"

        if normalized.startswith("/audit/"):
            return "audit"

        # Everything else is treated as proxy traffic.
        return "proxy"

    def _client_identifier(self, request: Request) -> str:
        if settings.trust_proxy_headers:
            forwarded = request.headers.get("x-forwarded-for", "").strip()
            if forwarded:
                return forwarded.split(",")[0].strip() or "unknown"
            real_ip = request.headers.get("x-real-ip", "").strip()
            if real_ip:
                return real_ip

        if request.client and request.client.host:
            return request.client.host
        return "unknown"
