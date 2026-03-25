"""In-memory telemetry metrics for gateway operational visibility."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional


class TelemetryMetrics:
    """Process-local counters and latency aggregates."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._decision_counts: Dict[str, int] = defaultdict(int)
        self._provider_counts: Dict[str, int] = defaultdict(int)
        self._block_type_counts: Dict[str, int] = defaultdict(int)
        self._block_reason_counts: Dict[str, int] = defaultdict(int)
        self._event_total = 0
        self._latency_count = 0
        self._latency_sum = 0
        self._latency_min: Optional[int] = None
        self._latency_max: Optional[int] = None
        self._last_updated: Optional[datetime] = None

    def record_event(
        self,
        *,
        decision: str,
        provider: Optional[str] = None,
        response_time_ms: Optional[int] = None,
        attributes: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Record a gateway event outcome for metrics snapshots."""
        with self._lock:
            self._event_total += 1
            key = (decision or "UNKNOWN").upper()
            self._decision_counts[key] += 1

            provider_key = (provider or "unknown").lower()
            self._provider_counts[provider_key] += 1

            attrs = attributes or {}
            block_type = str(attrs.get("block_type") or "unspecified").lower()
            if key == "BLOCK":
                self._block_type_counts[block_type] += 1
                if reason:
                    self._block_reason_counts[str(reason)[:120]] += 1

            if isinstance(response_time_ms, int) and response_time_ms >= 0:
                self._latency_count += 1
                self._latency_sum += response_time_ms
                self._latency_min = (
                    response_time_ms if self._latency_min is None else min(self._latency_min, response_time_ms)
                )
                self._latency_max = (
                    response_time_ms if self._latency_max is None else max(self._latency_max, response_time_ms)
                )

            self._last_updated = datetime.now(timezone.utc)

    def snapshot(self) -> Dict[str, Any]:
        """Return point-in-time telemetry metrics."""
        with self._lock:
            latency_avg = (
                int(self._latency_sum / self._latency_count)
                if self._latency_count > 0
                else None
            )
            return {
                "event_total": self._event_total,
                "decision_counts": dict(self._decision_counts),
                "provider_counts": dict(self._provider_counts),
                "block_type_counts": dict(self._block_type_counts),
                "block_reason_counts": dict(self._block_reason_counts),
                "latency_ms": {
                    "count": self._latency_count,
                    "avg": latency_avg,
                    "min": self._latency_min,
                    "max": self._latency_max,
                },
                "last_updated": self._last_updated.isoformat() if self._last_updated else None,
            }

    def reset(self) -> None:
        """Reset counters for tests/debug sessions."""
        with self._lock:
            self._decision_counts.clear()
            self._provider_counts.clear()
            self._block_type_counts.clear()
            self._block_reason_counts.clear()
            self._event_total = 0
            self._latency_count = 0
            self._latency_sum = 0
            self._latency_min = None
            self._latency_max = None
            self._last_updated = None


telemetry_metrics = TelemetryMetrics()

