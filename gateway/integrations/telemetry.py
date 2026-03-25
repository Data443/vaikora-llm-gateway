"""In-memory telemetry metrics for gateway operational visibility."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional


def _escape_label_value(value: str) -> str:
    """Escape label values for Prometheus text exposition format."""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


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

    def to_prometheus(self) -> str:
        """Expose metrics in Prometheus text format."""
        snap = self.snapshot()
        latency = snap.get("latency_ms", {})

        lines = [
            "# HELP gateway_event_total Total number of gateway events recorded",
            "# TYPE gateway_event_total counter",
            f"gateway_event_total {snap.get('event_total', 0)}",
            "# HELP gateway_decision_total Gateway event decisions by type",
            "# TYPE gateway_decision_total counter",
        ]

        for decision, count in sorted(snap.get("decision_counts", {}).items()):
            label = _escape_label_value(str(decision))
            lines.append(f'gateway_decision_total{{decision="{label}"}} {count}')

        lines.extend(
            [
                "# HELP gateway_provider_total Gateway events by upstream provider",
                "# TYPE gateway_provider_total counter",
            ]
        )
        for provider, count in sorted(snap.get("provider_counts", {}).items()):
            label = _escape_label_value(str(provider))
            lines.append(f'gateway_provider_total{{provider="{label}"}} {count}')

        lines.extend(
            [
                "# HELP gateway_block_type_total Blocked events by block type",
                "# TYPE gateway_block_type_total counter",
            ]
        )
        for block_type, count in sorted(snap.get("block_type_counts", {}).items()):
            label = _escape_label_value(str(block_type))
            lines.append(f'gateway_block_type_total{{block_type="{label}"}} {count}')

        lines.extend(
            [
                "# HELP gateway_block_reason_total Blocked events by normalized reason",
                "# TYPE gateway_block_reason_total counter",
            ]
        )
        for reason, count in sorted(snap.get("block_reason_counts", {}).items()):
            label = _escape_label_value(str(reason))
            lines.append(f'gateway_block_reason_total{{reason="{label}"}} {count}')

        lines.extend(
            [
                "# HELP gateway_response_latency_ms_count Response latency samples",
                "# TYPE gateway_response_latency_ms_count gauge",
                f"gateway_response_latency_ms_count {latency.get('count', 0)}",
                "# HELP gateway_response_latency_ms_avg Average response latency in milliseconds",
                "# TYPE gateway_response_latency_ms_avg gauge",
                f"gateway_response_latency_ms_avg {latency.get('avg') or 0}",
                "# HELP gateway_response_latency_ms_min Minimum response latency in milliseconds",
                "# TYPE gateway_response_latency_ms_min gauge",
                f"gateway_response_latency_ms_min {latency.get('min') or 0}",
                "# HELP gateway_response_latency_ms_max Maximum response latency in milliseconds",
                "# TYPE gateway_response_latency_ms_max gauge",
                f"gateway_response_latency_ms_max {latency.get('max') or 0}",
            ]
        )

        timestamp_value = 0
        last_updated_raw = snap.get("last_updated")
        if isinstance(last_updated_raw, str):
            try:
                timestamp_value = datetime.fromisoformat(last_updated_raw).timestamp()
            except ValueError:
                timestamp_value = 0

        lines.extend(
            [
                "# HELP gateway_metrics_last_updated_timestamp Last metrics update timestamp (unix seconds)",
                "# TYPE gateway_metrics_last_updated_timestamp gauge",
                f"gateway_metrics_last_updated_timestamp {timestamp_value}",
            ]
        )

        return "\n".join(lines) + "\n"

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
