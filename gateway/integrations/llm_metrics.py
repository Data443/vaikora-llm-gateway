"""Prometheus LLM-execution metrics for the gateway.

Implements the shared Data443 metric contract (llm-observability/CONTRACT.md) so this
gateway shows up on the same "LLM executions per hour by infra class" dashboard as every
other product:

* ``llm_requests_total``            one per upstream call (an execution), by status + caller
* ``llm_tokens_total``              token counts parsed from the upstream ``usage`` block
* ``llm_request_duration_seconds``  upstream round-trip time
* ``llm_inflight_requests``         in-flight upstream calls (multiprocess ``livesum``)
* ``llm_gateway_blocked_total``     requests the gateway refused before any upstream call

``infra_class`` is resolved from the HOST of the URL the request is actually sent to, not
from the provider id: in production the ``openai`` provider points at inference-01.

Multi-worker servers: when ``PROMETHEUS_MULTIPROC_DIR`` is set (the Docker image sets it)
prometheus_client writes every value to per-process mmap files in that directory and
``render_metrics()`` aggregates them with ``MultiProcessCollector``. The directory must be
emptied before the first worker starts (the image CMD does it, as does ``gateway.main``),
otherwise counters from a previous container run would be summed in.

Metric recording never raises into the request path.
"""

from __future__ import annotations

import asyncio
import glob
import json
import os
import re
import shutil
import threading
import time
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from loguru import logger

MULTIPROC_DIR: Optional[str] = (
    os.environ.get("PROMETHEUS_MULTIPROC_DIR") or os.environ.get("prometheus_multiproc_dir") or None
)
if MULTIPROC_DIR:
    try:
        os.makedirs(MULTIPROC_DIR, exist_ok=True)
    except OSError as _exc:  # metrics must never make the gateway fail to boot
        logger.warning(f"llm_metrics: cannot create PROMETHEUS_MULTIPROC_DIR {MULTIPROC_DIR}: {_exc}")

from prometheus_client import (  # noqa: E402  (directory must exist before values are created)
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client import multiprocess  # noqa: E402
from prometheus_client.exposition import CONTENT_TYPE_PLAIN_0_0_4  # noqa: E402

# Classic text format: understood by every Prometheus 2.x/3.x scraper.
METRICS_CONTENT_TYPE = CONTENT_TYPE_PLAIN_0_0_4

PRODUCT = "llm-gateway"
FEATURE = "proxy"

INFRA_CLASSES = frozenset({"cpu_local", "gpu_local", "gpu_offprem", "api_thirdparty", "unknown"})

# Built-in host-suffix defaults from the contract. LLM_INFRA_CLASS_MAP is checked first.
_DEFAULT_INFRA_SUFFIXES: Tuple[Tuple[str, str], ...] = (
    ("10.40.5.106", "cpu_local"),
    ("llm-gateway.data443.io", "cpu_local"),
    ("inference-01", "cpu_local"),
    ("proxy.runpod.net", "gpu_offprem"),
    ("runpod.net", "gpu_offprem"),
    ("runpod.ai", "gpu_offprem"),
    ("api.anthropic.com", "api_thirdparty"),
    ("api.openai.com", "api_thirdparty"),
    ("generativelanguage.googleapis.com", "api_thirdparty"),
    ("openrouter.ai", "api_thirdparty"),
    ("integrate.api.nvidia.com", "api_thirdparty"),
    ("api.z.ai", "api_thirdparty"),
    ("api.x.ai", "api_thirdparty"),
    ("api.perplexity.ai", "api_thirdparty"),
    ("fal.run", "api_thirdparty"),
    ("api.together.xyz", "api_thirdparty"),
    ("api.groq.com", "api_thirdparty"),
)

# Bounded reasons for llm_gateway_blocked_total.
BLOCK_REASONS = (
    "auth",
    "entitlement",
    "content_filter",
    "policy",
    "hitl",
    "rate_limit",
    "agent",
    "config_error",
    "other",
)
_BLOCKING_DECISIONS = frozenset({"BLOCK", "ERROR", "PENDING_APPROVAL"})

DURATION_BUCKETS = (0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300)

# Registry for single-process mode. In multiprocess mode values live in the mmap files
# and render_metrics() builds a fresh aggregating registry per scrape instead.
REGISTRY = CollectorRegistry()

REQUESTS = Counter(
    "llm_requests",
    "LLM executions (upstream calls) made by this gateway.",
    ["product", "feature", "infra_class", "provider", "model", "status", "caller"],
    registry=REGISTRY,
)
TOKENS = Counter(
    "llm_tokens",
    "LLM tokens reported by the upstream usage block.",
    ["product", "infra_class", "provider", "model", "type"],
    registry=REGISTRY,
)
DURATION = Histogram(
    "llm_request_duration_seconds",
    "Upstream LLM call duration in seconds.",
    ["product", "infra_class", "provider", "model"],
    buckets=DURATION_BUCKETS,
    registry=REGISTRY,
)
INFLIGHT = Gauge(
    "llm_inflight_requests",
    "Upstream LLM calls currently in flight.",
    ["product", "infra_class"],
    multiprocess_mode="livesum",
    registry=REGISTRY,
)
BLOCKED = Counter(
    "llm_gateway_blocked",
    "Requests refused by the gateway before any upstream LLM call.",
    ["reason"],
    registry=REGISTRY,
)


# ---------------------------------------------------------------------------
# infra_class
# ---------------------------------------------------------------------------


def _host_of(url: Optional[str]) -> str:
    if not url:
        return ""
    raw = str(url).strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "//" + raw
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


@lru_cache(maxsize=8)
def _parse_infra_map(raw: str) -> Tuple[Tuple[str, str], ...]:
    entries: List[Tuple[str, str]] = []
    for item in raw.split(","):
        if "=" not in item:
            continue
        suffix, cls = item.split("=", 1)
        suffix = suffix.strip().lower().rstrip(".")
        cls = cls.strip().lower()
        if suffix and cls in INFRA_CLASSES:
            entries.append((suffix, cls))
    return tuple(entries)


def _longest_suffix_match(host: str, table: Iterable[Tuple[str, str]]) -> Optional[str]:
    best: Optional[Tuple[str, str]] = None
    for suffix, cls in table:
        if host == suffix or host.endswith("." + suffix):
            if best is None or len(suffix) > len(best[0]):
                best = (suffix, cls)
    return best[1] if best else None


def resolve_infra_class(url: Optional[str]) -> str:
    """Classify the infra behind a base/target URL by its hostname.

    ``LLM_INFRA_CLASS_MAP`` (``host_suffix=class,...``) is checked first, then the built-in
    defaults; within each table the longest matching suffix wins. Anything unmatched is
    ``unknown`` so it surfaces on the dashboard for someone to classify.
    """
    host = _host_of(url)
    if not host:
        return "unknown"
    env_map = _parse_infra_map(os.environ.get("LLM_INFRA_CLASS_MAP", ""))
    return (
        _longest_suffix_match(host, env_map)
        or _longest_suffix_match(host, _DEFAULT_INFRA_SUFFIXES)
        or "unknown"
    )


# ---------------------------------------------------------------------------
# label sanitisation
# ---------------------------------------------------------------------------


class BoundedLabel:
    """Caps the number of distinct values a label can take in this process.

    ``admit=False`` maps any value not already seen to ``overflow`` without using a slot,
    so requests the upstream rejected cannot mint new label values.
    """

    def __init__(self, limit: int, overflow: str = "other") -> None:
        self.limit = limit
        self.overflow = overflow
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def __call__(self, value: str, admit: bool = True) -> str:
        with self._lock:
            if value in self._seen:
                return value
            if not admit or len(self._seen) >= self.limit:
                return self.overflow
            self._seen.add(value)
            return value


_CALLER_INVALID = re.compile(r"[^a-z0-9_.-]+")
_MODEL_INVALID = re.compile(r"[^a-z0-9_.:/@+-]+")
_PROVIDER_INVALID = re.compile(r"[^a-z0-9_-]+")

# Per-process caps. caller and model are client-controlled (header / request body), so the
# (model, caller) pairs are capped too: without it the cross product alone could exceed the
# contract's <500-series budget. Overflow callers are recorded as "other".
_caller_bound = BoundedLabel(limit=64)
_model_bound = BoundedLabel(limit=32)
_caller_model_pair_bound = BoundedLabel(limit=96)


def sanitize_caller(raw: Optional[str]) -> str:
    if raw is None:
        return "anonymous"
    value = _CALLER_INVALID.sub("_", str(raw).strip().lower()).strip("_.-")
    value = value[:40].strip("_.-")
    return value or "anonymous"


def resolve_caller(headers: Mapping[str, str], agent_context: Optional[Mapping[str, Any]] = None) -> str:
    """``x-caller`` header, else the managed agent id, else ``anonymous``."""
    raw = (headers.get("x-caller") or "").strip()
    if not raw and agent_context:
        raw = str(agent_context.get("agent_id") or "").strip()
    if not raw:
        raw = (headers.get("x-agent-id") or "").strip()
    return sanitize_caller(raw)


def sanitize_model(raw: Optional[str]) -> str:
    if raw is None:
        return "unknown"
    value = _MODEL_INVALID.sub("_", str(raw).strip().lower()).strip("_")
    return value[:80] or "unknown"


def _sanitize_provider(raw: Optional[str]) -> str:
    value = _PROVIDER_INVALID.sub("_", str(raw or "").strip().lower()).strip("_")
    return value[:32] or "unknown"


def block_reason_for(decision: Any, attributes: Optional[Mapping[str, Any]]) -> str:
    """Map a gateway event (decision + attributes.block_type) to a bounded block reason."""
    attrs = attributes or {}
    block_type = str(attrs.get("block_type") or "").strip().lower()
    if block_type in {"proxy_auth", "auth"}:
        return "auth"
    if block_type == "auth_configuration":
        return "config_error"
    if block_type.startswith("entitlement"):
        return "entitlement"
    if block_type == "content_filter":
        return "content_filter"
    if block_type.startswith("hitl"):
        return "hitl"
    if block_type:
        return "other"
    if attrs.get("exception") == "provider_configuration_error":
        return "config_error"
    if str(getattr(decision, "value", decision)).upper() == "BLOCK":
        return "policy"
    return "other"


def is_blocking_decision(decision: Any) -> bool:
    return str(getattr(decision, "value", decision)).upper() in _BLOCKING_DECISIONS


# ---------------------------------------------------------------------------
# token usage
# ---------------------------------------------------------------------------


def _nonneg_int(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def extract_token_usage(payload: Any) -> Dict[str, int]:
    """Token counts by contract ``type`` from an OpenAI, Anthropic or Gemini response body.

    Cached prompt tokens are reported as ``cache_read`` and excluded from ``input`` so the
    types sum to the tokens actually billed/processed (Anthropic semantics). Zero counts
    are omitted.
    """
    if not isinstance(payload, dict):
        return {}

    counts: Dict[str, int] = {}
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        message = payload.get("message")  # Anthropic SSE message_start
        usage = message.get("usage") if isinstance(message, dict) else None

    if isinstance(usage, dict):
        if "prompt_tokens" in usage or "completion_tokens" in usage:
            details = usage.get("prompt_tokens_details")
            cached = _nonneg_int(details.get("cached_tokens")) if isinstance(details, dict) else 0
            counts["input"] = max(_nonneg_int(usage.get("prompt_tokens")) - cached, 0)
            counts["output"] = _nonneg_int(usage.get("completion_tokens"))
            counts["cache_read"] = cached
        elif "input_tokens" in usage or "output_tokens" in usage:
            details = usage.get("input_tokens_details")  # OpenAI Responses API shape
            cached = _nonneg_int(details.get("cached_tokens")) if isinstance(details, dict) else 0
            counts["input"] = max(_nonneg_int(usage.get("input_tokens")) - cached, 0)
            counts["output"] = _nonneg_int(usage.get("output_tokens"))
            counts["cache_read"] = cached + _nonneg_int(usage.get("cache_read_input_tokens"))
            counts["cache_write"] = _nonneg_int(usage.get("cache_creation_input_tokens"))

    metadata = payload.get("usageMetadata")
    if not counts and isinstance(metadata, dict):
        cached = _nonneg_int(metadata.get("cachedContentTokenCount"))
        counts["input"] = max(_nonneg_int(metadata.get("promptTokenCount")) - cached, 0)
        # Gemini thinking models bill reasoning tokens as output but report them separately.
        counts["output"] = _nonneg_int(metadata.get("candidatesTokenCount")) + _nonneg_int(
            metadata.get("thoughtsTokenCount")
        )
        counts["cache_read"] = cached

    return {k: v for k, v in counts.items() if v > 0}


_SSE_NULL_USAGE = re.compile(rb'"usage"\s*:\s*null')


def extract_sse_usage(body: bytes) -> Dict[str, int]:
    """Best-effort token counts from a buffered SSE stream (max per type across chunks)."""
    merged: Dict[str, int] = {}
    if not body:
        return merged
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith(b"data:") or b"usage" not in line:
            continue
        # OpenAI include_usage streams put "usage": null on every chunk but the last:
        # skip those without paying for a json.loads.
        if _SSE_NULL_USAGE.search(line) and b"usageMetadata" not in line:
            continue
        data = line[5:].strip()
        try:
            chunk = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            continue
        for key, value in extract_token_usage(chunk).items():
            merged[key] = max(merged.get(key, 0), value)
    return merged


# ---------------------------------------------------------------------------
# recording
# ---------------------------------------------------------------------------


def record_blocked(reason: Optional[str]) -> None:
    try:
        label = reason if reason in BLOCK_REASONS else "other"
        BLOCKED.labels(label).inc()
    except Exception as exc:  # pragma: no cover - metrics must never break requests
        logger.debug(f"llm_metrics: failed to record blocked request: {exc}")


def _status_for_http(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "ok"
    if status_code in (408, 504):
        return "timeout"
    return "error"


def _status_for_exception(exc: BaseException) -> str:
    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    return "error"


class LLMExecution:
    """One upstream LLM call. Create right before the call, ``finish()`` exactly once after."""

    def __init__(
        self,
        *,
        target_url: Optional[str],
        provider: Optional[str],
        model: Optional[str],
        caller: Optional[str],
    ) -> None:
        self.infra_class = "unknown"
        self.provider = "unknown"
        self.model = "unknown"
        self.caller = "anonymous"
        self.status: Optional[str] = None
        self.upstream_rejected = False  # 4xx: upstream refused it (e.g. unknown model)
        self.usage: Dict[str, int] = {}
        self._start = time.perf_counter()
        self._end: Optional[float] = None
        self._finished = False
        self._inflight_counted = False
        try:
            self.infra_class = resolve_infra_class(target_url)
            self.provider = _sanitize_provider(provider)
            self.model = sanitize_model(model)
            self.caller = sanitize_caller(caller)
            INFLIGHT.labels(PRODUCT, self.infra_class).inc()
            self._inflight_counted = True
        except Exception as exc:  # pragma: no cover
            logger.debug(f"llm_metrics: failed to start execution: {exc}")

    def mark_response(self, status_code: int) -> None:
        if self._end is None:
            self._end = time.perf_counter()
        self.status = _status_for_http(int(status_code))
        self.upstream_rejected = 400 <= int(status_code) < 500 and int(status_code) != 408
        self._release_inflight()

    def mark_exception(self, exc: BaseException) -> None:
        if self._end is None:
            self._end = time.perf_counter()
        self.status = _status_for_exception(exc)
        self._release_inflight()

    def _release_inflight(self) -> None:
        """The upstream call is over: stop counting it (gateway post-processing is not)."""
        if not self._inflight_counted:
            return
        self._inflight_counted = False
        try:
            INFLIGHT.labels(PRODUCT, self.infra_class).dec()
        except Exception:  # pragma: no cover
            pass

    def _bounded_labels(self) -> Tuple[str, str]:
        """Apply the per-process caps to (model, caller); only accepted calls mint values."""
        admit = not self.upstream_rejected
        model = _model_bound(self.model, admit)
        caller = self.caller
        if caller != "anonymous":
            caller = _caller_bound(caller, admit)
            if caller != "other" and _caller_model_pair_bound(f"{model}\x00{caller}", admit) == "other":
                caller = "other"
        return model, caller

    def finish(self) -> None:
        if self._finished:
            return
        self._finished = True
        try:
            end = self._end if self._end is not None else time.perf_counter()
            status = self.status or "error"
            model, caller = self._bounded_labels()
            REQUESTS.labels(
                PRODUCT, FEATURE, self.infra_class, self.provider, model, status, caller
            ).inc()
            DURATION.labels(PRODUCT, self.infra_class, self.provider, model).observe(
                max(end - self._start, 0.0)
            )
            for token_type, count in (self.usage or {}).items():
                if token_type in {"input", "output", "cache_read", "cache_write"} and count > 0:
                    TOKENS.labels(PRODUCT, self.infra_class, self.provider, model, token_type).inc(count)
        except Exception as exc:  # pragma: no cover
            logger.debug(f"llm_metrics: failed to record execution: {exc}")
        finally:
            self._release_inflight()


# ---------------------------------------------------------------------------
# exposition + multiprocess bookkeeping
# ---------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def reap_dead_workers(path: Optional[str] = None) -> None:
    """Drop live-gauge files of worker PIDs that no longer exist.

    uvicorn's supervisor has no child-exit hook, so a worker that crashes would otherwise
    leave its in-flight gauge contribution behind forever. Counter/histogram files of dead
    workers are kept on purpose: their totals must stay in the sum.
    """
    path = path or MULTIPROC_DIR
    if not path:
        return
    own_pid = os.getpid()
    for file_path in glob.glob(os.path.join(path, "gauge_live*_*.db")):
        stem = os.path.basename(file_path)[: -len(".db")]
        pid_part = stem.rsplit("_", 1)[-1]
        if not pid_part.isdigit():
            continue
        pid = int(pid_part)
        if pid != own_pid and not _pid_alive(pid):
            try:
                multiprocess.mark_process_dead(pid, path)
            except OSError:
                pass


def mark_worker_exit() -> None:
    """Call on worker shutdown so its live gauges stop counting."""
    if not MULTIPROC_DIR:
        return
    try:
        multiprocess.mark_process_dead(os.getpid(), MULTIPROC_DIR)
    except Exception as exc:  # pragma: no cover
        logger.debug(f"llm_metrics: mark_process_dead failed: {exc}")


def prepare_multiproc_dir(path: Optional[str] = None) -> None:
    """Create and empty the multiprocess directory. Run once BEFORE workers start."""
    path = path or MULTIPROC_DIR
    if not path:
        return
    os.makedirs(path, exist_ok=True)
    for entry in os.listdir(path):
        full = os.path.join(path, entry)
        if os.path.isdir(full) and not os.path.islink(full):
            shutil.rmtree(full, ignore_errors=True)
        else:
            try:
                os.remove(full)
            except FileNotFoundError:
                pass


def render_metrics() -> Tuple[bytes, str]:
    """Prometheus text exposition for /metrics (aggregated across workers when multiprocess)."""
    if MULTIPROC_DIR:
        reap_dead_workers(MULTIPROC_DIR)
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry, path=MULTIPROC_DIR)
        return generate_latest(registry), METRICS_CONTENT_TYPE
    return generate_latest(REGISTRY), METRICS_CONTENT_TYPE
