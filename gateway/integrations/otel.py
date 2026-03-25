"""Optional OpenTelemetry hooks for gateway tracing.

This module is safe when OTel dependencies are absent or disabled.
"""

from __future__ import annotations

import importlib
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from loguru import logger

from gateway.core.config import settings


class _NoopSpan:
    def set_attribute(self, key: str, value: Any) -> None:  # pragma: no cover - noop helper
        return

    def record_exception(self, exc: BaseException) -> None:  # pragma: no cover - noop helper
        return


class _NoopTracer:
    @contextmanager
    def start_as_current_span(self, _name: str) -> Iterator[_NoopSpan]:
        yield _NoopSpan()


_tracer: Any = _NoopTracer()
_tracer_provider: Any = None
_initialized = False


@contextmanager
def start_span(name: str, attributes: Optional[Dict[str, Any]] = None) -> Iterator[Any]:
    """Create a tracing span when OTel is enabled; otherwise use a no-op span."""
    with _tracer.start_as_current_span(name) as span:
        if attributes:
            for key, value in attributes.items():
                if value is None:
                    continue
                try:
                    span.set_attribute(key, value)
                except Exception:
                    # Attribute errors should never break request handling.
                    continue
        yield span


def initialize_otel() -> None:
    """Initialize OTel tracer provider when configured."""
    global _initialized, _tracer, _tracer_provider

    if _initialized:
        return
    _initialized = True

    if not settings.otel_enabled:
        logger.info("OpenTelemetry disabled")
        return

    try:
        trace = importlib.import_module("opentelemetry.trace")
        OTLPSpanExporter = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter"
        ).OTLPSpanExporter
        Resource = importlib.import_module("opentelemetry.sdk.resources").Resource
        TracerProvider = importlib.import_module("opentelemetry.sdk.trace").TracerProvider
        BatchSpanProcessor = importlib.import_module(
            "opentelemetry.sdk.trace.export"
        ).BatchSpanProcessor
    except Exception as exc:  # pragma: no cover - dependency edge
        logger.warning(f"OpenTelemetry requested but not available: {exc}")
        return

    resource = Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.version": "1.0.0",
        }
    )
    provider = TracerProvider(resource=resource)

    if settings.otel_exporter_otlp_endpoint:
        exporter = OTLPSpanExporter(
            endpoint=settings.otel_exporter_otlp_endpoint,
            timeout=settings.otel_exporter_timeout_seconds,
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
        logger.info(
            "OpenTelemetry initialized with OTLP HTTP exporter "
            f"({settings.otel_exporter_otlp_endpoint})"
        )
    else:
        logger.info("OpenTelemetry enabled without exporter endpoint; traces remain in-process")

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(settings.otel_service_name)
    _tracer_provider = provider


def shutdown_otel() -> None:
    """Flush and shutdown OTel provider on process exit."""
    global _tracer_provider
    if _tracer_provider is None:
        return

    try:
        _tracer_provider.shutdown()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"OpenTelemetry shutdown error: {exc}")


