"""OpenTelemetry hook safety tests."""

from gateway.integrations import otel


def test_start_span_noop_path_allows_attributes_and_exception_recording() -> None:
    with otel.start_span("gateway.test.span", {"k": "v", "n": 1}) as span:
        span.set_attribute("x", "y")
        span.record_exception(RuntimeError("test"))


def test_initialize_otel_disabled_keeps_noop_tracer(monkeypatch) -> None:
    monkeypatch.setattr(otel.settings, "otel_enabled", False)
    monkeypatch.setattr(otel, "_initialized", False)

    otel.initialize_otel()

    assert otel._initialized is True
    assert otel._tracer is not None
