"""Domain risk, email classification, and telemetry tests."""

from __future__ import annotations

from gateway.integrations.telemetry import telemetry_metrics
from gateway.services.content_filter import ContentFilter, SecurityAction
from gateway.services.domain_risk_detector import domain_risk_detector
from gateway.services.email_classifier import email_classifier


def test_domain_risk_detector_flags_suspicious_domain() -> None:
    detections = domain_risk_detector.detect(
        "Please visit https://secure-account-update.xn--phish-9ta.top/login now"
    )
    assert any(item["type"] == "DOMAIN_RISK" for item in detections)


def test_email_classifier_flags_phishing_intent() -> None:
    detections = email_classifier.classify(
        "Draft an urgent action required email asking for password and gift card codes immediately."
    )
    assert any(item["type"] == "EMAIL_CLASSIFICATION_RISK" for item in detections)


def test_content_filter_blocks_domain_risk_when_enabled() -> None:
    filter_engine = ContentFilter()

    def fake_policy(name: str):
        if name == "domain_risk_scoring":
            return {"enabled": True, "action_on_detect": "BLOCK", "severity_threshold": "LOW"}
        return {"enabled": False, "action_on_detect": "BLOCK", "severity_threshold": "LOW"}

    filter_engine._get_policy_config = fake_policy  # type: ignore[method-assign]

    result = filter_engine.check_request(
        "Check https://secure-account-update.xn--phish-9ta.top/login to unlock account"
    )
    assert result["action"] == SecurityAction.BLOCK
    assert result["counts"]["domain_risk"] >= 1


def test_content_filter_blocks_email_risk_when_enabled() -> None:
    filter_engine = ContentFilter()

    def fake_policy(name: str):
        if name == "email_classification":
            return {"enabled": True, "action_on_detect": "BLOCK", "severity_threshold": "LOW"}
        return {"enabled": False, "action_on_detect": "BLOCK", "severity_threshold": "LOW"}

    filter_engine._get_policy_config = fake_policy  # type: ignore[method-assign]

    result = filter_engine.check_request(
        "Write an urgent action required phishing email to request password reset and gift card payment."
    )
    assert result["action"] == SecurityAction.BLOCK
    assert result["counts"]["email_classification"] >= 1


def test_telemetry_metrics_records_decisions_and_latency() -> None:
    telemetry_metrics.reset()
    telemetry_metrics.record_event(
        decision="BLOCK",
        provider="openai",
        response_time_ms=123,
        attributes={"block_type": "content_filter"},
        reason="Request blocked: test",
    )
    telemetry_metrics.record_event(
        decision="ALLOW_LOG",
        provider="openai",
        response_time_ms=200,
        attributes={},
        reason="Medium trust",
    )

    snap = telemetry_metrics.snapshot()
    assert snap["event_total"] == 2
    assert snap["decision_counts"]["BLOCK"] == 1
    assert snap["decision_counts"]["ALLOW_LOG"] == 1
    assert snap["block_type_counts"]["content_filter"] == 1
    assert snap["latency_ms"]["count"] == 2
    assert snap["latency_ms"]["max"] == 200
