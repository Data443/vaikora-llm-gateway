"""Audit payload redaction/masking regression tests."""

from __future__ import annotations

import pytest

from gateway.core.config import settings
from gateway.integrations.audit import AuditLogger


@pytest.mark.parametrize(
    "mask_sensitive,redact_messages,max_len",
    [
        (True, True, 10),
        (True, False, 10),
    ],
)
def test_sanitize_payload_masks_sensitive_and_respects_content_flags(
    monkeypatch: pytest.MonkeyPatch,
    mask_sensitive: bool,
    redact_messages: bool,
    max_len: int,
) -> None:
    monkeypatch.setattr(settings, "audit_mask_sensitive_fields", mask_sensitive)
    monkeypatch.setattr(settings, "audit_redact_message_content", redact_messages)
    monkeypatch.setattr(settings, "audit_max_string_length", max_len)

    logger = AuditLogger()
    payload = {
        "authorization": "Bearer abc123",
        "messages": [{"role": "user", "content": "sensitive user content"}],
        "nested": {
            "api_key": "secret-key",
            "prompt": "exfiltrate this data",
            "notes": "1234567890ABCDEFGHIJ",
        },
    }

    sanitized = logger._sanitize_payload(payload)

    assert sanitized["authorization"] == "***REDACTED***"
    assert sanitized["nested"]["api_key"] == "***REDACTED***"

    if redact_messages:
        assert sanitized["messages"][0]["content"] == "[REDACTED]"
        assert sanitized["nested"]["prompt"] == "[REDACTED]"
    else:
        assert sanitized["messages"][0]["content"] == "sensitive ...<truncated>"
        assert sanitized["nested"]["prompt"] == "exfiltrate...<truncated>"

    assert sanitized["nested"]["notes"] == "1234567890...<truncated>"


def test_sanitize_payload_no_truncation_when_limit_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "audit_mask_sensitive_fields", False)
    monkeypatch.setattr(settings, "audit_redact_message_content", False)
    monkeypatch.setattr(settings, "audit_max_string_length", 0)

    logger = AuditLogger()
    text = "abcdefghijklmnopqrstuvwxyz"
    payload = {"notes": text, "prompt": "keep full prompt"}

    sanitized = logger._sanitize_payload(payload)

    assert sanitized["notes"] == text
    assert sanitized["prompt"] == "keep full prompt"


def test_sanitize_payload_masks_fragmented_sensitive_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "audit_mask_sensitive_fields", True)
    monkeypatch.setattr(settings, "audit_redact_message_content", False)
    monkeypatch.setattr(settings, "audit_max_string_length", 500)

    logger = AuditLogger()
    payload = {
        "db_password_hash": "abc",
        "refresh_token_value": "xyz",
        "normal_field": "ok",
    }

    sanitized = logger._sanitize_payload(payload)

    assert sanitized["db_password_hash"] == "***REDACTED***"
    assert sanitized["refresh_token_value"] == "***REDACTED***"
    assert sanitized["normal_field"] == "ok"

