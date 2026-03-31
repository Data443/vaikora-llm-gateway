"""Constraint-mode request transform tests."""

from __future__ import annotations

from unittest.mock import Mock

from gateway.services.proxy_service import ProxyHandler


def _build_handler() -> ProxyHandler:
    policy_engine = Mock()
    policy_engine.cyren_client = Mock(get_circuit_breaker_state=Mock(return_value="closed"))
    policy_engine.audit_logger = Mock(connected=False)
    return ProxyHandler(policy_engine=policy_engine)


def test_apply_constraints_clamps_generation_and_redacts_detected_matches() -> None:
    handler = _build_handler()
    request_body = {
        "model": "gpt-4o-mini",
        "max_tokens": 1024,
        "temperature": 0.9,
        "messages": [
            {
                "role": "user",
                "content": "Please send password and token details.",
            }
        ],
    }
    content_security = {
        "detected": [
            {"type": "PII", "match": "password"},
            {"type": "PII", "match": "token"},
        ]
    }

    constrained = handler._apply_constraints_to_request(request_body, content_security)

    assert isinstance(constrained, dict)
    assert constrained["max_tokens"] == 256
    assert constrained["temperature"] == 0.2
    assert constrained["messages"][0]["role"] == "system"
    assert "Gateway constraint mode" in constrained["messages"][0]["content"]
    assert "[REDACTED]" in constrained["messages"][1]["content"]

    # Ensure original payload remains unchanged.
    assert request_body["messages"][0]["content"] == "Please send password and token details."


def test_apply_constraints_does_not_duplicate_constraint_system_prompt() -> None:
    handler = _build_handler()
    constraint_prompt = handler._CONSTRAIN_SYSTEM_PROMPT
    request_body = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": constraint_prompt},
            {"role": "user", "content": "hello"},
        ],
    }

    constrained = handler._apply_constraints_to_request(request_body, content_security={})

    assert isinstance(constrained, dict)
    prompt_count = sum(
        1
        for item in constrained["messages"]
        if isinstance(item, dict)
        and str(item.get("role", "")).lower() == "system"
        and constraint_prompt in str(item.get("content", ""))
    )
    assert prompt_count == 1


def test_apply_constraints_returns_non_dict_payload_unchanged() -> None:
    handler = _build_handler()

    assert handler._apply_constraints_to_request(None, content_security={}) is None
