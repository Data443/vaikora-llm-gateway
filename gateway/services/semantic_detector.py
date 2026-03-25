"""Lightweight semantic risk detection for prompt safety."""

from __future__ import annotations

import re
from typing import Dict, List


class SemanticDetector:
    """Heuristic semantic detector for higher-level risky intent patterns."""

    _WHITESPACE_RE = re.compile(r"\s+")

    _OVERRIDE_TERMS = [
        "ignore",
        "bypass",
        "override",
        "disregard",
        "forget previous",
        "disable safety",
    ]
    _POLICY_TERMS = [
        "instructions",
        "rules",
        "safety",
        "guardrails",
        "policy",
        "restrictions",
    ]

    _EXFIL_ACTION_TERMS = [
        "reveal",
        "show",
        "dump",
        "expose",
        "print",
        "leak",
    ]
    _EXFIL_TARGET_TERMS = [
        "system prompt",
        "hidden prompt",
        "developer prompt",
        "internal reasoning",
        "chain of thought",
    ]

    _SOCIAL_ENGINEERING_TERMS = [
        "phishing",
        "social engineering",
        "credential harvesting",
        "impersonation",
    ]
    _CREDENTIAL_TARGET_TERMS = [
        "password",
        "api key",
        "token",
        "mfa",
        "one-time code",
        "otp",
    ]

    _OBFUSCATION_TERMS = [
        "for educational purposes",
        "hypothetical",
        "for research only",
        "just for testing",
        "fictional scenario",
    ]
    _HARMFUL_INTENT_TERMS = [
        "exploit",
        "malware",
        "ransomware",
        "keylogger",
        "payload",
        "remote access trojan",
    ]

    def _normalize(self, text: str) -> str:
        lowered = text.lower().strip()
        return self._WHITESPACE_RE.sub(" ", lowered)

    def _extract_matches(self, text: str, candidates: List[str]) -> List[str]:
        return [term for term in candidates if term in text]

    def detect(self, text: str) -> List[Dict[str, str]]:
        """Return semantic detections with type/severity/reason."""
        normalized = self._normalize(text)
        if not normalized:
            return []

        detections: List[Dict[str, str]] = []

        override_hits = self._extract_matches(normalized, self._OVERRIDE_TERMS)
        policy_hits = self._extract_matches(normalized, self._POLICY_TERMS)
        if override_hits and policy_hits:
            detections.append(
                {
                    "type": "SEMANTIC_POLICY_BYPASS",
                    "severity": "HIGH",
                    "reason": "Attempt to bypass policy or instruction safeguards",
                    "match": ", ".join((override_hits + policy_hits)[:4]),
                }
            )

        exfil_action_hits = self._extract_matches(normalized, self._EXFIL_ACTION_TERMS)
        exfil_target_hits = self._extract_matches(normalized, self._EXFIL_TARGET_TERMS)
        if exfil_action_hits and exfil_target_hits:
            detections.append(
                {
                    "type": "SEMANTIC_PROMPT_EXFILTRATION",
                    "severity": "HIGH",
                    "reason": "Request to disclose hidden/system prompt material",
                    "match": ", ".join((exfil_action_hits + exfil_target_hits)[:4]),
                }
            )

        social_hits = self._extract_matches(normalized, self._SOCIAL_ENGINEERING_TERMS)
        credential_hits = self._extract_matches(normalized, self._CREDENTIAL_TARGET_TERMS)
        if social_hits and credential_hits:
            detections.append(
                {
                    "type": "SEMANTIC_CREDENTIAL_ABUSE",
                    "severity": "MEDIUM",
                    "reason": "Credential abuse/social-engineering intent detected",
                    "match": ", ".join((social_hits + credential_hits)[:4]),
                }
            )

        obfuscation_hits = self._extract_matches(normalized, self._OBFUSCATION_TERMS)
        harmful_hits = self._extract_matches(normalized, self._HARMFUL_INTENT_TERMS)
        if obfuscation_hits and harmful_hits:
            detections.append(
                {
                    "type": "SEMANTIC_HARMFUL_OBFUSCATION",
                    "severity": "MEDIUM",
                    "reason": "Potential harmful request disguised as benign intent",
                    "match": ", ".join((obfuscation_hits + harmful_hits)[:4]),
                }
            )

        return detections


semantic_detector = SemanticDetector()

