"""Lightweight semantic risk detection for prompt safety."""

from __future__ import annotations

import re
from typing import Dict, List


class SemanticDetector:
    """Heuristic semantic detector for higher-level risky intent patterns."""

    _WHITESPACE_RE = re.compile(r"\s+")
    _SPACED_CHARS_RE = re.compile(r"(?<=\w)\s(?=\w(?:\s\w)*$)")

    _OVERRIDE_TERMS = [
        "ignore",
        "bypass",
        "override",
        "disregard",
        "forget previous",
        "disable safety",
        "do not apply",
        "skip",
        "turn off",
        "deactivate",
    ]
    _POLICY_TERMS = [
        "instructions",
        "rules",
        "safety",
        "guardrails",
        "policy",
        "restrictions",
        "filters",
        "checks",
        "policy checks",
        "content filter",
    ]

    _EXFIL_ACTION_TERMS = [
        "reveal",
        "show",
        "dump",
        "expose",
        "print",
        "leak",
        "exfiltrate",
        "steal",
        "output",
        "display",
        "list",
        "return",
    ]
    _EXFIL_TARGET_TERMS = [
        "system prompt",
        "hidden prompt",
        "developer prompt",
        "internal reasoning",
        "chain of thought",
        "master prompt",
        "secret prompt",
        "prompt stack",
        "internal config",
        "internal configuration",
        "environment variable",
        "env variable",
        "api key",
        "api keys",
        "internal secret",
        "secrets",
        "config and secrets",
    ]

    _UNRESTRICTED_MODE_TERMS = [
        "developer mode",
        "developer-debug mode",
        "debug mode",
        "unrestricted mode",
        "unrestricted model",
        "no filter",
        "no filters",
        "without any policy",
        "without policy",
        "without safety",
        "without restrictions",
        "without any filter",
        "unfiltered mode",
        "god mode",
        "sudo mode",
        "admin mode",
        "jailbreak mode",
    ]

    _PENTEST_SOCIAL_ENGINEERING_TERMS = [
        "authorized pentest",
        "authorized penetration",
        "security test",
        "red team",
        "assume i am authorized",
        "treat this as authorized",
        "i have permission",
        "confirm you will not follow",
    ]

    _ROLEPLAY_BYPASS_TERMS = [
        "roleplay as unrestricted",
        "pretend you have no",
        "act as if no safety",
        "act as unrestricted",
        "you are now in",
        "you are now an unrestricted",
        "pretend to be an ai without",
        "simulate a model without",
        "content without any policy",
    ]

    _SENSITIVE_DATA_ACTION_TERMS = [
        "list all",
        "show all",
        "dump all",
        "print all",
        "return all",
        "give me all",
        "provide all",
        "output all",
        "export all",
        "list every",
        "show every",
        "output every",
        "print every",
    ]
    _SENSITIVE_DATA_TARGET_TERMS = [
        "customer record",
        "customer records",
        "user record",
        "user records",
        "employee record",
        "employee records",
        "passwords",
        "password",
        "recovery token",
        "recovery tokens",
        "private key",
        "private keys",
        "environment variable",
        "environment variables",
        "database record",
        "database records",
        "credit card",
        "credit cards",
        "ssn",
        "social security",
    ]

    _SOCIAL_ENGINEERING_TERMS = [
        "phishing",
        "spear-phishing",
        "social engineering",
        "social-engineering",
        "credential harvesting",
        "impersonation",
        "fake it support",
        "it support message",
    ]
    _CREDENTIAL_TARGET_TERMS = [
        "password",
        "passwords",
        "credentials",
        "credential",
        "api key",
        "token",
        "mfa",
        "one-time code",
        "otp",
        "login",
        "account",
    ]
    _ABUSE_ACTION_TERMS = [
        "steal",
        "scrape",
        "scraping",
        "scrapping",
        "harvest",
        "collect",
        "bypass",
        "brute force",
        "account takeover",
        "take over",
    ]
    _SCALING_ABUSE_TERMS = [
        "billions",
        "million",
        "mass",
        "bulk",
        "automated",
        "bot",
        "botnet",
        "unlimited",
        "free accounts",
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

    _ENCODING_BYPASS_TERMS = [
        "base64-decode",
        "base64 decode",
        "decode and follow",
        "decode and execute",
        "rot13",
        "hex decode",
        "decode this instruction",
        "translate exactly",
        "translate and do not apply",
    ]

    def _normalize(self, text: str) -> str:
        lowered = text.lower().strip()
        return self._WHITESPACE_RE.sub(" ", lowered)

    def _despaced(self, text: str) -> str:
        """Collapse single-space-separated single chars (e.g. 'r u l e s' -> 'rules')."""
        parts = text.split()
        result: list[str] = []
        run: list[str] = []
        for part in parts:
            if len(part) == 1 and part.isalpha():
                run.append(part)
            else:
                if len(run) > 2:
                    result.append("".join(run))
                else:
                    result.extend(run)
                run = []
                result.append(part)
        if len(run) > 2:
            result.append("".join(run))
        else:
            result.extend(run)
        return " ".join(result)

    def _extract_matches(self, text: str, candidates: List[str]) -> List[str]:
        return [term for term in candidates if term in text]

    def detect(self, text: str) -> List[Dict[str, str]]:
        """Return semantic detections with type/severity/reason."""
        normalized = self._normalize(text)
        if not normalized:
            return []

        despaced = self._despaced(normalized)
        check_text = despaced if despaced != normalized else normalized

        detections: List[Dict[str, str]] = []

        override_hits = self._extract_matches(check_text, self._OVERRIDE_TERMS)
        policy_hits = self._extract_matches(check_text, self._POLICY_TERMS)
        if override_hits and policy_hits:
            detections.append(
                {
                    "type": "SEMANTIC_POLICY_BYPASS",
                    "severity": "HIGH",
                    "reason": "Attempt to bypass policy or instruction safeguards",
                    "match": ", ".join((override_hits + policy_hits)[:4]),
                }
            )

        exfil_action_hits = self._extract_matches(check_text, self._EXFIL_ACTION_TERMS)
        exfil_target_hits = self._extract_matches(check_text, self._EXFIL_TARGET_TERMS)
        if exfil_action_hits and exfil_target_hits:
            detections.append(
                {
                    "type": "SEMANTIC_PROMPT_EXFILTRATION",
                    "severity": "HIGH",
                    "reason": "Request to disclose hidden/system prompt material",
                    "match": ", ".join((exfil_action_hits + exfil_target_hits)[:4]),
                }
            )

        unrestricted_hits = self._extract_matches(check_text, self._UNRESTRICTED_MODE_TERMS)
        if unrestricted_hits:
            detections.append(
                {
                    "type": "SEMANTIC_UNRESTRICTED_MODE",
                    "severity": "HIGH",
                    "reason": "Attempt to switch model to unrestricted/debug mode",
                    "match": ", ".join(unrestricted_hits[:3]),
                }
            )

        roleplay_hits = self._extract_matches(check_text, self._ROLEPLAY_BYPASS_TERMS)
        if roleplay_hits:
            detections.append(
                {
                    "type": "SEMANTIC_ROLEPLAY_BYPASS",
                    "severity": "HIGH",
                    "reason": "Roleplay-based attempt to bypass safety controls",
                    "match": ", ".join(roleplay_hits[:3]),
                }
            )

        pentest_hits = self._extract_matches(check_text, self._PENTEST_SOCIAL_ENGINEERING_TERMS)
        if pentest_hits:
            detections.append(
                {
                    "type": "SEMANTIC_PENTEST_SOCIAL_ENGINEERING",
                    "severity": "HIGH",
                    "reason": "Social engineering via false authorization claim",
                    "match": ", ".join(pentest_hits[:3]),
                }
            )

        sensitive_action_hits = self._extract_matches(check_text, self._SENSITIVE_DATA_ACTION_TERMS)
        sensitive_target_hits = self._extract_matches(check_text, self._SENSITIVE_DATA_TARGET_TERMS)
        if sensitive_action_hits and sensitive_target_hits:
            detections.append(
                {
                    "type": "SEMANTIC_SENSITIVE_DATA_REQUEST",
                    "severity": "HIGH",
                    "reason": "Bulk request for sensitive/protected data",
                    "match": ", ".join((sensitive_action_hits + sensitive_target_hits)[:4]),
                }
            )

        encoding_hits = self._extract_matches(check_text, self._ENCODING_BYPASS_TERMS)
        if encoding_hits:
            detections.append(
                {
                    "type": "SEMANTIC_ENCODING_BYPASS",
                    "severity": "HIGH",
                    "reason": "Attempt to bypass filters via encoding/translation",
                    "match": ", ".join(encoding_hits[:3]),
                }
            )

        social_hits = self._extract_matches(check_text, self._SOCIAL_ENGINEERING_TERMS)
        credential_hits = self._extract_matches(check_text, self._CREDENTIAL_TARGET_TERMS)
        if social_hits and credential_hits:
            detections.append(
                {
                    "type": "SEMANTIC_CREDENTIAL_ABUSE",
                    "severity": "MEDIUM",
                    "reason": "Credential abuse/social-engineering intent detected",
                    "match": ", ".join((social_hits + credential_hits)[:4]),
                }
            )

        abuse_action_hits = self._extract_matches(check_text, self._ABUSE_ACTION_TERMS)
        if abuse_action_hits and credential_hits:
            detections.append(
                {
                    "type": "SEMANTIC_ACCOUNT_ABUSE",
                    "severity": "MEDIUM",
                    "reason": "Potential credential or account abuse intent detected",
                    "match": ", ".join((abuse_action_hits + credential_hits)[:4]),
                }
            )

        scaling_hits = self._extract_matches(check_text, self._SCALING_ABUSE_TERMS)
        if scaling_hits and (credential_hits or abuse_action_hits):
            detections.append(
                {
                    "type": "SEMANTIC_MASS_ACCOUNT_ABUSE",
                    "severity": "HIGH",
                    "reason": "Potential large-scale account abuse or credential misuse intent",
                    "match": ", ".join((scaling_hits + credential_hits + abuse_action_hits)[:4]),
                }
            )

        obfuscation_hits = self._extract_matches(check_text, self._OBFUSCATION_TERMS)
        harmful_hits = self._extract_matches(check_text, self._HARMFUL_INTENT_TERMS)
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
