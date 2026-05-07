"""Deterministic domain risk scoring for request payload inspection."""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


class DomainRiskDetector:
    """Heuristic domain-risk detector (entitlement/policy gated)."""

    _URL_RE = re.compile(
        r"(?i)\b((?:https?://|www\.)[^\s<>'\"]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>'\"]*)?)\b"
    )

    _HIGH_RISK_TLDS = {
        "zip", "mov", "top", "click", "gq", "tk", "work", "link", "country", "icu"
    }
    _SUSPICIOUS_TERMS = {
        "login", "verify", "secure", "update", "account", "wallet", "password", "reset"
    }

    def _extract_domain(self, candidate: str) -> Optional[tuple[str, str]]:
        value = candidate.strip().strip(".,;:!?)]}")
        if not value:
            return None

        target = value
        if not value.lower().startswith(("http://", "https://")):
            target = f"http://{value}"

        parsed = urlparse(target)
        domain = parsed.netloc.lower().strip()
        path = parsed.path.lower().strip()
        if not domain:
            return None
        if domain.startswith("www."):
            domain = domain[4:]
        return domain, path

    def _score_domain(self, domain: str, path: str, raw: str) -> tuple[int, List[str]]:
        score = 0
        signals: List[str] = []

        if domain.startswith("xn--"):
            score += 45
            signals.append("punycode_domain")

        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in self._HIGH_RISK_TLDS:
            score += 30
            signals.append(f"high_risk_tld:{tld}")

        if "@" in raw:
            score += 40
            signals.append("embedded_at_symbol")

        suspicious_in_domain = [term for term in self._SUSPICIOUS_TERMS if term in domain]
        suspicious_in_path = [term for term in self._SUSPICIOUS_TERMS if term in path]
        if suspicious_in_domain:
            score += 15
            signals.append("domain_keyword:" + ",".join(sorted(suspicious_in_domain)[:2]))
        if suspicious_in_path:
            score += 15
            signals.append("path_keyword:" + ",".join(sorted(suspicious_in_path)[:2]))

        if "-" in domain and any(ch.isdigit() for ch in domain):
            score += 10
            signals.append("hyphen_digit_pattern")

        return min(score, 100), signals

    def detect(self, text: str) -> List[Dict[str, object]]:
        """Detect risky domains/URLs and return structured findings."""
        detections: List[Dict[str, object]] = []

        for raw in self._URL_RE.findall(text or ""):
            extracted = self._extract_domain(raw)
            if not extracted:
                continue

            domain, path = extracted
            score, signals = self._score_domain(domain, path, raw)
            if score < 40:
                continue

            severity = "HIGH" if score >= 70 else "MEDIUM"
            detections.append(
                {
                    "type": "DOMAIN_RISK",
                    "severity": severity,
                    "domain": domain,
                    "risk_score": score,
                    "signals": signals,
                    "match": raw,
                }
            )

        return detections


domain_risk_detector = DomainRiskDetector()

