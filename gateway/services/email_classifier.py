"""Deterministic email-risk classification (CTAS-ready local baseline)."""

from __future__ import annotations

from typing import Dict, List


class EmailClassifier:
    """Heuristic email classification focused on phishing-like intent."""

    _URGENCY_TERMS = {
        "urgent", "immediately", "asap", "action required", "final notice", "within 24 hours"
    }
    _CREDENTIAL_TERMS = {
        "verify your account", "password", "login", "mfa", "otp", "one-time code", "security code"
    }
    _PAYMENT_TERMS = {
        "wire transfer", "gift card", "bank details", "invoice payment", "crypto transfer"
    }
    _IMPERSONATION_TERMS = {
        "impersonate", "spoof", "from ceo", "from finance", "from it support", "pretend to be"
    }

    def _hits(self, text: str, terms: set[str]) -> List[str]:
        return [term for term in terms if term in text]

    def classify(self, text: str) -> List[Dict[str, object]]:
        """Classify risky email intent from free-form text."""
        normalized = (text or "").lower()
        if not normalized:
            return []

        urgency_hits = self._hits(normalized, self._URGENCY_TERMS)
        credential_hits = self._hits(normalized, self._CREDENTIAL_TERMS)
        payment_hits = self._hits(normalized, self._PAYMENT_TERMS)
        impersonation_hits = self._hits(normalized, self._IMPERSONATION_TERMS)

        score = 0
        score += min(len(urgency_hits), 3) * 10
        score += min(len(credential_hits), 3) * 15
        score += min(len(payment_hits), 3) * 20
        score += min(len(impersonation_hits), 3) * 15

        if urgency_hits and (credential_hits or payment_hits):
            score += 20
        if impersonation_hits and (credential_hits or payment_hits):
            score += 15

        if score < 40:
            return []

        if score >= 70:
            classification = "PHISHING"
            severity = "HIGH"
        else:
            classification = "SUSPICIOUS"
            severity = "MEDIUM"

        hits = (urgency_hits + credential_hits + payment_hits + impersonation_hits)[:6]
        return [
            {
                "type": "EMAIL_CLASSIFICATION_RISK",
                "severity": severity,
                "classification": classification,
                "risk_score": min(score, 100),
                "match": ", ".join(hits),
            }
        ]


email_classifier = EmailClassifier()

