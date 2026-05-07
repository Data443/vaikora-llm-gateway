"""
Data443 LLM Gateway - Content Security Layer

Detects PII (Personally Identifiable Information) and malicious prompt patterns.
Includes PII pattern detection and known malicious prompt blocking.
"""

import json
import re
from typing import List, Optional, Dict, Any
from enum import Enum
from loguru import logger

from gateway.core.config import settings
from gateway.api.admin import get_policy
from gateway.policy.store import policy_store
from gateway.services.semantic_detector import semantic_detector
from gateway.services.domain_risk_detector import domain_risk_detector
from gateway.services.email_classifier import email_classifier


class SecurityAction(str, Enum):
    """Security actions for detected content."""
    BLOCK = "BLOCK"
    CONSTRAIN = "CONSTRAIN"
    LOG_ONLY = "LOG_ONLY"
    PASS = "PASS"


class ContentFilter:
    """Content security filter for PII and malicious patterns."""

    _SEVERITY_RANK = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    # PII Patterns (compiled regex for performance)
    _SSN_PATTERN = re.compile(
        r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',  # 123-45-6789
        flags=re.IGNORECASE
    )
    _SSN_PATTERN_HYPHENS = re.compile(
        r'\b\d{3}-\d{2}-\d{4}\b',  # 123-45-6789
        flags=re.IGNORECASE
    )

    _EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        flags=re.IGNORECASE
    )

    _PHONE_PATTERN_US = re.compile(
        r'\b(?:\+1[-.\s]?)?(?:\(?[2-9]\d{2}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b',
        flags=re.IGNORECASE
    )
    _PHONE_PATTERN_INTL = re.compile(
        r'(?<!\w)\+(?:\d[-.\s]?){8,15}\d(?!\w)',
        flags=re.IGNORECASE
    )

    _CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:\d[ -]*?){13,19}\b',
        flags=re.IGNORECASE
    )

    _IP_ADDRESS_PATTERN = re.compile(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        flags=re.IGNORECASE
    )

    _PASSPORT_PATTERN = re.compile(
        r'\b[A-Za-z]{1,2}[0-9]{7,8}\b',
        flags=re.IGNORECASE
    )

    _BANK_ACCOUNT_PATTERN = re.compile(
        r'(?i)\b(?:account|acct|iban)\s*(?:number|no\.?|#)?\s*[:\-]?\s*([A-Z0-9]{8,34})\b',
        flags=re.IGNORECASE
    )

    # Malicious Prompt Patterns (simplified to avoid regex errors)
    _JAILBREAK_PATTERNS = [
        r'ignore\s+(your\s+)?(previous|earlier|above|past)\s+(instructions?|commands?|directives?|constraints?|rules?|limitations?|orders?)',
        r'disregard\s+(your\s+)?(previous|earlier|above|past)\s+(instructions?|commands?|directives?|constraints?|rules?|limitations?|orders?)',
        r'forget\s+(your\s+)?(previous|earlier|above|past)\s+(instructions?|commands?|directives?|constraints?|rules?|limitations?|orders?)',
        r'act\s+as\s+(persona|character|role|identity|behavior)',
        r'behave\s+like\s+(persona|character|role|identity|behavior)',
        r'pretend\s+to\s+(persona|character|role|identity|behavior)',
        r'roleplay\s+as\s+(persona|character|role|identity|behavior)',
        r'impersonate\s+(persona|character|role|identity|behavior)',
        r'reveal\s+your\s+(system\s+prompt|initial\s+prompt|instructions|reasoning)',
        r'show\s+your\s+(system\s+prompt|initial\s+prompt|instructions|reasoning)',
        r'bypass\s+(restrictions?|limitations?|filters?|controls?|rules?|safety)',
        r'override\s+(restrictions?|limitations?|filters?|controls?|rules?|safety)',
    ]

    _INJECTION_PATTERNS = [
        r'system:\s+.*',
        r'assistant:\s+.*',
    ]

    def __init__(self):
        self.config = settings
        # Compile all jailbreak patterns
        self._jailbreak_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self._JAILBREAK_PATTERNS
        ]
        self._injection_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self._INJECTION_PATTERNS
        ]

    def _extract_text(self, content: Any) -> str:
        """Extract text from common request/response payload shapes."""
        if content is None:
            return ""

        if isinstance(content, bytes):
            return content.decode("utf-8", errors="ignore")

        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts = [self._extract_text(item) for item in content]
            return "\n".join([p for p in parts if p])

        if isinstance(content, dict):
            parts = []

            # Common request fields
            for key in ("prompt", "input", "content", "text", "query"):
                if key in content:
                    parts.append(self._extract_text(content.get(key)))

            # OpenAI chat format
            messages = content.get("messages")
            if isinstance(messages, list):
                for msg in messages:
                    parts.append(self._extract_text(msg))

            # Response choices (OpenAI-style)
            choices = content.get("choices")
            if isinstance(choices, list):
                for choice in choices:
                    if isinstance(choice, dict):
                        if "message" in choice:
                            parts.append(self._extract_text(choice.get("message")))
                        if "text" in choice:
                            parts.append(self._extract_text(choice.get("text")))

            if parts:
                return "\n".join([p for p in parts if p])

            try:
                return json.dumps(content, ensure_ascii=True)
            except Exception:
                return str(content)

        return str(content)

    def _get_policy_config(self, name: str) -> Dict[str, Any]:
        """Get policy config with defaults."""
        module_map = {
            "pii_detection": "pii_detection",
            "jailbreak_detection": "jailbreak_detection",
            "injection_detection": "injection_detection",
            "semantic_detection": "semantic_detection",
            "domain_risk_scoring": "domain_risk_scoring",
            "email_classification": "email_classification",
        }
        policy = get_policy(name)
        module_name = module_map.get(name)
        entitlement_enabled = True if module_name is None else policy_store.is_module_enabled(module_name)
        return {
            "enabled": policy.get("enabled", True) and entitlement_enabled,
            "action_on_detect": str(policy.get("action_on_detect", "BLOCK")).upper(),
            "severity_threshold": str(policy.get("severity_threshold", "LOW")).upper(),
        }

    def _severity_meets_threshold(self, severity: str, threshold: str) -> bool:
        sev_rank = self._SEVERITY_RANK.get(severity.upper(), 0)
        thr_rank = self._SEVERITY_RANK.get(threshold.upper(), 1)
        return sev_rank >= thr_rank

    def _luhn_valid(self, candidate: str) -> bool:
        """Validate card candidate using Luhn checksum."""
        digits = "".join(ch for ch in candidate if ch.isdigit())
        if len(digits) < 13 or len(digits) > 19:
            return False

        total = 0
        parity = len(digits) % 2
        for idx, char in enumerate(digits):
            digit = int(char)
            if idx % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    def check_pii(self, text: str) -> List[Dict[str, Any]]:
        """
        Check text for PII patterns.

        Args:
            text: Text to analyze

        Returns:
            List of detected PII items with type and match
        """
        detections = []

        # Check SSN
        if self._SSN_PATTERN.search(text):
            detections.append({
                "type": "SSN",
                "pattern": "XXX-XX-XXXX",
                "match": self._SSN_PATTERN.search(text).group(),
                "severity": "HIGH"
            })
        elif self._SSN_PATTERN_HYPHENS.search(text):
            detections.append({
                "type": "SSN",
                "pattern": "XXX-XX-XXXX",
                "match": self._SSN_PATTERN_HYPHENS.search(text).group(),
                "severity": "HIGH"
            })

        # Check Email
        email_matches = self._EMAIL_PATTERN.findall(text)
        for match in email_matches:
            detections.append({
                "type": "EMAIL",
                "pattern": "user@example.com",
                "match": match,
                "severity": "MEDIUM"
            })

        # Check Phone (US)
        if self._PHONE_PATTERN_US.search(text):
            detections.append({
                "type": "PHONE_US",
                "pattern": "XXX-XXX-XXXX",
                "match": self._PHONE_PATTERN_US.search(text).group(),
                "severity": "MEDIUM"
            })

        # Check Phone (International)
        intl_match = self._PHONE_PATTERN_INTL.search(text)
        if intl_match:
            detections.append({
                "type": "PHONE_INTL",
                "pattern": "+XX-XXXX-XXXX",
                "match": intl_match.group(),
                "severity": "MEDIUM"
            })

        # Check Credit Card
        for match in self._CREDIT_CARD_PATTERN.findall(text):
            if not self._luhn_valid(match):
                continue
            digits = "".join(ch for ch in match if ch.isdigit())
            masked = f"{digits[:4]}-****-****-{digits[-4:]}" if len(digits) >= 8 else digits
            detections.append({
                "type": "CREDIT_CARD",
                "pattern": "XXXX-XXXX-XXXX-XXXX",
                "match": masked,
                "severity": "HIGH"
            })
            break

        # Check IP Address
        if self._IP_ADDRESS_PATTERN.search(text):
            detections.append({
                "type": "IP_ADDRESS",
                "pattern": "XXX.XXX.XXX.XXX",
                "match": self._IP_ADDRESS_PATTERN.search(text).group(),
                "severity": "MEDIUM"
            })

        # Check Passport
        if self._PASSPORT_PATTERN.search(text):
            detections.append({
                "type": "PASSPORT",
                "pattern": "US Passport",
                "match": self._PASSPORT_PATTERN.search(text).group(),
                "severity": "HIGH"
            })

        # Check Bank Account
        bank_match = self._BANK_ACCOUNT_PATTERN.search(text)
        if bank_match:
            account_value = bank_match.group(1)
            if len(account_value) < 8:
                account_value = ""
        else:
            account_value = ""
        if account_value:
            masked_account = (
                f"{account_value[:2]}{'*' * max(2, len(account_value) - 4)}{account_value[-2:]}"
            )
            detections.append({
                "type": "BANK_ACCOUNT",
                "pattern": "US Bank Account",
                "match": masked_account,
                "severity": "HIGH"
            })

        if detections:
            logger.warning(f"PII detected: {[d['type'] for d in detections]}")

        return detections

    def check_jailbreak_attempts(self, text: str) -> List[Dict[str, Any]]:
        """
        Check for jailbreak attempt patterns.

        Args:
            text: Text to analyze

        Returns:
            List of detected jailbreak attempts
        """
        detections = []

        for pattern in self._jailbreak_patterns:
            if pattern.search(text):
                detections.append({
                    "type": "JAILBREAK_ATTEMPT",
                    "match": pattern.search(text).group(),
                    "severity": "HIGH"
                })

        if detections:
            logger.warning(f"Jailbreak attempt detected: {len(detections)} patterns")

        return detections

    def check_injection_attempts(self, text: str) -> List[Dict[str, Any]]:
        """
        Check for injection attack patterns.

        Args:
            text: Text to analyze

        Returns:
            List of detected injection attempts
        """
        detections = []

        for pattern in self._injection_patterns:
            if pattern.search(text):
                detections.append({
                    "type": "INJECTION_ATTEMPT",
                    "match": pattern.search(text).group(),
                    "severity": "HIGH"
                })

        if detections:
            logger.warning(f"Injection attempt detected: {len(detections)} patterns")

        return detections

    def check_domain_risk(self, text: str) -> List[Dict[str, Any]]:
        """Check text for risky domains/URLs."""
        detections = domain_risk_detector.detect(text)
        if detections:
            logger.warning(f"Domain-risk detections: {len(detections)}")
        return detections

    def check_email_classification(self, text: str) -> List[Dict[str, Any]]:
        """Classify phishing-like email intent in prompt text."""
        detections = email_classifier.classify(text)
        if detections:
            logger.warning(f"Email-classification detections: {len(detections)}")
        return detections

    def check_request(self, content: Optional[Any] = None) -> Dict[str, Any]:
        """
        Check request content for security issues.

        Args:
            content: Request content (prompt, messages, etc.)

        Returns:
            Security analysis result
        """
        text = self._extract_text(content)

        if not text:
            return {
                "action": SecurityAction.PASS,
                "detected": [],
                "reason": "No content to analyze"
            }

        pii_policy = self._get_policy_config("pii_detection")
        jailbreak_policy = self._get_policy_config("jailbreak_detection")
        injection_policy = self._get_policy_config("injection_detection")
        semantic_policy = self._get_policy_config("semantic_detection")
        domain_policy = self._get_policy_config("domain_risk_scoring")
        email_policy = self._get_policy_config("email_classification")

        # Check for PII
        pii_detections = self.check_pii(text) if pii_policy["enabled"] else []

        # Check for jailbreak attempts
        jailbreak_detections = self.check_jailbreak_attempts(text) if jailbreak_policy["enabled"] else []

        # Check for injection attempts
        injection_detections = self.check_injection_attempts(text) if injection_policy["enabled"] else []

        # Check for semantic abuse intent
        semantic_detections = semantic_detector.detect(text) if semantic_policy["enabled"] else []

        # Check for risky domains
        domain_detections = self.check_domain_risk(text) if domain_policy["enabled"] else []

        # Check for phishing/bulk email risk intents
        email_detections = self.check_email_classification(text) if email_policy["enabled"] else []

        # Combine all detections
        all_detections = (
            pii_detections
            + jailbreak_detections
            + injection_detections
            + semantic_detections
            + domain_detections
            + email_detections
        )

        if not all_detections:
            return {
                "action": SecurityAction.PASS,
                "detected": [],
                "reason": "No security issues detected"
            }

        # Determine actions based on policies
        actions = []
        for detection in all_detections:
            if detection["type"] == "JAILBREAK_ATTEMPT":
                policy = jailbreak_policy
            elif detection["type"] == "INJECTION_ATTEMPT":
                policy = injection_policy
            elif detection["type"].startswith("SEMANTIC_"):
                policy = semantic_policy
            elif detection["type"] == "DOMAIN_RISK":
                policy = domain_policy
            elif detection["type"] == "EMAIL_CLASSIFICATION_RISK":
                policy = email_policy
            else:
                policy = pii_policy

            if not policy["enabled"]:
                continue

            if not self._severity_meets_threshold(detection.get("severity", "LOW"), policy["severity_threshold"]):
                continue

            action = policy["action_on_detect"]
            if action not in SecurityAction._value2member_map_:
                action = "BLOCK"
            actions.append(action)

        # Count detections
        pii_count = len(pii_detections)
        jailbreak_count = len(jailbreak_detections)
        injection_count = len(injection_detections)
        semantic_count = len(semantic_detections)
        domain_count = len(domain_detections)
        email_count = len(email_detections)
        total_count = len(all_detections)

        # Determine action
        if not actions:
            return {
                "action": SecurityAction.PASS,
                "detected": [],
                "reason": "No security issues detected"
            }

        if "BLOCK" in actions:
            action = SecurityAction.BLOCK
            reason = (
                f"Block: {jailbreak_count} jailbreak, {injection_count} injection, "
                f"{semantic_count} semantic, {domain_count} domain, "
                f"{email_count} email, {pii_count} PII detected"
            )
        elif "CONSTRAIN" in actions:
            action = SecurityAction.CONSTRAIN
            reason = f"Constrain: {total_count} security issues detected"
        elif "LOG_ONLY" in actions:
            action = SecurityAction.LOG_ONLY
            reason = f"Log: {total_count} security issues detected"
        else:
            action = SecurityAction.PASS
            reason = "Pass: Low risk content"

        return {
            "action": action,
            "detected": all_detections,
            "reason": reason,
            "counts": {
                "pii": pii_count,
                "jailbreak": jailbreak_count,
                "injection": injection_count,
                "semantic": semantic_count,
                "domain_risk": domain_count,
                "email_classification": email_count,
                "total": total_count
            }
        }

    def check_response(self, content: Optional[Any] = None) -> Dict[str, Any]:
        """Check response content for security issues."""
        result = self.check_request(content)
        if result.get("action") != SecurityAction.PASS:
            result["reason"] = f"Response {result.get('reason', '')}".strip()
        return result


# Global content filter instance
content_filter = ContentFilter()


def get_content_filter() -> ContentFilter:
    """Get global content filter instance."""
    return content_filter

