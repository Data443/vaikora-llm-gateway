"""
Data443 LLM Gateway - Content Security Layer

Detects PII (Personally Identifiable Information) and malicious prompt patterns.
Includes PII pattern detection and known malicious prompt blocking.
"""

import re
from typing import List, Optional, Dict, Any
from enum import Enum
from loguru import logger

from config.settings import settings


class SecurityAction(str, Enum):
    """Security actions for detected content."""
    BLOCK = "BLOCK"
    CONSTRAIN = "CONSTRAIN"
    LOG_ONLY = "LOG_ONLY"
    PASS = "PASS"


class ContentFilter:
    """Content security filter for PII and malicious patterns."""

    # PII Patterns (compiled regex for performance)
    _SSN_PATTERN = re.compile(
        r'\b\d{3}[-.\s]?\d{2}\b',  # 123-45-6789
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
        r'\b\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}\b',
        flags=re.IGNORECASE
    )
    _PHONE_PATTERN_INTL = re.compile(
        r'\b\+?[0-9]{1,3}[-.\s]?[(]?[0-9]{1,4}[)\s]?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}\b',
        flags=re.IGNORECASE
    )

    _CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3(?:0[0-5][0-9]{11}|7(?:0[1-3][0-9]{11}))[0-9]{3}(?:[0-9]{3})?\b',
        flags=re.IGNORECASE
    )

    _IP_ADDRESS_PATTERN = re.compile(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        flags=re.IGNORECASE
    )

    _PASSPORT_PATTERN = re.compile(
        r'\b[A-Za-z]{2}[0-9]{2}\b',  # US format
        flags=re.IGNORECASE
    )

    _BANK_ACCOUNT_PATTERN = re.compile(
        r'\b(?:0[0-9]{13}|6[ -9][0-9]{2}|[0-24][0-9]{2})[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}\b',
        flags=re.IGNORECASE
    )

    # Malicious Prompt Patterns
    _JAILBREAK_PATTERNS = [
        # Ignore previous instructions
        r'(?i)(ignore|disregard|forget|overlook|skip|do not follow)\s+(your\s+)?(previous|earlier|above|past)\s+(instructions?|commands?|directives?|constraints?|rules?|limitations?|orders?)',
        # Assume different persona/role
        r'(?i)(act as|behave like|pretend to|roleplay as|impersonate|simulate|adopt the\s+(persona|character|role|identity|behavior))',
        # System prompt extraction
        r'(?i)(reveal|show|display|print|output|tell me|what are your|how do you\s+(work|function|operate|instructions|system prompt|initial prompt|preliminary instructions|original instructions|base instructions))',
        # Bypass restrictions
        r'(?i)(bypass|override|circumvent|evade|ignore|disable|turn off|deactivate)\s+(restrictions?|limitations?|filters?|controls?|rules?|safety|security)',
        # Chain of thought extraction
        r'(?i)(show|reveal|display|output|share|tell me)\s+(your\s+)?(reasoning?|thought process?|thinking process?|chain of thought?|internal monologue)',
    ]

    _INJECTION_PATTERNS = [
        # Command injection
        r'(?i)(ignore|do not follow|forget|overlook|skip)\s+(all\s+)?(future|previous)\s+(instructions?|commands?|text)',
        # Prompt injection via system messages
        r'(?i)(system|assistant):\s*(?!\s*(?i)(act|behave|roleplay|impersonate|simulate))',
        # Translation injection
        r'(?i)(translate|rewrite|rephrase)\s+(this|that)\s+(response|answer|output) as (a different language|another way|something else)',
        # Few-shot injection
        r'(?i)(few.?shot|zero.?shot|one.?shot)\s*(?!\s*(example|demonstrate|show me)(\s+a complete)?',
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
        if self._PHONE_PATTERN_INTL.search(text):
            detections.append({
                "type": "PHONE_INTL",
                "pattern": "+XX-XXXX-XXXX",
                "match": self._PHONE_PATTERN_INTL.search(text).group(),
                "severity": "MEDIUM"
            })

        # Check Credit Card
        if self._CREDIT_CARD_PATTERN.search(text):
            match = self._CREDIT_CARD_PATTERN.search(text).group()
            detections.append({
                "type": "CREDIT_CARD",
                "pattern": "XXXX-XXXX-XXXX-XXXX",
                "match": match[:4] + "-" + match[4:8] + "-" + match[8:12],  # Mask
                "severity": "HIGH"
            })

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
        if self._BANK_ACCOUNT_PATTERN.search(text):
            match = self._BANK_ACCOUNT_PATTERN.search(text).group()
            detections.append({
                "type": "BANK_ACCOUNT",
                "pattern": "US Bank Account",
                "match": match[:4] + "*" + match[4:8] + "*" + match[8:12],  # Mask
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

    def check_request(self, content: Optional[str] = None) -> Dict[str, Any]:
        """
        Check request content for security issues.

        Args:
            content: Request content (prompt, messages, etc.)

        Returns:
            Security analysis result
        """
        if not content:
            return {
                "action": SecurityAction.PASS,
                "detected": [],
                "reason": "No content to analyze"
            }

        # Check for PII
        pii_detections = self.check_pii(content)

        # Check for jailbreak attempts
        jailbreak_detections = self.check_jailbreak_attempts(content)

        # Check for injection attempts
        injection_detections = self.check_injection_attempts(content)

        # Combine all detections
        all_detections = pii_detections + jailbreak_detections + injection_detections

        if not all_detections:
            return {
                "action": SecurityAction.PASS,
                "detected": [],
                "reason": "No security issues detected"
            }

        # Determine action based on severity
        has_high_severity = any(d.get("severity") == "HIGH" for d in all_detections)

        # Count detections
        pii_count = len(pii_detections)
        jailbreak_count = len(jailbreak_detections)
        injection_count = len(injection_detections)
        total_count = len(all_detections)

        # Determine action
        if has_high_severity or jailbreak_count > 0:
            action = SecurityAction.BLOCK
            reason = f"Block: {jailbreak_count} jailbreak, {injection_count} injection, {pii_count} PII detected"
        elif total_count >= 3:
            action = SecurityAction.CONSTRAIN
            reason = f"Constrain: {total_count} security issues detected"
        elif total_count >= 1:
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
                "total": total_count
            }
        }


# Global content filter instance
content_filter = ContentFilter()


def get_content_filter() -> ContentFilter:
    """Get the global content filter instance."""
    return content_filter
