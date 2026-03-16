"""
Data443 LLM Gateway - Policy Evaluation Engine

Determines ALLOW/BLOCK/CONSTRAIN decisions based on Cyren threat intelligence.
Fully deterministic - no LLM in decision path.
"""

from enum import Enum
from typing import Optional, Dict, Any

from loguru import logger

from config.settings import settings
from gateway.audit import Decision, AuditLogger
from gateway.cyren_client import CyrenClient, CyrenResponse


class PolicyDecision:
    """Policy decision with full context."""

    def __init__(
        self,
        decision: Decision,
        risk_score: Optional[int] = None,
        reason: str = "",
        ip_risk_score: Optional[int] = None,
        url_category: Optional[int] = None,
        cyren_ref_id: Optional[str] = None,
    ):
        self.decision = decision
        self.risk_score = risk_score
        self.reason = reason
        self.ip_risk_score = ip_risk_score
        self.url_category = url_category
        self.cyren_ref_id = cyren_ref_id

    def __repr__(self) -> str:
        return f"PolicyDecision(decision={self.decision}, risk_score={self.risk_score}, reason={self.reason})"


class PolicyEngine:
    """
    Policy evaluation engine for LLM Gateway decisions.

    Decision Logic:
    - Risk score 80-100 = HIGH trust → ALLOW
    - Risk score 50-79 = MEDIUM trust → ALLOW with logging
    - Risk score 20-49 = LOW trust → CONSTRAIN
    - Risk score 0-19 = CRITICAL risk → BLOCK
    """

    def __init__(self, cyren_client: CyrenClient, audit_logger: AuditLogger):
        self.cyren_client = cyren_client
        self.audit_logger = audit_logger

    async def evaluate_request(
        self,
        ip_address: Optional[str] = None,
        url: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        request_body: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evaluate a request and return a policy decision.

        Args:
            ip_address: Client IP address
            url: Requested URL
            user_agent: User-Agent header
            request_id: Request identifier
            request_method: HTTP method
            request_path: Request path
            request_body: Request body

        Returns:
            PolicyDecision with ALLOW/BLOCK/CONSTRAIN action
        """
        # Get threat intelligence from Cyren
        ip_response = await self.cyren_client.classify_ip(ip_address) if ip_address else None
        url_response = await self.cyren_client.classify_url(url) if url else None

        # Calculate overall risk score
        risk_score = self._calculate_risk_score(ip_response, url_response)

        # Determine decision based on risk score
        decision, reason = self._get_decision_from_score(risk_score)

        # Log the decision
        await self.audit_logger.log_decision(
            decision=decision,
            ip_address=ip_address,
            url=url,
            risk_score=risk_score,
            ip_risk_score=ip_response.risk_level if ip_response else None,
            url_category=url_response.category if url_response else None,
            user_agent=user_agent,
            request_id=request_id,
            request_method=request_method,
            request_path=request_path,
            request_body=request_body,
            reason=reason,
            cyren_ref_id=(ip_response.ref_id if ip_response else None) or (url_response.ref_id if url_response else None),
        )

        return PolicyDecision(
            decision=decision,
            risk_score=risk_score,
            reason=reason,
            ip_risk_score=ip_response.risk_level if ip_response else None,
            url_category=url_response.category if url_response else None,
            cyren_ref_id=(ip_response.ref_id if ip_response else None) or (url_response.ref_id if url_response else None),
        )

    def _calculate_risk_score(
        self,
        ip_response: Optional[CyrenResponse],
        url_response: Optional[CyrenResponse],
    ) -> int:
        """
        Calculate overall risk score from IP and URL responses.

        Risk scoring:
        - IP risk level (0-100) - primary factor
        - URL category mapped to risk (0-100) - secondary factor

        If both are available, take the higher risk.
        If only one is available, use that.
        If neither is available, return default safe score (100).
        """
        ip_risk = ip_response.risk_level if ip_response else None
        url_risk = self._map_category_to_risk(url_response.category) if url_response else None

        # Return higher risk if both available
        if ip_risk is not None and url_risk is not None:
            return min(ip_risk, url_risk)  # Take the lower (more conservative) score

        # Return available score
        if ip_risk is not None:
            return ip_risk
        if url_risk is not None:
            return url_risk

        # No threat data available - return safe score (high trust)
        logger.warning("No threat intelligence available, defaulting to ALLOW")
        return 100

    def _map_category_to_risk(self, category: Optional[int]) -> Optional[int]:
        """
        Map URL category ID to risk score (0-100).

        This is a simplified mapping. Production should use Cyren's category-to-risk mapping.

        Common categories (Cyren):
        - 35: Search engines/Portals - LOW risk (85-100)
        - Other categories mapped accordingly
        """
        if category is None:
            return None

        # Simplified category mapping (update with actual Cyren categories)
        category_risk_map = {
            # Safe/Low risk
            35: 90,   # Search engines/Portals
            31: 95,   # Reference/Education
            30: 95,   # News/Media

            # Medium risk
            20: 70,   # Social Networking
            21: 60,   # Forums/Chat

            # High risk
            4: 10,    # Pornography
            5: 15,    # Violence/Hate
            6: 5,     # Illegal Drugs
        }

        return category_risk_map.get(category, 70)  # Default to medium risk for unknown categories

    def _get_decision_from_score(self, risk_score: int) -> tuple[Decision, str]:
        """
        Get decision based on risk score.

        Risk score thresholds:
        - 80-100: ALLOW (HIGH trust)
        - 50-79: ALLOW with logging (MEDIUM trust)
        - 20-49: CONSTRAIN (LOW trust)
        - 0-19: BLOCK (CRITICAL risk)
        """
        if risk_score >= settings.allow_threshold:
            return Decision.ALLOW, f"High trust (risk score: {risk_score})"

        if risk_score >= settings.allow_log_threshold:
            return Decision.ALLOW_LOG, f"Medium trust (risk score: {risk_score})"

        if risk_score >= settings.constrain_threshold:
            return Decision.CONSTRAIN, f"Low trust (risk score: {risk_score})"

        return Decision.BLOCK, f"Critical risk (risk score: {risk_score})"

    def is_request_allowed(self, decision: PolicyDecision) -> bool:
        """Check if request is allowed (including ALLOW_LOG)."""
        return decision.decision in (Decision.ALLOW, Decision.ALLOW_LOG)

    def is_request_constrained(self, decision: PolicyDecision) -> bool:
        """Check if request should be constrained."""
        return decision.decision == Decision.CONSTRAIN

    def is_request_blocked(self, decision: PolicyDecision) -> bool:
        """Check if request should be blocked."""
        return decision.decision == Decision.BLOCK


# Global policy engine instance
# Note: Must be initialized after cyren_client and audit_logger are created
policy_engine = None


def init_policy_engine(cyren_client, audit_logger) -> PolicyEngine:
    """Initialize the global policy engine."""
    global policy_engine
    policy_engine = PolicyEngine(cyren_client, audit_logger)
    return policy_engine
