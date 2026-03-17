"""
Data443 LLM Gateway - Tests

Basic unit tests for gateway functionality.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from gateway.policy import PolicyEngine, PolicyDecision
from gateway.audit import Decision
from gateway.cyren_client import CyrenClient


@pytest.fixture
def mock_cyren_client():
    """Mock Cyren client."""
    client = Mock(spec=CyrenClient)
    client.classify_ip = AsyncMock()
    client.classify_url = AsyncMock()
    client._calculate_risk_score = AsyncMock(return_value=90)
    return client


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger."""
    logger = Mock()
    logger.log_decision = AsyncMock()
    return logger


@pytest.fixture
def policy_engine(mock_cyren_client, mock_audit_logger):
    """Create policy engine with mocked dependencies."""
    mock_cyren_client._calculate_risk_score.return_value = 90
    return PolicyEngine(mock_cyren_client, mock_audit_logger)


@pytest.mark.asyncio
class TestPolicyEngine:
    """Test policy engine functionality."""

    async def test_high_trust_allows(self, policy_engine, mock_cyren_client):
        """Test high risk score (80-100) results in ALLOW."""
        decision = await policy_engine.evaluate_request(
            ip_address="8.8.8.8",
            url="https://google.com"
        )

        assert decision.decision in (Decision.ALLOW, Decision.ALLOW_LOG)
        assert decision.risk_score == 90

    async def test_medium_trust_allows_with_log(self, policy_engine, mock_cyren_client):
        """Test medium risk score (50-79) results in ALLOW_LOG."""
        mock_cyren_client._calculate_risk_score.return_value = 60
        decision = await policy_engine.evaluate_request(
            ip_address="1.2.3.4",
            url="https://example.com"
        )

        assert decision.decision == Decision.ALLOW_LOG
        assert decision.risk_score == 60

    async def test_low_trust_constrains(self, policy_engine, mock_cyren_client):
        """Test low risk score (20-49) results in CONSTRAIN."""
        mock_cyren_client._calculate_risk_score.return_value = 30
        decision = await policy_engine.evaluate_request(
            ip_address="192.0.2.1",
            url="https://suspicious.com"
        )

        assert decision.decision == Decision.CONSTRAIN
        assert decision.risk_score == 30

    async def test_critical_risk_blocks(self, policy_engine, mock_cyren_client):
        """Test critical risk score (0-19) results in BLOCK."""
        mock_cyren_client._calculate_risk_score.return_value = 10
        decision = await policy_engine.evaluate_request(
            ip_address="203.0.113.1",
            url="https://malicious.com"
        )

        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 10

    async def test_no_threat_data_defaults_to_allow(self, policy_engine, mock_cyren_client):
        """Test missing threat intelligence defaults to safe score (100)."""
        mock_cyren_client._calculate_risk_score.return_value = 100
        decision = await policy_engine.evaluate_request(
            ip_address="10.0.0.1",
            url="https://internal.com"
        )

        assert decision.decision in (Decision.ALLOW, Decision.ALLOW_LOG)
        assert decision.risk_score == 100


@pytest.mark.asyncio
class TestCyrenClient:
    """Test Cyren client functionality."""

    async def test_validates_ip_address(self):
        """Test IP address validation."""
        client = CyrenClient()

        assert client._validate_ip("8.8.8.8") is True
        assert client._validate_ip("192.168.1.1") is True
        assert client._validate_ip("10.0.0.1") is True
        assert client._validate_ip("256.0.0.1") is False
        assert client._validate_ip("invalid") is False
        assert client._validate_ip("") is False

    async def test_normalizes_url(self):
        """Test URL normalization."""
        client = CyrenClient()

        assert client._normalize_url("google.com") == "http://google.com"
        assert client._normalize_url("https://google.com") == "https://google.com"
        assert client._normalize_url("https://google.com/path") == "https://google.com/path"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
