"""
Data443 LLM Gateway - Tests

Basic tests for gateway functionality.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
import json
import asyncio

from gateway.main import app
from gateway.policy import PolicyDecision, Decision, PolicyEngine
from gateway.cyren_client import CyrenClient, CyrenResponse


@pytest.fixture
def mock_cyren_client():
    """Mock Cyren client."""
    client = Mock(spec=CyrenClient)
    client.classify_ip = AsyncMock()
    client.classify_url = AsyncMock()
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
    return PolicyEngine(mock_cyren_client, mock_audit_logger)


@pytest.mark.asyncio
class TestPolicyEngine:
    """Test policy engine functionality."""

    async def test_high_trust_allows(self, policy_engine, mock_cyren_client):
        """Test high risk score (80-100) results in ALLOW."""
        # Mock IP response with high trust
        mock_response = Mock()
        mock_response.risk_level = 90
        mock_response.ref_id = "test123"
        mock_cyren_client.classify_ip.return_value = mock_response

        decision = await policy_engine.evaluate_request(
            ip_address="8.8.8.8",
            url="https://google.com"
        )

        assert decision.decision == Decision.ALLOW
        assert decision.risk_score == 90

    async def test_medium_trust_allows_with_log(self, policy_engine, mock_cyren_client):
        """Test medium risk score (50-79) results in ALLOW_LOG."""
        mock_response = Mock()
        mock_response.risk_level = 60
        mock_response.ref_id = "test123"
        mock_cyren_client.classify_ip.return_value = mock_response

        decision = await policy_engine.evaluate_request(
            ip_address="1.2.3.4",
            url="https://example.com"
        )

        assert decision.decision == Decision.ALLOW_LOG
        assert decision.risk_score == 60

    async def test_low_trust_constrains(self, policy_engine, mock_cyren_client):
        """Test low risk score (20-49) results in CONSTRAIN."""
        mock_response = Mock()
        mock_response.risk_level = 30
        mock_response.ref_id = "test123"
        mock_cyren_client.classify_ip.return_value = mock_response

        decision = await policy_engine.evaluate_request(
            ip_address="192.0.2.1",
            url="https://suspicious.com"
        )

        assert decision.decision == Decision.CONSTRAIN
        assert decision.risk_score == 30

    async def test_critical_risk_blocks(self, policy_engine, mock_cyren_client):
        """Test critical risk score (0-19) results in BLOCK."""
        mock_response = Mock()
        mock_response.risk_level = 10
        mock_response.ref_id = "test123"
        mock_cyren_client.classify_ip.return_value = mock_response

        decision = await policy_engine.evaluate_request(
            ip_address="203.0.113.1",
            url="https://malicious.com"
        )

        assert decision.decision == Decision.BLOCK
        assert decision.risk_score == 10

    async def test_no_threat_data_defaults_to_allow(self, policy_engine, mock_cyren_client):
        """Test missing threat intelligence defaults to safe score (100)."""
        mock_cyren_client.classify_ip.return_value = None
        mock_cyren_client.classify_url.return_value = None

        decision = await policy_engine.evaluate_request(
            ip_address="10.0.0.1",
            url="https://internal.com"
        )

        assert decision.decision == Decision.ALLOW
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


@pytest.mark.asyncio
class TestAPIEndpoints:
    """Test FastAPI endpoints."""

    async def test_health_endpoint(self):
        """Test health check endpoint."""
        from fastapi.testclient import TestClient
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "circuit_breaker" in data
        assert "cache_connected" in data
        assert "audit_connected" in data

    async def test_root_endpoint(self):
        """Test root endpoint."""
        from fastapi.testclient import TestClient
        client = TestClient(app)

        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert data["status"] == "operational"

    async def test_admin_policies_list(self):
        """Test admin policies list endpoint."""
        from fastapi.testclient import TestClient
        client = TestClient(app)

        response = client.get("/admin/policies")

        assert response.status_code == 200
        data = response.json()
        assert "policies" in data

    async def test_admin_pii_policy_get(self):
        """Test get PII policy endpoint."""
        from fastapi.testclient import TestClient
        client = TestClient(app)

        response = client.get("/admin/policies/pii")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    async def test_admin_jwt_policy_get(self):
        """Test get JWT policy endpoint."""
        from fastapi.testclient import TestClient
        client = TestClient(app)

        response = client.get("/admin/policies/jwt")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    async def test_proxy_endpoint_forwards_request(self, mock_cyren_client):
        """Test proxy forwards requests (will fail due to no LLM endpoint)."""
        from fastapi.testclient import TestClient
        client = TestClient(app)

        # Mock Cyren to return high trust (ALLOW)
        mock_response = Mock()
        mock_response.risk_level = 95
        mock_cyren_client.classify_ip.return_value = mock_response

        # Create a test that will fail at forward (no LLM endpoint configured)
        response = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "test"}]}
        )

        # Request should be accepted by policy but fail at forward (502/503)
        assert response.status_code in [502, 503]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
