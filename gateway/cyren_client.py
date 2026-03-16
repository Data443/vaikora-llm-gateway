"""
Data443 LLM Gateway - Cyren API Integration

Integrates with Cyren IP Reputation and URL Filtering APIs.
Includes circuit breaker for fault tolerance.
"""

from typing import Optional, Dict, Any
import re
import asyncio

import httpx
from loguru import logger

from config.settings import settings
from gateway.audit import audit_logger


class CyrenResponse:
    """Parsed Cyren API response."""

    def __init__(self, raw_response: str):
        self.raw = raw_response
        self.data = self._parse_response(raw_response)

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse Cyren key-value response format."""
        data = {}
        for line in response.split('\n'):
            if ':' in line and not line.startswith('>>'):
                key, value = line.split(':', 1)
                data[key.strip()] = value.strip()
        return data

    @property
    def status(self) -> Optional[int]:
        """Get request status (0 = success)."""
        return int(self.data.get('x-ctch-request-status', -1))

    @property
    def risk_level(self) -> Optional[int]:
        """Get risk level (0-100)."""
        return int(self.data.get('x-ctch-risk-level', -1)) if 'x-ctch-risk-level' in self.data else None

    @property
    def category(self) -> Optional[int]:
        """Get category ID."""
        return int(self.data.get('x-ctch-categories', -1)) if 'x-ctch-categories' in self.data else None

    @property
    def ref_id(self) -> Optional[str]:
        """Get reference ID."""
        return self.data.get('x-ctch-refid')

    @property
    def ip_class(self) -> Optional[str]:
        """Get IP classification."""
        return self.data.get('x-ctch-ipclass')

    @property
    def normalized_url(self) -> Optional[str]:
        """Get normalized URL."""
        return self.data.get('x-ctch-normalized-url')


class CircuitBreaker:
    """Circuit breaker for Cyren API calls."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half-open

    def record_success(self) -> None:
        """Record a successful call."""
        self.failure_count = 0
        if self.state == "half-open":
            self.state = "closed"
            logger.info("Circuit breaker closed")

    def record_failure(self) -> None:
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = asyncio.get_event_loop().time()

        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")

    def allow_request(self) -> bool:
        """Check if request is allowed."""
        if self.state == "closed":
            return True

        if self.state == "open":
            if asyncio.get_event_loop().time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
                logger.info("Circuit breaker half-open, allowing one request")
                return True
            return False

        if self.state == "half-open":
            return True

        return True


class CyrenClient:
    """Cyren API client with caching and circuit breaker."""

    def __init__(self):
        self.iprep_url = settings.cyren_iprep_url
        self.urlf_url = settings.cyren_urlf_url
        self.timeout = settings.cyren_timeout
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=settings.circuit_breaker_failure_threshold,
            recovery_timeout=settings.circuit_breaker_recovery_timeout
        )

    async def classify_ip(self, ip_address: str) -> Optional[CyrenResponse]:
        """
        Classify an IP address using Cyren IP Reputation API.

        Args:
            ip_address: IPv4 address to classify

        Returns:
            CyrenResponse with risk level (0-100), or None if failed
        """
        if not self.circuit_breaker.allow_request():
            logger.warning(f"Circuit breaker open, skipping IP check: {ip_address}")
            return None

        if not self._validate_ip(ip_address):
            logger.warning(f"Invalid IP address: {ip_address}")
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                request_body = f"""x-ctch-request-type: classifyip
x-ctch-pver: 1.0

x-ctch-ip: {ip_address}
"""

                response = await client.post(
                    self.iprep_url,
                    content=request_body.encode(),
                    headers={"Content-Type": "text/plain"},
                )

                if response.status_code == 200:
                    self.circuit_breaker.record_success()
                    cyren_response = CyrenResponse(response.text)

                    logger.info(
                        f"IP Reputation: {ip_address} -> "
                        f"risk={cyren_response.risk_level}, "
                        f"class={cyren_response.ip_class}"
                    )

                    return cyren_response
                else:
                    self.circuit_breaker.record_failure()
                    logger.warning(f"IP Reputation failed: {response.status_code}")

        except httpx.TimeoutException:
            self.circuit_breaker.record_failure()
            logger.warning(f"IP Reputation timeout: {ip_address}")
        except Exception as e:
            self.circuit_breaker.record_failure()
            logger.error(f"IP Reputation error: {e}")

        return None

    async def classify_url(self, url: str) -> Optional[CyrenResponse]:
        """
        Classify a URL using Cyren URL Filtering API.

        Args:
            url: URL to classify (normalized, no encoded characters)

        Returns:
            CyrenResponse with category ID, or None if failed
        """
        if not self.circuit_breaker.allow_request():
            logger.warning(f"Circuit breaker open, skipping URL check: {url}")
            return None

        # Normalize URL
        normalized_url = self._normalize_url(url)
        if not normalized_url:
            logger.warning(f"Invalid URL: {url}")
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                request_body = f"""x-ctch-request-type: classifyurl
x-ctch-pver: 1.0

x-ctch-url: {normalized_url}
"""

                response = await client.post(
                    self.urlf_url,
                    content=request_body.encode(),
                    headers={"Content-Type": "text/plain"},
                )

                if response.status_code == 200:
                    self.circuit_breaker.record_success()
                    cyren_response = CyrenResponse(response.text)

                    logger.info(
                        f"URL Filtering: {normalized_url} -> "
                        f"category={cyren_response.category}"
                    )

                    return cyren_response
                else:
                    self.circuit_breaker.record_failure()
                    logger.warning(f"URL Filtering failed: {response.status_code}")

        except httpx.TimeoutException:
            self.circuit_breaker.record_failure()
            logger.warning(f"URL Filtering timeout: {url}")
        except Exception as e:
            self.circuit_breaker.record_failure()
            logger.error(f"URL Filtering error: {e}")

        return None

    def _validate_ip(self, ip: str) -> bool:
        """Validate IPv4 address."""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False

        # Check each octet is 0-255
        for octet in ip.split('.'):
            if not 0 <= int(octet) <= 255:
                return False

        return True

    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize URL for Cyren URL Filtering API."""
        try:
            from urllib.parse import urlparse

            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'

            parsed = urlparse(url)

            # Reconstruct with only scheme, host, and port
            normalized = parsed.scheme + '://' + parsed.netloc
            if parsed.path and parsed.path != '/':
                normalized += parsed.path

            return normalized
        except Exception as e:
            logger.error(f"URL normalization error: {e}")
            return None

    def get_circuit_breaker_state(self) -> str:
        """Get current circuit breaker state."""
        return self.circuit_breaker.state


# Global Cyren client instance
cyren_client = CyrenClient()
