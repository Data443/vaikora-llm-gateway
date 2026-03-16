import requests
import logging
from config.settings import settings

logger = logging.getLogger(__name__)

class CyrenClient:

    def check_url(self, url: str) -> dict:
        try:
            data = (
                "x-ctch-request-type: classifyurl\r\n"
                "x-ctch-pver: 1.0\r\n\r\n"
                f"x-ctch-url: {url}\r\n"
            )
            response = requests.post(
                settings.cyren_urlf_endpoint,
                data=data,
                timeout=5
            )
            if response.ok:
                return {"status": "ok", "result": response.text, "url": url}
            return {"status": "error", "result": None, "url": url}
        except Exception as e:
            logger.error(f"Cyren URL check failed: {e}")
            return {"status": "error", "result": None, "url": url}

    def check_ip(self, ip: str) -> dict:
        try:
            data = (
                "x-ctch-request-type: classifyip\n"
                "x-ctch-pver: 1.0\n"
                f"\nx-ctch-ip: {ip}\n"
            )
            response = requests.post(
                settings.cyren_iprep_endpoint,
                data=data,
                timeout=5
            )
            if response.ok:
                return {"status": "ok", "result": response.text, "ip": ip}
            return {"status": "error", "result": None, "ip": ip}
        except Exception as e:
            logger.error(f"Cyren IP check failed: {e}")
            return {"status": "error", "result": None, "ip": ip}

    def get_trust_score(self, result: str) -> int:
        if result is None:
            return 50
        result_lower = result.lower()
        if any(word in result_lower for word in ["malware", "phishing", "spam", "botnet"]):
            return 10
        if any(word in result_lower for word in ["suspicious", "unknown"]):
            return 40
        if "clean" in result_lower or "legitimate" in result_lower:
            return 90
        return 50

    def get_decision(self, score: int) -> str:
        if score >= settings.score_high:
            return "ALLOW"
        elif score >= settings.score_medium:
            return "CONSTRAIN"
        else:
            return "BLOCK"

cyren_client = CyrenClient()