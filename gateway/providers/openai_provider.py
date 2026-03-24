"""OpenAI provider adapter."""

from __future__ import annotations

from typing import Any, Dict

from gateway.providers.base import (
    NormalizedProviderResponse,
    PreparedProviderRequest,
    ProviderAdapter,
)


def _build_openai_chat_url(endpoint: str) -> str:
    base = endpoint.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/chat/completions"
    return f"{base}/v1/chat/completions"


class OpenAIProviderAdapter(ProviderAdapter):
    """Adapter for OpenAI-compatible upstream endpoints."""

    name = "openai"

    def __init__(self, endpoint: str, api_key: str = "") -> None:
        self.endpoint = endpoint
        self.api_key = api_key.strip()

    def prepare_chat_completion(
        self,
        request_body: Dict[str, Any],
        incoming_headers: Dict[str, str],
    ) -> PreparedProviderRequest:
        headers = {"content-type": "application/json"}
        auth_header = incoming_headers.get("authorization", "").strip()
        if auth_header:
            headers["authorization"] = auth_header
        elif self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"

        return PreparedProviderRequest(
            url=_build_openai_chat_url(self.endpoint),
            headers=headers,
            json_body=request_body,
        )

    def normalize_chat_completion(
        self,
        status_code: int,
        payload: Dict[str, Any],
    ) -> NormalizedProviderResponse:
        return NormalizedProviderResponse(status_code=status_code, payload=payload)
