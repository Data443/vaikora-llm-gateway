"""Provider routing and adapter orchestration."""

from __future__ import annotations

from typing import Any, Dict

from gateway.core.config import settings
from gateway.providers.anthropic_provider import AnthropicProviderAdapter
from gateway.providers.base import (
    NormalizedProviderResponse,
    PreparedProviderRequest,
    ProviderAdapter,
)
from gateway.providers.gemini_provider import GeminiProviderAdapter
from gateway.providers.openai_provider import OpenAIProviderAdapter
from gateway.providers.openrouter_provider import OpenRouterProviderAdapter


SUPPORTED_PROVIDERS = {"openai", "anthropic", "gemini", "openrouter"}


def infer_provider_from_endpoint(endpoint: str) -> str:
    """Infer provider from base endpoint URL."""
    lower = endpoint.lower()
    if "openai" in lower:
        return "openai"
    if "anthropic" in lower:
        return "anthropic"
    if "gemini" in lower or "googleapis" in lower:
        return "gemini"
    if "openrouter" in lower:
        return "openrouter"
    return "openai"


class ProviderRouter:
    """Resolve provider for a request and delegate request/response transforms."""

    def __init__(self) -> None:
        default_provider = (settings.llm_provider or "").strip().lower()
        if default_provider not in SUPPORTED_PROVIDERS:
            default_provider = infer_provider_from_endpoint(settings.llm_endpoint)
        self.default_provider = default_provider

        self._adapters: Dict[str, ProviderAdapter] = {
            "openai": OpenAIProviderAdapter(
                endpoint=settings.openai_endpoint or settings.llm_endpoint,
                api_key=settings.openai_api_key or settings.llm_api_key,
            ),
            "anthropic": AnthropicProviderAdapter(
                endpoint=settings.anthropic_endpoint,
                api_key=settings.anthropic_api_key,
                api_version=settings.anthropic_api_version,
            ),
            "gemini": GeminiProviderAdapter(
                endpoint=settings.gemini_endpoint,
                api_key=settings.gemini_api_key,
            ),
            "openrouter": OpenRouterProviderAdapter(
                endpoint=settings.openrouter_endpoint,
                api_key=settings.openrouter_api_key,
            ),
        }

    def resolve_provider(self, request_body: Dict[str, Any] | None) -> str:
        """Resolve provider from explicit request hint, model hint, or defaults."""
        if isinstance(request_body, dict):
            explicit = str(request_body.get("provider", "")).strip().lower()
            if explicit in SUPPORTED_PROVIDERS:
                return explicit

            model = str(request_body.get("model", "")).strip().lower()
            from_model = self._provider_from_model(model)
            if from_model:
                return from_model

        return self.default_provider

    def prepare_chat_completion(
        self,
        provider_name: str,
        request_body: Dict[str, Any],
        incoming_headers: Dict[str, str],
    ) -> PreparedProviderRequest:
        """Prepare provider-specific request payload for chat completions."""
        adapter = self._require_adapter(provider_name)
        return adapter.prepare_chat_completion(request_body, incoming_headers)

    def normalize_chat_completion(
        self,
        provider_name: str,
        status_code: int,
        payload: Dict[str, Any],
    ) -> NormalizedProviderResponse:
        """Normalize provider-specific response payload to OpenAI-compatible format."""
        adapter = self._require_adapter(provider_name)
        return adapter.normalize_chat_completion(status_code, payload)

    def _require_adapter(self, provider_name: str) -> ProviderAdapter:
        key = provider_name.strip().lower()
        if key not in self._adapters:
            raise ValueError(f"Unsupported provider: {provider_name}")
        return self._adapters[key]

    def _provider_from_model(self, model: str) -> str | None:
        if not model:
            return None
        if model.startswith("claude") or model.startswith("anthropic/"):
            return "anthropic"
        if model.startswith("gemini") or model.startswith("models/gemini"):
            return "gemini"
        if model.startswith("openrouter/"):
            return "openrouter"
        return None
