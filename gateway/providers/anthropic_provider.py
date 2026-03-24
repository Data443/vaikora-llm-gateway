"""Anthropic provider adapter."""

from __future__ import annotations

from typing import Any, Dict, List

from gateway.providers.base import (
    NormalizedProviderResponse,
    PreparedProviderRequest,
    ProviderAdapter,
    ProviderConfigurationError,
    build_openai_style_payload,
    normalize_error_payload,
    split_system_and_messages,
)


def _build_anthropic_messages_url(endpoint: str) -> str:
    base = endpoint.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/messages"
    return f"{base}/v1/messages"


def _extract_bearer_token(headers: Dict[str, str]) -> str:
    auth = headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


class AnthropicProviderAdapter(ProviderAdapter):
    """Adapter for Anthropic Messages API."""

    name = "anthropic"

    def __init__(self, endpoint: str, api_key: str = "", api_version: str = "2023-06-01") -> None:
        self.endpoint = endpoint
        self.api_key = api_key.strip()
        self.api_version = api_version.strip() or "2023-06-01"

    def prepare_chat_completion(
        self,
        request_body: Dict[str, Any],
        incoming_headers: Dict[str, str],
    ) -> PreparedProviderRequest:
        key = self.api_key or _extract_bearer_token(incoming_headers)
        if not key:
            raise ProviderConfigurationError(
                "Anthropic provider selected but no API key is configured"
            )

        model = str(request_body.get("model", "")).strip() or "claude-3-5-sonnet-20241022"
        if model.lower().startswith("anthropic/"):
            model = model.split("/", 1)[1]

        system_text, messages = split_system_and_messages(request_body.get("messages"))
        if not messages:
            messages = [{"role": "user", "content": ""}]

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": int(request_body.get("max_tokens") or 1024),
        }
        if system_text:
            payload["system"] = system_text
        if request_body.get("temperature") is not None:
            payload["temperature"] = request_body.get("temperature")
        if request_body.get("top_p") is not None:
            payload["top_p"] = request_body.get("top_p")
        if request_body.get("stop") is not None:
            stop_value = request_body.get("stop")
            if isinstance(stop_value, list):
                payload["stop_sequences"] = [str(item) for item in stop_value]
            else:
                payload["stop_sequences"] = [str(stop_value)]

        headers = {
            "content-type": "application/json",
            "x-api-key": key,
            "anthropic-version": self.api_version,
        }

        return PreparedProviderRequest(
            url=_build_anthropic_messages_url(self.endpoint),
            headers=headers,
            json_body=payload,
        )

    def normalize_chat_completion(
        self,
        status_code: int,
        payload: Dict[str, Any],
    ) -> NormalizedProviderResponse:
        if status_code >= 400:
            return normalize_error_payload(
                provider=self.name,
                status_code=status_code,
                payload=payload,
            )

        content_texts: List[str] = []
        for item in payload.get("content", []) or []:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text")
                if isinstance(text, str) and text:
                    content_texts.append(text)

        usage = payload.get("usage", {}) if isinstance(payload.get("usage"), dict) else {}
        prompt_tokens = int(usage.get("input_tokens") or 0)
        completion_tokens = int(usage.get("output_tokens") or 0)
        finish_reason = str(payload.get("stop_reason") or "stop")
        if finish_reason in {"end_turn", "stop_sequence", "max_tokens"}:
            mapped_finish = "stop" if finish_reason != "max_tokens" else "length"
        else:
            mapped_finish = finish_reason

        normalized = build_openai_style_payload(
            model=str(payload.get("model") or "anthropic"),
            content="\n".join(content_texts).strip(),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            finish_reason=mapped_finish,
            completion_id=str(payload.get("id") or "chatcmpl-anthropic"),
        )
        return NormalizedProviderResponse(status_code=status_code, payload=normalized)
