"""Google Gemini provider adapter."""

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


def _extract_bearer_token(headers: Dict[str, str]) -> str:
    auth = headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _normalize_gemini_model(model_name: str) -> str:
    model = model_name.strip()
    if not model:
        return "gemini-2.0-flash"
    if model.lower().startswith("gemini/"):
        model = model.split("/", 1)[1]
    if model.lower().startswith("models/"):
        model = model.split("/", 1)[1]
    return model


def _build_gemini_generate_url(endpoint: str, model_name: str) -> str:
    base = endpoint.rstrip("/")
    return f"{base}/v1beta/models/{model_name}:generateContent"


class GeminiProviderAdapter(ProviderAdapter):
    """Adapter for Gemini generateContent API."""

    name = "gemini"

    def __init__(self, endpoint: str, api_key: str = "") -> None:
        self.endpoint = endpoint
        self.api_key = api_key.strip()

    def prepare_chat_completion(
        self,
        request_body: Dict[str, Any],
        incoming_headers: Dict[str, str],
    ) -> PreparedProviderRequest:
        key = self.api_key or _extract_bearer_token(incoming_headers)
        if not key:
            raise ProviderConfigurationError(
                "Gemini provider selected but no API key is configured"
            )

        model = _normalize_gemini_model(str(request_body.get("model", "")))
        system_text, messages = split_system_and_messages(request_body.get("messages"))
        contents: List[Dict[str, Any]] = []

        for msg in messages:
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append(
                {
                    "role": role,
                    "parts": [{"text": msg.get("content", "")}],
                }
            )
        if not contents:
            contents = [{"role": "user", "parts": [{"text": ""}]}]

        payload: Dict[str, Any] = {"contents": contents}
        generation_config: Dict[str, Any] = {}
        if request_body.get("temperature") is not None:
            generation_config["temperature"] = request_body.get("temperature")
        if request_body.get("top_p") is not None:
            generation_config["topP"] = request_body.get("top_p")
        if request_body.get("max_tokens") is not None:
            generation_config["maxOutputTokens"] = int(request_body.get("max_tokens"))
        if generation_config:
            payload["generationConfig"] = generation_config
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}

        return PreparedProviderRequest(
            url=_build_gemini_generate_url(self.endpoint, model),
            headers={"content-type": "application/json"},
            json_body=payload,
            params={"key": key},
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

        text_parts: List[str] = []
        finish_reason = "stop"
        candidates = payload.get("candidates", []) if isinstance(payload, dict) else []
        if candidates and isinstance(candidates[0], dict):
            first = candidates[0]
            finish_reason = str(first.get("finishReason") or "STOP").lower()
            content = first.get("content", {})
            parts = content.get("parts", []) if isinstance(content, dict) else []
            for part in parts:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    text_parts.append(part["text"])

        usage = payload.get("usageMetadata", {}) if isinstance(payload.get("usageMetadata"), dict) else {}
        prompt_tokens = int(usage.get("promptTokenCount") or 0)
        completion_tokens = int(usage.get("candidatesTokenCount") or 0)
        if completion_tokens == 0 and usage.get("totalTokenCount") and prompt_tokens:
            completion_tokens = int(usage["totalTokenCount"]) - prompt_tokens

        mapped_finish = "stop" if finish_reason in {"stop", "finish", "max_tokens"} else finish_reason
        if finish_reason in {"max_tokens", "max_output_tokens"}:
            mapped_finish = "length"

        normalized = build_openai_style_payload(
            model=str(payload.get("modelVersion") or "gemini"),
            content="\n".join(text_parts).strip(),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            finish_reason=mapped_finish,
            completion_id="chatcmpl-gemini",
        )
        return NormalizedProviderResponse(status_code=status_code, payload=normalized)
