"""Provider adapter contracts and shared helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


class ProviderConfigurationError(RuntimeError):
    """Raised when provider configuration is incomplete or invalid."""


@dataclass
class PreparedProviderRequest:
    """Normalized outbound request prepared by a provider adapter."""

    url: str
    headers: Dict[str, str]
    json_body: Dict[str, Any]
    params: Dict[str, str] = field(default_factory=dict)


@dataclass
class NormalizedProviderResponse:
    """OpenAI-compatible normalized response payload."""

    status_code: int
    payload: Dict[str, Any]


class ProviderAdapter:
    """Base adapter contract for upstream LLM providers."""

    name: str = "unknown"

    def prepare_chat_completion(
        self,
        request_body: Dict[str, Any],
        incoming_headers: Dict[str, str],
    ) -> PreparedProviderRequest:
        """Build outbound provider-specific request."""
        raise NotImplementedError

    def normalize_chat_completion(
        self,
        status_code: int,
        payload: Dict[str, Any],
    ) -> NormalizedProviderResponse:
        """Normalize provider response to OpenAI-compatible shape."""
        raise NotImplementedError


def extract_text(content: Any) -> str:
    """Best-effort extraction of plain text from chat content."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            if "text" in item and isinstance(item["text"], str):
                parts.append(item["text"])
                continue
            # OpenAI-style content chunks often use {"type": "text", "text": "..."}
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(part for part in parts if part)
    return str(content)


def split_system_and_messages(messages: Any) -> Tuple[str, List[Dict[str, str]]]:
    """
    Split OpenAI-style messages into:
    - combined system prompt text
    - role/content message list for model exchanges
    """
    if not isinstance(messages, list):
        return "", []

    system_parts: List[str] = []
    normalized: List[Dict[str, str]] = []

    for raw in messages:
        if not isinstance(raw, dict):
            continue
        role = str(raw.get("role", "user")).strip().lower()
        text = extract_text(raw.get("content"))
        if role == "system":
            if text:
                system_parts.append(text)
            continue
        if role not in {"user", "assistant"}:
            role = "user"
        normalized.append({"role": role, "content": text})

    return "\n\n".join(system_parts).strip(), normalized


def build_openai_style_payload(
    *,
    model: str,
    content: str,
    prompt_tokens: int,
    completion_tokens: int,
    finish_reason: str = "stop",
    completion_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a minimal OpenAI-compatible chat completion payload."""
    total_tokens = max(prompt_tokens, 0) + max(completion_tokens, 0)
    return {
        "id": completion_id or "chatcmpl-gateway",
        "object": "chat.completion",
        "created": int(datetime.now(timezone.utc).timestamp()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                    "refusal": None,
                    "annotations": [],
                },
                "logprobs": None,
                "finish_reason": finish_reason or "stop",
            }
        ],
        "usage": {
            "prompt_tokens": max(prompt_tokens, 0),
            "completion_tokens": max(completion_tokens, 0),
            "total_tokens": total_tokens,
        },
    }


def normalize_error_payload(
    *,
    provider: str,
    status_code: int,
    payload: Dict[str, Any],
) -> NormalizedProviderResponse:
    """Normalize provider error body to gateway's standard error payload."""
    message = "Upstream provider request failed"
    code = "provider_error"

    if isinstance(payload, dict):
        if isinstance(payload.get("error"), dict):
            message = str(payload["error"].get("message", message))
            code = str(payload["error"].get("type", code))
        elif "message" in payload:
            message = str(payload.get("message", message))

    return NormalizedProviderResponse(
        status_code=status_code,
        payload={
            "error": {
                "message": message,
                "type": "upstream_error",
                "code": code,
                "provider": provider,
            }
        },
    )
