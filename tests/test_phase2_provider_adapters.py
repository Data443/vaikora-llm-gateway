"""Phase 2 provider adapter tests."""

from gateway.providers.anthropic_provider import AnthropicProviderAdapter
from gateway.providers.gemini_provider import GeminiProviderAdapter
from gateway.providers.openai_provider import OpenAIProviderAdapter
from gateway.providers.openrouter_provider import OpenRouterProviderAdapter
from gateway.providers.router import ProviderRouter


def test_router_resolves_provider_from_explicit_hint() -> None:
    router = ProviderRouter()
    provider = router.resolve_provider({"provider": "anthropic", "model": "gpt-4o-mini"})
    assert provider == "anthropic"


def test_router_resolves_provider_from_model_prefix() -> None:
    router = ProviderRouter()
    provider = router.resolve_provider({"model": "gemini-2.0-flash"})
    assert provider == "gemini"


def test_anthropic_prepare_and_normalize() -> None:
    adapter = AnthropicProviderAdapter(
        endpoint="https://api.anthropic.com",
        api_key="anthropic-test-key",
        api_version="2023-06-01",
    )
    prepared = adapter.prepare_chat_completion(
        request_body={
            "model": "claude-3-5-sonnet-20241022",
            "messages": [
                {"role": "system", "content": "You are concise."},
                {"role": "user", "content": "Say hello"},
            ],
            "max_tokens": 128,
            "temperature": 0.1,
        },
        incoming_headers={},
    )

    assert prepared.url.endswith("/v1/messages")
    assert prepared.headers["x-api-key"] == "anthropic-test-key"
    assert prepared.json_body["model"] == "claude-3-5-sonnet-20241022"
    assert prepared.json_body["system"] == "You are concise."
    assert prepared.json_body["messages"][0]["role"] == "user"

    normalized = adapter.normalize_chat_completion(
        status_code=200,
        payload={
            "id": "msg_123",
            "model": "claude-3-5-sonnet-20241022",
            "content": [{"type": "text", "text": "Hello from Claude"}],
            "usage": {"input_tokens": 12, "output_tokens": 8},
            "stop_reason": "end_turn",
        },
    )
    assert normalized.status_code == 200
    assert normalized.payload["choices"][0]["message"]["content"] == "Hello from Claude"
    assert normalized.payload["usage"]["prompt_tokens"] == 12
    assert normalized.payload["usage"]["completion_tokens"] == 8


def test_gemini_prepare_and_normalize() -> None:
    adapter = GeminiProviderAdapter(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="gemini-test-key",
    )
    prepared = adapter.prepare_chat_completion(
        request_body={
            "model": "gemini-2.0-flash",
            "messages": [{"role": "user", "content": "Say hello"}],
            "max_tokens": 64,
        },
        incoming_headers={},
    )
    assert "/v1beta/models/gemini-2.0-flash:generateContent" in prepared.url
    assert prepared.params["key"] == "gemini-test-key"
    assert prepared.json_body["contents"][0]["parts"][0]["text"] == "Say hello"

    normalized = adapter.normalize_chat_completion(
        status_code=200,
        payload={
            "modelVersion": "gemini-2.0-flash",
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"parts": [{"text": "Hello from Gemini"}]},
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 7,
                "candidatesTokenCount": 6,
                "totalTokenCount": 13,
            },
        },
    )
    assert normalized.status_code == 200
    assert normalized.payload["choices"][0]["message"]["content"] == "Hello from Gemini"
    assert normalized.payload["usage"]["total_tokens"] == 13


def test_openai_and_openrouter_passthrough() -> None:
    openai = OpenAIProviderAdapter(endpoint="https://api.openai.com", api_key="openai-key")
    prepared_openai = openai.prepare_chat_completion(
        request_body={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hi"}]},
        incoming_headers={},
    )
    assert prepared_openai.url.endswith("/v1/chat/completions")
    assert prepared_openai.headers["authorization"] == "Bearer openai-key"

    openrouter = OpenRouterProviderAdapter(
        endpoint="https://openrouter.ai/api/v1",
        api_key="openrouter-key",
    )
    prepared_openrouter = openrouter.prepare_chat_completion(
        request_body={"model": "openai/gpt-4o-mini", "messages": [{"role": "user", "content": "Hi"}]},
        incoming_headers={},
    )
    assert prepared_openrouter.url.endswith("/chat/completions")
    assert prepared_openrouter.headers["authorization"] == "Bearer openrouter-key"
