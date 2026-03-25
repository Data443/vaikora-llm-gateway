"""
Data443 LLM Gateway - Configuration Management

Environment variables and settings for the gateway.
All sensitive data loaded from environment variables.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    # Server
    host: str = Field(default="0.0.0.0", description="Gateway host address")
    port: int = Field(default=8000, description="Gateway port")
    workers: int = Field(default=1, description="Number of worker processes")
    log_level: str = Field(default="INFO", description="Logging level")
    upstream_timeout_seconds: float = Field(
        default=60.0,
        description="Timeout in seconds for upstream LLM provider calls",
    )

    # CORS and proxy trust
    cors_allowed_origins: str = Field(
        default="http://localhost,http://127.0.0.1",
        description="Comma-separated CORS allowed origins; use * only in controlled environments",
    )
    cors_allowed_methods: str = Field(
        default="GET,POST,PUT,PATCH,DELETE,OPTIONS",
        description="Comma-separated CORS allowed methods",
    )
    cors_allowed_headers: str = Field(
        default="*",
        description="Comma-separated CORS allowed headers",
    )
    cors_allow_credentials: bool = Field(
        default=False,
        description="Allow CORS credentials; requires explicit non-wildcard origins",
    )
    trust_proxy_headers: bool = Field(
        default=False,
        description="Trust X-Forwarded-For/X-Real-IP headers for client IP extraction",
    )

    # Cyren API Configuration
    cyren_iprep_url: str = Field(
        default="https://try-now-ipreputation.data443.io/ctipd/iprep",
        description="Cyren IP Reputation API endpoint"
    )
    cyren_urlf_url: str = Field(
        default="https://try-now-urlcat.data443.io/ctwsd/websec",
        description="Cyren URL Filtering API endpoint"
    )
    cyren_api_key: str = Field(
        default="",
        description="Cyren API key (if required)"
    )
    cyren_timeout: float = Field(
        default=5.0,
        description="Cyren API timeout in seconds"
    )
    cyren_retry_attempts: int = Field(
        default=2,
        description="Number of retry attempts for Cyren API"
    )
    ctas_url: str = Field(
        default="https://try-now-antispam.data443.io/ctasd/ClassifyMessage_Inline",
        description="Cyren CTAS email classification API endpoint",
    )
    ctas_timeout: float = Field(
        default=5.0,
        description="Cyren CTAS timeout in seconds",
    )

    # Redis Configuration (L1/L2 Caching)
    redis_host: str = Field(default="localhost", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_db: int = Field(default=0, description="Redis database")
    redis_password: str = Field(default="", description="Redis password")
    redis_l1_ttl: int = Field(
        default=300,
        description="TTL for L1 cache (in-memory) in seconds"
    )
    redis_l2_ttl: int = Field(
        default=3600,
        description="TTL for L2 cache (Redis) in seconds"
    )

    # PostgreSQL Configuration (Audit Log)
    postgres_host: str = Field(default="localhost", description="PostgreSQL host")
    postgres_port: int = Field(default=5432, description="PostgreSQL port")
    postgres_db: str = Field(default="data443_audit", description="PostgreSQL database")
    postgres_user: str = Field(default="postgres", description="PostgreSQL user")
    postgres_password: str = Field(default="", description="PostgreSQL password")
    audit_retention_days: int = Field(
        default=30,
        description="Retention window (in days) applied to audit/event query APIs; 0 disables retention filtering",
    )
    audit_mask_sensitive_fields: bool = Field(
        default=True,
        description="Mask sensitive fields in audit/event API responses",
    )
    audit_redact_message_content: bool = Field(
        default=False,
        description="Redact prompt/message content in audit/event API responses",
    )
    audit_max_string_length: int = Field(
        default=4000,
        description="Max string length in audit/event API responses; 0 disables truncation",
    )

    # Target LLM Configuration (OpenAI)
    llm_provider: str = Field(
        default="openai",
        description="Default upstream provider (openai, anthropic, gemini, openrouter)"
    )
    llm_endpoint: str = Field(
        default="https://api.openai.com",
        description="Target LLM API base endpoint"
    )
    llm_api_key: str = Field(
        default="",
        description="Target LLM API key (will be proxied from request)"
    )

    # Provider-specific settings
    openai_endpoint: str = Field(
        default="https://api.openai.com",
        description="OpenAI API base endpoint"
    )
    openai_api_key: str = Field(
        default="",
        description="OpenAI API key (if explicit provider routing is used)"
    )
    anthropic_endpoint: str = Field(
        default="https://api.anthropic.com",
        description="Anthropic API base endpoint"
    )
    anthropic_api_key: str = Field(
        default="",
        description="Anthropic API key"
    )
    anthropic_api_version: str = Field(
        default="2023-06-01",
        description="Anthropic API version header value"
    )
    gemini_endpoint: str = Field(
        default="https://generativelanguage.googleapis.com",
        description="Google Gemini API base endpoint"
    )
    gemini_api_key: str = Field(
        default="",
        description="Google Gemini API key"
    )
    openrouter_endpoint: str = Field(
        default="https://openrouter.ai/api/v1",
        description="OpenRouter API base endpoint"
    )
    openrouter_api_key: str = Field(
        default="",
        description="OpenRouter API key"
    )

    # Policy Configuration
    allow_threshold: int = Field(
        default=80,
        description="Risk score threshold for ALLOW (80-100)"
    )
    allow_log_threshold: int = Field(
        default=50,
        description="Risk score threshold for ALLOW with logging (50-79)"
    )
    constrain_threshold: int = Field(
        default=20,
        description="Risk score threshold for CONSTRAIN (20-49)"
    )
    # BLOCK threshold is implicitly 0-19

    # JWT Authentication
    jwt_enabled: bool = Field(
        default=False,
        description="Enable JWT authentication"
    )
    jwt_secret: str = Field(
        default="",
        description="JWT secret key"
    )
    jwt_issuer: str = Field(
        default="data443-gateway",
        description="JWT issuer"
    )
    jwt_audience: str = Field(
        default="data443-gateway",
        description="JWT audience"
    )

    # Admin API hardening
    admin_auth_enabled: bool = Field(
        default=False,
        description="Enable admin API authentication"
    )
    admin_api_key: str = Field(
        default="",
        description="Static admin API key (x-admin-key)"
    )

    # Circuit Breaker
    circuit_breaker_failure_threshold: int = Field(
        default=5,
        description="Failure threshold to open circuit"
    )
    circuit_breaker_recovery_timeout: int = Field(
        default=60,
        description="Recovery timeout in seconds"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


# Global settings instance
settings = Settings()
