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
    log_format: str = Field(
        default="text",
        description="Logging format: 'text' for human-readable, 'json' for structured JSON",
    )
    upstream_timeout_seconds: float = Field(
        default=60.0,
        description="Timeout in seconds for upstream LLM provider calls",
    )
    max_request_body_bytes: int = Field(
        default=10_485_760,
        description="Maximum request body size in bytes (default 10 MB); 0 disables",
    )
    strict_startup_validation: bool = Field(
        default=False,
        description=(
            "Enable strict fail-fast startup validation for production "
            "(placeholder credentials and incomplete auth config are rejected)"
        ),
    )

    rate_limit_enabled: bool = Field(
        default=False,
        description="Enable gateway request rate limiting middleware",
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        description="Rate limit window size in seconds",
    )
    rate_limit_storage: str = Field(
        default="auto",
        description="Rate limit backend: auto, redis, or memory",
    )
    rate_limit_redis_prefix: str = Field(
        default="gw:ratelimit",
        description="Redis key prefix for distributed rate limiting",
    )
    rate_limit_proxy_requests: int = Field(
        default=120,
        description="Max proxy requests per client within rate limit window",
    )
    rate_limit_admin_requests: int = Field(
        default=300,
        description="Max admin requests per client within rate limit window",
    )
    rate_limit_audit_requests: int = Field(
        default=120,
        description="Max audit/metrics requests per client within rate limit window",
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
    cyren_fail_closed: bool = Field(
        default=True,
        description="Block traffic when Cyren is unavailable (fail-closed); false = fail-open",
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
    audit_purge_enabled: bool = Field(
        default=True,
        description="Enable scheduled background purge for expired audit/event records",
    )
    audit_purge_interval_seconds: int = Field(
        default=3600,
        description="How often to run background retention purge job (seconds)",
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
    admin_auth_mode: str = Field(
        default="api_key",
        description="Admin auth mode: api_key, jwt, or api_key_or_jwt",
    )
    admin_allowed_ips: str = Field(
        default="",
        description="Comma-separated admin IP allowlist; empty disables allowlist",
    )

    # Database migrations
    db_migrations_enabled: bool = Field(
        default=True,
        description="Apply SQL migrations on startup",
    )
    db_ddl_bootstrap_fallback: bool = Field(
        default=False,
        description="Run legacy CREATE TABLE bootstrap SQL after migrations",
    )

    # Proxy API key authentication
    proxy_api_key_enabled: bool = Field(
        default=False,
        description="Require API key (x-api-key header) for proxy endpoints",
    )
    proxy_api_key: str = Field(
        default="",
        description="Static API key that proxy callers must provide in x-api-key header",
    )

    # Agent governance hardening
    agent_link_enforcement_enabled: bool = Field(
        default=True,
        description="Require an active A2A link before creating agent interactions",
    )
    a2a_interaction_enforcement_enabled: bool = Field(
        default=True,
        description="Require an APPROVED a2a_interaction_id header on agent proxy calls",
    )
    agent_interaction_retention_days: int = Field(
        default=30,
        description=(
            "Retention window (days) applied to agent interaction list APIs; "
            "0 disables retention filtering"
        ),
    )
    # OpenTelemetry
    otel_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry tracing hooks",
    )
    otel_service_name: str = Field(
        default="data443-llm-gateway",
        description="Service name reported in OpenTelemetry resources",
    )
    otel_exporter_otlp_endpoint: str = Field(
        default="",
        description="OTLP HTTP endpoint for trace export (optional)",
    )
    otel_exporter_timeout_seconds: float = Field(
        default=5.0,
        description="Timeout for OTLP trace export",
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

    # Control Plane (Vaikora) Integration
    control_plane_enabled: bool = Field(
        default=False,
        description="Enable integration with a remote Vaikora control plane",
    )
    control_plane_url: str = Field(
        default="",
        description="Base URL of the Vaikora control plane (e.g. http://localhost:8000)",
    )
    control_plane_api_key: str = Field(
        default="",
        description="API key for authenticating with the control plane (vk_... or agent key)",
    )
    control_plane_policy_sync_interval: int = Field(
        default=60,
        description="Seconds between policy sync pulls from the control plane",
    )
    control_plane_audit_push_interval: int = Field(
        default=30,
        description="Seconds between audit metadata push batches to the control plane",
    )
    control_plane_audit_batch_size: int = Field(
        default=50,
        description="Max number of audit events per push batch",
    )
    control_plane_audit_buffer_size: int = Field(
        default=5000,
        description="Max number of outbound audit events buffered locally before drops",
    )
    control_plane_hitl_poll_interval: int = Field(
        default=5,
        description="Seconds between HITL approval status polls",
    )
    control_plane_hitl_timeout: int = Field(
        default=300,
        description="Max seconds to wait for HITL approval before timing out",
    )
    control_plane_request_timeout: float = Field(
        default=10.0,
        description="HTTP timeout in seconds for control plane API calls",
    )
    control_plane_startup_sync_retries: int = Field(
        default=3,
        description="Number of startup retries for initial control-plane policy sync",
    )
    control_plane_policy_stale_after_seconds: int = Field(
        default=300,
        description="Mark policy cache stale after this many seconds without a successful sync; 0 disables",
    )
    control_plane_circuit_breaker_failure_threshold: int = Field(
        default=5,
        description="Consecutive control-plane request failures before the circuit opens",
    )
    control_plane_circuit_breaker_recovery_timeout: int = Field(
        default=60,
        description="Seconds to wait before retrying control-plane calls after the circuit opens",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


# Global settings instance
settings = Settings()
