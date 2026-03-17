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

    # Target LLM Configuration (OpenAI)
    llm_endpoint: str = Field(
        default="https://api.openai.com/v1",
        description="Target LLM API endpoint"
    )
    llm_api_key: str = Field(
        default="",
        description="Target LLM API key (will be proxied from request)"
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
