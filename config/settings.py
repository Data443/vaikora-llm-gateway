from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # OpenAI
    openai_api_key: str = ""
    openai_endpoint: str = "https://api.openai.com"

    # Cyren API
    cyren_urlf_endpoint: str = "https://try-now-urlcat.data443.io/ctwsd/websec"
    cyren_iprep_endpoint: str = "https://try-now-ipreputation.data443.io/ctipd/iprep"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_ttl: int = 3600

    # Database
    database_url: str = "postgresql://postgres:password@localhost:5432/gateway_db"

    # Gateway
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8000

    # Trust score thresholds
    score_high: int = 80
    score_medium: int = 50
    score_low: int = 20

    class Config:
        env_file = ".env"

settings = Settings()