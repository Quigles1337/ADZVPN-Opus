"""
Gateway Configuration

Settings for the ADZVPN-Opus AI Gateway.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Gateway settings with environment variable support."""

    # Server
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    debug: bool = Field(default=False, description="Debug mode")

    # API
    api_prefix: str = Field(default="/api/v1", description="API prefix")
    api_title: str = Field(default="ADZVPN-Opus AI Gateway", description="API title")
    api_version: str = Field(default="1.0.0", description="API version")

    # Silver Router
    router_enabled: bool = Field(default=True, description="Enable silver router")
    router_cache_ttl: int = Field(default=60, description="Route cache TTL in seconds")

    # Threat AI
    threat_enabled: bool = Field(default=True, description="Enable threat detection")
    threat_threshold: float = Field(default=0.7, description="Threat score threshold")

    # Privacy AI
    privacy_enabled: bool = Field(default=True, description="Enable privacy optimization")
    privacy_noise_level: float = Field(default=0.5, description="Silver noise level (0-1)")

    # Assistant
    assistant_enabled: bool = Field(default=True, description="Enable chat assistant")
    ollama_host: str = Field(default="http://localhost:11434", description="Ollama host")
    ollama_model: str = Field(default="llama3.2", description="Ollama model")

    # Metrics
    metrics_enabled: bool = Field(default=True, description="Enable Prometheus metrics")

    class Config:
        env_prefix = "ADZVPN_"
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
