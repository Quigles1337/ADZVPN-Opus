"""
Gateway Configuration

Settings for the ADZVPN-Opus AI Gateway.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import os
from functools import lru_cache
from dataclasses import dataclass


@dataclass
class Settings:
    """Gateway settings with environment variable support."""

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # API
    api_prefix: str = "/api/v1"
    api_title: str = "ADZVPN-Opus AI Gateway"
    api_version: str = "1.0.0"

    # Silver Router
    router_enabled: bool = True
    router_cache_ttl: int = 60

    # Threat AI
    threat_enabled: bool = True
    threat_threshold: float = 0.7

    # Privacy AI
    privacy_enabled: bool = True
    privacy_noise_level: float = 0.5

    # Assistant
    assistant_enabled: bool = True
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Metrics
    metrics_enabled: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        """Create settings from environment variables."""
        return cls(
            host=os.getenv("ADZVPN_HOST", "0.0.0.0"),
            port=int(os.getenv("ADZVPN_PORT", "8000")),
            debug=os.getenv("ADZVPN_DEBUG", "false").lower() == "true",
            api_prefix=os.getenv("ADZVPN_API_PREFIX", "/api/v1"),
            api_title=os.getenv("ADZVPN_API_TITLE", "ADZVPN-Opus AI Gateway"),
            api_version=os.getenv("ADZVPN_API_VERSION", "1.0.0"),
            router_enabled=os.getenv("ADZVPN_ROUTER_ENABLED", "true").lower() == "true",
            router_cache_ttl=int(os.getenv("ADZVPN_ROUTER_CACHE_TTL", "60")),
            threat_enabled=os.getenv("ADZVPN_THREAT_ENABLED", "true").lower() == "true",
            threat_threshold=float(os.getenv("ADZVPN_THREAT_THRESHOLD", "0.7")),
            privacy_enabled=os.getenv("ADZVPN_PRIVACY_ENABLED", "true").lower() == "true",
            privacy_noise_level=float(os.getenv("ADZVPN_PRIVACY_NOISE_LEVEL", "0.5")),
            assistant_enabled=os.getenv("ADZVPN_ASSISTANT_ENABLED", "true").lower() == "true",
            ollama_host=os.getenv("ADZVPN_OLLAMA_HOST", "http://localhost:11434"),
            ollama_model=os.getenv("ADZVPN_OLLAMA_MODEL", "llama3.2"),
            metrics_enabled=os.getenv("ADZVPN_METRICS_ENABLED", "true").lower() == "true",
        )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings.from_env()
