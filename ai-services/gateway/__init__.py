"""
ADZVPN-Opus AI Gateway

FastAPI-based inference router for all AI services.
"""

from .app import app, create_app
from .config import Settings, get_settings

__all__ = ["app", "create_app", "Settings", "get_settings"]
