"""
Silver Router - AI-Powered Route Selection

Uses silver ratio weighted scoring for optimal VPN server selection.
"""

from .router import SilverRouter
from .models import ServerMetrics, RouteDecision

__all__ = ["SilverRouter", "ServerMetrics", "RouteDecision"]
