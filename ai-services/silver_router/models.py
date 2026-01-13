"""
Silver Router Models

Data models for the silver-weighted routing AI.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ServerStatus(Enum):
    """Server operational status."""
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


@dataclass
class ServerMetrics:
    """
    Real-time server metrics for routing decisions.

    These metrics feed into the silver-weighted scoring algorithm.
    """
    server_id: str
    address: str
    port: int = 51820

    # Performance metrics
    latency_ms: float = 0.0
    bandwidth_mbps: float = 0.0
    load_percent: float = 0.0
    packet_loss_percent: float = 0.0

    # Status
    status: ServerStatus = ServerStatus.ONLINE
    last_health_check: Optional[datetime] = None

    # Geographic info
    region: str = ""
    country: str = ""
    city: str = ""

    # Capabilities
    features: List[str] = field(default_factory=list)
    max_connections: int = 1000
    current_connections: int = 0

    # Historical stats
    uptime_percent: float = 100.0
    avg_latency_24h: float = 0.0

    def connection_availability(self) -> float:
        """Calculate connection slot availability (0-1)."""
        if self.max_connections == 0:
            return 0.0
        return 1.0 - (self.current_connections / self.max_connections)

    def is_available(self) -> bool:
        """Check if server is available for connections."""
        return (
            self.status == ServerStatus.ONLINE
            and self.current_connections < self.max_connections
        )


@dataclass
class RouteDecision:
    """
    Routing decision with silver-weighted scoring.

    Contains the selected server and all scoring details.
    """
    # Selected server
    server_id: str
    server_address: str
    server_port: int

    # Silver score (0-1, higher is better)
    score: float

    # Component scores
    latency_score: float
    bandwidth_score: float
    load_score: float

    # Weights used
    latency_weight: float  # δ_S
    bandwidth_weight: float  # τ
    load_weight: float  # 1.0

    # Decision metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    decision_time_ms: float = 0.0
    alternatives_count: int = 0

    # Confidence (based on data freshness and variance)
    confidence: float = 1.0

    # Reason for selection
    reason: str = "highest_silver_score"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "server_id": self.server_id,
            "server_address": self.server_address,
            "server_port": self.server_port,
            "score": self.score,
            "components": {
                "latency": self.latency_score,
                "bandwidth": self.bandwidth_score,
                "load": self.load_score,
            },
            "weights": {
                "latency": self.latency_weight,
                "bandwidth": self.bandwidth_weight,
                "load": self.load_weight,
            },
            "timestamp": self.timestamp.isoformat(),
            "decision_time_ms": self.decision_time_ms,
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass
class RoutingConstraints:
    """
    Constraints for route selection.

    Servers not meeting these constraints are filtered out.
    """
    # Performance requirements
    max_latency_ms: float = 500.0
    min_bandwidth_mbps: float = 10.0
    max_load_percent: float = 90.0
    max_packet_loss_percent: float = 5.0

    # Geographic preferences
    preferred_regions: List[str] = field(default_factory=list)
    excluded_regions: List[str] = field(default_factory=list)
    preferred_countries: List[str] = field(default_factory=list)

    # Feature requirements
    required_features: List[str] = field(default_factory=list)

    # Server exclusions
    excluded_servers: List[str] = field(default_factory=list)

    # Load balancing
    avoid_fully_loaded: bool = True
    load_threshold: float = 85.0


@dataclass
class RoutingHistory:
    """
    Historical routing data for learning.

    Used to improve routing decisions over time.
    """
    server_id: str
    selected_at: datetime
    score_at_selection: float
    actual_latency_ms: Optional[float] = None
    actual_bandwidth_mbps: Optional[float] = None
    session_duration_secs: Optional[float] = None
    user_satisfaction: Optional[float] = None  # 0-1 if provided
    disconnection_reason: Optional[str] = None

    def performance_delta(self) -> Optional[float]:
        """
        Calculate difference between predicted and actual performance.

        Negative = worse than predicted, Positive = better than predicted
        """
        # This would be used for ML model training
        pass
