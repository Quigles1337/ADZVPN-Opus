"""
Silver Router - Core Routing Algorithm

AI-powered route selection using silver ratio mathematics.

The silver ratio (δ_S = 1 + √2 ≈ 2.414) provides elegant weights
that prioritize latency over bandwidth over load.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
import time
import random
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from datetime import datetime, timedelta
from dataclasses import dataclass

# Add parent for silver_constants
sys.path.insert(0, str(Path(__file__).parent.parent))

from silver_constants import (
    DELTA_S, TAU, ETA,
    silver_score, silver_weights_normalized,
    pell,
)

from .models import (
    ServerMetrics,
    ServerStatus,
    RouteDecision,
    RoutingConstraints,
    RoutingHistory,
)


@dataclass
class ScoredServer:
    """Server with calculated silver score."""
    metrics: ServerMetrics
    score: float
    latency_score: float
    bandwidth_score: float
    load_score: float


class SilverRouter:
    """
    Silver-weighted routing AI.

    Uses the silver ratio (δ_S = 1 + √2) for intelligent
    route selection based on latency, bandwidth, and load.

    Scoring formula:
        score = (lat_score * δ_S + bw_score * τ + load_score) / (δ_S + τ + 1)

    Where:
        - δ_S ≈ 2.414 (silver ratio) - latency weight
        - τ ≈ 1.414 (√2) - bandwidth weight
        - 1.0 - load weight
    """

    def __init__(
        self,
        latency_base_ms: float = 100.0,
        bandwidth_base_mbps: float = 100.0,
        cache_ttl_secs: int = 60,
        history_size: int = 1000,
    ):
        """
        Initialize the Silver Router.

        Args:
            latency_base_ms: Base latency for normalization
            bandwidth_base_mbps: Base bandwidth for normalization
            cache_ttl_secs: How long to cache routing decisions
            history_size: Max history entries to keep
        """
        self.latency_base = latency_base_ms
        self.bandwidth_base = bandwidth_base_mbps
        self.cache_ttl = timedelta(seconds=cache_ttl_secs)
        self.history_size = history_size

        # State
        self._servers: Dict[str, ServerMetrics] = {}
        self._cache: Dict[str, Tuple[RouteDecision, datetime]] = {}
        self._history: List[RoutingHistory] = []

        # Weights (silver ratio based)
        self.latency_weight = DELTA_S
        self.bandwidth_weight = TAU
        self.load_weight = 1.0
        self.total_weight = DELTA_S + TAU + 1.0

    def register_server(self, metrics: ServerMetrics) -> None:
        """Register or update a server's metrics."""
        self._servers[metrics.server_id] = metrics

    def unregister_server(self, server_id: str) -> None:
        """Remove a server from the pool."""
        self._servers.pop(server_id, None)

    def update_metrics(self, server_id: str, **kwargs) -> None:
        """Update specific metrics for a server."""
        if server_id in self._servers:
            for key, value in kwargs.items():
                if hasattr(self._servers[server_id], key):
                    setattr(self._servers[server_id], key, value)

    def get_servers(self) -> List[ServerMetrics]:
        """Get all registered servers."""
        return list(self._servers.values())

    def _calculate_latency_score(self, latency_ms: float) -> float:
        """
        Calculate latency component score (0-1).

        Lower latency = higher score.
        Uses τ-scaled normalization.
        """
        if latency_ms <= 0:
            return 1.0
        return 1.0 / (1.0 + latency_ms / (TAU * self.latency_base))

    def _calculate_bandwidth_score(self, bandwidth_mbps: float) -> float:
        """
        Calculate bandwidth component score (0-1).

        Higher bandwidth = higher score.
        Uses δ_S-scaled normalization.
        """
        if bandwidth_mbps <= 0:
            return 0.0
        score = bandwidth_mbps / (DELTA_S * self.bandwidth_base)
        return min(score, 1.0)  # Cap at 1.0

    def _calculate_load_score(self, load_percent: float) -> float:
        """
        Calculate load component score (0-1).

        Lower load = higher score.
        """
        return (100.0 - load_percent) / 100.0

    def score_server(self, metrics: ServerMetrics) -> ScoredServer:
        """
        Calculate silver-weighted score for a server.

        Returns ScoredServer with full breakdown.
        """
        # Component scores
        lat_score = self._calculate_latency_score(metrics.latency_ms)
        bw_score = self._calculate_bandwidth_score(metrics.bandwidth_mbps)
        load_score = self._calculate_load_score(metrics.load_percent)

        # Status penalty
        status_multiplier = {
            ServerStatus.ONLINE: 1.0,
            ServerStatus.DEGRADED: 0.7,
            ServerStatus.OFFLINE: 0.0,
            ServerStatus.MAINTENANCE: 0.0,
        }.get(metrics.status, 0.0)

        # Combined silver score
        raw_score = (
            lat_score * self.latency_weight +
            bw_score * self.bandwidth_weight +
            load_score * self.load_weight
        ) / self.total_weight

        final_score = raw_score * status_multiplier

        return ScoredServer(
            metrics=metrics,
            score=final_score,
            latency_score=lat_score,
            bandwidth_score=bw_score,
            load_score=load_score,
        )

    def filter_servers(
        self,
        servers: List[ServerMetrics],
        constraints: Optional[RoutingConstraints] = None,
    ) -> List[ServerMetrics]:
        """
        Filter servers based on constraints.

        Returns only servers meeting all criteria.
        """
        if constraints is None:
            constraints = RoutingConstraints()

        filtered = []

        for server in servers:
            # Status check
            if server.status in [ServerStatus.OFFLINE, ServerStatus.MAINTENANCE]:
                continue

            # Performance checks
            if server.latency_ms > constraints.max_latency_ms:
                continue
            if server.bandwidth_mbps < constraints.min_bandwidth_mbps:
                continue
            if server.load_percent > constraints.max_load_percent:
                continue
            if server.packet_loss_percent > constraints.max_packet_loss_percent:
                continue

            # Load balancing
            if constraints.avoid_fully_loaded:
                if server.load_percent >= constraints.load_threshold:
                    continue

            # Geographic checks
            if constraints.preferred_regions:
                if server.region not in constraints.preferred_regions:
                    continue
            if constraints.excluded_regions:
                if server.region in constraints.excluded_regions:
                    continue

            # Feature checks
            if constraints.required_features:
                if not all(f in server.features for f in constraints.required_features):
                    continue

            # Exclusion checks
            if server.server_id in constraints.excluded_servers:
                continue

            filtered.append(server)

        return filtered

    def select_route(
        self,
        constraints: Optional[RoutingConstraints] = None,
        cache_key: Optional[str] = None,
    ) -> Optional[RouteDecision]:
        """
        Select optimal route using silver-weighted scoring.

        Args:
            constraints: Optional routing constraints
            cache_key: Optional key for caching the decision

        Returns:
            RouteDecision or None if no servers available
        """
        start_time = time.time()

        # Check cache
        if cache_key and cache_key in self._cache:
            decision, cached_at = self._cache[cache_key]
            if datetime.utcnow() - cached_at < self.cache_ttl:
                return decision

        # Get all servers
        servers = self.get_servers()
        if not servers:
            return None

        # Filter by constraints
        filtered = self.filter_servers(servers, constraints)
        if not filtered:
            return None

        # Score all servers
        scored = [self.score_server(s) for s in filtered]

        # Sort by score (highest first)
        scored.sort(key=lambda x: x.score, reverse=True)

        # Select best
        best = scored[0]

        # Calculate decision time
        decision_time_ms = (time.time() - start_time) * 1000

        # Create decision
        decision = RouteDecision(
            server_id=best.metrics.server_id,
            server_address=best.metrics.address,
            server_port=best.metrics.port,
            score=best.score,
            latency_score=best.latency_score,
            bandwidth_score=best.bandwidth_score,
            load_score=best.load_score,
            latency_weight=self.latency_weight,
            bandwidth_weight=self.bandwidth_weight,
            load_weight=self.load_weight,
            decision_time_ms=decision_time_ms,
            alternatives_count=len(scored) - 1,
            reason="highest_silver_score",
        )

        # Cache if key provided
        if cache_key:
            self._cache[cache_key] = (decision, datetime.utcnow())

        return decision

    def select_with_alternatives(
        self,
        constraints: Optional[RoutingConstraints] = None,
        max_alternatives: int = 3,
    ) -> Tuple[Optional[RouteDecision], List[ScoredServer]]:
        """
        Select route and return alternatives.

        Returns:
            Tuple of (best decision, list of alternative servers)
        """
        servers = self.get_servers()
        filtered = self.filter_servers(servers, constraints)

        if not filtered:
            return None, []

        scored = [self.score_server(s) for s in filtered]
        scored.sort(key=lambda x: x.score, reverse=True)

        best = scored[0]
        alternatives = scored[1:max_alternatives + 1]

        decision = RouteDecision(
            server_id=best.metrics.server_id,
            server_address=best.metrics.address,
            server_port=best.metrics.port,
            score=best.score,
            latency_score=best.latency_score,
            bandwidth_score=best.bandwidth_score,
            load_score=best.load_score,
            latency_weight=self.latency_weight,
            bandwidth_weight=self.bandwidth_weight,
            load_weight=self.load_weight,
            alternatives_count=len(alternatives),
        )

        return decision, alternatives

    def record_history(self, history: RoutingHistory) -> None:
        """Record a routing decision in history."""
        self._history.append(history)

        # Trim if too large
        if len(self._history) > self.history_size:
            self._history = self._history[-self.history_size:]

    def get_server_selection_stats(self) -> Dict[str, int]:
        """Get selection count per server from history."""
        stats: Dict[str, int] = {}
        for entry in self._history:
            stats[entry.server_id] = stats.get(entry.server_id, 0) + 1
        return stats

    def clear_cache(self) -> None:
        """Clear the routing cache."""
        self._cache.clear()

    def get_weights(self) -> Dict[str, float]:
        """Get current routing weights."""
        return {
            "latency": self.latency_weight,
            "bandwidth": self.bandwidth_weight,
            "load": self.load_weight,
            "total": self.total_weight,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_score(
    latency_ms: float,
    bandwidth_mbps: float,
    load_percent: float,
) -> float:
    """
    Quick silver score calculation.

    Convenience function for simple scoring without full router setup.
    """
    return silver_score(latency_ms, bandwidth_mbps, load_percent)


def compare_servers(
    servers: List[ServerMetrics],
) -> List[Tuple[str, float]]:
    """
    Compare multiple servers and return sorted scores.

    Returns list of (server_id, score) tuples, highest first.
    """
    router = SilverRouter()
    for server in servers:
        router.register_server(server)

    scored = [router.score_server(s) for s in servers]
    scored.sort(key=lambda x: x.score, reverse=True)

    return [(s.metrics.server_id, s.score) for s in scored]
