"""
Tests for Silver Router

Tests the AI-powered routing with silver ratio weights.
"""

import sys
from pathlib import Path

# Add parent for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "silver-router"))

from silver_constants import DELTA_S, TAU
from silver_router import SilverRouter, ServerMetrics, RouteDecision
from silver_router.models import ServerStatus, RoutingConstraints


class TestSilverRouter:
    """Test SilverRouter core functionality."""

    def setup_method(self):
        """Set up test router with sample servers."""
        self.router = SilverRouter()

        # Add test servers
        self.servers = [
            ServerMetrics(
                server_id="sv-1",
                address="server1.vpn",
                latency_ms=25,
                bandwidth_mbps=1000,
                load_percent=30,
                region="us-east",
            ),
            ServerMetrics(
                server_id="sv-2",
                address="server2.vpn",
                latency_ms=50,
                bandwidth_mbps=800,
                load_percent=50,
                region="us-west",
            ),
            ServerMetrics(
                server_id="sv-3",
                address="server3.vpn",
                latency_ms=100,
                bandwidth_mbps=500,
                load_percent=20,
                region="eu-west",
            ),
        ]

        for server in self.servers:
            self.router.register_server(server)

    def test_register_server(self):
        """Test server registration."""
        assert len(self.router.get_servers()) == 3

    def test_unregister_server(self):
        """Test server removal."""
        self.router.unregister_server("sv-1")
        assert len(self.router.get_servers()) == 2

    def test_update_metrics(self):
        """Test metric updates."""
        self.router.update_metrics("sv-1", latency_ms=30)
        servers = self.router.get_servers()
        sv1 = next(s for s in servers if s.server_id == "sv-1")
        assert sv1.latency_ms == 30

    def test_score_server(self):
        """Test server scoring."""
        scored = self.router.score_server(self.servers[0])

        assert scored.score > 0
        assert scored.score <= 1
        assert scored.latency_score > 0
        assert scored.bandwidth_score > 0
        assert scored.load_score > 0

    def test_best_server_selected(self):
        """Test best server is selected."""
        decision = self.router.select_route()

        assert decision is not None
        # Server 1 has best latency (highest weight), should win
        assert decision.server_id == "sv-1"

    def test_decision_contains_weights(self):
        """Test decision includes silver weights."""
        decision = self.router.select_route()

        assert decision.latency_weight == DELTA_S
        assert decision.bandwidth_weight == TAU
        assert decision.load_weight == 1.0

    def test_offline_server_excluded(self):
        """Test offline servers are excluded."""
        self.router.update_metrics("sv-1", status=ServerStatus.OFFLINE)
        decision = self.router.select_route()

        assert decision is not None
        assert decision.server_id != "sv-1"

    def test_degraded_server_penalty(self):
        """Test degraded servers get score penalty."""
        # Score when online
        online_scored = self.router.score_server(self.servers[0])

        # Mark as degraded
        self.servers[0].status = ServerStatus.DEGRADED
        degraded_scored = self.router.score_server(self.servers[0])

        # Degraded should have lower score
        assert degraded_scored.score < online_scored.score


class TestRoutingConstraints:
    """Test constraint-based filtering."""

    def setup_method(self):
        """Set up router with diverse servers."""
        self.router = SilverRouter()

        self.servers = [
            ServerMetrics(
                server_id="fast",
                address="fast.vpn",
                latency_ms=20,
                bandwidth_mbps=1000,
                load_percent=80,
                region="us-east",
                features=["streaming", "p2p"],
            ),
            ServerMetrics(
                server_id="slow",
                address="slow.vpn",
                latency_ms=200,
                bandwidth_mbps=100,
                load_percent=20,
                region="eu-west",
                features=["streaming"],
            ),
            ServerMetrics(
                server_id="loaded",
                address="loaded.vpn",
                latency_ms=30,
                bandwidth_mbps=800,
                load_percent=95,
                region="us-west",
                features=["p2p", "gaming"],
            ),
        ]

        for server in self.servers:
            self.router.register_server(server)

    def test_max_latency_filter(self):
        """Test filtering by max latency."""
        constraints = RoutingConstraints(max_latency_ms=100, max_load_percent=100, avoid_fully_loaded=False)
        filtered = self.router.filter_servers(self.servers, constraints)

        # "slow" server should be filtered out
        assert len(filtered) == 2
        assert all(s.server_id != "slow" for s in filtered)

    def test_min_bandwidth_filter(self):
        """Test filtering by min bandwidth."""
        constraints = RoutingConstraints(min_bandwidth_mbps=500, max_load_percent=100, avoid_fully_loaded=False)
        filtered = self.router.filter_servers(self.servers, constraints)

        # "slow" server should be filtered out
        assert len(filtered) == 2
        assert all(s.bandwidth_mbps >= 500 for s in filtered)

    def test_max_load_filter(self):
        """Test filtering by max load."""
        constraints = RoutingConstraints(max_load_percent=90, avoid_fully_loaded=False)
        filtered = self.router.filter_servers(self.servers, constraints)

        # "loaded" server should be filtered out
        assert len(filtered) == 2
        assert all(s.server_id != "loaded" for s in filtered)

    def test_region_filter(self):
        """Test filtering by preferred region."""
        constraints = RoutingConstraints(preferred_regions=["us-east", "us-west"], max_load_percent=100, avoid_fully_loaded=False)
        filtered = self.router.filter_servers(self.servers, constraints)

        # Only US servers
        assert len(filtered) == 2
        assert all(s.region.startswith("us") for s in filtered)

    def test_feature_filter(self):
        """Test filtering by required features."""
        constraints = RoutingConstraints(required_features=["p2p"], max_load_percent=100, avoid_fully_loaded=False)
        filtered = self.router.filter_servers(self.servers, constraints)

        # Only p2p servers
        assert len(filtered) == 2
        assert all("p2p" in s.features for s in filtered)

    def test_combined_constraints(self):
        """Test multiple constraints together."""
        constraints = RoutingConstraints(
            max_latency_ms=100,
            max_load_percent=90,
            required_features=["streaming"],
        )
        filtered = self.router.filter_servers(self.servers, constraints)

        # Only "fast" server meets all criteria
        assert len(filtered) == 1
        assert filtered[0].server_id == "fast"


class TestRoutingCache:
    """Test routing decision caching."""

    def setup_method(self):
        """Set up router."""
        self.router = SilverRouter(cache_ttl_secs=60)

        self.router.register_server(ServerMetrics(
            server_id="sv-1",
            address="server1.vpn",
            latency_ms=25,
            bandwidth_mbps=1000,
            load_percent=30,
        ))

    def test_cache_stores_decision(self):
        """Test cache stores routing decision."""
        decision1 = self.router.select_route(cache_key="test")
        decision2 = self.router.select_route(cache_key="test")

        # Should return same decision from cache
        assert decision1.server_id == decision2.server_id
        assert decision1.score == decision2.score

    def test_cache_clear(self):
        """Test cache can be cleared."""
        self.router.select_route(cache_key="test")
        self.router.clear_cache()

        # Cache should be empty
        assert len(self.router._cache) == 0


class TestAlternatives:
    """Test alternative server selection."""

    def setup_method(self):
        """Set up router with multiple servers."""
        self.router = SilverRouter()

        for i in range(5):
            self.router.register_server(ServerMetrics(
                server_id=f"sv-{i}",
                address=f"server{i}.vpn",
                latency_ms=20 + i * 10,
                bandwidth_mbps=1000 - i * 100,
                load_percent=20 + i * 10,
            ))

    def test_alternatives_returned(self):
        """Test alternatives are returned."""
        decision, alternatives = self.router.select_with_alternatives(
            max_alternatives=3
        )

        assert decision is not None
        assert len(alternatives) == 3

    def test_alternatives_ranked(self):
        """Test alternatives are ranked by score."""
        decision, alternatives = self.router.select_with_alternatives()

        scores = [decision.score] + [a.score for a in alternatives]

        # Should be in descending order
        assert scores == sorted(scores, reverse=True)


class TestScoringMath:
    """Test the mathematical correctness of scoring."""

    def test_latency_weight_highest(self):
        """Test latency has highest weight (δ_S)."""
        router = SilverRouter()
        assert router.latency_weight == DELTA_S
        assert router.latency_weight > router.bandwidth_weight
        assert router.latency_weight > router.load_weight

    def test_bandwidth_weight_medium(self):
        """Test bandwidth has medium weight (τ)."""
        router = SilverRouter()
        assert router.bandwidth_weight == TAU
        assert router.bandwidth_weight > router.load_weight

    def test_load_weight_lowest(self):
        """Test load has lowest weight (1.0)."""
        router = SilverRouter()
        assert router.load_weight == 1.0

    def test_total_weight(self):
        """Test total weight is δ_S + τ + 1."""
        router = SilverRouter()
        expected = DELTA_S + TAU + 1.0
        assert abs(router.total_weight - expected) < 1e-10


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
