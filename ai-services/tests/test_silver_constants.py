"""
Tests for Silver Constants

Verifies the mathematical foundations of ADZVPN-Opus.
"""

import sys
import math
from pathlib import Path

# Add parent for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from silver_constants import (
    ETA, TAU, DELTA_S, ETA_SQUARED, LAMBDA_SQUARED,
    pell, pell_sequence, silver_from_pell,
    verify_palindrome_identity, verify_unit_magnitude, verify_pell_convergence,
    silver_weights, silver_weights_normalized,
    silver_delay_us, silver_padding, silver_score,
)


class TestSilverConstants:
    """Test silver ratio constants."""

    def test_eta_value(self):
        """Test η = 1/√2."""
        expected = 1.0 / math.sqrt(2)
        assert abs(ETA - expected) < 1e-10

    def test_tau_value(self):
        """Test τ = √2."""
        expected = math.sqrt(2)
        assert abs(TAU - expected) < 1e-10

    def test_delta_s_value(self):
        """Test δ_S = 1 + √2."""
        expected = 1.0 + math.sqrt(2)
        assert abs(DELTA_S - expected) < 1e-10

    def test_eta_tau_relationship(self):
        """Test η = 1/τ."""
        assert abs(ETA - 1.0 / TAU) < 1e-10

    def test_balanced_traffic_ratios(self):
        """Test η² = λ² = 0.5."""
        assert ETA_SQUARED == 0.5
        assert LAMBDA_SQUARED == 0.5


class TestPellSequence:
    """Test Pell number generation."""

    def test_pell_base_cases(self):
        """Test P(0) = 0, P(1) = 1."""
        assert pell(0) == 0
        assert pell(1) == 1

    def test_pell_sequence_values(self):
        """Test known Pell numbers."""
        # P(n) = 0, 1, 2, 5, 12, 29, 70, 169, 408, 985...
        expected = [0, 1, 2, 5, 12, 29, 70, 169, 408, 985]
        for i, exp in enumerate(expected):
            assert pell(i) == exp, f"pell({i}) should be {exp}"

    def test_pell_recurrence(self):
        """Test P(n) = 2P(n-1) + P(n-2)."""
        for n in range(2, 15):
            assert pell(n) == 2 * pell(n - 1) + pell(n - 2)

    def test_pell_sequence_function(self):
        """Test pell_sequence generates correct list."""
        seq = pell_sequence(5)
        assert seq == [0, 1, 2, 5, 12]

    def test_silver_from_pell_convergence(self):
        """Test P(n+1)/P(n) converges to δ_S."""
        # Should converge quickly
        approx = silver_from_pell(20)
        assert abs(approx - DELTA_S) < 0.0001


class TestVerifications:
    """Test mathematical identity verifications."""

    def test_palindrome_identity(self):
        """Test δ_S = τ² + 1/δ_S."""
        assert verify_palindrome_identity()

        # Manual check
        lhs = DELTA_S
        rhs = TAU * TAU + 1.0 / DELTA_S
        assert abs(lhs - rhs) < 1e-10

    def test_unit_magnitude(self):
        """Test η² + λ² = 1."""
        assert verify_unit_magnitude()
        assert abs(ETA_SQUARED + LAMBDA_SQUARED - 1.0) < 1e-10

    def test_pell_convergence(self):
        """Test Pell sequence convergence."""
        assert verify_pell_convergence()


class TestSilverWeights:
    """Test silver weight generation."""

    def test_weights_pattern(self):
        """Test weights cycle through 1, τ, δ_S."""
        weights = silver_weights(6)
        assert abs(weights[0] - 1.0) < 1e-10
        assert abs(weights[1] - TAU) < 1e-10
        assert abs(weights[2] - DELTA_S) < 1e-10
        assert abs(weights[3] - 2.0) < 1e-10  # 1 * 2
        assert abs(weights[4] - TAU * 2) < 1e-10
        assert abs(weights[5] - DELTA_S * 2) < 1e-10

    def test_normalized_weights_sum(self):
        """Test normalized weights sum to 1."""
        for n in [3, 5, 10]:
            normalized = silver_weights_normalized(n)
            assert abs(sum(normalized) - 1.0) < 1e-10


class TestSilverTiming:
    """Test silver timing calculations."""

    def test_delay_base_case(self):
        """Test delay at packet index 0."""
        # pell(0) = 0, so delay = base * (1 + 0/δ_S) = base
        delay = silver_delay_us(0, 10000)
        assert delay == 10000

    def test_delay_increases_with_pell(self):
        """Test delay increases with Pell sequence."""
        base = 10000
        delays = [silver_delay_us(i, base) for i in range(5)]

        # Delays should generally increase (not strictly due to modulo)
        # But at least some should be larger than base
        assert any(d > base for d in delays[1:])

    def test_delay_pattern_cycles(self):
        """Test delay uses packet_index % 20."""
        base = 10000
        delay_0 = silver_delay_us(0, base)
        delay_20 = silver_delay_us(20, base)
        assert delay_0 == delay_20  # Should cycle


class TestSilverPadding:
    """Test silver padding calculations."""

    def test_balanced_padding(self):
        """Test padding equals payload when balanced."""
        # When η² = λ² = 0.5, ratio = 1, so padding = payload
        payload = 1000
        padding = silver_padding(payload)
        assert padding == payload

    def test_padding_ratio(self):
        """Test total maintains η² + λ² = 1."""
        payload = 1000
        padding = silver_padding(payload)
        total = payload + padding

        payload_ratio = payload / total
        padding_ratio = padding / total

        assert abs(payload_ratio - ETA_SQUARED) < 0.01
        assert abs(padding_ratio - LAMBDA_SQUARED) < 0.01


class TestSilverScore:
    """Test silver-weighted scoring."""

    def test_perfect_score(self):
        """Test ideal server gets high score."""
        score = silver_score(
            latency_ms=0,
            bandwidth_mbps=1000,
            load_percent=0,
        )
        # Should be close to 1.0
        assert score > 0.9

    def test_poor_score(self):
        """Test poor server gets low score."""
        score = silver_score(
            latency_ms=500,
            bandwidth_mbps=10,
            load_percent=95,
        )
        # Should be low
        assert score < 0.3

    def test_score_latency_impact(self):
        """Test latency has highest impact (δ_S weight)."""
        # Same bandwidth and load, different latency
        score_low_lat = silver_score(10, 100, 50)
        score_high_lat = silver_score(200, 100, 50)

        assert score_low_lat > score_high_lat

    def test_score_bandwidth_impact(self):
        """Test bandwidth has medium impact (τ weight)."""
        # Same latency and load, different bandwidth
        score_high_bw = silver_score(50, 500, 50)
        score_low_bw = silver_score(50, 50, 50)

        assert score_high_bw > score_low_bw

    def test_score_load_impact(self):
        """Test load has lowest impact (1.0 weight)."""
        # Same latency and bandwidth, different load
        score_low_load = silver_score(50, 100, 10)
        score_high_load = silver_score(50, 100, 90)

        assert score_low_load > score_high_load

    def test_score_range(self):
        """Test score stays in 0-1 range."""
        test_cases = [
            (0, 1000, 0),
            (1000, 0, 100),
            (50, 100, 50),
            (200, 50, 80),
        ]
        for lat, bw, load in test_cases:
            score = silver_score(lat, bw, load)
            assert 0 <= score <= 1, f"Score {score} out of range for {lat}, {bw}, {load}"


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
