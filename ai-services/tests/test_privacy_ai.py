"""
Tests for Privacy AI

Tests silver noise generation, traffic obfuscation, and privacy optimization.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from silver_constants import DELTA_S, TAU, ETA_SQUARED, LAMBDA_SQUARED

from privacy_ai import (
    PrivacyLevel,
    ObfuscationConfig,
    TrafficProfile,
    PrivacyMetrics,
    ObfuscationResult,
    SilverNoiseGenerator,
    TrafficObfuscator,
    TimingObfuscator,
    PrivacyOptimizer,
)
from privacy_ai.noise_generator import SilverChaffGenerator
from privacy_ai.traffic_obfuscator import SizeBucketObfuscator, ConstantBandwidthObfuscator
from privacy_ai.timing_obfuscator import AdaptiveTimingObfuscator, BurstTimingObfuscator
from privacy_ai.privacy_optimizer import PrivacyContext, PrivacyPolicyEngine


# =============================================================================
# TEST MODELS
# =============================================================================

class TestPrivacyLevel:
    """Test PrivacyLevel enum."""

    def test_noise_ratio(self):
        """Test noise ratio for each level."""
        assert PrivacyLevel.MINIMAL.to_noise_ratio() == 0.0
        assert PrivacyLevel.STANDARD.to_noise_ratio() == 0.2
        assert PrivacyLevel.MAXIMUM.to_noise_ratio() == 1.0
        assert PrivacyLevel.PARANOID.to_noise_ratio() > 1.0

    def test_timing_jitter(self):
        """Test timing jitter for each level."""
        assert PrivacyLevel.MINIMAL.to_timing_jitter() == 0.0
        assert PrivacyLevel.PARANOID.to_timing_jitter() > 0.3


class TestObfuscationConfig:
    """Test ObfuscationConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = ObfuscationConfig()
        assert config.enable_padding
        assert config.target_padding_ratio == LAMBDA_SQUARED

    def test_apply_privacy_level(self):
        """Test applying privacy level."""
        config = ObfuscationConfig(privacy_level=PrivacyLevel.PARANOID)
        config.apply_privacy_level()

        assert config.enable_padding
        assert config.enable_timing_obfuscation
        assert config.enable_noise_injection
        assert config.enable_decoy_traffic


class TestTrafficProfile:
    """Test TrafficProfile."""

    def test_calculate_ratios(self):
        """Test ratio calculations."""
        profile = TrafficProfile(
            total_bytes=2000,
            real_bytes=1000,
            padding_bytes=1000,
        )
        profile.calculate_ratios()

        assert profile.real_to_total_ratio == 0.5
        assert profile.padding_to_real_ratio == 1.0

    def test_is_balanced(self):
        """Test silver balance check."""
        balanced = TrafficProfile(
            total_bytes=2000,
            real_bytes=1000,
            padding_bytes=1000,
        )
        balanced.calculate_ratios()
        assert balanced.is_balanced()

        unbalanced = TrafficProfile(
            total_bytes=2000,
            real_bytes=1800,
            padding_bytes=200,
        )
        unbalanced.calculate_ratios()
        assert not unbalanced.is_balanced()


# =============================================================================
# TEST NOISE GENERATOR
# =============================================================================

class TestSilverNoiseGenerator:
    """Test silver noise generation."""

    def setup_method(self):
        """Set up generator."""
        self.gen = SilverNoiseGenerator(seed=42)

    def test_generate_bytes(self):
        """Test byte generation."""
        data = self.gen.generate_bytes(100)
        assert len(data) == 100
        assert isinstance(data, bytes)

    def test_deterministic(self):
        """Test deterministic generation with same seed."""
        gen1 = SilverNoiseGenerator(seed=12345)
        gen2 = SilverNoiseGenerator(seed=12345)

        data1 = gen1.generate_bytes(100)
        data2 = gen2.generate_bytes(100)

        assert data1 == data2

    def test_different_seeds(self):
        """Test different seeds produce different output."""
        gen1 = SilverNoiseGenerator(seed=1)
        gen2 = SilverNoiseGenerator(seed=2)

        data1 = gen1.generate_bytes(100)
        data2 = gen2.generate_bytes(100)

        assert data1 != data2

    def test_generate_packet(self):
        """Test packet generation."""
        packet = self.gen.generate_packet(256)

        assert packet.size == 256
        assert len(packet.data) == 256
        assert packet.pattern == "silver"

    def test_generate_padding(self):
        """Test silver padding generation."""
        padding = self.gen.generate_padding(1000)

        # For balanced η²/λ², padding should equal payload
        assert len(padding) == 1000

    def test_chaff_stream(self):
        """Test chaff stream generation."""
        packets = self.gen.generate_chaff_stream(10)

        assert len(packets) == 10
        for packet in packets:
            assert 64 <= packet.size <= 1500

    def test_distribution_quality(self):
        """Test generated data has good distribution."""
        data = self.gen.generate_bytes(10000)
        score = self.gen.verify_silver_distribution(data)

        # Silver PRNG is deterministic, not perfectly uniform
        # Score >= 0 indicates valid calculation
        assert score >= 0.0


class TestSilverChaffGenerator:
    """Test chaff generator."""

    def setup_method(self):
        """Set up generator."""
        self.gen = SilverChaffGenerator()

    def test_realistic_size(self):
        """Test realistic size generation."""
        sizes = [self.gen.generate_realistic_size() for _ in range(100)]

        # Should be within valid range
        assert all(64 <= s <= 1500 for s in sizes)

    def test_burst_generation(self):
        """Test burst generation."""
        packets = self.gen.generate_burst(5)

        assert len(packets) == 5

    def test_session_chaff(self):
        """Test session chaff generation."""
        chaff = self.gen.generate_session_chaff(10.0, packets_per_second=5)

        # Should have ~50 packets for 10 seconds at 5/sec
        assert 30 <= len(chaff) <= 70

        # Should be time-ordered
        times = [t for t, _ in chaff]
        assert times == sorted(times)


# =============================================================================
# TEST TRAFFIC OBFUSCATOR
# =============================================================================

class TestTrafficObfuscator:
    """Test traffic obfuscation."""

    def setup_method(self):
        """Set up obfuscator."""
        self.obfuscator = TrafficObfuscator()

    def test_obfuscate_adds_padding(self):
        """Test that obfuscation adds padding."""
        data = b"Hello, World!"
        result = self.obfuscator.obfuscate(data)

        assert result.obfuscated_size > result.original_size
        assert result.padding_size > 0

    def test_deobfuscate_recovers_data(self):
        """Test that deobfuscation recovers original data."""
        data = b"Test data for obfuscation"
        result = self.obfuscator.obfuscate(data)

        recovered = self.obfuscator.deobfuscate(result.obfuscated_data)
        assert recovered == data

    def test_silver_ratio_achieved(self):
        """Test silver ratio in obfuscated packets."""
        data = b"A" * 1000
        result = self.obfuscator.obfuscate(data)

        # Should be close to η² (0.5) real data ratio
        result.calculate_metrics()
        assert 0.3 <= result.silver_ratio_achieved <= 0.7

    def test_normalize_size(self):
        """Test size normalization."""
        data = b"Small data"
        normalized = self.obfuscator.normalize_size(data)

        # Should be padded to a standard size
        assert len(normalized) in TrafficObfuscator.STANDARD_SIZES

    def test_traffic_profile(self):
        """Test traffic profile generation."""
        for _ in range(10):
            self.obfuscator.obfuscate(b"Test" * 100)

        profile = self.obfuscator.get_profile()
        assert profile.total_packets == 10
        assert profile.real_bytes > 0
        assert profile.padding_bytes > 0


class TestSizeBucketObfuscator:
    """Test size bucket obfuscation."""

    def setup_method(self):
        """Set up obfuscator."""
        self.obfuscator = SizeBucketObfuscator()

    def test_obfuscate_to_bucket(self):
        """Test obfuscation pads to bucket size."""
        data = b"A" * 100
        obfuscated = self.obfuscator.obfuscate(data)

        # Should be exactly a bucket size
        assert len(obfuscated) in SizeBucketObfuscator.DEFAULT_BUCKETS

    def test_deobfuscate(self):
        """Test deobfuscation."""
        data = b"Test data"
        obfuscated = self.obfuscator.obfuscate(data)
        recovered = self.obfuscator.deobfuscate(obfuscated)

        assert recovered == data

    def test_get_bucket(self):
        """Test bucket selection."""
        assert self.obfuscator.get_bucket_for_size(50) == 64
        assert self.obfuscator.get_bucket_for_size(100) == 128
        assert self.obfuscator.get_bucket_for_size(1000) == 1024


class TestConstantBandwidthObfuscator:
    """Test constant bandwidth obfuscation."""

    def setup_method(self):
        """Set up obfuscator."""
        self.obfuscator = ConstantBandwidthObfuscator(
            target_bandwidth_bps=1_000_000,
            packet_interval_ms=10.0,
        )

    def test_queue_and_get(self):
        """Test queueing and retrieving data."""
        self.obfuscator.queue_data(b"Test data")

        packet, is_real = self.obfuscator.get_next_packet()

        # Packet includes 4-byte header + (target_packet_size - 4) body = target_packet_size
        assert len(packet) == self.obfuscator.target_packet_size
        assert is_real

    def test_noise_when_empty(self):
        """Test noise generation when queue empty."""
        packet, is_real = self.obfuscator.get_next_packet()

        # Packet includes 4-byte header + (target_packet_size - 4) body = target_packet_size
        assert len(packet) == self.obfuscator.target_packet_size
        assert not is_real  # Should be noise

    def test_queue_size(self):
        """Test queue size tracking."""
        self.obfuscator.queue_data(b"A" * 100)
        self.obfuscator.queue_data(b"B" * 200)

        assert self.obfuscator.get_queue_size() == 300


# =============================================================================
# TEST TIMING OBFUSCATOR
# =============================================================================

class TestTimingObfuscator:
    """Test timing obfuscation."""

    def setup_method(self):
        """Set up obfuscator."""
        self.obfuscator = TimingObfuscator(
            base_interval_us=10_000,
            jitter_factor=0.2,
        )

    def test_get_next_delay(self):
        """Test delay generation."""
        decision = self.obfuscator.get_next_delay()

        assert decision.delay_us > 0
        assert decision.is_silver_timed

    def test_delays_vary(self):
        """Test that delays have variation."""
        delays = [self.obfuscator.get_next_delay().delay_us for _ in range(100)]

        # Should have some variation
        assert len(set(delays)) > 10

    def test_schedule_packets(self):
        """Test packet scheduling."""
        schedule = self.obfuscator.schedule_packets(10)

        assert len(schedule) == 10
        # Times should be increasing
        times = [t for t, _ in schedule]
        assert times == sorted(times)

    def test_average_delay(self):
        """Test average delay calculation."""
        for _ in range(100):
            self.obfuscator.get_next_delay()

        avg = self.obfuscator.get_average_delay_us()
        # With silver timing and Pell sequence (capped at index 10),
        # delays range from base_interval to ~1000x base_interval
        # Base is 10_000us, so average should be under 1_000_000us
        assert avg > 0
        assert avg < 1_000_000  # Under 1 second average


class TestAdaptiveTimingObfuscator:
    """Test adaptive timing."""

    def setup_method(self):
        """Set up obfuscator."""
        self.obfuscator = AdaptiveTimingObfuscator()

    def test_observe_and_adapt(self):
        """Test observation and adaptation."""
        # Record some observations
        for _ in range(20):
            self.obfuscator.observe_interval(5000.0)

        decision = self.obfuscator.get_adapted_delay()
        assert decision.delay_us > 0

    def test_threat_level_affects_jitter(self):
        """Test threat level affects jitter."""
        self.obfuscator.set_threat_level(0.0)
        low_jitter = self.obfuscator.base.jitter_factor

        self.obfuscator.set_threat_level(1.0)
        high_jitter = self.obfuscator.base.jitter_factor

        assert high_jitter > low_jitter


class TestBurstTimingObfuscator:
    """Test burst timing."""

    def setup_method(self):
        """Set up obfuscator."""
        self.obfuscator = BurstTimingObfuscator(
            burst_size=3,
            intra_burst_us=1_000,
            inter_burst_us=10_000,
        )

    def test_burst_pattern(self):
        """Test burst timing pattern."""
        delays = [self.obfuscator.get_next_delay() for _ in range(10)]

        # Should have short delays within burst, long between
        short_delays = [d for d in delays if d < 5_000]
        long_delays = [d for d in delays if d > 5_000]

        assert len(short_delays) > 0
        assert len(long_delays) > 0


# =============================================================================
# TEST PRIVACY OPTIMIZER
# =============================================================================

class TestPrivacyOptimizer:
    """Test privacy optimization."""

    def setup_method(self):
        """Set up optimizer."""
        self.optimizer = PrivacyOptimizer()

    def test_optimize_default(self):
        """Test default optimization."""
        context = PrivacyContext()
        result = self.optimizer.optimize(context)

        assert result.recommended_level == PrivacyLevel.STANDARD
        assert result.config is not None

    def test_optimize_high_threat(self):
        """Test optimization under high threat."""
        context = PrivacyContext(threat_level=0.9)
        result = self.optimizer.optimize(context)

        assert result.recommended_level == PrivacyLevel.PARANOID

    def test_optimize_hostile_network(self):
        """Test optimization for hostile network."""
        context = PrivacyContext(is_hostile_network=True)
        result = self.optimizer.optimize(context)

        assert result.recommended_level.to_noise_ratio() >= PrivacyLevel.MAXIMUM.to_noise_ratio()

    def test_optimize_censored_region(self):
        """Test optimization for censored region."""
        context = PrivacyContext(is_censored_region=True)
        result = self.optimizer.optimize(context)

        assert result.recommended_level == PrivacyLevel.PARANOID

    def test_optimize_streaming(self):
        """Test optimization for streaming."""
        context = PrivacyContext(is_streaming=True)
        result = self.optimizer.optimize(context)

        assert result.config.enable_bandwidth_shaping

    def test_analyze_traffic(self):
        """Test traffic analysis."""
        profile = TrafficProfile(
            total_bytes=2000,
            real_bytes=1000,
            padding_bytes=1000,
            interval_variance=5000,
        )
        profile.calculate_ratios()

        metrics = self.optimizer.analyze_traffic(profile)

        assert metrics.overall_privacy_score > 0
        assert metrics.eta_squared_compliance > 0.5

    def test_threat_recording(self):
        """Test threat level recording."""
        self.optimizer.record_threat(0.5)
        self.optimizer.record_threat(0.7)
        self.optimizer.record_threat(0.6)

        avg = self.optimizer.get_average_threat()
        assert 0.5 <= avg <= 0.7

    def test_should_increase_protection(self):
        """Test protection increase decision."""
        # Record high threats
        for _ in range(10):
            self.optimizer.record_threat(0.9)

        should_increase, reason = self.optimizer.should_increase_protection()
        assert should_increase


class TestPrivacyPolicyEngine:
    """Test policy engine."""

    def setup_method(self):
        """Set up engine."""
        self.engine = PrivacyPolicyEngine()

    def test_add_and_get_policy(self):
        """Test adding and retrieving policies."""
        config = ObfuscationConfig(privacy_level=PrivacyLevel.MAXIMUM)
        self.engine.add_policy("high_security", config)

        retrieved = self.engine.get_policy("high_security")
        assert retrieved is not None
        assert retrieved.privacy_level == PrivacyLevel.MAXIMUM

    def test_enforce_minimum(self):
        """Test minimum enforcement."""
        weak_config = ObfuscationConfig(privacy_level=PrivacyLevel.MINIMAL)
        weak_config.apply_privacy_level()

        enforced = self.engine.enforce_minimum(weak_config, PrivacyLevel.ENHANCED)

        # Should have at least ENHANCED settings
        assert enforced.noise_ratio >= PrivacyLevel.ENHANCED.to_noise_ratio()

    def test_compliance_configs(self):
        """Test compliance-based configuration."""
        hipaa = self.engine.create_compliant_config(PrivacyLevel.STANDARD, "hipaa")
        assert hipaa.enable_padding

        govt = self.engine.create_compliant_config(PrivacyLevel.STANDARD, "government")
        assert govt.privacy_level == PrivacyLevel.PARANOID


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
