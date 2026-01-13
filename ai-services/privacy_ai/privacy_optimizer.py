"""
Privacy Optimizer

AI-driven privacy optimization that adapts protection based on:
- Current threat level
- Traffic patterns
- User preferences
- Network conditions

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import DELTA_S, TAU, ETA, ETA_SQUARED, LAMBDA_SQUARED

from .models import (
    PrivacyLevel,
    ObfuscationConfig,
    TrafficProfile,
    PrivacyMetrics,
    ObfuscationResult,
)
from .noise_generator import SilverNoiseGenerator, SilverChaffGenerator
from .traffic_obfuscator import TrafficObfuscator, ConstantBandwidthObfuscator
from .timing_obfuscator import TimingObfuscator, AdaptiveTimingObfuscator


@dataclass
class PrivacyContext:
    """Context for privacy decisions."""
    # Threat assessment
    threat_level: float = 0.0          # 0-1
    is_hostile_network: bool = False
    is_censored_region: bool = False

    # Traffic characteristics
    is_streaming: bool = False
    is_interactive: bool = False
    is_bulk_transfer: bool = False

    # Network conditions
    bandwidth_limited: bool = False
    high_latency: bool = False

    # User preferences
    user_privacy_level: PrivacyLevel = PrivacyLevel.STANDARD
    prefer_performance: bool = False


@dataclass
class OptimizationResult:
    """Result of privacy optimization."""
    recommended_level: PrivacyLevel
    config: ObfuscationConfig
    reasoning: List[str]
    expected_overhead: float  # Bandwidth overhead factor
    privacy_score: float      # Expected privacy score (0-1)


class PrivacyOptimizer:
    """
    AI-driven privacy optimizer.

    Analyzes context and recommends optimal privacy settings
    using silver-weighted decision making.
    """

    def __init__(self):
        """Initialize the privacy optimizer."""
        # Components
        self.noise_gen = SilverNoiseGenerator()
        self.chaff_gen = SilverChaffGenerator(self.noise_gen)

        # State
        self._traffic_history: List[TrafficProfile] = []
        self._threat_history: List[Tuple[datetime, float]] = []
        self._current_config = ObfuscationConfig()

        # Decision weights (silver-based)
        self._weight_threat = DELTA_S      # Highest priority
        self._weight_network = TAU         # Medium priority
        self._weight_user = 1.0            # Base priority

    def optimize(self, context: PrivacyContext) -> OptimizationResult:
        """
        Optimize privacy settings for given context.

        Args:
            context: Current privacy context

        Returns:
            Optimization result with recommended settings
        """
        reasoning = []

        # Start with user preference
        base_level = context.user_privacy_level
        recommended_level = base_level
        reasoning.append(f"Starting with user preference: {base_level.value}")

        # Adjust for threat level
        if context.threat_level > 0.7:
            recommended_level = PrivacyLevel.PARANOID
            reasoning.append(f"High threat ({context.threat_level:.2f}): escalating to PARANOID")
        elif context.threat_level > 0.5:
            if recommended_level.to_noise_ratio() < PrivacyLevel.MAXIMUM.to_noise_ratio():
                recommended_level = PrivacyLevel.MAXIMUM
                reasoning.append(f"Elevated threat ({context.threat_level:.2f}): escalating to MAXIMUM")
        elif context.threat_level > 0.3:
            if recommended_level.to_noise_ratio() < PrivacyLevel.ENHANCED.to_noise_ratio():
                recommended_level = PrivacyLevel.ENHANCED
                reasoning.append(f"Moderate threat ({context.threat_level:.2f}): escalating to ENHANCED")

        # Hostile network adjustments
        if context.is_hostile_network:
            if recommended_level != PrivacyLevel.PARANOID:
                recommended_level = PrivacyLevel.MAXIMUM
                reasoning.append("Hostile network detected: using MAXIMUM")

        if context.is_censored_region:
            recommended_level = PrivacyLevel.PARANOID
            reasoning.append("Censored region: using PARANOID mode")

        # Performance adjustments
        if context.prefer_performance and recommended_level == PrivacyLevel.PARANOID:
            recommended_level = PrivacyLevel.MAXIMUM
            reasoning.append("Performance preference: downgrading from PARANOID")

        if context.bandwidth_limited:
            if recommended_level in [PrivacyLevel.PARANOID, PrivacyLevel.MAXIMUM]:
                recommended_level = PrivacyLevel.ENHANCED
                reasoning.append("Bandwidth limited: reducing to ENHANCED")

        if context.high_latency and context.is_interactive:
            if recommended_level.to_timing_jitter() > 0.3:
                reasoning.append("High latency + interactive: reducing timing jitter")

        # Traffic type adjustments
        if context.is_streaming:
            reasoning.append("Streaming detected: optimizing for consistent bandwidth")
        if context.is_bulk_transfer:
            reasoning.append("Bulk transfer: full obfuscation applied")

        # Build configuration
        config = self._build_config(recommended_level, context)

        # Calculate expected overhead
        overhead = self._calculate_overhead(config)

        # Calculate expected privacy score
        privacy_score = self._calculate_privacy_score(config, context)

        return OptimizationResult(
            recommended_level=recommended_level,
            config=config,
            reasoning=reasoning,
            expected_overhead=overhead,
            privacy_score=privacy_score,
        )

    def _build_config(
        self,
        level: PrivacyLevel,
        context: PrivacyContext,
    ) -> ObfuscationConfig:
        """Build configuration for given level and context."""
        config = ObfuscationConfig(privacy_level=level)
        config.apply_privacy_level()

        # Fine-tune based on context
        if context.is_streaming:
            # Constant bandwidth is good for streaming
            config.enable_bandwidth_shaping = True
            config.target_bandwidth_bps = 10_000_000  # 10 Mbps

        if context.is_interactive:
            # Reduce timing delays for responsiveness
            config.base_interval_us = 5_000  # 5ms instead of 10ms

        if context.is_bulk_transfer:
            # Maximum padding for bulk
            config.target_padding_ratio = LAMBDA_SQUARED

        if context.high_latency:
            # Don't add much timing overhead
            config.timing_jitter_factor = min(config.timing_jitter_factor, 0.1)

        return config

    def _calculate_overhead(self, config: ObfuscationConfig) -> float:
        """Calculate expected bandwidth overhead."""
        overhead = 1.0  # Base (no overhead)

        if config.enable_padding:
            # Padding adds ~100% in balanced mode
            overhead += config.target_padding_ratio / ETA_SQUARED

        if config.enable_noise_injection:
            # Noise adds additional overhead
            overhead += config.noise_ratio

        if config.enable_decoy_traffic:
            # Decoy adds significant overhead
            overhead += 0.5

        return overhead

    def _calculate_privacy_score(
        self,
        config: ObfuscationConfig,
        context: PrivacyContext,
    ) -> float:
        """Calculate expected privacy protection score."""
        score = 0.0

        # Padding protection
        if config.enable_padding:
            padding_score = min(config.target_padding_ratio / LAMBDA_SQUARED, 1.0)
            score += padding_score * 0.3

        # Timing protection
        if config.enable_timing_obfuscation:
            timing_score = min(config.timing_jitter_factor / 0.5, 1.0)
            score += timing_score * 0.3

        # Noise protection
        if config.enable_noise_injection:
            noise_score = min(config.noise_ratio, 1.0)
            score += noise_score * 0.2

        # Bandwidth shaping protection
        if config.enable_bandwidth_shaping:
            score += 0.1

        # Decoy protection
        if config.enable_decoy_traffic:
            score += 0.1

        return min(score, 1.0)

    def analyze_traffic(self, profile: TrafficProfile) -> PrivacyMetrics:
        """
        Analyze traffic profile and calculate privacy metrics.

        Args:
            profile: Current traffic profile

        Returns:
            Privacy metrics assessment
        """
        metrics = PrivacyMetrics()

        # Check silver compliance (η² ratio)
        if profile.total_bytes > 0:
            real_ratio = profile.real_bytes / profile.total_bytes
            metrics.eta_squared_compliance = 1.0 - abs(real_ratio - ETA_SQUARED) * 2

        # Timing entropy (based on variance)
        if profile.interval_variance > 0:
            # Higher variance = more entropy = better
            metrics.timing_entropy = min(profile.interval_variance / 10000, 1.0)

        # Size entropy (based on padding ratio)
        if profile.real_bytes > 0:
            size_ratio = profile.padding_bytes / profile.real_bytes
            metrics.size_entropy = min(size_ratio, 1.0)

        # Calculate protection scores
        metrics.timing_protection = metrics.timing_entropy * 0.8 + 0.2
        metrics.volume_protection = metrics.eta_squared_compliance
        metrics.pattern_protection = (metrics.timing_protection + metrics.volume_protection) / 2

        # Overall score
        metrics.calculate_overall()

        # Record history
        self._traffic_history.append(profile)
        if len(self._traffic_history) > 1000:
            self._traffic_history = self._traffic_history[-1000:]

        return metrics

    def record_threat(self, threat_level: float) -> None:
        """Record a threat level observation."""
        self._threat_history.append((datetime.utcnow(), threat_level))

        # Trim old entries
        cutoff = datetime.utcnow() - timedelta(hours=24)
        self._threat_history = [
            (t, l) for t, l in self._threat_history
            if t > cutoff
        ]

    def get_average_threat(self, window_minutes: int = 60) -> float:
        """Get average threat level over time window."""
        if not self._threat_history:
            return 0.0

        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        recent = [l for t, l in self._threat_history if t > cutoff]

        if not recent:
            return 0.0

        return sum(recent) / len(recent)

    def should_increase_protection(self) -> Tuple[bool, str]:
        """
        Determine if protection should be increased.

        Returns:
            Tuple of (should_increase, reason)
        """
        avg_threat = self.get_average_threat()

        if avg_threat > 0.7:
            return True, f"High average threat level: {avg_threat:.2f}"

        # Check for threat spikes
        if self._threat_history:
            recent_max = max(l for _, l in self._threat_history[-10:])
            if recent_max > 0.8:
                return True, f"Recent threat spike: {recent_max:.2f}"

        # Check traffic patterns
        if self._traffic_history:
            recent_profile = self._traffic_history[-1]
            if not recent_profile.is_balanced():
                return True, "Traffic not silver-balanced"

        return False, "Current protection adequate"


class PrivacyPolicyEngine:
    """
    Policy-based privacy enforcement.

    Enforces organizational privacy policies and compliance requirements.
    """

    def __init__(self):
        """Initialize policy engine."""
        self._policies: Dict[str, ObfuscationConfig] = {}
        self._default_policy = ObfuscationConfig()

    def add_policy(self, name: str, config: ObfuscationConfig) -> None:
        """Add a named policy."""
        self._policies[name] = config

    def get_policy(self, name: str) -> Optional[ObfuscationConfig]:
        """Get a named policy."""
        return self._policies.get(name)

    def enforce_minimum(self, config: ObfuscationConfig, minimum_level: PrivacyLevel) -> ObfuscationConfig:
        """Ensure config meets minimum privacy level."""
        min_config = ObfuscationConfig(privacy_level=minimum_level)
        min_config.apply_privacy_level()

        # Enforce minimums
        if config.noise_ratio < min_config.noise_ratio:
            config.noise_ratio = min_config.noise_ratio

        if config.timing_jitter_factor < min_config.timing_jitter_factor:
            config.timing_jitter_factor = min_config.timing_jitter_factor

        if not min_config.enable_padding:
            config.enable_padding = True

        return config

    def create_compliant_config(self, base_level: PrivacyLevel, compliance: str) -> ObfuscationConfig:
        """Create config compliant with specified standard."""
        config = ObfuscationConfig(privacy_level=base_level)
        config.apply_privacy_level()

        if compliance == "hipaa":
            # Healthcare: require encryption, padding
            config.enable_padding = True
            config.target_padding_ratio = 0.5
        elif compliance == "gdpr":
            # EU: strong privacy
            config.enable_padding = True
            config.enable_timing_obfuscation = True
        elif compliance == "financial":
            # Financial: maximum protection
            config.privacy_level = PrivacyLevel.MAXIMUM
            config.apply_privacy_level()
        elif compliance == "government":
            # Government: paranoid mode
            config.privacy_level = PrivacyLevel.PARANOID
            config.apply_privacy_level()

        return config
