"""
Privacy AI Models

Data models for privacy-preserving traffic obfuscation.
"""

import sys
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import DELTA_S, TAU, ETA, ETA_SQUARED, LAMBDA_SQUARED


class PrivacyLevel(Enum):
    """Privacy protection level."""
    MINIMAL = "minimal"      # Basic encryption only
    STANDARD = "standard"    # Padding + basic timing
    ENHANCED = "enhanced"    # Full traffic shaping
    MAXIMUM = "maximum"      # Constant bandwidth mode
    PARANOID = "paranoid"    # Maximum + decoy traffic

    def to_noise_ratio(self) -> float:
        """Get noise injection ratio for this level."""
        return {
            PrivacyLevel.MINIMAL: 0.0,
            PrivacyLevel.STANDARD: 0.2,
            PrivacyLevel.ENHANCED: 0.5,
            PrivacyLevel.MAXIMUM: 1.0,      # η²/λ² balanced
            PrivacyLevel.PARANOID: 1.5,     # Extra noise
        }[self]

    def to_timing_jitter(self) -> float:
        """Get timing jitter factor for this level."""
        return {
            PrivacyLevel.MINIMAL: 0.0,
            PrivacyLevel.STANDARD: 0.1,
            PrivacyLevel.ENHANCED: 0.3,
            PrivacyLevel.MAXIMUM: 0.5,
            PrivacyLevel.PARANOID: TAU - 1,  # ~0.414 (silver-derived)
        }[self]


@dataclass
class ObfuscationConfig:
    """Configuration for traffic obfuscation."""
    # Privacy level
    privacy_level: PrivacyLevel = PrivacyLevel.STANDARD

    # Padding settings
    enable_padding: bool = True
    target_padding_ratio: float = LAMBDA_SQUARED  # 0.5 for balanced
    min_packet_size: int = 64
    max_packet_size: int = 1500

    # Timing settings
    enable_timing_obfuscation: bool = True
    base_interval_us: int = 10_000  # 10ms
    timing_jitter_factor: float = 0.2

    # Noise injection
    enable_noise_injection: bool = True
    noise_ratio: float = 0.3  # 30% noise packets
    noise_pattern: str = "silver"  # silver, random, constant

    # Bandwidth shaping
    enable_bandwidth_shaping: bool = False
    target_bandwidth_bps: int = 10_000_000  # 10 Mbps
    bandwidth_variance: float = 0.1

    # Decoy traffic
    enable_decoy_traffic: bool = False
    decoy_interval_secs: float = 5.0

    def apply_privacy_level(self) -> None:
        """Apply settings based on privacy level."""
        level = self.privacy_level

        self.noise_ratio = level.to_noise_ratio()
        self.timing_jitter_factor = level.to_timing_jitter()

        if level == PrivacyLevel.MINIMAL:
            self.enable_padding = False
            self.enable_timing_obfuscation = False
            self.enable_noise_injection = False
        elif level == PrivacyLevel.STANDARD:
            self.enable_padding = True
            self.enable_timing_obfuscation = True
            self.enable_noise_injection = False
        elif level == PrivacyLevel.ENHANCED:
            self.enable_padding = True
            self.enable_timing_obfuscation = True
            self.enable_noise_injection = True
        elif level == PrivacyLevel.MAXIMUM:
            self.enable_padding = True
            self.enable_timing_obfuscation = True
            self.enable_noise_injection = True
            self.enable_bandwidth_shaping = True
        elif level == PrivacyLevel.PARANOID:
            self.enable_padding = True
            self.enable_timing_obfuscation = True
            self.enable_noise_injection = True
            self.enable_bandwidth_shaping = True
            self.enable_decoy_traffic = True


@dataclass
class TrafficProfile:
    """
    Traffic profile for analysis.

    Used to understand traffic patterns before obfuscation.
    """
    # Volume
    total_bytes: int = 0
    real_bytes: int = 0
    padding_bytes: int = 0
    noise_bytes: int = 0

    # Packets
    total_packets: int = 0
    real_packets: int = 0
    noise_packets: int = 0

    # Timing
    avg_interval_ms: float = 0.0
    interval_variance: float = 0.0
    min_interval_ms: float = 0.0
    max_interval_ms: float = 0.0

    # Ratios (silver metrics)
    real_to_total_ratio: float = 1.0    # Should be ~η² when obfuscated
    padding_to_real_ratio: float = 0.0  # Should be ~1 when balanced

    def calculate_ratios(self) -> None:
        """Calculate silver ratios."""
        if self.total_bytes > 0:
            self.real_to_total_ratio = self.real_bytes / self.total_bytes
        if self.real_bytes > 0:
            self.padding_to_real_ratio = self.padding_bytes / self.real_bytes

    def is_balanced(self, tolerance: float = 0.1) -> bool:
        """Check if traffic is silver-balanced (η² + λ² = 1)."""
        expected_ratio = ETA_SQUARED  # 0.5
        return abs(self.real_to_total_ratio - expected_ratio) < tolerance


@dataclass
class PrivacyMetrics:
    """Metrics for privacy assessment."""
    # Entropy metrics
    timing_entropy: float = 0.0       # Higher = harder to fingerprint
    size_entropy: float = 0.0         # Higher = more uniform sizes
    pattern_entropy: float = 0.0      # Higher = less predictable

    # Protection scores (0-1)
    timing_protection: float = 0.0    # Against timing analysis
    volume_protection: float = 0.0    # Against volume analysis
    pattern_protection: float = 0.0   # Against pattern analysis

    # Overall score
    overall_privacy_score: float = 0.0

    # Silver compliance
    eta_squared_compliance: float = 0.0  # How close to η² ratio
    timing_silver_compliance: float = 0.0  # How well timing follows silver

    def calculate_overall(self) -> None:
        """Calculate overall privacy score using silver weights."""
        total_weight = DELTA_S + TAU + 1.0
        self.overall_privacy_score = (
            self.timing_protection * DELTA_S +
            self.volume_protection * TAU +
            self.pattern_protection * 1.0
        ) / total_weight


@dataclass
class ObfuscationResult:
    """Result of traffic obfuscation."""
    # Original data
    original_size: int = 0
    original_data: Optional[bytes] = None

    # Obfuscated data
    obfuscated_size: int = 0
    obfuscated_data: Optional[bytes] = None

    # Padding info
    padding_size: int = 0
    padding_type: str = "silver"

    # Timing info
    suggested_delay_us: int = 0
    timing_pattern: str = "pell"

    # Noise info
    is_noise_packet: bool = False
    noise_seed: int = 0

    # Metrics
    size_overhead: float = 0.0
    silver_ratio_achieved: float = 0.0

    def calculate_metrics(self) -> None:
        """Calculate obfuscation metrics."""
        if self.original_size > 0:
            self.size_overhead = (self.obfuscated_size - self.original_size) / self.original_size
            # Silver ratio: real portion should be η² of total
            self.silver_ratio_achieved = self.original_size / self.obfuscated_size


@dataclass
class NoisePacket:
    """A noise/decoy packet."""
    data: bytes = field(default_factory=bytes)
    size: int = 0
    seed: int = 0
    pattern: str = "silver"
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        if self.data and self.size == 0:
            self.size = len(self.data)
