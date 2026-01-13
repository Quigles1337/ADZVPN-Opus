"""
ADZVPN-Opus Privacy AI

Privacy-preserving traffic obfuscation using Silver Ratio mathematics.

Components:
- SilverNoiseGenerator: Generate silver-seeded chaff data
- TrafficObfuscator: Obfuscate traffic patterns
- TimingObfuscator: Silver-ratio timing for anti-fingerprinting
- PrivacyOptimizer: AI-driven privacy optimization
"""

from .models import (
    PrivacyLevel,
    ObfuscationConfig,
    TrafficProfile,
    PrivacyMetrics,
    ObfuscationResult,
)
from .noise_generator import SilverNoiseGenerator
from .traffic_obfuscator import TrafficObfuscator
from .timing_obfuscator import TimingObfuscator
from .privacy_optimizer import PrivacyOptimizer

__all__ = [
    # Models
    "PrivacyLevel",
    "ObfuscationConfig",
    "TrafficProfile",
    "PrivacyMetrics",
    "ObfuscationResult",
    # Components
    "SilverNoiseGenerator",
    "TrafficObfuscator",
    "TimingObfuscator",
    "PrivacyOptimizer",
]
