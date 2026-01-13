"""
Privacy AI Routes

AI-powered privacy optimization and traffic obfuscation endpoints.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import List, Optional
from enum import Enum

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from silver_constants import DELTA_S, TAU, ETA_SQUARED, LAMBDA_SQUARED
from privacy_ai import (
    PrivacyLevel,
    ObfuscationConfig,
    TrafficProfile,
    PrivacyMetrics,
    SilverNoiseGenerator,
    TrafficObfuscator,
    TimingObfuscator,
    PrivacyOptimizer,
)
from privacy_ai.noise_generator import SilverChaffGenerator
from privacy_ai.traffic_obfuscator import SizeBucketObfuscator, ConstantBandwidthObfuscator
from privacy_ai.timing_obfuscator import AdaptiveTimingObfuscator, BurstTimingObfuscator
from privacy_ai.privacy_optimizer import PrivacyContext, PrivacyPolicyEngine

router = APIRouter(prefix="/privacy")


# =============================================================================
# SINGLETONS
# =============================================================================

_optimizer: Optional[PrivacyOptimizer] = None
_policy_engine: Optional[PrivacyPolicyEngine] = None


def get_optimizer() -> PrivacyOptimizer:
    """Get or create optimizer singleton."""
    global _optimizer
    if _optimizer is None:
        _optimizer = PrivacyOptimizer()
    return _optimizer


def get_policy_engine() -> PrivacyPolicyEngine:
    """Get or create policy engine singleton."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PrivacyPolicyEngine()
    return _policy_engine


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class PrivacyLevelEnum(str, Enum):
    """Privacy level enum for API."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"
    PARANOID = "paranoid"


class OptimizeRequest(BaseModel):
    """Privacy optimization request."""
    threat_level: float = Field(default=0.0, ge=0, le=1)
    is_hostile_network: bool = False
    is_censored_region: bool = False
    is_streaming: bool = False
    is_interactive: bool = False
    is_bulk_transfer: bool = False
    bandwidth_limited: bool = False
    high_latency: bool = False
    user_privacy_level: PrivacyLevelEnum = PrivacyLevelEnum.STANDARD
    prefer_performance: bool = False


class OptimizeResponse(BaseModel):
    """Privacy optimization response."""
    recommended_level: str
    config: dict
    reasoning: List[str]
    expected_overhead: float
    privacy_score: float


class ObfuscateRequest(BaseModel):
    """Traffic obfuscation request."""
    data_size: int = Field(..., ge=1, le=1_000_000)
    privacy_level: PrivacyLevelEnum = PrivacyLevelEnum.STANDARD


class ObfuscateResponse(BaseModel):
    """Traffic obfuscation response."""
    original_size: int
    obfuscated_size: int
    padding_size: int
    silver_ratio_achieved: float
    overhead_percent: float


class TimingRequest(BaseModel):
    """Timing obfuscation request."""
    packet_count: int = Field(..., ge=1, le=1000)
    base_interval_us: int = Field(default=10000, ge=100, le=1_000_000)
    jitter_factor: float = Field(default=0.2, ge=0, le=1)


class TimingResponse(BaseModel):
    """Timing obfuscation response."""
    schedule: List[dict]
    average_delay_us: float
    total_duration_us: int
    uses_pell_sequence: bool


class TrafficProfileRequest(BaseModel):
    """Traffic profile analysis request."""
    total_bytes: int = Field(..., ge=0)
    real_bytes: int = Field(..., ge=0)
    padding_bytes: int = Field(default=0, ge=0)
    interval_variance: float = Field(default=0, ge=0)


class TrafficProfileResponse(BaseModel):
    """Traffic profile analysis response."""
    is_balanced: bool
    real_to_total_ratio: float
    padding_to_real_ratio: float
    eta_squared_compliance: float
    timing_entropy: float
    overall_privacy_score: float
    recommendations: List[str]


class NoiseRequest(BaseModel):
    """Noise generation request."""
    size: int = Field(..., ge=1, le=100_000)
    seed: Optional[int] = None


class NoiseResponse(BaseModel):
    """Noise generation response."""
    size: int
    seed_used: int
    distribution_score: float
    sample_hex: str


class ComplianceRequest(BaseModel):
    """Compliance configuration request."""
    base_level: PrivacyLevelEnum = PrivacyLevelEnum.STANDARD
    compliance_standard: str = Field(..., description="hipaa, gdpr, financial, or government")


class ComplianceResponse(BaseModel):
    """Compliance configuration response."""
    compliance_standard: str
    applied_level: str
    config: dict
    requirements_met: List[str]


# =============================================================================
# ROUTES
# =============================================================================

@router.get("/status")
async def privacy_status():
    """Get privacy service status."""
    return {
        "status": "operational",
        "version": "1.0.0",
        "features": [
            "silver_noise_generation",
            "traffic_obfuscation",
            "timing_obfuscation",
            "privacy_optimization",
            "compliance_policies",
        ],
        "silver_constants": {
            "eta_squared": ETA_SQUARED,
            "lambda_squared": LAMBDA_SQUARED,
            "balance_equation": "η² + λ² = 1",
        },
    }


@router.get("/levels")
async def get_privacy_levels():
    """Get available privacy levels and their characteristics."""
    return {
        "levels": [
            {
                "name": "minimal",
                "noise_ratio": 0.0,
                "timing_jitter": 0.0,
                "description": "Basic encryption only, no padding",
                "overhead": "0%",
                "use_case": "Maximum performance, trusted networks",
            },
            {
                "name": "standard",
                "noise_ratio": 0.2,
                "timing_jitter": 0.1,
                "description": "Padding + basic timing obfuscation",
                "overhead": "~20%",
                "use_case": "Default for most users",
            },
            {
                "name": "enhanced",
                "noise_ratio": 0.5,
                "timing_jitter": 0.2,
                "description": "Full traffic shaping with silver ratio",
                "overhead": "~50%",
                "use_case": "Privacy-conscious users",
            },
            {
                "name": "maximum",
                "noise_ratio": 1.0,
                "timing_jitter": 0.3,
                "description": "Constant bandwidth mode (η² + λ² = 1)",
                "overhead": "100%",
                "use_case": "High-security environments",
            },
            {
                "name": "paranoid",
                "noise_ratio": 1.5,
                "timing_jitter": 0.5,
                "description": "Maximum + decoy traffic generation",
                "overhead": ">100%",
                "use_case": "Hostile networks, censored regions",
            },
        ],
        "recommendation": "Use 'standard' for everyday use, 'enhanced' for sensitive activities",
    }


@router.post("/optimize", response_model=OptimizeResponse)
async def optimize_privacy(request: OptimizeRequest):
    """
    Get AI-optimized privacy settings for current context.

    Analyzes:
    - Threat level
    - Network conditions
    - Traffic type
    - User preferences

    Returns optimal privacy configuration.
    """
    optimizer = get_optimizer()

    # Map API enum to internal enum
    level_map = {
        PrivacyLevelEnum.MINIMAL: PrivacyLevel.MINIMAL,
        PrivacyLevelEnum.STANDARD: PrivacyLevel.STANDARD,
        PrivacyLevelEnum.ENHANCED: PrivacyLevel.ENHANCED,
        PrivacyLevelEnum.MAXIMUM: PrivacyLevel.MAXIMUM,
        PrivacyLevelEnum.PARANOID: PrivacyLevel.PARANOID,
    }

    context = PrivacyContext(
        threat_level=request.threat_level,
        is_hostile_network=request.is_hostile_network,
        is_censored_region=request.is_censored_region,
        is_streaming=request.is_streaming,
        is_interactive=request.is_interactive,
        is_bulk_transfer=request.is_bulk_transfer,
        bandwidth_limited=request.bandwidth_limited,
        high_latency=request.high_latency,
        user_privacy_level=level_map[request.user_privacy_level],
        prefer_performance=request.prefer_performance,
    )

    result = optimizer.optimize(context)

    # Convert config to dict
    config_dict = {
        "privacy_level": result.config.privacy_level.value,
        "enable_padding": result.config.enable_padding,
        "target_padding_ratio": result.config.target_padding_ratio,
        "enable_timing_obfuscation": result.config.enable_timing_obfuscation,
        "timing_jitter_factor": result.config.timing_jitter_factor,
        "enable_noise_injection": result.config.enable_noise_injection,
        "noise_ratio": result.config.noise_ratio,
        "enable_decoy_traffic": result.config.enable_decoy_traffic,
        "enable_bandwidth_shaping": result.config.enable_bandwidth_shaping,
    }

    return OptimizeResponse(
        recommended_level=result.recommended_level.value,
        config=config_dict,
        reasoning=result.reasoning,
        expected_overhead=result.expected_overhead,
        privacy_score=result.privacy_score,
    )


@router.post("/obfuscate", response_model=ObfuscateResponse)
async def obfuscate_traffic(request: ObfuscateRequest):
    """
    Calculate obfuscation parameters for given data size.

    Uses silver ratio padding to achieve η² + λ² = 1 balance.
    """
    level_map = {
        PrivacyLevelEnum.MINIMAL: PrivacyLevel.MINIMAL,
        PrivacyLevelEnum.STANDARD: PrivacyLevel.STANDARD,
        PrivacyLevelEnum.ENHANCED: PrivacyLevel.ENHANCED,
        PrivacyLevelEnum.MAXIMUM: PrivacyLevel.MAXIMUM,
        PrivacyLevelEnum.PARANOID: PrivacyLevel.PARANOID,
    }

    config = ObfuscationConfig(privacy_level=level_map[request.privacy_level])
    config.apply_privacy_level()

    obfuscator = TrafficObfuscator(config=config)

    # Create dummy data to calculate obfuscation
    dummy_data = b"X" * request.data_size
    result = obfuscator.obfuscate(dummy_data)

    overhead = ((result.obfuscated_size - result.original_size) / result.original_size) * 100

    return ObfuscateResponse(
        original_size=result.original_size,
        obfuscated_size=result.obfuscated_size,
        padding_size=result.padding_size,
        silver_ratio_achieved=result.silver_ratio_achieved,
        overhead_percent=overhead,
    )


@router.post("/timing", response_model=TimingResponse)
async def calculate_timing(request: TimingRequest):
    """
    Calculate timing schedule for packet transmission.

    Uses Pell sequence for anti-fingerprinting:
    P(n) = 2P(n-1) + P(n-2), converges to δ_S
    """
    obfuscator = TimingObfuscator(
        base_interval_us=request.base_interval_us,
        jitter_factor=request.jitter_factor,
    )

    schedule = obfuscator.schedule_packets(request.packet_count)

    # Format schedule
    formatted_schedule = [
        {"packet_index": idx, "time_us": time_us}
        for time_us, idx in schedule
    ]

    # Calculate stats
    total_duration = schedule[-1][0] if schedule else 0
    avg_delay = obfuscator.get_average_delay_us()

    return TimingResponse(
        schedule=formatted_schedule,
        average_delay_us=avg_delay,
        total_duration_us=total_duration,
        uses_pell_sequence=True,
    )


@router.post("/analyze-profile", response_model=TrafficProfileResponse)
async def analyze_traffic_profile(request: TrafficProfileRequest):
    """
    Analyze traffic profile for privacy compliance.

    Checks if traffic maintains silver ratio balance.
    """
    optimizer = get_optimizer()

    profile = TrafficProfile(
        total_bytes=request.total_bytes,
        real_bytes=request.real_bytes,
        padding_bytes=request.padding_bytes,
        interval_variance=request.interval_variance,
    )
    profile.calculate_ratios()

    metrics = optimizer.analyze_traffic(profile)

    # Build recommendations
    recommendations = []
    if not profile.is_balanced():
        recommendations.append("Traffic is not silver-balanced")
        recommendations.append(f"Target ratio: {ETA_SQUARED:.2f} real / {LAMBDA_SQUARED:.2f} padding")

    if metrics.eta_squared_compliance < 0.8:
        recommendations.append("Increase padding to improve η² compliance")

    if metrics.timing_entropy < 0.5:
        recommendations.append("Add more timing variation for better entropy")

    if not recommendations:
        recommendations.append("Traffic profile meets silver ratio standards")

    return TrafficProfileResponse(
        is_balanced=profile.is_balanced(),
        real_to_total_ratio=profile.real_to_total_ratio,
        padding_to_real_ratio=profile.padding_to_real_ratio,
        eta_squared_compliance=metrics.eta_squared_compliance,
        timing_entropy=metrics.timing_entropy,
        overall_privacy_score=metrics.overall_privacy_score,
        recommendations=recommendations,
    )


@router.post("/generate-noise", response_model=NoiseResponse)
async def generate_noise(request: NoiseRequest):
    """
    Generate silver-seeded noise data.

    Produces deterministic but random-looking bytes
    using silver ratio mathematics.
    """
    gen = SilverNoiseGenerator(seed=request.seed)
    data = gen.generate_bytes(request.size)

    # Calculate distribution score
    score = gen.verify_silver_distribution(data)

    # Get sample (first 32 bytes as hex)
    sample_hex = data[:32].hex()

    return NoiseResponse(
        size=len(data),
        seed_used=gen.seed,
        distribution_score=score,
        sample_hex=sample_hex,
    )


@router.post("/compliance", response_model=ComplianceResponse)
async def get_compliance_config(request: ComplianceRequest):
    """
    Get privacy configuration for compliance standard.

    Supported standards:
    - hipaa: Healthcare data protection
    - gdpr: EU data protection
    - financial: Financial data requirements
    - government: Government/classified requirements
    """
    engine = get_policy_engine()

    valid_standards = ["hipaa", "gdpr", "financial", "government"]
    if request.compliance_standard not in valid_standards:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid compliance standard. Use one of: {valid_standards}",
        )

    level_map = {
        PrivacyLevelEnum.MINIMAL: PrivacyLevel.MINIMAL,
        PrivacyLevelEnum.STANDARD: PrivacyLevel.STANDARD,
        PrivacyLevelEnum.ENHANCED: PrivacyLevel.ENHANCED,
        PrivacyLevelEnum.MAXIMUM: PrivacyLevel.MAXIMUM,
        PrivacyLevelEnum.PARANOID: PrivacyLevel.PARANOID,
    }

    config = engine.create_compliant_config(
        level_map[request.base_level],
        request.compliance_standard,
    )

    # Build requirements met list
    requirements = []
    if config.enable_padding:
        requirements.append("Traffic padding enabled")
    if config.enable_timing_obfuscation:
        requirements.append("Timing obfuscation enabled")
    if config.enable_noise_injection:
        requirements.append("Noise injection enabled")
    if config.privacy_level in [PrivacyLevel.MAXIMUM, PrivacyLevel.PARANOID]:
        requirements.append("Maximum protection level")

    config_dict = {
        "privacy_level": config.privacy_level.value,
        "enable_padding": config.enable_padding,
        "target_padding_ratio": config.target_padding_ratio,
        "enable_timing_obfuscation": config.enable_timing_obfuscation,
        "enable_noise_injection": config.enable_noise_injection,
    }

    return ComplianceResponse(
        compliance_standard=request.compliance_standard,
        applied_level=config.privacy_level.value,
        config=config_dict,
        requirements_met=requirements,
    )


@router.get("/silver-balance")
async def get_silver_balance_info():
    """
    Get information about silver ratio traffic balance.

    Explains the η² + λ² = 1 identity used for traffic shaping.
    """
    return {
        "identity": "η² + λ² = 1",
        "components": {
            "eta_squared": {
                "value": ETA_SQUARED,
                "meaning": "Real traffic portion",
                "percentage": f"{ETA_SQUARED * 100}%",
            },
            "lambda_squared": {
                "value": LAMBDA_SQUARED,
                "meaning": "Padding/noise portion",
                "percentage": f"{LAMBDA_SQUARED * 100}%",
            },
        },
        "balance_explanation": (
            "In balanced mode, exactly 50% of bandwidth is real data "
            "and 50% is silver-generated padding. This makes traffic "
            "analysis extremely difficult because observers cannot "
            "distinguish real packets from noise."
        ),
        "benefits": [
            "Prevents bandwidth-based traffic analysis",
            "Hides actual data transfer volumes",
            "Makes timing correlation attacks harder",
            "Provides mathematical guarantee of balance",
        ],
    }
