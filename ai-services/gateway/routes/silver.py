"""
Silver Math Routes

Endpoints for silver ratio calculations and verification.
"""

import sys
from pathlib import Path
from typing import List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from silver_constants import (
    DELTA_S, TAU, ETA, ETA_SQUARED, LAMBDA_SQUARED,
    pell, pell_sequence, silver_from_pell,
    silver_weights, silver_weights_normalized,
    silver_delay_us, silver_padding, silver_score,
    verify_palindrome_identity, verify_unit_magnitude, verify_pell_convergence,
)


router = APIRouter(prefix="/silver")


# =============================================================================
# MODELS
# =============================================================================

class ConstantsResponse(BaseModel):
    """Silver constants."""
    eta: float = Field(description="η = 1/√2")
    tau: float = Field(description="τ = √2")
    delta_s: float = Field(description="δ_S = 1 + √2")
    eta_squared: float = Field(description="η² = 0.5")
    lambda_squared: float = Field(description="λ² = 0.5")


class VerificationResponse(BaseModel):
    """Verification results."""
    palindrome_identity: bool = Field(description="δ_S = τ² + 1/δ_S")
    unit_magnitude: bool = Field(description="η² + λ² = 1")
    pell_convergence: bool = Field(description="lim(P(n+1)/P(n)) = δ_S")
    all_valid: bool


class PellResponse(BaseModel):
    """Pell sequence response."""
    n: int
    pell_n: int
    sequence: List[int]
    silver_approx: float
    convergence_error: float


class WeightsResponse(BaseModel):
    """Silver weights response."""
    count: int
    weights: List[float]
    normalized: List[float]
    total: float


class TimingResponse(BaseModel):
    """Silver timing response."""
    packet_index: int
    base_interval_us: int
    delay_us: int
    delay_ms: float


class PaddingResponse(BaseModel):
    """Silver padding response."""
    payload_size: int
    padding_size: int
    total_size: int
    payload_ratio: float
    padding_ratio: float


class ScoreRequest(BaseModel):
    """Route score request."""
    latency_ms: float = Field(ge=0, description="Latency in milliseconds")
    bandwidth_mbps: float = Field(ge=0, description="Bandwidth in Mbps")
    load_percent: float = Field(ge=0, le=100, description="Load percentage")


class ScoreResponse(BaseModel):
    """Route score response."""
    score: float
    latency_component: float
    bandwidth_component: float
    load_component: float
    weights: dict


# =============================================================================
# ROUTES
# =============================================================================

@router.get("/constants", response_model=ConstantsResponse)
async def get_constants():
    """Get all silver ratio constants."""
    return ConstantsResponse(
        eta=ETA,
        tau=TAU,
        delta_s=DELTA_S,
        eta_squared=ETA_SQUARED,
        lambda_squared=LAMBDA_SQUARED,
    )


@router.get("/verify", response_model=VerificationResponse)
async def verify_constants():
    """Verify silver ratio mathematical identities."""
    palindrome = verify_palindrome_identity()
    unit_mag = verify_unit_magnitude()
    pell_conv = verify_pell_convergence()

    return VerificationResponse(
        palindrome_identity=palindrome,
        unit_magnitude=unit_mag,
        pell_convergence=pell_conv,
        all_valid=palindrome and unit_mag and pell_conv,
    )


@router.get("/pell", response_model=PellResponse)
async def get_pell(n: int = Query(default=10, ge=0, le=30, description="Pell index")):
    """
    Get Pell number and sequence.

    Pell sequence: P(0)=0, P(1)=1, P(n)=2P(n-1)+P(n-2)
    Converges to silver ratio.
    """
    pell_n = pell(n)
    seq = pell_sequence(min(n + 1, 15))
    silver_approx = silver_from_pell(n) if n > 0 else DELTA_S

    return PellResponse(
        n=n,
        pell_n=pell_n,
        sequence=seq,
        silver_approx=silver_approx,
        convergence_error=abs(silver_approx - DELTA_S),
    )


@router.get("/weights", response_model=WeightsResponse)
async def get_weights(count: int = Query(default=5, ge=1, le=20, description="Number of weights")):
    """
    Generate silver-weighted distribution.

    Weights cycle through: 1, τ, δ_S, 1*2, τ*2, δ_S*2, ...
    """
    weights = silver_weights(count)
    normalized = silver_weights_normalized(count)

    return WeightsResponse(
        count=count,
        weights=weights,
        normalized=normalized,
        total=sum(weights),
    )


@router.get("/timing", response_model=TimingResponse)
async def get_timing(
    packet_index: int = Query(default=0, ge=0, description="Packet index"),
    base_interval_us: int = Query(default=10000, ge=100, description="Base interval in microseconds"),
):
    """
    Calculate silver-timed delay for anti-fingerprinting.

    Uses Pell sequence to generate non-obvious but deterministic timing.
    """
    delay = silver_delay_us(packet_index, base_interval_us)

    return TimingResponse(
        packet_index=packet_index,
        base_interval_us=base_interval_us,
        delay_us=delay,
        delay_ms=delay / 1000.0,
    )


@router.get("/padding", response_model=PaddingResponse)
async def get_padding(payload_size: int = Query(default=1000, ge=1, description="Payload size in bytes")):
    """
    Calculate silver padding to maintain η² + λ² = 1.

    Real payload is η² of total, padding is λ² of total.
    When balanced (η² = λ² = 0.5), padding equals payload.
    """
    padding = silver_padding(payload_size)
    total = payload_size + padding

    return PaddingResponse(
        payload_size=payload_size,
        padding_size=padding,
        total_size=total,
        payload_ratio=payload_size / total,
        padding_ratio=padding / total,
    )


@router.post("/score", response_model=ScoreResponse)
async def calculate_score(request: ScoreRequest):
    """
    Calculate silver-weighted route score.

    Uses δ_S, τ, and 1.0 as weights for latency, bandwidth, and load.
    Higher score = better route.
    """
    # Calculate component scores
    latency_score = 1.0 / (1.0 + request.latency_ms / (TAU * 100))
    bandwidth_score = min(request.bandwidth_mbps / (DELTA_S * 100), 1.0)
    load_score = (100.0 - request.load_percent) / 100.0

    # Combined score
    score = silver_score(
        request.latency_ms,
        request.bandwidth_mbps,
        request.load_percent,
    )

    return ScoreResponse(
        score=score,
        latency_component=latency_score,
        bandwidth_component=bandwidth_score,
        load_component=load_score,
        weights={
            "latency_weight": DELTA_S,
            "bandwidth_weight": TAU,
            "load_weight": 1.0,
        },
    )
