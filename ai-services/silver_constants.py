"""
Silver Ratio Constants for ADZVPN-Opus AI Services

Mathematical foundation from COINjecture P2P protocol.
These constants are used throughout the AI services for:
- Route scoring weights
- Timing intervals
- Traffic shaping ratios
- Anomaly detection thresholds

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import math
from typing import List, Tuple

# =============================================================================
# CORE SILVER CONSTANTS
# =============================================================================

# η (eta) - unit component: 1/√2
ETA: float = 1.0 / math.sqrt(2)  # ≈ 0.7071067811865476

# τ (tau) - fundamental ratio: √2
TAU: float = math.sqrt(2)  # ≈ 1.4142135623730951

# δ_S (delta_s) - silver ratio: 1 + √2
DELTA_S: float = 1.0 + math.sqrt(2)  # ≈ 2.414213562373095

# η² - for balanced traffic (real portion)
ETA_SQUARED: float = 0.5

# λ² - for balanced traffic (padding portion)
LAMBDA_SQUARED: float = 0.5

# =============================================================================
# DERIVED CONSTANTS
# =============================================================================

# Silver KDF iterations (δ_S * 1000)
SILVER_KDF_ITERATIONS: int = int(DELTA_S * 1000)  # 2414

# τ mixing byte for KDF
TAU_MIX_BYTE: int = int(TAU * 256) % 256  # 362 % 256 = 106

# Silver timing base (microseconds)
SILVER_TIMING_BASE_US: int = 10_000  # 10ms

# =============================================================================
# PELL SEQUENCE
# =============================================================================

def pell(n: int) -> int:
    """
    Generate nth Pell number.

    P(0) = 0, P(1) = 1, P(n) = 2*P(n-1) + P(n-2)

    Pell numbers converge to the silver ratio:
    lim(P(n+1)/P(n)) = δ_S as n → ∞
    """
    if n <= 0:
        return 0
    if n == 1:
        return 1

    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, 2 * b + a
    return b


def pell_sequence(count: int) -> List[int]:
    """Generate first `count` Pell numbers."""
    return [pell(i) for i in range(count)]


def silver_from_pell(n: int) -> float:
    """
    Approximate silver ratio from Pell number ratio.

    lim(P(n+1)/P(n)) = δ_S
    """
    if n < 1:
        return DELTA_S
    p_n = pell(n)
    p_n1 = pell(n + 1)
    if p_n == 0:
        return DELTA_S
    return p_n1 / p_n


# =============================================================================
# VERIFICATION FUNCTIONS
# =============================================================================

def verify_palindrome_identity() -> bool:
    """
    Verify the palindrome identity: δ_S = τ² + 1/δ_S

    This is a fundamental property of the silver ratio.
    """
    lhs = DELTA_S
    rhs = TAU * TAU + 1.0 / DELTA_S
    return abs(lhs - rhs) < 1e-10


def verify_unit_magnitude() -> bool:
    """
    Verify unit magnitude: η² + λ² = 1

    This ensures balanced traffic shaping.
    """
    return abs(ETA_SQUARED + LAMBDA_SQUARED - 1.0) < 1e-10


def verify_pell_convergence(tolerance: float = 0.0001) -> bool:
    """
    Verify Pell sequence converges to silver ratio.
    """
    approx = silver_from_pell(20)
    return abs(approx - DELTA_S) < tolerance


# =============================================================================
# SILVER MATH UTILITIES
# =============================================================================

def silver_weights(n: int) -> List[float]:
    """
    Generate silver-weighted distribution for n items.

    Weights cycle through: 1, τ, δ_S, 1*2, τ*2, δ_S*2, ...
    """
    weights = []
    for i in range(n):
        base = [1.0, TAU, DELTA_S][i % 3]
        multiplier = 1.0 + (i // 3)
        weights.append(base * multiplier)
    return weights


def silver_weights_normalized(n: int) -> List[float]:
    """
    Generate normalized silver weights (sum to 1.0).
    """
    weights = silver_weights(n)
    total = sum(weights)
    return [w / total for w in weights]


def silver_delay_us(packet_index: int, base_interval_us: int) -> int:
    """
    Calculate silver-timed delay for packet timing.

    Uses Pell sequence for anti-fingerprinting.
    """
    pell_val = pell(packet_index % 20)
    delay = base_interval_us * (1.0 + pell_val / DELTA_S)
    return int(delay)


def silver_padding(payload_size: int) -> int:
    """
    Calculate silver padding to maintain η² + λ² = 1.

    Real payload is η² of total, padding is λ² of total.
    """
    # payload_size = η² * total
    # total = payload_size / η²
    # padding = total - payload_size = payload_size * (1/η² - 1)
    #         = payload_size * (2 - 1) = payload_size * 1
    # When η² = λ² = 0.5, padding equals payload
    ratio = LAMBDA_SQUARED / ETA_SQUARED
    return int(payload_size * ratio)


def silver_score(
    latency_ms: float,
    bandwidth_mbps: float,
    load_percent: float,
    latency_base: float = 100.0,
    bandwidth_base: float = 100.0
) -> float:
    """
    Calculate silver-weighted route score.

    Uses δ_S, τ, and 1.0 as weights for latency, bandwidth, and load.
    Higher score = better route.

    Args:
        latency_ms: Route latency in milliseconds
        bandwidth_mbps: Available bandwidth in Mbps
        load_percent: Current server load (0-100)
        latency_base: Base latency for normalization
        bandwidth_base: Base bandwidth for normalization

    Returns:
        Normalized score between 0 and 1
    """
    # Latency score (lower is better, invert)
    latency_score = 1.0 / (1.0 + latency_ms / (TAU * latency_base))

    # Bandwidth score (higher is better)
    bandwidth_score = bandwidth_mbps / (DELTA_S * bandwidth_base)
    bandwidth_score = min(bandwidth_score, 1.0)  # Cap at 1.0

    # Load score (lower is better)
    load_score = (100.0 - load_percent) / 100.0

    # Silver-weighted combination
    total_weight = DELTA_S + TAU + 1.0
    score = (
        latency_score * DELTA_S +
        bandwidth_score * TAU +
        load_score * 1.0
    ) / total_weight

    return score


def silver_threshold(base: float, level: int = 1) -> float:
    """
    Calculate silver-scaled threshold.

    Each level multiplies by τ.
    """
    return base * (TAU ** level)


# =============================================================================
# SELF-TEST
# =============================================================================

if __name__ == "__main__":
    print("Silver Constants Verification")
    print("=" * 50)
    print(f"η (eta)     = {ETA:.10f}")
    print(f"τ (tau)     = {TAU:.10f}")
    print(f"δ_S         = {DELTA_S:.10f}")
    print(f"η²          = {ETA_SQUARED}")
    print(f"λ²          = {LAMBDA_SQUARED}")
    print()
    print("Verifications:")
    print(f"  Palindrome identity (δ_S = τ² + 1/δ_S): {verify_palindrome_identity()}")
    print(f"  Unit magnitude (η² + λ² = 1):          {verify_unit_magnitude()}")
    print(f"  Pell convergence to δ_S:               {verify_pell_convergence()}")
    print()
    print("Pell sequence (first 10):", pell_sequence(10))
    print(f"Silver from Pell(20): {silver_from_pell(20):.10f}")
    print()
    print("Example silver score:")
    score = silver_score(latency_ms=50, bandwidth_mbps=100, load_percent=30)
    print(f"  latency=50ms, bandwidth=100Mbps, load=30% -> score={score:.4f}")
