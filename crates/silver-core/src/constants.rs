//! Silver Ratio Constants
//!
//! Core mathematical constants derived from the silver ratio (δ_S = 1 + √2),
//! originally developed for COINjecture's P2P protocol.
//!
//! These constants are used throughout ADZVPN-Opus for:
//! - Packet timing (anti-fingerprinting)
//! - Traffic shaping ratios
//! - Key derivation parameters
//! - Load balancing weights

use std::f64::consts::SQRT_2;

// =============================================================================
// PRIMARY CONSTANTS
// =============================================================================

/// η (eta) - Unit component: 1/√2
///
/// Used for balanced traffic calculations where η² represents
/// the real payload fraction of total traffic.
pub const ETA: f64 = 0.7071067811865476; // 1/√2

/// τ (tau) - Fundamental ratio: √2
///
/// The square root of 2, fundamental to all silver ratio calculations.
/// Used for timing intervals and load balancing weights.
pub const TAU: f64 = SQRT_2; // 1.4142135623730951

/// δ_S (delta_s) - The Silver Ratio: 1 + √2
///
/// The silver ratio, analogous to the golden ratio but based on √2.
/// This is the central constant of the ADZVPN-Opus protocol.
///
/// Properties:
/// - δ_S = 1 + √2 ≈ 2.414213562373095
/// - δ_S² = 3 + 2√2
/// - 1/δ_S = √2 - 1
/// - δ_S = τ² + 1/δ_S (palindrome identity)
pub const DELTA_S: f64 = 2.414213562373095; // 1 + √2

// =============================================================================
// SQUARED CONSTANTS (for traffic shaping)
// =============================================================================

/// η² - Real traffic ratio: 0.5
///
/// In balanced traffic mode, 50% of bandwidth is real payload.
/// This ensures η² + λ² = 1 (unit magnitude condition).
pub const ETA_SQUARED: f64 = 0.5;

/// λ² - Padding/chaff ratio: 0.5
///
/// In balanced traffic mode, 50% of bandwidth is padding/chaff.
/// Combined with η², this creates constant-bandwidth channels.
pub const LAMBDA_SQUARED: f64 = 0.5;

/// λ (lambda) - Padding component: 1/√2
///
/// Equal to η in the balanced configuration.
pub const LAMBDA: f64 = ETA;

// =============================================================================
// DERIVED CONSTANTS
// =============================================================================

/// 1/δ_S - Reciprocal of silver ratio: √2 - 1
///
/// Useful for various calculations. Note that 1/δ_S = √2 - 1 ≈ 0.4142135624
pub const DELTA_S_RECIPROCAL: f64 = 0.4142135623730951; // √2 - 1

/// τ² - Tau squared: 2
///
/// Simply 2, but named for clarity in formulas involving the palindrome identity.
pub const TAU_SQUARED: f64 = 2.0;

/// δ_S² - Silver ratio squared: 3 + 2√2
///
/// Useful for second-order calculations.
pub const DELTA_S_SQUARED: f64 = 5.82842712474619; // 3 + 2√2

// =============================================================================
// PROTOCOL CONSTANTS
// =============================================================================

/// Base KDF iteration multiplier
///
/// Silver KDF uses (DELTA_S * 1000) = 2414 iterations for key stretching.
pub const SILVER_KDF_MULTIPLIER: f64 = 1000.0;

/// Silver KDF iteration count
pub const SILVER_KDF_ITERATIONS: u32 = 2414; // floor(δ_S * 1000)

/// Tau mixing byte for KDF
///
/// Used as an additional mixing parameter in Silver KDF.
pub const TAU_MIX_BYTE: u8 = 181; // floor(τ * 128)

/// Silver timing base interval (microseconds)
///
/// Base interval for silver-timed packet scheduling.
pub const SILVER_TIMING_BASE_US: u64 = 1000; // 1ms base

/// Maximum Pell index for timing calculations
///
/// Pell sequence wraps at this index to prevent overflow.
pub const PELL_MAX_INDEX: u64 = 20;

// =============================================================================
// THRESHOLD CONSTANTS
// =============================================================================

/// Protocol switch threshold
///
/// Switch from UDP to QUIC when conditions exceed δ_S * base_threshold.
pub const PROTOCOL_SWITCH_THRESHOLD: f64 = DELTA_S;

/// Obfuscation trigger threshold
///
/// Enable enhanced obfuscation when risk score exceeds this value.
pub const OBFUSCATION_THRESHOLD: f64 = DELTA_S;

/// Latency threshold multiplier
///
/// Latency thresholds are set at τ * base_latency intervals.
pub const LATENCY_THRESHOLD_MULTIPLIER: f64 = TAU;

// =============================================================================
// VERIFICATION FUNCTIONS
// =============================================================================

/// Verify the palindrome identity: δ_S = τ² + 1/δ_S
///
/// This fundamental property of the silver ratio should always hold.
/// Used as a sanity check for constant integrity.
///
/// # Returns
/// `true` if the identity holds within floating-point tolerance
#[inline]
pub fn verify_palindrome_identity() -> bool {
    let lhs = DELTA_S;
    let rhs = TAU_SQUARED + DELTA_S_RECIPROCAL;
    (lhs - rhs).abs() < 1e-10
}

/// Verify unit magnitude condition: η² + λ² = 1
///
/// This ensures balanced traffic shaping is properly configured.
///
/// # Returns
/// `true` if the condition holds within floating-point tolerance
#[inline]
pub fn verify_unit_magnitude() -> bool {
    (ETA_SQUARED + LAMBDA_SQUARED - 1.0).abs() < 1e-10
}

/// Verify balance condition: |Re(μ)| = |Im(μ)|
///
/// For the complex number μ = -η + iλ, verify real and imaginary
/// parts have equal magnitude.
///
/// # Returns
/// `true` if balanced within floating-point tolerance
#[inline]
pub fn verify_balance_condition() -> bool {
    let re_magnitude = ETA; // |Re(μ)| = |-η| = η
    let im_magnitude = LAMBDA; // |Im(μ)| = |λ| = λ
    (re_magnitude - im_magnitude).abs() < 1e-10
}

/// Run all verification checks
///
/// # Returns
/// `true` if all mathematical properties hold
pub fn verify_all() -> bool {
    verify_palindrome_identity() && verify_unit_magnitude() && verify_balance_condition()
}

// =============================================================================
// DISPLAY HELPERS
// =============================================================================

/// Print all silver constants (for debugging)
pub fn print_constants() {
    println!("=== ADZVPN-Opus Silver Constants ===");
    println!("η (eta)        = {:.16}", ETA);
    println!("τ (tau)        = {:.16}", TAU);
    println!("δ_S (delta_s)  = {:.16}", DELTA_S);
    println!("η²             = {:.16}", ETA_SQUARED);
    println!("λ²             = {:.16}", LAMBDA_SQUARED);
    println!("1/δ_S          = {:.16}", DELTA_S_RECIPROCAL);
    println!("τ²             = {:.16}", TAU_SQUARED);
    println!("δ_S²           = {:.16}", DELTA_S_SQUARED);
    println!();
    println!("=== Verification ===");
    println!("Palindrome (δ_S = τ² + 1/δ_S): {}", verify_palindrome_identity());
    println!("Unit magnitude (η² + λ² = 1): {}", verify_unit_magnitude());
    println!("Balance (|Re| = |Im|): {}", verify_balance_condition());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eta_value() {
        assert!((ETA - 1.0 / SQRT_2).abs() < 1e-15);
    }

    #[test]
    fn test_tau_value() {
        assert!((TAU - SQRT_2).abs() < 1e-15);
    }

    #[test]
    fn test_delta_s_value() {
        assert!((DELTA_S - (1.0 + SQRT_2)).abs() < 1e-15);
    }

    #[test]
    fn test_delta_s_reciprocal() {
        assert!((DELTA_S_RECIPROCAL - (SQRT_2 - 1.0)).abs() < 1e-15);
        assert!((1.0 / DELTA_S - DELTA_S_RECIPROCAL).abs() < 1e-15);
    }

    #[test]
    fn test_palindrome_identity() {
        assert!(verify_palindrome_identity());
    }

    #[test]
    fn test_unit_magnitude() {
        assert!(verify_unit_magnitude());
    }

    #[test]
    fn test_balance_condition() {
        assert!(verify_balance_condition());
    }

    #[test]
    fn test_all_verifications() {
        assert!(verify_all());
    }

    #[test]
    fn test_kdf_iterations() {
        let expected = (DELTA_S * SILVER_KDF_MULTIPLIER) as u32;
        assert_eq!(SILVER_KDF_ITERATIONS, expected);
    }

    #[test]
    fn test_tau_mix_byte() {
        let expected = (TAU * 128.0) as u8;
        assert_eq!(TAU_MIX_BYTE, expected);
    }
}
