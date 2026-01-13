//! # Silver Core
//!
//! Mathematical foundation for ADZVPN-Opus, based on the Silver Ratio
//! framework from COINjecture's P2P protocol.
//!
//! ## Silver Ratio Constants
//!
//! The silver ratio (δ_S = 1 + √2) and related constants provide:
//! - Anti-fingerprinting timing patterns via Pell sequences
//! - Balanced traffic shaping (η² + λ² = 1)
//! - Elegant key derivation parameters
//!
//! ## Mathematical Properties
//!
//! ```text
//! Palindrome Identity: δ_S = τ² + 1/δ_S
//! Unit Magnitude: η² + λ² = 1
//! Balance Condition: |Re(μ)| = |Im(μ)|
//! Pell Convergence: lim(P(n+1)/P(n)) = δ_S
//! ```
//!
//! Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5

pub mod constants;
pub mod pell;
pub mod silver_math;

pub use constants::*;
pub use pell::*;
pub use silver_math::*;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::constants::*;
    pub use crate::pell::*;
    pub use crate::silver_math::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silver_constants_exist() {
        assert!(ETA > 0.0);
        assert!(TAU > 0.0);
        assert!(DELTA_S > 0.0);
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
    fn test_pell_convergence() {
        // Pell(20)/Pell(19) should be very close to δ_S
        let ratio = pell(21) as f64 / pell(20) as f64;
        assert!((ratio - DELTA_S).abs() < 1e-10);
    }
}
