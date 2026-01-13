//! # Silver Timing
//!
//! Anti-fingerprinting timing system for ADZVPN-Opus.
//!
//! Uses the Silver Ratio (δ_S = 1 + √2) and Pell sequence to create
//! deterministic but non-obvious timing patterns that resist traffic analysis.
//!
//! ## Features
//!
//! - **τ-Scheduler**: Packet timing based on Pell sequence
//! - **Traffic Shaper**: Maintains η² + λ² = 1 bandwidth ratio
//! - **Silver Jitter**: Adds controlled randomness within silver bounds
//!
//! ## Why Silver Timing?
//!
//! Traditional VPN timing patterns are vulnerable to fingerprinting:
//! - Fixed intervals: trivially detectable
//! - Random intervals: statistically distinguishable
//! - Adaptive intervals: can leak information about traffic
//!
//! Silver timing uses the mathematical properties of the silver ratio
//! to create patterns that are:
//! - Deterministic (reproducible for debugging)
//! - Non-periodic (hard to fingerprint)
//! - Mathematically elegant (from COINjecture heritage)
//!
//! Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5

pub mod scheduler;
pub mod shaper;
pub mod jitter;
mod errors;

pub use scheduler::*;
pub use shaper::*;
pub use jitter::*;
pub use errors::*;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::scheduler::*;
    pub use crate::shaper::*;
    pub use crate::jitter::*;
    pub use crate::errors::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_core::{DELTA_S, TAU};

    #[test]
    fn test_silver_timing_constants() {
        // Verify we're using correct silver constants
        assert!((TAU - std::f64::consts::SQRT_2).abs() < 1e-10);
        assert!((DELTA_S - (1.0 + std::f64::consts::SQRT_2)).abs() < 1e-10);
    }

    #[tokio::test]
    async fn test_scheduler_creation() {
        let scheduler = SilverScheduler::new(10_000); // 10ms base
        assert!(scheduler.base_interval_us() > 0);
    }

    #[test]
    fn test_shaper_creation() {
        let shaper = TrafficShaper::new(1_000_000); // 1 Mbps
        assert_eq!(shaper.target_bandwidth(), 1_000_000);
    }

    #[test]
    fn test_jitter_bounds() {
        let jitter = SilverJitter::new(1000); // 1ms base
        for _ in 0..100 {
            let j = jitter.generate();
            // Jitter should be bounded by silver ratio
            assert!(j <= (1000.0 * DELTA_S) as u64);
        }
    }
}
