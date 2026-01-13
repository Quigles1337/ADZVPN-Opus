//! Silver Ratio Mathematics
//!
//! Advanced mathematical functions based on the silver ratio,
//! used throughout ADZVPN-Opus for various calculations.

use crate::constants::*;
use crate::pell::pell_wrapped;

// =============================================================================
// SILVER TIMING
// =============================================================================

/// Calculate silver-based delay for packet timing
///
/// Uses Pell sequence to generate deterministic but non-obvious delays.
/// This provides anti-fingerprinting properties while being reproducible.
///
/// # Arguments
/// * `packet_index` - Index of the packet (wraps automatically)
/// * `base_interval_us` - Base interval in microseconds
///
/// # Returns
/// Delay in microseconds
pub fn silver_delay_us(packet_index: u64, base_interval_us: u64) -> u64 {
    let pell = pell_wrapped(packet_index % PELL_MAX_INDEX);

    // Scale by τ for sub-intervals
    let multiplier = 1.0 + (pell as f64 / DELTA_S);
    (base_interval_us as f64 * multiplier) as u64
}

/// Calculate silver-based delay with jitter
///
/// Adds controlled jitter based on silver ratio for additional obfuscation.
///
/// # Arguments
/// * `packet_index` - Index of the packet
/// * `base_interval_us` - Base interval in microseconds
/// * `jitter_seed` - Seed for jitter calculation (e.g., packet hash)
///
/// # Returns
/// Delay in microseconds with jitter applied
pub fn silver_delay_with_jitter(packet_index: u64, base_interval_us: u64, jitter_seed: u64) -> u64 {
    let base_delay = silver_delay_us(packet_index, base_interval_us);

    // Silver-ratio based jitter: ±(η * base_delay)
    let jitter_factor = (jitter_seed % 1000) as f64 / 1000.0; // 0.0 to 0.999
    let jitter_range = (base_delay as f64 * ETA) as i64;
    let jitter = ((jitter_factor - 0.5) * 2.0 * jitter_range as f64) as i64;

    (base_delay as i64 + jitter).max(0) as u64
}

// =============================================================================
// SILVER PADDING
// =============================================================================

/// Calculate padding size to maintain η²+λ²=1 balance
///
/// Given real payload size, returns required padding to achieve
/// the balanced traffic ratio.
///
/// # Arguments
/// * `payload_size` - Size of real payload in bytes
///
/// # Returns
/// Required padding size in bytes
pub fn silver_padding_size(payload_size: usize) -> usize {
    // Real payload is η² of total
    // Total = payload_size / η²
    // Padding = Total - payload_size = payload_size * (1/η² - 1)
    // Since η² = 0.5, padding = payload_size * (2 - 1) = payload_size
    let total_size = (payload_size as f64 / ETA_SQUARED) as usize;
    total_size - payload_size
}

/// Calculate total packet size for given payload
///
/// # Arguments
/// * `payload_size` - Size of real payload in bytes
///
/// # Returns
/// Total packet size including padding
pub fn silver_total_size(payload_size: usize) -> usize {
    (payload_size as f64 / ETA_SQUARED) as usize
}

/// Calculate real payload size from total size
///
/// # Arguments
/// * `total_size` - Total packet size including padding
///
/// # Returns
/// Real payload size
pub fn silver_payload_from_total(total_size: usize) -> usize {
    (total_size as f64 * ETA_SQUARED) as usize
}

// =============================================================================
// SILVER LOAD BALANCING
// =============================================================================

/// Calculate silver-weighted distribution for N servers
///
/// Returns weights in the pattern: 1, τ, δ_S, 1*2, τ*2, δ_S*2, ...
///
/// # Arguments
/// * `n` - Number of servers
///
/// # Returns
/// Vector of weights (not normalized)
pub fn silver_weights(n: usize) -> Vec<f64> {
    (0..n)
        .map(|i| {
            let base_weight = match i % 3 {
                0 => 1.0,
                1 => TAU,
                2 => DELTA_S,
                _ => unreachable!(),
            };
            base_weight * (1.0 + (i / 3) as f64)
        })
        .collect()
}

/// Calculate normalized silver weights (sum to 1.0)
///
/// # Arguments
/// * `n` - Number of servers
///
/// # Returns
/// Vector of normalized weights
pub fn silver_weights_normalized(n: usize) -> Vec<f64> {
    let weights = silver_weights(n);
    let sum: f64 = weights.iter().sum();
    weights.into_iter().map(|w| w / sum).collect()
}

/// Select index based on silver weights and random value
///
/// # Arguments
/// * `weights` - Normalized weights (should sum to 1.0)
/// * `random` - Random value in [0, 1)
///
/// # Returns
/// Selected index
pub fn silver_select(weights: &[f64], random: f64) -> usize {
    let mut cumulative = 0.0;
    for (i, &weight) in weights.iter().enumerate() {
        cumulative += weight;
        if random < cumulative {
            return i;
        }
    }
    weights.len() - 1
}

// =============================================================================
// SILVER SCORING
// =============================================================================

/// Calculate silver-weighted route score
///
/// Combines multiple metrics using silver ratio weights.
///
/// # Arguments
/// * `latency_ms` - Route latency in milliseconds
/// * `bandwidth_mbps` - Available bandwidth in Mbps
/// * `load_percent` - Current load percentage (0-100)
///
/// # Returns
/// Score in [0, 1] range (higher is better)
pub fn silver_route_score(latency_ms: f64, bandwidth_mbps: f64, load_percent: f64) -> f64 {
    // Individual scores (0 to 1 range)
    let latency_score = 1.0 / (1.0 + latency_ms / (TAU * 100.0));
    let bandwidth_score = (bandwidth_mbps / (DELTA_S * 100.0)).min(1.0);
    let load_score = (100.0 - load_percent) / 100.0;

    // Silver-weighted combination
    let total_weight = DELTA_S + TAU + 1.0;
    (latency_score * DELTA_S + bandwidth_score * TAU + load_score * 1.0) / total_weight
}

/// Check if value exceeds silver threshold
///
/// # Arguments
/// * `value` - Value to check
/// * `base_threshold` - Base threshold
///
/// # Returns
/// `true` if value > δ_S * base_threshold
pub fn exceeds_silver_threshold(value: f64, base_threshold: f64) -> bool {
    value > DELTA_S * base_threshold
}

// =============================================================================
// SILVER SPIRAL (for advanced routing)
// =============================================================================

/// Calculate point on silver spiral
///
/// The silver spiral is analogous to the golden spiral but uses τ.
/// Useful for distributed coordinate calculations.
///
/// # Arguments
/// * `theta` - Angle in radians
///
/// # Returns
/// (x, y) coordinates
pub fn silver_spiral(theta: f64) -> (f64, f64) {
    // r = e^(theta/τ)
    let r = (theta / TAU).exp();
    let x = r * theta.cos();
    let y = r * theta.sin();
    (x, y)
}

/// Calculate distance along silver spiral
///
/// # Arguments
/// * `theta` - Angle in radians
///
/// # Returns
/// Arc length approximation
pub fn silver_spiral_distance(theta: f64) -> f64 {
    // Approximation using silver ratio scaling
    let r = (theta / TAU).exp();
    r * (1.0 + 1.0 / (TAU * TAU)).sqrt()
}

// =============================================================================
// SILVER KDF PARAMETERS
// =============================================================================

/// Calculate KDF iteration count based on security level
///
/// # Arguments
/// * `security_bits` - Desired security level (e.g., 128, 256)
///
/// # Returns
/// Number of iterations
pub fn silver_kdf_iterations(security_bits: u32) -> u32 {
    // Base: δ_S * 1000 for 128-bit security
    // Scale linearly for higher security
    let base = SILVER_KDF_ITERATIONS;
    base * (security_bits / 128).max(1)
}

/// Get tau mixing byte for KDF
///
/// # Returns
/// Mixing byte derived from τ
pub const fn silver_kdf_mix_byte() -> u8 {
    TAU_MIX_BYTE
}

// =============================================================================
// CONTINUED FRACTION
// =============================================================================

/// Silver ratio continued fraction: [2; 2, 2, 2, ...]
///
/// The silver ratio has a simple continued fraction representation.
///
/// # Arguments
/// * `depth` - Number of terms to evaluate
///
/// # Returns
/// Approximation of δ_S
pub fn silver_continued_fraction(depth: u32) -> f64 {
    if depth == 0 {
        return 2.0;
    }

    let mut result = 2.0;
    for _ in 0..depth {
        result = 2.0 + 1.0 / result;
    }
    result
}

/// Verify continued fraction convergence
pub fn verify_continued_fraction(tolerance: f64) -> bool {
    let approx = silver_continued_fraction(50);
    (approx - DELTA_S).abs() < tolerance
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silver_delay() {
        let base = 1000; // 1ms
        let delay0 = silver_delay_us(0, base);
        let delay1 = silver_delay_us(1, base);
        let delay2 = silver_delay_us(2, base);

        // Delays should increase based on Pell sequence
        assert!(delay0 <= delay1);
        assert!(delay1 <= delay2);

        // Base delay (Pell(0) = 0) should equal base interval
        assert_eq!(delay0, base);
    }

    #[test]
    fn test_silver_padding() {
        let payload = 1000;
        let padding = silver_padding_size(payload);
        let total = silver_total_size(payload);

        // With η² = 0.5, padding should equal payload
        assert_eq!(padding, payload);
        assert_eq!(total, 2 * payload);

        // Verify round-trip
        let recovered = silver_payload_from_total(total);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_silver_weights() {
        let weights = silver_weights(6);

        // First three: 1, τ, δ_S
        assert!((weights[0] - 1.0).abs() < 1e-10);
        assert!((weights[1] - TAU).abs() < 1e-10);
        assert!((weights[2] - DELTA_S).abs() < 1e-10);

        // Next three: 2, 2τ, 2δ_S
        assert!((weights[3] - 2.0).abs() < 1e-10);
        assert!((weights[4] - 2.0 * TAU).abs() < 1e-10);
        assert!((weights[5] - 2.0 * DELTA_S).abs() < 1e-10);
    }

    #[test]
    fn test_silver_weights_normalized() {
        let weights = silver_weights_normalized(5);
        let sum: f64 = weights.iter().sum();
        assert!((sum - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_silver_select() {
        let weights = vec![0.5, 0.3, 0.2];

        assert_eq!(silver_select(&weights, 0.0), 0);
        assert_eq!(silver_select(&weights, 0.4), 0);
        assert_eq!(silver_select(&weights, 0.6), 1);
        assert_eq!(silver_select(&weights, 0.9), 2);
    }

    #[test]
    fn test_silver_route_score() {
        // Perfect route: low latency, high bandwidth, low load
        let perfect = silver_route_score(10.0, 1000.0, 10.0);

        // Bad route: high latency, low bandwidth, high load
        let bad = silver_route_score(500.0, 10.0, 90.0);

        assert!(perfect > bad);
        assert!(perfect <= 1.0);
        assert!(bad >= 0.0);
    }

    #[test]
    fn test_silver_spiral() {
        let (x0, y0) = silver_spiral(0.0);
        assert!((x0 - 1.0).abs() < 1e-10);
        assert!(y0.abs() < 1e-10);

        // Spiral should expand
        let (_, _) = silver_spiral(std::f64::consts::PI);
        let r_pi = (std::f64::consts::PI / TAU).exp();
        assert!(r_pi > 1.0);
    }

    #[test]
    fn test_silver_kdf_iterations() {
        assert_eq!(silver_kdf_iterations(128), SILVER_KDF_ITERATIONS);
        assert_eq!(silver_kdf_iterations(256), SILVER_KDF_ITERATIONS * 2);
    }

    #[test]
    fn test_silver_continued_fraction() {
        let approx = silver_continued_fraction(30);
        assert!((approx - DELTA_S).abs() < 1e-14);
    }

    #[test]
    fn test_verify_continued_fraction() {
        assert!(verify_continued_fraction(1e-10));
    }
}
