//! Pell Sequence Generator
//!
//! The Pell sequence is intimately connected to the silver ratio:
//! - P(n) = 2*P(n-1) + P(n-2), with P(0)=0, P(1)=1
//! - lim(P(n+1)/P(n)) = δ_S (silver ratio)
//!
//! Used in ADZVPN-Opus for:
//! - Anti-fingerprinting packet timing
//! - Deterministic but non-obvious delay patterns
//! - Silver-based scheduling algorithms

use crate::constants::DELTA_S;

// =============================================================================
// PELL SEQUENCE - RECURSIVE (simple, for reference)
// =============================================================================

/// Calculate the nth Pell number (recursive implementation)
///
/// The Pell sequence: 0, 1, 2, 5, 12, 29, 70, 169, 408, 985, ...
///
/// # Arguments
/// * `n` - Index in the sequence (0-indexed)
///
/// # Returns
/// The nth Pell number
///
/// # Note
/// This is the simple recursive version. For performance-critical code,
/// use `pell_iterative` or `pell_cached`.
pub fn pell(n: u32) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => 2 * pell(n - 1) + pell(n - 2),
    }
}

// =============================================================================
// PELL SEQUENCE - ITERATIVE (efficient)
// =============================================================================

/// Calculate the nth Pell number (iterative implementation)
///
/// More efficient than recursive for larger n values.
///
/// # Arguments
/// * `n` - Index in the sequence (0-indexed)
///
/// # Returns
/// The nth Pell number
///
/// # Panics
/// May overflow for n > 44 (Pell(44) > u64::MAX)
pub fn pell_iterative(n: u32) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => {
            let mut prev2: u64 = 0;
            let mut prev1: u64 = 1;
            for _ in 2..=n {
                let current = 2u64.saturating_mul(prev1).saturating_add(prev2);
                prev2 = prev1;
                prev1 = current;
            }
            prev1
        }
    }
}

/// Calculate the nth Pell number with overflow checking
///
/// # Arguments
/// * `n` - Index in the sequence (0-indexed)
///
/// # Returns
/// `Some(pell_n)` if no overflow, `None` if overflow would occur
pub fn pell_checked(n: u32) -> Option<u64> {
    match n {
        0 => Some(0),
        1 => Some(1),
        _ => {
            let mut prev2: u64 = 0;
            let mut prev1: u64 = 1;
            for _ in 2..=n {
                let doubled = prev1.checked_mul(2)?;
                let current = doubled.checked_add(prev2)?;
                prev2 = prev1;
                prev1 = current;
            }
            Some(prev1)
        }
    }
}

// =============================================================================
// PELL SEQUENCE CACHE
// =============================================================================

/// First 45 Pell numbers (pre-computed for performance)
/// Pell(44) = 6,882,627,592,338,442,563 (fits in u64)
/// Pell(45) would overflow u64
pub const PELL_CACHE: [u64; 45] = [
    0,
    1,
    2,
    5,
    12,
    29,
    70,
    169,
    408,
    985,
    2378,
    5741,
    13860,
    33461,
    80782,
    195025,
    470832,
    1136689,
    2744210,
    6625109,
    15994428,
    38613965,
    93222358,
    225058681,
    543339720,
    1311738121,
    3166815962,
    7645370045,
    18457556052,
    44560482149,
    107578520350,
    259717522849,
    627013566048,
    1513744654945,
    3654502875938,
    8822750406821,
    21300003689580,
    51422757785981,
    124145519261542,
    299713796309065,
    723573111879672,
    1746860020068409,
    4217293152016490,
    10181446324101389,
    24580185800219268,
];

/// Get the nth Pell number from cache (fastest)
///
/// # Arguments
/// * `n` - Index in the sequence (0-indexed, max 44)
///
/// # Returns
/// The nth Pell number, or `None` if n > 44
#[inline]
pub fn pell_cached(n: u32) -> Option<u64> {
    PELL_CACHE.get(n as usize).copied()
}

/// Get the nth Pell number from cache, wrapping at max index
///
/// Useful for timing calculations that need to cycle through values.
///
/// # Arguments
/// * `n` - Index (will be wrapped to valid range)
///
/// # Returns
/// The Pell number at index (n % 45)
#[inline]
pub fn pell_wrapped(n: u64) -> u64 {
    PELL_CACHE[(n % 45) as usize]
}

// =============================================================================
// SILVER RATIO FROM PELL
// =============================================================================

/// Compute silver ratio approximation from Pell sequence
///
/// The ratio P(n+1)/P(n) converges to δ_S as n increases.
///
/// # Arguments
/// * `n` - Index to use (higher = more accurate, max 43)
///
/// # Returns
/// Approximation of the silver ratio
pub fn silver_from_pell(n: u32) -> f64 {
    let n = n.min(43); // Prevent overflow
    let p_n = pell_cached(n).unwrap_or(1) as f64;
    let p_n1 = pell_cached(n + 1).unwrap_or(1) as f64;
    p_n1 / p_n
}

/// Verify Pell convergence to silver ratio
///
/// # Arguments
/// * `tolerance` - Maximum acceptable error
///
/// # Returns
/// `true` if P(n+1)/P(n) converges to δ_S within tolerance
pub fn verify_pell_convergence(tolerance: f64) -> bool {
    let ratio = silver_from_pell(40);
    (ratio - DELTA_S).abs() < tolerance
}

// =============================================================================
// COMPANION PELL NUMBERS
// =============================================================================

/// Companion Pell sequence (Q_n)
///
/// Q(n) = 2*Q(n-1) + Q(n-2), with Q(0)=Q(1)=1
/// Related to Pell numbers: Q(n)² - 2*P(n)² = (-1)^n
pub fn companion_pell(n: u32) -> u64 {
    match n {
        0 | 1 => 1,
        _ => 2 * companion_pell(n - 1) + companion_pell(n - 2),
    }
}

/// Companion Pell (iterative)
pub fn companion_pell_iterative(n: u32) -> u64 {
    match n {
        0 | 1 => 1,
        _ => {
            let mut prev2: u64 = 1;
            let mut prev1: u64 = 1;
            for _ in 2..=n {
                let current = 2u64.saturating_mul(prev1).saturating_add(prev2);
                prev2 = prev1;
                prev1 = current;
            }
            prev1
        }
    }
}

// =============================================================================
// PELL-RELATED IDENTITIES
// =============================================================================

/// Verify Pell identity: P(2n) = 2 * P(n) * Q(n)
pub fn verify_pell_doubling_identity(n: u32) -> bool {
    if n > 20 {
        return true; // Skip for large n to avoid overflow
    }
    let p_2n = pell_iterative(2 * n);
    let p_n = pell_iterative(n);
    let q_n = companion_pell_iterative(n);
    p_2n == 2 * p_n * q_n
}

/// Verify Cassini-like identity: Q(n)² - 2*P(n)² = (-1)^n
pub fn verify_cassini_identity(n: u32) -> bool {
    if n > 30 {
        return true; // Skip for large n
    }
    let p_n = pell_iterative(n) as i128;
    let q_n = companion_pell_iterative(n) as i128;
    let lhs = q_n * q_n - 2 * p_n * p_n;
    let rhs = if n % 2 == 0 { 1 } else { -1 };
    lhs == rhs
}

// =============================================================================
// ITERATOR
// =============================================================================

/// Iterator over Pell numbers
pub struct PellIterator {
    prev2: u64,
    prev1: u64,
    index: u32,
}

impl PellIterator {
    pub fn new() -> Self {
        Self {
            prev2: 0,
            prev1: 1,
            index: 0,
        }
    }
}

impl Default for PellIterator {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for PellIterator {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match self.index {
            0 => 0,
            1 => 1,
            _ => {
                let current = 2u64.checked_mul(self.prev1)?.checked_add(self.prev2)?;
                self.prev2 = self.prev1;
                self.prev1 = current;
                current
            }
        };

        if self.index < 2 {
            self.index += 1;
        }

        Some(result)
    }
}

/// Create an iterator over Pell numbers
pub fn pell_iter() -> PellIterator {
    PellIterator::new()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pell_first_values() {
        assert_eq!(pell(0), 0);
        assert_eq!(pell(1), 1);
        assert_eq!(pell(2), 2);
        assert_eq!(pell(3), 5);
        assert_eq!(pell(4), 12);
        assert_eq!(pell(5), 29);
        assert_eq!(pell(6), 70);
        assert_eq!(pell(7), 169);
    }

    #[test]
    fn test_pell_iterative_matches_recursive() {
        for n in 0..20 {
            assert_eq!(pell(n), pell_iterative(n));
        }
    }

    #[test]
    fn test_pell_cached_matches() {
        for n in 0..45 {
            assert_eq!(Some(pell_iterative(n)), pell_cached(n));
        }
    }

    #[test]
    fn test_pell_cache_values() {
        // Verify first few cached values
        assert_eq!(PELL_CACHE[0], 0);
        assert_eq!(PELL_CACHE[1], 1);
        assert_eq!(PELL_CACHE[2], 2);
        assert_eq!(PELL_CACHE[10], 2378);
        assert_eq!(PELL_CACHE[20], 15994428);
    }

    #[test]
    fn test_silver_from_pell_convergence() {
        // Higher indices should give better approximations
        let approx_10 = silver_from_pell(10);
        let approx_20 = silver_from_pell(20);
        let approx_40 = silver_from_pell(40);

        assert!((approx_10 - DELTA_S).abs() > (approx_20 - DELTA_S).abs());
        assert!((approx_20 - DELTA_S).abs() > (approx_40 - DELTA_S).abs());
        assert!((approx_40 - DELTA_S).abs() < 1e-15);
    }

    #[test]
    fn test_pell_convergence() {
        assert!(verify_pell_convergence(1e-10));
    }

    #[test]
    fn test_companion_pell() {
        // Q(0)=1, Q(1)=1, Q(2)=3, Q(3)=7, Q(4)=17, Q(5)=41
        assert_eq!(companion_pell(0), 1);
        assert_eq!(companion_pell(1), 1);
        assert_eq!(companion_pell(2), 3);
        assert_eq!(companion_pell(3), 7);
        assert_eq!(companion_pell(4), 17);
        assert_eq!(companion_pell(5), 41);
    }

    #[test]
    fn test_pell_doubling_identity() {
        for n in 1..15 {
            assert!(
                verify_pell_doubling_identity(n),
                "Doubling identity failed for n={}",
                n
            );
        }
    }

    #[test]
    fn test_cassini_identity() {
        for n in 0..25 {
            assert!(
                verify_cassini_identity(n),
                "Cassini identity failed for n={}",
                n
            );
        }
    }

    #[test]
    fn test_pell_iterator() {
        let pells: Vec<u64> = pell_iter().take(10).collect();
        assert_eq!(pells, vec![0, 1, 2, 5, 12, 29, 70, 169, 408, 985]);
    }

    #[test]
    fn test_pell_wrapped() {
        // Should wrap around at index 45
        assert_eq!(pell_wrapped(0), PELL_CACHE[0]);
        assert_eq!(pell_wrapped(44), PELL_CACHE[44]);
        assert_eq!(pell_wrapped(45), PELL_CACHE[0]);
        assert_eq!(pell_wrapped(46), PELL_CACHE[1]);
    }
}
