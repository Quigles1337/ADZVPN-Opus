//! Silver Jitter
//!
//! Controlled randomness for timing using silver ratio bounds.
//! Adds unpredictability while maintaining mathematical structure.
//!
//! ## Why Silver-Bounded Jitter?
//!
//! Pure random jitter can actually make fingerprinting easier because:
//! - Random distributions have detectable statistical signatures
//! - Unbounded randomness can cause performance issues
//!
//! Silver-bounded jitter uses the silver ratio to:
//! - Limit maximum variation (bounded by δ_S)
//! - Create structured randomness (follows mathematical patterns)
//! - Maintain timing predictability for debugging

use rand::Rng;
use silver_core::{DELTA_S, ETA, LAMBDA_SQUARED, TAU};
use std::time::Duration;

/// Silver-bounded jitter generator
pub struct SilverJitter {
    /// Base value for jitter calculation (microseconds)
    base_us: u64,
    /// Maximum jitter multiplier (defaults to δ_S)
    max_multiplier: f64,
    /// Minimum jitter multiplier (defaults to 1/δ_S)
    min_multiplier: f64,
    /// Whether jitter is enabled
    enabled: bool,
}

impl SilverJitter {
    /// Create new jitter generator with base value
    pub fn new(base_us: u64) -> Self {
        Self {
            base_us,
            max_multiplier: DELTA_S,
            min_multiplier: 1.0 / DELTA_S,
            enabled: true,
        }
    }

    /// Create jitter with custom bounds
    pub fn with_bounds(base_us: u64, min_mult: f64, max_mult: f64) -> Self {
        Self {
            base_us,
            max_multiplier: max_mult.max(1.0),
            min_multiplier: min_mult.min(1.0).max(0.0),
            enabled: true,
        }
    }

    /// Create tight jitter (smaller variation)
    pub fn tight(base_us: u64) -> Self {
        Self {
            base_us,
            max_multiplier: TAU,          // √2 ≈ 1.414
            min_multiplier: 1.0 / TAU,    // 1/√2 ≈ 0.707
            enabled: true,
        }
    }

    /// Generate a jitter value in microseconds
    pub fn generate(&self) -> u64 {
        if !self.enabled {
            return 0;
        }

        let mut rng = rand::thread_rng();
        let multiplier = rng.gen_range(self.min_multiplier..=self.max_multiplier);
        (self.base_us as f64 * multiplier) as u64
    }

    /// Generate jitter as a Duration
    pub fn generate_duration(&self) -> Duration {
        Duration::from_micros(self.generate())
    }

    /// Generate signed jitter (can be negative)
    ///
    /// Returns a value in the range [-base * λ², +base * λ²]
    pub fn generate_signed(&self) -> i64 {
        if !self.enabled {
            return 0;
        }

        let mut rng = rand::thread_rng();
        let range = self.base_us as f64 * LAMBDA_SQUARED;
        rng.gen_range(-range..=range) as i64
    }

    /// Apply jitter to a base delay
    pub fn apply(&self, delay_us: u64) -> u64 {
        if !self.enabled {
            return delay_us;
        }

        let jitter = self.generate_signed();
        if jitter >= 0 {
            delay_us.saturating_add(jitter as u64)
        } else {
            delay_us.saturating_sub((-jitter) as u64)
        }
    }

    /// Apply jitter to a Duration
    pub fn apply_duration(&self, delay: Duration) -> Duration {
        Duration::from_micros(self.apply(delay.as_micros() as u64))
    }

    /// Enable/disable jitter
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if jitter is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get base value
    pub fn base_us(&self) -> u64 {
        self.base_us
    }

    /// Set base value
    pub fn set_base_us(&mut self, base: u64) {
        self.base_us = base;
    }

    /// Get the jitter range [min, max] in microseconds
    pub fn range(&self) -> (u64, u64) {
        let min = (self.base_us as f64 * self.min_multiplier) as u64;
        let max = (self.base_us as f64 * self.max_multiplier) as u64;
        (min, max)
    }
}

/// Jitter mode for different scenarios
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterMode {
    /// No jitter
    None,
    /// Tight jitter (τ bounds)
    Tight,
    /// Normal jitter (δ_S bounds)
    Normal,
    /// Wide jitter (δ_S² bounds)
    Wide,
}

impl JitterMode {
    /// Get multiplier range for this mode
    pub fn bounds(&self) -> (f64, f64) {
        match self {
            JitterMode::None => (1.0, 1.0),
            JitterMode::Tight => (1.0 / TAU, TAU),
            JitterMode::Normal => (1.0 / DELTA_S, DELTA_S),
            JitterMode::Wide => (1.0 / (DELTA_S * DELTA_S), DELTA_S * DELTA_S),
        }
    }

    /// Create jitter generator for this mode
    pub fn create_jitter(&self, base_us: u64) -> SilverJitter {
        let (min, max) = self.bounds();
        SilverJitter::with_bounds(base_us, min, max)
    }
}

/// Correlated jitter generator
///
/// Generates jitter that has some correlation with previous values,
/// making the timing pattern smoother while still unpredictable.
pub struct CorrelatedJitter {
    /// Base jitter generator
    jitter: SilverJitter,
    /// Previous jitter value
    previous: f64,
    /// Correlation factor (0 = no correlation, 1 = full correlation)
    correlation: f64,
}

impl CorrelatedJitter {
    /// Create new correlated jitter
    pub fn new(base_us: u64) -> Self {
        Self {
            jitter: SilverJitter::new(base_us),
            previous: 1.0,
            correlation: ETA, // η ≈ 0.707 correlation
        }
    }

    /// Create with custom correlation
    pub fn with_correlation(base_us: u64, correlation: f64) -> Self {
        Self {
            jitter: SilverJitter::new(base_us),
            previous: 1.0,
            correlation: correlation.clamp(0.0, 1.0),
        }
    }

    /// Generate correlated jitter value
    pub fn generate(&mut self) -> u64 {
        let mut rng = rand::thread_rng();
        let random: f64 = rng.gen_range(self.jitter.min_multiplier..=self.jitter.max_multiplier);

        // Blend with previous value based on correlation
        let blended = self.correlation * self.previous + (1.0 - self.correlation) * random;

        // Clamp to valid range
        let multiplier = blended.clamp(self.jitter.min_multiplier, self.jitter.max_multiplier);

        self.previous = multiplier;

        (self.jitter.base_us as f64 * multiplier) as u64
    }

    /// Generate as Duration
    pub fn generate_duration(&mut self) -> Duration {
        Duration::from_micros(self.generate())
    }

    /// Reset correlation state
    pub fn reset(&mut self) {
        self.previous = 1.0;
    }

    /// Get correlation factor
    pub fn correlation(&self) -> f64 {
        self.correlation
    }
}

/// Exponential backoff with silver ratio
pub struct SilverBackoff {
    /// Base delay in microseconds
    base_us: u64,
    /// Current multiplier
    current_multiplier: f64,
    /// Maximum multiplier (caps the backoff)
    max_multiplier: f64,
    /// Number of backoffs performed
    attempts: u32,
}

impl SilverBackoff {
    /// Create new backoff with base delay
    pub fn new(base_us: u64) -> Self {
        Self {
            base_us,
            current_multiplier: 1.0,
            max_multiplier: DELTA_S * DELTA_S * DELTA_S, // δ_S³ ≈ 14
            attempts: 0,
        }
    }

    /// Create with custom maximum
    pub fn with_max(base_us: u64, max_mult: f64) -> Self {
        Self {
            base_us,
            current_multiplier: 1.0,
            max_multiplier: max_mult,
            attempts: 0,
        }
    }

    /// Get current delay
    pub fn current_delay(&self) -> Duration {
        Duration::from_micros((self.base_us as f64 * self.current_multiplier) as u64)
    }

    /// Perform a backoff (increase delay by τ)
    pub fn backoff(&mut self) -> Duration {
        self.attempts += 1;
        self.current_multiplier = (self.current_multiplier * TAU).min(self.max_multiplier);
        self.current_delay()
    }

    /// Reset backoff state
    pub fn reset(&mut self) {
        self.current_multiplier = 1.0;
        self.attempts = 0;
    }

    /// Get number of attempts
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Check if at maximum backoff
    pub fn is_maxed(&self) -> bool {
        self.current_multiplier >= self.max_multiplier
    }

    /// Get current multiplier
    pub fn multiplier(&self) -> f64 {
        self.current_multiplier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_creation() {
        let jitter = SilverJitter::new(1000);
        assert_eq!(jitter.base_us(), 1000);
        assert!(jitter.is_enabled());
    }

    #[test]
    fn test_jitter_bounds() {
        let jitter = SilverJitter::new(1000);
        let (min, max) = jitter.range();

        // With δ_S bounds
        assert!(min < 1000);
        assert!(max > 1000);
        assert!((min as f64 - 1000.0 / DELTA_S).abs() < 1.0);
        assert!((max as f64 - 1000.0 * DELTA_S).abs() < 1.0);
    }

    #[test]
    fn test_jitter_generation() {
        let jitter = SilverJitter::new(1000);
        let (min, max) = jitter.range();

        for _ in 0..100 {
            let val = jitter.generate();
            assert!(val >= min, "Jitter {} below min {}", val, min);
            assert!(val <= max, "Jitter {} above max {}", val, max);
        }
    }

    #[test]
    fn test_tight_jitter() {
        let jitter = SilverJitter::tight(1000);
        let (min, max) = jitter.range();

        // τ bounds are tighter than δ_S
        assert!(min > 1000 / 3); // > 1/δ_S
        assert!(max < 3000);     // < δ_S
    }

    #[test]
    fn test_jitter_disabled() {
        let mut jitter = SilverJitter::new(1000);
        jitter.set_enabled(false);

        for _ in 0..10 {
            assert_eq!(jitter.generate(), 0);
            assert_eq!(jitter.generate_signed(), 0);
        }
    }

    #[test]
    fn test_apply_jitter() {
        let jitter = SilverJitter::new(100);

        // Apply to base delay
        let delay = 10_000u64;
        let jittered = jitter.apply(delay);

        // Should be within reasonable bounds
        assert!(jittered > delay / 2);
        assert!(jittered < delay * 3);
    }

    #[test]
    fn test_jitter_mode() {
        let base = 1000u64;

        let none = JitterMode::None.create_jitter(base);
        let tight = JitterMode::Tight.create_jitter(base);
        let normal = JitterMode::Normal.create_jitter(base);
        let wide = JitterMode::Wide.create_jitter(base);

        // None should have no range
        let (min, max) = none.range();
        assert_eq!(min, max);

        // Ranges should get progressively wider
        let (_, tight_max) = tight.range();
        let (_, normal_max) = normal.range();
        let (_, wide_max) = wide.range();

        assert!(tight_max < normal_max);
        assert!(normal_max < wide_max);
    }

    #[test]
    fn test_correlated_jitter() {
        let mut jitter = CorrelatedJitter::new(1000);

        let mut values = Vec::new();
        for _ in 0..10 {
            values.push(jitter.generate());
        }

        // Values should be generated (non-zero)
        assert!(values.iter().all(|&v| v > 0));

        // With correlation, consecutive values shouldn't be too different
        // (This is probabilistic, so we just check they're in range)
        let (min, max) = jitter.jitter.range();
        for val in &values {
            assert!(*val >= min && *val <= max);
        }
    }

    #[test]
    fn test_silver_backoff() {
        let mut backoff = SilverBackoff::new(1000);

        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.current_delay(), Duration::from_micros(1000));

        // First backoff: multiply by τ
        let delay1 = backoff.backoff();
        assert_eq!(backoff.attempts(), 1);
        assert!(delay1 > Duration::from_micros(1000));

        // Second backoff: multiply by τ again
        let delay2 = backoff.backoff();
        assert!(delay2 > delay1);

        // Reset
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.current_delay(), Duration::from_micros(1000));
    }

    #[test]
    fn test_backoff_max() {
        let mut backoff = SilverBackoff::with_max(1000, 4.0);

        // Backoff until maxed
        for _ in 0..10 {
            backoff.backoff();
        }

        assert!(backoff.is_maxed());
        assert!(backoff.multiplier() <= 4.0);
    }

    #[test]
    fn test_signed_jitter_distribution() {
        let jitter = SilverJitter::new(1000);

        let mut positive = 0;
        let mut negative = 0;

        for _ in 0..1000 {
            let val = jitter.generate_signed();
            if val > 0 {
                positive += 1;
            } else if val < 0 {
                negative += 1;
            }
        }

        // Should be roughly balanced
        assert!(positive > 300);
        assert!(negative > 300);
    }
}
