//! τ-Scheduler
//!
//! Packet timing scheduler using the Pell sequence and silver ratio.
//! Creates deterministic but non-obvious timing patterns for anti-fingerprinting.
//!
//! ## How It Works
//!
//! The Pell sequence (0, 1, 2, 5, 12, 29, 70, 169, ...) has the property that
//! P(n+1)/P(n) converges to the silver ratio δ_S = 1 + √2.
//!
//! By using Pell numbers to modulate timing intervals, we create patterns that:
//! - Are mathematically structured (not random noise)
//! - Don't repeat for long periods
//! - Resist statistical fingerprinting

use silver_core::{silver_delay_us, DELTA_S, TAU};

#[cfg(test)]
use silver_core::pell_cached;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Silver-ratio based packet scheduler
///
/// Uses Pell sequence to generate timing intervals that resist fingerprinting.
pub struct SilverScheduler {
    /// Base interval in microseconds
    base_interval_us: u64,
    /// Current packet index (wraps at PELL_SEQUENCE_LENGTH)
    packet_index: u64,
    /// Last packet send time
    last_send: Option<Instant>,
    /// Accumulated timing drift for correction
    drift_us: i64,
    /// Whether scheduler is running
    running: bool,
}

impl SilverScheduler {
    /// Create a new scheduler with given base interval (microseconds)
    pub fn new(base_interval_us: u64) -> Self {
        Self {
            base_interval_us,
            packet_index: 0,
            last_send: None,
            drift_us: 0,
            running: true,
        }
    }

    /// Create scheduler from milliseconds
    pub fn from_millis(base_interval_ms: u64) -> Self {
        Self::new(base_interval_ms * 1000)
    }

    /// Get base interval
    pub fn base_interval_us(&self) -> u64 {
        self.base_interval_us
    }

    /// Calculate next delay using Pell sequence modulation
    ///
    /// The delay formula: base * (1 + P(n % 20) / δ_S)
    /// This creates a pattern that cycles through 20 Pell numbers,
    /// scaled by the silver ratio.
    pub fn next_delay(&mut self) -> Duration {
        let delay_us = self.calculate_delay_us();
        self.packet_index = self.packet_index.wrapping_add(1);
        Duration::from_micros(delay_us)
    }

    /// Calculate delay in microseconds
    fn calculate_delay_us(&self) -> u64 {
        silver_delay_us(self.packet_index, self.base_interval_us)
    }

    /// Get delay for a specific packet index without advancing
    pub fn peek_delay(&self, index: u64) -> Duration {
        Duration::from_micros(silver_delay_us(index, self.base_interval_us))
    }

    /// Wait for the next send slot
    ///
    /// This accounts for processing time and drift to maintain
    /// accurate timing over many packets.
    pub async fn wait_next(&mut self) {
        let target_delay = self.next_delay();

        let actual_delay = if let Some(last) = self.last_send {
            let elapsed = last.elapsed();
            if elapsed < target_delay {
                target_delay - elapsed
            } else {
                // We're behind schedule, accumulate drift
                self.drift_us += (elapsed.as_micros() - target_delay.as_micros()) as i64;
                Duration::ZERO
            }
        } else {
            target_delay
        };

        // Apply drift correction if we're ahead
        let corrected_delay = if self.drift_us < 0 && actual_delay > Duration::ZERO {
            let correction = (-self.drift_us as u64).min(actual_delay.as_micros() as u64 / 2);
            self.drift_us += correction as i64;
            Duration::from_micros(actual_delay.as_micros() as u64 - correction)
        } else {
            actual_delay
        };

        if corrected_delay > Duration::ZERO {
            sleep(corrected_delay).await;
        }

        self.last_send = Some(Instant::now());
    }

    /// Reset the scheduler state
    pub fn reset(&mut self) {
        self.packet_index = 0;
        self.last_send = None;
        self.drift_us = 0;
    }

    /// Stop the scheduler
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Check if scheduler is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get current packet index
    pub fn packet_index(&self) -> u64 {
        self.packet_index
    }

    /// Get accumulated drift
    pub fn drift_us(&self) -> i64 {
        self.drift_us
    }

    /// Generate a sequence of delays for analysis/debugging
    pub fn preview_delays(&self, count: usize) -> Vec<Duration> {
        (0..count as u64)
            .map(|i| self.peek_delay(self.packet_index + i))
            .collect()
    }
}

/// Timing statistics
#[derive(Debug, Clone, Default)]
pub struct TimingStats {
    /// Total packets scheduled
    pub packets_scheduled: u64,
    /// Total delay time in microseconds
    pub total_delay_us: u64,
    /// Maximum delay seen
    pub max_delay_us: u64,
    /// Minimum delay seen
    pub min_delay_us: u64,
    /// Current drift
    pub drift_us: i64,
}

impl TimingStats {
    /// Create new stats tracker
    pub fn new() -> Self {
        Self {
            min_delay_us: u64::MAX,
            ..Default::default()
        }
    }

    /// Record a delay
    pub fn record(&mut self, delay_us: u64) {
        self.packets_scheduled += 1;
        self.total_delay_us += delay_us;
        self.max_delay_us = self.max_delay_us.max(delay_us);
        self.min_delay_us = self.min_delay_us.min(delay_us);
    }

    /// Get average delay
    pub fn average_delay_us(&self) -> u64 {
        if self.packets_scheduled > 0 {
            self.total_delay_us / self.packets_scheduled
        } else {
            0
        }
    }
}

/// Burst scheduler for sending multiple packets with silver timing
pub struct BurstScheduler {
    /// Inner scheduler
    scheduler: SilverScheduler,
    /// Packets per burst
    burst_size: usize,
    /// Inter-burst multiplier (τ-scaled)
    burst_multiplier: f64,
}

impl BurstScheduler {
    /// Create a new burst scheduler
    pub fn new(base_interval_us: u64, burst_size: usize) -> Self {
        Self {
            scheduler: SilverScheduler::new(base_interval_us),
            burst_size,
            burst_multiplier: TAU, // √2 multiplier between bursts
        }
    }

    /// Get intra-burst delay (between packets in a burst)
    pub fn intra_burst_delay(&mut self) -> Duration {
        self.scheduler.next_delay()
    }

    /// Get inter-burst delay (between bursts)
    pub fn inter_burst_delay(&mut self) -> Duration {
        let base = self.scheduler.next_delay();
        Duration::from_micros((base.as_micros() as f64 * self.burst_multiplier) as u64)
    }

    /// Get burst size
    pub fn burst_size(&self) -> usize {
        self.burst_size
    }

    /// Set burst multiplier
    pub fn set_burst_multiplier(&mut self, multiplier: f64) {
        self.burst_multiplier = multiplier.max(1.0);
    }
}

/// Adaptive scheduler that adjusts based on network conditions
pub struct AdaptiveScheduler {
    /// Base scheduler
    scheduler: SilverScheduler,
    /// Minimum interval (microseconds)
    min_interval_us: u64,
    /// Maximum interval (microseconds)
    max_interval_us: u64,
    /// Current congestion factor (1.0 = no congestion)
    congestion_factor: f64,
}

impl AdaptiveScheduler {
    /// Create new adaptive scheduler
    pub fn new(base_interval_us: u64) -> Self {
        Self {
            scheduler: SilverScheduler::new(base_interval_us),
            min_interval_us: base_interval_us / 2,
            max_interval_us: base_interval_us * 4,
            congestion_factor: 1.0,
        }
    }

    /// Get next delay, adjusted for congestion
    pub fn next_delay(&mut self) -> Duration {
        let base_delay = self.scheduler.next_delay();
        let adjusted_us = (base_delay.as_micros() as f64 * self.congestion_factor) as u64;
        let clamped = adjusted_us.clamp(self.min_interval_us, self.max_interval_us);
        Duration::from_micros(clamped)
    }

    /// Report successful transmission (reduce congestion)
    pub fn report_success(&mut self) {
        // Decrease congestion factor by τ^-1
        self.congestion_factor = (self.congestion_factor / TAU).max(0.5);
    }

    /// Report timeout/failure (increase congestion)
    pub fn report_timeout(&mut self) {
        // Increase congestion factor by τ
        self.congestion_factor = (self.congestion_factor * TAU).min(DELTA_S);
    }

    /// Get current congestion factor
    pub fn congestion_factor(&self) -> f64 {
        self.congestion_factor
    }

    /// Reset congestion tracking
    pub fn reset_congestion(&mut self) {
        self.congestion_factor = 1.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = SilverScheduler::new(10_000);
        assert_eq!(scheduler.base_interval_us(), 10_000);
        assert_eq!(scheduler.packet_index(), 0);
    }

    #[test]
    fn test_scheduler_from_millis() {
        let scheduler = SilverScheduler::from_millis(10);
        assert_eq!(scheduler.base_interval_us(), 10_000);
    }

    #[test]
    fn test_delay_sequence() {
        let mut scheduler = SilverScheduler::new(10_000);

        // Collect delays
        let delays: Vec<u64> = (0..20)
            .map(|_| scheduler.next_delay().as_micros() as u64)
            .collect();

        // All delays should be >= base interval
        for delay in &delays {
            assert!(*delay >= 10_000, "Delay {} < base 10000", delay);
        }

        // Delays should vary (Pell modulation)
        let unique: std::collections::HashSet<_> = delays.iter().collect();
        assert!(unique.len() > 1, "Delays should vary");
    }

    #[test]
    fn test_delay_is_pell_modulated() {
        let scheduler = SilverScheduler::new(10_000);

        // Check that delay follows: base * (1 + P(n % 20) / δ_S)
        for i in 0..20u64 {
            let delay = scheduler.peek_delay(i);
            let pell = pell_cached((i % 20) as u32).unwrap_or(0);
            let expected = 10_000.0 * (1.0 + pell as f64 / DELTA_S);

            let diff = (delay.as_micros() as f64 - expected).abs();
            assert!(diff < 1.0, "Delay mismatch at {}: {} vs {}", i, delay.as_micros(), expected);
        }
    }

    #[test]
    fn test_preview_delays() {
        let scheduler = SilverScheduler::new(10_000);
        let preview = scheduler.preview_delays(5);

        assert_eq!(preview.len(), 5);
        for delay in preview {
            assert!(delay.as_micros() >= 10_000);
        }
    }

    #[test]
    fn test_scheduler_reset() {
        let mut scheduler = SilverScheduler::new(10_000);

        // Advance
        for _ in 0..10 {
            scheduler.next_delay();
        }
        assert_eq!(scheduler.packet_index(), 10);

        // Reset
        scheduler.reset();
        assert_eq!(scheduler.packet_index(), 0);
    }

    #[test]
    fn test_timing_stats() {
        let mut stats = TimingStats::new();

        stats.record(100);
        stats.record(200);
        stats.record(150);

        assert_eq!(stats.packets_scheduled, 3);
        assert_eq!(stats.total_delay_us, 450);
        assert_eq!(stats.average_delay_us(), 150);
        assert_eq!(stats.min_delay_us, 100);
        assert_eq!(stats.max_delay_us, 200);
    }

    #[test]
    fn test_burst_scheduler() {
        let mut burst = BurstScheduler::new(10_000, 5);

        assert_eq!(burst.burst_size(), 5);

        let intra = burst.intra_burst_delay();
        let inter = burst.inter_burst_delay();

        // Inter-burst should be larger (τ multiplied)
        assert!(inter > intra);
    }

    #[test]
    fn test_adaptive_scheduler_congestion() {
        let mut adaptive = AdaptiveScheduler::new(10_000);

        let initial_factor = adaptive.congestion_factor();
        assert!((initial_factor - 1.0).abs() < 0.01);

        // Report timeout - should increase congestion
        adaptive.report_timeout();
        assert!(adaptive.congestion_factor() > initial_factor);

        // Report success - should decrease congestion
        adaptive.report_success();
        adaptive.report_success();
        // After two successes, should be below the timeout level
    }

    #[tokio::test]
    async fn test_scheduler_wait() {
        let mut scheduler = SilverScheduler::new(1_000); // 1ms base

        let start = Instant::now();
        scheduler.wait_next().await;
        let elapsed = start.elapsed();

        // Should have waited approximately the delay time
        assert!(elapsed >= Duration::from_micros(900)); // Allow some tolerance
    }

    #[test]
    fn test_scheduler_stop() {
        let mut scheduler = SilverScheduler::new(10_000);
        assert!(scheduler.is_running());

        scheduler.stop();
        assert!(!scheduler.is_running());
    }
}
