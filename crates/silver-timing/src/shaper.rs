//! Traffic Shaper
//!
//! Maintains constant bandwidth using the silver ratio identity η² + λ² = 1.
//! This means real traffic is η² (50%) of bandwidth, padding is λ² (50%).
//!
//! ## Why Constant Bandwidth?
//!
//! Variable bandwidth leaks information:
//! - High bandwidth = user is active (streaming, downloading)
//! - Low bandwidth = user is idle
//! - Burst patterns = specific application signatures
//!
//! By maintaining constant bandwidth with silver-ratio padding,
//! all activity looks identical to an observer.

use silver_core::{ETA_SQUARED, LAMBDA_SQUARED, DELTA_S, TAU};
use std::time::{Duration, Instant};

/// Traffic shaper maintaining η² + λ² = 1 bandwidth ratio
pub struct TrafficShaper {
    /// Target bandwidth in bytes per second
    target_bandwidth: u64,
    /// Bytes sent in current window
    bytes_sent: u64,
    /// Bytes of real data sent
    real_bytes_sent: u64,
    /// Padding bytes sent
    padding_bytes_sent: u64,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
    /// Whether shaping is enabled
    enabled: bool,
}

impl TrafficShaper {
    /// Create a new traffic shaper
    ///
    /// # Arguments
    /// * `target_bandwidth` - Target bandwidth in bytes per second
    pub fn new(target_bandwidth: u64) -> Self {
        Self {
            target_bandwidth,
            bytes_sent: 0,
            real_bytes_sent: 0,
            padding_bytes_sent: 0,
            window_start: Instant::now(),
            window_duration: Duration::from_secs(1),
            enabled: true,
        }
    }

    /// Create shaper with custom window duration
    pub fn with_window(target_bandwidth: u64, window: Duration) -> Self {
        Self {
            target_bandwidth,
            bytes_sent: 0,
            real_bytes_sent: 0,
            padding_bytes_sent: 0,
            window_start: Instant::now(),
            window_duration: window,
            enabled: true,
        }
    }

    /// Get target bandwidth
    pub fn target_bandwidth(&self) -> u64 {
        self.target_bandwidth
    }

    /// Set target bandwidth
    pub fn set_target_bandwidth(&mut self, bandwidth: u64) {
        self.target_bandwidth = bandwidth;
    }

    /// Calculate padding needed for a payload to maintain η² ratio
    ///
    /// Real data should be η² (50%) of total, so padding = payload
    pub fn calculate_padding(&self, payload_size: usize) -> usize {
        // η² = 0.5, so padding equals payload for 50/50 split
        // This is the silver ratio identity in action
        let ratio = LAMBDA_SQUARED / ETA_SQUARED; // = 1.0 when balanced
        (payload_size as f64 * ratio) as usize
    }

    /// Calculate total packet size for a payload
    pub fn total_size(&self, payload_size: usize) -> usize {
        payload_size + self.calculate_padding(payload_size)
    }

    /// Record bytes sent (real data)
    pub fn record_real(&mut self, bytes: usize) {
        self.real_bytes_sent += bytes as u64;
        self.bytes_sent += bytes as u64;
        self.maybe_reset_window();
    }

    /// Record padding bytes sent
    pub fn record_padding(&mut self, bytes: usize) {
        self.padding_bytes_sent += bytes as u64;
        self.bytes_sent += bytes as u64;
        self.maybe_reset_window();
    }

    /// Record a complete packet (real + padding)
    pub fn record_packet(&mut self, real_bytes: usize, padding_bytes: usize) {
        self.real_bytes_sent += real_bytes as u64;
        self.padding_bytes_sent += padding_bytes as u64;
        self.bytes_sent += (real_bytes + padding_bytes) as u64;
        self.maybe_reset_window();
    }

    /// Reset window if duration exceeded
    fn maybe_reset_window(&mut self) {
        if self.window_start.elapsed() >= self.window_duration {
            self.reset_window();
        }
    }

    /// Reset the current window
    pub fn reset_window(&mut self) {
        self.bytes_sent = 0;
        self.real_bytes_sent = 0;
        self.padding_bytes_sent = 0;
        self.window_start = Instant::now();
    }

    /// Calculate delay needed before sending more data
    ///
    /// Returns how long to wait to stay within bandwidth target.
    pub fn calculate_delay(&self) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }

        let elapsed = self.window_start.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();

        if elapsed_secs <= 0.0 {
            return Duration::ZERO;
        }

        // Calculate current bandwidth
        let current_bps = self.bytes_sent as f64 / elapsed_secs;

        if current_bps <= self.target_bandwidth as f64 {
            Duration::ZERO
        } else {
            // Calculate how long to wait to bring average down
            let target_time = self.bytes_sent as f64 / self.target_bandwidth as f64;
            let delay_secs = target_time - elapsed_secs;
            if delay_secs > 0.0 {
                Duration::from_secs_f64(delay_secs)
            } else {
                Duration::ZERO
            }
        }
    }

    /// Check if we can send more data without exceeding bandwidth
    pub fn can_send(&self, bytes: usize) -> bool {
        if !self.enabled {
            return true;
        }

        // Always allow first packet (burst allowance)
        if self.bytes_sent == 0 {
            return true;
        }

        let elapsed = self.window_start.elapsed();
        let elapsed_secs = elapsed.as_secs_f64().max(0.001); // Avoid division by zero

        let projected_bytes = self.bytes_sent + bytes as u64;
        let projected_bps = projected_bytes as f64 / elapsed_secs;

        projected_bps <= self.target_bandwidth as f64 * 1.1 // 10% tolerance
    }

    /// Get current bandwidth (bytes per second)
    pub fn current_bandwidth(&self) -> f64 {
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_sent as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Get the real/padding ratio (should be close to η²/λ² = 1.0)
    pub fn ratio(&self) -> f64 {
        if self.padding_bytes_sent > 0 {
            self.real_bytes_sent as f64 / self.padding_bytes_sent as f64
        } else if self.real_bytes_sent > 0 {
            f64::INFINITY
        } else {
            1.0 // No data sent, ratio is balanced by definition
        }
    }

    /// Check if ratio is within silver bounds
    pub fn is_balanced(&self) -> bool {
        let ratio = self.ratio();
        // Should be close to 1.0 (η² = λ² = 0.5)
        ratio >= 0.8 && ratio <= 1.25
    }

    /// Get shaping statistics
    pub fn stats(&self) -> ShapingStats {
        ShapingStats {
            target_bandwidth: self.target_bandwidth,
            current_bandwidth: self.current_bandwidth(),
            bytes_sent: self.bytes_sent,
            real_bytes: self.real_bytes_sent,
            padding_bytes: self.padding_bytes_sent,
            ratio: self.ratio(),
            is_balanced: self.is_balanced(),
            window_elapsed: self.window_start.elapsed(),
        }
    }

    /// Enable/disable shaping
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if shaping is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Shaping statistics
#[derive(Debug, Clone)]
pub struct ShapingStats {
    /// Target bandwidth (bytes/sec)
    pub target_bandwidth: u64,
    /// Current bandwidth (bytes/sec)
    pub current_bandwidth: f64,
    /// Total bytes sent in window
    pub bytes_sent: u64,
    /// Real data bytes
    pub real_bytes: u64,
    /// Padding bytes
    pub padding_bytes: u64,
    /// Real/padding ratio
    pub ratio: f64,
    /// Whether ratio is balanced
    pub is_balanced: bool,
    /// Time since window start
    pub window_elapsed: Duration,
}

/// Bandwidth tier based on silver ratio
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthTier {
    /// Low bandwidth: base rate
    Low,
    /// Medium bandwidth: τ * base
    Medium,
    /// High bandwidth: δ_S * base
    High,
}

impl BandwidthTier {
    /// Get multiplier for this tier
    pub fn multiplier(&self) -> f64 {
        match self {
            BandwidthTier::Low => 1.0,
            BandwidthTier::Medium => TAU,
            BandwidthTier::High => DELTA_S,
        }
    }

    /// Calculate bandwidth for this tier given a base rate
    pub fn bandwidth(&self, base: u64) -> u64 {
        (base as f64 * self.multiplier()) as u64
    }

    /// Get tier from multiplier
    pub fn from_multiplier(m: f64) -> Self {
        if m >= DELTA_S * 0.9 {
            BandwidthTier::High
        } else if m >= TAU * 0.9 {
            BandwidthTier::Medium
        } else {
            BandwidthTier::Low
        }
    }
}

/// Adaptive bandwidth controller
pub struct BandwidthController {
    /// Base bandwidth
    base_bandwidth: u64,
    /// Current tier
    current_tier: BandwidthTier,
    /// Traffic shaper
    shaper: TrafficShaper,
}

impl BandwidthController {
    /// Create new controller
    pub fn new(base_bandwidth: u64) -> Self {
        Self {
            base_bandwidth,
            current_tier: BandwidthTier::Medium,
            shaper: TrafficShaper::new((base_bandwidth as f64 * TAU) as u64),
        }
    }

    /// Set bandwidth tier
    pub fn set_tier(&mut self, tier: BandwidthTier) {
        self.current_tier = tier;
        self.shaper.set_target_bandwidth(tier.bandwidth(self.base_bandwidth));
    }

    /// Get current tier
    pub fn current_tier(&self) -> BandwidthTier {
        self.current_tier
    }

    /// Upgrade tier (if possible)
    pub fn upgrade(&mut self) -> bool {
        match self.current_tier {
            BandwidthTier::Low => {
                self.set_tier(BandwidthTier::Medium);
                true
            }
            BandwidthTier::Medium => {
                self.set_tier(BandwidthTier::High);
                true
            }
            BandwidthTier::High => false,
        }
    }

    /// Downgrade tier (if possible)
    pub fn downgrade(&mut self) -> bool {
        match self.current_tier {
            BandwidthTier::High => {
                self.set_tier(BandwidthTier::Medium);
                true
            }
            BandwidthTier::Medium => {
                self.set_tier(BandwidthTier::Low);
                true
            }
            BandwidthTier::Low => false,
        }
    }

    /// Get shaper reference
    pub fn shaper(&self) -> &TrafficShaper {
        &self.shaper
    }

    /// Get mutable shaper reference
    pub fn shaper_mut(&mut self) -> &mut TrafficShaper {
        &mut self.shaper
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shaper_creation() {
        let shaper = TrafficShaper::new(1_000_000);
        assert_eq!(shaper.target_bandwidth(), 1_000_000);
    }

    #[test]
    fn test_padding_calculation() {
        let shaper = TrafficShaper::new(1_000_000);

        // For η² = λ² = 0.5, padding should equal payload
        let padding = shaper.calculate_padding(100);
        assert_eq!(padding, 100);

        let total = shaper.total_size(100);
        assert_eq!(total, 200);
    }

    #[test]
    fn test_silver_ratio_identity() {
        // Verify η² + λ² = 1
        assert!((ETA_SQUARED + LAMBDA_SQUARED - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_record_packet() {
        let mut shaper = TrafficShaper::new(1_000_000);

        shaper.record_packet(100, 100);

        let stats = shaper.stats();
        assert_eq!(stats.real_bytes, 100);
        assert_eq!(stats.padding_bytes, 100);
        assert_eq!(stats.bytes_sent, 200);
        assert!((stats.ratio - 1.0).abs() < 0.01);
        assert!(stats.is_balanced);
    }

    #[test]
    fn test_ratio_balanced() {
        let mut shaper = TrafficShaper::new(1_000_000);

        // Balanced: equal real and padding
        shaper.record_packet(100, 100);
        assert!(shaper.is_balanced());

        // Reset and test unbalanced
        shaper.reset_window();
        shaper.record_packet(100, 10); // Way more real than padding
        assert!(!shaper.is_balanced());
    }

    #[test]
    fn test_bandwidth_tier() {
        let base = 1_000_000u64;

        assert_eq!(BandwidthTier::Low.bandwidth(base), 1_000_000);
        assert_eq!(
            BandwidthTier::Medium.bandwidth(base),
            (1_000_000.0 * TAU) as u64
        );
        assert_eq!(
            BandwidthTier::High.bandwidth(base),
            (1_000_000.0 * DELTA_S) as u64
        );
    }

    #[test]
    fn test_bandwidth_controller() {
        let mut controller = BandwidthController::new(1_000_000);

        assert_eq!(controller.current_tier(), BandwidthTier::Medium);

        // Upgrade
        assert!(controller.upgrade());
        assert_eq!(controller.current_tier(), BandwidthTier::High);

        // Can't upgrade further
        assert!(!controller.upgrade());

        // Downgrade
        assert!(controller.downgrade());
        assert_eq!(controller.current_tier(), BandwidthTier::Medium);

        assert!(controller.downgrade());
        assert_eq!(controller.current_tier(), BandwidthTier::Low);

        // Can't downgrade further
        assert!(!controller.downgrade());
    }

    #[test]
    fn test_can_send() {
        let shaper = TrafficShaper::new(1000); // 1000 bytes/sec

        // At start, should be able to send
        assert!(shaper.can_send(100));
    }

    #[test]
    fn test_shaper_disable() {
        let mut shaper = TrafficShaper::new(1000);

        shaper.set_enabled(false);
        assert!(!shaper.is_enabled());

        // When disabled, always can send
        assert!(shaper.can_send(1_000_000));
        assert_eq!(shaper.calculate_delay(), Duration::ZERO);
    }
}
