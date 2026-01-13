//! Connection Management
//!
//! Handles connection lifecycle and reconnection logic.

use silver_timing::SilverBackoff;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Server address
    pub server_addr: SocketAddr,
    /// Connection time
    pub connected_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Reconnection count
    pub reconnect_count: u32,
}

impl ConnectionInfo {
    /// Create new connection info
    pub fn new(server_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            server_addr,
            connected_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            reconnect_count: 0,
        }
    }

    /// Record sent data
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
        self.last_activity = Instant::now();
    }

    /// Record received data
    pub fn record_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
        self.last_activity = Instant::now();
    }

    /// Get connection duration
    pub fn duration(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Increment reconnection count
    pub fn increment_reconnect(&mut self) {
        self.reconnect_count += 1;
    }
}

/// Reconnection handler with silver-ratio backoff
pub struct ReconnectionHandler {
    /// Maximum attempts
    max_attempts: u32,
    /// Current attempt
    current_attempt: u32,
    /// Backoff calculator
    backoff: SilverBackoff,
    /// Whether reconnection is in progress
    reconnecting: bool,
}

impl ReconnectionHandler {
    /// Create new reconnection handler
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            current_attempt: 0,
            backoff: SilverBackoff::new(1_000_000), // 1 second base
            reconnecting: false,
        }
    }

    /// Start reconnection process
    pub fn start(&mut self) {
        self.reconnecting = true;
        self.current_attempt = 0;
        self.backoff.reset();
    }

    /// Get next reconnection delay
    pub fn next_delay(&mut self) -> Option<Duration> {
        if !self.reconnecting || self.current_attempt >= self.max_attempts {
            return None;
        }

        self.current_attempt += 1;
        Some(self.backoff.backoff())
    }

    /// Check if should retry
    pub fn should_retry(&self) -> bool {
        self.reconnecting && self.current_attempt < self.max_attempts
    }

    /// Stop reconnection
    pub fn stop(&mut self) {
        self.reconnecting = false;
    }

    /// Check if reconnecting
    pub fn is_reconnecting(&self) -> bool {
        self.reconnecting
    }

    /// Get current attempt number
    pub fn current_attempt(&self) -> u32 {
        self.current_attempt
    }

    /// Get remaining attempts
    pub fn remaining_attempts(&self) -> u32 {
        self.max_attempts.saturating_sub(self.current_attempt)
    }

    /// Reset the handler
    pub fn reset(&mut self) {
        self.current_attempt = 0;
        self.reconnecting = false;
        self.backoff.reset();
    }
}

/// Connection health check
pub struct HealthChecker {
    /// Last check time
    last_check: Instant,
    /// Check interval
    interval: Duration,
    /// Consecutive failures
    failures: u32,
    /// Max failures before unhealthy
    max_failures: u32,
}

impl HealthChecker {
    /// Create new health checker
    pub fn new(interval: Duration) -> Self {
        Self {
            last_check: Instant::now(),
            interval,
            failures: 0,
            max_failures: 3,
        }
    }

    /// Check if health check is due
    pub fn is_check_due(&self) -> bool {
        self.last_check.elapsed() >= self.interval
    }

    /// Record successful check
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.last_check = Instant::now();
    }

    /// Record failed check
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.last_check = Instant::now();
    }

    /// Check if connection is healthy
    pub fn is_healthy(&self) -> bool {
        self.failures < self.max_failures
    }

    /// Get failure count
    pub fn failure_count(&self) -> u32 {
        self.failures
    }

    /// Reset the checker
    pub fn reset(&mut self) {
        self.failures = 0;
        self.last_check = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_info() {
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let mut info = ConnectionInfo::new(addr);

        assert_eq!(info.bytes_sent, 0);
        assert_eq!(info.packets_sent, 0);

        info.record_sent(100);
        assert_eq!(info.bytes_sent, 100);
        assert_eq!(info.packets_sent, 1);

        info.record_received(200);
        assert_eq!(info.bytes_received, 200);
        assert_eq!(info.packets_received, 1);
    }

    #[test]
    fn test_reconnection_handler() {
        let mut handler = ReconnectionHandler::new(3);

        assert!(!handler.is_reconnecting());

        handler.start();
        assert!(handler.is_reconnecting());
        assert_eq!(handler.remaining_attempts(), 3);

        // First attempt
        let delay1 = handler.next_delay();
        assert!(delay1.is_some());
        assert_eq!(handler.current_attempt(), 1);

        // Second attempt (should be longer)
        let delay2 = handler.next_delay();
        assert!(delay2.is_some());
        assert!(delay2.unwrap() > delay1.unwrap());

        // Third attempt
        let delay3 = handler.next_delay();
        assert!(delay3.is_some());

        // No more attempts
        let delay4 = handler.next_delay();
        assert!(delay4.is_none());
    }

    #[test]
    fn test_health_checker() {
        let mut checker = HealthChecker::new(Duration::from_secs(30));

        assert!(checker.is_healthy());
        assert_eq!(checker.failure_count(), 0);

        checker.record_failure();
        assert!(checker.is_healthy()); // Still healthy after 1 failure

        checker.record_failure();
        checker.record_failure();
        assert!(!checker.is_healthy()); // Unhealthy after 3 failures

        checker.record_success();
        assert!(checker.is_healthy()); // Back to healthy
        assert_eq!(checker.failure_count(), 0);
    }
}
