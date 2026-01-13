//! Timing Errors
//!
//! Error types for the silver timing system.

use thiserror::Error;

/// Result type for timing operations
pub type TimingResult<T> = Result<T, TimingError>;

/// Timing errors
#[derive(Error, Debug)]
pub enum TimingError {
    /// Invalid timing configuration
    #[error("Invalid timing configuration: {0}")]
    InvalidConfig(String),

    /// Timing deadline exceeded
    #[error("Timing deadline exceeded by {exceeded_us} microseconds")]
    DeadlineExceeded { exceeded_us: u64 },

    /// Scheduler stopped
    #[error("Scheduler has been stopped")]
    SchedulerStopped,

    /// Channel closed
    #[error("Timing channel closed")]
    ChannelClosed,

    /// Invalid bandwidth target
    #[error("Invalid bandwidth target: {0} bytes/sec")]
    InvalidBandwidth(u64),
}
