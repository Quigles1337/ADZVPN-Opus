//! Server Errors
//!
//! Error types for the VPN server.

use thiserror::Error;

/// Result type for server operations
pub type ServerResult<T> = Result<T, ServerError>;

/// Server errors
#[derive(Error, Debug)]
pub enum ServerError {
    /// Server is already running
    #[error("Server is already running")]
    AlreadyRunning,

    /// Server is not running
    #[error("Server is not running")]
    NotRunning,

    /// Failed to bind to address
    #[error("Failed to bind to {address}: {reason}")]
    BindFailed { address: String, reason: String },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Handshake error
    #[error("Handshake failed: {0}")]
    Handshake(String),

    /// Session not found
    #[error("Session not found")]
    SessionNotFound,

    /// Session limit reached
    #[error("Maximum sessions ({max}) reached")]
    SessionLimitReached { max: usize },

    /// Packet too small
    #[error("Packet too small to parse")]
    PacketTooSmall,

    /// Packet too large
    #[error("Packet exceeds maximum size")]
    PacketTooLarge,

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error
    #[error("Decryption failed")]
    Decryption,

    /// Tunnel error
    #[error("Tunnel error: {0}")]
    Tunnel(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Channel closed
    #[error("Internal channel closed")]
    ChannelClosed,
}

impl From<silver_protocol::ProtocolError> for ServerError {
    fn from(e: silver_protocol::ProtocolError) -> Self {
        ServerError::Protocol(e.to_string())
    }
}
