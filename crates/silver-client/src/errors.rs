//! Client Errors
//!
//! Error types for the VPN client.

use thiserror::Error;

/// Result type for client operations
pub type ClientResult<T> = Result<T, ClientError>;

/// Client errors
#[derive(Error, Debug)]
pub enum ClientError {
    /// Already connected
    #[error("Already connected to server")]
    AlreadyConnected,

    /// Not connected
    #[error("Not connected to server")]
    NotConnected,

    /// Connection failed
    #[error("Failed to connect: {0}")]
    ConnectionFailed(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    Handshake(String),

    /// Handshake timeout
    #[error("Handshake timed out")]
    HandshakeTimeout,

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption failed
    #[error("Decryption failed")]
    Decryption,

    /// Invalid server address
    #[error("Invalid server address: {0}")]
    InvalidAddress(String),

    /// DNS resolution failed
    #[error("DNS resolution failed for {host}: {reason}")]
    DnsResolutionFailed { host: String, reason: String },

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Session expired
    #[error("Session expired")]
    SessionExpired,

    /// Server rejected connection
    #[error("Server rejected connection: {0}")]
    Rejected(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Channel closed
    #[error("Internal channel closed")]
    ChannelClosed,

    /// Reconnection failed
    #[error("Reconnection failed after {attempts} attempts")]
    ReconnectionFailed { attempts: u32 },
}

impl From<silver_protocol::ProtocolError> for ClientError {
    fn from(e: silver_protocol::ProtocolError) -> Self {
        ClientError::Protocol(e.to_string())
    }
}
