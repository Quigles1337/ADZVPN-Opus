//! Protocol Error Types

use thiserror::Error;
use crate::constants::ErrorCode;

/// Protocol errors
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Invalid packet format
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Packet too small
    #[error("Packet too small: got {got} bytes, need at least {min}")]
    PacketTooSmall { got: usize, min: usize },

    /// Packet too large
    #[error("Packet too large: got {got} bytes, max is {max}")]
    PacketTooLarge { got: usize, max: usize },

    /// Invalid packet type
    #[error("Unknown packet type: 0x{0:02x}")]
    UnknownPacketType(u8),

    /// Decryption failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Session expired
    #[error("Session expired")]
    SessionExpired,

    /// Handshake error
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Invalid state for operation
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Protocol version mismatch
    #[error("Version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u16, got: u16 },

    /// Nonce reuse detected
    #[error("Nonce reuse detected")]
    NonceReuse,

    /// Key rotation required
    #[error("Key rotation required")]
    KeyRotationRequired,

    /// Crypto error from silver-crypto
    #[error("Crypto error: {0}")]
    CryptoError(#[from] silver_crypto::CryptoError),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl ProtocolError {
    /// Convert to error code for wire format
    pub fn to_error_code(&self) -> ErrorCode {
        match self {
            ProtocolError::InvalidPacket(_) => ErrorCode::InvalidPacket,
            ProtocolError::PacketTooSmall { .. } => ErrorCode::InvalidPacket,
            ProtocolError::PacketTooLarge { .. } => ErrorCode::InvalidPacket,
            ProtocolError::UnknownPacketType(_) => ErrorCode::InvalidPacket,
            ProtocolError::DecryptionFailed => ErrorCode::DecryptionFailed,
            ProtocolError::EncryptionFailed(_) => ErrorCode::Unknown,
            ProtocolError::SessionNotFound(_) => ErrorCode::SessionNotFound,
            ProtocolError::SessionExpired => ErrorCode::SessionExpired,
            ProtocolError::HandshakeFailed(_) => ErrorCode::HandshakeFailed,
            ProtocolError::VersionMismatch { .. } => ErrorCode::VersionMismatch,
            _ => ErrorCode::Unknown,
        }
    }
}

/// Result type for protocol operations
pub type ProtocolResult<T> = Result<T, ProtocolError>;
