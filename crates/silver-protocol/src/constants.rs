//! Protocol Constants
//!
//! Version numbers, sizes, and protocol parameters.

/// Protocol version (major.minor)
pub const PROTOCOL_VERSION: u16 = 0x0001;

/// Protocol magic bytes for identification
pub const PROTOCOL_MAGIC: [u8; 4] = [0x41, 0x44, 0x5A, 0x56]; // "ADZV"

/// Maximum packet size (including headers and padding)
pub const MAX_PACKET_SIZE: usize = 1500; // MTU-friendly

/// Minimum packet size (after padding)
pub const MIN_PACKET_SIZE: usize = 64;

/// Header size in bytes
pub const HEADER_SIZE: usize = 4;

/// Session ID size
pub const SESSION_ID_SIZE: usize = 16;

/// Timestamp size
pub const TIMESTAMP_SIZE: usize = 8;

// Note: NONCE_SIZE, TAG_SIZE, PUBLIC_KEY_SIZE are imported from silver_crypto::prelude

/// Handshake timeout in seconds
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Session timeout in seconds (idle)
pub const SESSION_IDLE_TIMEOUT_SECS: u64 = 120;

/// Key rotation interval in seconds
pub const KEY_ROTATION_INTERVAL_SECS: u64 = 3600; // 1 hour

/// Maximum packets before forced key rotation
pub const MAX_PACKETS_PER_KEY: u64 = 1_000_000;

/// Packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Client hello (handshake initiation)
    ClientHello = 0x01,
    /// Server hello (handshake response)
    ServerHello = 0x02,
    /// Encrypted data packet
    Data = 0x03,
    /// Keep-alive packet
    KeepAlive = 0x04,
    /// Key rotation request
    KeyRotation = 0x05,
    /// Session close
    Close = 0x06,
    /// Error/rejection
    Error = 0xFF,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(PacketType::ClientHello),
            0x02 => Some(PacketType::ServerHello),
            0x03 => Some(PacketType::Data),
            0x04 => Some(PacketType::KeepAlive),
            0x05 => Some(PacketType::KeyRotation),
            0x06 => Some(PacketType::Close),
            0xFF => Some(PacketType::Error),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Error codes for protocol errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Unknown/generic error
    Unknown = 0x00,
    /// Invalid packet format
    InvalidPacket = 0x01,
    /// Decryption failed
    DecryptionFailed = 0x02,
    /// Session not found
    SessionNotFound = 0x03,
    /// Session expired
    SessionExpired = 0x04,
    /// Handshake failed
    HandshakeFailed = 0x05,
    /// Rate limited
    RateLimited = 0x06,
    /// Server full
    ServerFull = 0x07,
    /// Protocol version mismatch
    VersionMismatch = 0x08,
}

impl ErrorCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => ErrorCode::InvalidPacket,
            0x02 => ErrorCode::DecryptionFailed,
            0x03 => ErrorCode::SessionNotFound,
            0x04 => ErrorCode::SessionExpired,
            0x05 => ErrorCode::HandshakeFailed,
            0x06 => ErrorCode::RateLimited,
            0x07 => ErrorCode::ServerFull,
            0x08 => ErrorCode::VersionMismatch,
            _ => ErrorCode::Unknown,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_magic() {
        assert_eq!(&PROTOCOL_MAGIC, b"ADZV");
    }

    #[test]
    fn test_packet_type_roundtrip() {
        for pt in [
            PacketType::ClientHello,
            PacketType::ServerHello,
            PacketType::Data,
            PacketType::KeepAlive,
            PacketType::KeyRotation,
            PacketType::Close,
            PacketType::Error,
        ] {
            let byte = pt.to_u8();
            let recovered = PacketType::from_u8(byte).unwrap();
            assert_eq!(pt, recovered);
        }
    }

    #[test]
    fn test_error_code_roundtrip() {
        for ec in [
            ErrorCode::InvalidPacket,
            ErrorCode::DecryptionFailed,
            ErrorCode::SessionNotFound,
        ] {
            let byte = ec.to_u8();
            let recovered = ErrorCode::from_u8(byte);
            assert_eq!(ec, recovered);
        }
    }
}
