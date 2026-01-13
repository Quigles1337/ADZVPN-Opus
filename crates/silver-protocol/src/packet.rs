//! Silver Packet Format
//!
//! Implements the Silver packet format with η-padding for traffic analysis resistance.
//!
//! ## Packet Structure
//!
//! ```text
//! +--------+----------+------------+---------+----------+
//! | Header | Nonce    | Encrypted  | Auth    | Silver   |
//! | 4 bytes| 12 bytes | Payload    | Tag 16B | Pad η    |
//! +--------+----------+------------+---------+----------+
//! ```
//!
//! ## Header Format (4 bytes)
//!
//! ```text
//! +------+------+----------+
//! | Type | Flags| Reserved |
//! | 1B   | 1B   | 2B       |
//! +------+------+----------+
//! ```
//!
//! ## Silver Padding (η² + λ² = 1)
//!
//! Real payload is η² (50%) of total, padding is λ² (50%).
//! This creates constant-bandwidth channels resistant to traffic analysis.

// bytes crate available for future packet buffer operations
use rand::RngCore;
use silver_core::{silver_padding_size, silver_total_size};
use silver_crypto::prelude::*;

use crate::constants::*;
use crate::errors::{ProtocolError, ProtocolResult};
use crate::session::Session;

/// Packet header
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Packet type
    pub packet_type: PacketType,
    /// Flags
    pub flags: PacketFlags,
    /// Reserved (protocol version in handshake packets)
    pub reserved: u16,
}

impl PacketHeader {
    /// Create a new header
    pub fn new(packet_type: PacketType) -> Self {
        Self {
            packet_type,
            flags: PacketFlags::empty(),
            reserved: 0,
        }
    }

    /// Create header with flags
    pub fn with_flags(packet_type: PacketType, flags: PacketFlags) -> Self {
        Self {
            packet_type,
            flags,
            reserved: 0,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = self.packet_type.to_u8();
        buf[1] = self.flags.bits();
        buf[2..4].copy_from_slice(&self.reserved.to_le_bytes());
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                got: data.len(),
                min: HEADER_SIZE,
            });
        }

        let packet_type = PacketType::from_u8(data[0])
            .ok_or(ProtocolError::UnknownPacketType(data[0]))?;
        let flags = PacketFlags::from_bits_truncate(data[1]);
        let reserved = u16::from_le_bytes([data[2], data[3]]);

        Ok(Self {
            packet_type,
            flags,
            reserved,
        })
    }
}

/// Packet flags
#[derive(Debug, Clone, Copy)]
pub struct PacketFlags(u8);

impl PacketFlags {
    /// No flags set
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Compressed payload
    pub const COMPRESSED: Self = Self(0x01);

    /// Priority packet (expedited handling)
    pub const PRIORITY: Self = Self(0x02);

    /// Padded to fixed size
    pub const PADDED: Self = Self(0x04);

    /// Fragment (more fragments follow)
    pub const FRAGMENT: Self = Self(0x08);

    /// Last fragment
    pub const LAST_FRAGMENT: Self = Self(0x10);

    /// Check if flag is set
    pub fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set a flag
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    /// Get raw bits
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// Create from bits (truncating unknown flags)
    pub fn from_bits_truncate(bits: u8) -> Self {
        Self(bits & 0x1F) // Only lower 5 bits are defined
    }
}

impl std::ops::BitOr for PacketFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Silver Packet - the main encrypted packet type
#[derive(Debug, Clone)]
pub struct SilverPacket {
    /// Packet header
    pub header: PacketHeader,
    /// Nonce used for encryption
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted payload (includes padding and auth tag)
    pub ciphertext: Vec<u8>,
}

impl SilverPacket {
    /// Create a new data packet with silver padding
    pub fn new_data(payload: &[u8], session: &Session) -> ProtocolResult<Self> {
        Self::new_data_with_flags(payload, session, PacketFlags::empty())
    }

    /// Create a new data packet with flags
    pub fn new_data_with_flags(
        payload: &[u8],
        session: &Session,
        mut flags: PacketFlags,
    ) -> ProtocolResult<Self> {
        // Apply silver padding
        let padded = Self::apply_silver_padding(payload);
        flags.set(PacketFlags::PADDED);

        // Encrypt with session cipher
        let (ciphertext, nonce) = session.encrypt(&padded)?;

        let header = PacketHeader::with_flags(PacketType::Data, flags);

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }

    /// Create a keep-alive packet
    pub fn new_keepalive(session: &Session) -> ProtocolResult<Self> {
        let payload = [0u8; 1]; // Minimal payload
        let padded = Self::apply_silver_padding(&payload);

        let (ciphertext, nonce) = session.encrypt(&padded)?;

        let header = PacketHeader::with_flags(PacketType::KeepAlive, PacketFlags::PADDED);

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }

    /// Create a close packet
    pub fn new_close(session: &Session) -> ProtocolResult<Self> {
        let payload = [0u8; 1];
        let padded = Self::apply_silver_padding(&payload);

        let (ciphertext, nonce) = session.encrypt(&padded)?;

        let header = PacketHeader::new(PacketType::Close);

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }

    /// Apply silver padding (η² + λ² = 1)
    ///
    /// Pads payload so real data is η² of total, padding is λ².
    fn apply_silver_padding(payload: &[u8]) -> Vec<u8> {
        let payload_len = payload.len();
        let _padding_len = silver_padding_size(payload_len);
        let total_len = silver_total_size(payload_len);

        // Ensure minimum packet size
        let total_len = total_len.max(MIN_PACKET_SIZE - HEADER_SIZE - NONCE_SIZE - TAG_SIZE);

        let mut padded = Vec::with_capacity(total_len + 2); // +2 for length prefix

        // Length prefix (2 bytes) - actual payload length
        padded.extend_from_slice(&(payload_len as u16).to_le_bytes());

        // Actual payload
        padded.extend_from_slice(payload);

        // Silver padding (random chaff)
        let current_len = padded.len();
        let remaining = total_len.saturating_sub(current_len);
        if remaining > 0 {
            let mut chaff = vec![0u8; remaining];
            rand::thread_rng().fill_bytes(&mut chaff);
            padded.extend_from_slice(&chaff);
        }

        padded
    }

    /// Remove silver padding and extract payload
    fn remove_silver_padding(padded: &[u8]) -> ProtocolResult<Vec<u8>> {
        if padded.len() < 2 {
            return Err(ProtocolError::InvalidPacket(
                "Padded data too short for length prefix".into(),
            ));
        }

        // Read length prefix
        let payload_len = u16::from_le_bytes([padded[0], padded[1]]) as usize;

        if padded.len() < 2 + payload_len {
            return Err(ProtocolError::InvalidPacket(format!(
                "Padded data too short: need {} bytes, have {}",
                2 + payload_len,
                padded.len()
            )));
        }

        // Extract payload (skip length prefix, ignore padding)
        Ok(padded[2..2 + payload_len].to_vec())
    }

    /// Decrypt packet and extract payload
    pub fn decrypt(&self, session: &Session) -> ProtocolResult<Vec<u8>> {
        let padded = session.decrypt(&self.ciphertext, &self.nonce)?;

        if self.header.flags.contains(PacketFlags::PADDED) {
            Self::remove_silver_padding(&padded)
        } else {
            Ok(padded)
        }
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + NONCE_SIZE + self.ciphertext.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        let min_size = HEADER_SIZE + NONCE_SIZE + TAG_SIZE;
        if data.len() < min_size {
            return Err(ProtocolError::PacketTooSmall {
                got: data.len(),
                min: min_size,
            });
        }

        if data.len() > MAX_PACKET_SIZE {
            return Err(ProtocolError::PacketTooLarge {
                got: data.len(),
                max: MAX_PACKET_SIZE,
            });
        }

        let header = PacketHeader::from_bytes(&data[0..HEADER_SIZE])?;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[HEADER_SIZE..HEADER_SIZE + NONCE_SIZE]);

        let ciphertext = data[HEADER_SIZE + NONCE_SIZE..].to_vec();

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }

    /// Get total packet size
    pub fn size(&self) -> usize {
        HEADER_SIZE + NONCE_SIZE + self.ciphertext.len()
    }
}

/// Unencrypted packet for handshake
#[derive(Debug, Clone)]
pub struct HandshakePacket {
    /// Packet header
    pub header: PacketHeader,
    /// Unencrypted payload
    pub payload: Vec<u8>,
}

impl HandshakePacket {
    /// Create a new handshake packet
    pub fn new(packet_type: PacketType, payload: Vec<u8>) -> Self {
        let mut header = PacketHeader::new(packet_type);
        header.reserved = PROTOCOL_VERSION;

        Self { header, payload }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                got: data.len(),
                min: HEADER_SIZE,
            });
        }

        let header = PacketHeader::from_bytes(&data[0..HEADER_SIZE])?;
        let payload = data[HEADER_SIZE..].to_vec();

        Ok(Self { header, payload })
    }
}

/// Calculate silver-padded size for a payload
pub fn padded_packet_size(payload_len: usize) -> usize {
    let padded_payload = silver_total_size(payload_len) + 2; // +2 for length prefix
    let padded_payload = padded_payload.max(MIN_PACKET_SIZE - HEADER_SIZE - NONCE_SIZE - TAG_SIZE);
    HEADER_SIZE + NONCE_SIZE + padded_payload + TAG_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_roundtrip() {
        let header = PacketHeader::with_flags(
            PacketType::Data,
            PacketFlags::PADDED | PacketFlags::PRIORITY,
        );

        let bytes = header.to_bytes();
        let recovered = PacketHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.packet_type, recovered.packet_type);
        assert_eq!(header.flags.bits(), recovered.flags.bits());
    }

    #[test]
    fn test_packet_flags() {
        let mut flags = PacketFlags::empty();
        assert!(!flags.contains(PacketFlags::PADDED));

        flags.set(PacketFlags::PADDED);
        assert!(flags.contains(PacketFlags::PADDED));

        flags.set(PacketFlags::PRIORITY);
        assert!(flags.contains(PacketFlags::PADDED));
        assert!(flags.contains(PacketFlags::PRIORITY));

        flags.clear(PacketFlags::PADDED);
        assert!(!flags.contains(PacketFlags::PADDED));
        assert!(flags.contains(PacketFlags::PRIORITY));
    }

    #[test]
    fn test_silver_padding_roundtrip() {
        let payload = b"Hello, ADZVPN-Opus!";
        let padded = SilverPacket::apply_silver_padding(payload);

        // Should be larger due to padding
        assert!(padded.len() > payload.len());

        // Should be able to recover original
        let recovered = SilverPacket::remove_silver_padding(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_silver_padding_ratio() {
        let payload = vec![0u8; 100];
        let padded = SilverPacket::apply_silver_padding(&payload);

        // Real data should be ~η² (50%) of total
        // Note: includes 2-byte length prefix
        let total_len = padded.len();
        let real_len = payload.len() + 2; // +2 for length prefix
        let ratio = real_len as f64 / total_len as f64;

        // Should be close to η² = 0.5 (with some tolerance for minimum size)
        assert!(ratio <= 0.6, "Ratio {} should be <= 0.6", ratio);
    }

    #[test]
    fn test_empty_payload_padding() {
        let payload = b"";
        let padded = SilverPacket::apply_silver_padding(payload);

        // Should still have minimum size
        assert!(padded.len() >= 2); // At least length prefix

        let recovered = SilverPacket::remove_silver_padding(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_handshake_packet_roundtrip() {
        let packet = HandshakePacket::new(PacketType::ClientHello, vec![1, 2, 3, 4, 5]);

        let bytes = packet.to_bytes();
        let recovered = HandshakePacket::from_bytes(&bytes).unwrap();

        assert_eq!(packet.header.packet_type, recovered.header.packet_type);
        assert_eq!(packet.payload, recovered.payload);
        assert_eq!(recovered.header.reserved, PROTOCOL_VERSION);
    }

    #[test]
    fn test_padded_packet_size() {
        let size = padded_packet_size(100);

        // Should include header, nonce, padded payload, and tag
        assert!(size > HEADER_SIZE + NONCE_SIZE + 100 + TAG_SIZE);

        // Should be reasonable size
        assert!(size <= MAX_PACKET_SIZE);
    }
}
