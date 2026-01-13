//! Client Tunnel
//!
//! Handles encrypted tunnel operations on the client side.

use crate::errors::ClientError;
use silver_protocol::{Session, SilverPacket};
use std::time::{Duration, Instant};

/// Tunnel statistics
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    /// Bytes sent through tunnel
    pub bytes_sent: u64,
    /// Bytes received through tunnel
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Encryption errors
    pub encryption_errors: u64,
    /// Decryption errors
    pub decryption_errors: u64,
    /// Last packet time
    pub last_packet: Option<Instant>,
}

impl TunnelStats {
    /// Record sent packet
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
        self.last_packet = Some(Instant::now());
    }

    /// Record received packet
    pub fn record_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
        self.last_packet = Some(Instant::now());
    }

    /// Record encryption error
    pub fn record_encryption_error(&mut self) {
        self.encryption_errors += 1;
    }

    /// Record decryption error
    pub fn record_decryption_error(&mut self) {
        self.decryption_errors += 1;
    }

    /// Get total bytes
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    /// Get total packets
    pub fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_received
    }

    /// Get total errors
    pub fn total_errors(&self) -> u64 {
        self.encryption_errors + self.decryption_errors
    }

    /// Get idle time
    pub fn idle_time(&self) -> Option<Duration> {
        self.last_packet.map(|t| t.elapsed())
    }
}

/// Encrypt data for tunnel transmission
pub fn encrypt_payload(session: &Session, data: &[u8]) -> Result<Vec<u8>, ClientError> {
    let packet = SilverPacket::new_data(data, session)
        .map_err(|e| ClientError::Encryption(e.to_string()))?;

    Ok(packet.to_bytes())
}

/// Decrypt data from tunnel
pub fn decrypt_payload(session: &Session, data: &[u8]) -> Result<Vec<u8>, ClientError> {
    let packet = SilverPacket::from_bytes(data)
        .map_err(|e| ClientError::Protocol(e.to_string()))?;

    packet.decrypt(session).map_err(|_| ClientError::Decryption)
}

/// Create a keepalive packet
pub fn create_keepalive_packet(session: &Session) -> Result<Vec<u8>, ClientError> {
    let packet = SilverPacket::new_keepalive(session)
        .map_err(|e| ClientError::Encryption(e.to_string()))?;

    Ok(packet.to_bytes())
}

/// Create a close packet
pub fn create_close_packet(session: &Session) -> Result<Vec<u8>, ClientError> {
    let packet = SilverPacket::new_close(session)
        .map_err(|e| ClientError::Encryption(e.to_string()))?;

    Ok(packet.to_bytes())
}

/// Data to send through the tunnel
#[derive(Debug, Clone)]
pub struct TunnelData {
    /// Raw data
    pub data: Vec<u8>,
    /// Priority flag
    pub priority: bool,
    /// Timestamp
    pub timestamp: Instant,
}

impl TunnelData {
    /// Create new tunnel data
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            priority: false,
            timestamp: Instant::now(),
        }
    }

    /// Create priority tunnel data
    pub fn priority(data: Vec<u8>) -> Self {
        Self {
            data,
            priority: true,
            timestamp: Instant::now(),
        }
    }

    /// Get age of this data
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::SessionId;

    fn create_test_session() -> Session {
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];
        Session::from_shared_secret(id, &shared_secret, true)
    }

    #[test]
    fn test_tunnel_stats() {
        let mut stats = TunnelStats::default();

        stats.record_sent(100);
        stats.record_received(200);

        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 200);
        assert_eq!(stats.total_bytes(), 300);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.total_packets(), 2);
    }

    #[test]
    fn test_tunnel_stats_errors() {
        let mut stats = TunnelStats::default();

        stats.record_encryption_error();
        stats.record_decryption_error();
        stats.record_decryption_error();

        assert_eq!(stats.encryption_errors, 1);
        assert_eq!(stats.decryption_errors, 2);
        assert_eq!(stats.total_errors(), 3);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let session = create_test_session();
        let payload = b"Hello, tunnel!";

        let encrypted = encrypt_payload(&session, payload).unwrap();
        assert!(encrypted.len() > payload.len());

        let decrypted = decrypt_payload(&session, &encrypted).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_keepalive_packet() {
        let session = create_test_session();
        let packet = create_keepalive_packet(&session).unwrap();
        assert!(!packet.is_empty());
    }

    #[test]
    fn test_close_packet() {
        let session = create_test_session();
        let packet = create_close_packet(&session).unwrap();
        assert!(!packet.is_empty());
    }

    #[test]
    fn test_tunnel_data() {
        let data = TunnelData::new(vec![1, 2, 3]);
        assert!(!data.priority);
        assert_eq!(data.data, vec![1, 2, 3]);

        let priority_data = TunnelData::priority(vec![4, 5, 6]);
        assert!(priority_data.priority);
    }
}
