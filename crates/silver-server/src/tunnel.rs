//! Tunnel Management
//!
//! Handles encrypted tunnel forwarding between clients and the network.

use silver_protocol::{Session, SilverPacket};
use silver_timing::{SilverScheduler, TrafficShaper};
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Packet to be sent through the tunnel
#[derive(Debug)]
pub struct TunnelPacket {
    /// Destination address
    pub dest: SocketAddr,
    /// Encrypted packet data
    pub data: Vec<u8>,
    /// Priority flag
    pub priority: bool,
}

/// Tunnel for a single client session
pub struct ClientTunnel {
    /// Remote client address
    remote_addr: SocketAddr,
    /// Send channel
    send_tx: mpsc::Sender<TunnelPacket>,
    /// Traffic shaper
    shaper: TrafficShaper,
    /// Timing scheduler (reserved for packet timing)
    #[allow(dead_code)]
    scheduler: SilverScheduler,
    /// Packets queued
    packets_queued: u64,
    /// Packets sent
    packets_sent: u64,
}

impl ClientTunnel {
    /// Create a new client tunnel
    pub fn new(
        remote_addr: SocketAddr,
        send_tx: mpsc::Sender<TunnelPacket>,
        target_bandwidth: u64,
    ) -> Self {
        Self {
            remote_addr,
            send_tx,
            shaper: TrafficShaper::new(target_bandwidth),
            scheduler: SilverScheduler::new(10_000),
            packets_queued: 0,
            packets_sent: 0,
        }
    }

    /// Queue a packet for sending
    pub async fn queue_packet(&mut self, data: Vec<u8>, priority: bool) -> Result<(), TunnelError> {
        let packet = TunnelPacket {
            dest: self.remote_addr,
            data,
            priority,
        };

        self.send_tx
            .send(packet)
            .await
            .map_err(|_| TunnelError::ChannelClosed)?;

        self.packets_queued += 1;
        Ok(())
    }

    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get packets queued
    pub fn packets_queued(&self) -> u64 {
        self.packets_queued
    }

    /// Get packets sent
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    /// Record a sent packet
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.shaper.record_real(bytes);
    }
}

/// Tunnel errors
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("Channel closed")]
    ChannelClosed,

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed")]
    Decryption,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Invalid packet")]
    InvalidPacket,
}

/// Tunnel statistics
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Dropped packets (queue full)
    pub packets_dropped: u64,
}

impl TunnelStats {
    /// Record sent data
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += 1;
    }

    /// Record received data
    pub fn record_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += 1;
    }

    /// Record dropped packet
    pub fn record_dropped(&mut self) {
        self.packets_dropped += 1;
    }

    /// Get total throughput
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }
}

/// Encrypt payload for tunnel transmission
pub fn encrypt_for_tunnel(
    session: &Session,
    payload: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    let packet = SilverPacket::new_data(payload, session)
        .map_err(|e| TunnelError::Encryption(e.to_string()))?;

    Ok(packet.to_bytes())
}

/// Decrypt payload from tunnel
pub fn decrypt_from_tunnel(
    session: &Session,
    data: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    let packet = SilverPacket::from_bytes(data)
        .map_err(|_| TunnelError::InvalidPacket)?;

    packet
        .decrypt(session)
        .map_err(|_| TunnelError::Decryption)
}

/// Create a keepalive packet
pub fn create_keepalive(session: &Session) -> Result<Vec<u8>, TunnelError> {
    let packet = SilverPacket::new_keepalive(session)
        .map_err(|e| TunnelError::Encryption(e.to_string()))?;

    Ok(packet.to_bytes())
}

/// Create a close packet
pub fn create_close(session: &Session) -> Result<Vec<u8>, TunnelError> {
    let packet = SilverPacket::new_close(session)
        .map_err(|e| TunnelError::Encryption(e.to_string()))?;

    Ok(packet.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::SessionId;

    fn create_test_session() -> Session {
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];
        Session::from_shared_secret(id, &shared_secret, false)
    }

    #[test]
    fn test_tunnel_stats() {
        let mut stats = TunnelStats::default();

        stats.record_sent(100);
        stats.record_received(200);
        stats.record_dropped();

        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 200);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.packets_dropped, 1);
        assert_eq!(stats.total_bytes(), 300);
    }

    #[test]
    fn test_encrypt_decrypt_tunnel() {
        let session = create_test_session();
        let payload = b"Hello through the tunnel!";

        let encrypted = encrypt_for_tunnel(&session, payload).unwrap();
        assert!(encrypted.len() > payload.len());

        let decrypted = decrypt_from_tunnel(&session, &encrypted).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_keepalive_packet() {
        let session = create_test_session();
        let keepalive = create_keepalive(&session).unwrap();
        assert!(!keepalive.is_empty());
    }

    #[test]
    fn test_close_packet() {
        let session = create_test_session();
        let close = create_close(&session).unwrap();
        assert!(!close.is_empty());
    }

    #[tokio::test]
    async fn test_client_tunnel() {
        let (tx, mut rx) = mpsc::channel(10);
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let mut tunnel = ClientTunnel::new(addr, tx, 1_000_000);

        tunnel.queue_packet(vec![1, 2, 3], false).await.unwrap();
        assert_eq!(tunnel.packets_queued(), 1);

        let packet = rx.recv().await.unwrap();
        assert_eq!(packet.dest, addr);
        assert_eq!(packet.data, vec![1, 2, 3]);
        assert!(!packet.priority);
    }
}
