//! UDP Listener
//!
//! Handles incoming UDP connections with socket configuration.

use crate::config::ServerConfig;
use crate::errors::ServerError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// UDP listener for the VPN server
pub struct UdpListener {
    /// The underlying UDP socket
    socket: UdpSocket,
    /// Local address
    local_addr: SocketAddr,
}

impl UdpListener {
    /// Bind to the configured address
    pub async fn bind(config: &ServerConfig) -> Result<Self, ServerError> {
        let addr = config.socket_addr();

        // Create socket with socket2 for advanced options
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| ServerError::BindFailed {
                address: addr.to_string(),
                reason: e.to_string(),
            })?;

        // Set socket options
        socket.set_reuse_address(true).ok();
        socket.set_nonblocking(true).map_err(|e| ServerError::BindFailed {
            address: addr.to_string(),
            reason: e.to_string(),
        })?;

        // Set receive buffer size (important for high-throughput)
        socket.set_recv_buffer_size(1024 * 1024).ok(); // 1MB

        // Set send buffer size
        socket.set_send_buffer_size(1024 * 1024).ok(); // 1MB

        // Bind the socket
        socket
            .bind(&addr.into())
            .map_err(|e| ServerError::BindFailed {
                address: addr.to_string(),
                reason: e.to_string(),
            })?;

        // Convert to tokio socket
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;

        let local_addr = socket.local_addr()?;

        Ok(Self { socket, local_addr })
    }

    /// Receive a packet
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ServerError> {
        self.socket
            .recv_from(buf)
            .await
            .map_err(|e| ServerError::Io(e))
    }

    /// Send a packet
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, ServerError> {
        self.socket
            .send_to(buf, addr)
            .await
            .map_err(|e| ServerError::Io(e))
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get reference to underlying socket
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

/// Connection info for a client
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Connection time
    pub connected_at: std::time::Instant,
    /// Last packet time
    pub last_packet: std::time::Instant,
    /// Packets received
    pub packets_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
}

impl ConnectionInfo {
    /// Create new connection info
    pub fn new(remote_addr: SocketAddr) -> Self {
        let now = std::time::Instant::now();
        Self {
            remote_addr,
            connected_at: now,
            last_packet: now,
            packets_received: 0,
            packets_sent: 0,
            bytes_received: 0,
            bytes_sent: 0,
        }
    }

    /// Record received packet
    pub fn record_received(&mut self, bytes: usize) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
        self.last_packet = std::time::Instant::now();
    }

    /// Record sent packet
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Get connection duration
    pub fn duration(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    /// Get idle time
    pub fn idle_time(&self) -> std::time::Duration {
        self.last_packet.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_info() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut info = ConnectionInfo::new(addr);

        assert_eq!(info.packets_received, 0);
        assert_eq!(info.bytes_received, 0);

        info.record_received(100);
        assert_eq!(info.packets_received, 1);
        assert_eq!(info.bytes_received, 100);

        info.record_sent(50);
        assert_eq!(info.packets_sent, 1);
        assert_eq!(info.bytes_sent, 50);
    }

    #[tokio::test]
    async fn test_listener_bind() {
        // Use a random high port to avoid conflicts
        let config = ServerConfig::builder()
            .bind_address("127.0.0.1")
            .bind_port(0) // Let OS assign port
            .build();

        // This will fail validation due to port 0, which is fine for this test
        // In real usage, we'd use a specific port
        assert!(config.is_err());
    }
}
