//! # Silver VPN Client
//!
//! Client library for connecting to ADZVPN-Opus servers.
//!
//! ## Features
//!
//! - Async connection to VPN servers
//! - Silver handshake with perfect forward secrecy
//! - Automatic reconnection with exponential backoff
//! - Traffic shaping and timing obfuscation
//! - Event-driven architecture
//!
//! ## Quick Start
//!
//! ```ignore
//! use silver_client::{SilverClient, ClientConfig, ClientError};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ClientError> {
//!     let config = ClientConfig::builder()
//!         .server_address("vpn.example.com:51820")
//!         .build()?;
//!
//!     let client = SilverClient::new(config);
//!     client.connect().await?;
//!
//!     // Send data through the tunnel
//!     client.send(b"Hello, VPN!").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5

pub mod config;
pub mod connection;
pub mod tunnel;
pub mod errors;
pub mod events;

pub use config::*;
pub use connection::*;
pub use tunnel::*;
pub use errors::*;
pub use events::*;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::config::*;
    pub use crate::connection::*;
    pub use crate::tunnel::*;
    pub use crate::errors::*;
    pub use crate::events::*;
}

use silver_protocol::{Session, SessionId};
use silver_timing::{SilverScheduler, TrafficShaper};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::net::UdpSocket;
use tracing::{info, debug};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connecting (handshake in progress)
    Connecting,
    /// Connected and ready
    Connected,
    /// Reconnecting after disconnect
    Reconnecting,
    /// Disconnecting
    Disconnecting,
}

/// Main VPN client
pub struct SilverClient {
    /// Client configuration
    config: ClientConfig,
    /// Current connection state
    state: Arc<RwLock<ConnectionState>>,
    /// Active session (if connected)
    session: Arc<RwLock<Option<Session>>>,
    /// UDP socket
    socket: Arc<Mutex<Option<UdpSocket>>>,
    /// Server address
    server_addr: Arc<RwLock<Option<SocketAddr>>>,
    /// Traffic shaper
    shaper: Arc<Mutex<TrafficShaper>>,
    /// Timing scheduler
    scheduler: Arc<Mutex<SilverScheduler>>,
    /// Event sender
    event_tx: mpsc::Sender<ClientEvent>,
    /// Event receiver (for the user to consume)
    event_rx: Arc<Mutex<mpsc::Receiver<ClientEvent>>>,
}

impl SilverClient {
    /// Create a new client with configuration
    pub fn new(config: ClientConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);

        Self {
            shaper: Arc::new(Mutex::new(TrafficShaper::new(config.target_bandwidth))),
            scheduler: Arc::new(Mutex::new(SilverScheduler::new(config.base_timing_us))),
            config,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            session: Arc::new(RwLock::new(None)),
            socket: Arc::new(Mutex::new(None)),
            server_addr: Arc::new(RwLock::new(None)),
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        }
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == ConnectionState::Connected
    }

    /// Get the configuration
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Connect to the server
    pub async fn connect(&self) -> Result<(), ClientError> {
        // Check if already connected
        if self.is_connected().await {
            return Err(ClientError::AlreadyConnected);
        }

        // Update state
        *self.state.write().await = ConnectionState::Connecting;
        self.emit_event(ClientEvent::Connecting).await;

        // Resolve server address
        let server_addr = self.config.resolve_server_address()?;
        *self.server_addr.write().await = Some(server_addr);

        debug!("Connecting to server at {}", server_addr);

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server_addr).await?;

        // Perform handshake
        let session = self.perform_handshake(&socket).await?;

        // Store socket and session
        *self.socket.lock().await = Some(socket);
        *self.session.write().await = Some(session);
        *self.state.write().await = ConnectionState::Connected;

        self.emit_event(ClientEvent::Connected).await;
        info!("Connected to VPN server at {}", server_addr);

        Ok(())
    }

    /// Perform the Silver handshake
    async fn perform_handshake(&self, socket: &UdpSocket) -> Result<Session, ClientError> {
        use silver_protocol::{ClientHandshake, ServerHello, HandshakePacket, PacketType};

        // Create client handshake
        let mut handshake = ClientHandshake::new();
        let client_hello = handshake.generate_hello();

        // Send ClientHello
        let hello_bytes = client_hello.to_bytes();
        socket.send(&hello_bytes).await?;

        debug!("Sent ClientHello, waiting for ServerHello");

        // Wait for ServerHello with timeout
        let mut buf = vec![0u8; self.config.max_packet_size];
        let recv_future = socket.recv(&mut buf);

        let len = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.handshake_timeout_secs),
            recv_future,
        )
        .await
        .map_err(|_| ClientError::HandshakeTimeout)?
        .map_err(|e| ClientError::Io(e))?;

        // Parse ServerHello
        let response = HandshakePacket::from_bytes(&buf[..len])
            .map_err(|e| ClientError::Handshake(e.to_string()))?;

        if response.header.packet_type != PacketType::ServerHello {
            return Err(ClientError::Handshake(format!(
                "Expected ServerHello, got {:?}",
                response.header.packet_type
            )));
        }

        let server_hello = ServerHello::from_bytes(&response.payload)
            .map_err(|e| ClientError::Handshake(e.to_string()))?;

        // Complete handshake
        let (session, _config) = handshake
            .process_server_hello(&server_hello)
            .map_err(|e| ClientError::Handshake(e.to_string()))?;

        debug!("Handshake complete, session established");

        Ok(session)
    }

    /// Send data through the tunnel
    pub async fn send(&self, data: &[u8]) -> Result<(), ClientError> {
        let session = self.session.read().await;
        let session = session.as_ref().ok_or(ClientError::NotConnected)?;

        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref().ok_or(ClientError::NotConnected)?;

        // Create encrypted packet with silver padding
        let packet = silver_protocol::SilverPacket::new_data(data, session)
            .map_err(|e| ClientError::Encryption(e.to_string()))?;

        // Apply timing
        {
            let mut scheduler = self.scheduler.lock().await;
            scheduler.wait_next().await;
        }

        // Send packet
        let bytes = packet.to_bytes();
        socket.send(&bytes).await?;

        // Record for traffic shaping
        {
            let mut shaper = self.shaper.lock().await;
            shaper.record_packet(data.len(), bytes.len() - data.len());
        }

        Ok(())
    }

    /// Receive data from the tunnel
    pub async fn recv(&self) -> Result<Vec<u8>, ClientError> {
        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref().ok_or(ClientError::NotConnected)?;

        let mut buf = vec![0u8; self.config.max_packet_size];
        let len = socket.recv(&mut buf).await?;

        let session = self.session.read().await;
        let session = session.as_ref().ok_or(ClientError::NotConnected)?;

        // Parse and decrypt packet
        let packet = silver_protocol::SilverPacket::from_bytes(&buf[..len])
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        let data = packet
            .decrypt(session)
            .map_err(|_| ClientError::Decryption)?;

        // Record for traffic shaping
        {
            let mut shaper = self.shaper.lock().await;
            shaper.record_real(len);
        }

        Ok(data)
    }

    /// Send a keepalive packet
    pub async fn send_keepalive(&self) -> Result<(), ClientError> {
        let session = self.session.read().await;
        let session = session.as_ref().ok_or(ClientError::NotConnected)?;

        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref().ok_or(ClientError::NotConnected)?;

        let packet = silver_protocol::SilverPacket::new_keepalive(session)
            .map_err(|e| ClientError::Encryption(e.to_string()))?;

        socket.send(&packet.to_bytes()).await?;
        Ok(())
    }

    /// Disconnect from the server
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        if !self.is_connected().await {
            return Ok(());
        }

        *self.state.write().await = ConnectionState::Disconnecting;
        self.emit_event(ClientEvent::Disconnecting).await;

        // Send close packet
        if let (Some(session), Some(socket)) = (
            self.session.read().await.as_ref(),
            self.socket.lock().await.as_ref(),
        ) {
            if let Ok(packet) = silver_protocol::SilverPacket::new_close(session) {
                let _ = socket.send(&packet.to_bytes()).await;
            }
        }

        // Clear state
        *self.session.write().await = None;
        *self.socket.lock().await = None;
        *self.server_addr.write().await = None;
        *self.state.write().await = ConnectionState::Disconnected;

        self.emit_event(ClientEvent::Disconnected).await;
        info!("Disconnected from VPN server");

        Ok(())
    }

    /// Get session ID if connected
    pub async fn session_id(&self) -> Option<SessionId> {
        self.session.read().await.as_ref().map(|s| s.id())
    }

    /// Get client statistics
    pub async fn stats(&self) -> ClientStats {
        let shaper = self.shaper.lock().await;
        let state = *self.state.read().await;

        ClientStats {
            state,
            shaper_stats: shaper.stats(),
        }
    }

    /// Emit an event
    async fn emit_event(&self, event: ClientEvent) {
        let _ = self.event_tx.send(event).await;
    }

    /// Get the event receiver for handling events
    pub fn events(&self) -> Arc<Mutex<mpsc::Receiver<ClientEvent>>> {
        Arc::clone(&self.event_rx)
    }
}

/// Client statistics
#[derive(Debug, Clone)]
pub struct ClientStats {
    /// Current state
    pub state: ConnectionState,
    /// Traffic shaping stats
    pub shaper_stats: silver_timing::ShapingStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = ClientConfig::default();
        let client = SilverClient::new(config);
        assert!(matches!(client.state().await, ConnectionState::Disconnected));
    }

    #[tokio::test]
    async fn test_client_not_connected() {
        let config = ClientConfig::default();
        let client = SilverClient::new(config);

        assert!(!client.is_connected().await);
        assert!(client.session_id().await.is_none());
    }

    #[tokio::test]
    async fn test_send_without_connection() {
        let config = ClientConfig::default();
        let client = SilverClient::new(config);

        let result = client.send(b"test").await;
        assert!(matches!(result, Err(ClientError::NotConnected)));
    }

    #[tokio::test]
    async fn test_disconnect_when_not_connected() {
        let config = ClientConfig::default();
        let client = SilverClient::new(config);

        // Should succeed (no-op)
        let result = client.disconnect().await;
        assert!(result.is_ok());
    }
}
