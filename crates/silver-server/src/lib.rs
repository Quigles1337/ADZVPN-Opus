//! # Silver VPN Server
//!
//! High-performance VPN server using the Silver protocol.
//!
//! ## Features
//!
//! - UDP-based tunnel with QUIC fallback
//! - Silver handshake with perfect forward secrecy
//! - η-padded packets for traffic analysis resistance
//! - τ-scheduled timing for anti-fingerprinting
//! - Multi-client session management
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Silver VPN Server                     │
//! ├─────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
//! │  │ UDP Listener│  │Session Mgr  │  │ Traffic Shaper  │  │
//! │  │             │──│             │──│ (η² + λ² = 1)   │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────┘  │
//! │         │                │                   │          │
//! │         ▼                ▼                   ▼          │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
//! │  │ Handshake   │  │ Encryption  │  │  τ-Scheduler    │  │
//! │  │ (1-RTT)     │  │ ChaCha20    │  │  (Pell timing)  │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────┘  │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5

pub mod config;
pub mod listener;
pub mod session_manager;
pub mod tunnel;
pub mod errors;

pub use config::*;
pub use listener::*;
pub use session_manager::*;
pub use tunnel::*;
pub use errors::*;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::config::*;
    pub use crate::listener::*;
    pub use crate::session_manager::*;
    pub use crate::tunnel::*;
    pub use crate::errors::*;
}

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Main VPN server
pub struct SilverServer {
    /// Server configuration
    config: ServerConfig,
    /// Session manager
    sessions: Arc<RwLock<SessionManager>>,
    /// Running state
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl SilverServer {
    /// Create a new server with configuration
    pub fn new(config: ServerConfig) -> Self {
        let sessions = Arc::new(RwLock::new(SessionManager::new(config.max_clients)));

        Self {
            config,
            sessions,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Create server with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ServerConfig::default())
    }

    /// Get server configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Start the server
    pub async fn start(&self) -> Result<(), ServerError> {
        if self.is_running() {
            return Err(ServerError::AlreadyRunning);
        }

        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        info!(
            "Starting Silver VPN Server on {}:{}",
            self.config.bind_address, self.config.bind_port
        );

        // Create the UDP listener
        let listener = UdpListener::bind(&self.config).await?;

        info!("Server listening, ready for connections");

        // Run the main server loop
        self.run_loop(listener).await
    }

    /// Main server loop
    async fn run_loop(&self, mut listener: UdpListener) -> Result<(), ServerError> {
        let mut buf = vec![0u8; self.config.max_packet_size];

        while self.is_running() {
            match listener.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let packet_data = buf[..len].to_vec();

                    // Handle packet in background task
                    let sessions = Arc::clone(&self.sessions);
                    let config = self.config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_packet(&sessions, &config, &packet_data, addr).await {
                            warn!("Error handling packet from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Error receiving packet: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Stop the server
    pub fn stop(&self) {
        info!("Stopping Silver VPN Server");
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get the running flag for external shutdown handling
    pub fn running_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Get session count
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.active_count()
    }

    /// Get server statistics
    pub async fn stats(&self) -> ServerStats {
        let sessions = self.sessions.read().await;
        ServerStats {
            active_sessions: sessions.active_count(),
            total_sessions: sessions.total_created(),
            uptime_secs: 0, // Would need to track start time
        }
    }
}

/// Handle an incoming packet
async fn handle_packet(
    sessions: &Arc<RwLock<SessionManager>>,
    config: &ServerConfig,
    data: &[u8],
    addr: std::net::SocketAddr,
) -> Result<(), ServerError> {
    use silver_protocol::{PacketHeader, PacketType, HandshakePacket, ClientHello, ServerHandshake};

    if data.len() < 4 {
        return Err(ServerError::PacketTooSmall);
    }

    let header = PacketHeader::from_bytes(data)
        .map_err(|e| ServerError::Protocol(e.to_string()))?;

    match header.packet_type {
        PacketType::ClientHello => {
            // Parse handshake packet
            let handshake_packet = HandshakePacket::from_bytes(data)
                .map_err(|e| ServerError::Protocol(e.to_string()))?;

            let client_hello = ClientHello::from_bytes(&handshake_packet.payload)
                .map_err(|e| ServerError::Protocol(e.to_string()))?;

            // Process handshake
            let server = ServerHandshake::new();
            let (_server_hello, session) = server
                .process_client_hello(&client_hello, config.max_time_drift)
                .map_err(|e| ServerError::Handshake(e.to_string()))?;

            // Store session
            {
                let mut sessions = sessions.write().await;
                sessions.add_session(addr, session);
            }

            info!("New client connected from {}", addr);

            // TODO: Send server_hello response back to client
            // This would require storing the socket in the session manager

            Ok(())
        }
        PacketType::Data => {
            // Handle encrypted data packet
            let sessions = sessions.read().await;
            if let Some(_session) = sessions.get_session(&addr) {
                // Decrypt and process
                // TODO: Forward to tunnel
                Ok(())
            } else {
                Err(ServerError::SessionNotFound)
            }
        }
        PacketType::KeepAlive => {
            // Update session activity
            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.get_session_mut(&addr) {
                session.touch();
            }
            Ok(())
        }
        PacketType::Close => {
            // Remove session
            let mut sessions = sessions.write().await;
            sessions.remove_session(&addr);
            info!("Client disconnected: {}", addr);
            Ok(())
        }
        _ => {
            warn!("Unexpected packet type from {}: {:?}", addr, header.packet_type);
            Ok(())
        }
    }
}

/// Server statistics
#[derive(Debug, Clone)]
pub struct ServerStats {
    /// Number of active sessions
    pub active_sessions: usize,
    /// Total sessions created
    pub total_sessions: u64,
    /// Server uptime in seconds
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let server = SilverServer::with_defaults();
        assert!(!server.is_running());
    }

    #[test]
    fn test_server_config() {
        let config = ServerConfig::default();
        let server = SilverServer::new(config.clone());
        assert_eq!(server.config().bind_port, config.bind_port);
    }

    #[tokio::test]
    async fn test_session_count() {
        let server = SilverServer::with_defaults();
        assert_eq!(server.session_count().await, 0);
    }
}
