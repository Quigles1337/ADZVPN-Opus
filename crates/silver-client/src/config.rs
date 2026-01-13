//! Client Configuration
//!
//! Configuration types and defaults for the VPN client.

use crate::errors::ClientError;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server address (host:port)
    pub server_address: String,

    /// Maximum packet size
    pub max_packet_size: usize,

    /// Handshake timeout in seconds
    pub handshake_timeout_secs: u64,

    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,

    /// Keepalive interval in seconds
    pub keepalive_interval_secs: u64,

    /// Enable automatic reconnection
    pub auto_reconnect: bool,

    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,

    /// Enable traffic shaping
    pub enable_traffic_shaping: bool,

    /// Enable timing obfuscation
    pub enable_timing_obfuscation: bool,

    /// Target bandwidth for traffic shaping (bytes/sec)
    pub target_bandwidth: u64,

    /// Base timing interval (microseconds)
    pub base_timing_us: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_address: "127.0.0.1:51820".to_string(),
            max_packet_size: 1500,
            handshake_timeout_secs: 10,
            connection_timeout_secs: 30,
            keepalive_interval_secs: 30,
            auto_reconnect: true,
            max_reconnect_attempts: 5,
            enable_traffic_shaping: true,
            enable_timing_obfuscation: true,
            target_bandwidth: 10_000_000, // 10 MB/s
            base_timing_us: 10_000,       // 10ms
        }
    }
}

impl ClientConfig {
    /// Create a new configuration builder
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }

    /// Resolve the server address to a SocketAddr
    pub fn resolve_server_address(&self) -> Result<SocketAddr, ClientError> {
        self.server_address
            .to_socket_addrs()
            .map_err(|e| ClientError::DnsResolutionFailed {
                host: self.server_address.clone(),
                reason: e.to_string(),
            })?
            .next()
            .ok_or_else(|| ClientError::InvalidAddress(self.server_address.clone()))
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.server_address.is_empty() {
            return Err(ClientError::Config("Server address is required".into()));
        }

        if self.max_packet_size < 64 {
            return Err(ClientError::Config(
                "Max packet size must be at least 64".into(),
            ));
        }

        if self.handshake_timeout_secs == 0 {
            return Err(ClientError::Config(
                "Handshake timeout cannot be 0".into(),
            ));
        }

        Ok(())
    }
}

/// Configuration builder
#[derive(Default)]
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    /// Set server address
    pub fn server_address(mut self, addr: impl Into<String>) -> Self {
        self.config.server_address = addr.into();
        self
    }

    /// Set maximum packet size
    pub fn max_packet_size(mut self, size: usize) -> Self {
        self.config.max_packet_size = size;
        self
    }

    /// Set handshake timeout
    pub fn handshake_timeout(mut self, secs: u64) -> Self {
        self.config.handshake_timeout_secs = secs;
        self
    }

    /// Set connection timeout
    pub fn connection_timeout(mut self, secs: u64) -> Self {
        self.config.connection_timeout_secs = secs;
        self
    }

    /// Set keepalive interval
    pub fn keepalive_interval(mut self, secs: u64) -> Self {
        self.config.keepalive_interval_secs = secs;
        self
    }

    /// Enable/disable auto reconnect
    pub fn auto_reconnect(mut self, enabled: bool) -> Self {
        self.config.auto_reconnect = enabled;
        self
    }

    /// Set max reconnect attempts
    pub fn max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.config.max_reconnect_attempts = attempts;
        self
    }

    /// Enable/disable traffic shaping
    pub fn traffic_shaping(mut self, enabled: bool) -> Self {
        self.config.enable_traffic_shaping = enabled;
        self
    }

    /// Enable/disable timing obfuscation
    pub fn timing_obfuscation(mut self, enabled: bool) -> Self {
        self.config.enable_timing_obfuscation = enabled;
        self
    }

    /// Set target bandwidth
    pub fn target_bandwidth(mut self, bps: u64) -> Self {
        self.config.target_bandwidth = bps;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<ClientConfig, ClientError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.server_address, "127.0.0.1:51820");
        assert!(config.auto_reconnect);
    }

    #[test]
    fn test_config_builder() {
        let config = ClientConfig::builder()
            .server_address("10.0.0.1:8080")
            .max_packet_size(1400)
            .auto_reconnect(false)
            .build()
            .unwrap();

        assert_eq!(config.server_address, "10.0.0.1:8080");
        assert_eq!(config.max_packet_size, 1400);
        assert!(!config.auto_reconnect);
    }

    #[test]
    fn test_config_validation() {
        let result = ClientConfig::builder()
            .server_address("")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_address() {
        let config = ClientConfig::builder()
            .server_address("127.0.0.1:51820")
            .build()
            .unwrap();

        let addr = config.resolve_server_address().unwrap();
        assert_eq!(addr.port(), 51820);
    }
}
