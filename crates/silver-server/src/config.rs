//! Server Configuration
//!
//! Configuration types and defaults for the VPN server.

use serde::{Deserialize, Serialize};
use silver_core::{DELTA_S, TAU};
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address
    pub bind_address: String,

    /// Bind port
    pub bind_port: u16,

    /// Maximum number of clients
    pub max_clients: usize,

    /// Maximum packet size
    pub max_packet_size: usize,

    /// Session timeout in seconds
    pub session_timeout_secs: u64,

    /// Handshake timeout in seconds
    pub handshake_timeout_secs: u64,

    /// Maximum time drift for handshake timestamps (seconds)
    pub max_time_drift: u64,

    /// Enable traffic shaping (η² + λ² = 1)
    pub enable_traffic_shaping: bool,

    /// Enable timing obfuscation (τ-scheduler)
    pub enable_timing_obfuscation: bool,

    /// Target bandwidth for traffic shaping (bytes/sec)
    pub target_bandwidth: u64,

    /// Base timing interval (microseconds)
    pub base_timing_interval_us: u64,

    /// Private key path (optional, generates if not present)
    pub private_key_path: Option<PathBuf>,

    /// Log level
    pub log_level: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            bind_port: 51820, // Same as WireGuard default
            max_clients: 256,
            max_packet_size: 1500,
            session_timeout_secs: 120,
            handshake_timeout_secs: 30,
            max_time_drift: 60,
            enable_traffic_shaping: true,
            enable_timing_obfuscation: true,
            target_bandwidth: 10_000_000, // 10 MB/s
            base_timing_interval_us: 10_000, // 10ms
            private_key_path: None,
            log_level: "info".to_string(),
        }
    }
}

impl ServerConfig {
    /// Create a new configuration builder
    pub fn builder() -> ServerConfigBuilder {
        ServerConfigBuilder::default()
    }

    /// Load configuration from a TOML file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(e.to_string()))?;

        toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Save configuration to a TOML file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;

        std::fs::write(path, content)
            .map_err(|e| ConfigError::IoError(e.to_string()))
    }

    /// Get the bind socket address
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        format!("{}:{}", self.bind_address, self.bind_port)
            .parse()
            .expect("Invalid bind address")
    }

    /// Get silver-scaled bandwidth tiers
    pub fn bandwidth_tiers(&self) -> (u64, u64, u64) {
        let base = self.target_bandwidth;
        let medium = (base as f64 * TAU) as u64;
        let high = (base as f64 * DELTA_S) as u64;
        (base, medium, high)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.bind_port == 0 {
            return Err(ConfigError::InvalidValue("bind_port cannot be 0".into()));
        }

        if self.max_clients == 0 {
            return Err(ConfigError::InvalidValue("max_clients cannot be 0".into()));
        }

        if self.max_packet_size < 64 {
            return Err(ConfigError::InvalidValue(
                "max_packet_size must be at least 64".into(),
            ));
        }

        if self.session_timeout_secs == 0 {
            return Err(ConfigError::InvalidValue(
                "session_timeout_secs cannot be 0".into(),
            ));
        }

        Ok(())
    }
}

/// Configuration builder
#[derive(Default)]
pub struct ServerConfigBuilder {
    config: ServerConfig,
}

impl ServerConfigBuilder {
    /// Set bind address
    pub fn bind_address(mut self, addr: impl Into<String>) -> Self {
        self.config.bind_address = addr.into();
        self
    }

    /// Set bind port
    pub fn bind_port(mut self, port: u16) -> Self {
        self.config.bind_port = port;
        self
    }

    /// Set maximum clients
    pub fn max_clients(mut self, max: usize) -> Self {
        self.config.max_clients = max;
        self
    }

    /// Set maximum packet size
    pub fn max_packet_size(mut self, size: usize) -> Self {
        self.config.max_packet_size = size;
        self
    }

    /// Set session timeout
    pub fn session_timeout(mut self, secs: u64) -> Self {
        self.config.session_timeout_secs = secs;
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

    /// Set log level
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.config.log_level = level.into();
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<ServerConfig, ConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Serialize error: {0}")]
    SerializeError(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.bind_port, 51820);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_builder() {
        let config = ServerConfig::builder()
            .bind_address("127.0.0.1")
            .bind_port(8080)
            .max_clients(100)
            .build()
            .unwrap();

        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.bind_port, 8080);
        assert_eq!(config.max_clients, 100);
    }

    #[test]
    fn test_config_validation() {
        let result = ServerConfig::builder()
            .bind_port(0)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_bandwidth_tiers() {
        let config = ServerConfig::default();
        let (low, medium, high) = config.bandwidth_tiers();

        assert_eq!(low, config.target_bandwidth);
        assert!(medium > low);
        assert!(high > medium);
    }

    #[test]
    fn test_socket_addr() {
        let config = ServerConfig::default();
        let addr = config.socket_addr();
        assert_eq!(addr.port(), 51820);
    }
}
