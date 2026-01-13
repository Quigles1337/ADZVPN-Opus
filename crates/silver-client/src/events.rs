//! Client Events
//!
//! Event types for the VPN client.

use std::net::SocketAddr;

/// Client events
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// Connecting to server
    Connecting,

    /// Successfully connected
    Connected,

    /// Disconnecting from server
    Disconnecting,

    /// Disconnected from server
    Disconnected,

    /// Reconnecting to server
    Reconnecting {
        /// Attempt number
        attempt: u32,
        /// Maximum attempts
        max_attempts: u32,
    },

    /// Reconnection failed
    ReconnectionFailed {
        /// Total attempts made
        attempts: u32,
    },

    /// Session established
    SessionEstablished {
        /// Session ID (hex string)
        session_id: String,
    },

    /// Session expired
    SessionExpired,

    /// Data received
    DataReceived {
        /// Number of bytes
        bytes: usize,
    },

    /// Data sent
    DataSent {
        /// Number of bytes
        bytes: usize,
    },

    /// Error occurred
    Error {
        /// Error message
        message: String,
    },

    /// Keepalive sent
    KeepaliveSent,

    /// Keepalive received
    KeepaliveReceived,

    /// Server address resolved
    AddressResolved {
        /// Resolved address
        address: SocketAddr,
    },

    /// Bandwidth statistics update
    BandwidthUpdate {
        /// Current upload rate (bytes/sec)
        upload_bps: u64,
        /// Current download rate (bytes/sec)
        download_bps: u64,
    },
}

impl ClientEvent {
    /// Check if this is an error event
    pub fn is_error(&self) -> bool {
        matches!(self, ClientEvent::Error { .. } | ClientEvent::ReconnectionFailed { .. })
    }

    /// Check if this is a connection state change
    pub fn is_connection_change(&self) -> bool {
        matches!(
            self,
            ClientEvent::Connecting
                | ClientEvent::Connected
                | ClientEvent::Disconnecting
                | ClientEvent::Disconnected
                | ClientEvent::Reconnecting { .. }
        )
    }

    /// Get event name for logging
    pub fn name(&self) -> &'static str {
        match self {
            ClientEvent::Connecting => "Connecting",
            ClientEvent::Connected => "Connected",
            ClientEvent::Disconnecting => "Disconnecting",
            ClientEvent::Disconnected => "Disconnected",
            ClientEvent::Reconnecting { .. } => "Reconnecting",
            ClientEvent::ReconnectionFailed { .. } => "ReconnectionFailed",
            ClientEvent::SessionEstablished { .. } => "SessionEstablished",
            ClientEvent::SessionExpired => "SessionExpired",
            ClientEvent::DataReceived { .. } => "DataReceived",
            ClientEvent::DataSent { .. } => "DataSent",
            ClientEvent::Error { .. } => "Error",
            ClientEvent::KeepaliveSent => "KeepaliveSent",
            ClientEvent::KeepaliveReceived => "KeepaliveReceived",
            ClientEvent::AddressResolved { .. } => "AddressResolved",
            ClientEvent::BandwidthUpdate { .. } => "BandwidthUpdate",
        }
    }
}

impl std::fmt::Display for ClientEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientEvent::Connecting => write!(f, "Connecting to server"),
            ClientEvent::Connected => write!(f, "Connected to server"),
            ClientEvent::Disconnecting => write!(f, "Disconnecting from server"),
            ClientEvent::Disconnected => write!(f, "Disconnected from server"),
            ClientEvent::Reconnecting { attempt, max_attempts } => {
                write!(f, "Reconnecting (attempt {}/{})", attempt, max_attempts)
            }
            ClientEvent::ReconnectionFailed { attempts } => {
                write!(f, "Reconnection failed after {} attempts", attempts)
            }
            ClientEvent::SessionEstablished { session_id } => {
                write!(f, "Session established: {}", session_id)
            }
            ClientEvent::SessionExpired => write!(f, "Session expired"),
            ClientEvent::DataReceived { bytes } => write!(f, "Received {} bytes", bytes),
            ClientEvent::DataSent { bytes } => write!(f, "Sent {} bytes", bytes),
            ClientEvent::Error { message } => write!(f, "Error: {}", message),
            ClientEvent::KeepaliveSent => write!(f, "Keepalive sent"),
            ClientEvent::KeepaliveReceived => write!(f, "Keepalive received"),
            ClientEvent::AddressResolved { address } => {
                write!(f, "Address resolved: {}", address)
            }
            ClientEvent::BandwidthUpdate { upload_bps, download_bps } => {
                write!(
                    f,
                    "Bandwidth: {} KB/s up, {} KB/s down",
                    upload_bps / 1024,
                    download_bps / 1024
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_is_error() {
        assert!(ClientEvent::Error {
            message: "test".into()
        }
        .is_error());
        assert!(ClientEvent::ReconnectionFailed { attempts: 3 }.is_error());
        assert!(!ClientEvent::Connected.is_error());
    }

    #[test]
    fn test_event_is_connection_change() {
        assert!(ClientEvent::Connecting.is_connection_change());
        assert!(ClientEvent::Connected.is_connection_change());
        assert!(ClientEvent::Disconnected.is_connection_change());
        assert!(!ClientEvent::DataSent { bytes: 100 }.is_connection_change());
    }

    #[test]
    fn test_event_name() {
        assert_eq!(ClientEvent::Connecting.name(), "Connecting");
        assert_eq!(ClientEvent::Connected.name(), "Connected");
        assert_eq!(
            ClientEvent::DataReceived { bytes: 100 }.name(),
            "DataReceived"
        );
    }

    #[test]
    fn test_event_display() {
        let event = ClientEvent::Reconnecting {
            attempt: 2,
            max_attempts: 5,
        };
        assert_eq!(format!("{}", event), "Reconnecting (attempt 2/5)");
    }
}
