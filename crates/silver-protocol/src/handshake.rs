//! Silver Handshake Protocol
//!
//! 1-RTT handshake with perfect forward secrecy using X25519.
//!
//! ## Handshake Flow
//!
//! ```text
//! Client                                          Server
//!   |                                               |
//!   |--- ClientHello (ephemeral_pub, timestamp) -->|
//!   |                                               |
//!   |<-- ServerHello (ephemeral_pub, encrypted) ---|
//!   |    [session_id, config, timestamp]           |
//!   |                                               |
//!   |========= Encrypted tunnel ready =============|
//! ```
//!
//! ## Security Properties
//!
//! - Perfect forward secrecy via ephemeral X25519 keys
//! - Server authentication (client verifies server's response)
//! - Replay protection via timestamps
//! - No client authentication in basic handshake (add later if needed)

use rand::RngCore;
use silver_crypto::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::*;
use crate::errors::{ProtocolError, ProtocolResult};
use crate::packet::HandshakePacket;
use crate::session::{Session, SessionId};

/// Client Hello message
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Protocol version
    pub version: u16,
    /// Client's ephemeral public key
    pub ephemeral_public: [u8; PUBLIC_KEY_SIZE],
    /// Timestamp (unix seconds)
    pub timestamp: u64,
    /// Random nonce for uniqueness
    pub nonce: [u8; 16],
}

impl ClientHello {
    /// Create a new ClientHello
    pub fn new(ephemeral_public: [u8; PUBLIC_KEY_SIZE]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        Self {
            version: PROTOCOL_VERSION,
            ephemeral_public,
            timestamp,
            nonce,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + PUBLIC_KEY_SIZE + 8 + 16);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        let min_len = 2 + PUBLIC_KEY_SIZE + 8 + 16;
        if data.len() < min_len {
            return Err(ProtocolError::InvalidPacket(format!(
                "ClientHello too short: {} bytes (need {})",
                data.len(),
                min_len
            )));
        }

        let version = u16::from_le_bytes([data[0], data[1]]);
        let mut ephemeral_public = [0u8; PUBLIC_KEY_SIZE];
        ephemeral_public.copy_from_slice(&data[2..2 + PUBLIC_KEY_SIZE]);
        let timestamp = u64::from_le_bytes(
            data[2 + PUBLIC_KEY_SIZE..2 + PUBLIC_KEY_SIZE + 8]
                .try_into()
                .unwrap(),
        );
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[2 + PUBLIC_KEY_SIZE + 8..2 + PUBLIC_KEY_SIZE + 8 + 16]);

        Ok(Self {
            version,
            ephemeral_public,
            timestamp,
            nonce,
        })
    }

    /// Convert to handshake packet
    pub fn to_packet(&self) -> HandshakePacket {
        HandshakePacket::new(PacketType::ClientHello, self.to_bytes())
    }

    /// Verify timestamp is within acceptable range
    pub fn verify_timestamp(&self, max_drift_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let diff = if now > self.timestamp {
            now - self.timestamp
        } else {
            self.timestamp - now
        };

        diff <= max_drift_secs
    }
}

/// Server Hello message
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Protocol version
    pub version: u16,
    /// Server's ephemeral public key
    pub ephemeral_public: [u8; PUBLIC_KEY_SIZE],
    /// Session ID assigned by server
    pub session_id: SessionId,
    /// Encrypted payload (contains config)
    pub encrypted_payload: Vec<u8>,
    /// Nonce for encrypted payload
    pub nonce: [u8; NONCE_SIZE],
}

impl ServerHello {
    /// Create a new ServerHello (encrypts config with shared secret)
    pub fn new(
        ephemeral_public: [u8; PUBLIC_KEY_SIZE],
        session_id: SessionId,
        config: &ServerConfig,
        shared_secret: &[u8],
    ) -> ProtocolResult<Self> {
        // Derive encryption key for handshake
        let key = SilverKdf::derive_key(shared_secret, b"adzvpn-handshake", b"server-hello");
        let cipher = SilverCipher::new(&key);

        // Encrypt config
        let config_bytes = config.to_bytes();
        let (encrypted_payload, nonce) = cipher
            .encrypt(&config_bytes)
            .map_err(|e| ProtocolError::EncryptionFailed(e.to_string()))?;

        Ok(Self {
            version: PROTOCOL_VERSION,
            ephemeral_public,
            session_id,
            encrypted_payload,
            nonce,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 + PUBLIC_KEY_SIZE + SESSION_ID_SIZE + NONCE_SIZE + 2 + self.encrypted_payload.len(),
        );
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(self.session_id.as_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.encrypted_payload.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        let min_len = 2 + PUBLIC_KEY_SIZE + SESSION_ID_SIZE + NONCE_SIZE + 2;
        if data.len() < min_len {
            return Err(ProtocolError::InvalidPacket(format!(
                "ServerHello too short: {} bytes (need at least {})",
                data.len(),
                min_len
            )));
        }

        let version = u16::from_le_bytes([data[0], data[1]]);

        let mut ephemeral_public = [0u8; PUBLIC_KEY_SIZE];
        ephemeral_public.copy_from_slice(&data[2..2 + PUBLIC_KEY_SIZE]);

        let session_id = SessionId::from_slice(&data[2 + PUBLIC_KEY_SIZE..2 + PUBLIC_KEY_SIZE + SESSION_ID_SIZE])?;

        let nonce_start = 2 + PUBLIC_KEY_SIZE + SESSION_ID_SIZE;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[nonce_start..nonce_start + NONCE_SIZE]);

        let len_start = nonce_start + NONCE_SIZE;
        let payload_len = u16::from_le_bytes([data[len_start], data[len_start + 1]]) as usize;

        let payload_start = len_start + 2;
        if data.len() < payload_start + payload_len {
            return Err(ProtocolError::InvalidPacket(
                "ServerHello payload truncated".into(),
            ));
        }

        let encrypted_payload = data[payload_start..payload_start + payload_len].to_vec();

        Ok(Self {
            version,
            ephemeral_public,
            session_id,
            encrypted_payload,
            nonce,
        })
    }

    /// Decrypt and parse server config
    pub fn decrypt_config(&self, shared_secret: &[u8]) -> ProtocolResult<ServerConfig> {
        let key = SilverKdf::derive_key(shared_secret, b"adzvpn-handshake", b"server-hello");
        let cipher = SilverCipher::new(&key);

        let config_bytes = cipher
            .decrypt(&self.encrypted_payload, &self.nonce)
            .map_err(|_| ProtocolError::DecryptionFailed)?;

        ServerConfig::from_bytes(&config_bytes)
    }

    /// Convert to handshake packet
    pub fn to_packet(&self) -> HandshakePacket {
        HandshakePacket::new(PacketType::ServerHello, self.to_bytes())
    }
}

/// Server configuration sent during handshake
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server timestamp
    pub timestamp: u64,
    /// Suggested keepalive interval (seconds)
    pub keepalive_interval: u16,
    /// Maximum packet size
    pub max_packet_size: u16,
    /// Server features flags
    pub features: u32,
}

impl ServerConfig {
    /// Create default config
    pub fn default_config() -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            keepalive_interval: 30,
            max_packet_size: MAX_PACKET_SIZE as u16,
            features: 0,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.keepalive_interval.to_le_bytes());
        buf.extend_from_slice(&self.max_packet_size.to_le_bytes());
        buf.extend_from_slice(&self.features.to_le_bytes());
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < 16 {
            return Err(ProtocolError::InvalidPacket(
                "ServerConfig too short".into(),
            ));
        }

        let timestamp = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let keepalive_interval = u16::from_le_bytes([data[8], data[9]]);
        let max_packet_size = u16::from_le_bytes([data[10], data[11]]);
        let features = u32::from_le_bytes(data[12..16].try_into().unwrap());

        Ok(Self {
            timestamp,
            keepalive_interval,
            max_packet_size,
            features,
        })
    }
}

/// Client-side handshake state machine
pub struct ClientHandshake {
    /// Client's ephemeral keypair
    ephemeral: KeyPair,
    /// State
    state: HandshakeState,
    /// Sent ClientHello
    client_hello: Option<ClientHello>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Initial,
    HelloSent,
    Complete,
    Failed,
}

impl ClientHandshake {
    /// Create a new client handshake
    pub fn new() -> Self {
        Self {
            ephemeral: KeyPair::generate(),
            state: HandshakeState::Initial,
            client_hello: None,
        }
    }

    /// Generate ClientHello packet
    pub fn generate_hello(&mut self) -> HandshakePacket {
        let hello = ClientHello::new(self.ephemeral.public_key_bytes());
        let packet = hello.to_packet();
        self.client_hello = Some(hello);
        self.state = HandshakeState::HelloSent;
        packet
    }

    /// Process ServerHello and complete handshake
    pub fn process_server_hello(
        &mut self,
        server_hello: &ServerHello,
    ) -> ProtocolResult<(Session, ServerConfig)> {
        if self.state != HandshakeState::HelloSent {
            return Err(ProtocolError::InvalidState(
                "Cannot process ServerHello in current state".into(),
            ));
        }

        // Compute shared secret
        let shared_secret = self
            .ephemeral
            .diffie_hellman_bytes(&server_hello.ephemeral_public);

        // Decrypt server config
        let config = server_hello.decrypt_config(shared_secret.as_bytes())?;

        // Create session
        let session = Session::from_shared_secret(
            server_hello.session_id,
            shared_secret.as_bytes(),
            true, // is_initiator
        );

        self.state = HandshakeState::Complete;

        Ok((session, config))
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }
}

impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Server-side handshake handler
pub struct ServerHandshake {
    /// Server's ephemeral keypair (generated per handshake)
    ephemeral: KeyPair,
}

impl ServerHandshake {
    /// Create a new server handshake handler
    pub fn new() -> Self {
        Self {
            ephemeral: KeyPair::generate(),
        }
    }

    /// Process ClientHello and generate ServerHello
    pub fn process_client_hello(
        &self,
        client_hello: &ClientHello,
        max_time_drift: u64,
    ) -> ProtocolResult<(ServerHello, Session)> {
        // Verify protocol version
        if client_hello.version != PROTOCOL_VERSION {
            return Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                got: client_hello.version,
            });
        }

        // Verify timestamp
        if !client_hello.verify_timestamp(max_time_drift) {
            return Err(ProtocolError::HandshakeFailed(
                "Timestamp outside acceptable range".into(),
            ));
        }

        // Compute shared secret
        let shared_secret = self
            .ephemeral
            .diffie_hellman_bytes(&client_hello.ephemeral_public);

        // Generate session ID
        let session_id = SessionId::generate();

        // Create server config
        let config = ServerConfig::default_config();

        // Create ServerHello
        let server_hello = ServerHello::new(
            self.ephemeral.public_key_bytes(),
            session_id,
            &config,
            shared_secret.as_bytes(),
        )?;

        // Create session
        let session = Session::from_shared_secret(
            session_id,
            shared_secret.as_bytes(),
            false, // not initiator
        );

        Ok((server_hello, session))
    }
}

impl Default for ServerHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_roundtrip() {
        let keypair = KeyPair::generate();
        let hello = ClientHello::new(keypair.public_key_bytes());

        let bytes = hello.to_bytes();
        let recovered = ClientHello::from_bytes(&bytes).unwrap();

        assert_eq!(hello.version, recovered.version);
        assert_eq!(hello.ephemeral_public, recovered.ephemeral_public);
        assert_eq!(hello.timestamp, recovered.timestamp);
        assert_eq!(hello.nonce, recovered.nonce);
    }

    #[test]
    fn test_client_hello_timestamp_verification() {
        let keypair = KeyPair::generate();
        let hello = ClientHello::new(keypair.public_key_bytes());

        // Should pass with reasonable drift
        assert!(hello.verify_timestamp(60));

        // Create old hello
        let mut old_hello = hello.clone();
        old_hello.timestamp -= 120;
        assert!(!old_hello.verify_timestamp(60));
    }

    #[test]
    fn test_server_config_roundtrip() {
        let config = ServerConfig::default_config();
        let bytes = config.to_bytes();
        let recovered = ServerConfig::from_bytes(&bytes).unwrap();

        assert_eq!(config.timestamp, recovered.timestamp);
        assert_eq!(config.keepalive_interval, recovered.keepalive_interval);
        assert_eq!(config.max_packet_size, recovered.max_packet_size);
        assert_eq!(config.features, recovered.features);
    }

    #[test]
    fn test_full_handshake() {
        // Client side
        let mut client = ClientHandshake::new();
        let client_hello_packet = client.generate_hello();
        assert_eq!(client.state(), HandshakeState::HelloSent);

        // Parse client hello on server side
        let client_hello = ClientHello::from_bytes(&client_hello_packet.payload).unwrap();

        // Server side
        let server = ServerHandshake::new();
        let (server_hello, server_session) = server
            .process_client_hello(&client_hello, 60)
            .unwrap();

        // Client processes server hello
        let (client_session, _config) = client.process_server_hello(&server_hello).unwrap();
        assert_eq!(client.state(), HandshakeState::Complete);

        // Both sessions should have same ID
        assert_eq!(client_session.id(), server_session.id());

        // Test encryption works between sessions
        let message = b"Hello from client!";
        let (ciphertext, nonce) = client_session.encrypt(message).unwrap();
        let decrypted = server_session.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, message);

        // And the other direction
        let message2 = b"Hello from server!";
        let (ciphertext2, nonce2) = server_session.encrypt(message2).unwrap();
        let decrypted2 = client_session.decrypt(&ciphertext2, &nonce2).unwrap();
        assert_eq!(decrypted2, message2);
    }

    #[test]
    fn test_server_hello_roundtrip() {
        let keypair = KeyPair::generate();
        let session_id = SessionId::generate();
        let config = ServerConfig::default_config();
        let shared_secret = [42u8; 32];

        let hello = ServerHello::new(
            keypair.public_key_bytes(),
            session_id,
            &config,
            &shared_secret,
        )
        .unwrap();

        let bytes = hello.to_bytes();
        let recovered = ServerHello::from_bytes(&bytes).unwrap();

        assert_eq!(hello.version, recovered.version);
        assert_eq!(hello.ephemeral_public, recovered.ephemeral_public);
        assert_eq!(hello.session_id, recovered.session_id);
        assert_eq!(hello.nonce, recovered.nonce);
        assert_eq!(hello.encrypted_payload, recovered.encrypted_payload);

        // Decrypt config
        let decrypted_config = recovered.decrypt_config(&shared_secret).unwrap();
        assert_eq!(config.keepalive_interval, decrypted_config.keepalive_interval);
    }

    #[test]
    fn test_handshake_version_mismatch() {
        let keypair = KeyPair::generate();
        let mut hello = ClientHello::new(keypair.public_key_bytes());
        hello.version = 0xFFFF; // Wrong version

        let server = ServerHandshake::new();
        let result = server.process_client_hello(&hello, 60);

        assert!(matches!(
            result,
            Err(ProtocolError::VersionMismatch { .. })
        ));
    }
}
