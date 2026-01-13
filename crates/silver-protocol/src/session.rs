//! Session Management
//!
//! Manages encrypted sessions between client and server.
//! Handles key derivation, encryption/decryption, and session lifecycle.

use rand::RngCore;
use silver_crypto::prelude::*;
use std::time::{Duration, Instant};

use crate::constants::*;
use crate::errors::{ProtocolError, ProtocolResult};

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; SESSION_ID_SIZE]);

impl SessionId {
    /// Generate a random session ID
    pub fn generate() -> Self {
        let mut id = [0u8; SESSION_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        Self(id)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; SESSION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.0
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> ProtocolResult<Self> {
        if slice.len() != SESSION_ID_SIZE {
            return Err(ProtocolError::InvalidPacket(format!(
                "Invalid session ID length: {} (expected {})",
                slice.len(),
                SESSION_ID_SIZE
            )));
        }
        let mut id = [0u8; SESSION_ID_SIZE];
        id.copy_from_slice(slice);
        Ok(Self(id))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..4])) // Show first 4 bytes
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, handshake not started
    Initial,
    /// Handshake in progress
    Handshaking,
    /// Session established and active
    Established,
    /// Session is closing
    Closing,
    /// Session is closed
    Closed,
}

/// Encrypted session
pub struct Session {
    /// Session identifier
    id: SessionId,
    /// Current state
    state: SessionState,
    /// Encryption cipher
    cipher: SilverCipher,
    /// Nonce counter for outgoing packets (reserved for stateful nonce management)
    #[allow(dead_code)]
    send_nonce: NonceCounter,
    /// Last received nonce (for replay protection)
    #[allow(dead_code)]
    recv_nonce_high: u64,
    /// Packet counters
    packets_sent: u64,
    packets_received: u64,
    /// Bytes counters
    bytes_sent: u64,
    bytes_received: u64,
    /// Timing
    created_at: Instant,
    last_activity: Instant,
    /// Is this the initiator (client) side?
    is_initiator: bool,
}

impl Session {
    /// Create a new session from shared secret (after handshake)
    pub fn from_shared_secret(
        id: SessionId,
        shared_secret: &[u8],
        is_initiator: bool,
    ) -> Self {
        // Derive encryption key using Silver KDF
        // Both sides use the same key for symmetric encryption
        let salt = id.as_bytes();
        let info = b"adzvpn-session-key"; // Symmetric key for both directions

        let key = SilverKdf::derive_key(shared_secret, salt, info);
        let cipher = SilverCipher::new(&key);

        // Initialize nonce counter with session-specific prefix
        let mut nonce_prefix = [0u8; 4];
        nonce_prefix.copy_from_slice(&salt[0..4]);
        if is_initiator {
            nonce_prefix[0] |= 0x80; // Set high bit for initiator
        }
        let send_nonce = NonceCounter::with_prefix(nonce_prefix);

        let now = Instant::now();

        Self {
            id,
            state: SessionState::Established,
            cipher,
            send_nonce,
            recv_nonce_high: 0,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            created_at: now,
            last_activity: now,
            is_initiator,
        }
    }

    /// Get session ID
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if session is established
    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    /// Check if session is active (not closed/closing)
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            SessionState::Handshaking | SessionState::Established
        )
    }

    /// Encrypt data for sending
    pub fn encrypt(&self, plaintext: &[u8]) -> ProtocolResult<(Vec<u8>, [u8; NONCE_SIZE])> {
        // Note: In real impl, we'd use a mutable borrow to increment nonce counter
        // For now, generate random nonce (safe but less efficient)
        let nonce = SilverCipher::generate_nonce()
            .map_err(|e| ProtocolError::EncryptionFailed(e.to_string()))?;

        let ciphertext = self
            .cipher
            .encrypt_with_nonce(plaintext, &nonce)
            .map_err(|e| ProtocolError::EncryptionFailed(e.to_string()))?;

        Ok((ciphertext, nonce))
    }

    /// Decrypt received data
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> ProtocolResult<Vec<u8>> {
        self.cipher
            .decrypt(ciphertext, nonce)
            .map_err(|_| ProtocolError::DecryptionFailed)
    }

    /// Update activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Record sent packet
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.touch();
    }

    /// Record received packet
    pub fn record_received(&mut self, bytes: usize) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
        self.touch();
    }

    /// Get packets sent
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    /// Get packets received
    pub fn packets_received(&self) -> u64 {
        self.packets_received
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Check if session has expired (idle timeout)
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS)
    }

    /// Check if key rotation is needed
    pub fn needs_key_rotation(&self) -> bool {
        // Rotate after too many packets or too much time
        self.packets_sent >= MAX_PACKETS_PER_KEY
            || self.created_at.elapsed() > Duration::from_secs(KEY_ROTATION_INTERVAL_SECS)
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Transition to closing state
    pub fn close(&mut self) {
        self.state = SessionState::Closing;
    }

    /// Transition to closed state
    pub fn mark_closed(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Is this the initiator side?
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("packets_sent", &self.packets_sent)
            .field("packets_received", &self.packets_received)
            .field("bytes_sent", &self.bytes_sent)
            .field("bytes_received", &self.bytes_received)
            .field("is_initiator", &self.is_initiator)
            .finish()
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub id: SessionId,
    pub state: SessionState,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub is_initiator: bool,
}

impl From<&Session> for SessionStats {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id,
            state: session.state,
            packets_sent: session.packets_sent,
            packets_received: session.packets_received,
            bytes_sent: session.bytes_sent,
            bytes_received: session.bytes_received,
            age_secs: session.age().as_secs(),
            idle_secs: session.idle_time().as_secs(),
            is_initiator: session.is_initiator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generation() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();

        // Should be different (extremely high probability)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_id_from_bytes() {
        let bytes = [1u8; SESSION_ID_SIZE];
        let id = SessionId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_session_id_from_slice() {
        let bytes = vec![42u8; SESSION_ID_SIZE];
        let id = SessionId::from_slice(&bytes).unwrap();
        assert_eq!(id.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn test_session_id_from_slice_invalid() {
        let bytes = vec![42u8; 8]; // Wrong size
        let result = SessionId::from_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_creation() {
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];
        let session = Session::from_shared_secret(id, &shared_secret, true);

        assert_eq!(session.id(), id);
        assert_eq!(session.state(), SessionState::Established);
        assert!(session.is_established());
        assert!(session.is_active());
        assert!(session.is_initiator());
        assert_eq!(session.packets_sent(), 0);
        assert_eq!(session.packets_received(), 0);
    }

    #[test]
    fn test_session_encrypt_decrypt() {
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];
        let session = Session::from_shared_secret(id, &shared_secret, true);

        let plaintext = b"Hello, ADZVPN-Opus!";
        let (ciphertext, nonce) = session.encrypt(plaintext).unwrap();

        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        // Should decrypt back to original
        let decrypted = session.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_session_stats() {
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];
        let mut session = Session::from_shared_secret(id, &shared_secret, false);

        session.record_sent(100);
        session.record_sent(200);
        session.record_received(150);

        assert_eq!(session.packets_sent(), 2);
        assert_eq!(session.packets_received(), 1);
        assert_eq!(session.bytes_sent(), 300);
        assert_eq!(session.bytes_received(), 150);

        let stats = SessionStats::from(&session);
        assert_eq!(stats.packets_sent, 2);
        assert_eq!(stats.bytes_sent, 300);
        assert!(!stats.is_initiator);
    }

    #[test]
    fn test_session_state_transitions() {
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];
        let mut session = Session::from_shared_secret(id, &shared_secret, true);

        assert!(session.is_active());

        session.close();
        assert_eq!(session.state(), SessionState::Closing);
        assert!(!session.is_established());

        session.mark_closed();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(!session.is_active());
    }

    #[test]
    fn test_symmetric_sessions() {
        // Two ends of a connection should be able to communicate
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];

        // Note: In real protocol, client and server derive different keys
        // This test uses same key for simplicity
        let client = Session::from_shared_secret(id, &shared_secret, true);
        let server = Session::from_shared_secret(id, &shared_secret, true);

        let message = b"Test message";
        let (ciphertext, nonce) = client.encrypt(message).unwrap();
        let decrypted = server.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, message);
    }
}
