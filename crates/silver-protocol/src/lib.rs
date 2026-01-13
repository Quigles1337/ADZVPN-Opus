//! # Silver Protocol
//!
//! The core VPN protocol for ADZVPN-Opus, featuring:
//! - Silver packet format with η-padding for traffic analysis resistance
//! - 1-RTT handshake with perfect forward secrecy
//! - ChaCha20-Poly1305 authenticated encryption
//! - Silver ratio-based timing and traffic shaping
//!
//! ## Protocol Overview
//!
//! ```text
//! Client                                 Server
//!   |                                      |
//!   |------- ClientHello (ephemeral) ----->|
//!   |                                      |
//!   |<------ ServerHello (ephemeral) ------|
//!   |        + encrypted config            |
//!   |                                      |
//!   |===== Encrypted tunnel established ===|
//!   |                                      |
//!   |<------- Silver Packets ------------->|
//!   |       (η-padded, τ-timed)            |
//! ```
//!
//! Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5

pub mod packet;
pub mod handshake;
pub mod session;
pub mod errors;
pub mod constants;

pub use packet::*;
pub use handshake::*;
pub use session::*;
pub use errors::*;
pub use constants::*;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::packet::*;
    pub use crate::handshake::*;
    pub use crate::session::*;
    pub use crate::errors::*;
    pub use crate::constants::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_crypto::prelude::*;

    #[test]
    fn test_full_handshake_and_packet() {
        // Client initiates
        let client_ephemeral = KeyPair::generate();
        let _client_hello = ClientHello::new(client_ephemeral.public_key_bytes());

        // Server responds
        let server_ephemeral = KeyPair::generate();
        let _server_static = KeyPair::generate();

        // Derive shared secret (simplified - real impl uses both keys)
        let shared = client_ephemeral.diffie_hellman(server_ephemeral.public_key());

        // Create session
        let session_id = SessionId::generate();
        let session = Session::from_shared_secret(
            session_id,
            shared.as_bytes(),
            true, // is_initiator
        );

        // Create and encrypt a packet
        let payload = b"Hello from ADZVPN-Opus!";
        let packet = SilverPacket::new_data(payload, &session).unwrap();

        // Verify packet structure
        assert!(packet.ciphertext.len() > payload.len()); // Has padding + tag

        // Decrypt (would need matching session on other side)
        // This test just verifies the flow works
    }
}
