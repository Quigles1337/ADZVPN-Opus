//! # Silver Crypto
//!
//! Cryptographic primitives for ADZVPN-Opus, featuring Silver Ratio-enhanced
//! key derivation and standard modern cryptography.
//!
//! ## Components
//!
//! - **Silver KDF**: Key derivation using δ_S-based iterations
//! - **Encryption**: ChaCha20-Poly1305 AEAD encryption
//! - **Key Exchange**: X25519 Diffie-Hellman
//! - **Hashing**: BLAKE3 for fast, secure hashing
//!
//! ## Security
//!
//! - ChaCha20-Poly1305 for authenticated encryption
//! - X25519 for key exchange (Curve25519)
//! - Silver KDF adds δ_S * 1000 = 2414 HKDF iterations
//! - BLAKE3 for hashing (faster than SHA-256, equally secure)
//!
//! Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5

pub mod silver_kdf;
pub mod encryption;
pub mod key_exchange;
pub mod hashing;
pub mod errors;

pub use silver_kdf::*;
pub use encryption::*;
pub use key_exchange::*;
pub use hashing::*;
pub use errors::*;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::silver_kdf::*;
    pub use crate::encryption::*;
    pub use crate::key_exchange::*;
    pub use crate::hashing::*;
    pub use crate::errors::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_roundtrip() {
        // Generate keypairs
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        // Derive shared secret
        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        // Both should derive the same secret
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

        // Derive encryption key using Silver KDF
        let key = SilverKdf::derive_key(
            alice_shared.as_bytes(),
            b"adzvpn-session",
            b"encryption-key",
        );

        // Encrypt a message
        let plaintext = b"Hello from ADZVPN-Opus!";
        let cipher = SilverCipher::new(&key);
        let (ciphertext, nonce) = cipher.encrypt(plaintext).unwrap();

        // Decrypt
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
