//! X25519 Key Exchange
//!
//! Elliptic Curve Diffie-Hellman using Curve25519.
//! Provides perfect forward secrecy with ephemeral key pairs.

use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use serde::{Deserialize, Serialize};

use crate::errors::{CryptoError, CryptoResult};

/// Size of X25519 public key in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 private key in bytes
pub const PRIVATE_KEY_SIZE: usize = 32;

/// Size of shared secret in bytes
pub const SHARED_SECRET_SIZE: usize = 32;

/// X25519 Key Pair for Diffie-Hellman key exchange
///
/// Uses static secrets that can be serialized/stored.
/// For ephemeral (one-time) keys, use `EphemeralKeyPair`.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from existing secret key bytes
    pub fn from_secret(secret_bytes: [u8; PRIVATE_KEY_SIZE]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        *self.public.as_bytes()
    }

    /// Get secret key bytes (be careful with this!)
    pub fn secret_key_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
        self.secret.to_bytes()
    }

    /// Perform Diffie-Hellman key exchange
    ///
    /// # Arguments
    /// * `their_public` - The other party's public key
    ///
    /// # Returns
    /// Shared secret (32 bytes)
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public)
    }

    /// Perform DH from public key bytes
    pub fn diffie_hellman_bytes(&self, their_public_bytes: &[u8; PUBLIC_KEY_SIZE]) -> SharedSecret {
        let their_public = PublicKey::from(*their_public_bytes);
        self.diffie_hellman(&their_public)
    }
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        Self::from_secret(self.secret.to_bytes())
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &hex::encode(self.public.as_bytes()))
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Ephemeral Key Pair for one-time use
///
/// Cannot be serialized or cloned - ensures single use.
/// Provides better forward secrecy guarantees.
pub struct EphemeralKeyPair {
    secret: Option<EphemeralSecret>,
    public: PublicKey,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        *self.public.as_bytes()
    }

    /// Perform Diffie-Hellman and consume the secret
    ///
    /// The secret is consumed to prevent reuse (forward secrecy).
    ///
    /// # Arguments
    /// * `their_public` - The other party's public key
    ///
    /// # Returns
    /// Shared secret, or error if already consumed
    pub fn diffie_hellman(mut self, their_public: &PublicKey) -> CryptoResult<SharedSecret> {
        let secret = self
            .secret
            .take()
            .ok_or(CryptoError::InvalidPublicKey)?;
        Ok(secret.diffie_hellman(their_public))
    }

    /// Perform DH from public key bytes
    pub fn diffie_hellman_bytes(
        self,
        their_public_bytes: &[u8; PUBLIC_KEY_SIZE],
    ) -> CryptoResult<SharedSecret> {
        let their_public = PublicKey::from(*their_public_bytes);
        self.diffie_hellman(&their_public)
    }

    /// Check if the secret has been consumed
    pub fn is_consumed(&self) -> bool {
        self.secret.is_none()
    }
}

impl std::fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("public", &hex::encode(self.public.as_bytes()))
            .field("consumed", &self.is_consumed())
            .finish()
    }
}

/// Serializable public key wrapper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerializablePublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl SerializablePublicKey {
    /// Create from public key
    pub fn from_public_key(pk: &PublicKey) -> Self {
        Self {
            bytes: *pk.as_bytes(),
        }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Get as PublicKey
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from(self.bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

impl From<PublicKey> for SerializablePublicKey {
    fn from(pk: PublicKey) -> Self {
        Self::from_public_key(&pk)
    }
}

impl From<SerializablePublicKey> for PublicKey {
    fn from(spk: SerializablePublicKey) -> Self {
        spk.to_public_key()
    }
}

/// Generate a random nonce/salt for key exchange
pub fn generate_random_bytes<const N: usize>() -> CryptoResult<[u8; N]> {
    let mut bytes = [0u8; N];
    rand::thread_rng()
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RngError)?;
    Ok(bytes)
}

/// Wrapper around SharedSecret for convenience
pub struct DhSharedSecret(SharedSecret);

impl DhSharedSecret {
    /// Create from SharedSecret
    pub fn new(secret: SharedSecret) -> Self {
        Self(secret)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        self.0.as_bytes()
    }

    /// Convert to owned bytes
    pub fn to_bytes(&self) -> [u8; SHARED_SECRET_SIZE] {
        *self.0.as_bytes()
    }
}

impl From<SharedSecret> for DhSharedSecret {
    fn from(secret: SharedSecret) -> Self {
        Self::new(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(kp.secret_key_bytes().len(), PRIVATE_KEY_SIZE);
    }

    #[test]
    fn test_keypair_from_secret() {
        let kp1 = KeyPair::generate();
        let secret_bytes = kp1.secret_key_bytes();

        let kp2 = KeyPair::from_secret(secret_bytes);

        // Same secret should produce same public key
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        // Both parties compute shared secret
        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        // Shared secrets should match
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_diffie_hellman_bytes() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let bob_pub_bytes = bob.public_key_bytes();
        let alice_pub_bytes = alice.public_key_bytes();

        let alice_shared = alice.diffie_hellman_bytes(&bob_pub_bytes);
        let bob_shared = bob.diffie_hellman_bytes(&alice_pub_bytes);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_ephemeral_keypair() {
        let alice = EphemeralKeyPair::generate();
        let bob = KeyPair::generate();

        assert!(!alice.is_consumed());

        let alice_pub = alice.public_key_bytes();
        let shared = alice.diffie_hellman(bob.public_key()).unwrap();

        // Verify Bob gets the same shared secret
        let bob_shared = bob.diffie_hellman_bytes(&alice_pub);
        assert_eq!(shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let eve = KeyPair::generate();

        let alice_bob = alice.diffie_hellman(bob.public_key());
        let alice_eve = alice.diffie_hellman(eve.public_key());

        // Different partners should produce different secrets
        assert_ne!(alice_bob.as_bytes(), alice_eve.as_bytes());
    }

    #[test]
    fn test_serializable_public_key() {
        let kp = KeyPair::generate();
        let spk = SerializablePublicKey::from_public_key(kp.public_key());

        // Serialize and deserialize
        let json = serde_json::to_string(&spk).unwrap();
        let deserialized: SerializablePublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(spk.as_bytes(), deserialized.as_bytes());

        // Convert back to PublicKey
        let pk: PublicKey = deserialized.into();
        assert_eq!(pk.as_bytes(), kp.public_key().as_bytes());
    }

    #[test]
    fn test_generate_random_bytes() {
        let bytes1: [u8; 32] = generate_random_bytes().unwrap();
        let bytes2: [u8; 32] = generate_random_bytes().unwrap();

        // Should be different (extremely high probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_keypair_clone() {
        let kp1 = KeyPair::generate();
        let kp2 = kp1.clone();

        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
        assert_eq!(kp1.secret_key_bytes(), kp2.secret_key_bytes());
    }

    #[test]
    fn test_dh_shared_secret_wrapper() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared = alice.diffie_hellman(bob.public_key());
        let wrapped = DhSharedSecret::new(shared);

        assert_eq!(wrapped.as_bytes().len(), SHARED_SECRET_SIZE);
        assert_eq!(wrapped.to_bytes().len(), SHARED_SECRET_SIZE);
    }
}
