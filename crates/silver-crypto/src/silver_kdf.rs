//! Silver Key Derivation Function
//!
//! Enhanced HKDF using silver ratio parameters for additional security.
//! The Silver KDF uses δ_S * 1000 = 2414 iterations for key stretching.

use hkdf::Hkdf;
use sha2::Sha256;
use silver_core::{DELTA_S, SILVER_KDF_ITERATIONS, TAU_MIX_BYTE};

use crate::errors::{CryptoError, CryptoResult};

/// Key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Salt size in bytes
pub const SALT_SIZE: usize = 32;

/// Silver KDF - Key derivation with silver ratio enhancement
///
/// Uses HKDF-SHA256 with additional iterations based on δ_S.
pub struct SilverKdf;

impl SilverKdf {
    /// Derive a key from input key material
    ///
    /// # Arguments
    /// * `ikm` - Input key material (e.g., shared secret from DH)
    /// * `salt` - Optional salt (use domain separator if no random salt)
    /// * `info` - Context/application-specific info
    ///
    /// # Returns
    /// 32-byte derived key
    pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; KEY_SIZE] {
        Self::derive_key_with_iterations(ikm, salt, info, SILVER_KDF_ITERATIONS)
    }

    /// Derive a key with custom iteration count
    ///
    /// # Arguments
    /// * `ikm` - Input key material
    /// * `salt` - Salt value
    /// * `info` - Context info
    /// * `iterations` - Number of HKDF iterations
    ///
    /// # Returns
    /// 32-byte derived key
    pub fn derive_key_with_iterations(
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        iterations: u32,
    ) -> [u8; KEY_SIZE] {
        let mut current_key = [0u8; KEY_SIZE];

        // Initial HKDF extraction and expansion
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        hk.expand(info, &mut current_key)
            .expect("HKDF expand should not fail with 32-byte output");

        // Silver iteration loop
        // Each iteration mixes in τ and re-derives
        for i in 0..iterations {
            // Create iteration-specific info by mixing τ byte
            let iter_info = Self::mix_iteration_info(info, i);

            let hk = Hkdf::<Sha256>::new(Some(&current_key), &current_key);
            hk.expand(&iter_info, &mut current_key)
                .expect("HKDF expand should not fail");
        }

        current_key
    }

    /// Mix iteration info with τ for additional entropy
    fn mix_iteration_info(info: &[u8], iteration: u32) -> Vec<u8> {
        let mut mixed = Vec::with_capacity(info.len() + 5);
        mixed.extend_from_slice(info);
        mixed.push(TAU_MIX_BYTE);
        mixed.extend_from_slice(&iteration.to_le_bytes());
        mixed
    }

    /// Derive multiple keys from the same IKM
    ///
    /// Useful for deriving encryption key + authentication key
    ///
    /// # Arguments
    /// * `ikm` - Input key material
    /// * `salt` - Salt value
    /// * `labels` - Labels for each key to derive
    ///
    /// # Returns
    /// Vector of derived keys
    pub fn derive_keys(ikm: &[u8], salt: &[u8], labels: &[&[u8]]) -> Vec<[u8; KEY_SIZE]> {
        labels
            .iter()
            .map(|label| Self::derive_key(ikm, salt, label))
            .collect()
    }

    /// Derive session keys for encryption and authentication
    ///
    /// # Arguments
    /// * `shared_secret` - DH shared secret
    /// * `session_id` - Unique session identifier
    ///
    /// # Returns
    /// Tuple of (encryption_key, auth_key)
    pub fn derive_session_keys(
        shared_secret: &[u8],
        session_id: &[u8],
    ) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
        let enc_key = Self::derive_key(shared_secret, session_id, b"adzvpn-encryption");
        let auth_key = Self::derive_key(shared_secret, session_id, b"adzvpn-authentication");
        (enc_key, auth_key)
    }

    /// Calculate the number of iterations for a given security level
    ///
    /// # Arguments
    /// * `security_bits` - Desired security level (128, 192, or 256)
    ///
    /// # Returns
    /// Number of iterations
    pub fn iterations_for_security(security_bits: u32) -> u32 {
        // Base: δ_S * 1000 for 128-bit security
        // Scale for higher security levels
        let multiplier = match security_bits {
            128 => 1,
            192 => 2,
            256 => 3,
            _ => (security_bits / 128).max(1),
        };
        SILVER_KDF_ITERATIONS * multiplier
    }

    /// Get the silver ratio multiplier used in KDF
    pub fn silver_multiplier() -> f64 {
        DELTA_S
    }

    /// Get the default iteration count
    pub fn default_iterations() -> u32 {
        SILVER_KDF_ITERATIONS
    }
}

/// Key material wrapper for secure handling
#[derive(Clone)]
pub struct KeyMaterial {
    key: [u8; KEY_SIZE],
}

impl KeyMaterial {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { key: bytes }
    }

    /// Create from slice (must be exactly KEY_SIZE bytes)
    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                got: slice.len(),
            });
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(slice);
        Ok(Self { key })
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Derive from password using Silver KDF
    pub fn from_password(password: &[u8], salt: &[u8]) -> Self {
        let key = SilverKdf::derive_key(password, salt, b"adzvpn-password");
        Self { key }
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Zero out key material on drop
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't leak key material in debug output
        f.debug_struct("KeyMaterial")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let ikm = b"test input key material";
        let salt = b"test salt";
        let info = b"test info";

        let key1 = SilverKdf::derive_key(ikm, salt, info);
        let key2 = SilverKdf::derive_key(ikm, salt, info);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_inputs() {
        let ikm = b"test input key material";
        let salt = b"test salt";

        let key1 = SilverKdf::derive_key(ikm, salt, b"info1");
        let key2 = SilverKdf::derive_key(ikm, salt, b"info2");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let ikm = b"test input key material";
        let info = b"test info";

        let key1 = SilverKdf::derive_key(ikm, b"salt1", info);
        let key2 = SilverKdf::derive_key(ikm, b"salt2", info);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_session_keys() {
        let shared_secret = b"shared secret from DH";
        let session_id = b"unique-session-id";

        let (enc_key, auth_key) = SilverKdf::derive_session_keys(shared_secret, session_id);

        // Keys should be different
        assert_ne!(enc_key, auth_key);

        // Should be deterministic
        let (enc_key2, auth_key2) = SilverKdf::derive_session_keys(shared_secret, session_id);
        assert_eq!(enc_key, enc_key2);
        assert_eq!(auth_key, auth_key2);
    }

    #[test]
    fn test_derive_keys_multiple() {
        let ikm = b"input key material";
        let salt = b"salt";
        let labels: &[&[u8]] = &[b"key1", b"key2", b"key3"];

        let keys = SilverKdf::derive_keys(ikm, salt, labels);

        assert_eq!(keys.len(), 3);
        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_iterations_for_security() {
        assert_eq!(
            SilverKdf::iterations_for_security(128),
            SILVER_KDF_ITERATIONS
        );
        assert_eq!(
            SilverKdf::iterations_for_security(256),
            SILVER_KDF_ITERATIONS * 3
        );
    }

    #[test]
    fn test_key_material_from_password() {
        let password = b"my secret password";
        let salt = b"random salt value";

        let key = KeyMaterial::from_password(password, salt);

        // Should produce a valid key
        assert_eq!(key.as_bytes().len(), KEY_SIZE);

        // Should be deterministic
        let key2 = KeyMaterial::from_password(password, salt);
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_material_from_slice() {
        let bytes = [42u8; KEY_SIZE];
        let key = KeyMaterial::from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_material_from_slice_invalid_length() {
        let bytes = [42u8; 16]; // Wrong length
        let result = KeyMaterial::from_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_silver_constants() {
        assert_eq!(SilverKdf::default_iterations(), 2414);
        assert!((SilverKdf::silver_multiplier() - 2.414213562373095).abs() < 1e-10);
    }
}
