//! ChaCha20-Poly1305 AEAD Encryption
//!
//! Provides authenticated encryption using ChaCha20 stream cipher
//! with Poly1305 message authentication.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

use crate::errors::{CryptoError, CryptoResult};
use crate::silver_kdf::KEY_SIZE;

/// Nonce size for ChaCha20-Poly1305 (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size (128 bits)
pub const TAG_SIZE: usize = 16;

/// Silver Cipher - ChaCha20-Poly1305 AEAD encryption
///
/// Provides authenticated encryption with associated data (AEAD).
/// Uses ChaCha20 for encryption and Poly1305 for authentication.
pub struct SilverCipher {
    cipher: ChaCha20Poly1305,
}

impl SilverCipher {
    /// Create a new cipher with the given key
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    ///
    /// # Returns
    /// New SilverCipher instance
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .expect("Key size is always valid");
        Self { cipher }
    }

    /// Encrypt plaintext with random nonce
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Tuple of (ciphertext with tag, nonce)
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<(Vec<u8>, [u8; NONCE_SIZE])> {
        let nonce = Self::generate_nonce()?;
        let ciphertext = self.encrypt_with_nonce(plaintext, &nonce)?;
        Ok((ciphertext, nonce))
    }

    /// Encrypt plaintext with specified nonce
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 12-byte nonce (must be unique per key)
    ///
    /// # Returns
    /// Ciphertext with authentication tag appended
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8; NONCE_SIZE],
    ) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionError("ChaCha20-Poly1305 encryption failed".into()))
    }

    /// Encrypt with associated data (AEAD)
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Associated data (authenticated but not encrypted)
    /// * `nonce` - 12-byte nonce
    ///
    /// # Returns
    /// Ciphertext with authentication tag
    pub fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        nonce: &[u8; NONCE_SIZE],
    ) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::EncryptionError("AEAD encryption failed".into()))
    }

    /// Decrypt ciphertext
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with tag
    /// * `nonce` - 12-byte nonce used during encryption
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionError)
    }

    /// Decrypt with associated data (AEAD)
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with tag
    /// * `aad` - Associated data (must match encryption)
    /// * `nonce` - 12-byte nonce
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &[u8; NONCE_SIZE],
    ) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionError)
    }

    /// Generate a random nonce
    pub fn generate_nonce() -> CryptoResult<[u8; NONCE_SIZE]> {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng()
            .try_fill_bytes(&mut nonce)
            .map_err(|_| CryptoError::RngError)?;
        Ok(nonce)
    }

    /// Calculate ciphertext length for given plaintext length
    pub fn ciphertext_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_SIZE
    }

    /// Calculate plaintext length from ciphertext length
    pub fn plaintext_len(ciphertext_len: usize) -> Option<usize> {
        ciphertext_len.checked_sub(TAG_SIZE)
    }
}

/// Nonce counter for sequential nonce generation
///
/// For protocols that need sequential nonces instead of random.
/// WARNING: Never reuse a nonce with the same key!
pub struct NonceCounter {
    counter: u64,
    prefix: [u8; 4],
}

impl NonceCounter {
    /// Create a new nonce counter with random prefix
    pub fn new() -> CryptoResult<Self> {
        let mut prefix = [0u8; 4];
        rand::thread_rng()
            .try_fill_bytes(&mut prefix)
            .map_err(|_| CryptoError::RngError)?;
        Ok(Self { counter: 0, prefix })
    }

    /// Create with specific prefix
    pub fn with_prefix(prefix: [u8; 4]) -> Self {
        Self { counter: 0, prefix }
    }

    /// Get the next nonce
    pub fn next(&mut self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..4].copy_from_slice(&self.prefix);
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    /// Get current counter value
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Check if counter is about to wrap (dangerous!)
    pub fn is_near_exhaustion(&self) -> bool {
        self.counter > u64::MAX - 1000
    }
}

impl Default for NonceCounter {
    fn default() -> Self {
        Self::with_prefix([0; 4])
    }
}

/// Encrypted packet with metadata
#[derive(Debug, Clone)]
pub struct EncryptedPacket {
    /// Nonce used for encryption
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext with authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedPacket {
    /// Create a new encrypted packet
    pub fn new(nonce: [u8; NONCE_SIZE], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Serialize to bytes (nonce || ciphertext)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_SIZE + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_SIZE,
                got: bytes.len(),
            });
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[0..NONCE_SIZE]);
        let ciphertext = bytes[NONCE_SIZE..].to_vec();

        Ok(Self { nonce, ciphertext })
    }

    /// Total serialized size
    pub fn size(&self) -> usize {
        NONCE_SIZE + self.ciphertext.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = test_key();
        let cipher = SilverCipher::new(&key);
        let plaintext = b"Hello, ADZVPN-Opus!";

        let (ciphertext, nonce) = cipher.encrypt(plaintext).unwrap();

        // Ciphertext should be larger (includes tag)
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        // Decrypt
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_nonce() {
        let key = test_key();
        let cipher = SilverCipher::new(&key);
        let plaintext = b"Test message";
        let nonce = [42u8; NONCE_SIZE];

        let ciphertext = cipher.encrypt_with_nonce(plaintext, &nonce).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_with_aad() {
        let key = test_key();
        let cipher = SilverCipher::new(&key);
        let plaintext = b"Secret message";
        let aad = b"Associated data";
        let nonce = [1u8; NONCE_SIZE];

        let ciphertext = cipher.encrypt_with_aad(plaintext, aad, &nonce).unwrap();

        // Decrypt with correct AAD
        let decrypted = cipher.decrypt_with_aad(&ciphertext, aad, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decrypt with wrong AAD should fail
        let result = cipher.decrypt_with_aad(&ciphertext, b"wrong aad", &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = test_key();
        let cipher = SilverCipher::new(&key);
        let plaintext = b"Original message";

        let (mut ciphertext, nonce) = cipher.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Decryption should fail
        let result = cipher.decrypt(&ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0xFF;

        let cipher1 = SilverCipher::new(&key1);
        let cipher2 = SilverCipher::new(&key2);

        let plaintext = b"Secret";
        let (ciphertext, nonce) = cipher1.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = cipher2.decrypt(&ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_counter() {
        let mut counter = NonceCounter::with_prefix([1, 2, 3, 4]);

        let nonce1 = counter.next();
        let nonce2 = counter.next();
        let nonce3 = counter.next();

        // Nonces should be different
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);

        // Prefix should be preserved
        assert_eq!(&nonce1[0..4], &[1, 2, 3, 4]);
        assert_eq!(&nonce2[0..4], &[1, 2, 3, 4]);

        // Counter should increment
        assert_eq!(counter.counter(), 3);
    }

    #[test]
    fn test_encrypted_packet_serialization() {
        let nonce = [42u8; NONCE_SIZE];
        let ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];

        let packet = EncryptedPacket::new(nonce, ciphertext.clone());
        let bytes = packet.to_bytes();

        let deserialized = EncryptedPacket::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.nonce, nonce);
        assert_eq!(deserialized.ciphertext, ciphertext);
    }

    #[test]
    fn test_ciphertext_length_calculation() {
        let plaintext_len = 100;
        let ciphertext_len = SilverCipher::ciphertext_len(plaintext_len);
        assert_eq!(ciphertext_len, plaintext_len + TAG_SIZE);

        let recovered = SilverCipher::plaintext_len(ciphertext_len).unwrap();
        assert_eq!(recovered, plaintext_len);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let cipher = SilverCipher::new(&key);
        let plaintext = b"";

        let (ciphertext, nonce) = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = test_key();
        let cipher = SilverCipher::new(&key);
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1MB

        let (ciphertext, nonce) = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
