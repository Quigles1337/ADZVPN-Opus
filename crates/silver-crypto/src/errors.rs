//! Error types for silver-crypto

use thiserror::Error;

/// Errors that can occur in silver-crypto operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    /// Decryption failed (likely tampered or wrong key)
    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionError,

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// Invalid nonce length
    #[error("Invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KdfError(String),

    /// Random number generation failed
    #[error("Random number generation failed")]
    RngError,

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for silver-crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;
