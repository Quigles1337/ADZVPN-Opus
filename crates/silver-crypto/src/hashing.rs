//! BLAKE3 Hashing
//!
//! Fast, secure hashing using BLAKE3 algorithm.
//! Used for packet integrity, key derivation assistance, and general hashing.

use blake3::{Hash, Hasher, OUT_LEN};

/// Hash output size (256 bits)
pub const HASH_SIZE: usize = OUT_LEN;

/// BLAKE3 hash function wrapper
pub struct SilverHash;

impl SilverHash {
    /// Hash data and return fixed-size output
    pub fn hash(data: &[u8]) -> [u8; HASH_SIZE] {
        *blake3::hash(data).as_bytes()
    }

    /// Hash data and return Hash object
    pub fn hash_to_hash(data: &[u8]) -> Hash {
        blake3::hash(data)
    }

    /// Hash multiple pieces of data
    pub fn hash_many(data: &[&[u8]]) -> [u8; HASH_SIZE] {
        let mut hasher = Hasher::new();
        for d in data {
            hasher.update(d);
        }
        *hasher.finalize().as_bytes()
    }

    /// Create a keyed hash (MAC)
    pub fn keyed_hash(key: &[u8; HASH_SIZE], data: &[u8]) -> [u8; HASH_SIZE] {
        *blake3::keyed_hash(key, data).as_bytes()
    }

    /// Derive a key from context and input
    pub fn derive_key(context: &str, input: &[u8]) -> [u8; HASH_SIZE] {
        let mut output = [0u8; HASH_SIZE];
        blake3::Hasher::new_derive_key(context)
            .update(input)
            .finalize_xof()
            .fill(&mut output);
        output
    }

    /// Derive a key with custom output length
    pub fn derive_key_custom<const N: usize>(context: &str, input: &[u8]) -> [u8; N] {
        let mut output = [0u8; N];
        blake3::Hasher::new_derive_key(context)
            .update(input)
            .finalize_xof()
            .fill(&mut output);
        output
    }

    /// Verify data matches expected hash
    pub fn verify(data: &[u8], expected: &[u8; HASH_SIZE]) -> bool {
        let actual = Self::hash(data);
        constant_time_eq(&actual, expected)
    }

    /// Verify keyed hash
    pub fn verify_keyed(key: &[u8; HASH_SIZE], data: &[u8], expected: &[u8; HASH_SIZE]) -> bool {
        let actual = Self::keyed_hash(key, data);
        constant_time_eq(&actual, expected)
    }
}

/// Incremental hasher for streaming data
pub struct StreamingHasher {
    hasher: Hasher,
}

impl StreamingHasher {
    /// Create a new streaming hasher
    pub fn new() -> Self {
        Self {
            hasher: Hasher::new(),
        }
    }

    /// Create a keyed streaming hasher
    pub fn new_keyed(key: &[u8; HASH_SIZE]) -> Self {
        Self {
            hasher: Hasher::new_keyed(key),
        }
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and get hash
    pub fn finalize(self) -> [u8; HASH_SIZE] {
        *self.hasher.finalize().as_bytes()
    }

    /// Finalize without consuming (can continue hashing)
    pub fn finalize_peek(&self) -> [u8; HASH_SIZE] {
        *self.hasher.finalize().as_bytes()
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        self.hasher.reset();
    }
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Hash-based message authentication code
pub struct SilverHmac {
    key: [u8; HASH_SIZE],
}

impl SilverHmac {
    /// Create new HMAC with key
    pub fn new(key: &[u8; HASH_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Create HMAC from arbitrary key (hashes if needed)
    pub fn from_key(key: &[u8]) -> Self {
        let derived_key = if key.len() == HASH_SIZE {
            let mut k = [0u8; HASH_SIZE];
            k.copy_from_slice(key);
            k
        } else {
            SilverHash::hash(key)
        };
        Self { key: derived_key }
    }

    /// Compute MAC for data
    pub fn mac(&self, data: &[u8]) -> [u8; HASH_SIZE] {
        SilverHash::keyed_hash(&self.key, data)
    }

    /// Verify MAC
    pub fn verify(&self, data: &[u8], tag: &[u8; HASH_SIZE]) -> bool {
        SilverHash::verify_keyed(&self.key, data, tag)
    }
}

/// Hash chain for creating linked hashes
pub struct HashChain {
    current: [u8; HASH_SIZE],
    count: u64,
}

impl HashChain {
    /// Create new hash chain with seed
    pub fn new(seed: &[u8]) -> Self {
        Self {
            current: SilverHash::hash(seed),
            count: 0,
        }
    }

    /// Get current hash
    pub fn current(&self) -> &[u8; HASH_SIZE] {
        &self.current
    }

    /// Advance chain and return new hash
    pub fn advance(&mut self) -> [u8; HASH_SIZE] {
        self.current = SilverHash::hash(&self.current);
        self.count += 1;
        self.current
    }

    /// Get chain length
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Verify a hash is in the chain (expensive for long chains)
    pub fn verify_in_chain(&self, target: &[u8; HASH_SIZE], max_steps: u64) -> Option<u64> {
        let mut current = self.current;
        for i in 0..max_steps {
            if &current == target {
                return Some(i);
            }
            current = SilverHash::hash(&current);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"Hello, ADZVPN-Opus!";
        let hash = SilverHash::hash(data);

        assert_eq!(hash.len(), HASH_SIZE);

        // Same input should produce same hash
        let hash2 = SilverHash::hash(data);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = SilverHash::hash(b"Different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_hash_many() {
        let part1 = b"Hello, ";
        let part2 = b"ADZVPN-Opus!";
        let combined = b"Hello, ADZVPN-Opus!";

        let hash_parts = SilverHash::hash_many(&[part1, part2]);
        let hash_combined = SilverHash::hash(combined);

        assert_eq!(hash_parts, hash_combined);
    }

    #[test]
    fn test_keyed_hash() {
        let key = [42u8; HASH_SIZE];
        let data = b"Test data";

        let mac = SilverHash::keyed_hash(&key, data);

        // Different key should produce different MAC
        let key2 = [43u8; HASH_SIZE];
        let mac2 = SilverHash::keyed_hash(&key2, data);
        assert_ne!(mac, mac2);
    }

    #[test]
    fn test_derive_key() {
        let context = "adzvpn-test-context";
        let input = b"input data";

        let key = SilverHash::derive_key(context, input);

        assert_eq!(key.len(), HASH_SIZE);

        // Should be deterministic
        let key2 = SilverHash::derive_key(context, input);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_derive_key_custom() {
        let context = "adzvpn-custom";
        let input = b"input";

        let key_64: [u8; 64] = SilverHash::derive_key_custom(context, input);
        let key_16: [u8; 16] = SilverHash::derive_key_custom(context, input);

        assert_eq!(key_64.len(), 64);
        assert_eq!(key_16.len(), 16);

        // First 16 bytes should match
        assert_eq!(&key_64[0..16], &key_16[..]);
    }

    #[test]
    fn test_verify() {
        let data = b"Test data";
        let hash = SilverHash::hash(data);

        assert!(SilverHash::verify(data, &hash));
        assert!(!SilverHash::verify(b"Wrong data", &hash));
    }

    #[test]
    fn test_streaming_hasher() {
        let mut hasher = StreamingHasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"ADZVPN-Opus!");
        let hash = hasher.finalize();

        let direct_hash = SilverHash::hash(b"Hello, ADZVPN-Opus!");
        assert_eq!(hash, direct_hash);
    }

    #[test]
    fn test_streaming_hasher_peek() {
        let mut hasher = StreamingHasher::new();
        hasher.update(b"Part 1");

        let peek1 = hasher.finalize_peek();

        hasher.update(b"Part 2");
        let peek2 = hasher.finalize_peek();

        // Peek should not consume, so adding more data changes the hash
        assert_ne!(peek1, peek2);
    }

    #[test]
    fn test_silver_hmac() {
        let key = [42u8; HASH_SIZE];
        let hmac = SilverHmac::new(&key);
        let data = b"Message to authenticate";

        let tag = hmac.mac(data);
        assert!(hmac.verify(data, &tag));
        assert!(!hmac.verify(b"Wrong message", &tag));
    }

    #[test]
    fn test_silver_hmac_from_key() {
        let key = b"variable length key";
        let hmac = SilverHmac::from_key(key);

        let tag = hmac.mac(b"data");
        assert!(hmac.verify(b"data", &tag));
    }

    #[test]
    fn test_hash_chain() {
        let mut chain = HashChain::new(b"seed");

        let h0 = *chain.current();
        let h1 = chain.advance();
        let h2 = chain.advance();

        // Each advance should produce different hash
        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_eq!(chain.count(), 2);

        // h1 should be hash of h0
        assert_eq!(h1, SilverHash::hash(&h0));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3])); // Different length
    }

    #[test]
    fn test_hash_empty() {
        let hash = SilverHash::hash(b"");
        assert_eq!(hash.len(), HASH_SIZE);

        // BLAKE3 of empty string is well-defined
        let hash2 = SilverHash::hash(b"");
        assert_eq!(hash, hash2);
    }
}
