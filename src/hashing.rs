//! Cryptographic hashing module v2.0
//!
//! Provides multiple hash algorithms: SHA-256, SHA-3, and BLAKE3.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use sha3::{Sha3_256, Sha3_512};
use thiserror::Error;

/// Hashing errors
#[derive(Error, Debug)]
pub enum HashError {
    #[error("Invalid hash length")]
    InvalidLength,

    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake3,
}

impl HashAlgorithm {
    /// Get output length in bytes
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Sha3_512 => 64,
            HashAlgorithm::Blake3 => 32,
        }
    }

    /// Get algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Sha3_256 => "SHA3-256",
            HashAlgorithm::Sha3_512 => "SHA3-512",
            HashAlgorithm::Blake3 => "BLAKE3",
        }
    }
}

/// Hash output wrapper
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashOutput {
    algorithm: HashAlgorithm,
    bytes: Vec<u8>,
}

impl HashOutput {
    /// Create from raw bytes
    pub fn from_bytes(algorithm: HashAlgorithm, bytes: Vec<u8>) -> Result<Self, HashError> {
        if bytes.len() != algorithm.output_length() {
            return Err(HashError::InvalidLength);
        }
        Ok(Self { algorithm, bytes })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Get algorithm used
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Verify against expected hash (constant-time)
    pub fn verify(&self, expected: &[u8]) -> bool {
        constant_time_eq::constant_time_eq(&self.bytes, expected)
    }

    /// Verify against hex string (constant-time)
    pub fn verify_hex(&self, expected_hex: &str) -> bool {
        if let Ok(expected) = hex::decode(expected_hex) {
            self.verify(&expected)
        } else {
            false
        }
    }
}

impl std::fmt::Debug for HashOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HashOutput({}: {})", self.algorithm.name(), &self.to_hex()[..16])
    }
}

/// Universal hasher supporting multiple algorithms
pub struct Hasher {
    algorithm: HashAlgorithm,
}

impl Hasher {
    /// Create a new hasher with the specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Hash data and return output
    pub fn hash(&self, data: &[u8]) -> HashOutput {
        let bytes = match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(data);
                hash.as_bytes().to_vec()
            }
        };

        HashOutput {
            algorithm: self.algorithm,
            bytes,
        }
    }

    /// Hash string data
    pub fn hash_str(&self, data: &str) -> HashOutput {
        self.hash(data.as_bytes())
    }

    /// Hash and return hex string
    pub fn hash_to_hex(&self, data: &[u8]) -> String {
        self.hash(data).to_hex()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
}

/// Incremental hasher for streaming data
pub struct IncrementalHasher {
    state: IncrementalState,
    algorithm: HashAlgorithm,
}

enum IncrementalState {
    Sha256(Sha256),
    Sha512(Sha512),
    Sha3_256(Sha3_256),
    Sha3_512(Sha3_512),
    Blake3(blake3::Hasher),
}

impl IncrementalHasher {
    /// Create a new incremental hasher
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let state = match algorithm {
            HashAlgorithm::Sha256 => IncrementalState::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => IncrementalState::Sha512(Sha512::new()),
            HashAlgorithm::Sha3_256 => IncrementalState::Sha3_256(Sha3_256::new()),
            HashAlgorithm::Sha3_512 => IncrementalState::Sha3_512(Sha3_512::new()),
            HashAlgorithm::Blake3 => IncrementalState::Blake3(blake3::Hasher::new()),
        };
        Self { state, algorithm }
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            IncrementalState::Sha256(h) => h.update(data),
            IncrementalState::Sha512(h) => h.update(data),
            IncrementalState::Sha3_256(h) => h.update(data),
            IncrementalState::Sha3_512(h) => h.update(data),
            IncrementalState::Blake3(h) => { h.update(data); }
        }
    }

    /// Finalize and return hash output
    pub fn finalize(self) -> HashOutput {
        let bytes = match self.state {
            IncrementalState::Sha256(h) => h.finalize().to_vec(),
            IncrementalState::Sha512(h) => h.finalize().to_vec(),
            IncrementalState::Sha3_256(h) => h.finalize().to_vec(),
            IncrementalState::Sha3_512(h) => h.finalize().to_vec(),
            IncrementalState::Blake3(h) => h.finalize().as_bytes().to_vec(),
        };

        HashOutput {
            algorithm: self.algorithm,
            bytes,
        }
    }
}

/// Convenience functions
pub fn sha256(data: &[u8]) -> HashOutput {
    Hasher::new(HashAlgorithm::Sha256).hash(data)
}

pub fn sha3_256(data: &[u8]) -> HashOutput {
    Hasher::new(HashAlgorithm::Sha3_256).hash(data)
}

pub fn blake3(data: &[u8]) -> HashOutput {
    Hasher::new(HashAlgorithm::Blake3).hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hasher = Hasher::new(HashAlgorithm::Sha256);
        let hash = hasher.hash(b"hello world");
        assert_eq!(hash.as_bytes().len(), 32);
        assert_eq!(hash.algorithm(), HashAlgorithm::Sha256);
    }

    #[test]
    fn test_sha3_256() {
        let hasher = Hasher::new(HashAlgorithm::Sha3_256);
        let hash = hasher.hash(b"hello world");
        assert_eq!(hash.as_bytes().len(), 32);
        assert_eq!(hash.algorithm(), HashAlgorithm::Sha3_256);
    }

    #[test]
    fn test_blake3() {
        let hasher = Hasher::new(HashAlgorithm::Blake3);
        let hash = hasher.hash(b"hello world");
        assert_eq!(hash.as_bytes().len(), 32);
        assert_eq!(hash.algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_different_algorithms_different_output() {
        let data = b"test data";
        let sha256 = Hasher::new(HashAlgorithm::Sha256).hash(data);
        let sha3 = Hasher::new(HashAlgorithm::Sha3_256).hash(data);
        let blake = Hasher::new(HashAlgorithm::Blake3).hash(data);

        assert_ne!(sha256.as_bytes(), sha3.as_bytes());
        assert_ne!(sha256.as_bytes(), blake.as_bytes());
        assert_ne!(sha3.as_bytes(), blake.as_bytes());
    }

    #[test]
    fn test_verify() {
        let hasher = Hasher::new(HashAlgorithm::Sha256);
        let hash = hasher.hash(b"password");

        assert!(hash.verify(hash.as_bytes()));
        assert!(!hash.verify(b"wrong hash"));
    }

    #[test]
    fn test_verify_hex() {
        let hasher = Hasher::new(HashAlgorithm::Sha256);
        let hash = hasher.hash(b"test");
        let hex = hash.to_hex();

        assert!(hash.verify_hex(&hex));
        assert!(!hash.verify_hex("0000"));
    }

    #[test]
    fn test_incremental_hasher() {
        let data = b"hello world";

        // One-shot hash
        let one_shot = Hasher::new(HashAlgorithm::Sha256).hash(data);

        // Incremental hash
        let mut incremental = IncrementalHasher::new(HashAlgorithm::Sha256);
        incremental.update(b"hello ");
        incremental.update(b"world");
        let result = incremental.finalize();

        assert_eq!(one_shot.as_bytes(), result.as_bytes());
    }

    #[test]
    fn test_convenience_functions() {
        let data = b"test";

        let h1 = sha256(data);
        let h2 = sha3_256(data);
        let h3 = blake3(data);

        assert_eq!(h1.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(h2.algorithm(), HashAlgorithm::Sha3_256);
        assert_eq!(h3.algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_hex_conversion() {
        let hash = sha256(b"test");
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }
}
