//! Key wrapping module for secure key storage v2.0
//!
//! Provides AES key wrapping (RFC 3394) for secure key hierarchies.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key wrapping errors
#[derive(Error, Debug)]
pub enum KeyWrapError {
    #[error("Wrapping failed: {0}")]
    WrapFailed(String),

    #[error("Unwrapping failed: {0}")]
    UnwrapFailed(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid wrapped key format")]
    InvalidFormat,
}

/// Key Encryption Key (KEK) for wrapping/unwrapping
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey {
    key: Vec<u8>,
}

impl KeyEncryptionKey {
    /// Generate a new random KEK
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create from existing bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyWrapError> {
        if bytes.len() != 32 {
            return Err(KeyWrapError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            key: bytes.to_vec(),
        })
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// Wrapped key structure
#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_id: String,
    pub algorithm: String,
    pub wrapped_at: chrono::DateTime<chrono::Utc>,
}

impl WrappedKey {
    /// Get wrapped key as hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.ciphertext)
    }

    /// Get nonce as hex
    pub fn nonce_hex(&self) -> String {
        hex::encode(self.nonce)
    }

    /// Export as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Key wrapper using AES-256-GCM
pub struct KeyWrapper {
    cipher: Aes256Gcm,
}

impl KeyWrapper {
    /// Create a new key wrapper with the given KEK
    pub fn new(kek: &KeyEncryptionKey) -> Result<Self, KeyWrapError> {
        let cipher = Aes256Gcm::new_from_slice(kek.as_bytes())
            .map_err(|e| KeyWrapError::WrapFailed(e.to_string()))?;
        Ok(Self { cipher })
    }

    /// Wrap a key
    pub fn wrap(&self, key: &[u8], key_id: &str) -> Result<WrappedKey, KeyWrapError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, key)
            .map_err(|e| KeyWrapError::WrapFailed(e.to_string()))?;

        Ok(WrappedKey {
            ciphertext,
            nonce: nonce_bytes,
            key_id: key_id.to_string(),
            algorithm: "AES-256-GCM".to_string(),
            wrapped_at: chrono::Utc::now(),
        })
    }

    /// Unwrap a key
    pub fn unwrap(&self, wrapped: &WrappedKey) -> Result<Vec<u8>, KeyWrapError> {
        let nonce = Nonce::from_slice(&wrapped.nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, wrapped.ciphertext.as_ref())
            .map_err(|e| KeyWrapError::UnwrapFailed(e.to_string()))?;

        Ok(plaintext)
    }

    /// Rewrap a key with a new KEK
    pub fn rewrap(
        &self,
        wrapped: &WrappedKey,
        new_wrapper: &KeyWrapper,
    ) -> Result<WrappedKey, KeyWrapError> {
        let key = self.unwrap(wrapped)?;
        new_wrapper.wrap(&key, &wrapped.key_id)
    }
}

/// Key hierarchy manager for multi-level key wrapping
pub struct KeyHierarchy {
    master_wrapper: KeyWrapper,
    level_keys: Vec<KeyEncryptionKey>,
}

impl KeyHierarchy {
    /// Create a new key hierarchy with a master KEK
    pub fn new(master_kek: KeyEncryptionKey) -> Result<Self, KeyWrapError> {
        let master_wrapper = KeyWrapper::new(&master_kek)?;
        Ok(Self {
            master_wrapper,
            level_keys: Vec::new(),
        })
    }

    /// Add a new level to the hierarchy
    pub fn add_level(&mut self) -> Result<WrappedKey, KeyWrapError> {
        let level_kek = KeyEncryptionKey::generate();
        let level_id = format!("level-{}", self.level_keys.len());
        let wrapped = self.master_wrapper.wrap(level_kek.as_bytes(), &level_id)?;
        self.level_keys.push(level_kek);
        Ok(wrapped)
    }

    /// Get wrapper for a specific level
    pub fn get_level_wrapper(&self, level: usize) -> Result<KeyWrapper, KeyWrapError> {
        let kek = self
            .level_keys
            .get(level)
            .ok_or(KeyWrapError::InvalidFormat)?;
        KeyWrapper::new(kek)
    }

    /// Wrap a data key at a specific level
    pub fn wrap_data_key(
        &self,
        key: &[u8],
        level: usize,
        key_id: &str,
    ) -> Result<WrappedKey, KeyWrapError> {
        let wrapper = self.get_level_wrapper(level)?;
        wrapper.wrap(key, key_id)
    }

    /// Unwrap a data key at a specific level
    pub fn unwrap_data_key(
        &self,
        wrapped: &WrappedKey,
        level: usize,
    ) -> Result<Vec<u8>, KeyWrapError> {
        let wrapper = self.get_level_wrapper(level)?;
        wrapper.unwrap(wrapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap() {
        let kek = KeyEncryptionKey::generate();
        let wrapper = KeyWrapper::new(&kek).unwrap();

        let data_key = vec![0u8; 32]; // 256-bit key
        let wrapped = wrapper.wrap(&data_key, "key-001").unwrap();
        let unwrapped = wrapper.unwrap(&wrapped).unwrap();

        assert_eq!(data_key, unwrapped);
    }

    #[test]
    fn test_wrapped_key_metadata() {
        let kek = KeyEncryptionKey::generate();
        let wrapper = KeyWrapper::new(&kek).unwrap();

        let data_key = vec![0u8; 32];
        let wrapped = wrapper.wrap(&data_key, "my-key").unwrap();

        assert_eq!(wrapped.key_id, "my-key");
        assert_eq!(wrapped.algorithm, "AES-256-GCM");
    }

    #[test]
    fn test_wrong_kek_fails() {
        let kek1 = KeyEncryptionKey::generate();
        let kek2 = KeyEncryptionKey::generate();

        let wrapper1 = KeyWrapper::new(&kek1).unwrap();
        let wrapper2 = KeyWrapper::new(&kek2).unwrap();

        let data_key = vec![0u8; 32];
        let wrapped = wrapper1.wrap(&data_key, "key-001").unwrap();
        let result = wrapper2.unwrap(&wrapped);

        assert!(result.is_err());
    }

    #[test]
    fn test_rewrap() {
        let kek1 = KeyEncryptionKey::generate();
        let kek2 = KeyEncryptionKey::generate();

        let wrapper1 = KeyWrapper::new(&kek1).unwrap();
        let wrapper2 = KeyWrapper::new(&kek2).unwrap();

        let data_key = vec![0u8; 32];
        let wrapped1 = wrapper1.wrap(&data_key, "key-001").unwrap();
        let wrapped2 = wrapper1.rewrap(&wrapped1, &wrapper2).unwrap();

        let unwrapped = wrapper2.unwrap(&wrapped2).unwrap();
        assert_eq!(data_key, unwrapped);
    }

    #[test]
    fn test_key_hierarchy() {
        let master_kek = KeyEncryptionKey::generate();
        let mut hierarchy = KeyHierarchy::new(master_kek).unwrap();

        // Add two levels
        hierarchy.add_level().unwrap();
        hierarchy.add_level().unwrap();

        // Wrap a data key at level 0
        let data_key = vec![42u8; 32];
        let wrapped = hierarchy
            .wrap_data_key(&data_key, 0, "data-key-001")
            .unwrap();

        // Unwrap it
        let unwrapped = hierarchy.unwrap_data_key(&wrapped, 0).unwrap();
        assert_eq!(data_key, unwrapped);
    }

    #[test]
    fn test_wrapped_key_json() {
        let kek = KeyEncryptionKey::generate();
        let wrapper = KeyWrapper::new(&kek).unwrap();

        let wrapped = wrapper.wrap(&[0u8; 32], "test-key").unwrap();
        let json = wrapped.to_json().unwrap();

        assert!(json.contains("test-key"));
        assert!(json.contains("AES-256-GCM"));
    }

    #[test]
    fn test_invalid_kek_length() {
        let result = KeyEncryptionKey::from_bytes(&[0u8; 16]); // Too short
        assert!(result.is_err());
    }
}
