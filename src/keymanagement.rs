//! Secure key management and storage

use crate::{CryptoError, SecureKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub algorithm: String,
    pub purpose: String,
    pub rotation_count: u32,
}

impl KeyMetadata {
    /// Create new metadata
    pub fn new(key_id: String, algorithm: String, purpose: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            key_id,
            created_at,
            expires_at: None,
            algorithm,
            purpose,
            rotation_count: 0,
        }
    }

    /// Set expiration (seconds from now)
    pub fn with_expiration(mut self, seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.expires_at = Some(now + seconds);
        self
    }

    /// Check if key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now >= expires_at
        } else {
            false
        }
    }

    /// Get age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.created_at)
    }
}

/// In-memory key store with automatic cleanup
pub struct KeyStore {
    keys: HashMap<String, (SecureKey, KeyMetadata)>,
}

impl KeyStore {
    /// Create new key store
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Store a key with metadata
    pub fn store_key(
        &mut self,
        key_id: String,
        key: SecureKey,
        metadata: KeyMetadata,
    ) -> Result<(), CryptoError> {
        if self.keys.contains_key(&key_id) {
            return Err(CryptoError::HashingError(
                "Key ID already exists".to_string(),
            ));
        }
        self.keys.insert(key_id, (key, metadata));
        Ok(())
    }

    /// Retrieve a key (returns clone of metadata but reference to key)
    pub fn get_key(&self, key_id: &str) -> Option<(&SecureKey, KeyMetadata)> {
        self.keys
            .get(key_id)
            .map(|(key, meta)| (key, meta.clone()))
    }

    /// Remove a key
    pub fn remove_key(&mut self, key_id: &str) -> Option<(SecureKey, KeyMetadata)> {
        self.keys.remove(key_id)
    }

    /// List all key IDs
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Clean up expired keys
    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<String> = self
            .keys
            .iter()
            .filter(|(_, (_, meta))| meta.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for key_id in expired {
            self.keys.remove(&key_id);
        }
        count
    }

    /// Get count of stored keys
    pub fn count(&self) -> usize {
        self.keys.len()
    }

    /// Rotate a key (generate new key, increment rotation counter)
    pub fn rotate_key(&mut self, key_id: &str) -> Result<(), CryptoError> {
        if let Some((_, meta)) = self.keys.get_mut(key_id) {
            let new_key = SecureKey::generate();
            meta.rotation_count += 1;
            meta.created_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.keys.insert(key_id.to_string(), (new_key, meta.clone()));
            Ok(())
        } else {
            Err(CryptoError::HashingError("Key not found".to_string()))
        }
    }

    /// Find keys by purpose
    pub fn find_by_purpose(&self, purpose: &str) -> Vec<(String, KeyMetadata)> {
        self.keys
            .iter()
            .filter(|(_, (_, meta))| meta.purpose == purpose)
            .map(|(id, (_, meta))| (id.clone(), meta.clone()))
            .collect()
    }

    /// Get keys requiring rotation (older than specified age in seconds)
    pub fn keys_requiring_rotation(&self, max_age_seconds: u64) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(_, (_, meta))| meta.age_seconds() > max_age_seconds)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Key rotation policy
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Maximum key age in seconds before rotation required
    pub max_age_seconds: u64,
    /// Automatically rotate keys when max age is reached
    pub auto_rotate: bool,
}

impl RotationPolicy {
    /// Create policy with 90-day rotation
    pub fn ninety_days() -> Self {
        Self {
            max_age_seconds: 90 * 24 * 60 * 60,
            auto_rotate: false,
        }
    }

    /// Create policy with 30-day rotation
    pub fn thirty_days() -> Self {
        Self {
            max_age_seconds: 30 * 24 * 60 * 60,
            auto_rotate: false,
        }
    }

    /// Create policy with custom days
    pub fn custom_days(days: u64) -> Self {
        Self {
            max_age_seconds: days * 24 * 60 * 60,
            auto_rotate: false,
        }
    }

    /// Enable auto-rotation
    pub fn with_auto_rotate(mut self) -> Self {
        self.auto_rotate = true;
        self
    }

    /// Check if key needs rotation
    pub fn needs_rotation(&self, metadata: &KeyMetadata) -> bool {
        metadata.age_seconds() > self.max_age_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_metadata_creation() {
        let meta = KeyMetadata::new(
            "key-001".to_string(),
            "AES-256-GCM".to_string(),
            "encryption".to_string(),
        );

        assert_eq!(meta.key_id, "key-001");
        assert_eq!(meta.algorithm, "AES-256-GCM");
        assert_eq!(meta.rotation_count, 0);
        assert!(!meta.is_expired());
    }

    #[test]
    fn test_key_metadata_expiration() {
        let meta = KeyMetadata::new(
            "key-002".to_string(),
            "AES-256-GCM".to_string(),
            "encryption".to_string(),
        )
        .with_expiration(1); // Expires in 1 second

        assert!(!meta.is_expired());
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(meta.is_expired());
    }

    #[test]
    fn test_key_store_operations() {
        let mut store = KeyStore::new();
        let key = SecureKey::generate();
        let meta = KeyMetadata::new(
            "test-key".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        );

        // Store key
        assert!(store.store_key("test-key".to_string(), key, meta).is_ok());
        assert_eq!(store.count(), 1);

        // Retrieve key
        assert!(store.get_key("test-key").is_some());

        // List keys
        let keys = store.list_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"test-key".to_string()));
    }

    #[test]
    fn test_key_store_duplicate_prevention() {
        let mut store = KeyStore::new();
        let key1 = SecureKey::generate();
        let key2 = SecureKey::generate();
        let meta = KeyMetadata::new(
            "dup-key".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        );

        assert!(store
            .store_key("dup-key".to_string(), key1, meta.clone())
            .is_ok());
        assert!(store.store_key("dup-key".to_string(), key2, meta).is_err());
    }

    #[test]
    fn test_key_cleanup() {
        let mut store = KeyStore::new();

        // Add expired key
        let meta_expired = KeyMetadata::new(
            "expired".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        )
        .with_expiration(1);
        store
            .store_key(
                "expired".to_string(),
                SecureKey::generate(),
                meta_expired,
            )
            .unwrap();

        // Add non-expired key
        let meta_valid = KeyMetadata::new(
            "valid".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        )
        .with_expiration(3600);
        store
            .store_key("valid".to_string(), SecureKey::generate(), meta_valid)
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(2));

        let removed = store.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(store.count(), 1);
        assert!(store.get_key("valid").is_some());
        assert!(store.get_key("expired").is_none());
    }

    #[test]
    fn test_key_rotation() {
        let mut store = KeyStore::new();
        let key = SecureKey::generate();
        let meta = KeyMetadata::new(
            "rotate-key".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        );

        store
            .store_key("rotate-key".to_string(), key, meta)
            .unwrap();

        // Rotate
        assert!(store.rotate_key("rotate-key").is_ok());

        // Check rotation count increased
        let (_, meta) = store.get_key("rotate-key").unwrap();
        assert_eq!(meta.rotation_count, 1);
    }

    #[test]
    fn test_find_by_purpose() {
        let mut store = KeyStore::new();

        let meta1 = KeyMetadata::new(
            "enc-1".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        );
        let meta2 = KeyMetadata::new(
            "sig-1".to_string(),
            "HMAC".to_string(),
            "signing".to_string(),
        );
        let meta3 = KeyMetadata::new(
            "enc-2".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        );

        store
            .store_key("enc-1".to_string(), SecureKey::generate(), meta1)
            .unwrap();
        store
            .store_key("sig-1".to_string(), SecureKey::generate(), meta2)
            .unwrap();
        store
            .store_key("enc-2".to_string(), SecureKey::generate(), meta3)
            .unwrap();

        let encryption_keys = store.find_by_purpose("encryption");
        assert_eq!(encryption_keys.len(), 2);

        let signing_keys = store.find_by_purpose("signing");
        assert_eq!(signing_keys.len(), 1);
    }

    #[test]
    fn test_rotation_policy() {
        let policy = RotationPolicy::ninety_days();
        assert_eq!(policy.max_age_seconds, 90 * 24 * 60 * 60);

        let meta = KeyMetadata::new(
            "key".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        );
        assert!(!policy.needs_rotation(&meta));
    }

    #[test]
    fn test_keys_requiring_rotation() {
        let mut store = KeyStore::new();

        let meta = KeyMetadata::new(
            "old-key".to_string(),
            "AES-256".to_string(),
            "encryption".to_string(),
        );
        store
            .store_key("old-key".to_string(), SecureKey::generate(), meta)
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(2));

        let keys = store.keys_requiring_rotation(1); // Keys older than 1 second
        assert_eq!(keys.len(), 1);
    }
}
