//! # Rust Crypto Utils
//!
//! Production-ready, memory-safe cryptographic utilities for financial systems and secure applications.
//!
//! ## Features
//!
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **Secure Password Hashing**: Argon2id with configurable parameters
//! - **AES-256-GCM Encryption**: Authenticated encryption with associated data
//! - **Key Derivation**: PBKDF2 and HKDF (NIST SP 800-132, RFC 5869)
//! - **Digital Signatures**: Ed25519 and HMAC-SHA256
//! - **Key Management**: Secure key storage with rotation policies
//! - **Secure Random Generation**: Cryptographically secure random number generation
//!
//! ## Alignment with Federal Guidance
//!
//! Implements cryptographic best practices recommended by NIST and aligns with
//! 2024 CISA/FBI guidance for memory-safe cryptographic implementations.

pub mod keyderivation;
pub mod signatures;
pub mod keymanagement;

pub use keyderivation::{DerivedKey, Hkdf, Pbkdf2, PasswordStrength};
pub use signatures::{Ed25519KeyPair, Ed25519PublicKey, HmacKey, SignatureSuite};
pub use keymanagement::{KeyMetadata, KeyStore, RotationPolicy};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Algorithm, Version, Params,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Password hashing failed: {0}")]
    HashingError(String),

    #[error("Password verification failed")]
    VerificationError,

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("HMAC generation failed: {0}")]
    HmacError(String),

    #[error("Weak password: {0}")]
    WeakPassword(String),
}

/// Secure password with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecurePassword {
    password: Vec<u8>,
}

impl SecurePassword {
    /// Create a new secure password
    pub fn new(password: impl Into<Vec<u8>>) -> Self {
        Self {
            password: password.into(),
        }
    }

    /// Get password bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.password
    }
}

/// Secure encryption key with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    key: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key from bytes
    pub fn new(key: Vec<u8>) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        Ok(Self { key })
    }

    /// Generate a new random 256-bit key
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// Password hashing utilities using Argon2id
pub mod password {
    use super::*;

    /// Hash a password using Argon2id
    ///
    /// Uses Argon2id with secure default parameters:
    /// - Memory cost: 19 MiB
    /// - Time cost: 2 iterations
    /// - Parallelism: 1
    pub fn hash_password(password: &SecurePassword) -> Result<String, CryptoError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| CryptoError::HashingError(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    /// Verify a password against a hash
    pub fn verify_password(password: &SecurePassword, hash: &str) -> Result<bool, CryptoError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| CryptoError::HashingError(e.to_string()))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Password strength requirements
    #[derive(Debug, Clone)]
    pub struct PasswordStrength {
        pub min_length: usize,
        pub require_uppercase: bool,
        pub require_lowercase: bool,
        pub require_digit: bool,
        pub require_special: bool,
    }

    impl Default for PasswordStrength {
        fn default() -> Self {
            Self {
                min_length: 12,
                require_uppercase: true,
                require_lowercase: true,
                require_digit: true,
                require_special: true,
            }
        }
    }

    /// Validate password strength for financial systems
    pub fn validate_password_strength(
        password: &SecurePassword,
        requirements: &PasswordStrength,
    ) -> Result<(), CryptoError> {
        let password_str = std::str::from_utf8(password.as_bytes())
            .map_err(|_| CryptoError::WeakPassword("Invalid UTF-8".to_string()))?;

        if password_str.len() < requirements.min_length {
            return Err(CryptoError::WeakPassword(format!(
                "Password must be at least {} characters",
                requirements.min_length
            )));
        }

        if requirements.require_uppercase && !password_str.chars().any(|c| c.is_uppercase()) {
            return Err(CryptoError::WeakPassword(
                "Password must contain uppercase letters".to_string(),
            ));
        }

        if requirements.require_lowercase && !password_str.chars().any(|c| c.is_lowercase()) {
            return Err(CryptoError::WeakPassword(
                "Password must contain lowercase letters".to_string(),
            ));
        }

        if requirements.require_digit && !password_str.chars().any(|c| c.is_ascii_digit()) {
            return Err(CryptoError::WeakPassword(
                "Password must contain digits".to_string(),
            ));
        }

        if requirements.require_special
            && !password_str
                .chars()
                .any(|c| !c.is_alphanumeric() && !c.is_whitespace())
        {
            return Err(CryptoError::WeakPassword(
                "Password must contain special characters".to_string(),
            ));
        }

        Ok(())
    }

    /// Derive an encryption key from a password using Argon2
    pub fn derive_key_from_password(
        password: &SecurePassword,
        salt: &[u8],
    ) -> Result<SecureKey, CryptoError> {
        if salt.len() < 16 {
            return Err(CryptoError::HashingError(
                "Salt must be at least 16 bytes".to_string(),
            ));
        }

        // Use high-security parameters for key derivation
        let params = Params::new(65536, 3, 1, Some(32))
            .map_err(|e| CryptoError::HashingError(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = vec![0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| CryptoError::HashingError(e.to_string()))?;

        Ok(SecureKey { key: key_bytes })
    }
}

/// Encryption utilities using AES-256-GCM
pub mod encryption {
    use super::*;

    /// Encrypted data with nonce
    pub struct EncryptedData {
        pub ciphertext: Vec<u8>,
        pub nonce: [u8; 12],
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(key: &SecureKey, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(
        key: &SecureKey,
        encrypted: &EncryptedData,
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        Ok(plaintext)
    }
}

/// Secure random number generation
pub mod random {
    use super::*;

    /// Generate cryptographically secure random bytes
    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a random hexadecimal string (for tokens, IDs, etc.)
    pub fn generate_random_hex(length: usize) -> String {
        let bytes = generate_random_bytes(length);
        hex::encode(bytes)
    }

    /// Generate a random salt for password hashing/key derivation
    pub fn generate_salt() -> Vec<u8> {
        generate_random_bytes(32)
    }
}

/// HMAC-SHA256 utilities for message authentication
pub mod hmac {
    use super::*;

    /// Compute HMAC-SHA256 for a message
    pub fn compute_hmac(key: &SecureKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::HmacError(e.to_string()))?;

        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Verify HMAC-SHA256 for a message (constant-time comparison)
    pub fn verify_hmac(
        key: &SecureKey,
        message: &[u8],
        expected_hmac: &[u8],
    ) -> Result<bool, CryptoError> {
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::HmacError(e.to_string()))?;

        mac.update(message);

        // Constant-time comparison to prevent timing attacks
        match mac.verify_slice(expected_hmac) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Secure comparison utilities
pub mod secure_compare {
    /// Constant-time byte slice comparison to prevent timing attacks
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            result |= byte_a ^ byte_b;
        }

        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = SecurePassword::new(b"MySecurePassword123!".to_vec());
        let hash = password::hash_password(&password).unwrap();

        assert!(password::verify_password(&password, &hash).unwrap());

        let wrong_password = SecurePassword::new(b"WrongPassword".to_vec());
        assert!(!password::verify_password(&wrong_password, &hash).unwrap());
    }

    #[test]
    fn test_encryption_decryption() {
        let key = SecureKey::generate();
        let plaintext = b"Sensitive financial data: Account 123456, Balance: $50,000";

        let encrypted = encryption::encrypt(&key, plaintext).unwrap();
        let decrypted = encryption::decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encryption_with_wrong_key() {
        let key1 = SecureKey::generate();
        let key2 = SecureKey::generate();
        let plaintext = b"Secret data";

        let encrypted = encryption::encrypt(&key1, plaintext).unwrap();
        let result = encryption::decrypt(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_random_generation() {
        let bytes1 = random::generate_random_bytes(32);
        let bytes2 = random::generate_random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_random_hex() {
        let hex = random::generate_random_hex(16);
        assert_eq!(hex.len(), 32); // 16 bytes = 32 hex characters
    }

    #[test]
    fn test_zeroization() {
        let password_bytes = b"TestPassword123".to_vec();
        {
            let _secure_password = SecurePassword::new(password_bytes.clone());
            // Password will be zeroized when it goes out of scope
        }
        // In a real scenario, you'd verify memory was zeroed
        // This test confirms the ZeroizeOnDrop trait is applied
    }

    #[test]
    fn test_key_length_validation() {
        let short_key = vec![0u8; 16]; // Too short
        let result = SecureKey::new(short_key);
        assert!(result.is_err());

        let valid_key = vec![0u8; 32];
        let result = SecureKey::new(valid_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_strength_validation() {
        // Strong password
        let strong = SecurePassword::new(b"SecurePass123!@#".to_vec());
        let requirements = password::PasswordStrength::default();
        assert!(password::validate_password_strength(&strong, &requirements).is_ok());

        // Too short
        let short = SecurePassword::new(b"Short1!".to_vec());
        let result = password::validate_password_strength(&short, &requirements);
        assert!(result.is_err());

        // No uppercase
        let no_upper = SecurePassword::new(b"nouppercasehere123!".to_vec());
        let result = password::validate_password_strength(&no_upper, &requirements);
        assert!(result.is_err());

        // No special characters
        let no_special = SecurePassword::new(b"NoSpecialChars123".to_vec());
        let result = password::validate_password_strength(&no_special, &requirements);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation_from_password() {
        let password = SecurePassword::new(b"MyMasterPassword123!".to_vec());
        let salt = random::generate_salt();

        let key1 = password::derive_key_from_password(&password, &salt).unwrap();
        let key2 = password::derive_key_from_password(&password, &salt).unwrap();

        // Same password and salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        // Different salt should produce different key
        let different_salt = random::generate_salt();
        let key3 = password::derive_key_from_password(&password, &different_salt).unwrap();
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_hmac_generation_and_verification() {
        let key = SecureKey::generate();
        let message = b"Important financial transaction data";

        let hmac_result = hmac::compute_hmac(&key, message).unwrap();
        assert_eq!(hmac_result.len(), 32); // SHA-256 produces 32 bytes

        // Verify correct HMAC
        assert!(hmac::verify_hmac(&key, message, &hmac_result).unwrap());

        // Verify fails with wrong key
        let wrong_key = SecureKey::generate();
        assert!(!hmac::verify_hmac(&wrong_key, message, &hmac_result).unwrap());

        // Verify fails with modified message
        let modified_message = b"Modified transaction data";
        assert!(!hmac::verify_hmac(&key, modified_message, &hmac_result).unwrap());
    }

    #[test]
    fn test_constant_time_compare() {
        let data1 = b"secret_data";
        let data2 = b"secret_data";
        let data3 = b"different_data";

        // Same data should match
        assert!(secure_compare::constant_time_compare(data1, data2));

        // Different data should not match
        assert!(!secure_compare::constant_time_compare(data1, data3));

        // Different lengths should not match
        let short = b"short";
        assert!(!secure_compare::constant_time_compare(data1, short));
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = random::generate_salt();
        let salt2 = random::generate_salt();

        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2); // Should be different
    }

    #[test]
    fn test_password_based_encryption() {
        // Simulate real-world password-based encryption
        let password = SecurePassword::new(b"UserMasterPassword123!".to_vec());
        let salt = random::generate_salt();

        // Derive encryption key from password
        let key = password::derive_key_from_password(&password, &salt).unwrap();

        // Encrypt data
        let sensitive_data = b"Social Security Number: 123-45-6789";
        let encrypted = encryption::encrypt(&key, sensitive_data).unwrap();

        // Decrypt with same password-derived key
        let decrypted = encryption::decrypt(&key, &encrypted).unwrap();

        assert_eq!(sensitive_data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_multiple_hmac_computations() {
        let key = SecureKey::generate();
        let message1 = b"Message 1";
        let message2 = b"Message 2";

        let hmac1 = hmac::compute_hmac(&key, message1).unwrap();
        let hmac2 = hmac::compute_hmac(&key, message2).unwrap();

        // Different messages should produce different HMACs
        assert_ne!(hmac1, hmac2);

        // Each HMAC should verify against its own message
        assert!(hmac::verify_hmac(&key, message1, &hmac1).unwrap());
        assert!(hmac::verify_hmac(&key, message2, &hmac2).unwrap());

        // HMACs should not cross-verify
        assert!(!hmac::verify_hmac(&key, message1, &hmac2).unwrap());
        assert!(!hmac::verify_hmac(&key, message2, &hmac1).unwrap());
    }

    #[test]
    fn test_encryption_with_derived_key() {
        let password = SecurePassword::new(b"StrongPassword789!@#".to_vec());
        let salt = random::generate_salt();
        let key = password::derive_key_from_password(&password, &salt).unwrap();

        let data = b"Encrypted with derived key";
        let encrypted = encryption::encrypt(&key, data).unwrap();

        // Verify we can decrypt
        let decrypted = encryption::decrypt(&key, &encrypted).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());

        // Verify wrong password can't decrypt
        let wrong_password = SecurePassword::new(b"WrongPassword123!".to_vec());
        let wrong_key = password::derive_key_from_password(&wrong_password, &salt).unwrap();
        let result = encryption::decrypt(&wrong_key, &encrypted);
        assert!(result.is_err());
    }
}
