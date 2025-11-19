//! Key derivation functions (PBKDF2, HKDF)

use hmac::Hmac;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Derived key with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    key: Vec<u8>,
}

impl DerivedKey {
    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { key: bytes }
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get key length
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }
}

/// PBKDF2 key derivation (NIST SP 800-132)
pub struct Pbkdf2;

impl Pbkdf2 {
    /// Derive key using PBKDF2-HMAC-SHA256
    ///
    /// # Arguments
    /// * `password` - Password bytes
    /// * `salt` - Salt (should be at least 16 bytes)
    /// * `iterations` - Number of iterations (NIST recommends at least 10,000)
    /// * `key_length` - Desired key length in bytes
    pub fn derive_key_sha256(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> DerivedKey {
        let mut derived = vec![0u8; key_length];
        pbkdf2::pbkdf2::<HmacSha256>(password, salt, iterations, &mut derived)
            .expect("PBKDF2 derivation failed");
        DerivedKey::from_bytes(derived)
    }

    /// Derive key using PBKDF2-HMAC-SHA512
    pub fn derive_key_sha512(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> DerivedKey {
        let mut derived = vec![0u8; key_length];
        pbkdf2::pbkdf2::<HmacSha512>(password, salt, iterations, &mut derived)
            .expect("PBKDF2 derivation failed");
        DerivedKey::from_bytes(derived)
    }
}

/// HKDF key derivation (RFC 5869)
pub struct Hkdf;

impl Hkdf {
    /// Extract-and-Expand key derivation using HMAC-SHA256
    ///
    /// # Arguments
    /// * `input_key_material` - Input keying material
    /// * `salt` - Optional salt (use empty slice if none)
    /// * `info` - Optional context/application info
    /// * `output_length` - Desired output length in bytes
    pub fn derive_key(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> DerivedKey {
        use hkdf::Hkdf as HkdfImpl;

        let hk = HkdfImpl::<Sha256>::new(Some(salt), input_key_material);
        let mut okm = vec![0u8; output_length];
        hk.expand(info, &mut okm).expect("HKDF expand failed");

        DerivedKey::from_bytes(okm)
    }

    /// Derive multiple keys from a single input
    pub fn derive_multiple_keys(
        input_key_material: &[u8],
        salt: &[u8],
        contexts: &[&[u8]],
        key_length: usize,
    ) -> Vec<DerivedKey> {
        contexts
            .iter()
            .map(|context| Self::derive_key(input_key_material, salt, context, key_length))
            .collect()
    }
}

/// Secure password strength validator
pub struct PasswordStrength;

impl PasswordStrength {
    /// Check password strength
    /// Returns (score, feedback) where score is 0-4
    pub fn check(password: &str) -> (u8, Vec<String>) {
        let mut score = 0u8;
        let mut feedback = Vec::new();

        // Length check
        if password.len() >= 12 {
            score += 1;
        } else {
            feedback.push("Password should be at least 12 characters".to_string());
        }

        // Uppercase check
        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        } else {
            feedback.push("Add uppercase letters".to_string());
        }

        // Lowercase check
        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        } else {
            feedback.push("Add lowercase letters".to_string());
        }

        // Digit check
        if password.chars().any(|c| c.is_numeric()) {
            score += 1;
        } else {
            feedback.push("Add numbers".to_string());
        }

        // Special character check
        if password.chars().any(|c| !c.is_alphanumeric()) {
            score += 1;
        } else {
            feedback.push("Add special characters".to_string());
        }

        // Common password check (basic)
        let common_passwords = [
            "password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "dragon",
            "master", "sunshine", "princess", "football",
        ];
        if common_passwords
            .iter()
            .any(|&common| password.to_lowercase().contains(common))
        {
            score = score.saturating_sub(2);
            feedback.push("Avoid common passwords".to_string());
        }

        // Sequential characters check
        if Self::has_sequential_chars(password) {
            score = score.saturating_sub(1);
            feedback.push("Avoid sequential characters (abc, 123, etc.)".to_string());
        }

        (score.min(4), feedback)
    }

    fn has_sequential_chars(password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();
        for window in chars.windows(3) {
            if window.len() == 3 {
                let a = window[0] as i32;
                let b = window[1] as i32;
                let c = window[2] as i32;
                if (b == a + 1 && c == b + 1) || (b == a - 1 && c == b - 1) {
                    return true;
                }
            }
        }
        false
    }

    /// Get strength description
    pub fn strength_description(score: u8) -> &'static str {
        match score {
            0 => "Very Weak",
            1 => "Weak",
            2 => "Fair",
            3 => "Strong",
            4 | 5 => "Very Strong",
            _ => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_derivation() {
        let password = b"my_secure_password";
        let salt = b"random_salt_12345";
        let iterations = 10000;
        let key_length = 32;

        let key = Pbkdf2::derive_key_sha256(password, salt, iterations, key_length);
        assert_eq!(key.len(), key_length);
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let password = b"test_password";
        let salt = b"test_salt";
        let iterations = 1000;

        let key1 = Pbkdf2::derive_key_sha256(password, salt, iterations, 32);
        let key2 = Pbkdf2::derive_key_sha256(password, salt, iterations, 32);

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_hkdf_derivation() {
        let ikm = b"input_key_material";
        let salt = b"salt";
        let info = b"application_context";
        let key_length = 32;

        let key = Hkdf::derive_key(ikm, salt, info, key_length);
        assert_eq!(key.len(), key_length);
    }

    #[test]
    fn test_hkdf_multiple_keys() {
        let ikm = b"shared_secret";
        let salt = b"salt";
        let contexts = vec![b"encryption".as_slice(), b"authentication".as_slice()];

        let keys = Hkdf::derive_multiple_keys(ikm, salt, &contexts, 32);
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0].as_bytes(), keys[1].as_bytes());
    }

    #[test]
    fn test_password_strength_weak() {
        let (score, _feedback) = PasswordStrength::check("pass");
        assert!(score <= 2);
    }

    #[test]
    fn test_password_strength_strong() {
        let (score, feedback) = PasswordStrength::check("MyStr0ng!P@ssw0rd2024");
        assert_eq!(score, 4); // Maximum score is 4 per implementation
        assert!(feedback.is_empty());
    }

    #[test]
    fn test_password_strength_common() {
        let (score, feedback) = PasswordStrength::check("password123");
        assert!(score < 3);
        assert!(feedback.iter().any(|f| f.contains("common")));
    }

    #[test]
    fn test_password_strength_sequential() {
        let (_score, feedback) = PasswordStrength::check("abc123xyz");
        assert!(feedback.iter().any(|f| f.contains("sequential")));
    }

    #[test]
    fn test_strength_descriptions() {
        assert_eq!(PasswordStrength::strength_description(0), "Very Weak");
        assert_eq!(PasswordStrength::strength_description(2), "Fair");
        assert_eq!(PasswordStrength::strength_description(4), "Very Strong");
    }

    #[test]
    fn test_derived_key_zeroization() {
        let password = b"test";
        let salt = b"salt";
        {
            let _key = Pbkdf2::derive_key_sha256(password, salt, 1000, 32);
            // Key should be zeroized when dropped
        }
        // If we could inspect memory, it would be zeroed
    }
}
