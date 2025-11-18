//! Digital signatures using Ed25519 and HMAC

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Ed25519 signing key pair
#[derive(ZeroizeOnDrop)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        Self { signing_key }
    }

    /// Create from seed bytes (32 bytes)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Get public key
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Export signing key bytes (use with extreme caution)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Ed25519 public key for verification
#[derive(Clone)]
pub struct Ed25519PublicKey {
    verifying_key: VerifyingKey,
}

impl Ed25519PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, String> {
        VerifyingKey::from_bytes(bytes)
            .map(|verifying_key| Self { verifying_key })
            .map_err(|e| format!("Invalid public key: {}", e))
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        if signature.len() != 64 {
            return Err("Invalid signature length".to_string());
        }

        let sig_array: [u8; 64] = signature
            .try_into()
            .map_err(|_| "Failed to convert signature")?;
        let signature = Signature::from_bytes(&sig_array);

        self.verifying_key
            .verify(message, &signature)
            .map_err(|e| format!("Verification failed: {}", e))
    }

    /// Export public key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// HMAC-based message authentication
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HmacKey {
    key: Vec<u8>,
}

impl HmacKey {
    /// Create HMAC key from bytes
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Generate random HMAC key (32 bytes)
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        Self { key }
    }

    /// Generate HMAC tag for message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC key length error");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify HMAC tag
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> Result<(), String> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|e| format!("HMAC error: {}", e))?;
        mac.update(message);
        mac.verify_slice(tag)
            .map_err(|_| "HMAC verification failed".to_string())
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// Digital signature suite for multi-purpose signing
pub struct SignatureSuite {
    ed25519_keypair: Option<Ed25519KeyPair>,
    hmac_key: Option<HmacKey>,
}

impl SignatureSuite {
    /// Create new suite with Ed25519
    pub fn new_ed25519() -> Self {
        Self {
            ed25519_keypair: Some(Ed25519KeyPair::generate()),
            hmac_key: None,
        }
    }

    /// Create new suite with HMAC
    pub fn new_hmac() -> Self {
        Self {
            ed25519_keypair: None,
            hmac_key: Some(HmacKey::generate()),
        }
    }

    /// Create suite with both Ed25519 and HMAC
    pub fn new_combined() -> Self {
        Self {
            ed25519_keypair: Some(Ed25519KeyPair::generate()),
            hmac_key: Some(HmacKey::generate()),
        }
    }

    /// Sign with Ed25519 (returns None if not configured)
    pub fn sign_ed25519(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.ed25519_keypair.as_ref().map(|kp| kp.sign(message))
    }

    /// Sign with HMAC (returns None if not configured)
    pub fn sign_hmac(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.hmac_key.as_ref().map(|key| key.sign(message))
    }

    /// Get Ed25519 public key
    pub fn ed25519_public_key(&self) -> Option<Ed25519PublicKey> {
        self.ed25519_keypair.as_ref().map(|kp| kp.public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Test message for signing";

        let signature = keypair.sign(message);
        assert_eq!(signature.len(), 64);

        let public_key = keypair.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_ed25519_verify_failure() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Original message";
        let tampered = b"Tampered message";

        let signature = keypair.sign(message);
        let public_key = keypair.public_key();

        assert!(public_key.verify(tampered, &signature).is_err());
    }

    #[test]
    fn test_ed25519_from_seed() {
        let seed = [42u8; 32];
        let keypair1 = Ed25519KeyPair::from_seed(&seed);
        let keypair2 = Ed25519KeyPair::from_seed(&seed);

        let message = b"Test";
        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_verify() {
        let key = HmacKey::generate();
        let message = b"Test message";

        let tag = key.sign(message);
        assert!(key.verify(message, &tag).is_ok());
    }

    #[test]
    fn test_hmac_verify_failure() {
        let key = HmacKey::generate();
        let message = b"Original message";
        let tampered = b"Tampered message";

        let tag = key.sign(message);
        assert!(key.verify(tampered, &tag).is_err());
    }

    #[test]
    fn test_hmac_different_keys() {
        let key1 = HmacKey::generate();
        let key2 = HmacKey::generate();
        let message = b"Test";

        let tag1 = key1.sign(message);
        assert!(key2.verify(message, &tag1).is_err());
    }

    #[test]
    fn test_signature_suite_ed25519() {
        let suite = SignatureSuite::new_ed25519();
        let message = b"Test message";

        let signature = suite.sign_ed25519(message).expect("Signing failed");
        let public_key = suite.ed25519_public_key().expect("No public key");

        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_suite_hmac() {
        let suite = SignatureSuite::new_hmac();
        let message = b"Test message";

        let tag = suite.sign_hmac(message).expect("HMAC signing failed");
        assert!(!tag.is_empty());
    }

    #[test]
    fn test_signature_suite_combined() {
        let suite = SignatureSuite::new_combined();
        let message = b"Test message";

        assert!(suite.sign_ed25519(message).is_some());
        assert!(suite.sign_hmac(message).is_some());
    }

    #[test]
    fn test_ed25519_public_key_serialization() {
        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.public_key();

        let bytes = public_key.to_bytes();
        let restored = Ed25519PublicKey::from_bytes(&bytes).unwrap();

        let message = b"Test";
        let signature = keypair.sign(message);

        assert!(restored.verify(message, &signature).is_ok());
    }
}
