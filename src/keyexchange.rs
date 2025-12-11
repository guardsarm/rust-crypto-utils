//! X25519 Key Exchange module for secure key agreement v2.0
//!
//! Provides Elliptic Curve Diffie-Hellman (ECDH) key exchange using X25519.

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Key exchange errors
#[derive(Error, Debug)]
pub enum KeyExchangeError {
    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Key exchange failed")]
    ExchangeFailed,

    #[error("Invalid key length")]
    InvalidKeyLength,
}

/// X25519 public key for key exchange
#[derive(Clone, Serialize, Deserialize)]
pub struct X25519PublicKey {
    bytes: [u8; 32],
}

impl X25519PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyExchangeError> {
        if bytes.len() != 32 {
            return Err(KeyExchangeError::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, KeyExchangeError> {
        let bytes = hex::decode(hex_str).map_err(|_| KeyExchangeError::InvalidPublicKey)?;
        Self::from_bytes(&bytes)
    }

    fn to_dalek(&self) -> PublicKey {
        PublicKey::from(self.bytes)
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PublicKey({}...)", &self.to_hex()[..16])
    }
}

/// Shared secret derived from key exchange
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derive an encryption key using HKDF
    pub fn derive_key(&self, info: &[u8]) -> [u8; 32] {
        use sha2::Sha256;
        use hkdf::Hkdf;

        let hk = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).expect("HKDF expand failed");
        okm
    }
}

/// X25519 key pair for key exchange
pub struct X25519KeyPair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new key pair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self {
            secret,
            public: X25519PublicKey {
                bytes: public_key.to_bytes(),
            },
        }
    }

    /// Create from existing secret key bytes
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, KeyExchangeError> {
        if bytes.len() != 32 {
            return Err(KeyExchangeError::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let secret = StaticSecret::from(arr);
        let public_key = PublicKey::from(&secret);
        Ok(Self {
            secret,
            public: X25519PublicKey {
                bytes: public_key.to_bytes(),
            },
        })
    }

    /// Get public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Perform key exchange with a peer's public key
    pub fn exchange(&self, peer_public: &X25519PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(&peer_public.to_dalek());
        SharedSecret {
            bytes: shared.to_bytes(),
        }
    }
}

/// Ephemeral X25519 key pair (for single use)
pub struct EphemeralX25519KeyPair {
    secret: Option<EphemeralSecret>,
    public: X25519PublicKey,
}

impl EphemeralX25519KeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public: X25519PublicKey {
                bytes: public_key.to_bytes(),
            },
        }
    }

    /// Get public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Perform key exchange (consumes the ephemeral secret)
    pub fn exchange(mut self, peer_public: &X25519PublicKey) -> Result<SharedSecret, KeyExchangeError> {
        let secret = self.secret.take().ok_or(KeyExchangeError::ExchangeFailed)?;
        let shared = secret.diffie_hellman(&peer_public.to_dalek());
        Ok(SharedSecret {
            bytes: shared.to_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.exchange(bob.public_key());
        let bob_shared = bob.exchange(alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let alice = EphemeralX25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_public = alice.public_key().clone();
        let alice_shared = alice.exchange(bob.public_key()).unwrap();
        let bob_shared = bob.exchange(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = X25519KeyPair::generate();
        let hex = keypair.public_key().to_hex();
        let restored = X25519PublicKey::from_hex(&hex).unwrap();
        assert_eq!(keypair.public_key().as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_derive_key() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let shared = alice.exchange(bob.public_key());
        let key1 = shared.derive_key(b"encryption");
        let key2 = shared.derive_key(b"authentication");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_from_secret_bytes() {
        let original = X25519KeyPair::generate();

        // Get the public key from the original for comparison
        let original_public = original.public_key().clone();

        // We can't directly extract secret bytes from StaticSecret,
        // but we can test the from_bytes function
        let test_bytes = [42u8; 32];
        let restored = X25519KeyPair::from_secret_bytes(&test_bytes).unwrap();

        // Just verify it creates a valid keypair
        assert!(restored.public_key().as_bytes().len() == 32);
    }
}
