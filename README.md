# Rust Crypto Utils

[![CI](https://github.com/guardsarm/rust-crypto-utils/actions/workflows/ci.yml/badge.svg)](https://github.com/guardsarm/rust-crypto-utils/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rust-crypto-utils.svg)](https://crates.io/crates/rust-crypto-utils)
[![Documentation](https://docs.rs/rust-crypto-utils/badge.svg)](https://docs.rs/rust-crypto-utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Memory-safe cryptographic utilities for financial systems and secure applications. Built with Rust to eliminate memory vulnerabilities in cryptographic implementations.

## Security-First Design

Implements cryptographic best practices with automatic memory zeroization and secure key handling. Aligns with **NIST cryptographic standards** and **2024 CISA/FBI guidance** for memory-safe implementations.

## Features

- **Memory Safety** - Rust's ownership system prevents memory leaks of sensitive cryptographic material
- **Automatic Zeroization** - Sensitive data (passwords, keys) automatically zeroed when dropped
- **Argon2id Password Hashing** - Secure password hashing resistant to GPU attacks
- **AES-256-GCM Encryption** - Authenticated encryption with associated data (AEAD)
- **Secure Random Generation** - Cryptographically secure random number generation
- **Type Safety** - Strong typing prevents cryptographic errors at compile time

## Use Cases

- Password hashing and verification for financial applications
- Data encryption for sensitive financial records
- Secure token generation
- Key management for banking systems
- Cryptographic operations in payment processing

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-crypto-utils = "0.1.0"
```

## Quick Start

### Password Hashing

```rust
use rust_crypto_utils::{SecurePassword, password};

// Hash a password
let password = SecurePassword::new(b"UserPassword123!".to_vec());
let hash = password::hash_password(&password).unwrap();

// Verify password
let is_valid = password::verify_password(&password, &hash).unwrap();
assert!(is_valid);
```

### Data Encryption

```rust
use rust_crypto_utils::{SecureKey, encryption};

// Generate encryption key
let key = SecureKey::generate();

// Encrypt sensitive data
let plaintext = b"Account: 123456, Balance: $50,000";
let encrypted = encryption::encrypt(&key, plaintext).unwrap();

// Decrypt data
let decrypted = encryption::decrypt(&key, &encrypted).unwrap();
assert_eq!(plaintext.as_slice(), decrypted.as_slice());
```

### Secure Random Generation

```rust
use rust_crypto_utils::random;

// Generate random bytes
let random_bytes = random::generate_random_bytes(32);

// Generate random hex string (for tokens)
let token = random::generate_random_hex(16); // 32 hex characters
```

## Security Features

### Automatic Memory Zeroization

All sensitive types (`SecurePassword`, `SecureKey`) automatically zero their memory when dropped:

```rust
{
    let password = SecurePassword::new(b"secret".to_vec());
    // Use password...
} // Memory automatically zeroed here
```

### Type Safety for Keys

```rust
// Won't compile: key length checked at runtime
let short_key = vec![0u8; 16];
let key = SecureKey::new(short_key); // Returns Err(InvalidKeyLength)

// Correct: 256-bit key
let valid_key = vec![0u8; 32];
let key = SecureKey::new(valid_key).unwrap();
```

### Secure Password Hashing

Uses Argon2id with secure default parameters:
- Memory cost: 19 MiB
- Time cost: 2 iterations
- Algorithm: Argon2id (resistant to GPU attacks)

## Examples

See the `examples/` directory:

```bash
cargo run --example password_hashing
cargo run --example file_encryption
```

## Testing

```bash
cargo test
```

## Alignment with Standards

This library implements cryptographic best practices from:

- **NIST SP 800-63B** - Digital Identity Guidelines (password hashing)
- **NIST SP 800-38D** - GCM mode for encryption
- **CISA/FBI Joint Guidance (2024)** - Memory-safe cryptographic implementations
- **OWASP Cryptographic Storage Cheat Sheet**

## Cryptographic Algorithms

- **Password Hashing**: Argon2id (winner of Password Hashing Competition)
- **Encryption**: AES-256-GCM (NIST-approved, authenticated encryption)
- **Random Generation**: OS-provided CSPRNG (OsRng)

## Use in Financial Systems

Designed for financial institutions requiring:
- **PCI-DSS compliance** - Secure cryptographic key management
- **GLBA compliance** - Protection of financial information
- **SOX compliance** - Data integrity and encryption
- **GDPR compliance** - Secure personal data handling

## Performance

- Low overhead cryptographic operations
- Efficient memory usage with automatic cleanup
- Suitable for high-volume financial transaction systems

## License

MIT License - See LICENSE file

## Author

Tony Chuks Awunor
- Former FINMA-regulated forex broker operator (2008-2013)
- M.S. Computer Science (CGPA: 4.52/5.00)
- EC-Council Certified SOC Analyst (CSA)
- Specialization: Memory-safe cryptographic implementations for financial infrastructure

## Contributing

Contributions welcome! Please open an issue or pull request.

## Security Disclosure

If you discover a security vulnerability, please email security@example.com (do not open public issue).

## Related Projects

- [rust-secure-logger](https://github.com/guardsarm/rust-secure-logger) - Secure logging with cryptographic integrity
- [rust-transaction-validator](https://github.com/guardsarm/rust-transaction-validator) - Financial transaction validation
- [rust-threat-detector](https://github.com/guardsarm/rust-threat-detector) - SIEM threat detection

## Citation

If you use this library in research or production systems, please cite:

```
Awunor, T.C. (2024). Rust Crypto Utils: Memory-Safe Cryptographic Utilities.
https://github.com/guardsarm/rust-crypto-utils
```

---

**Built for financial security. Designed for memory safety. Implemented in Rust.**
