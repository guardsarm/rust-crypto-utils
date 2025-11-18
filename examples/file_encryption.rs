//! File encryption example using AES-256-GCM
//!
//! This example demonstrates secure file encryption and decryption
//! for protecting sensitive financial data.

use rust_crypto_utils::{encryption, random, SecureKey};

fn main() {
    println!("=== File Encryption Example ===\n");

    // Simulate encrypting sensitive financial data
    println!("1. Encrypting Sensitive Financial Data");

    let financial_data = b"\
Customer: John Smith
Account Number: 1234-5678-9012-3456
Balance: $125,450.00
SSN: 123-45-6789
Transaction History:
- 2024-11-01: Deposit $5,000.00
- 2024-11-05: Withdrawal $2,500.00
- 2024-11-06: Wire Transfer $10,000.00";

    println!("   Original data size: {} bytes", financial_data.len());

    // Generate encryption key
    let encryption_key = SecureKey::generate();
    println!("   ✓ Generated 256-bit encryption key");

    // Encrypt the data
    let encrypted_data = encryption::encrypt(&encryption_key, financial_data)
        .expect("Encryption failed");

    println!("   ✓ Data encrypted with AES-256-GCM");
    println!("   Encrypted size: {} bytes", encrypted_data.ciphertext.len());
    println!("   Nonce (12 bytes): {}", hex::encode(&encrypted_data.nonce));
    println!("   First 32 bytes of ciphertext: {}...",
             hex::encode(&encrypted_data.ciphertext[..32.min(encrypted_data.ciphertext.len())]));

    // Decrypt the data
    println!("\n2. Decrypting Data with Correct Key");
    let decrypted_data = encryption::decrypt(&encryption_key, &encrypted_data)
        .expect("Decryption failed");

    let decrypted_text = String::from_utf8(decrypted_data.clone()).unwrap();
    println!("   ✓ Decryption successful!");
    println!("   Decrypted data matches original: {}",
             decrypted_data == financial_data);
    println!("\n   Decrypted content:");
    println!("{}", decrypted_text);

    // Demonstrate decryption failure with wrong key
    println!("\n3. Attempting Decryption with Wrong Key");
    let wrong_key = SecureKey::generate();
    match encryption::decrypt(&wrong_key, &encrypted_data) {
        Ok(_) => println!("   ✗ Decryption succeeded (should have failed!)"),
        Err(e) => println!("   ✓ Decryption correctly failed: {}", e),
    }

    // Encrypt multiple files
    println!("\n4. Encrypting Multiple Financial Records");

    let records = vec![
        ("customer_001.txt", b"Customer: Alice Johnson, Account: ACC-001, Balance: $50,000"),
        ("customer_002.txt", b"Customer: Bob Williams, Account: ACC-002, Balance: $75,250"),
        ("customer_003.txt", b"Customer: Carol Davis, Account: ACC-003, Balance: $100,500"),
    ];

    let mut encrypted_records = Vec::new();

    for (filename, data) in &records {
        let encrypted = encryption::encrypt(&encryption_key, data)
            .expect("Encryption failed");
        encrypted_records.push((filename, encrypted));
        println!("   ✓ Encrypted {}", filename);
    }

    // Decrypt and verify all records
    println!("\n5. Decrypting All Records");
    for ((filename, original_data), (_, encrypted)) in records.iter().zip(encrypted_records.iter()) {
        let decrypted = encryption::decrypt(&encryption_key, encrypted)
            .expect("Decryption failed");
        let matches = &decrypted == original_data;
        println!("   {} - Decryption: {}",
                 filename,
                 if matches { "✓ Success" } else { "✗ Failed" });
    }

    // Generate secure tokens
    println!("\n6. Generating Secure Random Tokens");
    let session_token = random::generate_random_hex(32);
    let api_key = random::generate_random_hex(24);
    let transaction_id = random::generate_random_hex(16);

    println!("   Session Token: {}", session_token);
    println!("   API Key: {}", api_key);
    println!("   Transaction ID: {}", transaction_id);

    println!("\n=== Security Features ===");
    println!("✓ AES-256-GCM authenticated encryption");
    println!("✓ Automatic authentication tag verification");
    println!("✓ Unique nonce for each encryption");
    println!("✓ Memory-safe implementation (no buffer overflows)");
    println!("✓ Keys automatically zeroized when dropped");
    println!("✓ Wrong key detection (decryption fails safely)");
    println!("✓ NIST-approved cryptographic algorithm");

    println!("\n=== Use Cases ===");
    println!("✓ Customer financial records encryption");
    println!("✓ Database encryption at rest");
    println!("✓ Secure backup encryption");
    println!("✓ PCI-DSS compliant data protection");
    println!("✓ GDPR-compliant personal data encryption");
}
