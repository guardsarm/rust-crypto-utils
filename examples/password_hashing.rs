//! Password hashing example using Argon2id
//!
//! This example demonstrates secure password hashing and verification
//! for user authentication systems.

use rust_crypto_utils::{password, SecurePassword};

fn main() {
    println!("=== Password Hashing Example ===\n");

    // Simulate user registration
    println!("1. User Registration");
    let user_password = SecurePassword::new(b"MySecurePassword123!".to_vec());

    println!("   Hashing password with Argon2id...");
    let password_hash = password::hash_password(&user_password)
        .expect("Failed to hash password");

    println!("   Password hash: {}...", &password_hash[..50]);
    println!("   ✓ Hash stored in database\n");

    // Simulate user login with correct password
    println!("2. User Login - Correct Password");
    let login_password = SecurePassword::new(b"MySecurePassword123!".to_vec());

    println!("   Verifying password...");
    match password::verify_password(&login_password, &password_hash) {
        Ok(true) => println!("   ✓ Authentication successful!\n"),
        Ok(false) => println!("   ✗ Authentication failed - wrong password\n"),
        Err(e) => println!("   ✗ Verification error: {}\n", e),
    }

    // Simulate login attempt with wrong password
    println!("3. User Login - Wrong Password");
    let wrong_password = SecurePassword::new(b"WrongPassword".to_vec());

    println!("   Verifying password...");
    match password::verify_password(&wrong_password, &password_hash) {
        Ok(true) => println!("   ✓ Authentication successful!\n"),
        Ok(false) => println!("   ✗ Authentication failed - wrong password\n"),
        Err(e) => println!("   ✗ Verification error: {}\n", e),
    }

    // Demonstrate multiple users with different passwords
    println!("4. Multiple User Accounts");

    let users = vec![
        ("alice", b"AlicePass123!"),
        ("bob", b"BobSecure456@"),
        ("charlie", b"Charlie789#Pwd"),
    ];

    let mut hashes = Vec::new();

    for (username, password) in &users {
        let pwd = SecurePassword::new(password.to_vec());
        let hash = password::hash_password(&pwd).unwrap();
        hashes.push((username, hash));
        println!("   ✓ User '{}' registered", username);
    }

    println!("\n5. Authenticating Multiple Users");

    // Authenticate Alice correctly
    let alice_pwd = SecurePassword::new(b"AlicePass123!".to_vec());
    let (_, alice_hash) = &hashes[0];
    let is_valid = password::verify_password(&alice_pwd, alice_hash).unwrap();
    println!("   Alice authentication: {}", if is_valid { "✓ Success" } else { "✗ Failed" });

    // Try to authenticate Bob with wrong password
    let wrong_bob_pwd = SecurePassword::new(b"WrongPassword".to_vec());
    let (_, bob_hash) = &hashes[1];
    let is_valid = password::verify_password(&wrong_bob_pwd, bob_hash).unwrap();
    println!("   Bob authentication (wrong pwd): {}", if is_valid { "✓ Success" } else { "✗ Failed" });

    // Authenticate Charlie correctly
    let charlie_pwd = SecurePassword::new(b"Charlie789#Pwd".to_vec());
    let (_, charlie_hash) = &hashes[2];
    let is_valid = password::verify_password(&charlie_pwd, charlie_hash).unwrap();
    println!("   Charlie authentication: {}", if is_valid { "✓ Success" } else { "✗ Failed" });

    println!("\n=== Security Features ===");
    println!("✓ Argon2id algorithm (resistant to GPU attacks)");
    println!("✓ Secure salt generation (cryptographically random)");
    println!("✓ Memory-safe implementation (no buffer overflows)");
    println!("✓ Automatic zeroization (passwords cleared from memory)");
    println!("✓ Same password produces different hashes (due to unique salts)");

    // Demonstrate that same password produces different hashes
    println!("\n6. Salt Uniqueness Demonstration");
    let same_pwd = SecurePassword::new(b"SamePassword123".to_vec());
    let hash1 = password::hash_password(&same_pwd).unwrap();
    let hash2 = password::hash_password(&same_pwd).unwrap();

    println!("   Hash 1: {}...", &hash1[..50]);
    println!("   Hash 2: {}...", &hash2[..50]);
    println!("   Hashes different: {}", hash1 != hash2);
    println!("   ✓ Each hash uses unique salt for security");
}
