//! Basic usage example for the TOPAY-01 cryptographic library

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate random bytes
    let random_bytes = topay_01::generate_random_bytes(32)?;
    println!("Random bytes: {}", hex::encode(&random_bytes));

    // Hash data with BLAKE3
    let hash = topay_01::blake3_hash(b"Hello, TOPAY!")?;
    println!("BLAKE3 Hash: {}", hash);

    // Password hashing with Argon2id
    let password = "secure_password";
    let (hash_str, _) = topay_01::argon2_hash(password, None, None)?;
    println!("Argon2 Hash: {}", hash_str);

    let is_valid = topay_01::argon2_verify(password, &hash_str)?;
    println!("Password valid: {}", is_valid);

    Ok(())
}