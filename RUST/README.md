# TOPAY-01 Cryptographic Library (Rust Implementation)

A lightweight, high-security cryptographic library optimized for mobile processors with quantum-resistant algorithms.

## Features

- Modern cryptographic algorithms that offer better security than SHA-256 while maintaining efficiency on resource-constrained devices
- Quantum-resistant cryptographic algorithms to protect against attacks from quantum computers
- Optimized for mobile processors
- Idiomatic Rust implementation with zero-cost abstractions

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
topay-01 = "0.0.1"
```

## Usage

### Basic Usage

```rust
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
```

### Quantum-Resistant Features

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Kyber Key Exchange
    let alice_key_pair = topay_01::kyber_generate_key_pair()?;
    let encapsulation = topay_01::kyber_encapsulate(&alice_key_pair.public_key)?;
    let alice_shared_secret = topay_01::kyber_decapsulate(
        &alice_key_pair.private_key, 
        &encapsulation.ciphertext
    )?;
    
    // SPHINCS+ Digital Signatures
    let key_pair = topay_01::sphincs_generate_key_pair()?;
    let message = b"This message is signed with a quantum-resistant algorithm";
    let signature = topay_01::sphincs_sign(&key_pair.private_key, message)?;
    let is_valid = topay_01::sphincs_verify(&key_pair.public_key, message, &signature)?;
    
    Ok(())
}
```

## API Documentation

See the [docs.rs](https://docs.rs/topay-01) for complete API documentation.

## License

MIT
