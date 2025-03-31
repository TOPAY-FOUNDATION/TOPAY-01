//! Quantum-resistant example for the TOPAY-01 cryptographic library

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nExample 1: Kyber Key Exchange");
    // Alice generates a key pair
    println!("Alice generates a Kyber key pair...");
    let alice_key_pair = topay_01::kyber_generate_key_pair()?;
    
    // Bob encapsulates a shared secret using Alice's public key
    println!("Bob encapsulates a shared secret using Alice's public key...");
    let encapsulation = topay_01::kyber_encapsulate(&alice_key_pair.public_key)?;
    println!(
        "Bob's shared secret (first 8 bytes): {}", 
        hex::encode(&encapsulation.shared_secret[..8])
    );
    
    // Alice decapsulates the shared secret using her private key and Bob's ciphertext
    println!("Alice decapsulates the shared secret...");
    let alice_shared_secret = topay_01::kyber_decapsulate(
        &alice_key_pair.private_key, 
        &encapsulation.ciphertext
    )?;
    println!(
        "Alice's shared secret (first 8 bytes): {}", 
        hex::encode(&alice_shared_secret[..8])
    );
    
    println!("In a real implementation, both shared secrets would be identical");

    println!("\nExample 2: SPHINCS+ Digital Signatures");
    // Generate a key pair
    println!("Generating a SPHINCS+ key pair...");
    let key_pair = topay_01::sphincs_generate_key_pair()?;
    
    // Sign a message
    let message = b"This message is signed with a quantum-resistant algorithm";
    println!("Signing message: {}", std::str::from_utf8(message)?);
    let signature = topay_01::sphincs_sign(&key_pair.private_key, message)?;
    println!("Signature size: {} bytes", signature.len());
    
    // Verify the signature
    println!("Verifying signature...");
    let is_valid = topay_01::sphincs_verify(&key_pair.public_key, message, &signature)?;
    println!("Signature valid: {}", is_valid);
    
    // Try with wrong message
    let wrong_message = b"This is not the original message";
    println!("Verifying with wrong message: {}", std::str::from_utf8(wrong_message)?);
    let is_invalid = topay_01::sphincs_verify(&key_pair.public_key, wrong_message, &signature)?;
    println!("Signature should be invalid in a real implementation, but for this simulation: {}", is_invalid);

    Ok(())
}