//! Example demonstrating quantum-resistant threshold signatures using Dilithium
//! 
//! This example shows how to use the threshold signature scheme with Dilithium
//! for distributed security in blockchain and multi-party applications.

use topay01::{threshold_generate_keys, threshold_sign, threshold_combine, threshold_verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TOPAY-01 Quantum-Resistant Threshold Signature Example");
    println!("====================================================\n");
    
    // Set up threshold parameters
    let threshold = 3;  // Minimum signatures required
    let total_shares = 5;  // Total number of participants
    
    println!("Generating threshold signature keys with parameters:");
    println!("  - Threshold (t): {}", threshold);
    println!("  - Total shares (n): {}", total_shares);
    println!("  - Security property: Any {} of {} participants can create a valid signature", 
             threshold, total_shares);
    println!("  - Quantum resistance: Using Dilithium for post-quantum security\n");
    
    // Generate threshold keys
    let (public_key, shares) = threshold_generate_keys(threshold, total_shares)?;
    
    println!("Generated {} key shares and a public key of {} bytes", shares.len(), public_key.len());
    println!("Each share contains a portion of the Dilithium private key\n");
    
    // Create a message to sign
    let message = b"This message requires multiple parties to sign and is protected against quantum attacks";
    println!("Message to sign: {}", std::str::from_utf8(message).unwrap());
    
    // Simulate distributed signing (each participant creates a partial signature)
    println!("\nCollecting partial signatures from participants...");
    
    let mut partial_signatures = Vec::new();
    
    // We'll use only 3 of the 5 shares (meeting the threshold)
    for i in 0..threshold {
        let share = &shares[i as usize];
        println!("  - Participant {} creating a partial signature", share.index);
        
        let partial_sig = threshold_sign(message, share)?;
        println!("    Partial signature size: {} bytes", partial_sig.len());
        partial_signatures.push((share.index, partial_sig));
    }
    
    println!("\nCombining {} partial signatures (threshold: {})", partial_signatures.len(), threshold);
    println!("Using Lagrange interpolation to reconstruct the original signature");
    
    // Combine the partial signatures
    let combined_signature = threshold_combine(&partial_signatures, threshold)?;
    
    println!("Combined signature size: {} bytes (Dilithium signature)", combined_signature.len());
    
    // Verify the combined signature
    println!("\nVerifying the threshold signature using Dilithium verification...");
    let is_valid = threshold_verify(message, &combined_signature, &public_key)?;
    
    println!("Signature verification result: {}", if is_valid { "VALID ✓" } else { "INVALID ✗" });
    
    // Demonstrate threshold property by trying with fewer signatures
    if threshold > 1 {
        println!("\nDemonstrating threshold property:");
        println!("Attempting to combine only {} of {} required signatures...", threshold - 1, threshold);
        
        let insufficient_sigs = partial_signatures[0..threshold as usize - 1].to_vec();
        
        match threshold_combine(&insufficient_sigs, threshold) {
            Ok(_) => println!("Unexpectedly succeeded with insufficient signatures!"),
            Err(e) => println!("As expected, combining failed: {}", e),
        }
    }
    
    println!("\nThis implementation uses Shamir's Secret Sharing with Dilithium");
    println!("to provide a quantum-resistant threshold signature scheme.");
    println!("It allows {} of {} participants to collaboratively sign messages", threshold, total_shares);
    println!("while maintaining security against quantum computing attacks.");
    
    Ok(())
}