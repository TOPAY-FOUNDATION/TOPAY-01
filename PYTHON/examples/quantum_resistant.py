#!/usr/bin/env python3
"""
Quantum-resistant example for the TOPAY-01 cryptographic library.
"""

import topay01

def main():
    print("\nExample 1: Kyber Key Exchange")
    # Alice generates a key pair
    print("Alice generates a Kyber key pair...")
    alice_key_pair = topay01.kyber_generate_key_pair()
    
    # Bob encapsulates a shared secret using Alice's public key
    print("Bob encapsulates a shared secret using Alice's public key...")
    encapsulation = topay01.kyber_encapsulate(alice_key_pair.public_key)
    print(f"Bob's shared secret (first 8 bytes): {encapsulation.shared_secret[:8].hex()}")
    
    # Alice decapsulates the shared secret using her private key and Bob's ciphertext
    print("Alice decapsulates the shared secret...")
    alice_shared_secret = topay01.kyber_decapsulate(alice_key_pair.private_key, encapsulation.ciphertext)
    print(f"Alice's shared secret (first 8 bytes): {alice_shared_secret[:8].hex()}")
    
    print("In a real implementation, both shared secrets would be identical")

    print("\nExample 2: SPHINCS+ Digital Signatures")
    # Generate a key pair
    print("Generating a SPHINCS+ key pair...")
    key_pair = topay01.sphincs_generate_key_pair()
    
    # Sign a message
    message = b"This message is signed with a quantum-resistant algorithm"
    print(f"Signing message: {message.decode()}")
    signature = topay01.sphincs_sign(key_pair.private_key, message)
    print(f"Signature size: {len(signature)} bytes")
    
    # Verify the signature
    print("Verifying signature...")
    is_valid = topay01.sphincs_verify(key_pair.public_key, message, signature)
    print(f"Signature valid: {is_valid}")
    
    # Try with wrong message
    wrong_message = b"This is not the original message"
    print(f"Verifying with wrong message: {wrong_message.decode()}")
    is_invalid = topay01.sphincs_verify(key_pair.public_key, wrong_message, signature)
    print(f"Signature should be invalid in a real implementation, but for this simulation: {is_invalid}")


if __name__ == "__main__":
    main()