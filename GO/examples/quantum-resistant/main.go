package main

import (
	"encoding/hex"
	"fmt"

	topay01 "github.com/MdShahriya/TOPAY-01/GO"
)

func main() {
	// Example 1: Kyber Key Exchange
	fmt.Println("\nExample 1: Kyber Key Exchange")
	// Alice generates a key pair
	fmt.Println("Alice generates a Kyber key pair...")
	aliceKeyPair, err := topay01.KyberGenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Bob encapsulates a shared secret using Alice's public key
	fmt.Println("Bob encapsulates a shared secret using Alice's public key...")
	encapsulation, err := topay01.KyberEncapsulate(aliceKeyPair.PublicKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Bob's shared secret (first 8 bytes): %s\n", hex.EncodeToString(encapsulation.SharedSecret[:8]))

	// Alice decapsulates the shared secret using her private key and Bob's ciphertext
	fmt.Println("Alice decapsulates the shared secret...")
	aliceSharedSecret, err := topay01.KyberDecapsulate(aliceKeyPair.PrivateKey, encapsulation.Ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Alice's shared secret (first 8 bytes): %s\n", hex.EncodeToString(aliceSharedSecret[:8]))

	fmt.Println("In a real implementation, both shared secrets would be identical")

	// Example 2: SPHINCS+ Digital Signatures
	fmt.Println("\nExample 2: SPHINCS+ Digital Signatures")
	// Generate a key pair
	fmt.Println("Generating a SPHINCS+ key pair...")
	keyPair, err := topay01.SPHINCSGenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Sign a message
	message := []byte("This message is signed with a quantum-resistant algorithm")
	fmt.Printf("Signing message: %s\n", string(message))
	signature, err := topay01.SPHINCSSign(keyPair.PrivateKey, message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature size: %d bytes\n", len(signature))

	// Verify the signature
	fmt.Println("Verifying signature...")
	isValid, err := topay01.SPHINCSVerify(keyPair.PublicKey, message, signature)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature valid: %v\n", isValid)

	// Try with wrong message
	wrongMessage := []byte("This is not the original message")
	fmt.Printf("Verifying with wrong message: %s\n", string(wrongMessage))
	isInvalid, err := topay01.SPHINCSVerify(keyPair.PublicKey, wrongMessage, signature)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature should be invalid in a real implementation, but for this simulation: %v\n", isInvalid)

	// Example 3: Dilithium Digital Signatures
	fmt.Println("\nExample 3: Dilithium Digital Signatures")
	// Generate a key pair
	fmt.Println("Generating a Dilithium key pair...")
	dilithiumKeyPair, err := topay01.DilithiumGenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Sign a message
	dilithiumMessage := []byte("This message is signed with Dilithium, a quantum-resistant algorithm")
	fmt.Printf("Signing message: %s\n", string(dilithiumMessage))
	dilithiumSignature, err := topay01.DilithiumSign(dilithiumKeyPair.PrivateKey, dilithiumMessage)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature size: %d bytes\n", len(dilithiumSignature))

	// Verify the signature
	fmt.Println("Verifying signature...")
	dilithiumIsValid, err := topay01.DilithiumVerify(dilithiumKeyPair.PublicKey, dilithiumMessage, dilithiumSignature)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature valid: %v\n", dilithiumIsValid)
}
