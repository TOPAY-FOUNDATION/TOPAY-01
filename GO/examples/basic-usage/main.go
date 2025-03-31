package main

import (
	"encoding/hex"
	"fmt"

	topay01 "github.com/MdShahriya/TOPAY-01/GO"
)

func main() {
	// Generate random bytes
	randomBytes, err := topay01.GenerateRandomBytes(32)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Random bytes: %s\n", hex.EncodeToString(randomBytes))

	// Hash data with BLAKE3
	hash, err := topay01.Blake3Hash([]byte("Hello, TOPAY!"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("BLAKE3 Hash: %s\n", hash)

	// Password hashing with Argon2id
	password := "secure_password"
	hashStr, _, err := topay01.Argon2Hash(password, nil, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Argon2 Hash: %s\n", hashStr)

	isValid, err := topay01.Argon2Verify(password, hashStr)
	if err != nil {
		fmt.Printf("Verification error: %v\n", err)
	} else {
		fmt.Printf("Password valid: %v\n", isValid)
	}
}
