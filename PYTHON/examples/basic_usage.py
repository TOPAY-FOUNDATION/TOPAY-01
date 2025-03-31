#!/usr/bin/env python3
"""
Basic usage example for the TOPAY-01 cryptographic library.
"""

import topay01

def main():
    # Generate random bytes
    random_bytes = topay01.generate_random_bytes(32)
    print(f"Random bytes: {random_bytes.hex()}")

    # Hash data with BLAKE3
    hash_value = topay01.blake3_hash("Hello, TOPAY!")
    print(f"BLAKE3 Hash: {hash_value}")

    # Password hashing with Argon2id
    password = "secure_password"
    hash_str, _ = topay01.argon2_hash(password)
    print(f"Argon2 Hash: {hash_str}")

    is_valid = topay01.argon2_verify(password, hash_str)
    print(f"Password valid: {is_valid}")


if __name__ == "__main__":
    main()