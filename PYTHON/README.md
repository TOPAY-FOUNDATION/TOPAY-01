# TOPAY-01 Cryptographic Library (Python Implementation)

A lightweight, high-security cryptographic library optimized for mobile processors with quantum-resistant algorithms.

## Features

- Modern cryptographic algorithms that offer better security than SHA-256 while maintaining efficiency on resource-constrained devices
- Quantum-resistant cryptographic algorithms to protect against attacks from quantum computers
- Optimized for mobile processors
- Pythonic implementation with type hints

## Installation

```bash
pip install topay01
```

## Usage

### Basic Usage

```python
import topay01

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
```

### Quantum-Resistant Features

```python
import topay01

# Kyber Key Exchange
alice_key_pair = topay01.kyber_generate_key_pair()
encapsulation = topay01.kyber_encapsulate(alice_key_pair.public_key)
print(f"Bob's shared secret: {encapsulation.shared_secret.hex()[:16]}...")

alice_shared_secret = topay01.kyber_decapsulate(alice_key_pair.private_key, encapsulation.ciphertext)
print(f"Alice's shared secret: {alice_shared_secret.hex()[:16]}...")

# SPHINCS+ Digital Signatures
key_pair = topay01.sphincs_generate_key_pair()
message = b"This message is signed with a quantum-resistant algorithm"
signature = topay01.sphincs_sign(key_pair.private_key, message)
print(f"Signature size: {len(signature)} bytes")

is_valid = topay01.sphincs_verify(key_pair.public_key, message, signature)
print(f"Signature valid: {is_valid}")
```

## API Documentation

See the [documentation](https://topay01.readthedocs.io/) for complete API documentation.

## License

MIT