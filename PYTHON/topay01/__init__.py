\"""TOPAY-01 Cryptographic Library (Python Implementation)

A lightweight, high-security cryptographic library optimized for mobile processors
with quantum-resistant algorithms.
"""

from .crypto import (
    generate_random_bytes,
    blake3_hash,
    argon2_hash,
    argon2_verify,
    Argon2HashOptions,
    default_argon2_options,
    kyber_generate_key_pair,
    kyber_encapsulate,
    kyber_decapsulate,
    sphincs_generate_key_pair,
    sphincs_sign,
    sphincs_verify,
    dilithium_generate_key_pair,
    dilithium_sign,
    dilithium_verify,
)

__version__ = '0.0.1'