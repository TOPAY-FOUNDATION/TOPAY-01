# TOPAY-01 Cryptographic Library

A lightweight, high-security cryptographic library optimized for mobile processors with quantum-resistant algorithms.

## Features

- Modern cryptographic algorithms that offer better security than SHA-256 while maintaining efficiency on resource-constrained devices
- Quantum-resistant cryptographic algorithms to protect against attacks from quantum computers
- Optimized for mobile processors
- TypeScript definitions included

## Installation

```bash
npm install topay-01
```

Or add it directly to your project:

```bash
npm install https://github.com/MdShahriya/TOPAY-01.git
```

## Usage

### Basic Usage

```javascript
const TOPAYCrypto = require('topay-01');

// Generate random bytes
const randomBytes = TOPAYCrypto.generateRandomBytes(32);
console.log('Random bytes:', Buffer.from(randomBytes).toString('hex'));

// Hash data with BLAKE3
async function hashExample() {
  const hash = await TOPAYCrypto.blake3Hash('Hello, TOPAY!');
  console.log('BLAKE3 Hash:', hash);
}

// Password hashing with Argon2id
async function passwordExample() {
  const password = 'secure_password';
  const hash = await TOPAYCrypto.argon2Hash(password);
  const isValid = await TOPAYCrypto.argon2Verify(password, hash);
}

// Encryption with ChaCha20-Poly1305
async function encryptionExample() {
  const key = TOPAYCrypto.generateRandomBytes(32);
  const nonce = TOPAYCrypto.generateRandomBytes(12);
  const plaintext = new TextEncoder().encode('Secret message');
  
  const { ciphertext, tag } = await TOPAYCrypto.chacha20poly1305Encrypt(key, nonce, plaintext);
  const decrypted = await TOPAYCrypto.chacha20poly1305Decrypt(key, nonce, ciphertext, tag);
}
```

### Quantum-Resistant Features

```javascript
const TOPAYCrypto = require('topay-01');

// Kyber Key Exchange
async function kyberExample() {
  const aliceKeyPair = await TOPAYCrypto.kyberGenerateKeyPair();
  const { ciphertext, sharedSecret: bobSharedSecret } = await TOPAYCrypto.kyberEncapsulate(aliceKeyPair.publicKey);
  const aliceSharedSecret = await TOPAYCrypto.kyberDecapsulate(aliceKeyPair.privateKey, ciphertext);
}

// Dilithium Digital Signatures
async function dilithiumExample() {
  const keyPair = await TOPAYCrypto.dilithiumGenerateKeyPair();
  const message = 'This message is signed with a quantum-resistant algorithm';
  const signature = await TOPAYCrypto.dilithiumSign(keyPair.privateKey, message);
  const isValid = await TOPAYCrypto.dilithiumVerify(keyPair.publicKey, message, signature);
}

// SPHINCS+ Digital Signatures
async function sphincsExample() {
  const keyPair = await TOPAYCrypto.sphincsGenerateKeyPair();
  const message = 'This message is signed with SPHINCS+';
  const signature = await TOPAYCrypto.sphincsSign(keyPair.privateKey, message);
  const isValid = await TOPAYCrypto.sphincsVerify(keyPair.publicKey, message, signature);
}
```

## API Documentation

See the [types/index.d.ts](types/index.d.ts) file for complete API documentation.

## License

MIT