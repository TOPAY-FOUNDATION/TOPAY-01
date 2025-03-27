/**
 * TOPAY Cryptographic Library - Basic Usage Examples
 */

const TOPAYCrypto = require('../index');

// Example 1: Generate random bytes
console.log('\nExample 1: Generate Random Bytes');
const randomBytes = TOPAYCrypto.generateRandomBytes(32);
console.log('Random bytes:', Buffer.from(randomBytes).toString('hex'));

// Example 2: Hash data with BLAKE3
console.log('\nExample 2: Hash Data with BLAKE3');
async function hashExample() {
  const hash = await TOPAYCrypto.blake3Hash('Hello, TOPAY!');
  console.log('BLAKE3 Hash of "Hello, TOPAY!":', hash);
}

// Example 3: Password hashing with Argon2id
console.log('\nExample 3: Password Hashing with Argon2id');
async function passwordHashExample() {
  const password = 'secure_TOPAY_password';
  
  // Hash the password
  const hash = await TOPAYCrypto.argon2Hash(password);
  console.log('Argon2id Hash:', hash);
  
  // Verify the password
  const isValid = await TOPAYCrypto.argon2Verify(password, hash);
  console.log('Password valid:', isValid);
  
  // Try with wrong password
  const isInvalid = await TOPAYCrypto.argon2Verify('wrong_password', hash);
  console.log('Wrong password valid:', isInvalid);
}

// Example 4: Encryption with ChaCha20-Poly1305
console.log('\nExample 4: Encryption with ChaCha20-Poly1305');
async function encryptionExample() {
  // Generate a key and nonce
  const key = TOPAYCrypto.generateRandomBytes(32);
  const nonce = TOPAYCrypto.generateRandomBytes(12);
  
  // Data to encrypt
  const encoder = new TextEncoder();
  const plaintext = encoder.encode('This is a secret message');
  
  // Encrypt the data
  const { ciphertext, tag } = await TOPAYCrypto.chacha20poly1305Encrypt(key, nonce, plaintext);
  console.log('Encrypted data length:', ciphertext.length, 'bytes');
  console.log('Authentication tag length:', tag.length, 'bytes');
  
  // Decrypt the data
  const decrypted = await TOPAYCrypto.chacha20poly1305Decrypt(key, nonce, ciphertext, tag);
  const decoder = new TextDecoder();
  console.log('Decrypted message:', decoder.decode(decrypted));
}