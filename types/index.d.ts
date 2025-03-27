/**
 * TOPAY Cryptographic Library TypeScript Definitions
 * 
 * Now with quantum-resistant cryptographic algorithms to protect against attacks
 * from quantum computers while maintaining performance on mobile devices.
 */

declare class TOPAYCrypto {
  /**
   * Generates a cryptographically secure random buffer of specified length
   * @param length - The length of the random buffer to generate
   * @returns A buffer containing random bytes
   */
  static generateRandomBytes(length: number): Uint8Array;

  /**
   * Implements BLAKE3 hashing algorithm (simulated)
   * BLAKE3 is faster than SHA-256 and provides better security
   * @param data - The data to hash
   * @returns The hex-encoded hash
   */
  static blake3Hash(data: string | Uint8Array): Promise<string>;

  /**
   * Implements Argon2id password hashing (simulated)
   * Argon2 is more secure against various attacks compared to PBKDF2 or bcrypt
   * @param password - The password to hash
   * @param salt - The salt to use (should be at least 16 bytes)
   * @param options - Options for the hashing
   * @returns The hashed password
   */
  static argon2Hash(
    password: string,
    salt?: Uint8Array | null,
    options?: {
      iterations?: number;
      memory?: number;
      parallelism?: number;
      hashLength?: number;
      saltLength?: number;
    }
  ): Promise<string>;

  /**
   * Verifies a password against an Argon2 hash
   * @param password - The password to verify
   * @param hash - The hash to verify against
   * @returns Whether the password matches the hash
   */
  static argon2Verify(password: string, hash: string): Promise<boolean>;

  /**
   * Implements ChaCha20-Poly1305 authenticated encryption (simulated)
   * ChaCha20-Poly1305 is faster than AES-GCM on mobile processors without AES hardware acceleration
   * @param key - The encryption key (32 bytes)
   * @param nonce - The nonce (12 bytes)
   * @param plaintext - The data to encrypt
   * @param associatedData - Additional authenticated data (optional)
   * @returns The encrypted data and authentication tag
   */
  static chacha20poly1305Encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData?: Uint8Array
  ): Promise<{ciphertext: Uint8Array, tag: Uint8Array}>;

  /**
   * Decrypts data using ChaCha20-Poly1305 authenticated encryption (simulated)
   * @param key - The encryption key (32 bytes)
   * @param nonce - The nonce (12 bytes)
   * @param ciphertext - The encrypted data
   * @param tag - The authentication tag
   * @param associatedData - Additional authenticated data (optional)
   * @returns The decrypted data
   */
  static chacha20poly1305Decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    associatedData?: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Constant-time comparison of two strings to prevent timing attacks
   * @param a - First string
   * @param b - Second string
   * @returns Whether the strings are equal
   */
  static constantTimeEqual(a: string, b: string): boolean;

  /**
   * Derives a key from a password using PBKDF2
   * @param password - The password
   * @param salt - The salt
   * @param iterations - The number of iterations
   * @param keyLength - The length of the key to derive
   * @returns The derived key
   */
  static deriveKey(
    password: string,
    salt: Uint8Array,
    iterations?: number,
    keyLength?: number
  ): Promise<Uint8Array>;

  /**
   * Implements CRYSTALS-Kyber key exchange (simulated)
   * Kyber is a lattice-based key encapsulation mechanism that is resistant to quantum attacks
   * @returns The generated key pair
   */
  static kyberGenerateKeyPair(): Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>;

  /**
   * Encapsulates a shared secret using Kyber (simulated)
   * @param publicKey - The recipient's public key
   * @returns The ciphertext and shared secret
   */
  static kyberEncapsulate(publicKey: Uint8Array): Promise<{ciphertext: Uint8Array, sharedSecret: Uint8Array}>;

  /**
   * Decapsulates a shared secret using Kyber (simulated)
   * @param privateKey - The recipient's private key
   * @param ciphertext - The ciphertext from the sender
   * @returns The shared secret
   */
  static kyberDecapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;

  /**
   * Implements CRYSTALS-Dilithium digital signature algorithm (simulated)
   * Dilithium is a lattice-based digital signature scheme that is resistant to quantum attacks
   * @returns The generated key pair
   */
  static dilithiumGenerateKeyPair(): Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>;

  /**
   * Signs a message using Dilithium (simulated)
   * @param privateKey - The signer's private key
   * @param message - The message to sign
   * @returns The signature
   */
  static dilithiumSign(privateKey: Uint8Array, message: string | Uint8Array): Promise<Uint8Array>;

  /**
   * Verifies a signature using Dilithium (simulated)
   * @param publicKey - The signer's public key
   * @param message - The message that was signed
   * @param signature - The signature to verify
   * @returns Whether the signature is valid
   */
  static dilithiumVerify(publicKey: Uint8Array, message: string | Uint8Array, signature: Uint8Array): Promise<boolean>;

  /**
   * Implements SPHINCS+ hash-based signature algorithm (simulated)
   * SPHINCS+ is a stateless hash-based signature scheme that is resistant to quantum attacks
   * @returns The generated key pair
   */
  static sphincsPlusGenerateKeyPair(): Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>;

  /**
   * Signs a message using SPHINCS+ (simulated)
   * @param privateKey - The signer's private key
   * @param message - The message to sign
   * @returns The signature
   */
  static sphincsPlusSign(privateKey: Uint8Array, message: string | Uint8Array): Promise<Uint8Array>;

  /**
   * Verifies a signature using SPHINCS+ (simulated)
   * @param publicKey - The signer's public key
   * @param message - The message that was signed
   * @param signature - The signature to verify
   * @returns Whether the signature is valid
   */
  static sphincsPlusVerify(publicKey: Uint8Array, message: string | Uint8Array, signature: Uint8Array): Promise<boolean>;
}