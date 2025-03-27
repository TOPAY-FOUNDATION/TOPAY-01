/**
 * TOPAY Cryptographic Library - Quantum-Resistant Examples
 */

const TOPAYCrypto = require('../crypto');

// Example 1: Kyber Key Exchange
console.log('\nExample 1: Kyber Key Exchange');
async function kyberExample() {
  // Alice generates a key pair
  console.log('Alice generates a Kyber key pair...');
  const aliceKeyPair = await TOPAYCrypto.kyberGenerateKeyPair();
  
  // Bob encapsulates a shared secret using Alice's public key
  console.log('Bob encapsulates a shared secret using Alice\'s public key...');
  const { ciphertext, sharedSecret: bobSharedSecret } = await TOPAYCrypto.kyberEncapsulate(aliceKeyPair.publicKey);
  console.log('Bob\'s shared secret (first 8 bytes):', Buffer.from(bobSharedSecret.slice(0, 8)).toString('hex'));
  
  // Alice decapsulates the shared secret using her private key and Bob's ciphertext
  console.log('Alice decapsulates the shared secret...');
  const aliceSharedSecret = await TOPAYCrypto.kyberDecapsulate(aliceKeyPair.privateKey, ciphertext);
  console.log('Alice\'s shared secret (first 8 bytes):', Buffer.from(aliceSharedSecret.slice(0, 8)).toString('hex'));
  
  // In a real implementation, both shared secrets would be identical
  console.log('In a real implementation, both shared secrets would be identical');
}

// Example 2: Dilithium Digital Signatures
console.log('\nExample 2: Dilithium Digital Signatures');
async function dilithiumExample() {
  // Generate a key pair
  console.log('Generating a Dilithium key pair...');
  const keyPair = await TOPAYCrypto.dilithiumGenerateKeyPair();
  
  // Sign a message
  const message = 'This message is signed with a quantum-resistant algorithm';
  console.log('Signing message:', message);
  const signature = await TOPAYCrypto.dilithiumSign(keyPair.privateKey, message);
  console.log('Signature size:', signature.length, 'bytes');
  
  // Verify the signature
  console.log('Verifying signature...');
  const isValid = await TOPAYCrypto.dilithiumVerify(keyPair.publicKey, message, signature);
  console.log('Signature valid:', isValid);
  
  // Try with wrong message
  const wrongMessage = 'This is not the original message';
  console.log('Verifying with wrong message:', wrongMessage);
  const isInvalid = await TOPAYCrypto.dilithiumVerify(keyPair.publicKey, wrongMessage, signature);
  console.log('Signature should be invalid in a real implementation, but for this simulation:', isInvalid);
}

// Example 3: SPHINCS+ Hash-Based Signatures
console.log('\nExample 3: SPHINCS+ Hash-Based Signatures');
async function sphincsPlusExample() {
  // Generate a key pair
  console.log('Generating a SPHINCS+ key pair...');
  const keyPair = await TOPAYCrypto.sphincsPlusGenerateKeyPair();
  
  // Sign a message
  const message = 'This message is signed with SPHINCS+, a hash-based signature scheme';
  console.log('Signing message:', message);
  const signature = await TOPAYCrypto.sphincsPlusSign(keyPair.privateKey, message);
  console.log('Signature size:', signature.length, 'bytes');
  
  // Verify the signature
  console.log('Verifying signature...');
  const isValid = await TOPAYCrypto.sphincsPlusVerify(keyPair.publicKey, message, signature);
  console.log('Signature valid:', isValid);
}

// Run the examples
async function runExamples() {
  try {
    await kyberExample();
    await dilithiumExample();
    await sphincsPlusExample();
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

runExamples();