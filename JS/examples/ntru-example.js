/**
 * TOPAY Cryptographic Library - NTRU Encryption Example
 */

const TOPAYCrypto = require('../crypto');
require('../ntru'); // Import NTRU extension

// Example: NTRU Encryption
console.log('\nTOPAY-01 NTRU Encryption Example');
console.log('===================================\n');

async function ntruExample() {
  // Generate a key pair
  console.log('Generating NTRU key pair...');
  const keyPair = await TOPAYCrypto.ntruGenerateKeyPair();
  
  console.log(`Public key size: ${keyPair.publicKey.length} bytes`);
  console.log(`Private key size: ${keyPair.privateKey.length} bytes`);
  
  // Encrypt a message
  const message = 'This message is encrypted with NTRU, a quantum-resistant algorithm';
  console.log('\nOriginal message:', message);
  
  console.log('Encrypting message with NTRU...');
  const ciphertext = await TOPAYCrypto.ntruEncrypt(keyPair.publicKey, message);
  console.log(`Ciphertext size: ${ciphertext.length} bytes`);
  
  // Decrypt the message
  console.log('\nDecrypting message with NTRU...');
  const decryptedBuffer = await TOPAYCrypto.ntruDecrypt(keyPair.privateKey, ciphertext);
  
  // Convert the decrypted buffer back to a string
  // In a real implementation, the decrypted buffer would contain the original message
  // For this simulation, we'll just show the first few bytes of the buffer
  console.log('Decrypted data (first 8 bytes):', Buffer.from(decryptedBuffer.slice(0, 8)).toString('hex'));
  
  console.log('\nIn a real implementation, the decrypted message would match the original message');
}

// Run the example
async function runExample() {
  try {
    await ntruExample();
  } catch (error) {
    console.error('Error running NTRU example:', error);
  }
}

runExample();