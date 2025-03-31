/**
 * TOPAY Cryptographic Library - Zero-Knowledge Proof Example
 */

const TOPAYCrypto = require('../crypto');
require('../zk-proof'); // Import Zero-Knowledge Proof extension

// Example: Zero-Knowledge Proofs
console.log('\nTOPAY-01 Zero-Knowledge Proof Examples');
console.log('=======================================\n');

async function zkBasicProofExample() {
  console.log('Example 1: Basic Zero-Knowledge Proof');
  console.log('-------------------------------------');
  
  // Generate parameters
  console.log('Generating zero-knowledge parameters...');
  const { publicParameters, secretKey } = await TOPAYCrypto.zkGenerateParameters();
  
  console.log(`Public parameters size: ${publicParameters.length} bytes`);
  console.log(`Secret key size: ${secretKey.length} bytes`);
  
  // Create a proof
  const statement = 'I know the secret key';
  console.log('\nCreating a proof for statement:', statement);
  
  const proof = await TOPAYCrypto.zkCreateProof(publicParameters, secretKey, statement);
  console.log(`Proof size: ${proof.length} bytes`);
  
  // Verify the proof
  console.log('\nVerifying the proof...');
  const isValid = await TOPAYCrypto.zkVerifyProof(publicParameters, proof, statement);
  console.log('Proof valid:', isValid);
  
  console.log('\nIn a real implementation, the verifier would not learn anything about the secret key,');
  console.log('only that the prover knows it.');
}

async function zkRangeProofExample() {
  console.log('\nExample 2: Zero-Knowledge Range Proof');
  console.log('-----------------------------------');
  
  // Generate parameters
  console.log('Generating zero-knowledge parameters...');
  const { publicParameters, secretKey } = await TOPAYCrypto.zkGenerateParameters();
  
  // Create a range proof
  const value = 42; // The secret value
  const lowerBound = 0;
  const upperBound = 100;
  
  console.log(`\nCreating a proof that a secret value is in range [${lowerBound}, ${upperBound}]`);
  console.log(`(The secret value is ${value}, but this will not be revealed to the verifier)`);
  
  const rangeProof = await TOPAYCrypto.zkCreateRangeProof(
    publicParameters, 
    secretKey, 
    value, 
    lowerBound, 
    upperBound
  );
  
  console.log(`Range proof size: ${rangeProof.length} bytes`);
  
  // Verify the range proof
  console.log('\nVerifying the range proof...');
  const isRangeValid = await TOPAYCrypto.zkVerifyRangeProof(
    publicParameters, 
    rangeProof, 
    lowerBound, 
    upperBound
  );
  
  console.log('Range proof valid:', isRangeValid);
  
  console.log('\nIn a real implementation, the verifier would only learn that the secret value');
  console.log(`is between ${lowerBound} and ${upperBound}, but not the actual value.`);
}

async function zkPrivacyPreservingExample() {
  console.log('\nExample 3: Privacy-Preserving Credential Verification');
  console.log('--------------------------------------------------');
  
  // Generate parameters
  console.log('Generating zero-knowledge parameters...');
  const { publicParameters, secretKey } = await TOPAYCrypto.zkGenerateParameters();
  
  // Simulate a credential with sensitive information
  const age = 25;
  const minimumAge = 18;
  
  console.log(`\nScenario: Proving a person is at least ${minimumAge} years old`);
  console.log(`(The person's actual age is ${age}, but this will not be revealed to the verifier)`);
  
  // Create a credential proof
  const credential = { age, name: 'John Doe', ssn: '123-45-6789' };
  const predicates = { ageAtLeast: minimumAge };
  
  console.log('Creating a zero-knowledge proof for age verification...');
  const credentialProof = await TOPAYCrypto.zkCreateCredentialProof(
    publicParameters,
    secretKey,
    credential,
    predicates
  );
  
  console.log(`Credential proof size: ${credentialProof.length} bytes`);
  
  // Verify the credential proof
  console.log('\nVerifying the credential proof...');
  const isCredentialValid = await TOPAYCrypto.zkVerifyCredentialProof(
    publicParameters,
    credentialProof,
    predicates
  );
  
  console.log('Credential proof valid:', isCredentialValid);
  
  console.log('\nIn a real implementation, the verifier would only learn that the person is');
  console.log(`at least ${minimumAge} years old, but not their actual age or other personal information.`);
}

// Run the examples
async function runExamples() {
  try {
    await zkBasicProofExample();
    await zkRangeProofExample();
    await zkPrivacyPreservingExample();
  } catch (error) {
    console.error('Error running zero-knowledge proof examples:', error);
  }
}

runExamples();