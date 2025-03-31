//! Error types for the TOPAY-01 cryptographic library

use thiserror::Error;

/// Errors that can occur in the TOPAY-01 library
#[derive(Error, Debug)]
pub enum TopayError {
    /// Input validation error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Format error (e.g., invalid hash format)
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Random number generation error
    #[error("Random number generation failed: {0}")]
    RandomError(String),

    /// Cryptographic operation error
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Other error
    #[error("{0}")]
    Other(String),
}