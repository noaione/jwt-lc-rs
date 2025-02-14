//! A collection of all the signing algorithms supported by this library.
//!
//! Please see each module for details and usages.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use serde::{Deserialize, Serialize};

pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod rsa;
#[cfg(feature = "es256k")]
pub mod secp256k1;

pub use ecdsa::EcdsaAlgorithm;
pub use eddsa::Ed25519Algorithm;
pub use hmac::HmacAlgorithm;
pub use rsa::{RsaAlgorithm, RsaPssAlgorithm};
#[cfg(feature = "es256k")]
pub use secp256k1::Secp256k1Algorithm;

/// A trait for signing and verifying data
pub trait SigningAlgorithm {
    /// The algorithm kind used for signing
    fn kind(&self) -> Algorithm;

    /// Sign the given data
    ///
    /// This should return the base64 encoded signature
    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error>;

    /// Verify the given signature for the given data
    ///
    /// Returns true if the signature is valid
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error>;
}

/// Supported hashing algorithms.
///
/// Used by:
/// - HMAC
/// - RSA
/// - ECDSA
#[derive(Debug, Clone, Copy)]
pub enum SHALevel {
    /// SHA-256
    SHA256,
    /// SHA-384
    SHA384,
    /// SHA-512
    SHA512,
}

/// A list of supported algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// HMAC using SHA-256.
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
    /// RSA 2048-8192 bits, PKCS#1.5 padding, and SHA-256.
    RS256,
    /// RSA 2048-8192 bits, PKCS#1.5 padding, and SHA-384.
    RS384,
    /// RSA 2048-8192 bits, PKCS#1.5 padding, and SHA-512.
    RS512,
    /// RSA 2048-8192 bits, PSS padding, and SHA-256.
    PS256,
    /// RSA 2048-8192 bits, PSS padding, and SHA-384.
    PS384,
    /// RSA 2048-8192 bits, PSS padding, and SHA-512.
    PS512,
    /// ECDSA using the P-256 curve and SHA-256.
    ES256,
    /// ECDSA using the P-384 curve and SHA-384.
    ES384,
    /// ECDSA using the P-521 curve and SHA-512.
    ES512,
    /// secp256k1 using SHA3-256.
    #[cfg(feature = "es256k")]
    ES256K,
    /// Ed25519 PCKS#8 v1 or v2.
    EdDSA,
}
