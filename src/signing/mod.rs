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

pub use ecdsa::{EcdsaAlgorithm, Secp256k1Algorithm};
pub use eddsa::Ed25519Algorithm;
pub use hmac::HmacAlgorithm;
pub use rsa::{RsaAlgorithm, RsaPssAlgorithm};

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
    /// ECDSA using the P-384 curve and SHA3-384.
    ES384,
    /// ECDSA using the P-521 curve and SHA3-512.
    ES512,
    /// ECDSA using the P-256K1 curve and SHA3-256.
    ES256K,
    /// Ed25519 PCKS#8 v1 or v2.
    EdDSA,
}

/// The algorithm or signer used for signing and verifying
///
/// See each of the algorithms for details
pub enum Signer {
    /// HMAC signer with SHA
    ///
    /// Wraps [`HmacAlgorithm`]
    Hmac(HmacAlgorithm),
    /// RSA v1.5 signer
    ///
    /// Wraps [`RsaAlgorithm`]
    Rsa(RsaAlgorithm),
    /// RSA PSS signer
    ///
    /// Wraps [`RsaPssAlgorithm`]
    RsaPss(RsaPssAlgorithm),
    /// ECDSA signer
    ///
    /// Wraps [`EcdsaAlgorithm`]
    Ecdsa(EcdsaAlgorithm),
    /// Secp256k1 signer
    ///
    /// Wraps [`Secp256k1Algorithm`]
    Secp256k1(Secp256k1Algorithm),
    /// EdDSA or Ed25519 signer
    ///
    /// Wraps [`Ed25519Algorithm`]
    Ed25519(Ed25519Algorithm),
}

impl Signer {
    /// Get the algorithm kind
    pub fn kind(&self) -> Algorithm {
        match self {
            Signer::Hmac(alg) => alg.kind(),
            Signer::Rsa(alg) => alg.kind(),
            Signer::RsaPss(alg) => alg.kind(),
            Signer::Ecdsa(alg) => alg.kind(),
            Signer::Secp256k1(alg) => alg.kind(),
            Signer::Ed25519(alg) => alg.kind(),
        }
    }

    /// Forward the signing to the underlying algorithm
    pub(crate) fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        match self {
            Signer::Hmac(alg) => alg.sign(data),
            Signer::Rsa(alg) => alg.sign(data),
            Signer::RsaPss(alg) => alg.sign(data),
            Signer::Ecdsa(alg) => alg.sign(data),
            Signer::Secp256k1(alg) => alg.sign(data),
            Signer::Ed25519(alg) => alg.sign(data),
        }
    }

    /// Forward the verification to the underlying algorithm
    pub(crate) fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::errors::Error> {
        match self {
            Signer::Hmac(alg) => alg.verify(data, signature),
            Signer::Rsa(alg) => alg.verify(data, signature),
            Signer::RsaPss(alg) => alg.verify(data, signature),
            Signer::Ecdsa(alg) => alg.verify(data, signature),
            Signer::Secp256k1(alg) => alg.verify(data, signature),
            Signer::Ed25519(alg) => alg.verify(data, signature),
        }
    }
}

impl From<HmacAlgorithm> for Signer {
    fn from(alg: HmacAlgorithm) -> Self {
        Signer::Hmac(alg)
    }
}

impl From<RsaAlgorithm> for Signer {
    fn from(alg: RsaAlgorithm) -> Self {
        Signer::Rsa(alg)
    }
}

impl From<RsaPssAlgorithm> for Signer {
    fn from(alg: RsaPssAlgorithm) -> Self {
        Signer::RsaPss(alg)
    }
}

impl From<EcdsaAlgorithm> for Signer {
    fn from(alg: EcdsaAlgorithm) -> Self {
        Signer::Ecdsa(alg)
    }
}

impl From<Secp256k1Algorithm> for Signer {
    fn from(alg: Secp256k1Algorithm) -> Self {
        Signer::Secp256k1(alg)
    }
}

impl From<Ed25519Algorithm> for Signer {
    fn from(alg: Ed25519Algorithm) -> Self {
        Signer::Ed25519(alg)
    }
}
