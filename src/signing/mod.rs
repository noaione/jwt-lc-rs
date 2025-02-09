use serde::{Deserialize, Serialize};

pub mod eddsa;
pub mod hmac;
pub mod rsa;
pub mod secp256k1;

pub use eddsa::Ed25519Algorithm;
pub use hmac::HmacAlgorithm;
pub use rsa::{RsaAlgorithm, RsaPssAlgorithm};
#[cfg(feature = "es256k")]
pub use secp256k1::Secp256k1Algorithm;

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

#[derive(Debug, Clone, Copy)]
pub enum SHALevel {
    SHA256,
    SHA384,
    SHA512,
}

/// A list of supported algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    #[cfg(feature = "es256k")]
    ES256K,
    EdDSA,
}
