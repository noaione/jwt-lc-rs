//! A HMAC algorithm for signing and verifying
//!
//! We support the following SHAs:
//! - `SHA-256` ([`SHALevel::SHA256`])
//! - `SHA-384` ([`SHALevel::SHA384`])
//! - `SHA-512` ([`SHALevel::SHA512`])
//!
//! ## Examples
//!
//! Encoding the JWTs:
//! ```rust,no_run
//! use jwt_lc_rs::{HmacAlgorithm, SHALevel};
//! use serde::{Deserialize, Serialize};
//!
//! // Initialize the signing algorithm with SHA-384
//! let alg = HmacAlgorithm::new(SHALevel::SHA384, b"super-duper-secret");
//! // Or you can use anything that can be converted to `AsRef<[u8]>`
//! // let alg = HmacAlgorithm::new(SHALevel::SHA384, "this-is-a-str-secret");
//!
//! // Sign a message
//! #[derive(Serialize, Deserialize, Debug)]
//! struct SignedMessage {
//!     text: String,
//! }
//!
//! let data = SignedMessage { text: "Hello, world!".to_string() };
//!
//! let signer = jwt_lc_rs::Signer::Hmac(alg);
//! let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
//! println!("JWT Encoded: {}", encoded);
//! ```
//!
//! Decoding:
//! ```rust,no_run
//! use jwt_lc_rs::validator::Validator;
//! # use serde::{Deserialize, Serialize};
//! # #[derive(Serialize, Deserialize, Debug)]
//! # struct SignedMessage { text: String };
//! # let encoded = "test-data";
//! # let alg = jwt_lc_rs::HmacAlgorithm::new(jwt_lc_rs::SHALevel::SHA384, b"super-duper-secret");
//! # let signer = jwt_lc_rs::Signer::Hmac(alg);
//!
//! let decoded: jwt_lc_rs::TokenData<SignedMessage> = jwt_lc_rs::decode(
//!     &encoded,
//!     &signer,
//!     &Validator::default(), // You can also use validator like `jwt_lc_rs::validator::ExpiryValidator`
//! ).unwrap();
//!
//! println!("JWT Decoded: {:?}", decoded.get_claims());
//! ```

use aws_lc_rs::constant_time::verify_slices_are_equal;

use super::{SHALevel, SigningAlgorithm};
use crate::utils::b64_encode;

#[derive(Debug, Clone)]
pub struct HmacAlgorithm {
    key: aws_lc_rs::hmac::Key,
    hash: SHALevel,
}

impl HmacAlgorithm {
    /// Create a new [`HmacAlgorithm`]
    ///
    /// Given a [`SHALevel`] and a secret key that can be any type that implements `AsRef<[u8]>`
    pub fn new<B: AsRef<[u8]>>(hash: SHALevel, secret: B) -> Self {
        let alg = match hash {
            SHALevel::SHA256 => aws_lc_rs::hmac::HMAC_SHA256,
            SHALevel::SHA384 => aws_lc_rs::hmac::HMAC_SHA384,
            SHALevel::SHA512 => aws_lc_rs::hmac::HMAC_SHA512,
        };

        let key = aws_lc_rs::hmac::Key::new(alg, secret.as_ref());

        Self { key, hash }
    }
}

impl SigningAlgorithm for HmacAlgorithm {
    fn kind(&self) -> super::Algorithm {
        match self.hash {
            SHALevel::SHA256 => super::Algorithm::HS256,
            SHALevel::SHA384 => super::Algorithm::HS384,
            SHALevel::SHA512 => super::Algorithm::HS512,
        }
    }

    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        let tag = aws_lc_rs::hmac::sign(&self.key, data);
        Ok(b64_encode(tag.as_ref()))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error> {
        let tag = aws_lc_rs::hmac::sign(&self.key, data);
        Ok(verify_slices_are_equal(signature, tag.as_ref()).is_ok())
    }
}
