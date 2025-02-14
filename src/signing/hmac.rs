//! A HMAC algorithm for signing and verifying

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
    /// Given a [`SHALevel`] and a secret key
    pub fn new(hash: SHALevel, secret: &[u8]) -> Self {
        let alg = match hash {
            SHALevel::SHA256 => aws_lc_rs::hmac::HMAC_SHA256,
            SHALevel::SHA384 => aws_lc_rs::hmac::HMAC_SHA384,
            SHALevel::SHA512 => aws_lc_rs::hmac::HMAC_SHA512,
        };

        let key = aws_lc_rs::hmac::Key::new(alg, secret);

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
