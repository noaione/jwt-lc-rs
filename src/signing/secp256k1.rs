#![cfg(feature = "es256k")]

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};

use super::SigningAlgorithm;
use crate::utils::b64_encode;

/// A secp256k1 algorithm for signing and verifying
///
/// The message will be digested with SHA3-256 since it is more secure.
#[derive(Debug)]
pub struct Secp256k1Algorithm {
    kp: SecretKey,
    pkey: PublicKey,
}

impl Secp256k1Algorithm {
    /// Create a new [`Ed25519Algorithm`] from DER data
    ///
    /// Given a private key and a public key.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der(
        private_key: &[u8; 32],
        public_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let secret = SecretKey::from_byte_array(private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let public = PublicKey::from_slice(public_key)
            .map_err(|_| crate::errors::Error::InvalidPublicKey)?;

        Ok(Self {
            kp: secret,
            pkey: public,
        })
    }

    /// Consume a message and digest it with SHA3-256
    fn digest_message(&self, data: &[u8]) -> Result<Message, crate::errors::Error> {
        let output = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA3_256, data);
        let output_arr: [u8; 32] = output
            .as_ref()
            .try_into()
            .map_err(|_| crate::errors::Error::InvalidDigest(32))?;

        Ok(Message::from_digest(output_arr))
    }
}

impl SigningAlgorithm for Secp256k1Algorithm {
    fn kind(&self) -> super::Algorithm {
        super::Algorithm::EdDSA
    }

    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        let secp = Secp256k1::new();
        let digest = self.digest_message(data)?;
        let signed = secp.sign_ecdsa(&digest, &self.kp);
        Ok(b64_encode(&signed.serialize_compact()))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error> {
        let secp = Secp256k1::new();
        let signature = Signature::from_compact(signature)
            .map_err(|_| crate::errors::Error::InvalidSignature)?;
        let digest = self.digest_message(data)?;

        Ok(secp.verify_ecdsa(&digest, &signature, &self.pkey).is_ok())
    }
}
