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
    /// Create a new [`Secp256k1Algorithm`] from DER data
    ///
    /// Given a private key and a public key.
    pub fn new_der(private_key: &[u8], public_key: &[u8]) -> Result<Self, crate::errors::Error> {
        let private_key_cast: &[u8; 32] = private_key
            .try_into()
            .map_err(|_| crate::errors::Error::InvalidKeyLength(32, private_key.len()))?;

        let secret = SecretKey::from_byte_array(private_key_cast)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let public = PublicKey::from_slice(public_key)
            .map_err(|_| crate::errors::Error::InvalidPublicKey)?;

        Ok(Self {
            kp: secret,
            pkey: public,
        })
    }

    /// Create a new [`Secp256k1Algorithm`] from PEM data
    ///
    /// Given a private key and a public key.
    #[cfg(feature = "pem")]
    pub fn new_pem<B: AsRef<[u8]>>(
        private_key: B,
        public_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        let allowed_class = [
            crate::pem::Classification::Ec,
            crate::pem::Classification::Secp256k1,
        ];
        if !allowed_class.contains(&private_pem.classify()) {
            return Err(crate::errors::Error::MismatchedKey(
                "secp256k1/ECDSA",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let public_pem = crate::pem::PemEncodedKey::read(public_key)?;
        if !allowed_class.contains(&public_pem.classify()) {
            return Err(crate::errors::Error::MismatchedKey(
                "secp256k1/ECDSA",
                public_pem.classify().name(),
            ));
        }
        if public_pem.kind() != &crate::pem::PemKind::Public {
            return Err(crate::errors::Error::ExpectedPublicKey);
        }

        Self::new_der(private_pem.contents()?, public_pem.contents()?)
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
