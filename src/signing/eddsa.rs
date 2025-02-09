use aws_lc_rs::signature;

use super::SigningAlgorithm;
use crate::utils::b64_encode;

#[derive(Debug)]
pub struct Ed25519Algorithm {
    kp: signature::Ed25519KeyPair,
    pkey: signature::UnparsedPublicKey<Vec<u8>>,
}

impl Ed25519Algorithm {
    /// Create a new [`Ed25519Algorithm`] from DER data
    ///
    /// Given a private key and a public key.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der(private_key: &[u8], public_key: &[u8]) -> Result<Self, crate::errors::Error> {
        let kp = signature::Ed25519KeyPair::from_pkcs8(private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pkey = signature::UnparsedPublicKey::new(&signature::ED25519, public_key.to_vec());

        Ok(Self { kp, pkey })
    }
}

impl SigningAlgorithm for Ed25519Algorithm {
    fn kind(&self) -> super::Algorithm {
        super::Algorithm::EdDSA
    }

    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        let sig = self.kp.sign(data);
        Ok(b64_encode(sig.as_ref()))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error> {
        Ok(self.pkey.verify(data, signature).is_ok())
    }
}
