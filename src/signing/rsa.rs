use aws_lc_rs::{rand, signature};

use super::{SHALevel, SigningAlgorithm};
use crate::utils::b64_encode;

#[derive(Debug)]
pub struct RsaAlgorithm {
    kp: signature::RsaKeyPair,
    pkey: signature::UnparsedPublicKey<Vec<u8>>,
    hash: SHALevel,
}

impl RsaAlgorithm {
    /// Create a new [`RsaAlgorithm`] from DER data
    ///
    /// Given a [`SHALevel`] a private key and a public key.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der(
        hash: SHALevel,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let alg = match hash {
            SHALevel::SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            SHALevel::SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            SHALevel::SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        };

        let key_pair = signature::RsaKeyPair::from_der(private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pub_key = signature::UnparsedPublicKey::new(alg, public_key.to_vec());

        Ok(Self {
            kp: key_pair,
            pkey: pub_key,
            hash,
        })
    }
}

impl SigningAlgorithm for RsaAlgorithm {
    fn kind(&self) -> super::Algorithm {
        match self.hash {
            SHALevel::SHA256 => super::Algorithm::RS256,
            SHALevel::SHA384 => super::Algorithm::RS384,
            SHALevel::SHA512 => super::Algorithm::RS512,
        }
    }

    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        let pad_alg = match self.hash {
            SHALevel::SHA256 => &signature::RSA_PKCS1_SHA256,
            SHALevel::SHA384 => &signature::RSA_PKCS1_SHA384,
            SHALevel::SHA512 => &signature::RSA_PKCS1_SHA512,
        };

        let rng = rand::SystemRandom::new();
        let mut sig = vec![0; self.kp.public_modulus_len()];
        self.kp
            .sign(pad_alg, &rng, data, &mut sig)
            .map_err(|_| crate::errors::Error::SigningError)?;

        Ok(b64_encode(&sig))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error> {
        Ok(self.pkey.verify(data, signature).is_ok())
    }
}

#[derive(Debug)]
pub struct RsaPssAlgorithm {
    kp: signature::RsaKeyPair,
    pkey: signature::UnparsedPublicKey<Vec<u8>>,
    hash: SHALevel,
}

impl RsaPssAlgorithm {
    /// Create a new [`RsaPssAlgorithm`] from DER data
    ///
    /// Given a [`SHALevel`] a private key and a public key.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der(
        hash: SHALevel,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let alg = match hash {
            SHALevel::SHA256 => &signature::RSA_PSS_2048_8192_SHA256,
            SHALevel::SHA384 => &signature::RSA_PSS_2048_8192_SHA384,
            SHALevel::SHA512 => &signature::RSA_PSS_2048_8192_SHA512,
        };

        let key_pair = signature::RsaKeyPair::from_der(private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pub_key = signature::UnparsedPublicKey::new(alg, public_key.to_vec());

        Ok(Self {
            kp: key_pair,
            pkey: pub_key,
            hash,
        })
    }
}

impl SigningAlgorithm for RsaPssAlgorithm {
    fn kind(&self) -> super::Algorithm {
        match self.hash {
            SHALevel::SHA256 => super::Algorithm::PS256,
            SHALevel::SHA384 => super::Algorithm::PS384,
            SHALevel::SHA512 => super::Algorithm::PS512,
        }
    }

    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        let pad_alg = match self.hash {
            SHALevel::SHA256 => &signature::RSA_PSS_SHA256,
            SHALevel::SHA384 => &signature::RSA_PSS_SHA384,
            SHALevel::SHA512 => &signature::RSA_PSS_SHA512,
        };

        let rng = rand::SystemRandom::new();
        let mut sig = vec![0; self.kp.public_modulus_len()];
        self.kp
            .sign(pad_alg, &rng, data, &mut sig)
            .map_err(|_| crate::errors::Error::SigningError)?;

        Ok(b64_encode(&sig))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error> {
        Ok(self.pkey.verify(data, signature).is_ok())
    }
}
