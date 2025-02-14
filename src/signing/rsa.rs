use aws_lc_rs::{
    rand,
    signature::{self, KeyPair},
};

use super::{SHALevel, SigningAlgorithm};
use crate::utils::b64_encode;

#[derive(Debug)]
pub struct RsaAlgorithm {
    kp: signature::RsaKeyPair,
    pkey: Vec<u8>,
    hash: SHALevel,
}

impl RsaAlgorithm {
    /// Create a new [`RsaAlgorithm`] from DER data
    ///
    /// Given a [`SHALevel`] a private key and a public key.
    /// We only support PKCS#1 encoded public key and not PKCS#8.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der(
        hash: SHALevel,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let key_pair = signature::RsaKeyPair::from_der(private_key)
            // try with pkcs#8
            .or_else(|_| signature::RsaKeyPair::from_pkcs8(private_key))
            // still fail, error
            .map_err(|_| crate::errors::Error::InvalidKey)?;

        Ok(Self {
            kp: key_pair,
            pkey: public_key.to_vec(),
            hash,
        })
    }

    /// Create a new [`RsaAlgorithm`] from DER data
    ///
    /// Given a [`SHALevel`] a private key.
    /// Public key will automatically inferred.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der_from_private_key(
        hash: SHALevel,
        private_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let key_pair = signature::RsaKeyPair::from_der(private_key)
            // try with pkcs#8
            .or_else(|_| signature::RsaKeyPair::from_pkcs8(private_key))
            // still fail, error
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pub_key_gen = key_pair.public_key().as_ref();
        let pub_key = pub_key_gen.to_vec();

        Ok(Self {
            kp: key_pair,
            pkey: pub_key,
            hash,
        })
    }

    /// Create a new [`RsaAlgorithm`] from PEM data
    ///
    /// Given a [`SHALevel`] a private key and a public key.
    /// We only support PKCS#1 encoded public key and not PKCS#8.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    #[cfg(feature = "pem")]
    pub fn new_pem<B: AsRef<[u8]>>(
        hash: SHALevel,
        private_key: B,
        public_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let public_pem = crate::pem::PemEncodedKey::read(public_key)?;
        if public_pem.classify() != &crate::pem::Classification::Rsa {
            return Err(crate::errors::Error::MismatchedKey(
                "RSA",
                public_pem.classify().name(),
            ));
        }
        if public_pem.kind() != &crate::pem::PemKind::Public {
            return Err(crate::errors::Error::ExpectedPublicKey);
        }
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Rsa {
            return Err(crate::errors::Error::MismatchedKey(
                "RSA",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let key_pair = signature::RsaKeyPair::from_der(private_pem.contents()?)
            .map_err(|_| crate::errors::Error::InvalidKey)?;

        Ok(Self {
            kp: key_pair,
            pkey: public_pem.contents()?.to_vec(),
            hash,
        })
    }

    /// Create a new [`RsaAlgorithm`] from PEM data
    ///
    /// Given a [`SHALevel`] a private key.
    /// Public key will automatically inferred.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    #[cfg(feature = "pem")]
    pub fn new_pem_from_private_key<B: AsRef<[u8]>>(
        hash: SHALevel,
        private_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Rsa {
            return Err(crate::errors::Error::MismatchedKey(
                "RSA",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let key_pair = signature::RsaKeyPair::from_der(private_pem.contents()?)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pub_key = key_pair.public_key().as_ref();
        let pub_key = pub_key.to_vec();

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
        let alg = match self.hash {
            SHALevel::SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            SHALevel::SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            SHALevel::SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        };
        let refdata: &[u8] = self.pkey.as_ref();
        let pub_key = signature::UnparsedPublicKey::new(alg, refdata);
        Ok(pub_key.verify(data, signature).is_ok())
    }
}

#[derive(Debug)]
pub struct RsaPssAlgorithm {
    kp: signature::RsaKeyPair,
    pkey: Vec<u8>,
    hash: SHALevel,
}

impl RsaPssAlgorithm {
    /// Create a new [`RsaPssAlgorithm`] from DER data
    ///
    /// Given a [`SHALevel`] a private key and a public key.
    /// We only support PKCS#1 encoded public key and not PKCS#8.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der(
        hash: SHALevel,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let key_pair = signature::RsaKeyPair::from_der(private_key)
            // try with pkcs#8
            .or_else(|_| signature::RsaKeyPair::from_pkcs8(private_key))
            // still fail, error
            .map_err(|_| crate::errors::Error::InvalidKey)?;

        Ok(Self {
            kp: key_pair,
            pkey: public_key.to_vec(),
            hash,
        })
    }

    /// Create a new [`RsaPssAlgorithm`] from DER data
    ///
    /// Given a [`SHALevel`] a private key.
    /// Public key will automatically inferred.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    pub fn new_der_from_private_key(
        hash: SHALevel,
        private_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let key_pair = signature::RsaKeyPair::from_der(private_key)
            // try with pkcs#8
            .or_else(|_| signature::RsaKeyPair::from_pkcs8(private_key))
            // still fail, error
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pub_key_gen = key_pair.public_key().as_ref();
        let pub_key = pub_key_gen.to_vec();

        Ok(Self {
            kp: key_pair,
            pkey: pub_key,
            hash,
        })
    }

    /// Create a new [`RsaPssAlgorithm`] from PEM data
    ///
    /// Given a [`SHALevel`] a private key and a public key.
    /// We only support PKCS#1 encoded public key and not PKCS#8.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    #[cfg(feature = "pem")]
    pub fn new_pem<B: AsRef<[u8]>>(
        hash: SHALevel,
        private_key: B,
        public_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let public_pem = crate::pem::PemEncodedKey::read(public_key)?;
        if public_pem.classify() != &crate::pem::Classification::RsaPss {
            return Err(crate::errors::Error::MismatchedKey(
                "RSA-PSS",
                public_pem.classify().name(),
            ));
        }
        if public_pem.kind() != &crate::pem::PemKind::Public {
            return Err(crate::errors::Error::ExpectedPublicKey);
        }
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::RsaPss {
            return Err(crate::errors::Error::MismatchedKey(
                "RSA-PSS",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let key_pair = signature::RsaKeyPair::from_der(private_pem.contents()?)
            .map_err(|_| crate::errors::Error::InvalidKey)?;

        Ok(Self {
            kp: key_pair,
            pkey: public_pem.contents()?.to_vec(),
            hash,
        })
    }

    /// Create a new [`RsaPssAlgorithm`] from PEM data
    ///
    /// Given a [`SHALevel`] a private key.
    /// Public key will automatically inferred.
    ///
    /// Minimum supported key size is 2048 bits and maximum is 8192 bits.
    #[cfg(feature = "pem")]
    pub fn new_pem_from_private_key<B: AsRef<[u8]>>(
        hash: SHALevel,
        private_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::RsaPss {
            return Err(crate::errors::Error::MismatchedKey(
                "RSA-PSS",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let key_pair = signature::RsaKeyPair::from_der(private_pem.contents()?)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pub_key_gen = key_pair.public_key().as_ref();
        let pub_key = pub_key_gen.to_vec();

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
        let alg = match self.hash {
            SHALevel::SHA256 => &signature::RSA_PSS_2048_8192_SHA256,
            SHALevel::SHA384 => &signature::RSA_PSS_2048_8192_SHA384,
            SHALevel::SHA512 => &signature::RSA_PSS_2048_8192_SHA512,
        };

        let refdata: &[u8] = self.pkey.as_ref();
        let pub_key = signature::UnparsedPublicKey::new(alg, refdata);
        Ok(pub_key.verify(data, signature).is_ok())
    }
}
