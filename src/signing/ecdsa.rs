//! A ECDSA algorithm for signing and verifying

use aws_lc_rs::{
    rand,
    signature::{self, KeyPair},
};

use super::{SHALevel, SigningAlgorithm};
use crate::utils::b64_encode;

/// An ECDSA with P-{256, 384, 521} curves for signing and verifying
///
/// Depending on the [`SHALevel`], the message will be digested with SHA-256, SHA3-384, or SHA3-512.
#[derive(Debug)]
pub struct EcdsaAlgorithm {
    kp: signature::EcdsaKeyPair,
    pkey: signature::UnparsedPublicKey<Vec<u8>>,
    hash: SHALevel,
}

fn get_signing_alg(hash: SHALevel) -> &'static signature::EcdsaSigningAlgorithm {
    match hash {
        SHALevel::SHA256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        SHALevel::SHA384 => &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
        SHALevel::SHA512 => &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
    }
}

fn get_verification_alg(hash: SHALevel) -> &'static signature::EcdsaVerificationAlgorithm {
    match hash {
        SHALevel::SHA256 => &signature::ECDSA_P256_SHA256_FIXED,
        SHALevel::SHA384 => &signature::ECDSA_P384_SHA3_384_FIXED,
        SHALevel::SHA512 => &signature::ECDSA_P521_SHA3_512_FIXED,
    }
}

impl EcdsaAlgorithm {
    /// Create a new [`EcdsaAlgorithm`] from PKCS#8 bytes data
    ///
    /// Given a private key and a public key.
    pub fn new_pkcs8(
        hash: SHALevel,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let kp = signature::EcdsaKeyPair::from_pkcs8(get_signing_alg(hash), private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;

        let pkey =
            signature::UnparsedPublicKey::new(get_verification_alg(hash), public_key.to_vec());

        Ok(Self { kp, pkey, hash })
    }

    /// Create a new [`EcdsaAlgorithm`] from PKCS#8 bytes data
    ///
    /// Given a private key.
    pub fn new_pkcs8_from_private_key(
        hash: SHALevel,
        private_key: &[u8],
    ) -> Result<Self, crate::errors::Error> {
        let kp = signature::EcdsaKeyPair::from_pkcs8(get_signing_alg(hash), private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pubkey = kp.public_key().as_ref();
        let pkey = signature::UnparsedPublicKey::new(get_verification_alg(hash), pubkey.to_vec());

        Ok(Self { kp, pkey, hash })
    }

    /// Create a new [`EcdsaAlgorithm`] from PKCS#8 PEM-encoded data
    ///
    /// Given a [`SHALevel`], a private key, and a public key.
    #[cfg(feature = "pem")]
    pub fn new_pkcs8_pem<B: AsRef<[u8]>>(
        hash: SHALevel,
        private_key: B,
        public_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let public_pem = crate::pem::PemEncodedKey::read(public_key)?;
        if public_pem.classify() != &crate::pem::Classification::Ec {
            return Err(crate::errors::Error::MismatchedKey(
                "ECDSA",
                public_pem.classify().name(),
            ));
        }
        if public_pem.kind() != &crate::pem::PemKind::Public {
            return Err(crate::errors::Error::ExpectedPublicKey);
        }
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Ec {
            return Err(crate::errors::Error::MismatchedKey(
                "ECDSA",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let kp =
            signature::EcdsaKeyPair::from_pkcs8(get_signing_alg(hash), private_pem.contents()?)
                .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pkey = signature::UnparsedPublicKey::new(
            get_verification_alg(hash),
            public_pem.contents()?.to_vec(),
        );

        Ok(Self { kp, pkey, hash })
    }

    /// Create a new [`EcdsaAlgorithm`] from PKCS#8 PEM-encoded data
    ///
    /// Given a [`SHALevel`] and a private key.
    #[cfg(feature = "pem")]
    pub fn new_pkcs8_pem_from_private_key<B: AsRef<[u8]>>(
        hash: SHALevel,
        private_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Ec {
            return Err(crate::errors::Error::MismatchedKey(
                "ECDSA",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let kp =
            signature::EcdsaKeyPair::from_pkcs8(get_signing_alg(hash), private_pem.contents()?)
                .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pubkey = kp.public_key().as_ref();
        let pkey = signature::UnparsedPublicKey::new(get_verification_alg(hash), pubkey.to_vec());

        Ok(Self { kp, pkey, hash })
    }
}

impl SigningAlgorithm for EcdsaAlgorithm {
    fn kind(&self) -> super::Algorithm {
        match self.hash {
            SHALevel::SHA256 => super::Algorithm::ES256,
            SHALevel::SHA384 => super::Algorithm::ES384,
            SHALevel::SHA512 => super::Algorithm::ES512,
        }
    }

    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        let rng = rand::SystemRandom::new();
        let sig = self
            .kp
            .sign(&rng, data)
            .map_err(|_| crate::errors::Error::SigningError)?;

        Ok(b64_encode(sig.as_ref()))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error> {
        Ok(self.pkey.verify(data, signature).is_ok())
    }
}

/// An ECDSA with secp256k1 curves for signing and verifying
///
/// The message will be digested with SHA3-256 since it is more secure.
#[derive(Debug)]
pub struct Secp256k1Algorithm {
    kp: signature::EcdsaKeyPair,
    pkey: signature::UnparsedPublicKey<Vec<u8>>,
}

impl Secp256k1Algorithm {
    /// Create a new [`Secp256k1Algorithm`] from PKCS#8 bytes data
    ///
    /// Given a private key and a public key.
    pub fn new_pkcs8(private_key: &[u8], public_key: &[u8]) -> Result<Self, crate::errors::Error> {
        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
            private_key,
        )
        .map_err(|_| crate::errors::Error::InvalidKey)?;

        let pkey = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256K1_SHA3_256_FIXED,
            public_key.to_vec(),
        );

        Ok(Self { kp, pkey })
    }

    /// Create a new [`Secp256k1Algorithm`] from PKCS#8 bytes data
    ///
    /// Given a private key.
    pub fn new_pkcs8_from_private_key(private_key: &[u8]) -> Result<Self, crate::errors::Error> {
        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
            private_key,
        )
        .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pubkey = kp.public_key().as_ref();
        let pkey = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256K1_SHA3_256_FIXED,
            pubkey.to_vec(),
        );

        Ok(Self { kp, pkey })
    }

    /// Create a new [`Secp256k1Algorithm`] from PKCS#8 PEM-encoded data
    ///
    /// Given a [`SHALevel`], a private key, and a public key.
    #[cfg(feature = "pem")]
    pub fn new_pkcs8_pem<B: AsRef<[u8]>>(
        private_key: B,
        public_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let public_pem = crate::pem::PemEncodedKey::read(public_key)?;
        if public_pem.classify() != &crate::pem::Classification::Ec {
            return Err(crate::errors::Error::MismatchedKey(
                "ECDSA",
                public_pem.classify().name(),
            ));
        }
        if public_pem.kind() != &crate::pem::PemKind::Public {
            return Err(crate::errors::Error::ExpectedPublicKey);
        }
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Ec {
            return Err(crate::errors::Error::MismatchedKey(
                "ECDSA",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
            private_pem.contents()?,
        )
        .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pkey = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256K1_SHA3_256_FIXED,
            public_pem.contents()?.to_vec(),
        );

        Ok(Self { kp, pkey })
    }

    /// Create a new [`Secp256k1Algorithm`] from PKCS#8 PEM-encoded data
    ///
    /// Given a [`SHALevel`] and a private key.
    #[cfg(feature = "pem")]
    pub fn new_pkcs8_pem_from_private_key<B: AsRef<[u8]>>(
        private_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Ec {
            return Err(crate::errors::Error::MismatchedKey(
                "ECDSA",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
            private_pem.contents()?,
        )
        .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pubkey = kp.public_key().as_ref();
        let pkey = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256K1_SHA3_256_FIXED,
            pubkey.to_vec(),
        );

        Ok(Self { kp, pkey })
    }
}

impl SigningAlgorithm for Secp256k1Algorithm {
    fn kind(&self) -> super::Algorithm {
        super::Algorithm::ES256K
    }

    fn sign(&self, data: &[u8]) -> Result<String, crate::errors::Error> {
        let rng = rand::SystemRandom::new();
        let sig = self
            .kp
            .sign(&rng, data)
            .map_err(|_| crate::errors::Error::SigningError)?;

        Ok(b64_encode(sig.as_ref()))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, crate::errors::Error> {
        Ok(self.pkey.verify(data, signature).is_ok())
    }
}
