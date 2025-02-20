//! An ECDSA algorithm for signing and verifying
//!
//! The following curves variant are supported:
//! - `P-256` (with SHA-256)
//! - `P-384` (with SHA3-384)
//! - `P-521` (with SHA3-512)
//! - `P-256K1/secp256k1` (with SHA3-256)
//!
//! **NOTE**:
//! We only support ECDSA in PKCS#8 encoding format.
//!
//! The key usually starts with:
//! ```text
//! -----BEGIN PUBLIC KEY-----
//! ```
//!
//! Instead of:
//! ```text
//! -----BEGIN EC PUBLIC KEY-----
//! ```
//!
//! ## Generating
//!
//! You can use `openssl` to generate a key pair:
//! ```bash
//! # NIST P-256
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private_ecdsa_p256.pem
//! openssl pkey -in private_ecdsa_p256.pem -pubout -out public_ecdsa_p256.pem
//!
//! # NIST P-384
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out private_ecdsa_p384.pem
//! openssl pkey -in private_ecdsa_p384.pem -pubout -out public_ecdsa_p384.pem
//!
//! # NIST P-521
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out private_ecdsa_p521.pem
//! openssl pkey -in private_ecdsa_p521.pem -pubout -out public_ecdsa_p521.pem
//!
//! # secp256k1
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out private_ecdsa_p256k1.pem
//! openssl pkey -in private_ecdsa_p256k1.pem -pubout -out public_ecdsa_p256k1.pem
//! ```
//!
//! To convert to `DER` format:
//! ```bash
//! # Convert private keys from PEM to DER
//! openssl pkcs8 -topk8 -in private_ecdsa_p256.der -outform DER -nocrypt -out private_ecdsa_p256.der
//! openssl pkcs8 -topk8 -in private_ecdsa_p384.der -outform DER -nocrypt -out private_ecdsa_p384.der
//! openssl pkcs8 -topk8 -in private_ecdsa_p521.der -outform DER -nocrypt -out private_ecdsa_p521.der
//! openssl pkcs8 -topk8 -in private_ecdsa_p256k1.der -outform DER -nocrypt -out private_ecdsa_p256k1.der
//!
//! # Convert public keys from PEM to DER
//! openssl pkey -in public_ecdsa_p256.pem -pubin -outform DER -out public_ecdsa_p256.der
//! openssl pkey -in public_ecdsa_p384.pem -pubin -outform DER -out public_ecdsa_p384.der
//! openssl pkey -in public_ecdsa_p521.pem -pubin -outform DER -out public_ecdsa_p521.der
//! openssl pkey -in public_ecdsa_p256k1.pem -pubin -outform DER -out public_ecdsa_p256k1.der
//! ```
//!
//! ## Examples
//!
//! **NOTE**: You should use the same [`SHALevel`] with your curve.
//! - `P-256` -> [`SHALevel::SHA256`]
//! - `P-384` -> [`SHALevel::SHA384`]
//! - `P-521` -> [`SHALevel::SHA512`]
//!
//! Using the DER-encoded format with NIST P-384 curves (SHA3-384):
//! ```rust,no_run
//! use jwt_lc_rs::{EcdsaAlgorithm, SHALevel};
//! use serde::{Deserialize, Serialize};
//!
//! // Import key-pair
//! let private = std::fs::read("private_ecdsa_p384.der").unwrap();
//! let public = std::fs::read("public_ecdsa_p384.der").unwrap();
//!
//! // Initialize the signing algorithm
//! let alg = EcdsaAlgorithm::new_der(SHALevel::SHA384, &private, &public).unwrap();
//!
//! // Sign a message
//! #[derive(Serialize, Deserialize, Debug)]
//! struct SignedMessage {
//!     text: String,
//! }
//!
//! let data = SignedMessage { text: "Hello, world!".to_string() };
//!
//! let signer = jwt_lc_rs::Signer::Ecdsa(alg);
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
//! # let alg = jwt_lc_rs::EcdsaAlgorithm::new_der(jwt_lc_rs::SHALevel::SHA384, b"", b"").unwrap();
//! # let signer = jwt_lc_rs::Signer::Ecdsa(alg);
//!
//! let decoded: jwt_lc_rs::TokenData<SignedMessage> = jwt_lc_rs::decode(
//!     &encoded,
//!     &signer,
//!     &Validator::default(), // You can also use validator like `jwt_lc_rs::validator::ExpiryValidator`
//! ).unwrap();
//!
//! println!("JWT Decoded: {:?}", decoded.get_claims());
//! ```
//!
//! Using **P-256K1**:
//! ```rust,no_run
//! use jwt_lc_rs::Secp256k1Algorithm;
//! use serde::{Deserialize, Serialize};
//!
//! // Import key-pair
//! let private = std::fs::read("private_ecdsa_p256k1.der").unwrap();
//! let public = std::fs::read("public_ecdsa_p256k1.der").unwrap();
//!
//! // Initialize the signing algorithm
//! let alg = Secp256k1Algorithm::new_der(&private, &public).unwrap();
//!
//! // Sign a message
//! #[derive(Serialize, Deserialize, Debug)]
//! struct SignedMessage {
//!     text: String,
//! }
//!
//! let data = SignedMessage { text: "Hello, world!".to_string() };
//!
//! let signer = jwt_lc_rs::Signer::Secp256k1(alg);
//! let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
//! println!("JWT Encoded: {}", encoded);
//! ```

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
    pub fn new_der(
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
    pub fn new_der_from_private_key(
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
    pub fn new_pem<B: AsRef<[u8]>>(
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
    pub fn new_pem_from_private_key<B: AsRef<[u8]>>(
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
    pub fn new_der(private_key: &[u8], public_key: &[u8]) -> Result<Self, crate::errors::Error> {
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
    pub fn new_der_from_private_key(private_key: &[u8]) -> Result<Self, crate::errors::Error> {
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
    pub fn new_pem<B: AsRef<[u8]>>(
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
    pub fn new_pem_from_private_key<B: AsRef<[u8]>>(
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
