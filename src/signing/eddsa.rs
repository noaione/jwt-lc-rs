//! An EdDSA/ED25519 algorithm for signing and verifying
//!
//! **NOTE**:
//! We only support EdDSA/ED25519 in PKCS#8 encoding format.
//!
//! The key usually starts with:
//! ```text
//! -----BEGIN PUBLIC KEY-----
//! ```
//!
//! ## Generating
//!
//! You can use `openssl` to generate a key pair:
//! ```bash
//! openssl genpkey -algorithm ED25519 -out private_ed25519.pem
//! openssl pkey -in private_ed25519.pem -pubout -out public_ed25519.pem
//! ```
//!
//! To convert to `DER` format:
//! ```bash
//! openssl pkcs8 -topk8 -in private_ed25519.pem -outform DER -nocrypt -out private_ed25519.der
//! openssl pkey -in public_ed25519.pem -pubin -outform DER -out public_ed25519.der
//! ```
//!
//! ## Examples
//!
//! Using the DER-encoded format:
//! ```rust,no_run
//! use jwt_lc_rs::Ed25519Algorithm;
//! use serde::{Deserialize, Serialize};
//!
//! // Import key-pair
//! let private = std::fs::read("private_ed25519.der").unwrap();
//! let public = std::fs::read("public_ed25519.der").unwrap();
//!
//! // Initialize the signing algorithm
//! let alg = Ed25519Algorithm::new_der(&private, &public).unwrap();
//!
//! // Sign a message
//! #[derive(Serialize, Deserialize, Debug)]
//! struct SignedMessage {
//!     text: String,
//! }
//!
//! let data = SignedMessage { text: "Hello, world!".to_string() };
//!
//! let signer = jwt_lc_rs::Signer::Ed25519(alg);
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
//! # let alg = jwt_lc_rs::Ed25519Algorithm::new_der(b"", b"").unwrap();
//! # let signer = jwt_lc_rs::Signer::Ed25519(alg);
//!
//! let decoded: jwt_lc_rs::TokenData<SignedMessage> = jwt_lc_rs::decode(
//!     &encoded,
//!     &signer,
//!     &Validator::default(), // You can also use validator like `jwt_lc_rs::validator::ExpiryValidator`
//! ).unwrap();
//!
//! println!("JWT Decoded: {:?}", decoded.get_claims());
//! ```

use aws_lc_rs::signature::{self, KeyPair};

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
    pub fn new_der(private_key: &[u8], public_key: &[u8]) -> Result<Self, crate::errors::Error> {
        let kp = signature::Ed25519KeyPair::from_pkcs8(private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;
        let pkey = signature::UnparsedPublicKey::new(&signature::ED25519, public_key.to_vec());

        Ok(Self { kp, pkey })
    }

    /// Create a new [`Ed25519Algorithm`] from DER data
    ///
    /// Given a private key.
    /// Public key will automatically inferred.
    pub fn new_der_from_private_key(private_key: &[u8]) -> Result<Self, crate::errors::Error> {
        let kp = signature::Ed25519KeyPair::from_pkcs8(private_key)
            .map_err(|_| crate::errors::Error::InvalidKey)?;

        let pub_key = kp.public_key().as_ref();
        let pkey = signature::UnparsedPublicKey::new(&signature::ED25519, pub_key.to_vec());

        Ok(Self { kp, pkey })
    }

    /// Create a new [`Ed25519Algorithm`] from PEM data
    ///
    /// Given a private key and a public key.
    #[cfg(feature = "pem")]
    pub fn new_pem<B: AsRef<[u8]>>(
        private_key: B,
        public_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let public_pem = crate::pem::PemEncodedKey::read(public_key)?;
        if public_pem.classify() != &crate::pem::Classification::Ed {
            return Err(crate::errors::Error::MismatchedKey(
                "Ed25519",
                public_pem.classify().name(),
            ));
        }
        if public_pem.kind() != &crate::pem::PemKind::Public {
            return Err(crate::errors::Error::ExpectedPublicKey);
        }
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Ed {
            return Err(crate::errors::Error::MismatchedKey(
                "Ed25519",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        Self::new_der(private_pem.contents()?, public_pem.contents()?)
    }

    /// Create a new [`Ed25519Algorithm`] from PEM data
    ///
    /// Given a private key.
    /// Public key will automatically inferred.
    #[cfg(feature = "pem")]
    pub fn new_pem_from_private_key<B: AsRef<[u8]>>(
        private_key: B,
    ) -> Result<Self, crate::errors::Error> {
        let private_pem = crate::pem::PemEncodedKey::read(private_key)?;
        if private_pem.classify() != &crate::pem::Classification::Ed {
            return Err(crate::errors::Error::MismatchedKey(
                "Ed25519",
                private_pem.classify().name(),
            ));
        }
        if private_pem.kind() != &crate::pem::PemKind::Private {
            return Err(crate::errors::Error::ExpectedPrivateKey);
        }

        Self::new_der_from_private_key(private_pem.contents()?)
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
