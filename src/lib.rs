//! # jwt-lc-rs
//!
//! A simple library for generating and verifying JWTs using [`aws-lc-rs`](https://docs.rs/aws-lc-rs)
//!
//! This library does not implement the JWS specifications from the RFCs.
//!
//! ## Supported algorithms
//! - `HS256`
//! - `HS384`
//! - `HS512`
//! - `RS256`
//! - `RS384`
//! - `RS512`
//! - `PS256`
//! - `PS384`
//! - `PS512`
//! - `ES256`
//! - `ES384`
//! - `ES512`
//! - `ES256K`
//! - `EdDSA` (Ed25519)
//!
//! ## Supported native validations
//!
//! **Header**:
//! - `typ` (Type), always check it is set to `"JWT"` (case-sensitive)
//! - `alg` (Algorithm), verify that the requested algorithm is what you expect.
//!
//! **Claims/body**:
//! - `iss` (Issuer)
//! - `sub` (Subject)
//! - `aud` (Audience)
//! - `exp` (Expiry)
//! - `nbf` (Not before)
//! - Any other custom validation can be implemented using the [`validator::Validation`] trait
//!
//! **Note**: While we don't provide validation for `jti` and `iat`, you can implement it using the [`validator::Validation`] trait.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod errors;
pub mod models;
#[cfg(feature = "pem")]
pub(crate) mod pem;
pub mod signing;
pub mod utils;
pub mod validator;

pub use models::{ClaimsForValidation, Header, TokenData};
use serde::{de::DeserializeOwned, Serialize};
/// Re-export of our signing algorithms
pub use signing::{
    Algorithm, EcdsaAlgorithm, Ed25519Algorithm, HmacAlgorithm, RsaAlgorithm, RsaPssAlgorithm,
    SHALevel, Secp256k1Algorithm, Signer, SigningAlgorithm,
};

/// Re-export of [`simple_asn1::from_der`] function.
pub use simple_asn1::from_der as asn1_decode_der;
use validator::Validator;

/// Encode a JSON serializable type into a JWT token using a given [`Signer`].
///
/// If you need to use your own signer, use [`encode_custom`] instead.
///
/// # Errors
///
/// This function will error if the `SigningAlgorithm` fails to sign the message or if the
/// `data` cannot be serialized to JSON.
pub fn encode<T: Serialize>(data: &T, signer: &Signer) -> Result<String, crate::errors::Error> {
    encode_internal(data, signer.kind(), |message| signer.sign(message))
}

/// Encode a JSON serializable type into a JWT token using a given [`SigningAlgorithm`].
///
/// If you don't need to implement custom signers, use [`encode`] instead.
///
/// # Errors
///
/// This function will error if the `SigningAlgorithm` fails to sign the message or if the
/// `data` cannot be serialized to JSON.
pub fn encode_custom<T: Serialize>(
    data: &T,
    signer: &impl SigningAlgorithm,
) -> Result<String, crate::errors::Error> {
    encode_internal(data, signer.kind(), |message| signer.sign(message))
}

/// Decode a JWT token into a deserialized type using a given [`Signer`] and
/// a set of validators via [`Validator`].
///
/// If you need to use your own verification, use [`decode_custom`] instead.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided token is not a valid JWT token
/// * The given [`Signer`] fails to verify the signature
/// * The given [`Signer`] does not match the algorithm specified in the JWT header
/// * The given validators fail to validate the claims or the deserialized data
///
/// # Validators
///
/// Validators are used to validate the claims and the deserialized data. The validators are
/// checked in order, and if any of them fail, the function will return an error.
/// If you don't want to validate the claims, you can use [`validator::Validator::default`].
pub fn decode<T: DeserializeOwned>(
    token: &str,
    signer: &Signer,
    validator: &Validator,
) -> Result<TokenData<T>, crate::errors::Error> {
    decode_internal(
        token,
        |message, signature| signer.verify(message, signature),
        validator,
        signer.kind(),
    )
}

/// Decode a JWT token into a deserialized type using a given [`SigningAlgorithm`] and
/// a set of validators via [`Validator`].
///
/// If you don't need to implement custom signers, use [`decode`] instead.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided token is not a valid JWT token
/// * The given [`SigningAlgorithm`] fails to verify the signature
/// * The given [`SigningAlgorithm`] does not match the algorithm specified in the JWT header
/// * The given validators fail to validate the claims or the deserialized data
///
/// # Validators
///
/// Validators are used to validate the claims and the deserialized data. The validators are
/// checked in order, and if any of them fail, the function will return an error.
/// If you don't want to validate the claims, you can use [`validator::Validator::default`].
pub fn decode_custom<T: DeserializeOwned>(
    token: &str,
    signer: &impl SigningAlgorithm,
    validator: &Validator,
) -> Result<TokenData<T>, crate::errors::Error> {
    decode_internal(
        token,
        |message, signature| signer.verify(message, signature),
        validator,
        signer.kind(),
    )
}

/// Decode the header part of a token.
///
/// Decodes the first part of a token, which contains the header. The header
/// is returned as a [`Header`] struct.
///
/// # Errors
///
/// The function will return an error if the token is invalid or if the header
/// could not be decoded.
pub fn decode_header(token: &str) -> Result<Header, crate::errors::Error> {
    let (_, message) = split_two(token)?;
    let (_, header) = split_two(message)?;
    Header::from_encoded(header)
}

fn split_two(token: &str) -> Result<(&str, &str), crate::errors::Error> {
    let mut parts = token.rsplitn(2, '.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(first), Some(second), None) => Ok((first, second)),
        _ => Err(errors::Error::InvalidToken),
    }
}

fn encode_internal<T: Serialize, F>(
    data: &T,
    alg: Algorithm,
    signer_fn: F,
) -> Result<String, crate::errors::Error>
where
    F: Fn(&[u8]) -> Result<String, crate::errors::Error>,
{
    let header = Header {
        typ: Some("JWT".to_string()),
        alg,
    };

    let encoded_header = utils::b64_encode_serde(&header)?;
    let encoded_data = utils::b64_encode_serde(data)?;

    let message = [encoded_header, encoded_data].join(".");
    let signature = signer_fn(message.as_bytes())?;

    Ok([message, signature].join("."))
}

fn decode_internal<T: DeserializeOwned, F>(
    token: &str,
    verify_fn: F,
    validator: &Validator,
    expect_alg: Algorithm,
) -> Result<TokenData<T>, crate::errors::Error>
where
    F: Fn(&[u8], &[u8]) -> Result<bool, crate::errors::Error>,
{
    let (signature, message) = split_two(token)?;
    let (claims_or_data, header) = split_two(message)?;

    let header = Header::from_encoded(header)?;

    // Check for JWT type
    if header.typ != Some("JWT".to_string()) {
        return Err(errors::Error::InvalidToken);
    }

    // Check if signer kind and header alg match
    if header.alg != expect_alg {
        return Err(errors::Error::InvalidAlgorithm(expect_alg, header.alg));
    }

    // Validate signature
    let signature = utils::b64_decode(signature)?;

    if !verify_fn(message.as_bytes(), &signature)? {
        return Err(errors::Error::InvalidSignature);
    }

    // Decode claims
    let claims_or_data = utils::b64_decode(claims_or_data)?;
    // Parse claims
    let claims = serde_json::from_slice::<ClaimsForValidation>(&claims_or_data)
        .map_err(errors::Error::DeserializeError)?;
    // Parse as data
    let data =
        serde_json::from_slice::<T>(&claims_or_data).map_err(errors::Error::DeserializeError)?;

    // Validate claims
    validator.validate(&claims)?;

    // Success!
    Ok(TokenData::new(header, data))
}
