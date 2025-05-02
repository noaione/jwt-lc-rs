//! A collection of possible errors

use std::collections::HashSet;

/// Errors that can occur when using the library
#[derive(Debug)]
pub enum Error {
    /// Invalid private key
    InvalidKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid PEM key format
    InvalidKeyFormat,
    /// Invalid key length
    ///
    /// The first value is the expected length and the second is the actual length
    InvalidKeyLength(usize, usize),
    /// Invalid signature
    InvalidSignature,
    /// Invalid token format provided
    InvalidToken,
    /// Invalid digest size
    InvalidDigest(u32),
    /// Invalid algorithm used when creating in PEM mode
    InvalidAlgorithm(crate::signing::Algorithm, crate::signing::Algorithm),
    /// Invalid SPKI data
    InvalidSPKI,
    /// Mismatched PEM key type
    MismatchedKey(&'static str, &'static str),
    /// Expected a public key, but got private key instead.
    ExpectedPublicKey,
    /// Expected a private key, but got public key instead.
    ExpectedPrivateKey,
    /// Failed to decode base64 data
    Base64DecodeError(base64::DecodeError),
    /// There is an error occurred when trying to sign the message
    SigningError,
    /// There is an error occurred when trying to validate the signature
    VerifyError,
    /// Failed to serialize data
    ///
    /// This is a wrapper for [`serde_json::Error`]
    SerializeError(serde_json::Error),
    /// Failed to deserialize data
    ///
    /// This is a wrapper for [`serde_json::Error`]
    DeserializeError(serde_json::Error),
    /// Error when validating the token
    ///
    /// This is a wrapper for [`ValidationError`]
    ValidationError(crate::errors::ValidationError),
    /// Error when trying to parse a bytes data to PEM
    ///
    /// This is a wrapper for [`pem::PemError`]
    #[cfg(feature = "pem")]
    PemParseError(pem::PemError),
    /// Error when trying to parse a bytes data to ASM.1
    ///
    /// This is a wrapper for [`simple_asn1::ASN1DecodeErr`]
    #[cfg(feature = "pem")]
    ASN1ParseError(simple_asn1::ASN1DecodeErr),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidKeyFormat => write!(f, "Invalid key format"),
            Error::InvalidKeyLength(expect, actual) => write!(
                f,
                "Invalid key length, expected: {}, actual: {}",
                expect, actual
            ),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::InvalidToken => write!(f, "Invalid token"),
            Error::InvalidAlgorithm(expected, actual) => write!(
                f,
                "Invalid algorithm, expected: {:?}, actual: {:?}",
                expected, actual
            ),
            Error::InvalidSPKI => write!(f, "Invalid SPKI"),
            Error::InvalidDigest(expect) => write!(f, "Invalid digest size, expected {}", expect),
            Error::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            Error::SigningError => write!(f, "Failed to sign data"),
            Error::VerifyError => write!(f, "Failed to verify signature"),
            Error::SerializeError(e) => write!(f, "Failed to serialize data: {}", e),
            Error::DeserializeError(e) => write!(f, "Failed to deserialize data: {}", e),
            Error::ValidationError(e) => write!(f, "Validation error: {}", e),
            Error::MismatchedKey(expect, actual) => write!(
                f,
                "Mismatched key, expected: {:?}, actual: {:?}",
                expect, actual
            ),
            Error::ExpectedPublicKey => write!(f, "Expected public key, got private key"),
            Error::ExpectedPrivateKey => write!(f, "Expected private key, got public key"),
            #[cfg(feature = "pem")]
            Error::PemParseError(e) => write!(f, "Pem parse error: {}", e),
            #[cfg(feature = "pem")]
            Error::ASN1ParseError(e) => write!(f, "ASN1 parse error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64DecodeError(e)
    }
}

#[cfg(feature = "pem")]
impl From<pem::PemError> for Error {
    fn from(e: pem::PemError) -> Self {
        Error::PemParseError(e)
    }
}

#[cfg(feature = "pem")]
impl From<simple_asn1::ASN1DecodeErr> for Error {
    fn from(e: simple_asn1::ASN1DecodeErr) -> Self {
        Error::ASN1ParseError(e)
    }
}

/// Collection of errors that can occur when validating the token
#[derive(Debug)]
pub enum ValidationError {
    /// The issuer of the token does not match the expected issuer
    InvalidIssuer(HashSet<String>),
    /// The subject of the token does not match the expected subject
    InvalidSubject(String),
    /// The audience of the token does not match the expected audience
    InvalidAudience(HashSet<String>),
    /// The token has expired
    ///
    /// First value is the expiration time, second value is the current/before time
    TokenExpired(u64, u64),
    /// The token has not yet been valid
    ///
    /// First value is the not before time, second value is the current time
    TokenNotYetValid(u64, u64),
    /// A required field is missing
    MissingField(String),
    /// Failed to parse the token
    FailedToParse(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidIssuer(iss) => write!(f, "Invalid issuer, expected: {:?}", iss),
            ValidationError::InvalidSubject(sub) => {
                write!(f, "Invalid subject, expected: {:?}", sub)
            }
            ValidationError::InvalidAudience(aud) => {
                write!(f, "Invalid audience, expected: {:?}", aud)
            }
            ValidationError::TokenExpired(exp, before) => {
                write!(
                    f,
                    "Token expired, expired at: {} (expected before: {})",
                    exp, before
                )
            }
            ValidationError::TokenNotYetValid(nbf, current) => {
                write!(
                    f,
                    "Token not yet valid, valid from: {} (current time: {})",
                    nbf, current
                )
            }
            ValidationError::MissingField(field) => write!(f, "Missing field: {}", field),
            ValidationError::FailedToParse(field) => write!(f, "Failed to parse: {}", field),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<ValidationError> for Error {
    fn from(e: ValidationError) -> Self {
        Error::ValidationError(e)
    }
}
