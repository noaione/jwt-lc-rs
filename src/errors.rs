use std::collections::HashSet;

/// Errors that can occur when using the library
pub enum Error {
    InvalidKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidToken,
    InvalidDigest(u32),
    InvalidAlgorithm(crate::signing::Algorithm, crate::signing::Algorithm),
    Base64DecodeError(base64::DecodeError),
    SigningError,
    VerifyError,
    SerializeError(serde_json::Error),
    DeserializeError(serde_json::Error),
    ValidationError(crate::errors::ValidationError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::InvalidToken => write!(f, "Invalid token"),
            Error::InvalidAlgorithm(expected, actual) => write!(
                f,
                "Invalid algorithm, expected: {:?}, actual: {:?}",
                expected, actual
            ),
            Error::InvalidDigest(expect) => write!(f, "Invalid digest size, expected {}", expect),
            Error::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            Error::SigningError => write!(f, "Failed to sign data"),
            Error::VerifyError => write!(f, "Failed to verify signature"),
            Error::SerializeError(e) => write!(f, "Failed to serialize data: {}", e),
            Error::DeserializeError(e) => write!(f, "Failed to deserialize data: {}", e),
            Error::ValidationError(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64DecodeError(e)
    }
}

/// Collection of errors that can occur when validating the token
#[derive(Debug)]
pub enum ValidationError {
    InvalidIssuer(HashSet<String>),
    InvalidSubject(String),
    InvalidAudience(HashSet<String>),
    TokenExpired(i64),
    TokenNotYetValid(i64),
    MissingField(String),
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
            ValidationError::TokenExpired(exp) => write!(f, "Token expired, expired at: {}", exp),
            ValidationError::TokenNotYetValid(nbf) => {
                write!(f, "Token not yet valid, valid from: {}", nbf)
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
