//! A collection of JWT data structures

use std::{borrow::Cow, collections::HashSet, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::utils::b64_decode;

/// A really basic JWT header data
///
/// The `typ` field will be automatically set to `"JWT"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Header {
    /// The type of JWS: it can only be "JWT" here
    ///
    /// Defined in [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The algorithm used
    ///
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    pub alg: crate::signing::Algorithm,
}

impl Header {
    /// Create a new JWT header from a signer.
    ///
    /// This method will create a new JWT header with the correct `typ` field set to `"JWT"` and the
    /// `alg` field set to the algorithm used by the signer.
    pub(crate) fn from_signer(signer: &impl crate::signing::SigningAlgorithm) -> Self {
        Self {
            typ: Some("JWT".to_string()),
            alg: signer.kind(),
        }
    }

    /// Deserialize a JWT header from a base64url-encoded string.
    ///
    /// # Errors
    ///
    /// This function will error if the input string is not a valid base64url-encoded string or if
    /// the decoded data is not a valid JWT header.
    pub(crate) fn from_encoded(encoded: &str) -> Result<Self, crate::errors::Error> {
        let decoded = b64_decode(encoded)?;
        serde_json::from_slice(&decoded).map_err(crate::errors::Error::DeserializeError)
    }
}

/// The data of the decoded token
///
/// Contains the header and the claims/data
#[derive(Debug, Clone)]
pub struct TokenData<T> {
    header: Header,
    claims: T,
}

impl<T> TokenData<T> {
    pub(crate) fn new(header: Header, claims: T) -> Self {
        Self { header, claims }
    }

    /// Get a reference to the claims of the token
    ///
    /// This is the payload of the token, the actual data you want to access
    pub fn get_claims(&self) -> &T {
        &self.claims
    }

    /// Get the inner claims of the token
    ///
    /// This will move the claims out of the `TokenData` and return them.
    pub fn into_claims(self) -> T {
        self.claims
    }

    /// Get a reference to the header of the token
    ///
    /// This is the part of the token that contains the type of the token and the algorithm used
    /// to sign it.
    pub fn get_header(&self) -> &Header {
        &self.header
    }
}

/// Claims for validation
///
/// A *mostly* optional struct that can be used to validate the claims of a token
#[derive(Deserialize)]
pub struct ClaimsForValidation<'a> {
    /// Expiration Time, in seconds since the Unix epoch
    #[serde(deserialize_with = "numeric_type", default)]
    pub exp: TryParse<u64>,
    /// Not Before, in seconds since the Unix epoch
    #[serde(deserialize_with = "numeric_type", default)]
    pub nbf: TryParse<u64>,
    /// Issued At, in seconds since the Unix epoch
    #[serde(deserialize_with = "numeric_type", default)]
    pub iat: TryParse<u64>,
    /// Subject issuer
    #[serde(borrow)]
    pub sub: TryParse<Cow<'a, str>>,
    /// Issuer
    #[serde(borrow)]
    pub iss: TryParse<MaybeMultiString<'a>>,
    /// Audience
    #[serde(borrow)]
    pub aud: TryParse<MaybeMultiString<'a>>,
    /// JWT IDs, case sensitive string
    #[serde(borrow)]
    pub jti: TryParse<Cow<'a, str>>,
}

/// A type that will try to parse a value into a specific type
#[derive(Debug)]
pub enum TryParse<T> {
    /// The value was successfully parsed
    Parsed(T),
    /// The value could not be parsed
    FailedToParse,
    /// The value is not present
    NotPresent,
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for TryParse<T> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(deserializer) {
            Ok(Some(value)) => TryParse::Parsed(value),
            Ok(None) => TryParse::NotPresent,
            Err(_) => TryParse::FailedToParse,
        })
    }
}

impl<T> Default for TryParse<T> {
    fn default() -> Self {
        Self::NotPresent
    }
}

/// A borrowed string type that can either be a single string or a set of strings
#[derive(Deserialize)]
#[serde(untagged)]
pub enum MaybeMultiString<'a> {
    /// A single string
    Single(#[serde(borrow)] Cow<'a, str>),
    /// A set of strings
    Multiple(#[serde(borrow)] HashSet<BorrowedCowIfPossible<'a>>),
}

/// Usually #[serde(borrow)] on [`Cow`] enables deserializing with no allocations where
/// possible (no escapes in the original str) but it does not work on e.g. [`HashSet<Cow<str>>`]
/// We use this struct in this case.
#[derive(Deserialize, PartialEq, Eq, Hash)]
pub struct BorrowedCowIfPossible<'a>(#[serde(borrow)] Cow<'a, str>);

impl std::borrow::Borrow<str> for BorrowedCowIfPossible<'_> {
    fn borrow(&self) -> &str {
        &self.0
    }
}

fn numeric_type<'de, D>(deserializer: D) -> std::result::Result<TryParse<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NumericType(PhantomData<fn() -> TryParse<u64>>);

    impl serde::de::Visitor<'_> for NumericType {
        type Value = TryParse<u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("A NumericType that can be reasonably coerced into a u64")
        }

        fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.is_finite() && value >= 0.0 && value < (u64::MAX as f64) {
                Ok(TryParse::Parsed(value.round() as u64))
            } else {
                Err(serde::de::Error::custom(
                    "NumericType must be representable as a u64",
                ))
            }
        }

        fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(TryParse::Parsed(value))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v >= 0 && v < (u64::MAX as i64) {
                Ok(TryParse::Parsed(v as u64))
            } else {
                Err(serde::de::Error::custom(
                    "NumericType must be representable as a u64",
                ))
            }
        }
    }

    match deserializer.deserialize_any(NumericType(PhantomData)) {
        Ok(ok) => Ok(ok),
        Err(_) => Ok(TryParse::FailedToParse),
    }
}

pub(crate) fn is_subset(
    reference: &HashSet<String>,
    given: &HashSet<BorrowedCowIfPossible<'_>>,
) -> bool {
    // Check that intersection is non-empty, favoring iterating on smallest
    if reference.len() < given.len() {
        reference.iter().any(|a| given.contains(&**a))
    } else {
        given.iter().any(|a| reference.contains(&*a.0))
    }
}
