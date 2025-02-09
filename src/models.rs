use std::{borrow::Cow, collections::HashSet, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::utils::b64_decode;

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
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
    pub(crate) fn from_signer(signer: &impl crate::signing::SigningAlgorithm) -> Self {
        Self {
            typ: Some("JWT".to_string()),
            alg: signer.kind(),
        }
    }

    pub(crate) fn from_encoded(encoded: &str) -> Result<Self, crate::errors::Error> {
        let decoded = b64_decode(encoded)?;
        serde_json::from_slice(&decoded).map_err(crate::errors::Error::DeserializeError)
    }
}

#[derive(Debug, Clone)]
pub struct TokenData<T> {
    header: Header,
    claims: T,
}

impl<T> TokenData<T> {
    pub(crate) fn new(header: Header, claims: T) -> Self {
        Self { header, claims }
    }

    pub fn get_claims(&self) -> &T {
        &self.claims
    }

    pub fn get_header(&self) -> &Header {
        &self.header
    }
}

#[derive(Deserialize)]
pub struct ClaimsForValidation<'a> {
    #[serde(deserialize_with = "numeric_type", default)]
    pub exp: TryParse<u64>,
    #[serde(deserialize_with = "numeric_type", default)]
    pub nbf: TryParse<u64>,
    #[serde(borrow)]
    pub sub: TryParse<Cow<'a, str>>,
    #[serde(borrow)]
    pub iss: TryParse<MaybeMultiString<'a>>,
    #[serde(borrow)]
    pub aud: TryParse<MaybeMultiString<'a>>,
}

#[derive(Debug)]
pub enum TryParse<T> {
    Parsed(T),
    FailedToParse,
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

#[derive(Deserialize)]
#[serde(untagged)]
pub enum MaybeMultiString<'a> {
    Single(#[serde(borrow)] Cow<'a, str>),
    Multiple(#[serde(borrow)] HashSet<BorrowedCowIfPossible<'a>>),
}

/// Usually #[serde(borrow)] on `Cow` enables deserializing with no allocations where
/// possible (no escapes in the original str) but it does not work on e.g. `HashSet<Cow<str>>`
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
