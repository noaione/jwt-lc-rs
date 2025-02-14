//! A collection of built-in validator implementations

use std::collections::HashSet;

use serde::de::DeserializeOwned;

use crate::{is_subset, ClaimsForValidation, MaybeMultiString, TryParse};

/// A trait for validating token data
pub trait Validator {
    /// The function to validate token data
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError>;

    fn validate_full<T: DeserializeOwned>(
        &self,
        data: &T,
    ) -> Result<(), crate::errors::ValidationError>;
}

/// Validate the `iss` or Issuer claim
pub struct IssuerValidator {
    issuer: HashSet<String>,
}

impl IssuerValidator {
    /// Create a new [`IssuerValidator`]
    ///
    /// Accepts a list of issuer that can be converted to a [`String`]
    pub fn new<T: ToString>(issuer: &[T]) -> Self {
        Self {
            issuer: issuer.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Validator for IssuerValidator {
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        match &data.iss {
            TryParse::Parsed(MaybeMultiString::Single(iss)) => {
                if !self.issuer.contains(&**iss) {
                    Err(crate::errors::ValidationError::InvalidIssuer(
                        self.issuer.clone(),
                    ))
                } else {
                    Ok(())
                }
            }
            TryParse::Parsed(MaybeMultiString::Multiple(iss)) => {
                if !is_subset(&self.issuer, iss) {
                    Err(crate::errors::ValidationError::InvalidIssuer(
                        self.issuer.clone(),
                    ))
                } else {
                    Ok(())
                }
            }
            TryParse::FailedToParse => Err(crate::errors::ValidationError::FailedToParse(
                "Issuer".to_string(),
            )),
            TryParse::NotPresent => Err(crate::errors::ValidationError::MissingField(
                "Issuer".to_string(),
            )),
        }
    }

    fn validate_full<T: DeserializeOwned>(
        &self,
        _: &T,
    ) -> Result<(), crate::errors::ValidationError> {
        // We don't verify any data here
        Ok(())
    }
}

/// Validate the `aud` or Audience claim
pub struct AudienceValidator {
    audiences: HashSet<String>,
}

impl AudienceValidator {
    /// Create a new [`AudienceValidator`]
    ///
    /// Accepts a list of issuer that can be converted to a [`String`]
    pub fn new<T: ToString>(issuer: &[T]) -> Self {
        Self {
            audiences: issuer.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Validator for AudienceValidator {
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        match &data.iss {
            TryParse::Parsed(MaybeMultiString::Single(iss)) => {
                if !self.audiences.contains(&**iss) {
                    Err(crate::errors::ValidationError::InvalidAudience(
                        self.audiences.clone(),
                    ))
                } else {
                    Ok(())
                }
            }
            TryParse::Parsed(MaybeMultiString::Multiple(iss)) => {
                if !is_subset(&self.audiences, iss) {
                    Err(crate::errors::ValidationError::InvalidAudience(
                        self.audiences.clone(),
                    ))
                } else {
                    Ok(())
                }
            }
            TryParse::FailedToParse => Err(crate::errors::ValidationError::FailedToParse(
                "Audience".to_string(),
            )),
            TryParse::NotPresent => Err(crate::errors::ValidationError::MissingField(
                "Audience".to_string(),
            )),
        }
    }

    fn validate_full<T: DeserializeOwned>(
        &self,
        _: &T,
    ) -> Result<(), crate::errors::ValidationError> {
        // We don't verify any data here
        Ok(())
    }
}

/// Validate the `sub` or Subject claim
pub struct SubjectValidator {
    subject: String,
}

impl SubjectValidator {
    /// Create a new [`SubjectValidator`]
    ///
    /// Accepts a single subject that can be converted to a [`String`]
    pub fn new<T: ToString>(subject: T) -> Self {
        Self {
            subject: subject.to_string(),
        }
    }
}

impl Validator for SubjectValidator {
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        match &data.sub {
            TryParse::FailedToParse => Err(crate::errors::ValidationError::FailedToParse(
                "Subject".to_string(),
            )),
            TryParse::NotPresent => Err(crate::errors::ValidationError::MissingField(
                "Subject".to_string(),
            )),
            TryParse::Parsed(sub) => {
                if *sub != self.subject {
                    Err(crate::errors::ValidationError::InvalidSubject(
                        self.subject.clone(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn validate_full<T: DeserializeOwned>(
        &self,
        _: &T,
    ) -> Result<(), crate::errors::ValidationError> {
        // We don't verify any data here
        Ok(())
    }
}

/// Validate the `sub` or Subject claim
pub struct ExpiryValidator {
    expiry: u64,
    grace_period: u64,
}

impl ExpiryValidator {
    /// Create a new [`ExpiryValidator`]
    ///
    /// Accepts timestamp-like object, which can be converted to a [`u64`]
    ///
    /// By default, this has 5 seconds of grace period if it's timestamp format.
    pub fn new(expiry: impl Into<u64>) -> Self {
        Self {
            expiry: expiry.into(),
            grace_period: 5,
        }
    }

    /// Set the grace period for the validator
    ///
    /// If the token has expired, allow up to `grace_period` seconds of extra
    /// time before actually rejecting the token.
    ///
    /// The default is 5 seconds.
    pub fn with_grace_period(mut self, grace_period: u64) -> Self {
        self.grace_period = grace_period;
        self
    }
}

impl Validator for ExpiryValidator {
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        match data.exp {
            TryParse::Parsed(exp) => {
                if exp > self.expiry {
                    Ok(())
                } else {
                    // Grace period allows for some clock skew
                    // Use saturating to prevent underflow/overflow
                    let sat_exp = exp.saturating_sub(self.grace_period);
                    if sat_exp > self.expiry {
                        Ok(())
                    } else {
                        Err(crate::errors::ValidationError::TokenExpired(
                            exp,
                            self.expiry,
                        ))
                    }
                }
            }
            TryParse::FailedToParse => Err(crate::errors::ValidationError::FailedToParse(
                "Expiry".to_string(),
            )),
            TryParse::NotPresent => Err(crate::errors::ValidationError::MissingField(
                "Expiry".to_string(),
            )),
        }
    }

    fn validate_full<T: DeserializeOwned>(
        &self,
        _: &T,
    ) -> Result<(), crate::errors::ValidationError> {
        Ok(())
    }
}

/// Validate the `nbf` or Not Before claim
pub struct NotBeforeValidator {
    nbf: u64,
}

impl NotBeforeValidator {
    /// Create a new [`NotBeforeValidator`]
    ///
    /// Accepts timestamp-like object, which can be converted to a [`u64`]
    pub fn new(nbf: impl Into<u64>) -> Self {
        Self { nbf: nbf.into() }
    }

    /// Create a new [`NotBeforeValidator`] from the current UNIX timestamp.
    ///
    /// Internally this use [`std::time::SystemTime`], so this follows your
    /// system clock. If your system time is before the [`UNIX EPOCH`](std::time::SystemTime::UNIX_EPOCH), this will
    /// set the `nbf` to 0.
    pub fn now() -> Self {
        let current = std::time::SystemTime::now();
        match current.duration_since(std::time::SystemTime::UNIX_EPOCH) {
            Ok(duration) => Self::new(duration.as_secs()),
            Err(_) => Self::new(0u64),
        }
    }
}

impl Validator for NotBeforeValidator {
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        match data.nbf {
            TryParse::Parsed(nbf) => {
                if nbf <= self.nbf {
                    Ok(())
                } else {
                    Err(crate::errors::ValidationError::TokenNotYetValid(
                        nbf, self.nbf,
                    ))
                }
            }
            TryParse::FailedToParse => Err(crate::errors::ValidationError::FailedToParse(
                "Not Before".to_string(),
            )),
            TryParse::NotPresent => Err(crate::errors::ValidationError::MissingField(
                "Not Before".to_string(),
            )),
        }
    }

    fn validate_full<T: DeserializeOwned>(
        &self,
        _: &T,
    ) -> Result<(), crate::errors::ValidationError> {
        Ok(())
    }
}

/// A simple validator that does nothing
///
/// Used if you don't want to do any extra validation except signature checking.
pub struct NoopValidator;

impl Validator for NoopValidator {
    fn validate(&self, _: &ClaimsForValidation<'_>) -> Result<(), crate::errors::ValidationError> {
        Ok(())
    }

    fn validate_full<T: DeserializeOwned>(
        &self,
        _: &T,
    ) -> Result<(), crate::errors::ValidationError> {
        Ok(())
    }
}
