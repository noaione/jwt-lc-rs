//! A collection of built-in validator implementations

use std::collections::HashSet;

use crate::models::{is_subset, MaybeMultiString, TryParse};
use crate::ClaimsForValidation;

/// A trait for validating token data
pub trait Validation {
    /// Validate the token data from the deserialized [`ClaimsForValidation`] information.
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
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

impl Validation for IssuerValidator {
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

impl Validation for AudienceValidator {
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        match &data.aud {
            TryParse::Parsed(MaybeMultiString::Single(aud)) => {
                if !self.audiences.contains(&**aud) {
                    Err(crate::errors::ValidationError::InvalidAudience(
                        self.audiences.clone(),
                    ))
                } else {
                    Ok(())
                }
            }
            TryParse::Parsed(MaybeMultiString::Multiple(aud)) => {
                if !is_subset(&self.audiences, aud) {
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

impl Validation for SubjectValidator {
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
}

/// Validate the `exp` or Expiry claim
pub struct ExpiryValidator {
    grace_period: u64,
}

impl ExpiryValidator {
    /// Create a new [`ExpiryValidator`]
    ///
    /// Accepts a grace period in seconds, which will be converted to a [`u64`]
    pub fn new(grace_period: impl Into<u64>) -> Self {
        Self {
            grace_period: grace_period.into(),
        }
    }
}

impl Validation for ExpiryValidator {
    fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        match data.exp {
            TryParse::Parsed(exp) => {
                let now_time = now_timestamp();
                if exp > now_time {
                    Ok(())
                } else {
                    // Grace period allows for some clock skew
                    // Use saturating to prevent underflow/overflow
                    let sat_exp = exp.saturating_add(self.grace_period);
                    if sat_exp > now_time {
                        Ok(())
                    } else {
                        Err(crate::errors::ValidationError::TokenExpired(exp, now_time))
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
        Self::new(now_timestamp())
    }
}

impl Validation for NotBeforeValidator {
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
}

pub struct Validator {
    validators: Vec<Box<dyn Validation>>,
}

impl Validator {
    /// Create a new [`Validator`] instances
    pub fn new(validators: Vec<Box<dyn Validation>>) -> Self {
        Self { validators }
    }

    /// Add a new validator to the list of validators
    ///
    /// This method consumes the current [`Validator`] and returns a new [`Validator`]
    /// with the additional validator.
    ///
    /// The validator is added to the end of the list of validators, and the
    /// validation order is determined by the order of the validators in the
    /// list.
    pub fn add(mut self, validator: impl Validation + 'static) -> Self {
        self.validators.push(Box::new(validator));
        self
    }

    /// Add a new validator to the list of validators
    ///
    /// This method consumes the current [`Validator`] and returns a new [`Validator`]
    /// with the additional validator.
    ///
    /// The validator is added to the end of the list of validators, and the
    /// validation order is determined by the order of the validators in the
    /// list.
    pub fn add_boxed(mut self, validator: Box<dyn Validation>) -> Self {
        self.validators.push(validator);
        self
    }

    /// Validate a token using a set of validators
    pub(crate) fn validate(
        &self,
        data: &ClaimsForValidation<'_>,
    ) -> Result<(), crate::errors::ValidationError> {
        for validator in &self.validators {
            validator.validate(data)?
        }
        Ok(())
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new(vec![])
    }
}

/// Quickly get the current timestamp
///
/// If failed to convert the duration since, it will return 0
fn now_timestamp() -> u64 {
    let current = std::time::SystemTime::now();
    match current.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0u64,
    }
}
