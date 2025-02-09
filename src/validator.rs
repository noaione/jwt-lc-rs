//! Validator module

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

pub struct IssuerValidator {
    issuer: HashSet<String>,
}

impl IssuerValidator {
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

pub struct AudienceValidator {
    audiences: HashSet<String>,
}

impl AudienceValidator {
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

pub struct SubjectValidator {
    subject: String,
}

impl SubjectValidator {
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
