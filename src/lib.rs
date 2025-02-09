pub mod errors;
pub mod models;
pub mod signing;
pub mod utils;
pub mod validator;

pub use models::*;
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "es256k")]
pub use signing::Secp256k1Algorithm;
pub use signing::{
    Algorithm, Ed25519Algorithm, HmacAlgorithm, RsaAlgorithm, RsaPssAlgorithm, SHALevel,
    SigningAlgorithm,
};

/// Encode a JSON serializable type `T` into a JWT token using the given `SigningAlgorithm` `S`.
///
/// # Errors
///
/// This function will error if the `SigningAlgorithm` fails to sign the message or if the
/// `T` cannot be serialized to JSON.
pub fn encode<T: Serialize, S: SigningAlgorithm>(
    data: &T,
    signer: &S,
) -> Result<String, crate::errors::Error> {
    let header = Header::from_signer(signer);

    let encoded_header = utils::b64_encode_serde(&header)?;
    let encoded_data = utils::b64_encode_serde(data)?;

    let message = [encoded_header, encoded_data].join(".");
    println!("message A: {:?}", message.as_bytes());
    let signature = signer.sign(message.as_bytes())?;

    Ok([message, signature].join("."))
}

/// Decode a JWT token into a deserialized type `D` using the given `SigningAlgorithm` `S` and
/// validators `V`.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided token is not a valid JWT token
/// * The given `SigningAlgorithm` `S` fails to verify the signature
/// * The given `SigningAlgorithm` `S` does not match the algorithm specified in the JWT header
/// * The given validators `V` fail to validate the claims or the deserialized data
///
/// # Validators
///
/// Validators are used to validate the claims and the deserialized data. The validators are
/// checked in order, and if any of them fail, the function will return an error.
pub fn decode<T: DeserializeOwned, S: SigningAlgorithm>(
    token: &str,
    signer: &S,
    validator: &[impl validator::Validator],
) -> Result<TokenData<T>, crate::errors::Error> {
    let (signature, message) = split_two(token)?;
    let (claims_or_data, header) = split_two(message)?;

    let header = Header::from_encoded(header)?;

    if header.typ != Some("JWT".to_string()) {
        return Err(errors::Error::InvalidToken);
    }

    // Check if signer kind and header alg match
    if signer.kind() != header.alg {
        return Err(errors::Error::InvalidAlgorithm(signer.kind(), header.alg));
    }

    // Validate signature
    let signature = utils::b64_decode(signature)?;
    if !signer.verify(message.as_bytes(), &signature)? {
        return Err(errors::Error::InvalidSignature);
    }

    let claims_or_data = utils::b64_decode(claims_or_data)?;
    let claims = serde_json::from_slice::<ClaimsForValidation>(&claims_or_data)
        .map_err(errors::Error::DeserializeError)?;
    let data =
        serde_json::from_slice::<T>(&claims_or_data).map_err(errors::Error::DeserializeError)?;

    // Validate claims
    for v in validator {
        // Validate claims part
        v.validate(&claims)?;
        // Validate actual data
        v.validate_full::<T>(&data)?;
    }

    // Success!
    Ok(TokenData::new(header, data))
}

/// Decode the header part of a token.
///
/// Decodes the first part of a token, which contains the header. The header
/// is returned as a `Header` struct.
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
