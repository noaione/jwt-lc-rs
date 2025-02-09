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

pub fn encode<T: Serialize, S: SigningAlgorithm>(
    data: &T,
    signer: &S,
) -> Result<String, crate::errors::Error> {
    let header = Header::from_signer(signer);

    let encoded_header = utils::b64_encode_serde(&header)?;
    let encoded_data = utils::b64_encode_serde(data)?;

    let message = [encoded_header, encoded_data].join(".");
    let signature = signer.sign(message.as_bytes())?;

    Ok([message, signature].join("."))
}

pub fn decode<D: DeserializeOwned, S: SigningAlgorithm, V: validator::Validator<D>>(
    token: &str,
    signer: &S,
    validator: &[V],
) -> Result<TokenData<D>, crate::errors::Error> {
    let (signature, message) = split_two(token)?;
    let (header, claims_or_data) = split_two(message)?;

    let header = Header::from_encoded(header)?;

    // Check if signer kind and header alg match
    if signer.kind() != header.alg {
        return Err(errors::Error::InvalidAlgorithm(signer.kind(), header.alg));
    }

    // Validate signature
    if !signer.verify(message.as_bytes(), signature.as_bytes())? {
        return Err(errors::Error::InvalidSignature);
    }

    let claims_or_data = utils::b64_decode(claims_or_data)?;
    let claims = serde_json::from_slice::<ClaimsForValidation>(&claims_or_data)
        .map_err(errors::Error::DeserializeError)?;
    let data =
        serde_json::from_slice::<D>(&claims_or_data).map_err(errors::Error::DeserializeError)?;

    // Validate claims
    for v in validator.iter() {
        // Validate claims part
        v.validate(&claims)?;
        // Validate actual data
        v.validate_full(&data)?;
    }

    // Success!
    Ok(TokenData::new(header, data))
}

fn split_two(token: &str) -> Result<(&str, &str), crate::errors::Error> {
    let mut parts = token.rsplitn(2, '.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(first), Some(second), None) => Ok((first, second)),
        _ => Err(errors::Error::InvalidToken),
    }
}
