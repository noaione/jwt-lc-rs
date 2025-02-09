use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::Serialize;

pub(crate) fn b64_encode(data: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn b64_decode(input: &str) -> Result<Vec<u8>, crate::errors::Error> {
    let decoded = BASE64_URL_SAFE_NO_PAD.decode(input)?;
    Ok(decoded)
}

pub(crate) fn b64_encode_serde<T: Serialize>(data: &T) -> Result<String, crate::errors::Error> {
    let json = serde_json::to_vec(data).map_err(crate::errors::Error::SerializeError)?;
    Ok(b64_encode(&json))
}
