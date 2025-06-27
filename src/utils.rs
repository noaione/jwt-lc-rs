//! A collection of utility functions, mostly for encoding and decoding

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

/// Given a slice of ASN.1 blocks, find the first bitstring or
/// octetstring block and return the bytes inside it.
/// If no such block is found, return an error.
///
/// This is used to extract the actual EC/Ed25519 key data
/// from an ASN.1 dump of the PEM or DER encoded public key.
///
/// Code from: <https://github.com/Keats/jsonwebtoken/blob/master/src/pem/decoder.rs#L189-L208>
pub fn extract_first_bitstring(
    asn1: &[simple_asn1::ASN1Block],
) -> Result<&[u8], crate::errors::Error> {
    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                return extract_first_bitstring(&entries);
            }
            simple_asn1::ASN1Block::BitString(_, _, value) => {
                return Ok(value.as_ref());
            }
            simple_asn1::ASN1Block::OctetString(_, value) => {
                return Ok(value.as_ref());
            }
            _ => (),
        }
    }

    Err(crate::errors::Error::InvalidSPKI)
}
