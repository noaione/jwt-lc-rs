use jwt_lc_rs::{validator::Validator, Ed25519Algorithm, SigningAlgorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Basic {
    data: String,
}

#[test]
fn test_ed25519_round_trip_pem() {
    let private = include_str!("private_ed25519.pem");
    let public = include_str!("public_ed25519.pem");
    let alg = Ed25519Algorithm::new_pem(private, public).unwrap();

    let data = Basic {
        data: "Hello Ed25519 world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();
    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello Ed25519 world");
}

#[test]
fn test_ed25519_round_trip_no_public_pem() {
    let private = include_str!("private_ed25519.pem");
    let alg = Ed25519Algorithm::new_pem_from_private_key(private).unwrap();

    let data = Basic {
        data: "Hello Ed25519 private world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();
    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello Ed25519 private world");
}
