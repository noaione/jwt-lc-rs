use jwt_lc_rs::{validator::NoopValidator, Secp256k1Algorithm, SigningAlgorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Basic {
    data: String,
}

#[test]
fn test_secp256k1_round_trip() {
    let private: &[u8; 32] = include_bytes!("private_secp256k1.der");
    let public = include_bytes!("public_secp256k1.der");
    let alg = Secp256k1Algorithm::new_der(private, public).unwrap();

    let data = Basic {
        data: "Hello Ed25519 world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();
    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello Ed25519 world");
}
