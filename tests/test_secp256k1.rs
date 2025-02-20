use jwt_lc_rs::{validator::Validator, Secp256k1Algorithm, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Basic {
    data: String,
}

#[test]
fn test_secp256k1_round_trip_pem() {
    let private = include_str!("private_ecdsa_p256k1.pem");
    let public = include_str!("public_ecdsa_p256k1.pem");
    let alg = Secp256k1Algorithm::new_pem(private, public).unwrap();

    let data = Basic {
        data: "Hello ECDSA P-256K1 world".to_string(),
    };

    let signer = Signer::Secp256k1(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, "Hello ECDSA P-256K1 world");
}

#[test]
fn test_secp256k1_round_trip_der() {
    let private = include_bytes!("private_ecdsa_p256k1.der");
    let public = include_bytes!("public_ecdsa_p256k1.der");
    let alg = Secp256k1Algorithm::new_der(private, public).unwrap();

    let data = Basic {
        data: "Hello ECDSA P-256K1 world".to_string(),
    };

    let signer = Signer::Secp256k1(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, "Hello ECDSA P-256K1 world");
}

#[test]
fn test_secp256k1_round_trip_no_public_pem() {
    let private = include_str!("private_ecdsa_p256k1.pem");
    let alg = Secp256k1Algorithm::new_pem_from_private_key(private).unwrap();

    let data = Basic {
        data: "Hello ECDSA P-256K1 world".to_string(),
    };

    let signer = Signer::Secp256k1(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, "Hello ECDSA P-256K1 world");
}

#[test]
fn test_secp256k1_round_trip_no_public_der() {
    let private = include_bytes!("private_ecdsa_p256k1.der");
    let alg = Secp256k1Algorithm::new_der_from_private_key(private).unwrap();

    let data = Basic {
        data: "Hello ECDSA P-256K1 world".to_string(),
    };

    let signer = Signer::Secp256k1(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, "Hello ECDSA P-256K1 world");
}
