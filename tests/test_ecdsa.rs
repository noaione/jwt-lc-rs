use jwt_lc_rs::{validator::Validator, EcdsaAlgorithm, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Basic {
    data: String,
}

#[test]
fn test_ecdsa_p256_round_trip_pem() {
    let private = include_str!("private_ecdsa_p256.pem");
    let public = include_str!("public_ecdsa_p256.pem");

    let alg = EcdsaAlgorithm::new_pem(jwt_lc_rs::SHALevel::SHA256, private, public).unwrap();

    let data_txt = format!("Hello ECDSA P-256 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p256_round_trip_der() {
    let private = include_bytes!("private_ecdsa_p256.der");
    let public = include_bytes!("public_ecdsa_p256.der");

    let alg = EcdsaAlgorithm::new_der(jwt_lc_rs::SHALevel::SHA256, private, public).unwrap();

    let data_txt = format!("Hello ECDSA P-256 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p384_round_trip_pem() {
    let private = include_str!("private_ecdsa_p384.pem");
    let public = include_str!("public_ecdsa_p384.pem");

    let alg = EcdsaAlgorithm::new_pem(jwt_lc_rs::SHALevel::SHA384, private, public).unwrap();

    let data_txt = format!("Hello ECDSA P-384 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p384_round_trip_der() {
    let private = include_bytes!("private_ecdsa_p384.der");
    let public = include_bytes!("public_ecdsa_p384.der");

    let alg = EcdsaAlgorithm::new_der(jwt_lc_rs::SHALevel::SHA384, private, public).unwrap();

    let data_txt = format!("Hello ECDSA P-384 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p521_round_trip_pem() {
    let private = include_str!("private_ecdsa_p521.pem");
    let public = include_str!("public_ecdsa_p521.pem");

    let alg = EcdsaAlgorithm::new_pem(jwt_lc_rs::SHALevel::SHA512, private, public).unwrap();

    let data_txt = format!("Hello ECDSA P-521 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p521_round_trip_der() {
    let private = include_bytes!("private_ecdsa_p521.der");
    let public = include_bytes!("public_ecdsa_p521.der");

    let alg = EcdsaAlgorithm::new_der(jwt_lc_rs::SHALevel::SHA512, private, public).unwrap();

    let data_txt = format!("Hello ECDSA P-521 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p256_round_trip_no_public_pem() {
    let private = include_str!("private_ecdsa_p256.pem");

    let alg =
        EcdsaAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA256, private).unwrap();

    let data_txt = format!("Hello ECDSA P-256 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p256_round_trip_no_public_der() {
    let private = include_bytes!("private_ecdsa_p256.der");

    let alg =
        EcdsaAlgorithm::new_der_from_private_key(jwt_lc_rs::SHALevel::SHA256, private).unwrap();

    let data_txt = format!("Hello ECDSA P-256 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p384_round_trip_no_public_pem() {
    let private = include_str!("private_ecdsa_p384.pem");

    let alg =
        EcdsaAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA384, private).unwrap();

    let data_txt = format!("Hello ECDSA P-384 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p384_round_trip_no_public_der() {
    let private = include_bytes!("private_ecdsa_p384.der");

    let alg =
        EcdsaAlgorithm::new_der_from_private_key(jwt_lc_rs::SHALevel::SHA384, private).unwrap();

    let data_txt = format!("Hello ECDSA P-384 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p521_round_trip_no_public_pem() {
    let private = include_str!("private_ecdsa_p521.pem");

    let alg =
        EcdsaAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA512, private).unwrap();

    let data_txt = format!("Hello ECDSA P-521 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}

#[test]
fn test_ecdsa_p521_round_trip_no_public_der() {
    let private = include_bytes!("private_ecdsa_p521.der");

    let alg =
        EcdsaAlgorithm::new_der_from_private_key(jwt_lc_rs::SHALevel::SHA512, private).unwrap();

    let data_txt = format!("Hello ECDSA P-521 World");
    let data = Basic {
        data: data_txt.clone(),
    };

    let signer = Signer::Ecdsa(alg);
    let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

    assert_eq!(decoded.get_header().alg, signer.kind());
    assert_eq!(decoded.get_claims().data, data_txt);
}
