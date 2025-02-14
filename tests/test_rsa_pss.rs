use jwt_lc_rs::{validator::NoopValidator, RsaPssAlgorithm, SigningAlgorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Basic {
    data: String,
}

const SHA_TEST: &[jwt_lc_rs::SHALevel; 3] = &[
    jwt_lc_rs::SHALevel::SHA256,
    jwt_lc_rs::SHALevel::SHA384,
    jwt_lc_rs::SHALevel::SHA512,
];

#[test]
fn test_rsa_2048_sha256_round_trip_pem() {
    let private = include_str!("private_rsa_pss_2048_sha256.pem");
    let public = include_str!("public_rsa_pss_2048_sha256.pem");

    for hash in SHA_TEST {
        let alg = RsaPssAlgorithm::new_pem(*hash, private, public).unwrap();

        let data_txt = format!("Hello RSA PSS world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

        assert_eq!(decoded.get_header().alg, alg.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_2048_sha256_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_pss_2048_sha256.pem");

    let alg =
        RsaPssAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA256, private).unwrap();

    let data = Basic {
        data: "Hello RSA PSS world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello RSA PSS world");
}

#[test]
fn test_rsa_2048_sha384_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_pss_2048_sha384.pem");

    let alg =
        RsaPssAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA384, private).unwrap();

    let data = Basic {
        data: "Hello RSA PSS world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello RSA PSS world");
}

#[test]
fn test_rsa_2048_sha512_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_pss_2048_sha512.pem");

    let alg =
        RsaPssAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA512, private).unwrap();

    let data = Basic {
        data: "Hello RSA PSS world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello RSA PSS world");
}

#[test]
fn test_rsa_4096_sha256_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_pss_4096_sha256.pem");

    let alg =
        RsaPssAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA256, private).unwrap();

    let data = Basic {
        data: "Hello RSA PSS world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello RSA PSS world");
}

#[test]
fn test_rsa_4096_sha384_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_pss_4096_sha384.pem");

    let alg =
        RsaPssAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA384, private).unwrap();

    let data = Basic {
        data: "Hello RSA PSS world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello RSA PSS world");
}

#[test]
fn test_rsa_4096_sha512_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_pss_4096_sha512.pem");

    let alg =
        RsaPssAlgorithm::new_pem_from_private_key(jwt_lc_rs::SHALevel::SHA512, private).unwrap();

    let data = Basic {
        data: "Hello RSA PSS world".to_string(),
    };

    let encoded = jwt_lc_rs::encode(&data, &alg).unwrap();

    let decoded: jwt_lc_rs::TokenData<Basic> =
        jwt_lc_rs::decode(&encoded, &alg, &[NoopValidator]).unwrap();

    assert_eq!(decoded.get_header().alg, alg.kind());
    assert_eq!(decoded.get_claims().data, "Hello RSA PSS world");
}
