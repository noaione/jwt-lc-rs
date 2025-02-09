use jwt_lc_rs::{validator::NoopValidator, RsaAlgorithm, SigningAlgorithm};
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
fn test_rsa_2048_round_trip() {
    let private = include_str!("private_rsa_2048.pem");
    let public = include_str!("public_rsa_2048.pem");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_pem(*hash, private, public).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
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
fn test_rsa_4096_round_trip() {
    let private = include_str!("private_rsa_4096.pem");
    let public = include_str!("public_rsa_4096.pem");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_pem(*hash, private, public).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
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
