use jwt_lc_rs::{utils::extract_first_bitstring, validator::Validator, RsaAlgorithm, Signer};
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
fn test_rsa_2048_round_trip_pem() {
    let private = include_str!("private_rsa_2048.pem");
    let public = include_str!("public_rsa_2048.pem");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_pem(*hash, private, public).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_2048_round_trip_der() {
    let private = include_bytes!("private_rsa_2048.der");
    let public = include_bytes!("public_rsa_2048.der");

    // Convert to pkcs#1 since our key is in pkcs#8
    let asn_parsed = jwt_lc_rs::asn1_decode_der(public).unwrap();
    let public_pkcs1 = extract_first_bitstring(&asn_parsed).unwrap();

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_der(*hash, private, public_pkcs1).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_2048_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_2048.pem");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_pem_from_private_key(*hash, private).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_2048_round_trip_no_public_der() {
    let private = include_bytes!("private_rsa_2048.der");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_der_from_private_key(*hash, private).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_4096_round_trip_pem() {
    let private = include_str!("private_rsa_4096.pem");
    let public = include_str!("public_rsa_4096.pem");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_pem(*hash, private, public).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_4096_round_trip_der() {
    let private = include_bytes!("private_rsa_4096.der");
    let public = include_bytes!("public_rsa_4096.der");

    // Convert to pkcs#1
    let asn_parsed = jwt_lc_rs::asn1_decode_der(public).unwrap();
    let public_pkcs1 = extract_first_bitstring(&asn_parsed).unwrap();

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_der(*hash, private, public_pkcs1).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_4096_round_trip_no_public_pem() {
    let private = include_str!("private_rsa_4096.pem");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_pem_from_private_key(*hash, private).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_rsa_4096_round_trip_no_public_der() {
    let private = include_bytes!("private_rsa_4096.der");

    for hash in SHA_TEST {
        let alg = RsaAlgorithm::new_der_from_private_key(*hash, private).unwrap();

        let data_txt = format!("Hello RSA world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Rsa(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();

        let decoded: jwt_lc_rs::TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}
