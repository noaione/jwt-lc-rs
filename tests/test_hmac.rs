use jwt_lc_rs::{validator::Validator, HmacAlgorithm, Signer, TokenData};
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
fn test_hmac_round_trip() {
    let secret = b"super-duper-secret";

    for hash in SHA_TEST {
        let alg = HmacAlgorithm::new(*hash, secret);
        let data_txt = format!("Hello new world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Hmac(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
        let decoded: TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}

#[test]
fn test_hmac_with_string_round_trip() {
    let secret = "super-duper-secret";

    for hash in SHA_TEST {
        let alg = HmacAlgorithm::new(*hash, secret);
        let data_txt = format!("Hello new world: {:?}", hash);
        let data = Basic {
            data: data_txt.clone(),
        };

        let signer = Signer::Hmac(alg);
        let encoded = jwt_lc_rs::encode(&data, &signer).unwrap();
        let decoded: TokenData<Basic> =
            jwt_lc_rs::decode(&encoded, &signer, &Validator::default()).unwrap();

        assert_eq!(decoded.get_header().alg, signer.kind());
        assert_eq!(decoded.get_claims().data, data_txt);
    }
}
