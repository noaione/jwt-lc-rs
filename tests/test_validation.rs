use std::sync::LazyLock;

use jwt_lc_rs::{
    errors::ValidationError,
    validator::{
        AudienceValidator, ExpiryValidator, IssuerValidator, NotBeforeValidator, SubjectValidator,
        Validator,
    },
    HmacAlgorithm, Signer,
};
use serde::{Deserialize, Serialize};

const ISSUER: &str = "jwt-lc-rs-example-tests";
const AUDIENCE: &str = "auth";
const SUBJECT: &str = "login-context";
const SECRET: &[u8; 18] = b"super-duper-secret";

static SIGNER: LazyLock<Signer> =
    LazyLock::new(|| Signer::Hmac(HmacAlgorithm::new(jwt_lc_rs::SHALevel::SHA256, SECRET)));

#[allow(non_snake_case)]
fn S(s: &'static str) -> String {
    s.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IssuerBasic {
    data: String,
    iss: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AudienceBasic {
    data: String,
    aud: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubjectBasic {
    data: String,
    sub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotBeforeBasic {
    data: String,
    nbf: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpiryBasic {
    data: String,
    exp: u64,
}

fn now_shift(by: i64) -> u64 {
    let current = std::time::SystemTime::now();
    match current.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            // if minus, use saturating_sub
            let as_secs = duration.as_secs();
            if by < 0 {
                as_secs.saturating_sub(by.unsigned_abs())
            } else {
                as_secs.saturating_add(by as u64)
            }
        }
        Err(_) => 0u64,
    }
}

#[test]
fn test_validate_issuer() {
    let data = IssuerBasic {
        data: S("Hello world!"),
        iss: S(&ISSUER),
    };

    let validator = Validator::default().add(IssuerValidator::new(&[ISSUER]));
    let encoded = jwt_lc_rs::encode(&data, &*SIGNER).unwrap();
    let decoded: jwt_lc_rs::TokenData<IssuerBasic> =
        jwt_lc_rs::decode(&encoded, &*SIGNER, &validator).unwrap();
    assert_eq!(decoded.get_claims().iss, ISSUER);
}

#[test]
fn test_validate_audience() {
    let data = AudienceBasic {
        data: S("Hello world!"),
        aud: S(&AUDIENCE),
    };

    let validator = Validator::default().add(AudienceValidator::new(&[AUDIENCE]));
    let encoded = jwt_lc_rs::encode(&data, &*SIGNER).unwrap();
    let decoded: jwt_lc_rs::TokenData<AudienceBasic> =
        jwt_lc_rs::decode(&encoded, &*SIGNER, &validator).unwrap();
    assert_eq!(decoded.get_claims().aud, AUDIENCE);
}

#[test]
fn test_validate_subject() {
    let data = SubjectBasic {
        data: S("Hello world!"),
        sub: S(&SUBJECT),
    };

    let validator = Validator::default().add(SubjectValidator::new(SUBJECT));
    let encoded = jwt_lc_rs::encode(&data, &*SIGNER).unwrap();
    let decoded: jwt_lc_rs::TokenData<SubjectBasic> =
        jwt_lc_rs::decode(&encoded, &*SIGNER, &validator).unwrap();
    assert_eq!(decoded.get_claims().sub, SUBJECT);
}

#[test]
fn test_validate_not_before() {
    let shift_by_10 = now_shift(-10);
    let data = NotBeforeBasic {
        data: S("Hello world!"),
        nbf: shift_by_10,
    };

    let validator = Validator::default().add(NotBeforeValidator::now());
    let encoded = jwt_lc_rs::encode(&data, &*SIGNER).unwrap();
    let decoded: jwt_lc_rs::TokenData<NotBeforeBasic> =
        jwt_lc_rs::decode(&encoded, &*SIGNER, &validator).unwrap();
    assert_eq!(decoded.get_claims().nbf, shift_by_10);
}

#[test]
fn test_validate_expiry() {
    let shift_by_10 = now_shift(10);
    let data = ExpiryBasic {
        data: S("Hello world!"),
        exp: shift_by_10,
    };

    let validator = Validator::default().add(ExpiryValidator::now());
    let encoded = jwt_lc_rs::encode(&data, &*SIGNER).unwrap();
    let decoded: jwt_lc_rs::TokenData<ExpiryBasic> =
        jwt_lc_rs::decode(&encoded, &*SIGNER, &validator).unwrap();
    assert_eq!(decoded.get_claims().exp, shift_by_10);
}

#[test]
fn test_validate_expiry_via_grace_period() {
    let shift_by_10 = now_shift(10);
    let data = ExpiryBasic {
        data: S("Hello world!"),
        exp: shift_by_10,
    };

    let validator =
        Validator::default().add(ExpiryValidator::new(now_shift(12)).with_grace_period(5));
    let encoded = jwt_lc_rs::encode(&data, &*SIGNER).unwrap();
    let decoded: jwt_lc_rs::TokenData<ExpiryBasic> =
        jwt_lc_rs::decode(&encoded, &*SIGNER, &validator).unwrap();
    assert_eq!(decoded.get_claims().exp, shift_by_10);
}

#[test]
fn test_validate_expiry_via_grace_period_expired() {
    let shift_by_10 = now_shift(10);
    let data = ExpiryBasic {
        data: S("Hello world!"),
        exp: shift_by_10,
    };

    let validator =
        Validator::default().add(ExpiryValidator::new(now_shift(16)).with_grace_period(5));
    let encoded = jwt_lc_rs::encode(&data, &*SIGNER).unwrap();
    match jwt_lc_rs::decode::<ExpiryBasic>(&encoded, &*SIGNER, &validator) {
        Err(jwt_lc_rs::errors::Error::ValidationError(ValidationError::TokenExpired(_, _))) => (),
        _ => panic!("expected TokenExpired error"),
    }
}
