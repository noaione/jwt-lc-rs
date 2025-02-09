#![cfg(feature = "pem")]

#[derive(Debug, PartialEq)]
pub(crate) enum Classification {
    Ec,
    Ed,
    Rsa,
    RsaPss,
    Secp256k1,
}

impl Classification {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Ec => "EC",
            Self::Ed => "Ed25519",
            Self::Rsa => "RSA",
            Self::RsaPss => "RSA-PSS",
            Self::Secp256k1 => "secp256k1",
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum PemKind {
    Public,
    Private,
}

pub(crate) struct PemEncodedKey {
    kind: PemKind,
    content: Vec<u8>,
    classify: Classification,
}

impl PemEncodedKey {
    pub(crate) fn read<B: AsRef<[u8]>>(data: B) -> Result<Self, crate::errors::Error> {
        let parsed = pem::parse(data)?;
        let asn_parse = simple_asn1::from_der(parsed.contents())?;

        match parsed.tag() {
            "RSA PRIVATE KEY" => Ok(Self {
                kind: PemKind::Private,
                content: parsed.contents().to_vec(),
                classify: classify_pem(&asn_parse).unwrap_or(Classification::Rsa),
            }),
            "RSA PUBLIC KEY" => Ok(Self {
                kind: PemKind::Private,
                content: parsed.contents().to_vec(),
                classify: classify_pem(&asn_parse).unwrap_or(Classification::Rsa),
            }),
            "EC PUBLIC KEY" => Ok(Self {
                kind: PemKind::Public,
                content: parsed.contents().to_vec(),
                classify: classify_pem(&asn_parse).unwrap_or(Classification::Ec),
            }),
            "EC PRIVATE KEY" => Ok(Self {
                kind: PemKind::Private,
                content: parsed.contents().to_vec(),
                classify: classify_pem(&asn_parse).unwrap_or(Classification::Ec),
            }),

            tag @ "PRIVATE KEY" | tag @ "PUBLIC KEY" | tag @ "CERTIFICATE" => {
                match classify_pem(&asn_parse) {
                    Some(classify) => Ok(Self {
                        kind: if tag == "PRIVATE KEY" {
                            PemKind::Private
                        } else {
                            PemKind::Public
                        },
                        content: parsed.contents().to_vec(),
                        classify,
                    }),
                    None => Err(crate::errors::Error::InvalidKey),
                }
            }

            _ => Err(crate::errors::Error::InvalidKey),
        }
    }

    pub(crate) fn contents(&self) -> &[u8] {
        &self.content
    }

    pub(crate) fn kind(&self) -> &PemKind {
        &self.kind
    }

    pub(crate) fn classify(&self) -> &Classification {
        &self.classify
    }
}

/// Find whether this is EC, RSA, or Ed
fn classify_pem(asn1: &[simple_asn1::ASN1Block]) -> Option<Classification> {
    // These should be constant but the macro requires
    // #![feature(const_vec_new)]
    let ec_public_key_oid = simple_asn1::oid!(1, 2, 840, 10_045, 2, 1);
    let ec_secp256k1_key_oid = simple_asn1::oid!(1, 3, 132, 0, 10);
    let rsa_public_key_oid = simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1);
    let rsa_pss_public_key_oid = simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 10);
    let ed25519_oid = simple_asn1::oid!(1, 3, 101, 112);

    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Some(classification) = classify_pem(entries) {
                    return Some(classification);
                }
            }
            simple_asn1::ASN1Block::ObjectIdentifier(_, oid) => {
                if oid == ec_public_key_oid {
                    return Some(Classification::Ec);
                }
                if oid == rsa_public_key_oid {
                    return Some(Classification::Rsa);
                }
                if oid == rsa_pss_public_key_oid {
                    return Some(Classification::RsaPss);
                }
                if oid == ec_secp256k1_key_oid {
                    return Some(Classification::Secp256k1);
                }
                if oid == ed25519_oid {
                    return Some(Classification::Ed);
                }
            }
            _ => {}
        }
    }
    None
}
