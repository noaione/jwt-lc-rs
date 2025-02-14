# jwt-lc-rs

A simple library for generating and verifying JWTs using [aws-lc-rs](https://github.com/aws/aws-lc-rs)

This library only includes a tiny subset of the RFC specs.

## Supported algorithms
- `HS256`
- `HS384`
- `HS512`
- `RS256`
- `RS384`
- `RS512`
- `PS256`
- `PS384`
- `PS512`
- `ES256`
- `ES384`
- `ES512`
- `ES256K` (via [`secp256k1`](https://crates.io/crates/secp256k1) crate)
- `EdDSA` (Ed25519)

## Supported validations
- `iss` (Issuer)
- `sub` (Subject)
- `aud` (Audience)
- `exp` (Expiry)
- `nbf` (Not before)
- Any other custom validation can be implemented using the `Validation` trait

## Examples

TODO

## License

This project is dual-licensed under the [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT) licenses at your convenience.

## MSRV policy

The current minimum supported Rust version is `1.81.0`

This will be bumped periodically as we support newer versions of Rust.

## Acknowledgements
- [`jsonwebtoken`](https://github.com/Keats/jsonwebtoken) by Keats
  - Main inspiration and reference
  - Took some code related to `ClaimsForValidation` and some of the `pem` handling.
