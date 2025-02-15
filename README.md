# jwt-lc-rs

A simple library for generating and verifying JWTs using [aws-lc-rs](https://github.com/aws/aws-lc-rs)

This library does not implement the JWS specifications from the RFCs.

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
- `ES256K`
- `EdDSA` (Ed25519)

## Supported native validations

**Header**:
- `typ` (Type), always check it is set to `"JWT"` (case-sensitive)
- `alg` (Algorithm), verify that the requested algorithm is what you expect.

**Claims/body**:
- `iss` (Issuer)
- `sub` (Subject)
- `aud` (Audience)
- `exp` (Expiry)
- `nbf` (Not before)
- Any other custom validation can be implemented using the `Validator` trait

**Note**: While we don't provide validation for `jti` and `iat`, you can implement it using the `Validator` trait.

## Examples

See the tests for examples.

## License

This project is dual-licensed under the [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT) licenses at your convenience.

## MSRV policy

The current minimum supported Rust version is `1.81.0`

This will be bumped periodically as we support newer versions of Rust.

## Acknowledgements
- [`jsonwebtoken`](https://github.com/Keats/jsonwebtoken) by Keats
  - Main inspiration and reference
  - Took some code related to `ClaimsForValidation` and some of the `pem` handling.
