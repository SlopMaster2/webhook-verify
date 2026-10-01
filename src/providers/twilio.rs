//! Twilio webhook signature verification.
//!
//! Scheme, per Twilio's official security documentation ("Validating requests
//! are coming from Twilio",
//! <https://www.twilio.com/docs/usage/security#validating-requests>) and the
//! reference implementations in Twilio's official SDKs (e.g.
//! `twilio-python`'s `twilio/request_validator.py`, `twilio-go`'s
//! `client.NewRequestValidator`):
//!
//! - Header: `X-Twilio-Signature: <base64(HMAC-SHA1(auth_token, signed_string))>`
//! - Signed string: the full request URL (protocol through query string,
//!   exactly as configured with Twilio), followed by the `POST` form fields —
//!   sorted alphabetically by name in Unix-style byte order, each field's name
//!   and value concatenated directly to the string with no delimiter.
//! - Algorithm: HMAC-SHA1, base64-encoded (standard alphabet, padded). The
//!   docs note that HMAC construction is not affected by SHA-1's collision
//!   attacks given a secret key, which is why the scheme remains SHA-1.
//! - Key: the account's Auth Token, used as its UTF-8 bytes verbatim. An empty
//!   token fails closed with [`VerifyError::InvalidSecret`].
//!
//! # Not a raw-body scheme
//!
//! Twilio and Mailchimp Transactional ([`crate::Provider::Mandrill`]) are
//! the two shipped schemes that do **not** hash the raw body: the signature
//! covers the parsed form fields instead. Callers parse the
//! `application/x-www-form-urlencoded` body themselves and pass every received
//! field via [`VerifyOptions::form_params`] — Twilio's docs explicitly warn
//! against validating against a hardcoded subset of parameters, since new ones
//! may be added without notice. Sorting is part of the signing scheme and is
//! applied here; callers pass fields in any order. A duplicate field name
//! keeps its received relative order (the official SDKs use keyed dicts, which
//! cannot represent duplicates).
//!
//! # The JSON-body variant
//!
//! Twilio's JSON-body variant signs the **URL alone**: the body is not form
//! fields, so there is nothing for the signature to cover. Pass an explicitly
//! empty parameter list for that shape ([`VerifyOptions::with_form_params`]
//! with no items), and the body is authenticated by the `bodySHA256` query
//! parameter Twilio appends to the URL — the SHA-256 hex digest of the body it
//! sent.
//!
//! Whenever the configured [`VerifyOptions::request_url`] carries a
//! `bodySHA256` parameter, this provider checks `raw_body` against it in
//! addition to the signature, and fails closed on mismatch. Without that
//! second check the signature would authenticate the URL alone, so an
//! attacker who observes one legitimate JSON delivery could replay the same URL
//! and signature with a fully attacker-chosen body. A malformed
//! `bodySHA256` parameter is a comparison failure, never a skipped check; a URL
//! with no `bodySHA256` parameter is unchanged, which is the
//! form-encoded case where the signed form fields already cover the body.
//!
//! # Caller-supplied context
//!
//! Verification needs both [`VerifyOptions::request_url`] (the full URL,
//! including any query string) and [`VerifyOptions::form_params`]. Omitting
//! either fails closed with [`VerifyError::MissingContext`] rather than
//! degrading into a weaker check. The body itself is only consulted through
//! the `bodySHA256` parameter above — pass the received bytes as `raw_body`
//! either way.
//!
//! # Replay protection
//!
//! Twilio signs no timestamp, so [`VerifyOptions::max_age`] and the injected
//! clock have **no effect** for this provider; that is documented behavior,
//! not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::String;
use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::{verify_hmac_sha1, verify_sha256_digest};
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying Twilio's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Twilio-Signature";

/// Query parameter naming the SHA-256 hex digest of the body Twilio sent, and
/// the only thing authenticating the body in the JSON-body variant.
const BODY_HASH_PARAM: &str = "bodySHA256";

/// HMAC-SHA1 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 20;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;

    // Fail closed on missing caller context *before* touching the signature:
    // without the URL and the parsed fields there is nothing to verify
    // against, and falling through would turn a configuration error into an
    // attack-shaped `SignatureMismatch`.
    let url = options
        .request_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "Twilio signs the full request URL; set VerifyOptions::request_url",
        })?;
    let params = options
        .form_params
        .as_ref()
        .ok_or(VerifyError::MissingContext {
            reason: "Twilio signs the sorted POST form fields; set VerifyOptions::form_params",
        })?;

    let provided = parse_signature(value)?;
    let key = auth_token_bytes(secret.as_bytes())?;

    // Signed string: URL bytes first, then every form field's name and value
    // concatenated in byte-wise-sorted-by-name order, no delimiters. A stable
    // sort preserves the received relative order of same-named fields.
    let mut ordered: Vec<&(String, String)> = params.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));

    let mut capacity = url.len();
    for (name, value) in &ordered {
        capacity += name.len() + value.len();
    }
    let mut signed_string = Vec::with_capacity(capacity);
    signed_string.extend_from_slice(url.as_bytes());
    for (name, value) in ordered {
        signed_string.extend_from_slice(name.as_bytes());
        signed_string.extend_from_slice(value.as_bytes());
    }

    if !verify_hmac_sha1(key, &signed_string, &provided) {
        return Err(VerifyError::SignatureMismatch);
    }

    // A `bodySHA256` query parameter on the signed URL is Twilio's commitment
    // to the body it sent, and it is the *only* one when the JSON-body variant
    // signs the URL alone: the form-field list is empty, so the signature above
    // never touches the bytes that carry the event. `twilio-python` ANDs the
    // body-hash comparison into its result for exactly this reason, and this
    // must run before returning `Ok(())` — the signature is a wire value, so a
    // replayed one would otherwise authenticate an attacker-chosen body.
    //
    // The comparison is constant-time like every other digest check here, and
    // a malformed parameter is a comparison failure rather than a skipped
    // check (`twilio-python` compares the two as opaque strings, so a
    // wrong-length or non-hex value simply does not match).
    if let Some(provided) = body_sha256_param(url) {
        // A parameter that is not a hex digest cannot equal a SHA-256 digest,
        // so this fails the comparison below. Spelled as an early return rather
        // than `unwrap_or_default()` so the fail-closed path is visible.
        let Ok(expected) = hex::decode(provided) else {
            return Err(VerifyError::SignatureMismatch);
        };
        if !verify_sha256_digest(raw_body, &expected) {
            return Err(VerifyError::SignatureMismatch);
        }
    }

    Ok(())
}

/// Returns the value of the `bodySHA256` query parameter of `url`, if present.
///
/// The query string is everything after the first `?` up to the first `#`: a
/// fragment is never sent to the server, so a `bodySHA256` after one is not a
/// query parameter. Parameters are matched on their exact key, as `parse_qs`
/// does upstream, and the first occurrence wins (again matching upstream's
/// `query["bodySHA256"][0]`).
///
/// No percent-decoding is applied. The key `bodySHA256` consists entirely of
/// unreserved characters, so a conformant encoding leaves it intact, and the
/// value is a hex digest, whose characters are equally unaffected. This is not
/// a bypass surface: `url` is covered by the HMAC verified before this runs, so
/// an attacker cannot substitute a differently-spelled parameter without also
/// forging the signature over it.
fn body_sha256_param(url: &str) -> Option<&str> {
    let (_, after_query) = url.split_once('?')?;
    let query = after_query.split('#').next()?;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == BODY_HASH_PARAM).then_some(value)
    })
}

/// Returns the HMAC key bytes: the Auth Token exactly as configured.
///
/// Twilio's scheme uses the token as UTF-8 bytes; only an empty token is
/// rejected, failing closed with [`VerifyError::InvalidSecret`].
fn auth_token_bytes(secret: &[u8]) -> Result<&[u8], VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "auth token is empty",
        });
    }
    Ok(secret)
}

/// Parses `X-Twilio-Signature` into its 20 decoded signature bytes.
///
/// Every failure mode maps to a distinct error variant so callers can tell
/// malformed-request noise from signature-mismatch signals (§2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| VerifyError::BadEncoding {
            reason: "signature is not valid standard base64",
        })?;

    if bytes.len() != SIGNATURE_LEN_BYTES {
        return Err(VerifyError::BadEncoding {
            reason: "signature does not decode to 20 bytes",
        });
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;

    /// Official vector from Twilio's own documentation ("Explore the
    /// algorithm yourself", <https://www.twilio.com/docs/usage/security>),
    /// reproduced end-to-end: AuthToken `12345`, URL
    /// `https://example.com/myapp.php?foo=1&bar=2`, five documented `POST`
    /// fields, expected signature `L/OH5YylLD5NRKLltdqwSvS0BnU=`.
    const OFFICIAL_TOKEN: &str = "12345";
    const OFFICIAL_URL: &str = "https://example.com/myapp.php?foo=1&bar=2";
    const OFFICIAL_PARAMS: [(&str, &str); 5] = [
        ("CallSid", "CA1234567890ABCDE"),
        ("To", "+18005551212"),
        ("From", "+14158675310"),
        ("Caller", "+14158675310"),
        ("Digits", "1234"),
    ];
    const OFFICIAL_SIGNATURE: &str = "L/OH5YylLD5NRKLltdqwSvS0BnU=";

    /// Locally constructed over the same recipe with an *empty* parameter
    /// list (boundary case; matches how Twilio's SDKs sign their JSON-body
    /// variant, where only the URL is covered):
    /// `printf '%s' 'https://example.com/myapp' |
    ///  openssl dgst -sha1 -hmac '12345' -binary | base64`
    const EMPTY_PARAMS_SIGNATURE: &str = "XqNa/0zb23Pa5OkAE2d03kJM920=";

    /// Locally constructed over `"héllo, 🦀 world!"` as a `Body` field value
    /// (unicode boundary case), same recipe as above.
    const UNICODE_VALUE_SIGNATURE: &str = "DLL/FecOOE0jpcpnmuiNzzZ+GUA=";

    /// Locally constructed with the field name `Body` sent twice
    /// (`a` then `b`; duplicates keep received relative order under this
    /// crate's stable sort), same recipe as above.
    const DUPLICATE_KEYS_SIGNATURE: &str = "Pb31hQflAm8COuKbY6mJvTRORg0=";

    /// Locally constructed with mixed-case names pinned to byte-wise sorting
    /// (`Digits` < `api_version` < `StatusCallback`: digits sort before
    /// letters, uppercase before lowercase), same recipe as above.
    const BYTE_SORT_ORDER_SIGNATURE: &str = "Ww6eWkSu0j/9l8dG3e+uIq1kCUI=";

    /// Twilio's own JSON-body variant example, verbatim from "Explore the
    /// algorithm yourself" (<https://www.twilio.com/docs/usage/security>): the
    /// body below, its `bodySHA256` query parameter, and — constructed with the
    /// documented recipe over the URL *alone*, since the JSON variant signs no
    /// form fields — the expected signature
    /// `printf '%s' "$url" | openssl dgst -sha1 -hmac '12345' -binary | base64`.
    const JSON_BODY: &str = r#"{"property": "value", "boolean": true}"#;
    const JSON_BODY_SHA256: &str =
        "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";
    const JSON_BODY_URL: &str = concat!(
        "https://example.com/myapp?bodySHA256=",
        "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
    );
    const JSON_BODY_SIGNATURE: &str = "Klp85180pYIxzIO5cuyxpfh1BKw=";

    fn twilio_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    /// Verifies the JSON-body variant: an empty parameter list plus the raw
    /// body, which is authenticated by the URL's `bodySHA256` query parameter.
    fn verify_json_body(url: &str, body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Twilio,
            &twilio_headers(signature),
            body,
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default()
                .with_request_url(url)
                .with_form_params(core::iter::empty::<(&str, &str)>()),
        )
    }

    fn verify_with(params: &[(&str, &str)], signature: &str) -> Result<(), VerifyError> {
        verify_with_url("https://example.com/myapp", params, signature)
    }

    fn verify_with_url(
        url: &str,
        params: &[(&str, &str)],
        signature: &str,
    ) -> Result<(), VerifyError> {
        let options = VerifyOptions::default()
            .with_request_url(url)
            .with_form_params(params.iter().copied());
        verify(
            crate::Provider::Twilio,
            &twilio_headers(signature),
            b"unused: not a raw-body scheme",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        )
    }

    #[test]
    fn official_vector_verifies() {
        assert_eq!(
            verify_with_url(OFFICIAL_URL, &OFFICIAL_PARAMS, OFFICIAL_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn official_vector_verifies_with_params_in_any_order() {
        // Sorting is the verifier's job: reversed input order must still pass.
        let reversed: Vec<(&str, &str)> = OFFICIAL_PARAMS.iter().rev().copied().collect();
        assert_eq!(
            verify_with_url(OFFICIAL_URL, &reversed, OFFICIAL_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn boundary_param_lists_verify() {
        assert_eq!(verify_with(&[], EMPTY_PARAMS_SIGNATURE), Ok(()));
        assert_eq!(
            verify_with(&[("Body", "héllo, 🦀 world!")], UNICODE_VALUE_SIGNATURE),
            Ok(())
        );
        assert_eq!(
            verify_with(&[("Body", "a"), ("Body", "b")], DUPLICATE_KEYS_SIGNATURE),
            Ok(())
        );
        assert_eq!(
            verify_with(
                &[
                    ("StatusCallback", "https://cb"),
                    ("api_version", "2010"),
                    ("Digits", "1234")
                ],
                BYTE_SORT_ORDER_SIGNATURE
            ),
            Ok(())
        );
    }

    #[test]
    fn raw_body_is_irrelevant_to_the_scheme() {
        // The signature covers the parsed fields, not the body bytes; pin that
        // passing arbitrary body bytes alongside valid context verifies fine.
        // (Only true while the signed URL carries no `bodySHA256`: see
        // `json_body_variant_*`.)
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"totally different bytes than what was posted",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn json_body_variant_verifies_and_authenticates_the_body() {
        // Twilio's own worked example: the URL alone is signed, and the body
        // is authenticated by the `bodySHA256` query parameter carrying its
        // SHA-256 hex digest. `sha256_hexdigest` is asserted against the
        // documented digest independently so a bug in this provider's wiring
        // cannot be masked by a bug in the shared helper.
        assert_eq!(
            crate::core::crypto::sha256_hexdigest(JSON_BODY.as_bytes()),
            JSON_BODY_SHA256
        );
        assert_eq!(
            verify_json_body(JSON_BODY_URL, JSON_BODY.as_bytes(), JSON_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn json_body_variant_rejects_a_swapped_body() {
        // The bypass this closes: the signature and URL are unchanged, so only
        // the `bodySHA256` check stands between an attacker-chosen body and an
        // `Ok(())`.
        assert_eq!(
            verify_json_body(
                JSON_BODY_URL,
                br#"{"property": "attacker", "boolean": false}"#,
                JSON_BODY_SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn json_body_variant_rejects_an_altered_signed_body() {
        // A single flipped byte of the real body must not pass.
        let mut body = JSON_BODY.as_bytes().to_vec();
        let last = body.len() - 1;
        body[last] = b' ';
        assert_eq!(
            verify_json_body(JSON_BODY_URL, &body, JSON_BODY_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn malformed_body_sha256_fails_closed() {
        // `twilio-python` compares the digest as an opaque string, so a
        // malformed or wrong-length parameter is a plain comparison failure —
        // never a silently skipped check. Each signature is validly computed
        // over its own URL, so `SignatureMismatch` here can only come from the
        // body-hash check and not from the HMAC.
        let cases: &[(&str, &str)] = &[
            // Not hex.
            (
                "https://example.com/myapp?bodySHA256=not-a-hex-digest-at-all-but-long-enough-to-look-right!!",
                "Z8qKrg+/Q1Gp9IVtToZJ0VW82vQ=",
            ),
            // Valid hex, wrong length (SHA-1 size rather than SHA-256).
            (
                "https://example.com/myapp?bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b28",
                "cB8+ZyW0TufQ1tGySQc9x2fmJ44=",
            ),
            // Empty value.
            (
                "https://example.com/myapp?bodySHA256=",
                "PZ2ZB8j1sTWZk/inD7lFpKm8iPA=",
            ),
        ];
        for &(url, signature) in cases {
            assert_eq!(
                verify_json_body(url, JSON_BODY.as_bytes(), signature),
                Err(VerifyError::SignatureMismatch),
                "url: {url:?}"
            );
        }
    }

    #[test]
    fn body_sha256_is_compared_as_decoded_bytes() {
        // Twilio emits a lowercase digest; this pins that the comparison is on
        // the decoded 32 bytes rather than on the ASCII spelling, so a
        // case-folded spelling is accepted. Documented rather than relied upon:
        // hex encoding is canonical in practice, and this is the one input
        // shape where the crate is deliberately more permissive than upstream's
        // string comparison.
        const URL: &str = concat!(
            "https://example.com/myapp?bodySHA256=",
            "0A1FF7634D9AB3B95DB5C9A2DFE9416E41502B283A80C7CF19632632F96E6620"
        );
        const SIGNATURE: &str = "GScayKQw4JgUJBVFEY3VkzEkYnI=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn body_sha256_is_not_read_from_a_similar_named_parameter() {
        // Only the exact `bodySHA256` key names a body commitment. A lookalike
        // must not be mistaken for one — Twilio's SDKs match the key exactly
        // (`parse_qs`), so a `bodySHA256x` parameter commits to nothing and the
        // body check stays correctly skipped. The signature is valid over this
        // exact URL, so if the lookalike *were* read the swapped body would
        // fail; this pins that it is not read.
        const URL: &str = concat!(
            "https://example.com/myapp?bodySHA256x=",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
        );
        const SIGNATURE: &str = "xsTf5BeAjPX2Fn6DgoCix/OOr9Y=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(())
        );
        assert_eq!(verify_json_body(URL, b"attacker-chosen", SIGNATURE), Ok(()));
    }

    #[test]
    fn body_sha256_is_read_from_anywhere_in_the_query() {
        // `bodySHA256` is not required to be the first parameter, and other
        // parameters around it must not disturb the lookup. Signature
        // constructed over this exact URL with the documented recipe.
        const URL: &str = concat!(
            "https://example.com/myapp?a=1&bodySHA256=",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620&z=2"
        );
        const SIGNATURE: &str = "XfF5rbcC5Xzh39JhYVGh3vQlHAE=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn fragment_is_not_part_of_the_query() {
        // A `#` ends the query string: a `bodySHA256` after it is not a query
        // parameter and must not be read as one. Signature constructed over this
        // exact URL with the documented recipe.
        const URL: &str = concat!(
            "https://example.com/myapp?a=1#",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
        );
        const SIGNATURE: &str = "RMmDEbpnZkTnoUdeRvUv5GFboJU=";
        assert_eq!(
            verify_json_body(URL, b"attacker-chosen", SIGNATURE),
            Ok(()),
            "a fragment-borne lookalike is not a query parameter"
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Twilio,
            &[("x-twilio-signature", OFFICIAL_SIGNATURE)],
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default()
                .with_request_url(OFFICIAL_URL)
                .with_form_params(OFFICIAL_PARAMS),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}O{}", &OFFICIAL_SIGNATURE[..1], &OFFICIAL_SIGNATURE[2..]);
        assert_ne!(flipped, OFFICIAL_SIGNATURE);
        assert_eq!(
            verify_with(&OFFICIAL_PARAMS, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_field_value_fails() {
        let tampered: Vec<(&str, &str)> = OFFICIAL_PARAMS
            .iter()
            .map(|&(k, v)| if k == "Digits" { (k, "9999") } else { (k, v) })
            .collect();
        assert_eq!(
            verify_with(&tampered, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn omitted_field_fails() {
        // Twilio's docs warn against verifying against a hardcoded subset:
        // dropping any signed field must break verification.
        let subset = &OFFICIAL_PARAMS[1..];
        assert_eq!(
            verify_with(subset, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_url_fails() {
        // A delivery signed for any other endpoint — here differing by a
        // single trailing slash — must not verify.
        let options = VerifyOptions::default()
            .with_request_url("https://example.com/myapp.php/?foo=1&bar=2")
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn tampered_field_order_fails_when_signed_order_differs() {
        // Duplicate names keep received relative order; reversing two values
        // under one name changes the signed string and must fail.
        assert_eq!(
            verify_with(&[("Body", "a"), ("Body", "b")], DUPLICATE_KEYS_SIGNATURE),
            Ok(())
        );
        assert_eq!(
            verify_with(&[("Body", "b"), ("Body", "a")], DUPLICATE_KEYS_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new("secondary-auth-token-not-yet-primary"),
            options,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn empty_secret_fails_closed_as_invalid_secret() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(""),
            options,
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "secret is empty"
            })
        );
    }

    #[test]
    fn max_age_has_no_effect_for_twilio() {
        // Twilio signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::options::VerifyOptions {
            max_age: Some(std::time::Duration::ZERO),
            request_url: Some(OFFICIAL_URL.to_string()),
            form_params: Some(
                OFFICIAL_PARAMS
                    .iter()
                    .map(|&(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            ..crate::core::options::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_request_context_fails_closed_as_missing_context() {
        // No URL at all.
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default().with_form_params(OFFICIAL_PARAMS),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Twilio signs the full request URL; set VerifyOptions::request_url"
            })
        );

        // No form params at all (distinct from an explicit empty list, which
        // is meaningful and covered by `boundary_param_lists_verify`).
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default().with_request_url(OFFICIAL_URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Twilio signs the sorted POST form fields; set VerifyOptions::form_params"
            })
        );

        // An explicitly empty URL is equally unusable.
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default()
                .with_request_url("")
                .with_form_params(OFFICIAL_PARAMS),
        );
        assert!(matches!(result, Err(VerifyError::MissingContext { .. })));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &Vec::<(String, String)>::new(),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_and_bad_encoding_errors_are_distinct() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let cases: &[(&str, VerifyError)] = &[
            (
                "",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // Valid base64 alphabet but wrong decoded length (SHA-256 size).
            (
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 20 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Twilio,
                &[(SIGNATURE_HEADER, value)],
                b"",
                &Secret::new(OFFICIAL_TOKEN),
                options.clone(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        for value in [
            "not base64!!",
            // Padded standard-base64 engine rejects unpadded input.
            OFFICIAL_SIGNATURE.trim_end_matches('='),
        ] {
            let result = verify(
                crate::Provider::Twilio,
                &[(SIGNATURE_HEADER, value)],
                b"",
                &Secret::new(OFFICIAL_TOKEN),
                options.clone(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
