//! Mailchimp Transactional (formerly Mandrill) webhook signature verification.
//!
//! Scheme, per Mailchimp's official security guide ("Authenticating webhook
//! requests",
//! <https://mailchimp.com/developer/transactional/guides/track-respond-activity-webhooks/>)
//! and the official reference implementation in the same guide (the Node.js
//! `generateSignature` function):
//!
//! - Header: `X-Mandrill-Signature: <base64(HMAC-SHA1(webhook_key, signed_string))>`
//! - Signed string: the webhook's URL exactly as configured in Mailchimp
//!   Transactional (including any query strings), followed by each `POST`
//!   form field's name and value concatenated directly to the string with no
//!   delimiter — `"{url}{key1}{value1}{key2}{value2}..."`, the field names
//!   sorted alphabetically. The guide warns that escaping or expanding the
//!   URL string (e.g. unescaping slashes) breaks verification, so the URL is
//!   used verbatim.
//! - Algorithm: HMAC-SHA1, base64-encoded (standard alphabet, padded). The
//!   guide explicitly notes that a hexadecimal signature "will not work".
//!   As with Twilio, the scheme is immune to SHA-1's collision attacks
//!   because the HMAC is keyed with the shared webhook authentication key.
//! - Key: the webhook's authentication key, generated when the webhook is
//!   created and viewable/resettable from the Webhooks page or the
//!   Transactional API; used as its UTF-8 bytes verbatim. An empty key fails
//!   closed with [`VerifyError::InvalidSecret`].
//!
//! # Not a raw-body scheme
//!
//! As with Twilio, the signature covers the parsed form fields, not the body
//! bytes: `mandrill_events` (a JSON array of batched events, up to 1,000) is
//! historically the only field. Callers parse the
//! `application/x-www-form-urlencoded` body themselves and pass every
//! received field via [`VerifyOptions::form_params`]; the URL goes in
//! [`VerifyOptions::request_url`]. Sorting is part of the signing scheme and
//! is applied here; callers pass fields in any order. A duplicate field name
//! keeps its received relative order (Mailchimp's official verifier uses
//! keyed dicts, which cannot represent duplicates).
//!
//! # Caller-supplied context
//!
//! Verification needs both [`VerifyOptions::request_url`] (the full URL,
//! exactly as configured with Mailchimp, including any query string) and
//! [`VerifyOptions::form_params`]. Omitting either fails closed with
//! [`VerifyError::MissingContext`] rather than degrading into a weaker check.
//!
//! # Replay protection
//!
//! Mailchimp Transactional signs no timestamp, so [`VerifyOptions::max_age`]
//! and the injected clock have **no effect** for this provider; that is
//! documented behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::String;
use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha1;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying Mailchimp Transactional's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Mandrill-Signature";

/// HMAC-SHA1 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 20;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    _raw_body: &[u8],
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
            reason: "Mailchimp Transactional signs the webhook URL; set VerifyOptions::request_url",
        })?;
    let params = options
        .form_params
        .as_ref()
        .ok_or(VerifyError::MissingContext {
            reason: "Mailchimp Transactional signs the sorted POST form fields; set VerifyOptions::form_params",
        })?;

    let provided = parse_signature(value)?;
    let key = webhook_key_bytes(secret.as_bytes())?;

    // Signed string: URL bytes first, then every form field's name and value
    // concatenated in byte-wise-sorted-by-name order, no delimiters
    // (`{url}{key1}{value1}{key2}{value2}...`). A stable sort preserves the
    // received relative order of same-named fields.
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

    if verify_hmac_sha1(key, &signed_string, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Returns the HMAC key bytes: the webhook authentication key exactly as
/// configured.
///
/// Mailchimp Transactional's scheme uses the key as UTF-8 bytes verbatim;
/// only an empty key is rejected, failing closed with
/// [`VerifyError::InvalidSecret`].
fn webhook_key_bytes(secret: &[u8]) -> Result<&[u8], VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "webhook authentication key is empty",
        });
    }
    Ok(secret)
}

/// Parses `X-Mandrill-Signature` into its 20 decoded signature bytes.
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

    /// Mailchimp Transactional publishes the construction and a reference
    /// verifier but no byte-exact example signature, so the vectors below are
    /// locally constructed over exactly the documented recipe (URL verbatim,
    /// sorted `key + value` fields with no delimiter, HMAC-SHA1 binary then
    /// base64) and cross-checked with `openssl dgst -sha1 -hmac`.
    ///
    /// The primary vector reproduces Mailchimp's own webhook-URL-check
    /// scenario (same guide): a POST of `mandrill_events=[]` signed with the
    /// documented generic key `test-webhook`. Reference command:
    ///
    /// ```text
    /// printf '%s' 'https://example.com/webhookmandrill_events[]' |
    ///   openssl dgst -sha1 -hmac 'test-webhook' -binary | base64
    /// ```
    const CHECK_KEY: &str = "test-webhook";
    const CHECK_URL: &str = "https://example.com/webhook";
    const CHECK_PARAMS: [(&str, &str); 1] = [("mandrill_events", "[]")];
    const CHECK_SIGNATURE: &str = "w0287Pp/mlZMgekXJ4ut/zSzSwc=";

    /// Locally constructed over a realistic batched event payload (an `open`
    /// event from the guide's `Eiffel Flowers` example) with a query string
    /// on the URL, same recipe as above:
    /// `printf '%s' \
    ///   'https://example.com/my-webhook?source=mandrill&v=2mandrill_events[{"event":"open",\
    ///   "msg":{"email":"flowerfriend@example.com","subject":"Roses"}}]' |
    ///   openssl dgst -sha1 -hmac 'txn-webhook-key-12345' -binary | base64`
    const EVENTS_KEY: &str = "txn-webhook-key-12345";
    const EVENTS_URL: &str = "https://example.com/my-webhook?source=mandrill&v=2";
    const EVENTS_PARAMS: [(&str, &str); 1] = [(
        "mandrill_events",
        r#"[{"event":"open","msg":{"email":"flowerfriend@example.com","subject":"Roses"}}]"#,
    )];
    const EVENTS_SIGNATURE: &str = "sXsdQW6AITXKa0GXohKSjYHKW5w=";

    /// Locally constructed with an *empty* parameter list (boundary case:
    /// Mailchimp always sends at least `mandrill_events`, but the recipe
    /// degenerates to signing the URL alone when no fields are present):
    /// `printf '%s' 'https://example.com/webhook' |
    ///  openssl dgst -sha1 -hmac 'test-webhook' -binary | base64`
    const EMPTY_PARAMS_SIGNATURE: &str = "JOiao7SCu2gXj37t3Zi9NUDyTbk=";

    /// Locally constructed over `"héllo, 🦀 world!"` as a `mandrill_events`
    /// field value (unicode boundary case), same recipe as above.
    const UNICODE_VALUE_SIGNATURE: &str = "slP4wR1KfiurSQqS0GLAwOaUMYk=";

    /// Locally constructed with multiple fields (`eventname` < `mandrill_events`
    /// < `msg_id` under byte-wise sorting), same recipe as above.
    const SORTED_MULTI_SIGNATURE: &str = "D+0bnklDFx/yUQ1G6b9RBdGQTG8=";

    /// Locally constructed with the `mandrill_events` field name sent twice
    /// (duplicates keep received relative order under this crate's stable
    /// sort), same recipe as above.
    const DUPLICATE_KEYS_SIGNATURE: &str = "+dtLALpd+/+yjAWVGUrhn4GX2Hg=";

    fn mandrill_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(params: &[(&str, &str)], signature: &str) -> Result<(), VerifyError> {
        verify_with_context("https://example.com/webhook", CHECK_KEY, params, signature)
    }

    fn verify_with_key(
        key: &str,
        params: &[(&str, &str)],
        signature: &str,
    ) -> Result<(), VerifyError> {
        verify_with_context("https://example.com/webhook", key, params, signature)
    }

    fn verify_with_url(
        url: &str,
        params: &[(&str, &str)],
        signature: &str,
    ) -> Result<(), VerifyError> {
        verify_with_context(url, CHECK_KEY, params, signature)
    }

    fn verify_with_context(
        url: &str,
        key: &str,
        params: &[(&str, &str)],
        signature: &str,
    ) -> Result<(), VerifyError> {
        let options = VerifyOptions::default()
            .with_request_url(url)
            .with_form_params(params.iter().copied());
        verify(
            crate::Provider::Mandrill,
            &mandrill_headers(signature),
            b"unused: not a raw-body scheme",
            &Secret::new(key),
            options,
        )
    }

    #[test]
    fn official_check_scenario_verifies() {
        assert_eq!(
            verify_with_url(CHECK_URL, &CHECK_PARAMS, CHECK_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn batched_events_payload_with_query_string_verifies() {
        let options = VerifyOptions::default()
            .with_request_url(EVENTS_URL)
            .with_form_params(EVENTS_PARAMS.iter().copied());
        assert_eq!(
            verify(
                crate::Provider::Mandrill,
                &mandrill_headers(EVENTS_SIGNATURE),
                b"unused: not a raw-body scheme",
                &Secret::new(EVENTS_KEY),
                options,
            ),
            Ok(())
        );
    }

    #[test]
    fn fields_verify_in_any_order() {
        // Sorting is the verifier's job: reversed input order must still pass.
        let reversed: Vec<(&str, &str)> = EVENTS_PARAMS.iter().rev().copied().collect();
        let options = VerifyOptions::default()
            .with_request_url(EVENTS_URL)
            .with_form_params(reversed);
        assert_eq!(
            verify(
                crate::Provider::Mandrill,
                &mandrill_headers(EVENTS_SIGNATURE),
                b"unused: not a raw-body scheme",
                &Secret::new(EVENTS_KEY),
                options,
            ),
            Ok(())
        );
    }

    #[test]
    fn boundary_param_lists_verify() {
        assert_eq!(verify_with(&[], EMPTY_PARAMS_SIGNATURE), Ok(()));
        assert_eq!(
            verify_with_key(
                EVENTS_KEY,
                &[("mandrill_events", "héllo, 🦀 world!")],
                UNICODE_VALUE_SIGNATURE,
            ),
            Ok(())
        );
    }

    #[test]
    fn sorted_multi_field_signed_string_verifies() {
        let params: [(&str, &str); 3] = [
            ("msg_id", "d"),
            ("mandrill_events", "[]"),
            ("eventname", "open"),
        ];
        assert_eq!(
            verify_with_key(EVENTS_KEY, &params, SORTED_MULTI_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn duplicate_field_names_keep_relative_order() {
        let params: [(&str, &str); 2] = [("mandrill_events", "[]"), ("mandrill_events", "[]")];
        assert_eq!(verify_with(&params, DUPLICATE_KEYS_SIGNATURE), Ok(()));
    }

    #[test]
    fn tampered_field_value_is_rejected() {
        let tampered: [(&str, &str); 1] = [("mandrill_events", "[{}]")];
        assert_eq!(
            verify_with(&tampered, CHECK_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_url_is_rejected() {
        assert_eq!(
            verify_with_url("https://example.com/evil", &CHECK_PARAMS, CHECK_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_subset_of_fields_is_rejected() {
        // Omitting a received field breaks the signed string the same way a
        // changed value does — Mailchimp's docs warn against validating
        // against a hardcoded subset of parameters.
        let missing: [(&str, &str); 0] = [];
        let options = VerifyOptions::default()
            .with_request_url(EVENTS_URL)
            .with_form_params(missing);
        assert_eq!(
            verify(
                crate::Provider::Mandrill,
                &mandrill_headers(EVENTS_SIGNATURE),
                b"unused: not a raw-body scheme",
                &Secret::new(EVENTS_KEY),
                options,
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn flipped_bit_in_signature_is_rejected() {
        // Same inputs, one byte flipped in the signature -> SignatureMismatch.
        let flipped = format!("A{}", &CHECK_SIGNATURE[1..]);
        assert_eq!(
            verify_with_url(CHECK_URL, &CHECK_PARAMS, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn missing_context_fails_closed() {
        let headers = mandrill_headers(CHECK_SIGNATURE);

        // Missing URL.
        let no_url = VerifyOptions::default().with_form_params(CHECK_PARAMS.iter().copied());
        assert!(matches!(
            verify(
                crate::Provider::Mandrill,
                &headers,
                b"unused",
                &Secret::new(CHECK_KEY),
                no_url,
            ),
            Err(VerifyError::MissingContext { .. })
        ));

        // Missing form params.
        let no_params = VerifyOptions::default().with_request_url(CHECK_URL);
        assert!(matches!(
            verify(
                crate::Provider::Mandrill,
                &headers,
                b"unused",
                &Secret::new(CHECK_KEY),
                no_params,
            ),
            Err(VerifyError::MissingContext { .. })
        ));
    }

    #[test]
    fn empty_webhook_key_is_invalid_secret() {
        let options = VerifyOptions::default()
            .with_request_url(CHECK_URL)
            .with_form_params(CHECK_PARAMS.iter().copied());
        assert!(matches!(
            verify(
                crate::Provider::Mandrill,
                &mandrill_headers(CHECK_SIGNATURE),
                b"unused",
                &Secret::new(""),
                options,
            ),
            Err(VerifyError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn missing_signature_header_is_missing_header() {
        let options = VerifyOptions::default()
            .with_request_url(CHECK_URL)
            .with_form_params(CHECK_PARAMS.iter().copied());
        assert_eq!(
            verify(
                crate::Provider::Mandrill,
                &Vec::<(String, String)>::new(),
                b"unused",
                &Secret::new(CHECK_KEY),
                options,
            ),
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER,
            })
        );
    }

    #[test]
    fn empty_signature_header_is_malformed_header() {
        let options = VerifyOptions::default()
            .with_request_url(CHECK_URL)
            .with_form_params(CHECK_PARAMS.iter().copied());
        assert_eq!(
            verify(
                crate::Provider::Mandrill,
                &mandrill_headers(""),
                b"unused",
                &Secret::new(CHECK_KEY),
                options,
            ),
            Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "header is empty",
            })
        );
    }

    #[test]
    fn non_base64_signature_is_bad_encoding() {
        let options = VerifyOptions::default()
            .with_request_url(CHECK_URL)
            .with_form_params(CHECK_PARAMS.iter().copied());
        assert_eq!(
            verify(
                crate::Provider::Mandrill,
                &mandrill_headers("$$$ not base64 $$$"),
                b"unused",
                &Secret::new(CHECK_KEY),
                options,
            ),
            Err(VerifyError::BadEncoding {
                reason: "signature is not valid standard base64",
            })
        );
    }

    #[test]
    fn hex_signature_is_bad_encoding() {
        // The guide explicitly calls out this failure mode: Mailchimp
        // base64-encodes the binary HMAC, so a hexadecimal signature (what a
        // naive caller might produce) must not verify — and must not verify
        // as a *hex digest of the same input* either. The 40-hex-char value
        // is rejected at the length gate, not as a signature mismatch.
        let options = VerifyOptions::default()
            .with_request_url(CHECK_URL)
            .with_form_params(CHECK_PARAMS.iter().copied());
        assert_eq!(
            verify(
                crate::Provider::Mandrill,
                &mandrill_headers("0000000000000000000000000000000000000000"),
                b"unused",
                &Secret::new(CHECK_KEY),
                options,
            ),
            Err(VerifyError::BadEncoding {
                reason: "signature does not decode to 20 bytes",
            })
        );
    }
}
