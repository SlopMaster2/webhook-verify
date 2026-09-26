//! Ripple (Collections) webhook signature verification.
//!
//! Scheme, per Ripple's official documentation
//! (<https://docs.ripple.com/products/collections/guides/verifying-webhooks>,
//! "Verifying Webhooks" — the header reference, the signed-string table, and
//! the reference Python verifier; Ripple publishes no byte-exact example
//! signature):
//!
//! - Headers: `X-Webhook-Signature: t=<timestamp>,v1=<hex_hmac_sha256>` and
//!   `X-Webhook-Timestamp: <epoch_ms>` — the timestamp rides in **both** places
//!   and must match verbatim ("Ensure they match verbatim", the docs' pitfall
//!   table).
//! - Signed string: `"{timestamp}.{sha256_raw_body_hex}"` — the
//!   `X-Webhook-Timestamp` value exactly as it appears in its header, a literal
//!   dot, then the lowercase hex SHA-256 digest of the raw request body bytes
//!   (the docs: "Concatenate the timestamp, a dot (`.`), and the SHA256 hex
//!   digest of the raw request body"). This is a **double-hash** scheme — the
//!   body is first SHA-256-digested, and *that hex digest* is what an
//!   HMAC-SHA256 covers — unique among the built-in providers. The docs warn
//!   that any transform of body or timestamp breaks verification.
//! - Algorithm: HMAC-SHA256 over the signed string, hex-encoded, keyed by the
//!   **base64-decoded** `signature_verification_key` ("This value is a
//!   base64-encoded symmetric secret"; the reference verifier calls
//!   `base64.b64decode(secret, validate=True)` — a single strict standard
//!   decode; "Secret double-base64 encoded" is the docs' first listed
//!   signature-mismatch pitfall).
//! - The `t` element must equal the `X-Webhook-Timestamp` header value
//!   **verbatim**; the reference verifier rejects any mismatch before it even
//!   computes an HMAC (`parts.get("t") != timestamp` → `False`), so this crate
//!   treats a mismatch as a malformed header rather than a signature problem.
//! - Ripple's docs define exactly one signature element (`v1`) and no rotation
//!   window, so a second `v1=` is treated as malformed rather than rotation
//!   (matching the Calendly/WorkOS/Coinbase treatment of their single
//!   signature fields). Unknown fields are discarded for forward
//!   compatibility.
//!
//! # Replay protection
//!
//! `X-Webhook-Timestamp` is epoch **milliseconds**. The timestamp is the first
//! component of the HMAC-covered signed string, so the shared symmetric
//! `|now - t| > max_age` window (default 300s) applies via the injected clock.
//! The reference verifier detects millisecond values (`ts_int >
//! 1_000_000_000_000` → floor to seconds) before the freshness comparison;
//! this provider applies the same floor to the parsed value before the shared
//! check — identical treatment to WorkOS and HubSpot (`spec.md` §3). The docs'
//! example passes `max_age_seconds=300`, matching the crate default.
//!
//! Note: Ripple sends the timestamp in **two** header locations — inside
//! `X-Webhook-Signature` (`t=`) and as the separate `X-Webhook-Timestamp`
//! header — so both are listed for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::String;
use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::{is_all_nul_key, sha256_hexdigest, verify_hmac_sha256};
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_millis};
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying Ripple's combined `t` and `v1` fields.
pub(crate) const SIGNATURE_HEADER: &str = "X-Webhook-Signature";

/// The header carrying the signed timestamp, which Ripple's `t=` field must
/// echo verbatim.
pub(crate) const TIMESTAMP_HEADER: &str = "X-Webhook-Timestamp";

/// The `t` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const TIME_FIELD: &str = "t";

/// The only signature scheme Ripple defines, per its docs.
const SCHEME: &str = "v1";

/// Field separator inside [`SIGNATURE_HEADER`].
const FIELD_SEPARATOR: char = ',';

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

/// Millisecond timestamps are floored to whole seconds past this bound; any
/// 13-digit epoch-ms "now" exceeds it while a 10-digit unix-seconds value does
/// not. Matches the reference verifier's `if ts_int > 1_000_000_000_000`.
const MILLIS_THRESHOLD: u64 = 1_000_000_000_000;

/// Milliseconds in one second.
const MILLIS_PER_SECOND: u64 = 1000;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let signature_value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;
    let timestamp_raw = headers
        .get(TIMESTAMP_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: TIMESTAMP_HEADER,
        })?;

    let parsed = parse_header(signature_value)?;

    // Timestamp shape is validated before the headers-agreement check and
    // before any signature work, matching every other timestamped provider
    // (Slack, WorkOS, ...): a garbage `X-Webhook-Timestamp` must fail closed
    // with a timestamp error even if `t=` echoes it byte-for-byte.
    let timestamp_millis = parse_millis(TIMESTAMP_HEADER, timestamp_raw)?;

    // The `t` element must equal `X-Webhook-Timestamp` verbatim — Ripple's
    // reference verifier rejects any mismatch *before* the HMAC check (a
    // headers-level consistency requirement, not independent signed material).
    if parsed.timestamp_raw != timestamp_raw {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "`t=` timestamp does not match `X-Webhook-Timestamp`",
        });
    }

    // Signed string is `{timestamp}.{sha256(raw_body)}`: the header value
    // verbatim (never re-serialized from the parsed number), a literal dot,
    // then the lowercase hex SHA-256 digest of the untouched raw body bytes.
    let body_hash = sha256_hexdigest(raw_body);
    let mut signed_string = String::with_capacity(timestamp_raw.len() + 1 + body_hash.len());
    signed_string.push_str(timestamp_raw);
    signed_string.push('.');
    signed_string.push_str(&body_hash);

    let key = decode_key(secret.as_bytes())?;

    if !verify_hmac_sha256(&key, signed_string.as_bytes(), &parsed.signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    // `X-Webhook-Timestamp` is epoch milliseconds, so floor to whole seconds
    // for the shared replay window — detecting the unit exactly as the docs'
    // reference does (`> 1_000_000_000_000`) and treating a seconds-sized
    // value as already whole seconds.
    let timestamp_seconds = if timestamp_millis > MILLIS_THRESHOLD {
        timestamp_millis / MILLIS_PER_SECOND
    } else {
        timestamp_millis
    };

    check_replay(timestamp_seconds, options)
}

/// A successfully parsed `X-Webhook-Signature` header value.
struct ParsedHeader<'a> {
    /// The `t=` timestamp value as sent (must equal `X-Webhook-Timestamp`
    /// verbatim).
    timestamp_raw: &'a str,
    /// The `v1=` signature decoded to its 32 bytes.
    signature: Vec<u8>,
}

/// Parses the header per Ripple's documented shape: split on `,`, split each
/// element on the first `=`, keep `t` and `v1`, discard every other field
/// (including unknown/future schemes).
///
/// Keys are compared after trimming surrounding whitespace — the comma-space
/// spelling (`t=..., v1=...`) that proxy header-folding and hand-copied values
/// produce must not silently drop a recognized key. Values are never trimmed:
/// the timestamp is reused verbatim (and must match the separate timestamp
/// header byte-for-byte), and trimming the signature would change what gets
/// hex-decoded.
///
/// Duplicate `t=` or `v1=` elements are rejected as ambiguous (`spec.md` §4.4)
/// rather than last-wins or first-wins. Ripple's docs define exactly one
/// signature element and no rotation window, so a second `v1=` is treated as
/// malformed rather than rotation.
fn parse_header(value: &str) -> Result<ParsedHeader<'_>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut timestamp_raw: Option<&str> = None;
    let mut signature: Option<Vec<u8>> = None;

    for element in value.split(FIELD_SEPARATOR) {
        let Some((key, val)) = element.split_once('=') else {
            continue;
        };
        let key = key.trim();

        if key == TIME_FIELD {
            if timestamp_raw.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                });
            }
            timestamp_raw = Some(val);
        } else if key == SCHEME {
            if val.is_empty() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1=` prefix",
                });
            }
            if signature.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
                });
            }
            let bytes = hex::decode(val).map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid hexadecimal",
            })?;
            if bytes.len() != SIGNATURE_LEN_BYTES {
                return Err(VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                });
            }
            signature = Some(bytes);
        }
        // All other fields (unknown schemes, future metadata) are discarded.
    }

    let timestamp_raw = match timestamp_raw {
        Some(raw) if !raw.is_empty() => raw,
        Some(_) => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "empty timestamp after `t=` prefix",
            });
        }
        None => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "missing `t=` timestamp",
            });
        }
    };

    let signature = signature.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "no `v1=` signature present",
    })?;

    Ok(ParsedHeader {
        timestamp_raw,
        signature,
    })
}

/// Base64-decodes the `signature_verification_key` held in [`Secret`].
///
/// Ripple delivers the key base64-encoded and the reference verifier decodes
/// it with `base64.b64decode(secret, validate=True)` — a single strict
/// standard-base64 decode (with padding) to raw key bytes, never a UTF-8
/// string. The docs' first listed signature-mismatch pitfall is exactly a
/// double-base64-encoded secret, so anything undecodable means the operator
/// did not paste the subscription value — fail closed with
/// [`VerifyError::InvalidSecret`] rather than keying the HMAC with garbage
/// (mirroring `adyen::decode_key`).
///
/// The all-NUL case is rejected too, and it is the *decoded* bytes that
/// matter: RFC 2104 zero-pads a short key, so a secret like `"AAAAAAAAAAA="`
/// — not all-NUL text, so it slips past the entry-point guard — decodes to a
/// key that is literally the empty one and would accept its publicly
/// computable signature (`spec.md` §4.7).
fn decode_key(secret: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let encoded = core::str::from_utf8(secret).map_err(|_| VerifyError::InvalidSecret {
        reason: "verification key must be base64-encoded",
    })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| VerifyError::InvalidSecret {
            reason: "verification key is not valid base64",
        })?;
    if decoded.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "verification key is empty",
        });
    }
    if is_all_nul_key(&decoded) {
        return Err(VerifyError::InvalidSecret {
            reason: "decoded verification key is only NUL bytes",
        });
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{SIGNATURE_HEADER, TIMESTAMP_HEADER, sha256_hexdigest};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// The raw key bytes the signed vectors were computed over.
    ///
    /// Locally constructed (Ripple publishes no example): 32 ASCII bytes. The
    /// signed-string construction and every digest were computed with the docs'
    /// reference recipe (`base64.b64decode` → `sha256(raw_body).hexdigest()` →
    /// `f"{timestamp}.{body_hash}"` → `hmac.new(secret, signing_string,
    /// hashlib.sha256).hexdigest()`) using Python's `hashlib`/`hmac`, and
    /// independently cross-checked against `openssl dgst -sha256` (body digest)
    /// and `openssl dgst -sha256 -mac hmac -macopt hexkey:` over the derived
    /// signing string. Replace them if Ripple ever publishes fixed vectors.
    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    /// The base64 encoding of [`KEY`] — the `signature_verification_key`
    /// Ripple exposes at subscription creation time.
    const SECRET: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    /// A Collections-style event body (payment lifecycle webhooks are Ripple's
    /// documented event type). Carried verbatim, re-parsing-free, as the raw
    /// body that gets SHA-256-digested.
    const BODY: &[u8] = b"{\"event_type\":\"payment.completed\",\"data\":{\"id\":\"0220000000000000000000001\",\"amount\":\"1.00\",\"currency\":\"USD\"}}";

    /// The `X-Webhook-Timestamp` value the primary vectors sign: epoch
    /// milliseconds with a deliberate non-round sub-second component (.123) so
    /// the ms→s replay floor is exercised. Floors to 1725364800.
    const TIME_MS: &str = "1725364800123";

    /// A seconds-sized `X-Webhook-Timestamp` (<= 1e12 ms), which the docs'
    /// reference treats as already whole seconds rather than flooring: the
    /// boundary case for the unit-detection floor.
    const TIME_SECS: &str = "1725364800";

    /// The lowercase hex SHA-256 digest of [`BODY`]: `printf '<body>' |
    /// openssl dgst -sha256` / Python `hashlib.sha256`.
    const BODY_DIGEST: &str = "f75c22abd8ddd686e59d3c3c46e09ae2fe44f8c8b267d240e65fb28f69d35f88";

    /// Hex HMAC-SHA256 of `1725364800123.{BODY_DIGEST}` keyed by [`KEY`].
    const SIGNATURE: &str = "644a4ae96e126d3ca75d7e24f84c5275704e0692ed2e928c26c91aa10dceb28f";

    /// Same construction over [`TIME_SECS`] (seconds-sized timestamp).
    const SECONDS_SIGNATURE: &str =
        "915b1d6a0df54d2c0280487e1ec1c407b43f63a4bb8320420214e7cb36b19f6c";

    /// Same construction over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "e5f51eef464d5f2f9212bae3be74a800289f41548aaac00c96c4d97e756edad7";

    /// Same construction over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "bb0ac92eff0ca450287cd5f34d3303b1d1c855933a3c1712d6c985970a3f61c1";

    fn verify_with(
        body: &[u8],
        signature_header: &str,
        timestamp_header: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Ripple,
            &[
                (SIGNATURE_HEADER, signature_header),
                (TIMESTAMP_HEADER, timestamp_header),
            ],
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh millis timestamp, matching v1.
    ///
    /// `now` is pinned to the timestamp floored to seconds so the replay check
    /// sees a zero skew.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("t={TIME_MS},v1={signature}"),
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        )
    }

    /// The locally constructed vector over the documented construction
    /// (`{timestamp}.{sha256(body)}`, base64 key) verifies end to end.
    #[test]
    fn constructed_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    /// The published constants are self-consistent: [`SECRET`] is the strict
    /// base64 encoding of [`KEY`], and [`BODY_DIGEST`] is the SHA-256 of
    /// [`BODY`] — guarding against a copy/paste slip when vectors are
    /// regenerated.
    #[test]
    fn constants_are_self_consistent() {
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(KEY),
            SECRET
        );
        assert_eq!(sha256_hexdigest(BODY), BODY_DIGEST);
    }

    /// The seconds-sized timestamp boundary verifies too — the docs' reference
    /// only floors values past 1e12 ms, so a smaller value must be treated as
    /// whole seconds.
    #[test]
    fn seconds_sized_timestamp_vector_verifies() {
        assert_eq!(
            verify_with(
                BODY,
                &format!("t={TIME_SECS},v1={SECONDS_SIGNATURE}"),
                TIME_SECS,
                &Secret::new(SECRET),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_fresh(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_fresh("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify(
            crate::Provider::Ripple,
            &[
                (
                    "x-webhook-signature",
                    format!("t={TIME_MS},v1={SIGNATURE}").as_str(),
                ),
                ("x-webhook-timestamp", TIME_MS),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn comma_space_spelling_is_tolerated() {
        // The `t=..., v1=...` spelling produced by proxy header-folding must
        // not drop the recognized keys.
        let value = format!("t={TIME_MS}, v1={SIGNATURE}");
        assert_eq!(
            verify_with(
                BODY,
                &value,
                TIME_MS,
                &Secret::new(SECRET),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // Forward compatibility: fields other than `t`/`v1` (including a
        // hypothetical future scheme) must not break verification.
        let value = format!("version=1,t={TIME_MS},v2=deadbeef,v1={SIGNATURE}");
        assert_eq!(
            verify_with(
                BODY,
                &value,
                TIME_MS,
                &Secret::new(SECRET),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
    }

    #[test]
    fn t_must_match_timestamp_header_verbatim() {
        // Ripple's reference verifier rejects a `t`/`X-Webhook-Timestamp`
        // mismatch *before* computing any HMAC ("Ensure they match verbatim"),
        // so this must come back as a MalformedHeader even with a valid-looking
        // signature attached — never a SignatureMismatch.
        let shifted = format!("t={},v1={SIGNATURE}", 1_725_364_800_122u64);
        let result = verify_with(
            BODY,
            &shifted,
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "`t=` timestamp does not match `X-Webhook-Timestamp`",
            })
        );

        // Symmetric direction: the `t=` field matches, but the separate
        // timestamp header is what the signer saw — an attacker cannot swap in
        // their own timestamp header either.
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            &(1_725_364_800_122u64.to_string()),
            &Secret::new(SECRET),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "`t=` timestamp does not match `X-Webhook-Timestamp`",
            })
        );
    }

    #[test]
    fn negative_flipped_hex_character_fails() {
        // Flip one hex character *within* the alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}0{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_fresh(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // The body's SHA-256 digest is glued into the signed string, so any
        // body mutation after signing breaks verification.
        assert_eq!(
            verify_fresh(
                b"{\"event_type\":\"payment.completed\",\"data\":{\"id\":\"tampered\"}}",
                SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // Timestamp and `t=` moved in lockstep (so the verbatim-equality gate
        // passes), but the signature covers the *original* timestamp: the HMAC
        // must not verify.
        let shifted = "1725364800124";
        let result = verify_with(
            BODY,
            &format!("t={shifted},v1={SIGNATURE}"),
            shifted,
            &Secret::new(SECRET),
            clocked_at(1_725_364_801, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        // Any other key (here the raw-key bytes fed in as if base64) must not
        // verify.
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            TIME_MS,
            &Secret::new("ZGlmZmVyZW50LWtleS1ieXRlcw=="),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn invalid_secret_fails_closed() {
        // Base64 of something that decodes fine but is the wrong key matters
        // above; these are the undecodable-shape cases the docs' reference
        // returns `False` for — surfaced distinctly as InvalidSecret so an
        // operator sees their configured key is malformed, not that a delivery
        // is forged.
        for (secret, reason) in [
            ("not base64!", "verification key is not valid base64"),
            (
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", // valid alphabet, no padding
                "verification key is not valid base64",
            ),
        ] {
            let result = verify_with(
                BODY,
                &format!("t={TIME_MS},v1={SIGNATURE}"),
                TIME_MS,
                &Secret::new(secret),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            );
            assert_eq!(
                result,
                Err(VerifyError::InvalidSecret { reason }),
                "secret: {secret:?}"
            );
        }

        // An empty secret decodes to an empty key — fail closed rather than
        // key the HMAC with a key anyone can reproduce.
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            TIME_MS,
            &Secret::new(""),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "secret is empty"
            })
        );
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature delivered 301s after the (floored) signing instant.
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(1_725_364_800 + 301, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_future_timestamp_out_of_tolerance() {
        // Symmetric window: |now - t| > max_age in either direction is
        // rejected, matching the shared replay semantics of every timestamped
        // provider.
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(1_725_364_800 - 301, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_within_tolerance_verifies_at_window_edges() {
        // Exactly max_age old/new is still inside the closed window, and the
        // floor drops the .123 ms sub-second component before this comparison.
        for now in [1_725_364_800u64 - 300, 1_725_364_800 + 300] {
            let result = verify_with(
                BODY,
                &format!("t={TIME_MS},v1={SIGNATURE}"),
                TIME_MS,
                &Secret::new(SECRET),
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn replay_floor_matches_workos_treatment() {
        // The unsigned ms remainder must not leak into the window: a delivery
        // signed at 1725364800123 ms must survive a "now" at 1725364800299 ms
        // (the .299 differs by 176ms but the same whole second).
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        // `max_age: None` explicitly disables the recency check.
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(1_725_364_800 + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify(
            crate::Provider::Ripple,
            &[("X-Webhook-Timestamp", TIME_MS)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::Ripple,
            &[(
                "X-Webhook-Signature",
                format!("t={TIME_MS},v1={SIGNATURE}").as_str(),
            )],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );

        let both_missing = verify(
            crate::Provider::Ripple,
            &Vec::<(String, String)>::new(),
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            both_missing,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_signature_header_errors_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                format!("v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `t=` timestamp",
                },
            ),
            (
                format!("t={TIME_MS}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1=` signature present",
                },
            ),
            (
                format!("t={TIME_MS},v1="),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1=` prefix",
                },
            ),
            (
                format!("t=,v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty timestamp after `t=` prefix",
                },
            ),
            (
                format!("t={TIME_MS},t={},v1={SIGNATURE}", 1_725_364_800_122u64),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                },
            ),
            (
                format!(
                    "t={TIME_MS},v1=0000000000000000000000000000000000000000000000000000000000000000,v1={SIGNATURE}"
                ),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                &value,
                TIME_MS,
                &Secret::new(SECRET),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn malformed_timestamp_header_errors_distinctly() {
        // The timestamp rides in its own header; its shape is enforced by the
        // shared epoch-milliseconds parser with the same fail-closed rules as
        // every other timestamped provider.
        for value in [
            "",
            "not-a-number",
            format!("+{TIME_MS}").as_str(),
            format!(" {TIME_MS}").as_str(),
            "99999999999999999999999",
        ] {
            let result = verify_with(
                BODY,
                &format!("t={TIME_MS},v1={SIGNATURE}"),
                value,
                &Secret::new(SECRET),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::MalformedHeader {
                    reason:
                        "header is empty"
                        | "timestamp is not valid epoch milliseconds"
                        | "timestamp overflows epoch milliseconds",
                    ..
                }) => {}
                other => panic!("expected MalformedHeader for {value:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            format!("t={TIME_MS},v1=zzzz"),
            format!("t={TIME_MS},v1=abc"),
            format!("t={TIME_MS},v1=40f2d4d8a1a0f6a9c9b1f4e2d3c4b5a67890abcd"),
        ];
        for value in cases {
            let result = verify_with(
                BODY,
                &value,
                TIME_MS,
                &Secret::new(SECRET),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }

    /// The all-NUL rule applies to the **decoded** key, not the raw base64
    /// text (`spec.md` §4.7).
    ///
    /// `decode_key` base64-decodes the secret, and RFC 2104 zero-pads any key
    /// shorter than the block size, so `"AAAAAAAAAAA="` decodes to three zero
    /// bytes and is *literally the empty key*: its MAC is publicly computable,
    /// so a deployment configured that way accepts a forgery. The entry-point
    /// guard inspects the raw string, where `"AAAAAAAAAAA="` is neither empty,
    /// whitespace-only, nor all-NUL bytes.
    #[test]
    fn all_nul_base64_secret_is_the_empty_key_and_is_rejected() {
        // The empty key's HMAC-SHA256 over Ripple's documented signing string
        // (`{timestamp}.{sha256(raw_body)}`, hex), computed with the same
        // recipe as [`SIGNATURE`]:
        //   python3 -c "import hmac,hashlib;
        //     print(hmac.new(b'', b'1725364800123.f75c22ab...', hashlib.sha256).hexdigest())"
        const EMPTY_KEY_SIGNATURE: &str =
            "0287132342e92e490c8760b7a8e251ece004207b51a1a35017519a03624f5b70";

        for secret in ["AAAAAAAAAAA=", "AA=="] {
            let result = verify_with(
                BODY,
                &format!("t={TIME_MS},v1={EMPTY_KEY_SIGNATURE}"),
                TIME_MS,
                &Secret::new(secret),
                clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
            );
            assert_eq!(
                result,
                Err(VerifyError::InvalidSecret {
                    reason: "decoded verification key is only NUL bytes"
                }),
                "secret: {secret:?}"
            );
        }
    }

    /// The "entirely" boundary, in the permissive direction: a key that
    /// *contains* a NUL is legitimate material and must be used exactly as
    /// configured, not rejected.
    #[test]
    fn base64_secret_containing_nul_but_not_only_nul_is_used_as_configured() {
        use base64::Engine;

        // 32 bytes: one leading NUL then the ASCII of the real test key. This
        // is a different key from [`SECRET`], so it must surface as a
        // forgery — the signature simply does not match, which is what proves
        // the key reached the MAC instead of being rejected up front.
        let nul_prefixed =
            base64::engine::general_purpose::STANDARD.encode([&[0u8][..], KEY].concat());
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            TIME_MS,
            &Secret::new(nul_prefixed),
            clocked_at(1_725_364_800, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }
}
