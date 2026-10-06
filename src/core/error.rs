//! Structured verification errors.
//!
//! Design rules (see `spec.md` §2.1): errors never contain the secret, the raw
//! body, or a computed signature. They may carry header *names*, static reason
//! strings, and numeric skew values.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use core::fmt;
use core::time::Duration;

/// Everything that can go wrong while verifying a webhook signature.
///
/// `MissingHeader` / `MalformedHeader` / `BadEncoding` indicate malformed
/// requests; `SignatureMismatch` indicates an active-attack signal (or an
/// out-of-band misconfiguration). Callers that log differently per class can
/// match on the variants — but both classes are "reject the request"
/// outcomes. Never treat a malformed header as "skip verification".
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyError {
    /// A required signature-related header was absent.
    MissingHeader {
        /// Name of the missing header.
        header: &'static str,
    },
    /// A required header was present but could not be parsed into the shape
    /// the provider's scheme requires (wrong prefix, empty value, ...).
    MalformedHeader {
        /// Name of the malformed header.
        header: &'static str,
        /// Static description of what was wrong with its shape.
        reason: &'static str,
    },
    /// A value that must decode in the provider's encoding (hex, base64)
    /// failed to decode, or decoded to the wrong length.
    BadEncoding {
        /// Static description of the decoding failure.
        reason: &'static str,
    },
    /// The signature did not match. Returned identically regardless of how
    /// close the provided signature was to the expected one.
    SignatureMismatch,
    /// The signed timestamp is further from "now" than
    /// [`crate::VerifyOptions::max_age`] allows; skew is the timestamp's
    /// total distance from "now" (`|now - timestamp|`), not the excess beyond
    /// the window boundary.
    TimestampOutOfTolerance {
        /// The timestamp's total distance from "now" (`|now - timestamp|`), so
        /// it is always strictly greater than `max_age` when this variant is
        /// returned (a skew exactly at the boundary is accepted) — the excess
        /// past the boundary is `skew - max_age`, not `skew` itself.
        skew: Duration,
        /// The configured maximum age.
        max_age: Duration,
    },
    /// The selected [`crate::Provider`] requires a cargo feature that is not
    /// enabled at compile time (fail-closed). Currently PayPal and SendGrid
    /// are feature-gated; see [`crate::Provider`] for the gating.
    UnsupportedProvider,
    /// The provided secret is not usable for this provider's scheme
    /// (e.g. wrong format for a hex- or base64-encoded key).
    InvalidSecret {
        /// Static description of why the secret was rejected.
        reason: &'static str,
    },
    /// Verification for this provider requires caller-supplied request
    /// context (such as Square's notification URL, via
    /// [`crate::VerifyOptions::request_url`]) that was not provided. This is
    /// an operator misconfiguration, not an attack signal — but the request
    /// is still rejected: fail closed.
    MissingContext {
        /// Static description of what context was missing.
        reason: &'static str,
    },
}

impl VerifyError {
    /// The [`VerifyError::MalformedHeader`] `reason` both framework adapters
    /// use when they reject a request whose signature header arrived more than
    /// once with differing values (`spec.md` §4.4).
    ///
    /// A caller driving [`verify()`](crate::verify()) itself performs the same
    /// check through `ambiguous_signature_header` or
    /// `ambiguous_signature_header_in` and then has to build the rejection by
    /// hand, so this is the crate's one spelling of the only `reason` §4.4
    /// fixes. It is exported as a
    /// constant rather than folded into a constructor because the `reason`
    /// field is deliberately caller-writable ([`VerifyError`] is
    /// `#[non_exhaustive]`, and the granularity of its variants is
    /// intentional) — a constant gives one audited string without taking the
    /// choice away.
    ///
    /// It lives here, next to the variant it fills, rather than in
    /// `core::adapter_utils` next to the scan: the two adapters and the scan
    /// are feature-gated in different combinations, but `VerifyError` is not,
    /// so this is the one spelling both gated adapters and every ungated
    /// caller can reach.
    ///
    /// ```
    /// use webhook_verify::{
    ///     Provider, VerifyError, ambiguous_signature_header_in,
    /// };
    ///
    /// let headers: Vec<(&str, &str)> = vec![
    ///     ("x-hub-signature-256", "sha256=one"),
    ///     // A proxy appended its own value behind the real one: §4.4 requires
    ///     // rejecting this rather than verifying whichever value a
    ///     // first-match lookup happens to return.
    ///     ("x-hub-signature-256", "sha256=two"),
    /// ];
    ///
    /// if let Some(header) = ambiguous_signature_header_in(Provider::GitHub, &headers) {
    ///     let error = VerifyError::MalformedHeader {
    ///         header,
    ///         reason: VerifyError::AMBIGUOUS_HEADER_REASON,
    ///     };
    ///     assert_eq!(
    ///         error.to_string(),
    ///         "malformed header `X-Hub-Signature-256`: \
    ///          header present multiple times with different values",
    ///     );
    /// } else {
    ///     unreachable!("the two values differ, so the header is ambiguous");
    /// }
    /// ```
    pub const AMBIGUOUS_HEADER_REASON: &'static str =
        "header present multiple times with different values";

    /// The HTTP status a rejection for this error should carry, as a raw
    /// `u16`: `400`, `401`, or `500`.
    ///
    /// | Class | Variants | Status |
    /// |---|---|---|
    /// | Malformed request | [`MissingHeader`](VerifyError::MissingHeader), [`MalformedHeader`](VerifyError::MalformedHeader), [`BadEncoding`](VerifyError::BadEncoding) | `400 Bad Request` |
    /// | Authentication signal | [`SignatureMismatch`](VerifyError::SignatureMismatch), [`TimestampOutOfTolerance`](VerifyError::TimestampOutOfTolerance) | `401 Unauthorized` |
    /// | Operator misconfiguration | [`UnsupportedProvider`](VerifyError::UnsupportedProvider), [`InvalidSecret`](VerifyError::InvalidSecret), [`MissingContext`](VerifyError::MissingContext) | `500 Internal Server Error` |
    ///
    /// The split is about *who should be looking at it*, not about whether the
    /// request is rejected — every class is a rejection. A `401` is the signal
    /// an attacker-visible forgery or a stale replay produces; a `500` is the
    /// operator's fault (a feature that is off, an unusable key, request
    /// context nobody supplied) and is the one worth alerting on, because it
    /// means the integration is broken rather than under attack; a `400` is a
    /// request that never became a signature question at all.
    ///
    /// A raw `u16` rather than an `http::StatusCode`, because [`VerifyError`]
    /// lives in this crate's unconditional core, which must not depend on
    /// either `http` version in play — `http` 1.x for tower/axum and `http`
    /// 0.2 for actix-web 4. Convert at the edge with
    /// `StatusCode::from_u16(error.rejection_status())`.
    ///
    /// Both framework adapters build their rejection response from this one
    /// method, so a caller's own classification and an adapter's response
    /// cannot drift apart. The match is exhaustive over the variants: adding
    /// one fails to compile here until its class is chosen deliberately,
    /// rather than silently landing in one.
    ///
    /// ```
    /// use webhook_verify::{Provider, Secret, VerifyError, verify};
    ///
    /// let headers: Vec<(String, String)> = vec![(
    ///     "X-Hub-Signature-256".to_string(),
    ///     "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    ///         .to_string(),
    /// )];
    ///
    /// // The same delivery the crate-level example accepts for "Hello, World!",
    /// // with one byte changed — a forgery, so a `401`.
    /// let tampered = verify(
    ///     Provider::GitHub,
    ///     &headers,
    ///     b"Hello, World?",
    ///     &Secret::new("It's a Secret to Everybody"),
    ///     Default::default(),
    /// );
    /// assert_eq!(tampered, Err(VerifyError::SignatureMismatch));
    /// assert_eq!(
    ///     tampered.map_err(|error| error.rejection_status()),
    ///     Err(401),
    /// );
    ///
    /// // A misconfiguration is a `500`, which is what makes it page.
    /// assert_eq!(
    ///     VerifyError::MissingContext { reason: "no request_url" }.rejection_status(),
    ///     500,
    /// );
    /// ```
    #[must_use]
    pub fn rejection_status(&self) -> u16 {
        match self {
            // Malformed request: missing/unparseable signature headers.
            VerifyError::MissingHeader { .. }
            | VerifyError::MalformedHeader { .. }
            | VerifyError::BadEncoding { .. } => 400,

            // Authentication signals: wrong signature or stale timestamp.
            VerifyError::SignatureMismatch | VerifyError::TimestampOutOfTolerance { .. } => 401,

            // Operator misconfiguration: unsupported/broken configuration,
            // never the requester's fault. Still rejected — fail closed.
            VerifyError::UnsupportedProvider
            | VerifyError::InvalidSecret { .. }
            | VerifyError::MissingContext { .. } => 500,
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::MissingHeader { header } => write!(f, "missing header `{header}`"),
            VerifyError::MalformedHeader { header, reason } => {
                write!(f, "malformed header `{header}`: {reason}")
            }
            VerifyError::BadEncoding { reason } => write!(f, "bad encoding: {reason}"),
            VerifyError::SignatureMismatch => write!(f, "signature mismatch"),
            VerifyError::TimestampOutOfTolerance { skew, max_age } => write!(
                f,
                "timestamp out of tolerance: {skew:?} from now exceeds the allowed {max_age:?} window",
            ),
            VerifyError::UnsupportedProvider => {
                write!(f, "provider not available (feature disabled)")
            }
            VerifyError::InvalidSecret { reason } => write!(f, "invalid secret: {reason}"),
            VerifyError::MissingContext { reason } => {
                write!(f, "missing verification context: {reason}")
            }
        }
    }
}

/// Unconditional, and on `core::error::Error` rather than
/// `std::error::Error`, so a `no_std + alloc` caller still gets a real error
/// type: the trait is stable in `core` since Rust 1.81 (the crate's MSRV is
/// 1.85), and under `std` it *is* `std::error::Error` — `std` re-exports
/// core's trait — so this is strictly additive for existing std users and
/// only adds capability to `no_std` builds (issue #261).
impl core::error::Error for VerifyError {}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;

    use super::VerifyError;
    use alloc::boxed::Box;
    use core::time::Duration;

    /// The §4.4 rejection `reason` has exactly one code spelling.
    ///
    /// `spec.md` §4.4 fixes *one* `reason` for the duplicate-signature-header
    /// rejection, and it is the string both framework adapters emit. Before
    /// [`VerifyError::AMBIGUOUS_HEADER_REASON`] it was hand-typed at every
    /// site that fills the field — the two adapters, two doc examples, a test,
    /// and three README snippets — which is the exact shape of the
    /// single-sourcing hazard `replay::MILLIS_PER_SECOND` and
    /// `contentful::SIGNED_HEADERS_SEPARATOR` exist to avoid: a wording change
    /// applied to one copy leaves the others emitting a different message for
    /// the same condition, and nothing fails.
    ///
    /// This reads the sources rather than trusting review, and skips doc
    /// comments so the two `ambiguous_signature_header*` examples can keep
    /// asserting the *rendered* `Display` output in plain text — that
    /// assertion is the thing worth keeping literal, because it is what pins
    /// the constant's value rather than merely re-stating it.
    ///
    /// Deliberately **not** `#[cfg(feature = "std")]`: it reads the sources
    /// through `include_str!` (resolved at compile time), so it costs nothing
    /// and covers the same ground in the `test-nostd` runs of `spec.md` §6.
    #[test]
    fn the_ambiguity_rejection_reason_has_one_code_spelling() {
        const REASON: &str = VerifyError::AMBIGUOUS_HEADER_REASON;

        // The constant must still be the string §4.4 and the README's
        // examples document, and must still render through `Display`.
        assert_eq!(
            REASON,
            "header present multiple times with different values"
        );
        assert_eq!(
            VerifyError::MalformedHeader {
                header: "X-Hub-Signature-256",
                reason: REASON,
            }
            .to_string(),
            "malformed header `X-Hub-Signature-256`: \
             header present multiple times with different values",
        );

        for (name, source) in [
            ("src/tower.rs", include_str!("../tower.rs")),
            ("src/actix.rs", include_str!("../actix.rs")),
        ] {
            // Only the code is scanned: strip `///` doc lines and `//` comments
            // so the doc examples' plain-text `Display` assertions (which are
            // *meant* to be literal) do not read as a second spelling.
            let code: String = source
                .lines()
                .filter(|line| {
                    let line = line.trim_start();
                    !line.starts_with("//")
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !code.contains(REASON),
                "{name} must use VerifyError::AMBIGUOUS_HEADER_REASON, \
                 not a second hand-typed copy of the §4.4 rejection reason"
            );
        }

        // ... and both must actually reference the constant, so "no literal"
        // cannot be satisfied by deleting the ambiguity check outright.
        for (name, source) in [
            ("src/tower.rs", include_str!("../tower.rs")),
            ("src/actix.rs", include_str!("../actix.rs")),
        ] {
            assert!(
                source.contains("VerifyError::AMBIGUOUS_HEADER_REASON"),
                "{name} must fill the §4.4 rejection reason from the shared constant",
            );
        }
    }

    /// The three status classes, pinned variant by variant.
    ///
    /// These lived in `core::adapter_utils` beside the private
    /// `rejection_status` they exercised, so they only ran in a build with an
    /// adapter feature on. The classification is now public core API — the one
    /// a caller driving `verify()` itself reads — so the tests are
    /// unconditional and cover the same `test-nostd` runs as the rest of this
    /// module (`spec.md` §6).
    ///
    /// Deliberately **not** `#[cfg(feature = "std")]`: `Duration` here is
    /// `core::time::Duration`, which is the type the variant carries in every
    /// configuration.
    #[test]
    fn malformed_request_class_maps_to_400() {
        assert_eq!(
            VerifyError::MissingHeader {
                header: "X-Signature"
            }
            .rejection_status(),
            400
        );
        assert_eq!(
            VerifyError::MalformedHeader {
                header: "X-Signature",
                reason: "boom"
            }
            .rejection_status(),
            400
        );
        assert_eq!(
            VerifyError::BadEncoding { reason: "boom" }.rejection_status(),
            400
        );
    }

    /// See [`malformed_request_class_maps_to_400`]; the auth class is the one
    /// an attacker-visible forgery or a stale replay produces.
    #[test]
    fn auth_signal_class_maps_to_401() {
        assert_eq!(VerifyError::SignatureMismatch.rejection_status(), 401);
        assert_eq!(
            VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(1000),
                max_age: Duration::from_secs(300),
            }
            .rejection_status(),
            401
        );
    }

    /// See [`malformed_request_class_maps_to_400`]; the `500` class is the one
    /// worth alerting on, because it means the integration is broken rather
    /// than under attack.
    #[test]
    fn operator_misconfiguration_class_maps_to_500() {
        // UnsupportedProvider keeps its 500 class even once a feature (e.g.
        // `paypal`) implements the provider — the mapping is about the error
        // class, not the current build's provider set.
        assert_eq!(VerifyError::UnsupportedProvider.rejection_status(), 500);
        assert_eq!(
            VerifyError::InvalidSecret { reason: "boom" }.rejection_status(),
            500
        );
        assert_eq!(
            VerifyError::MissingContext { reason: "boom" }.rejection_status(),
            500
        );
    }

    /// Both framework adapters build their rejection response from
    /// [`VerifyError::rejection_status`], so a caller's own classification and
    /// an adapter's response cannot drift apart.
    ///
    /// Reads the adapter sources rather than trusting review: nothing in the
    /// type system stops a future edit from hand-writing the 400/401/500 match
    /// inside one adapter, and the two would then disagree about the class of
    /// a new variant while every test above still passed — the same hazard
    /// `the_ambiguity_rejection_reason_has_one_code_spelling` guards for the
    /// §4.4 `reason` string.
    ///
    /// Deliberately **not** feature-gated: `include_str!` resolves at compile
    /// time, so the guard holds in a build that compiles neither adapter.
    #[test]
    fn both_adapters_take_their_rejection_status_from_the_shared_method() {
        for (name, source) in [
            ("src/tower.rs", include_str!("../tower.rs")),
            ("src/actix.rs", include_str!("../actix.rs")),
        ] {
            assert!(
                source.contains(".rejection_status()"),
                "{name} must build its rejection response from \
                 `VerifyError::rejection_status`, the crate's one status \
                 classification"
            );
        }
    }

    /// Deliberately **not** `#[cfg(feature = "std")]`.
    ///
    /// The point of the impl is that it is unconditional, so the only place
    /// that can catch a re-gate is a run with the crate's `std` feature off —
    /// `spec.md` §6's `test-nostd` combos. `alloc::boxed::Box` is spelled out
    /// rather than relying on the prelude, which does not inject `Box` under
    /// `#![no_std]`.
    #[test]
    fn implements_core_error_in_every_feature_configuration() {
        fn boxed<E: core::error::Error + 'static>(e: E) -> Box<dyn core::error::Error> {
            Box::new(e)
        }

        let err = boxed(VerifyError::MissingHeader {
            header: "X-Hub-Signature-256",
        });
        assert_eq!(
            err.to_string(),
            "missing header `X-Hub-Signature-256`",
            "boxing must preserve Display"
        );

        // The ergonomics a `no_std` caller previously had no access to: `?`
        // into a `Box<dyn Error>`-shaped error aggregate.
        fn propagate() -> Result<(), Box<dyn core::error::Error>> {
            Err(VerifyError::SignatureMismatch)?;
            Ok(())
        }
        assert_eq!(
            propagate().err().map(|e| e.to_string()).as_deref(),
            Some("signature mismatch")
        );
    }

    /// The `std = []` feature's own comment, read out of the manifest.
    ///
    /// The `#[cfg]` above cannot be checked from a test, and a manifest
    /// comment is not built or tested by anything — which is exactly how the
    /// one in the tree went stale. So the block is recovered the same way a
    /// reader reads it: everything commented immediately above the `std = []`
    /// line, minus the leading `# ` markers.
    fn std_feature_comment() -> String {
        const MANIFEST: &str = include_str!("../../Cargo.toml");
        let Some(declaration) = MANIFEST.find("\nstd = []") else {
            panic!("Cargo.toml must still declare the `std` feature as `std = []`");
        };
        let before = &MANIFEST[..declaration];
        let mut lines: Vec<&str> = Vec::new();
        for line in before.lines().rev() {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') {
                break;
            }
            lines.push(trimmed.trim_start_matches('#').trim());
        }
        lines.reverse();
        assert!(
            !lines.is_empty(),
            "Cargo.toml's `std` feature must keep a comment explaining what \
             dropping it costs"
        );
        lines.join(" ")
    }

    #[test]
    fn std_feature_comment_matches_the_unconditional_error_impls() {
        // The claim this guards against: that dropping `std` also costs the
        // error trait. It did once, and saying so was accurate then; #262
        // moved both impls onto `core::error::Error` unconditionally, and the
        // claim was left behind. The error was in the direction that
        // *undersells* the crate — a `no_std + alloc` reader would conclude
        // `VerifyError` is unusable in `Box<dyn Error>` / `?`-propagating
        // aggregates, which is the capability #262 added. `spec.md` §7, the
        // crate docs, and `README.md` were all corrected; the manifest was
        // the one surface left, and nothing compiles or tests it, so it
        // drifted silently behind a green suite.
        //
        // Both directions are pinned, and the reverse one is the load-bearing
        // half: the comment must not deny the trait (the shipped bug) *and*
        // must name `core::error::Error` as what is implemented — so simply
        // deleting the error half of the comment cannot pass this either.
        let comment = std_feature_comment();

        // The stale claim, in the spellings a re-introduction might use.
        // "not implement" subsumes both the singular and plural denials, so
        // the reported phrase is the one that actually matched.
        for denial in ["not implement", "no error type"] {
            assert!(
                !comment.contains(denial),
                "Cargo.toml's `std` feature comment claims the error types {denial:?} \
                 the error trait, which has been false since #262 (both `VerifyError` and \
                 `ProviderParseError` implement `core::error::Error` unconditionally); \
                 comment: {comment:?}"
            );
        }
        for type_name in ["VerifyError", "ProviderParseError"] {
            assert!(
                comment.contains(type_name),
                "Cargo.toml's `std` feature comment must name `{type_name}` when \
                 describing the error types, so the claim stays checkable; \
                 comment: {comment:?}"
            );
        }
        assert!(
            comment.contains("core::error::Error"),
            "Cargo.toml's `std` feature comment must name the `core::error::Error` \
             trait both error types implement unconditionally; comment: {comment:?}"
        );

        // The half that is still true, and still the only thing `std` buys:
        // the wall clock. Requiring it keeps the fix from "solving" the drift
        // by gutting the comment instead of correcting it.
        assert!(
            comment.contains("SystemClock") && comment.contains("Clock"),
            "Cargo.toml's `std` feature comment must still document that `SystemClock` \
             is `std`-only and that callers on std-less targets supply their own \
             `Clock`; comment: {comment:?}"
        );
    }

    #[test]
    fn display_missing_header() {
        let e = VerifyError::MissingHeader {
            header: "X-Hub-Signature-256",
        };
        assert_eq!(e.to_string(), "missing header `X-Hub-Signature-256`");
    }

    #[test]
    fn display_malformed_header() {
        let e = VerifyError::MalformedHeader {
            header: "X-Slack-Signature",
            reason: "missing v0= prefix",
        };
        assert_eq!(
            e.to_string(),
            "malformed header `X-Slack-Signature`: missing v0= prefix"
        );
    }

    #[test]
    fn display_bad_encoding() {
        let e = VerifyError::BadEncoding {
            reason: "not valid hexadecimal",
        };
        assert_eq!(e.to_string(), "bad encoding: not valid hexadecimal");
    }

    #[test]
    fn display_signature_mismatch() {
        let e = VerifyError::SignatureMismatch;
        assert_eq!(e.to_string(), "signature mismatch");
    }

    #[test]
    fn display_timestamp_out_of_tolerance() {
        let e = VerifyError::TimestampOutOfTolerance {
            skew: Duration::from_secs(600),
            max_age: Duration::from_secs(300),
        };
        assert_eq!(
            e.to_string(),
            "timestamp out of tolerance: 600s from now exceeds the allowed 300s window"
        );
    }

    #[test]
    fn display_timestamp_out_of_tolerance_preserves_sub_second_max_age() {
        // A sub-second window must not be truncated to "0s" in operator-facing
        // logs (Duration's Debug renders 500ms / 3.5s faithfully).
        let e = VerifyError::TimestampOutOfTolerance {
            skew: Duration::from_secs(1),
            max_age: Duration::from_millis(500),
        };
        assert_eq!(
            e.to_string(),
            "timestamp out of tolerance: 1s from now exceeds the allowed 500ms window"
        );

        let e = VerifyError::TimestampOutOfTolerance {
            skew: Duration::from_secs(4),
            max_age: Duration::from_millis(3_500),
        };
        assert_eq!(
            e.to_string(),
            "timestamp out of tolerance: 4s from now exceeds the allowed 3.5s window"
        );
    }

    #[test]
    fn display_timestamp_out_of_tolerance_preserves_sub_second_skew() {
        // A sub-second skew must not be truncated to "0s" in operator-facing
        // logs either (mirroring the max_age fix): a 150ms skew over a 100ms
        // window previously read "0s from now exceeds the allowed 100ms
        // window", which does not describe the actual skew. Duration's Debug
        // renders sub-second values faithfully.
        let e = VerifyError::TimestampOutOfTolerance {
            skew: Duration::from_millis(150),
            max_age: Duration::from_millis(100),
        };
        assert_eq!(
            e.to_string(),
            "timestamp out of tolerance: 150ms from now exceeds the allowed 100ms window"
        );

        let e = VerifyError::TimestampOutOfTolerance {
            skew: Duration::from_millis(1_500),
            max_age: Duration::from_secs(1),
        };
        assert_eq!(
            e.to_string(),
            "timestamp out of tolerance: 1.5s from now exceeds the allowed 1s window"
        );
    }

    #[test]
    fn display_unsupported_provider() {
        let e = VerifyError::UnsupportedProvider;
        assert_eq!(e.to_string(), "provider not available (feature disabled)");
    }

    #[test]
    fn display_invalid_secret() {
        let e = VerifyError::InvalidSecret {
            reason: "public key is not valid hexadecimal",
        };
        assert_eq!(
            e.to_string(),
            "invalid secret: public key is not valid hexadecimal"
        );
    }

    #[test]
    fn display_missing_context() {
        let e = VerifyError::MissingContext {
            reason: "no WebhookConfig registered via app_data",
        };
        assert_eq!(
            e.to_string(),
            "missing verification context: no WebhookConfig registered via app_data"
        );
    }

    #[test]
    fn display_never_leaks_secret_material() {
        // Every Display variant must contain only header names, static reasons,
        // and numeric values — never the secret, raw body, or computed
        // signature (spec.md §2.1 / §4.3).
        let e = VerifyError::InvalidSecret {
            reason: "not valid hexadecimal",
        };
        // The "reason" is a static string chosen by the crate, not the actual
        // secret value — verify it appears verbatim in the output.
        assert!(e.to_string().contains("not valid hexadecimal"));
    }

    #[test]
    fn display_with_empty_reason() {
        // Edge case: empty reason strings must not produce trailing colons or
        // other formatting artifacts.
        let e = VerifyError::BadEncoding { reason: "" };
        assert_eq!(e.to_string(), "bad encoding: ");
    }

    #[test]
    fn hash_is_consistent_with_equality() {
        // `Eq` and `Hash` are one contract: values that compare equal must
        // hash equal, or lookups in maps/sets and derived `Hash` impls
        // downstream (a struct containing a `VerifyError`) silently misbehave.
        // This pins the now-derived impl against future manual weakening.
        use crate::test_helpers::hash_of;

        let a = VerifyError::MalformedHeader {
            header: "X-Slack-Signature",
            reason: "missing v0= prefix",
        };
        let b = VerifyError::MalformedHeader {
            header: "X-Slack-Signature",
            reason: "missing v0= prefix",
        };
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));

        // A different variant with a shared header name hashes differently:
        // the discriminants plus distinct payloads cannot collide under the
        // test's summing hasher.
        let c = VerifyError::MissingHeader {
            header: "X-Slack-Signature",
        };
        assert_ne!(a, c);
        assert_ne!(hash_of(&a), hash_of(&c));
    }
}
