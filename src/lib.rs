//! # webhook-verify
//!
//! One function to verify inbound webhook signatures from major providers.
//!
//! Every backend that accepts webhooks ends up hand-rolling HMAC verification,
//! and getting subtle details wrong: re-serialized bodies instead of raw bytes,
//! non-constant-time comparison, missing replay protection, provider-specific
//! encoding quirks. This crate does it once, correctly, behind a single API.
//!
//! ## Example: verifying a GitHub delivery
//!
//! The [`VerifyError`] assertions make this snippet run as a doc-test, so a
//! regression in GitHub's verification fails `cargo test` through its
//! doctests rather than only through the unit tests.
//!
//! ```
//! # #![deny(unused_imports)]
//! use webhook_verify::{
//!     Provider, Secret, VerifyError, ambiguous_signature_header_in, verify,
//! };
//!
//! let headers: Vec<(String, String)> = vec![(
//!     "X-Hub-Signature-256".to_string(),
//!     "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_string(),
//! )];
//! let raw_body = b"Hello, World!";
//!
//! // `verify()` reads the first value for a name and cannot see a second one,
//! // so a proxy that appended its own value behind a real one is invisible to
//! // it — while the pair table still holds it. Spec §4.4 obliges every caller
//! // of `verify()` to run this check first; the `tower` and `actix` adapters
//! // run it for you, and a caller extracting headers itself does not.
//! assert_eq!(ambiguous_signature_header_in(Provider::GitHub, &headers), None);
//!
//! let result = verify(
//!     Provider::GitHub,
//!     &headers,
//!     raw_body,
//!     &Secret::new("It's a Secret to Everybody"),
//!     Default::default(),
//! );
//!
//! assert_eq!(result, Ok(()));
//!
//! // A tampered delivery fails closed through the same call.
//! let tampered = verify(
//!     Provider::GitHub,
//!     &headers,
//!     b"Hello, World?",
//!     &Secret::new("It's a Secret to Everybody"),
//!     Default::default(),
//! );
//! assert_eq!(tampered, Err(VerifyError::SignatureMismatch));
//! ```
//!
//! `raw_body` **must** be the exact bytes the provider sent — before any JSON
//! parsing or re-serialization. Verification against anything else will fail.
//! The check above reports the provider-spelled name of a signature header that
//! arrived more than once with differing values; identical repeats are fine.
//! See [`ambiguous_signature_header_in`] for what it scans, and the crate's
//! `spec.md` §4.4 for the full contract.
//!
//! ## Supported providers
//!
//! A single [`Provider`] enum drives signature verification for:
//!
//! | Provider | Scheme |
//! |---|---|
//! | Stripe | HMAC-SHA256 over `timestamp.body`, `Stripe-Signature` (`t=`,`v1=` rotation list) + tolerance window |
//! | GitHub | HMAC-SHA256, `X-Hub-Signature-256` |
//! | Bitbucket | HMAC-SHA256, `sha256=` prefix, `X-Hub-Signature` |
//! | Contentful | hex HMAC-SHA256 of `[method, path, signedHeaders, body].join('\n')`, `x-contentful-signature` (headers and order self-described by `x-contentful-signed-headers`) + `x-contentful-timestamp` (epoch ms) replay window (needs `VerifyOptions::request_method` + `request_url`) |
//! | Box | HMAC-SHA256 over `{raw_body}{delivery_timestamp}`, base64, `BOX-SIGNATURE-PRIMARY`/`BOX-SIGNATURE-SECONDARY` (rotation-safe) + RFC 3339 timestamp tolerance window |
//! | Intercom | HMAC-SHA1, `sha1=` prefix, `X-Hub-Signature` |
//! | Expo (EAS) | HMAC-SHA1, `sha1=` prefix, `expo-signature` |
//! | Meta (Graph API, Messenger, Instagram, WhatsApp Cloud API) | HMAC-SHA256 over raw body, hex, `sha256=` prefix, `X-Hub-Signature-256` (App Secret key, no timestamp) |
//! | HubSpot | HMAC-SHA256 over `{method}{uri}{body}{timestamp}` (epoch ms), base64, `X-HubSpot-Signature-V3` + tolerance window (needs `VerifyOptions::request_method` + `request_url`) |
//! | Klaviyo | HMAC-SHA256 over `{raw_body}{timestamp}`, hex, `Klaviyo-Signature` + `Klaviyo-Timestamp` (IMF-fixdate) replay window |
//! | Shopify | HMAC-SHA256, base64, `X-Shopify-Hmac-Sha256` |
//! | Slack | HMAC-SHA256 `v0=` scheme, `X-Slack-Signature` + `X-Slack-Request-Timestamp` tolerance window |
//! | Square | HMAC-SHA256 over notification URL + body, base64, `x-square-hmacsha256-signature` (needs `VerifyOptions::request_url`) |
//! | Tally | HMAC-SHA256 over raw body, base64, `Tally-Signature` (no timestamp) |
//! | FastSpring | HMAC-SHA256 over raw body, base64, `X-FS-Signature` (per-webhook HMAC secret, no timestamp; header may arrive with varying case) |
//! | GoCardless | HMAC-SHA256 over raw body, hex, `Webhook-Signature` (endpoint secret used verbatim, no prefix, no timestamp) |
//! | Mollie (next-gen webhooks) | HMAC-SHA256 over raw body, hex, `sha256=` prefix, `X-Mollie-Signature` (per-webhook signing secret, no timestamp) |
//! | Twilio | HMAC-SHA1 (base64) over URL + sorted form params, `X-Twilio-Signature` (form params decoded from the raw body; needs `VerifyOptions::request_url`) |
//! | Mandrill (Mailchimp Transactional) | HMAC-SHA1 (base64) over URL + sorted form params, `X-Mandrill-Signature` (form params decoded from the raw body; needs `VerifyOptions::request_url`) |
//! | LINE (Messaging API) | HMAC-SHA256 over raw body, base64, `x-line-signature` (channel-secret key, no timestamp) |
//! | Twitch | HMAC-SHA256 over `{message_id}{message_timestamp}{raw_body}`, hex, `sha256=` prefix, `Twitch-Eventsub-Message-Signature` + RFC 3339 timestamp tolerance window |
//! | Typeform | HMAC-SHA256, base64, `sha256=` prefix, `Typeform-Signature` |
//! | Discord | Ed25519 public-key signatures (no shared secret): `X-Signature-Ed25519` + `X-Signature-Timestamp` tolerance window |
//! | PayPal | RSASSA-PKCS1-v1_5 SHA-256, `PayPal-Transmission-Sig` (+ `-Id`/`-Time`/`-Cert-Url`/`-Auth-Algo`), X.509 cert + webhook ID + `PayPal-Transmission-Time` tolerance window |
//! | SendGrid | ECDSA P-256 over `{timestamp}{raw_body}` (no separator), `X-Twilio-Email-Event-Webhook-Signature` + `X-Twilio-Email-Event-Webhook-Timestamp` tolerance window |
//! | Paystack | HMAC-SHA512 over raw body, hex, `x-paystack-signature` (no timestamp) |
//! | Paddle | HMAC-SHA256 over `{ts}:{raw_body}`, hex, `Paddle-Signature` + tolerance window |
//! | PagerDuty | HMAC-SHA256 over raw body, hex, `v1=` prefix, `X-PagerDuty-Signature` (`v1=` rotation list) |
//! | Pusher | HMAC-SHA256 over raw POST body, hex, `X-Pusher-Signature` (keyed by the app token's secret, no timestamp) |
//! | Linear | HMAC-SHA256, `linear-signature` |
//! | LaunchDarkly | HMAC-SHA256 over raw body, hex, `X-LD-Signature` (no timestamp) |
//! | Notion | HMAC-SHA256 over raw body, hex, `sha256=` prefix, `X-Notion-Signature` |
//! | Nylas | HMAC-SHA256 over raw body, bare hex, `x-nylas-signature` (no timestamp) |
//! | Zoom | HMAC-SHA256 `v0=` scheme, `x-zm-signature` + `x-zm-request-timestamp` tolerance window |
//! | Cloudflare (Stream) | HMAC-SHA256 over `time.body`, hex, `Webhook-Signature` + `time=` timestamp tolerance window |
//! | CircleCI (outbound webhooks) | HMAC-SHA256 over raw body, hex, `v1=` prefix, `circleci-signature` (versioned signature list, no timestamp) |
//! | Coinbase (CDP) | HMAC-SHA256 over `t.body`, hex, `X-Hook0-Signature` + tolerance window |
//! | Dropbox | HMAC-SHA256, `X-Dropbox-Signature` |
//! | DocuSign (Connect) | HMAC-SHA256 over raw body, base64, `X-Docusign-Signature-1` (first configured key, no timestamp) |
//! | Fintoc | HMAC-SHA256 over `t.body`, hex, `Fintoc-Signature` (`t=,v1=` list) + tolerance window |
//! | Razorpay | HMAC-SHA256 over raw body, hex, `X-Razorpay-Signature` (no timestamp) |
//! | Recharge | Plain SHA-256 over `{client_secret}{raw_body}`, hex, `X-Recharge-Hmac-Sha256` (no timestamp, not an HMAC) |
//! | Ripple (Collections) | HMAC-SHA256 over `{timestamp}.{sha256(body)}`, hex, `X-Webhook-Signature` + `X-Webhook-Timestamp` replay window (base64 key) |
//! | Lemon Squeezy | HMAC-SHA256, `X-Signature` (bare hex, no timestamp) |
//! | Xero | HMAC-SHA256, base64, `x-xero-signature` |
//! | Sentry | HMAC-SHA256 over raw body, hex, `Sentry-Hook-Signature` (no timestamp) |
//! | Adyen | HMAC-SHA256 over raw body, base64, `HmacSignature` (hex key, no timestamp) |
//! | Airwallex | HMAC-SHA256 over `{timestamp}{raw_body}`, hex, `x-signature` + `x-timestamp` (epoch ms→s replay window) |
//! | Mux | HMAC-SHA256 over `t.body`, hex, `Mux-Signature` + tolerance window |
//! | Zendesk | HMAC-SHA256 over `{timestamp}{raw_body}`, base64, `X-Zendesk-Webhook-Signature` + tolerance window |
//! | WorkOS | HMAC-SHA256 over `t.body`, hex, `WorkOS-Signature` (`t=,v1=` list, millis timestamp floored for the replay window) |
//! | WooCommerce | HMAC-SHA256 over raw body, base64, `X-WC-Webhook-Signature` (no timestamp) |
//! | Calendly | HMAC-SHA256 over `t.body`, hex, `Calendly-Webhook-Signature` (`t=,v1=` list) + tolerance window |
//! | Vercel | HMAC-SHA1 over raw body, hex, `x-vercel-signature` (no timestamp) |
//! | Webflow | HMAC-SHA256 over `{timestamp}:{raw_body}` (epoch ms), hex, `x-webflow-signature` + `x-webflow-timestamp` replay window |
//! | X (formerly Twitter) | HMAC-SHA256 over raw body, base64, `sha256=` prefix, `x-twitter-webhooks-signature` (no timestamp) |
//! | Tailscale | HMAC-SHA256 over `t.body`, hex, `Tailscale-Webhook-Signature` (`t=,v1=` list, rotation-safe) + tolerance window |
//! | Standard Webhooks | HMAC-SHA256 with replay + rotation lists, `webhook-signature`/`webhook-id`/`webhook-timestamp` or Svix-branded `svix-signature`/`svix-id`/`svix-timestamp` (Svix, Clerk, Resend, Bird/MessageBird, GitLab 19.0+ signing tokens, OpenAI, Warp, Loops, Anthropic, Gemini, Brex, BigCommerce, Lithic, incident.io, Supabase, Etsy, Sardine, Dodo Payments, Zapier, Vanta, SafetyKit, Prescience, TaskRabbit, Liveblocks, Flip, Replicate, inai, Drata, Nash, Render, Yoco, Novu, Crossmint, Daytona, Polar, Helcim, 360Learning, Celitech, Natural, Origami, Parallel, Openlayer, Acolad, Allo, Lexe, ...) |
//! | Custom | User-supplied HMAC scheme via [`Provider::Custom`] (SHA-256/SHA-1/SHA-512, hex/base64, optional prefix + timestamp replay window when a `timestamp_header` is set) |
//!
//! PayPal and SendGrid ship behind crate features; calling [`verify()`] with
//! them while the feature is off fails closed with [`VerifyError::UnsupportedProvider`].
//!
//! ## Crate features
//!
//! - `std` *(default)* — provides the wall clock used for replay protection.
//!   Disable for `no_std + alloc` targets (validated against
//!   `wasm32-unknown-unknown`); supply your own [`Clock`] for timestamped
//!   providers. Dropping it does **not** change the error types:
//!   [`VerifyError`] and [`ProviderParseError`] implement
//!   `core::error::Error` unconditionally (stable in `core` since Rust 1.81,
//!   below the MSRV), which `std::error::Error` re-exports anyway.
//! - `sendgrid` — enables the SendGrid provider (ECDSA P-256).
//! - `paypal` — enables the PayPal provider (RSA, X.509, CRC-32).
//! - `http` — `HeaderMap` impl for `http::HeaderMap` (axum, tower, hyper),
//!   plus `ambiguous_signature_header`, the §4.4 duplicate-header check
//!   that `HeaderMap`'s first-match-only lookup structurally cannot perform —
//!   call it before [`verify`] when you extract headers yourself instead of
//!   going through an adapter. (Plain text rather than an intra-doc link: this
//!   list is always compiled, the item it names is not.) The impl's own code is
//!   `no_std`-clean and the full test suite runs with the crate's `std`
//!   feature off in this configuration (spec §6), catching a `std` leak in the
//!   impl. The feature is nonetheless **std-bounded in practice**: the `http`
//!   crate itself requires `std`, so a genuinely std-less build cannot include
//!   it (spec §6, §7).
//! - `tower` — generic `tower::Layer`/`Service` middleware (works with axum
//!   routers too; `http` is implied). The `no_std + alloc` guarantee covers
//!   the core verification path only, so `tower` also implies `std` — the
//!   adapters are async framework glue and cannot build without it.
//! - `actix` — actix-web 4 extractor + header bridge. Also implies `std`, for
//!   the same reason.
//!
//! See [`verify_any`] for cross-secret key rotation during a rotation window.
//! The `tower` and `actix` adapters reach the same semantics without leaving
//! the adapter: `VerifyLayer::with_fallback_secrets` and
//! `WebhookConfig::with_fallback_secrets` (plain text rather than intra-doc
//! links, for the reason above).
//!
//! ## Security properties
//!
//! - All signature comparisons use [`subtle::ConstantTimeEq`], constant-time
//!   across candidates of the expected length. A candidate of a different
//!   length is rejected without a byte-by-byte comparison; that length is
//!   public information, so nothing secret leaks (issue #294).
//! - Bodies are hashed exactly as received; never re-encoded.
//! - A signature header that arrives twice with *differing* values is
//!   ambiguous and must be rejected before [`verify`] is trusted (spec §4.4).
//!   The `tower` and `actix` adapters do that for you; a caller extracting
//!   headers itself runs `ambiguous_signature_header` (an `http::HeaderMap`,
//!   `http` feature) or [`ambiguous_signature_header_in`] (a name/value pair
//!   table, no feature required) first, because [`HeaderMap`] exposes
//!   first-match lookup only and cannot see the second value itself.
//! - No secret material ever appears in errors, `Debug`, or `Display` output.
//! - An empty secret fails closed: it is not a weak key but no key at all, so
//!   every provider keyed by it rejects it with [`VerifyError::InvalidSecret`]
//!   before touching the request (PayPal and SendGrid ignore the secret and
//!   verify against [`VerifyOptions::verifying_material`] instead). So does a
//!   secret that is only whitespace — the same failure one character over — or
//!   one that is only NUL bytes, which HMAC zero-padding makes the *same key*
//!   as the empty one; but a secret that merely *contains* whitespace or a NUL
//!   is used exactly as configured: nothing is trimmed before the MAC. A
//!   secret that is not itself all-NUL but *decodes* to an all-NUL key is the
//!   same empty key one encoding layer deeper, so the three providers that
//!   hex- or base64-decode it into HMAC key material (Adyen, Ripple, Standard
//!   Webhooks) re-apply the rule to the decoded bytes. Discord hex-decodes its
//!   secret too, but into an Ed25519 *public key*, which no HMAC is keyed with
//!   and which RFC 2104 cannot zero-pad into anything; its degenerate shape is
//!   the low-order point the next bullet rejects.
//! - Ed25519 verification (Discord) uses dalek's **strict** equation, so a
//!   low-order ("weak") public key is rejected rather than used — a weak key
//!   forges signatures outright, and one is a valid compressed point, so the
//!   key-format check cannot see it. It is reported as
//!   [`VerifyError::InvalidSecret`], i.e. as operator misconfiguration.
//! - Parsing paths return [`VerifyError`] instead of panicking on
//!   attacker-controlled input.
//!
//! [`subtle::ConstantTimeEq`]: https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

mod core;
mod providers;

#[cfg(test)]
mod test_helpers;

#[cfg(feature = "actix")]
pub mod actix;

#[cfg(feature = "tower")]
pub mod tower;

#[cfg(feature = "std")]
pub use crate::core::SystemClock;
#[cfg(feature = "http")]
pub use crate::core::adapter_utils::ambiguous_signature_header;
pub use crate::core::adapter_utils::ambiguous_signature_header_in;
pub use crate::core::{Clock, HeaderMap, Secret, VerifyError, VerifyOptions, VerifyingKeyMaterial};
pub use crate::providers::{
    CustomScheme, Encoding, HashAlg, Provider, ProviderParseError, TimestampUnit, verify,
    verify_any,
};

/// Header-name constants for the Klaviyo provider.
///
/// Klaviyo's HMAC covers only `Klaviyo-Signature` and `Klaviyo-Timestamp`;
/// [`Provider::Klaviyo`] verification needs no other header. These constants
/// exist for the caller-side pair check Klaviyo delegates (`spec.md` §3): after
/// a successful [`verify`], match [`klaviyo::WEBHOOK_ID_HEADER`] against the
/// body's `meta.klaviyo_webhook_id`.
pub mod klaviyo {
    pub use crate::providers::klaviyo::{SIGNATURE_HEADER, TIMESTAMP_HEADER, WEBHOOK_ID_HEADER};
}

#[cfg(test)]
mod docs {
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Splits a `major.minor[.patch]` version into numbers, so two versions can
    /// be compared without pulling in a semver dependency the crate does not
    /// otherwise need. A third component that is not a number (a pre-release
    /// suffix such as `0.3.0-rc.1`) yields `None`: the caller decides what to
    /// do with it, and the guard below only ever *narrows* on it.
    fn version_numbers(version: &str) -> (u64, u64, Option<u64>) {
        let mut components = version.trim().split('.');
        let major = components
            .next()
            .and_then(|component| component.parse().ok())
            .unwrap_or_else(|| {
                panic!("version {version:?} does not begin with a numeric major component")
            });
        let minor = components
            .next()
            .and_then(|component| component.parse().ok())
            .unwrap_or_else(|| panic!("version {version:?} has no numeric minor component"));
        (
            major,
            minor,
            components.next().and_then(|patch| patch.parse().ok()),
        )
    }

    /// The `[package]` version from the manifest, read the way a reader reads
    /// it: the first `version = "…"` under the `[package]` header and before
    /// the next section.
    fn manifest_version() -> &'static str {
        const MANIFEST: &str = include_str!("../Cargo.toml");
        MANIFEST
            .lines()
            .skip_while(|line| line.trim() != "[package]")
            .skip(1)
            .take_while(|line| !line.trim_start().starts_with('['))
            .find_map(|line| line.trim().strip_prefix("version = "))
            .and_then(|quoted| quoted.trim().strip_prefix('"'))
            .and_then(|version| version.strip_suffix('"'))
            .unwrap_or_else(|| {
                panic!("Cargo.toml must still declare a quoted `[package] version = \"…\"`")
            })
    }

    /// The version requirement a README dependency line asks for, in either
    /// Cargo spelling: `webhook-verify = "0.2"` (bare) or
    /// `webhook-verify = { version = "0.2", features = ["http"] }` (table).
    /// The table form has further keys after `version`, so the value ends at
    /// the next `"` rather than at the closing brace.
    fn readme_requirement(line: &str) -> Option<&str> {
        let value = line.trim().strip_prefix("webhook-verify = ")?.trim();
        if let Some(quoted) = value.strip_prefix('"') {
            return quoted.strip_suffix('"');
        }
        let table = value.strip_prefix('{')?;
        let version = table
            .split_once("version = ")?
            .1
            .trim_start()
            .strip_prefix('"')?;
        Some(&version[..version.find('"')?])
    }

    /// The version a README line tags, for the `git tag v…` command in the
    /// Releasing checklist. A trailing `# …` comment on the same line is not
    /// part of the tag name, so it is cut before the version is read.
    fn readme_release_tag(line: &str) -> Option<&str> {
        let version = line.trim().strip_prefix("git tag v")?;
        let version = version.split('#').next()?.trim();
        (!version.is_empty()).then_some(version)
    }

    /// The requirement a reader who copy-pastes a `README.md` dependency
    /// snippet ends up with must be able to resolve to the release the rest of
    /// the README documents.
    ///
    /// The claim being guarded is the one the README makes seven times: "add
    /// this line to your `Cargo.toml`". For a `0.y.z` crate a caret requirement
    /// is *not* loose — `version = "0.1"` means `>=0.1.0, <0.2.0` — so a
    /// snippet that names an older minor line silently resolves away from
    /// the current release instead of failing. Every snippet said `0.1` for
    /// the whole 0.2 line (#288), which meant a copied install line could not
    /// get 0.2.0 at all, and could not express the `CustomScheme` field the
    /// README's own provider table advertises.
    ///
    /// Nothing compiles a README `toml` fence, so the bump to 0.2.0 could not
    /// have failed the build and the drift survived a green suite — the same
    /// shape as the stale `std` feature comment #264 fixed. Hence this guard.
    #[test]
    fn readme_dependency_snippets_resolve_to_the_current_release() {
        const README: &str = include_str!("../README.md");
        let (major, minor, patch) = version_numbers(manifest_version());
        // A two-component manifest version is pre-release, so no stable patch
        // has shipped; treat its floor as 0, which admits `"0.2"` but not
        // `"0.2.1"`.
        let manifest_patch = patch.unwrap_or(0);

        let mut checked = 0_usize;
        for line in README.lines() {
            let Some(requirement) = readme_requirement(line) else {
                continue;
            };
            checked += 1;

            let (req_major, req_minor, req_patch) = version_numbers(requirement);
            assert_eq!(
                (req_major, req_minor),
                (major, minor),
                "README.md's `webhook-verify = \"{requirement}\"` names release line \
                 {req_major}.{req_minor}.x while the manifest is {major}.{minor}.x — a caret \
                 requirement on a `0.y.z` crate pins the reader to that line rather than \
                 failing, so copying this line installs a release the rest of this file does \
                 not describe"
            );
            if let Some(req_patch) = req_patch {
                assert!(
                    req_patch <= manifest_patch,
                    "README.md's `webhook-verify = \"{requirement}\"` requires a patch release \
                     newer than the manifest's {major}.{minor}.{manifest_patch}, which is not \
                     released"
                );
            }
        }

        // Without this the loop above passes vacuously if the README's
        // dependency lines are ever renamed or reformatted out of recognition.
        assert!(
            checked > 0,
            "README.md must still show `webhook-verify` as a `Cargo.toml` dependency in a form \
             this guard can read"
        );
    }

    /// The release tag the README's Releasing checklist tells a maintainer to
    /// push must name the release the manifest is about to publish.
    ///
    /// Step 3 of that checklist was still `git tag v0.1.0` after the manifest
    /// moved to 0.2.0 (#292). Following it literally publishes 0.2.0 and then
    /// tags *that* commit `v0.1.0`, so the tag consumers are pointed at for a
    /// stable reference names a release line the manifest has already left —
    /// and `Cargo.toml`'s semver-checks lints, which are written against a
    /// specific published version, stop naming a version a reader can find.
    ///
    /// `readme_dependency_snippets_resolve_to_the_current_release` (#288) does
    /// not cover this line: `readme_requirement` only recognizes lines that
    /// start with `webhook-verify = ` and yield a Cargo version requirement,
    /// and a `git tag` command is not a dependency snippet. Same shape as that
    /// guard's motivation — nothing compiles a README `sh` fence, so the stale
    /// tag could not have failed the build.
    #[test]
    fn readme_release_tag_names_the_manifest_version() {
        const README: &str = include_str!("../README.md");
        let manifest = manifest_version();
        let (major, minor, patch) = version_numbers(manifest);

        let mut checked = 0_usize;
        for line in README.lines() {
            let Some(tag) = readme_release_tag(line) else {
                continue;
            };
            checked += 1;

            let (tag_major, tag_minor, tag_patch) = version_numbers(tag);
            assert_eq!(
                (tag_major, tag_minor, tag_patch),
                (major, minor, patch),
                "README.md's Releasing checklist tags the release `v{tag}`, but the manifest is \
                 `{manifest}` — step 1 of that checklist bumps `version` first, so a tag that \
                 does not match it publishes one release and names another. Update the tag in the \
                 same change that bumps the version"
            );
        }

        // Without this the loop above passes vacuously if the checklist's
        // `git tag` line is ever reworded out of recognition.
        assert!(
            checked > 0,
            "README.md's Releasing checklist must still show a `git tag v…` command in a form \
             this guard can read"
        );
    }

    /// The key a TOML line declares, or `None` if the line declares none.
    ///
    /// Recognizes the shapes README dependency snippets use — a bare key, a
    /// dotted key, either quoted. A table header is not a key, and a line with
    /// no `=` declares none, which is also what keeps a `# comment` out: a
    /// comment line holding an `=` puts its `#` where a key would be, and `#`
    /// is not a character a bare key can contain.
    fn toml_key(line: &str) -> Option<&str> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('[') {
            return None;
        }
        let (key, _value) = trimmed.split_once('=')?;
        let key = key.trim();
        let is_bare_key = !key.is_empty()
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '"' | '\''));
        is_bare_key.then_some(key)
    }

    /// Every key a single README `toml` fence declares twice under one table
    /// header — `(line, table, key)` for each repeat — and how many
    /// declarations were checked.
    ///
    /// This is a line scan rather than a TOML parse. Cargo's rejection of a
    /// repeated key is "cannot overwrite a value", so duplicate detection is the
    /// whole of the check, and a dev-dependency on a TOML parser to police a
    /// dependency snippet would cost more than the defect does. README fences
    /// also nest inside list items, so the scan trims indentation instead of
    /// assuming a fence opens in column 1, and a table's identity spans the
    /// whole fence: re-declaring `[dependencies]` twice in one fence is the
    /// same parse error as repeating a key inside it.
    fn readme_duplicate_toml_keys(readme: &str) -> (Vec<(usize, String, String)>, usize) {
        let root = String::from("(before the first table header)");
        let mut duplicates = Vec::new();
        let mut declared: Vec<(String, String)> = Vec::new();
        let mut table = root.clone();
        let mut in_toml = false;
        let mut checked = 0_usize;

        for (index, line) in readme.lines().enumerate() {
            let trimmed = line.trim();
            if let Some(info) = trimmed.strip_prefix("```") {
                if in_toml {
                    in_toml = false;
                    declared.clear();
                    table.clone_from(&root);
                } else {
                    in_toml = info.starts_with("toml");
                }
                continue;
            }
            if !in_toml {
                continue;
            }
            if trimmed.starts_with('[') {
                table = String::from(trimmed);
                continue;
            }
            let Some(key) = toml_key(line) else {
                continue;
            };
            checked += 1;
            if declared.iter().any(|(declared_table, declared_key)| {
                declared_table == &table && declared_key == key
            }) {
                duplicates.push((index + 1, table.clone(), String::from(key)));
            } else {
                declared.push((table.clone(), String::from(key)));
            }
        }
        (duplicates, checked)
    }

    /// A README `toml` fence must not declare one key twice under one table
    /// header.
    ///
    /// `readme_dependency_snippets_resolve_to_the_current_release` (#288) reads
    /// a dependency line's *version*, which is blind to this: four alternatives
    /// naming the correct `0.2` are four correct lines. The Installation block
    /// listed four `webhook-verify` keys in one `[dependencies]` table as if
    /// they were one manifest, so the first thing a reader does — add the
    /// dependency — failed to parse, and the parse error pointed at a line that
    /// reads as obviously fine (#376).
    #[test]
    fn readme_toml_fences_declare_each_key_once_per_table() {
        const README: &str = include_str!("../README.md");

        let (duplicates, checked) = readme_duplicate_toml_keys(README);
        let reported = duplicates
            .iter()
            .map(|(line, table, key)| {
                format!("README.md:{line} declares `{key}` a second time under `{table}`")
            })
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            duplicates.is_empty(),
            "{reported} — Cargo rejects a repeated key before it looks at a version, so an install \
             snippet a reader cannot paste is the first failure they meet. Give each alternative its \
             own fence, or one line each"
        );

        // Without this the scan above passes vacuously once the README's
        // dependency snippets stop being `toml` fences.
        assert!(
            checked > 0,
            "README.md must still show its dependency snippets as `toml` fences, or this guard can \
             no longer see the keys they declare"
        );
    }

    /// The duplicate-key scan has to catch the shape that shipped, ignore the
    /// same key under two different tables, and read a fence nested in a list
    /// item — or it enforces nothing while looking thorough.
    #[test]
    fn readme_duplicate_toml_keys_are_read_per_table_and_per_fence() {
        let readme = "\
```toml
[dependencies]
webhook-verify = \"0.2\"
webhook-verify = { version = \"0.2\", features = [\"http\"] }
```

- A variant inside a list item:

  ```toml
  [dependencies]
  webhook-verify = { version = \"0.2\", features = [\"tower\"] }
  ```

```toml
[dependencies]
axum = \"0.8\"

[dev-dependencies]
axum = \"0.8\"
```
";

        let (duplicates, checked) = readme_duplicate_toml_keys(readme);
        assert_eq!(
            duplicates
                .iter()
                .map(|(_, table, key)| (table.as_str(), key.as_str()))
                .collect::<Vec<_>>(),
            [("[dependencies]", "webhook-verify")],
            "only the repeated key under one table header is a parse error; the same key in \
             `[dev-dependencies]` and the next fence's own `[dependencies]` are both legal"
        );
        assert_eq!(
            checked, 5,
            "every declaration in every `toml` fence is counted, nested ones included, so the \
             guard's non-vacuity assertion cannot be satisfied by a single stray key"
        );
        assert!(
            readme_duplicate_toml_keys("```sh\n# not toml\nname = a\nname = b\n```\n").1 == 0,
            "a fence in another language declares nothing this guard reads"
        );
    }

    /// The body of `spec.md`'s `heading`, from the line after it to the next
    /// top-level `## ` heading.
    fn spec_section<'a>(spec: &'a str, heading: &str) -> &'a str {
        let body = spec
            .split_once(heading)
            .unwrap_or_else(|| panic!("spec.md must keep its `{heading}` heading"))
            .1;
        body.split_once("\n## ")
            .map_or(body, |(section, _)| section)
    }

    /// The first `- ` bullet of a `spec.md` section whose text contains
    /// `needle`, continuation lines joined onto their opening line.
    ///
    /// `spec.md` wraps its bullets across indented continuation lines, and a
    /// claim like "this configuration is compiled" can sit on any of them, so
    /// the whole bullet has to be searched rather than just its first line.
    /// Blank lines, `## ` headings, and the `---` between sections are prose
    /// rather than a bullet in progress, so leaving a bullet is explicit
    /// instead of an accident of the last-line-wins rule below.
    fn spec_bullet(section: &str, needle: &str) -> Option<String> {
        let mut bullets: Vec<String> = Vec::new();
        for line in section.lines() {
            if let Some(opening) = line.strip_prefix("- ") {
                bullets.push(String::from(opening.trim()));
                continue;
            }
            let continuation = line.trim();
            let is_prose = continuation.is_empty()
                || continuation.starts_with('#')
                || continuation == "---"
                || continuation.starts_with("--- ");
            if !is_prose {
                if let Some(bullet) = bullets.last_mut() {
                    bullet.push(' ');
                    bullet.push_str(continuation);
                }
            }
        }
        bullets.into_iter().find(|bullet| bullet.contains(needle))
    }

    /// The lines belonging to one `jobs:` entry of `ci.yml`, or `None` if no
    /// such job is declared.
    ///
    /// A workflow's job keys sit at exactly two spaces of indentation while
    /// every key inside a job is indented further, so the next two-space
    /// `key:` line ends the block. This is a line scan, not a YAML parse: the
    /// crate takes no dependency it does not already need, and the shapes read
    /// here (`name:`, `strategy:`, `continue-on-error:`, a flow-sequence
    /// `features: […]`) are stable across the workflow's edits.
    fn ci_job_block<'a>(workflow: &'a str, job: &str) -> Option<Vec<&'a str>> {
        let mut block: Vec<&str> = Vec::new();
        let mut inside = false;
        for line in workflow.lines() {
            let is_job_key =
                line.starts_with("  ") && !line.starts_with("   ") && line.trim().ends_with(':');
            if is_job_key {
                if inside {
                    break;
                }
                inside = line.trim() == format!("{job}:");
                continue;
            }
            if inside {
                block.push(line);
            }
        }
        inside.then_some(block)
    }

    /// The entries of a job block's flow-sequence `features:` matrix, e.g.
    /// `["--all-features", "--features actix"]`.
    fn ci_job_features(block: &[&str]) -> Vec<String> {
        block
            .iter()
            .filter_map(|line| line.trim().strip_prefix("features: ["))
            .flat_map(|list| list.trim_end_matches(']').split(','))
            .filter_map(|entry| entry.trim().strip_prefix('"'))
            .filter_map(|entry| entry.strip_suffix('"'))
            .map(String::from)
            .collect()
    }

    /// Whether a job block's failure fails the build, i.e. it does not carry
    /// `continue-on-error: true`.
    fn ci_job_is_blocking(block: &[&str]) -> bool {
        !block
            .iter()
            .any(|line| line.trim() == "continue-on-error: true")
    }

    /// `.github/workflows/ci.yml`, or `None` in a checkout that does not ship
    /// it.
    ///
    /// `.github` is in `Cargo.toml`'s `exclude`, so it is absent from the
    /// crates.io tarball and the guards below skip rather than fail — the same
    /// skip `fuzz_seed_bullets_and_corpus_agree` uses for `fuzz/`. They are
    /// repo-internal consistency checks, not part of the shipped crate's
    /// contract.
    fn ci_workflow() -> Option<String> {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml"),
        )
        .ok()
    }

    /// `spec.md` §6's clippy requirement must name every feature configuration
    /// CI actually compiles.
    ///
    /// The `clippy` job is a three-way feature matrix, not the single
    /// `--all-features` invocation §6 used to name, and the two extra entries
    /// are the whole point of it: `--features actix` and `--features tower`
    /// are configurations a downstream user reaches on their own, and each
    /// carried a warning `--all-features` structurally cannot see (issue #335).
    /// Nothing compiles §6 — it is prose in a file no tool reads — so the
    /// matrix grew there while the spec still described one configuration, and
    /// a reader taking §6 as the gate inventory had no home for the class of
    /// bug the matrix exists to catch. A new matrix entry must be recorded in
    /// §6 in the same change that adds it.
    #[test]
    fn spec_ci_clippy_bullet_names_every_compiled_configuration() {
        let Some(workflow) = ci_workflow() else {
            return;
        };
        let block = ci_job_block(&workflow, "clippy")
            .unwrap_or_else(|| panic!("ci.yml must still declare a `clippy` job"));

        let compiled = ci_job_features(&block);
        assert!(
            !compiled.is_empty(),
            "ci.yml's `clippy` job must still compile a flow-sequence `features:` matrix, or this \
             guard can no longer see which configurations it holds to `-D warnings`"
        );

        let spec = include_str!("../spec.md");
        let bullet = spec_bullet(spec_section(spec, "## 6. CI requirements"), "cargo clippy")
            .unwrap_or_else(|| panic!("spec.md §6 must keep a `cargo clippy` requirement"));
        for configuration in &compiled {
            assert!(
                bullet.contains(configuration.as_str()),
                "spec.md §6's clippy requirement does not name the `{configuration}` \
                 configuration that ci.yml's `clippy` job compiles — a lint gate that only ever \
                 compiles one feature set cannot see a warning unique to another (issue #335), so \
                 record every matrix entry in §6 in the same change that adds it"
            );
        }
    }

    /// `spec.md` §6 must not call a job advisory that CI runs as a gate.
    ///
    /// §6 described `cargo semver-checks` as informational on the reasoning
    /// that no baseline existed until the first release published — 0.1.0
    /// published 2026-09-08, and the job has blocked since issue #276, with
    /// `constructible_struct_adds_field` denied outright through
    /// `Cargo.toml`'s semver-checks lint config. That gap is how #274's
    /// deliberate `CustomScheme::timestamp_unit` source break merged with the
    /// job red: the spec that should have warned of the gate had kept calling
    /// it advisory. The check reads the workflow first and only then demands
    /// §6 agree, so the day someone deliberately relaxes the job this guard
    /// stops objecting rather than blocking the relaxation.
    #[test]
    fn spec_ci_semver_requirement_matches_how_the_job_runs() {
        let Some(workflow) = ci_workflow() else {
            return;
        };
        let block = ci_job_block(&workflow, "semver-checks")
            .unwrap_or_else(|| panic!("ci.yml must still declare a `semver-checks` job"));
        if !ci_job_is_blocking(&block) {
            // Deliberately advisory (or deliberately `continue-on-error`):
            // §6 may describe it either way, so there is nothing to check.
            return;
        }

        let spec = include_str!("../spec.md");
        let bullet = spec_bullet(
            spec_section(spec, "## 6. CI requirements"),
            "cargo semver-checks",
        )
        .unwrap_or_else(|| panic!("spec.md §6 must keep a `cargo semver-checks` requirement"));
        for claim in ["informational", "non-blocking", "does not block"] {
            assert!(
                !bullet.to_lowercase().contains(claim),
                "spec.md §6 calls `cargo semver-checks` {claim}, but ci.yml runs the job without \
                 `continue-on-error`, so it fails the build. A break that needs a version bump \
                 then lands as a red build the spec promised would not happen (#274), which is how \
                 the surprise has to be avoided"
            );
        }
    }

    /// The bullet reader has to find a claim that sits on a continuation line
    /// and stop at the end of its own bullet, or §6's wrapped prose would read
    /// as if the claim were never made.
    #[test]
    fn spec_bullets_are_read_across_their_continuation_lines() {
        let spec = "\
## 6. CI requirements

Prose before the list, which mentions `cargo clippy` only in passing.

- `cargo clippy --all-features --all-targets -- -D warnings` — a wrapped
  bullet whose second line names `--features tower` as a matrix entry.
- `cargo test --all-features` on stable, MSRV, and beta.

---

## 7. Open questions

- `cargo clippy` again, one section too far.
";
        let section = spec_section(spec, "## 6. CI requirements");

        let bullet = spec_bullet(section, "--features tower")
            .unwrap_or_else(|| panic!("a claim on a continuation line must be found"));
        assert!(
            bullet.starts_with("`cargo clippy"),
            "the claim must resolve to the bullet it belongs to, not to section prose"
        );
        assert!(
            !bullet.contains("stable, MSRV"),
            "the following bullet must not be joined onto the one that matched"
        );
        assert!(
            !section.contains("Open questions"),
            "the section must end at the next `## ` heading"
        );
        assert!(
            spec_bullet(section, "no claim like this exists").is_none(),
            "a section with no matching bullet reports none"
        );
    }

    /// The workflow reader has to see a job's own keys and stop at the next
    /// job, or the guards above compare §6 against the wrong job's lines.
    #[test]
    fn ci_job_blocks_are_read_from_their_own_job() {
        let workflow = "\
env:
  CARGO_TERM_COLOR: always
jobs:
  clippy:
    strategy:
      matrix:
        features: [\"--all-features\", \"--features actix\"]
    steps:
      - run: cargo clippy ${{ matrix.features }} --all-targets -- -D warnings
  constant-time:
    name: constant-time assertion (informational)
    continue-on-error: true
    steps:
      - run: cargo test --release --all-features
";

        let clippy = ci_job_block(workflow, "clippy")
            .unwrap_or_else(|| panic!("fixture must yield a `clippy` block"));
        assert_eq!(
            ci_job_features(&clippy),
            ["--all-features", "--features actix"],
            "the matrix must be read out of the `clippy` job, not the one that follows it"
        );
        assert!(
            ci_job_is_blocking(&clippy),
            "a job without `continue-on-error` fails the build"
        );

        let advisory = ci_job_block(workflow, "constant-time")
            .unwrap_or_else(|| panic!("fixture must yield a `constant-time` block"));
        assert!(
            !ci_job_is_blocking(&advisory),
            "`continue-on-error: true` must not be read out of a neighboring job"
        );
        assert!(
            ci_job_features(&advisory).is_empty(),
            "a job with no feature matrix yields no configurations, rather than the previous job's"
        );

        assert!(
            ci_job_block(workflow, "no-such-job").is_none(),
            "an absent job must be reported as absent, not as an empty block"
        );
    }
}
