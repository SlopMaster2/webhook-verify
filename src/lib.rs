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
//! use webhook_verify::{verify, HeaderMap, Provider, Secret, VerifyError};
//!
//! let headers: Vec<(String, String)> = vec![(
//!     "X-Hub-Signature-256".to_string(),
//!     "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_string(),
//! )];
//! let raw_body = b"Hello, World!";
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
//!
//! ## Supported providers
//!
//! A single [`Provider`] enum drives signature verification for:
//!
//! | Provider | Scheme |
//! |---|---|
//! | Stripe | HMAC-SHA256 over `timestamp.body`, tolerance window |
//! | GitHub | HMAC-SHA256, `X-Hub-Signature-256` |
//! | Bitbucket | HMAC-SHA256, `sha256=` prefix, `X-Hub-Signature` |
//! | Box | HMAC-SHA256 over `{raw_body}{delivery_timestamp}`, base64, `BOX-SIGNATURE-PRIMARY`/`BOX-SIGNATURE-SECONDARY` (rotation-safe) + RFC 3339 timestamp tolerance window |
//! | Intercom | HMAC-SHA1, `sha1=` prefix, `X-Hub-Signature` |
//! | Meta (Graph API, Messenger, Instagram, WhatsApp Cloud API) | HMAC-SHA256 over raw body, hex, `sha256=` prefix, `X-Hub-Signature-256` (App Secret key, no timestamp) |
//! | HubSpot | HMAC-SHA256 over `{method}{uri}{body}{timestamp}` (epoch ms), base64, `X-HubSpot-Signature-V3` + tolerance window |
//! | Klaviyo | HMAC-SHA256 over `{raw_body}{timestamp}`, hex, `Klaviyo-Signature` + `Klaviyo-Timestamp` (IMF-fixdate) replay window |
//! | Shopify | HMAC-SHA256, base64, `X-Shopify-Hmac-Sha256` |
//! | Slack | HMAC-SHA256 `v0=` scheme + timestamp |
//! | Square | HMAC-SHA256 over notification URL + body, base64 |
//! | Twilio | HMAC-SHA1 (base64) over URL + sorted form params, `X-Twilio-Signature` |
//! | Mandrill (Mailchimp Transactional) | HMAC-SHA1 (base64) over URL + sorted form params, `X-Mandrill-Signature` |
//! | LINE (Messaging API) | HMAC-SHA256 over raw body, base64, `x-line-signature` (channel-secret key, no timestamp) |
//! | Twitch | HMAC-SHA256 over `{message_id}{message_timestamp}{raw_body}`, hex, `sha256=` prefix, `Twitch-Eventsub-Message-Signature` + RFC 3339 timestamp tolerance window |
//! | Typeform | HMAC-SHA256, base64, `sha256=` prefix, `Typeform-Signature` |
//! | Discord | Ed25519 public-key signatures (no shared secret) |
//! | PayPal | RSASSA-PKCS1-v1_5 SHA-256, X.509 cert + webhook ID |
//! | SendGrid | ECDSA P-256 over `{timestamp}{raw_body}` (no separator) |
//! | Paystack | HMAC-SHA512 over raw body, hex, `x-paystack-signature` (no timestamp) |
//! | Paddle | HMAC-SHA256 over `{ts}:{raw_body}`, hex, `Paddle-Signature` + tolerance window |
//! | PagerDuty | HMAC-SHA256 over raw body, hex, `v1=` prefix, `X-PagerDuty-Signature` (`v1=` rotation list) |
//! | Pusher | HMAC-SHA256 over raw POST body, hex, `X-Pusher-Signature` (keyed by the app token's secret, no timestamp) |
//! | Linear | HMAC-SHA256, `linear-signature` |
//! | LaunchDarkly | HMAC-SHA256 over raw body, hex, `X-LD-Signature` (no timestamp) |
//! | Notion | HMAC-SHA256 over raw body, hex, `sha256=` prefix, `X-Notion-Signature` |
//! | Zoom | HMAC-SHA256 `v0=` scheme + timestamp |
//! | Cloudflare (Stream) | HMAC-SHA256 over `time.body`, hex, `Webhook-Signature` |
//! | CircleCI (outbound webhooks) | HMAC-SHA256 over raw body, hex, `v1=` prefix, `circleci-signature` (versioned signature list, no timestamp) |
//! | Coinbase (CDP) | HMAC-SHA256 over `t.body`, hex, `X-Hook0-Signature` + tolerance window |
//! | Dropbox | HMAC-SHA256, `X-Dropbox-Signature` |
//! | DocuSign (Connect) | HMAC-SHA256 over raw body, base64, `X-Docusign-Signature-1` (first configured key, no timestamp) |
//! | Razorpay | HMAC-SHA256 over raw body, hex, `X-Razorpay-Signature` (no timestamp) |
//! | Lemon Squeezy | HMAC-SHA256, `X-Signature` (bare hex, no timestamp) |
//! | Xero | HMAC-SHA256, base64, `x-xero-signature` |
//! | Sentry | HMAC-SHA256 over raw body, hex, `Sentry-Hook-Signature` (no timestamp) |
//! | Adyen | HMAC-SHA256 over raw body, base64, `HmacSignature` (hex key, no timestamp) |
//! | Mux | HMAC-SHA256 over `t.body`, hex, `Mux-Signature` + tolerance window |
//! | Zendesk | HMAC-SHA256 over `{timestamp}{raw_body}`, base64, `X-Zendesk-Webhook-Signature` + tolerance window |
//! | WorkOS | HMAC-SHA256 over `t.body`, hex, `WorkOS-Signature` (`t=,v1=` list, millis timestamp floored for the replay window) |
//! | WooCommerce | HMAC-SHA256 over raw body, base64, `X-WC-Webhook-Signature` (no timestamp) |
//! | Calendly | HMAC-SHA256 over `t.body`, hex, `Calendly-Webhook-Signature` (`t=,v1=` list) + tolerance window |
//! | Vercel | HMAC-SHA1 over raw body, hex, `x-vercel-signature` (no timestamp) |
//! | X (formerly Twitter) | HMAC-SHA256 over raw body, base64, `sha256=` prefix, `x-twitter-webhooks-signature` (no timestamp) |
//! | Standard Webhooks | HMAC-SHA256 with replay + rotation lists (Svix, Clerk, Resend, ...) |
//! | Custom | User-supplied HMAC scheme via [`Provider::Custom`] |
//!
//! PayPal and SendGrid ship behind crate features; calling [`verify()`] with
//! them while the feature is off fails closed with [`VerifyError::UnsupportedProvider`].
//!
//! ## Crate features
//!
//! - `std` *(default)* — provides the wall clock used for replay protection
//!   and the `std::error::Error` impl. Disable for `no_std + alloc` targets
//!   (validated against `wasm32-unknown-unknown`); supply your own [`Clock`]
//!   for timestamped providers.
//! - `sendgrid` — enables the SendGrid provider (ECDSA P-256).
//! - `paypal` — enables the PayPal provider (RSA, X.509, CRC-32).
//! - `http` — `HeaderMap` impl for `http::HeaderMap` (axum, tower, hyper).
//!   The impl's own code is `no_std`-clean and the full test suite runs with
//!   the crate's `std` feature off in this configuration (spec §6), catching a
//!   `std` leak in the impl. The feature is nonetheless **std-bounded in
//!   practice**: the `http` crate itself requires `std`, so a genuinely
//!   std-less build cannot include it (spec §6, §7).
//! - `tower` — generic `tower::Layer`/`Service` middleware (works with axum
//!   routers too; `http` is implied). The `no_std + alloc` guarantee covers
//!   the core verification path only, so `tower` also implies `std` — the
//!   adapters are async framework glue and cannot build without it.
//! - `actix` — actix-web 4 extractor + header bridge. Also implies `std`, for
//!   the same reason.
//!
//! See [`verify_any`] for cross-secret key rotation during a rotation window.
//!
//! ## Security properties
//!
//! - All signature comparisons are constant-time ([`subtle::ConstantTimeEq`]).
//! - Bodies are hashed exactly as received; never re-encoded.
//! - No secret material ever appears in errors, `Debug`, or `Display` output.
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
pub use crate::core::{Clock, HeaderMap, Secret, VerifyError, VerifyOptions, VerifyingKeyMaterial};
pub use crate::providers::{
    CustomScheme, Encoding, HashAlg, Provider, ProviderParseError, verify, verify_any,
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
