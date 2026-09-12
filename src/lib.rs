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
//! | HubSpot | HMAC-SHA256 over `{method}{uri}{body}{timestamp}` (epoch ms), base64, `X-HubSpot-Signature-V3` + tolerance window |
//! | Shopify | HMAC-SHA256, base64 |
//! | Slack | HMAC-SHA256 `v0=` scheme + timestamp |
//! | Square | HMAC-SHA256 over notification URL + body, base64 |
//! | Twilio | HMAC-SHA1 over URL + sorted form params |
//! | Discord | Ed25519 public-key signatures (no shared secret) |
//! | PayPal | RSASSA-PKCS1-v1_5 SHA-256, X.509 cert + webhook ID |
//! | SendGrid | ECDSA P-256 over `{timestamp}{raw_body}` (no separator) |
//! | Paddle | HMAC-SHA256 over `{ts}:{raw_body}`, hex, `Paddle-Signature` + tolerance window |
//! | Linear | HMAC-SHA256, `linear-signature` |
//! | Notion | HMAC-SHA256 over raw body, hex, `sha256=` prefix, `X-Notion-Signature` |
//! | Zoom | HMAC-SHA256 `v0=` scheme + timestamp |
//! | Cloudflare (Stream) | HMAC-SHA256 over `time.body`, hex, `Webhook-Signature` |
//! | Coinbase (CDP) | HMAC-SHA256 over `t.body`, hex, `X-Hook0-Signature` + tolerance window |
//! | Dropbox | HMAC-SHA256, `X-Dropbox-Signature` |
//! | Xero | HMAC-SHA256, base64, `x-xero-signature` |
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
#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

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
