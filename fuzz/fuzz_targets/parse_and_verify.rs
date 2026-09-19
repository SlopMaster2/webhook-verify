//! Shared fuzz target: feeds arbitrary bytes as headers + raw body into every
//! implemented provider's verification path, including the multi-secret
//! `verify_any` rotation path (`spec.md` §5.6).
//!
//! Correctness is covered by the per-provider vector tests; this target exists
//! purely to assert **no panic and no timeout** on adversarial input.
//!
//! # Seed corpus (`fuzz/corpus/parse_and_verify/`)
//!
//! The timed nightly run starts its exploration from the committed seeds, so
//! libFuzzer mutates known-good input *shapes* instead of rediscovering the
//! `Name: value` / blank-line / body layout from an empty input. Each seed is
//! a public test vector already committed in `src/providers/*` test modules or
//! this target's own constants, chosen so the parsed header/body reaches a
//! distinct provider path:
//!
//! - `github-valid-delivery` — GitHub's documented example (docs.github.com),
//!   parser-well-formed (`Name:value`, no space) so the `sha256=` prefix, hex
//!   decode, 32-byte gate, and constant-time HMAC comparison all run.
//! - `github-malformed-prefix` — the same vector in the `Name: value` spelling
//!   real HTTP uses; the leading space exercises the missing-`sha256=` prefix
//!   fail-closed branch for every exact-prefix provider (GitHub, Slack, Zoom).
//! - `bitbucket-hub-signature` — Bitbucket Cloud's documented worked example
//!   (support.atlassian.com), reaching the `X-Hub-Signature` `sha256=` prefix,
//!   hex decode, 32-byte gate, and constant-time HMAC comparison.
//! - `box-two-signature-delivery` — Box's two-signature delivery shape
//!   (`BOX-SIGNATURE-PRIMARY`/`BOX-SIGNATURE-SECONDARY` bare base64,
//!   `BOX-DELIVERY-TIMESTAMP` in the `-07:00`-offset RFC 3339 spelling, plus
//!   the optional `BOX-SIGNATURE-VERSION`/`BOX-SIGNATURE-ALGORITHM` metadata),
//!   reaching the RFC 3339 timestamp parse, both base64 decodes and 32-byte
//!   gates, the `{raw_body}{timestamp}` concatenation HMAC comparison, and
//!   the optional metadata validation.
//! - `intercom-hub-signature` — intercom's documented `X-Hub-Signature`
//!   construction (`sha1=` prefix, hex HMAC over the raw body), reaching the
//!   prefix, hex decode, 20-byte gate, and constant-time HMAC comparison.
//! - `meta-hub-signature-256` — the Meta vector (`sha256=` prefix, hex
//!   HMAC-SHA256 over the raw body, no timestamp), reaching the prefix, hex
//!   decode, 32-byte gate, and constant-time HMAC comparison.
//! - `slack-timestamped-delivery` — Slack's documented worked example
//!   (docs.slack.dev), reaching the `v0=` scheme, timestamp parse, and HMAC
//!   comparison over `v0:{ts}:{body}`.
//! - `stripe-comma-space-signature` — the combined `Stripe-Signature` header in
//!   the comma-space spelling real integrations emit, exercising key trim and
//!   the `t.{body}` signed-string construction.
//! - `discord-ed25519-shape` — Discord's two-header shape with a 128-hex-char
//!   signature, reaching Ed25519 signature decode and verification.
//! - `dropbox-hex-signature` — Dropbox's `X-Dropbox-Signature` bare-hex HMAC
//!   shape over the raw body, reaching hex decode, the 32-byte gate, and HMAC
//!   comparison (parser-well-formed, no space after the colon, matching the
//!   other bare-hex/bare-base64 HMAC seeds).
//! - `docusign-base64-signature` — DocuSign's `X-Docusign-Signature-1` bare
//!   base64 HMAC shape over the primary vector body (no prefix, no timestamp),
//!   reaching base64 decode, the 32-byte gate, and HMAC comparison.
//! - `paystack-hex-signature` — Paystack's `x-paystack-signature` bare-hex
//!   HMAC-SHA512 shape over the raw body (no prefix, no timestamp — the only
//!   built-in provider with a 64-byte digest), reaching hex decode, the 64-byte
//!   gate, and HMAC comparison.
//! - `razorpay-hex-signature` — Razorpay's `X-Razorpay-Signature` bare-hex HMAC
//!   shape over the raw body (no prefix, no timestamp), reaching hex decode,
//!   the 32-byte gate, and HMAC comparison.
//! - `sentry-hex-signature` — Sentry's `Sentry-Hook-Signature` bare-hex HMAC
//!   shape over the raw body (no prefix, no timestamp), reaching hex decode,
//!   the 32-byte gate, and HMAC comparison.
//! - `adyen-base64-signature` — Adyen's `HmacSignature` base64 HMAC shape over
//!   the official worked-example body (no prefix, no timestamp). The provider
//!   hex-decodes the Customer Area key, so the fixed seed secret (base64-shaped)
//!   reaches the `InvalidSecret` key-decode gate; the shaped attempt below pairs
//!   the same header shape with a hex key to reach base64 decode, the 32-byte
//!   gate, and HMAC comparison.
//! - `pagerduty-v1-signature` — the official `go-pagerduty` SDK test vector
//!   (`X-PagerDuty-Signature` with a `v1=` hex HMAC over the raw body, no
//!   timestamp), reaching the `v1=` prefix strip, comma-split rotation-list
//!   parsing, hex decode, the 32-byte gate, and HMAC comparison.
//! - `pusher-hex-signature` — Pusher's `X-Pusher-Signature` bare hex
//!   HMAC-SHA256 over the raw body (no prefix, no timestamp), reaching hex
//!   decode, the 32-byte gate, and HMAC comparison.
//! - `standard-webhooks-shape` — the official test-suite delivery (three
//!   `webhook-*` headers), reaching the `v1,<base64>` split, base64 decode,
//!   and multi-element comparison.
//! - `hubspot-v3-delivery` — HubSpot's V3 two-header shape (base64
//!   `X-HubSpot-Signature-V3` + millisecond `X-HubSpot-Request-Timestamp`),
//!   reaching base64 decode and the HMAC comparison over
//!   `{method}{uri}{body}{timestamp}`.
//! - `zoom-timestamped-delivery` — Zoom's documented `v0=` +
//!   `x-zm-request-timestamp` two-header shape, reaching timestamp parse and the
//!   `v0:{ts}:{body}` HMAC comparison.
//! - `twitch-eventsub-delivery` — Twitch EventSub's three-header
//!   `Twitch-Eventsub-Message-*` shape (opaque id, nanosecond RFC 3339
//!   timestamp, `sha256=` hex signature), reaching the RFC 3339 timestamp
//!   parse and the `{id}{ts}{body}` concatenation HMAC comparison.
//! - `paddle-ts-h1-signature` — Paddle's combined `ts=...;h1=...` header,
//!   exercising the `;`-splitting parser and the `{ts}:{raw_body}` signed
//!   string (Paddle's documented `hmac(secret, "{ts}:{body}")`, matching
//!   `src/providers/paddle.rs`).
//! - `cloudflare-time-sig1-delivery` — Cloudflare's combined `time=...,sig1=...`
//!   header, reaching the comma-split and HMAC comparison.
//! - `coinbase-t-v0-delivery` — Coinbase's combined `t=...,v0=...` header (the
//!   shape also carries optional `h=`/`v1=` fields), reaching timestamp and
//!   `v0` comparison parsing.
//! - `circleci-v1-signature` — CircleCI's `circleci-signature` header with a
//!   single `v1=<hex>` signature (the current, only documented version),
//!   reaching `v1` version-selection, hex decode, the 32-byte gate, and HMAC
//!   comparison over the raw body (no timestamp).
//! - `mux-t-v1-signature` — Mux's combined `t=...,v1=...` header with a
//!   `v1=` rotation list, reaching the comma-split, timestamp parse, hex
//!   decode, and multi-element HMAC comparison.
//! - `workos-t-v1-delivery` — WorkOS's combined `t=...,v1=...` header with an
//!   epoch-*millisecond* timestamp, reaching the comma-split, ms-timestamp
//!   parse, hex decode, and HMAC comparison.
//! - `notion-sha256-prefix-delivery` — Notion's official `sha256=` sample value,
//!   reaching prefix match, hex decode, and the 32-byte gate.
//! - `typeform-sha256-prefix-signature` — Typeform's documented `sha256=` +
//!   base64 header shape, reaching prefix match, base64 decode, and the 32-byte
//!   gate.
//! - `zendesk-timestamped-delivery` — Zendesk's two-header shape (bare base64
//!   signature + RFC 3339 `X-Zendesk-Webhook-Signature-Timestamp`), reaching
//!   the RFC 3339 timestamp parse and the `{timestamp}{body}` concatenation
//!   base64 HMAC comparison.
//! - `square-base64-signature` — Square's documented base64 HMAC-SHA256 signature
//!   over the signed message containing the `request_url`.
//! - `xero-base64-signature` — Xero's raw base64 HMAC-SHA256 signature (no
//!   prefix, no timestamp).
//! - `lemonsqueezy-hex-signature` — Lemon Squeezy's bare hex HMAC-SHA256
//!   signature (no prefix, no timestamp).
//! - `linear-hex-signature` — Linear's raw hex HMAC-SHA256 signature (no
//!   prefix, no timestamp).
//! - `launchdarkly-hex-signature` — LaunchDarkly's bare hex HMAC-SHA256
//!   signature (no prefix, no timestamp).
//! - `shopify-base64-signature` — Shopify's base64 HMAC-SHA256 signature (no
//!   prefix, no timestamp).
//! - `line-base64-signature` — LINE's official byte-exact example
//!   (`x-line-signature`, base64 HMAC-SHA256 over the confirmation webhook
//!   body, channel-secret key), reaching base64 decode, the 32-byte gate, and
//!   HMAC comparison on the lowercase header spelling the docs use.
//! - `woocommerce-base64-signature` — WooCommerce's `X-WC-Webhook-Signature`
//!   base64 HMAC-SHA256 signature over the raw body (no prefix, no timestamp),
//!   reaching base64 decode, the 32-byte gate, and HMAC comparison.
//! - `calendly-t-v1-signature` — Calendly's combined `t=...,v1=...`
//!   `Calendly-Webhook-Signature` header, reaching the comma-split, timestamp
//!   parse, hex decode, 32-byte gate, and HMAC comparison over `{t}.{body}`.
//! - `klaviyo-timestamp-delivery` — Klaviyo's two-header shape (bare hex
//!   `Klaviyo-Signature` + IMF-fixdate `Klaviyo-Timestamp`), reaching the
//!   RFC 1123 timestamp parse and the `{raw_body}{timestamp}` concatenation
//!   HMAC comparison.
//! - `twilio-base64-signature` — Twilio's documented example signature
//!   (`X-Twilio-Signature`, sha1 base64 over the request URL + sorted form
//!   fields), reaching base64 decode, the 20-byte gate, and the HMAC comparison
//!   constructed from the `twilio_options` below.
//! - `mandrill-base64-signature` — the Mailchimp Transactional webhook-URL-check
//!   scenario (`X-Mandrill-Signature`, sha1 base64 over the request URL +
//!   sorted form fields, the documented generic `test-webhook` key), reaching
//!   base64 decode, the 20-byte gate, and the HMAC comparison constructed from
//!   the `mandrill_options` below.
//! - `paypal-signature-delivery` — PayPal's published example delivery (the
//!   five `PayPal-*` headers, RFC 3339 transmission time, decimal CRC-32
//!   signed string, and the docs event body), reaching the RSA/X.509 and
//!   replay paths with caller-supplied `webhook_id`.
//! - `sendgrid-ecdsa-delivery` — SendGrid's official test vector (two-header
//!   shape, `{timestamp}{body}` message, P-256 key from the provider's own
//!   suite), reaching DER/SPKI parsing and ECDSA verification.
//! - `vercel-hex-signature` — Vercel's `x-vercel-signature` bare-hex
//!   HMAC-SHA1 shape over the raw body (no prefix, no timestamp — the only
//!   built-in bare-hex raw-body SHA-1 digest), reaching hex decode, the
//!   40-hex-char / 20-byte gate, and HMAC comparison.
//! - `x-twitter-sha256-prefix-signature` — X's documented
//!   `x-twitter-webhooks-signature` shape (`sha256=` prefixed base64
//!   HMAC-SHA256 over the raw body, no timestamp), reaching the prefix match,
//!   base64 decode, the 32-byte gate, and HMAC comparison.
//! - `header-garbage-without-body-separator` — an adversarial malformed input
//!   with no `\n\n` separator, anchoring the parser's fail-closed paths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use webhook_verify::{CustomScheme, Encoding, HashAlg, Provider, Secret, VerifyOptions};
// `VerifyingKeyMaterial` is used by both the `sendgrid` and `paypal` cfg
// blocks below. The crate re-exports it unconditionally, so gate the import
// on either feature — gating it on `sendgrid` alone made the `paypal`-only
// feature combination (which the `not(feature = "sendgrid")` fallback arms below
// exist to build) fail to compile with an unresolved import.
#[cfg(any(feature = "sendgrid", feature = "paypal"))]
use webhook_verify::VerifyingKeyMaterial;

/// Upper bound on parsed header lines so a pathological input cannot spin the
/// loop long enough to trip the fuzzer's timeout.
const MAX_HEADER_LINES: usize = 64;

/// Providers with an implementation in `src/providers/`. When a new provider
/// ships, add it here so its parsing path gets coverage too.
const IMPLEMENTED: &[Provider] = &[
    Provider::Stripe,
    Provider::GitHub,
    // Bitbucket is a single-header raw-body HMAC (`sha256=` prefixed hex, no
    // timestamp); arbitrary header bytes exercise its prefix-strip, hex-decode,
    // and 32-byte gate, and a well-formed-shaped attempt below reaches HMAC
    // comparison.
    Provider::Bitbucket,
    // Box needs four headers (two base64 signature values + RFC 3339 delivery
    // timestamp, with optional version/algorithm metadata) to reach its
    // signature path; a well-formed-shaped attempt below reaches its RFC 3339
    // timestamp parse, both base64 decodes, the `{body}{timestamp}`
    // concatenation HMAC comparison, and the optional metadata validation.
    Provider::Box,
    // Intercom is a single-header raw-body HMAC (`sha1=` prefixed hex, 20-byte
    // digest, no timestamp); arbitrary header bytes exercise its prefix-strip
    // and hex-decode paths, and a well-formed-shaped attempt below reaches its
    // 20-byte gate and HMAC comparison.
    Provider::Intercom,
    // Meta is a single-header raw-body HMAC (`sha256=` prefixed hex, 32-byte
    // digest, no timestamp); arbitrary header bytes exercise its prefix-strip
    // and hex-decode paths, and a well-formed-shaped attempt below reaches its
    // 32-byte gate and HMAC comparison.
    Provider::Meta,
    // HubSpot needs both a method and a URL in VerifyOptions to get past its
    // context check and into the signature path; arbitrary header bytes
    // exercise its header splitting and MissingContext fail-closed paths, and
    // a well-formed-shaped attempt below reaches base64 decode + HMAC paths.
    Provider::HubSpot,
    // Klaviyo needs two headers (bare-hex signature + IMF-fixdate timestamp)
    // to reach its signature path; a well-formed-shaped attempt below reaches
    // its timestamp parse, hex decode, and `{body}{timestamp}` HMAC
    // comparison.
    Provider::Klaviyo,
    // Shopify is a single-header raw-body HMAC (base64, no prefix); arbitrary
    // header bytes exercise its base64-decode and 32-byte gate, and a
    // well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Shopify,
    Provider::Slack,
    // Line is a single-header raw-body HMAC (base64, no prefix, no timestamp,
    // verbatim string key); arbitrary header bytes exercise its base64-decode
    // and 32-byte gate, and a well-formed-shaped attempt below reaches HMAC
    // comparison.
    Provider::Line,
    // Linear is a single-header raw-body HMAC (hex, no prefix); arbitrary
    // header bytes exercise its hex-decode and 32-byte gate, and a
    // well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Linear,
    // LaunchDarkly is a single-header raw-body HMAC (bare hex, no prefix, no
    // timestamp); arbitrary header bytes exercise its hex-decode and 32-byte
    // gate, and a well-formed-shaped attempt below reaches HMAC comparison.
    Provider::LaunchDarkly,
    // Dropbox is a single-header raw-body HMAC (hex, no prefix); arbitrary
    // header bytes exercise its hex-decode and 32-byte gate, and a
    // well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Dropbox,
    // DocuSign is a single-header raw-body HMAC (bare base64, no prefix, no
    // timestamp, verbatim string key); arbitrary header bytes exercise its
    // base64-decode and 32-byte gate, and a well-formed-shaped attempt below
    // reaches HMAC comparison.
    Provider::DocuSign,
    // Razorpay is a single-header raw-body HMAC (bare hex, no prefix, no
    // timestamp); arbitrary header bytes exercise its hex-decode and 32-byte
    // gate, and a well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Razorpay,
    // Paystack is a single-header raw-body HMAC (bare hex, no prefix, no
    // timestamp, but SHA-512 — the only built-in provider with a 64-byte
    // digest); arbitrary header bytes exercise its hex-decode and 64-byte
    // gate, and a well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Paystack,
    // Sentry is a single-header raw-body HMAC (bare hex, no prefix, no
    // timestamp); arbitrary header bytes exercise its hex-decode and 32-byte
    // gate, and a well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Sentry,
    // Adyen is a single-header raw-body HMAC (bare base64, no prefix, no
    // timestamp) whose key is a hex string hex-decoded to raw bytes; arbitrary
    // header bytes exercise its base64-decode and 32-byte gate, and a
    // well-formed-shaped attempt below (with a hex key) reaches HMAC
    // comparison. The fixed base64-shaped secret exercises the InvalidSecret
    // key-decode gate.
    Provider::Adyen,
    // LemonSqueezy is a single-header raw-body HMAC (bare hex, no prefix);
    // arbitrary header bytes exercise its hex-decode and 32-byte gate, and
    // a well-formed-shaped attempt below reaches HMAC comparison.
    Provider::LemonSqueezy,
    // Notion is a single-header raw-body HMAC (`sha256=` prefixed hex); the
    // loop below exercises its prefix-strip and hex-decode paths, and a
    // well-formed-shaped attempt below reaches its 32-byte gate and HMAC
    // comparison.
    Provider::Notion,
    // Cloudflare needs a combined `time=...,sig1=...` header to reach its
    // signature path; arbitrary bytes exercise the comma/key-value splitting
    // and empty-header rejection, and a well-formed-shaped attempt below
    // reaches its hex-decode/comparison paths too.
    Provider::Cloudflare,
    // CircleCi needs a combined `v1=<hex>[,v2=...]` header to reach its
    // signature path; arbitrary bytes exercise the comma/key=value splitting,
    // version-selection, and empty-header rejection, and a well-formed-shaped
    // attempt below reaches its hex-decode/comparison paths too.
    Provider::CircleCi,
    // Coinbase (CDP) needs a combined `t=...,v0=...` header to reach its
    // signature path; arbitrary bytes exercise the comma/key-value splitting
    // and empty-header rejection, and a well-formed-shaped attempt below
    // reaches its hex-decode/comparison paths too.
    Provider::Coinbase,
    // Mux needs a combined `t=...,v1=...` header to reach its signature path;
    // arbitrary bytes exercise the comma/key-value splitting and empty-header
    // rejection, and a well-formed-shaped attempt below reaches its
    // hex-decode/comparison (including the multi-`v1` rotation) paths too.
    Provider::Mux,
    // Xero is a single-header raw-body HMAC (base64, no prefix); arbitrary
    // header bytes exercise its base64-decode and 32-byte gate, and a
    // well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Xero,
    // Typeform is a single-header raw-body HMAC (`sha256=` prefixed base64);
    // the loop below exercises its prefix-strip and base64-decode paths, and a
    // well-formed-shaped attempt below reaches its 32-byte gate and HMAC
    // comparison.
    Provider::Typeform,
    // Square needs VerifyOptions::request_url to get past its context check
    // and into the signature path.
    Provider::Square,
    Provider::StandardWebhooks,
    // Discord's secret is a hex public key; the arbitrary-secret loop below
    // exercises its InvalidSecret decoding paths, and a dedicated valid-key
    // attempt below reaches its signature-decode/comparison paths too.
    Provider::Discord,
    // Twilio is exercised separately below: it needs form-param context to
    // reach its signature path, and ignores the raw body by design.
    Provider::Twilio,
    // Mandrill (Mailchimp Transactional) is exercised like Twilio: it needs
    // URL + form-param context to reach its signature path, and ignores the
    // raw body by design.
    Provider::Mandrill,
    // Zoom needs two headers (signature + timestamp) to reach its signature
    // path; timestamp-based replay is exercised via arbitrary body bytes.
    Provider::Zoom,
    // Twitch needs three headers (signature + RFC 3339 timestamp + message id)
    // to reach its signature path; a well-formed-shaped attempt below reaches
    // its timestamp parse and HMAC comparison.
    Provider::Twitch,
    // SendGrid needs `verifying_material` to get past its context check and
    // into the ECDSA/SPKI parsing path; it is additionally exercised with a
    // constant valid SPKI below.
    Provider::SendGrid,
    // Paddle: a `ts=...;h1=...` header that reaches the constant-time
    // comparison is built below; arbitrary bytes still exercise the
    // semicolon/key=value splitting, timestamp parsing, and hex-decode paths.
    Provider::Paddle,
    // PagerDuty is a single-header raw-body HMAC (`v1=` prefixed hex, no
    // timestamp); arbitrary header bytes exercise its prefix-strip and
    // hex-decode paths, and a well-formed-shaped attempt below reaches its
    // 32-byte gate and HMAC comparison.
    Provider::PagerDuty,
    // Pusher is a single-header raw-body HMAC (bare hex, no prefix, no
    // timestamp); arbitrary header bytes exercise its hex-decode and 32-byte
    // gate, and a well-formed-shaped attempt below reaches HMAC comparison.
    Provider::Pusher,
    // Zendesk needs two headers (bare-base64 signature + RFC 3339 timestamp) to
    // reach its signature path; a well-formed-shaped attempt below reaches its
    // timestamp parse, base64 decode, and `{timestamp}{body}` HMAC comparison.
    Provider::Zendesk,
    // WorkOS needs a combined `t=...,v1=...` header to reach its signature
    // path; arbitrary bytes exercise the comma/key-value splitting and
    // empty-header rejection, and a well-formed-shaped attempt below
    // reaches its hex-decode/comparison and ms→s replay paths too.
    Provider::WorkOS,
    // WooCommerce is a single-header raw-body HMAC (base64, no prefix, no
    // timestamp) with a verbatim string key; arbitrary header bytes exercise
    // its base64-decode and 32-byte gate, and a well-formed-shaped attempt
    // below reaches HMAC comparison.
    Provider::WooCommerce,
    // Calendly needs a combined `t=...,v1=...` header to reach its signature
    // path; arbitrary bytes exercise the comma/key-value splitting and
    // empty-header rejection, and a well-formed-shaped attempt below reaches
    // its hex-decode/comparison and replay paths too.
    Provider::Calendly,
    // Vercel is a single-header raw-body HMAC (bare hex, no prefix, no
    // timestamp, but SHA-1 — a 20-byte digest); arbitrary header bytes
    // exercise its hex-decode and 20-byte gate, and a well-formed-shaped
    // attempt below reaches HMAC comparison.
    Provider::Vercel,
    // X is a single-header raw-body HMAC (`sha256=` prefixed *base64*, no
    // timestamp); arbitrary header bytes exercise its prefix-strip and
    // base64-decode paths, and a well-formed-shaped attempt below reaches its
    // 32-byte gate and HMAC comparison.
    Provider::X,
];

/// A well-formed secret for each provider's scheme, so the fuzzer reaches the
/// signature-construction/comparison paths and not just early secret errors.
/// (Only Standard Webhooks parses its key format; the rest accept any string.)
///
/// Deliberately spelled *without* the `whsec_` prefix: the prefix is optional
/// per the Standard Webhooks spec (see `src/providers/standard_webhooks.rs`),
/// and the prefixed form's `whsec_<base64>` spelling matches GitHub's
/// Stripe-secret pattern and trips secret scanning (issue #13). Dropping the
/// prefix yields an identical decoded key.
const WELL_FORMED_SECRET: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

/// A valid Discord public key (hex-encoded Ed25519), so Discord's
/// *signature-decoding* path is exercised by the fuzzer too.
///
/// Discord's `Secret` must decode to a 32-byte hex key, which neither
/// [`WELL_FORMED_SECRET`] (base64-shaped) nor an arbitrary body-derived
/// string reliably satisfies — so without the dedicated attempt below,
/// `verify()` always fails Discord's key-format gate before parsing the
/// signature header and the base64/hex-decode paths stay uncovered (spec
/// §5.6). This is the verifying key for the same deterministic seed the
/// provider's own test vectors use (`src/providers/discord.rs` `VECTOR_SEED`).
const DISCORD_PUBLIC_KEY_HEX: &str =
    "b85b5508c0fc30a8d6702e2177ffe835ff3466b9a3abf9adb3dbf43b754ecdd8";

/// A well-formed hex secret for Adyen, whose Customer Area HMAC key is a hex
/// string hex-decoded to raw key bytes. [`WELL_FORMED_SECRET`] is base64-shaped
/// and therefore stops Adyen at its `InvalidSecret` key-decode gate before the
/// signature path; this value lets the shaped attempt below reach base64
/// decode, the 32-byte gate, and HMAC comparison. It is the key from Adyen's
/// own worked example (`src/providers/adyen.rs`).
const ADYEN_HEX_SECRET: &str = "79a3eaf309c43708726a8c284c0d72618696a12e840dfa1df3a158afa3b577da";

fn attempt(
    provider: Provider,
    headers: &dyn webhook_verify::HeaderMap,
    body: &[u8],
    secret: &str,
    options: &VerifyOptions,
) {
    let _ = webhook_verify::verify(
        provider,
        headers,
        body,
        &Secret::new(secret),
        options.clone(),
    );
}

/// [`webhook_verify::verify_any`] counterpart of [`attempt`]: drives the
/// cross-secret rotation path (`spec.md` §2.1) with a caller-supplied secret
/// slice, asserting only that it never panics or hangs on adversarial input.
fn attempt_any(
    provider: Provider,
    headers: &dyn webhook_verify::HeaderMap,
    body: &[u8],
    secrets: &[Secret],
    options: &VerifyOptions,
) {
    let _ = webhook_verify::verify_any(provider, headers, body, secrets, options.clone());
}

fuzz_target!(|data: &[u8]| {
    // Input layout: `Name: value` lines, then a blank line, then the body.
    // Everything malformed stays malformed on purpose — garbage header lines
    // are exactly the input class this target exists to exercise.
    let (header_bytes, body): (&[u8], &[u8]) = match data.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (&data[..pos], &data[pos + 2..]),
        None => (data, &[]),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_bytes.split(|&b| b == b'\n').take(MAX_HEADER_LINES) {
        let line = String::from_utf8_lossy(line);
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.to_string()));
        }
    }

    // URL-scoped schemes need request context to reach their signature path.
    let url_scoped_options =
        VerifyOptions::default().with_request_url("https://example.com/webhook");

    // HubSpot additionally signs the request method into its source string.
    let hubspot_options = VerifyOptions::default()
        .with_request_method("POST")
        .with_request_url("https://example.com/webhook");

    // Twilio additionally needs parsed form params; arbitrary field bytes
    // exercise its signed-string construction and base64 parsing paths.
    let twilio_options = VerifyOptions::default()
        .with_request_url("https://example.com/webhook")
        .with_form_params([
            ("CallSid", "CA1234567890ABCDE"),
            ("Digits", "1234"),
            ("From", "+14158675310"),
        ]);

    // Mandrill additionally needs parsed form params (like Twilio); arbitrary
    // field bytes exercise its signed-string construction and base64 parsing
    // paths. The form fields mirror its real request shape (`mandrill_events`
    // carries the batched JSON events).
    let mandrill_options = VerifyOptions::default()
        .with_request_url("https://example.com/webhook")
        .with_form_params([("mandrill_events", r#"[{"event":"open"}]"#)]);

    // Fail-closed dispatch for feature-gated providers must also never
    // panic. Square is exercised via IMPLEMENTED below, with and without
    // its required URL context.
    attempt(
        Provider::Square,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );
    attempt(
        Provider::Square,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &VerifyOptions::default(),
    );
    attempt(
        Provider::Twilio,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &twilio_options,
    );
    attempt(
        Provider::Twilio,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &VerifyOptions::default(),
    );
    attempt(
        Provider::Mandrill,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &mandrill_options,
    );
    attempt(
        Provider::Mandrill,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &VerifyOptions::default(),
    );
    // HubSpot: method-only and url-only options exercise the two MissingContext
    // fail-closed paths; the combined options reach the signature path below.
    attempt(
        Provider::HubSpot,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &VerifyOptions::default().with_request_method("POST"),
    );
    attempt(
        Provider::HubSpot,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );
    attempt(
        Provider::HubSpot,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &hubspot_options,
    );

    // Discord's secret must be a *valid hex public key* to get past the key
    // gate and reach its signature header parsing; neither WELL_FORMED_SECRET
    // nor the body-derived arbitrary secret is reliably hex, so the loop above
    // sticks at InvalidSecret. A constant valid key lets arbitrary header/body
    // bytes exercise the signature hex-decode, length-gate, and replay paths.
    attempt(
        Provider::Discord,
        &headers,
        body,
        DISCORD_PUBLIC_KEY_HEX,
        &url_scoped_options,
    );

    // PayPal requires `webhook_id` + an X.509 certificate (never fetched; the
    // caller supplies it). With a constant valid test certificate, arbitrary
    // header/body bytes exercise the RFC 3339 timestamp, base64, CRC-32, and
    // RSA/X.509 parsing paths; without the context, the MissingContext
    // fail-closed path is covered.
    #[cfg(feature = "paypal")]
    {
        const PAYPAL_CERT_PEM: &[u8] = include_bytes!("../../tests/data/paypal_test_cert.pem");
        let paypal_options = VerifyOptions::default()
            .with_webhook_id("0NH55953DH663215D")
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(
                PAYPAL_CERT_PEM.to_vec(),
            ));
        attempt(
            Provider::PayPal,
            &headers,
            body,
            WELL_FORMED_SECRET,
            &paypal_options,
        );
        attempt(
            Provider::PayPal,
            &headers,
            body,
            WELL_FORMED_SECRET,
            &VerifyOptions::default(),
        );
    }
    #[cfg(not(feature = "paypal"))]
    attempt(
        Provider::PayPal,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &VerifyOptions::default(),
    );

    // SendGrid reaches its ECDSA path only with caller-supplied key material;
    // a constant valid P-256 SPKI (the provider's own vector key) lets
    // arbitrary signature/timestamp/body bytes exercise DER/SPKI parsing, and
    // the options without material exercise the MissingContext fail-closed
    // path.
    #[cfg(feature = "sendgrid")]
    {
        const SENDGRID_SPKI_DER: [u8; 91] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf3,
            0x74, 0xf8, 0x3b, 0xf9, 0xfc, 0xe2, 0x2a, 0x2d, 0x22, 0xf2, 0x16, 0xe2, 0x67, 0x41,
            0x81, 0x0f, 0xfb, 0x74, 0x07, 0xd2, 0x9a, 0x9a, 0x88, 0x33, 0xc9, 0x05, 0xf6, 0x63,
            0x75, 0x7e, 0x5a, 0x55, 0x29, 0x2d, 0xc6, 0x46, 0xa7, 0xba, 0xda, 0x0c, 0x3e, 0xd9,
            0xf3, 0x4d, 0x45, 0xa2, 0x0d, 0x5e, 0xf5, 0x69, 0x8a, 0x09, 0x52, 0x23, 0xc7, 0x8d,
            0x11, 0xce, 0xb0, 0x10, 0x0d, 0xc5, 0xfa,
        ];
        let sendgrid_options = VerifyOptions::default().with_verifying_material(
            VerifyingKeyMaterial::EcdsaP256PublicKey(SENDGRID_SPKI_DER.to_vec()),
        );
        attempt(
            Provider::SendGrid,
            &headers,
            body,
            WELL_FORMED_SECRET,
            &sendgrid_options,
        );
        attempt(
            Provider::SendGrid,
            &headers,
            body,
            WELL_FORMED_SECRET,
            &VerifyOptions::default(),
        );
    }
    #[cfg(not(feature = "sendgrid"))]
    attempt(
        Provider::SendGrid,
        &headers,
        body,
        WELL_FORMED_SECRET,
        &VerifyOptions::default(),
    );

    // CustomScheme (spec §2.2): a Slack-shaped configuration exercises the
    // prefix-strip, hex-decode, timestamp-parse, and user signed-string
    // paths with arbitrary bytes; the raw-body/base64 variant covers the
    // remaining encoding/algorithm combinations.
    let slack_like = CustomScheme {
        hash: HashAlg::Sha256,
        signature_header: "X-Slack-Signature",
        timestamp_header: Some("X-Slack-Request-Timestamp"),
        encoding: Encoding::Hex,
        prefix: Some("v0="),
        signed_string: |headers, raw_body| {
            let ts = headers.get("X-Slack-Request-Timestamp").unwrap_or_default();
            let mut signed = Vec::with_capacity(3 + ts.len() + 1 + raw_body.len());
            signed.extend_from_slice(b"v0:");
            signed.extend_from_slice(ts.as_bytes());
            signed.push(b':');
            signed.extend_from_slice(raw_body);
            signed
        },
    };
    attempt(
        Provider::Custom(slack_like),
        &headers,
        body,
        "fuzz-signing-secret",
        &VerifyOptions::default(),
    );

    let raw_b64 = |hash| CustomScheme {
        hash,
        signature_header: "X-Raw-Sig",
        timestamp_header: None,
        encoding: Encoding::Base64,
        prefix: None,
        signed_string: |_headers, raw_body| raw_body.to_vec(),
    };
    for hash in [HashAlg::Sha256, HashAlg::Sha1, HashAlg::Sha512] {
        attempt(
            Provider::Custom(raw_b64(hash)),
            &headers,
            body,
            "fuzz-signing-secret",
            &url_scoped_options.clone(),
        );
    }

    // Cloudflare: a well-formed-shaped `Webhook-Signature` (valid hex sig1,
    // digit time) lets arbitrary body bytes reach the 32-byte length gate and
    // HMAC comparison; without it the loop above mostly fails earlier on
    // malformed/missing header fields.
    attempt(
        Provider::Cloudflare,
        &[(
            "Webhook-Signature".to_string(),
            "time=1700000000,sig1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e"
                .to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // CircleCi: a well-formed-shaped `circleci-signature` header (a single
    // valid-hex 64-char `v1=` signature, the current documented version) lets
    // arbitrary body bytes reach the `v1` version-selection, 32-byte length
    // gate, and HMAC comparison; the docs' `v2=`/`v3=` example elements
    // exercise the version-discard path in the arbitrary-bytes loop above.
    attempt(
        Provider::CircleCi,
        &[(
            "circleci-signature".to_string(),
            "v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Bitbucket: a well-formed-shaped `X-Hub-Signature` (valid `sha256=`
    // hex) lets arbitrary body bytes reach the 32-byte length gate and HMAC
    // comparison; without it the loop above mostly fails earlier on
    // malformed/missing prefix or hex.
    attempt(
        Provider::Bitbucket,
        &[(
            "X-Hub-Signature".to_string(),
            "sha256=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Box: a well-formed-shaped three-header delivery (base64 signature plus
    // RFC 3339 delivery timestamp on both signature headers) lets arbitrary
    // body bytes reach the RFC 3339 timestamp parse, both 32-byte length
    // gates, the `{body}{timestamp}` concatenation HMAC comparison, and the
    // optional version/algorithm metadata validation; without it the loop
    // above mostly fails earlier on malformed/missing header fields.
    attempt(
        Provider::Box,
        &[
            (
                "BOX-SIGNATURE-PRIMARY".to_string(),
                WELL_FORMED_SECRET.to_string(),
            ),
            (
                "BOX-SIGNATURE-SECONDARY".to_string(),
                WELL_FORMED_SECRET.to_string(),
            ),
            (
                "BOX-DELIVERY-TIMESTAMP".to_string(),
                "2020-01-01T00:00:00-07:00".to_string(),
            ),
            ("BOX-SIGNATURE-VERSION".to_string(), "1".to_string()),
            (
                "BOX-SIGNATURE-ALGORITHM".to_string(),
                "HmacSHA256".to_string(),
            ),
        ],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Intercom: a well-formed-shaped `X-Hub-Signature` (valid `sha1=` hex of
    // 20 bytes) lets arbitrary body bytes reach the 20-byte length gate and
    // HMAC comparison; without it the loop above mostly fails earlier on
    // malformed/missing prefix or hex.
    attempt(
        Provider::Intercom,
        &[(
            "X-Hub-Signature".to_string(),
            "sha1=cbf9bf16f89d9cf089ee3500c5ba94595b3aedcd".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Meta: a well-formed-shaped `X-Hub-Signature-256` (valid `sha256=` hex
    // sig) lets arbitrary body bytes reach the 32-byte length gate and HMAC
    // comparison; without it the loop above mostly fails earlier on
    // malformed/missing prefix or hex.
    attempt(
        Provider::Meta,
        &[(
            "X-Hub-Signature-256".to_string(),
            "sha256=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Notion: a well-formed-shaped `X-Notion-Signature` (valid `sha256=`
    // hex) lets arbitrary body bytes reach the 32-byte length gate and HMAC
    // comparison; without it the loop above mostly fails earlier on
    // malformed/missing prefix or hex.
    attempt(
        Provider::Notion,
        &[(
            "X-Notion-Signature".to_string(),
            "sha256=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Typeform: a well-formed-shaped `Typeform-Signature` (valid `sha256=`
    // base64 of 32 bytes) lets arbitrary body bytes reach the 32-byte length
    // gate and HMAC comparison; without it the loop above mostly fails earlier
    // on malformed/missing prefix or base64.
    attempt(
        Provider::Typeform,
        &[(
            "Typeform-Signature".to_string(),
            "sha256=hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Coinbase: a well-formed-shaped `X-Hook0-Signature` (valid hex v0,
    // digit t) lets arbitrary body bytes reach the 32-byte length gate and
    // HMAC comparison; without it the loop above mostly fails earlier on
    // malformed/missing header fields.
    attempt(
        Provider::Coinbase,
        &[(
            "X-Hook0-Signature".to_string(),
            "t=1700000000,v0=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e"
                .to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Mux: a well-formed-shaped `Mux-Signature` (digit t, valid-hex 32-byte
    // v1 entries, rotation list) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison; without it the loop above mostly fails
    // earlier on malformed/missing header fields.
    attempt(
        Provider::Mux,
        &[(
            "Mux-Signature".to_string(),
            "t=1700000000,v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e,v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Paddle: a well-formed-shaped `Paddle-Signature` (digit ts, valid-hex
    // 32-byte h1) lets arbitrary body bytes reach the 32-byte length gate and
    // HMAC comparison; without it the loop above mostly fails earlier on
    // malformed/missing header fields.
    attempt(
        Provider::Paddle,
        &[(
            "Paddle-Signature".to_string(),
            "ts=1700000000;h1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e"
                .to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Twitch: a well-formed-shaped three-header delivery (opaque message id,
    // valid RFC 3339 timestamp, `sha256=` hex sig) lets arbitrary body bytes
    // reach the RFC 3339 timestamp parse, the 32-byte length gate, and the
    // `{id}{ts}{body}` concatenation HMAC comparison; without it the loop
    // above mostly fails earlier on malformed/missing header fields.
    attempt(
        Provider::Twitch,
        &[
            (
                "Twitch-Eventsub-Message-Id".to_string(),
                "b2f45e9d-85a3-4b8c-91c1-7c03b6b6e4f2".to_string(),
            ),
            (
                "Twitch-Eventsub-Message-Timestamp".to_string(),
                "2026-01-01T00:00:00.000000000Z".to_string(),
            ),
            (
                "Twitch-Eventsub-Message-Signature".to_string(),
                "sha256=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e"
                    .to_string(),
            ),
        ],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Zendesk: a well-formed-shaped two-header delivery (bare base64 sig of
    // 32 bytes + valid RFC 3339 timestamp) lets arbitrary body bytes reach the
    // RFC 3339 timestamp parse, the 32-byte length gate, and the
    // `{timestamp}{body}` concatenation HMAC comparison; without it the loop
    // above mostly fails earlier on malformed/missing header fields.
    attempt(
        Provider::Zendesk,
        &[
            (
                "X-Zendesk-Webhook-Signature".to_string(),
                "hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
            ),
            (
                "X-Zendesk-Webhook-Signature-Timestamp".to_string(),
                "2021-03-25T05:09:27Z".to_string(),
            ),
        ],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // HubSpot: a well-formed-shaped `X-HubSpot-Signature-V3` (base64 32-byte,
    // per WELL_FORMED_SECRET) plus a digit millisecond timestamp lets
    // arbitrary body/method/URL bytes reach the 32-byte length gate and HMAC
    // comparison (via the constant-time path), and its ms→s replay handling;
    // without the context the loop above mostly fails earlier.
    attempt(
        Provider::HubSpot,
        &[
            (
                "X-HubSpot-Signature-V3".to_string(),
                WELL_FORMED_SECRET.to_string(),
            ),
            (
                "X-HubSpot-Request-Timestamp".to_string(),
                "1700000000000".to_string(),
            ),
        ],
        body,
        WELL_FORMED_SECRET,
        &hubspot_options,
    );

    // Dropbox: a well-formed-shaped `X-Dropbox-Signature` (valid hex sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::Dropbox,
        &[(
            "X-Dropbox-Signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Razorpay: a well-formed-shaped `X-Razorpay-Signature` (valid hex sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::Razorpay,
        &[(
            "X-Razorpay-Signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Sentry: a well-formed-shaped `Sentry-Hook-Signature` (valid hex sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::Sentry,
        &[(
            "Sentry-Hook-Signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Paystack: a well-formed-shaped `x-paystack-signature` (valid 128-char
    // hex sig, no prefix, no timestamp) lets arbitrary body bytes reach the
    // 64-byte length gate and HMAC comparison; without it the loop above
    // mostly fails earlier on malformed/missing header fields.
    attempt(
        Provider::Paystack,
        &[(
            "x-paystack-signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e\
             5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e"
                .to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Vercel: a well-formed-shaped `x-vercel-signature` (valid 40-char hex
    // sig, no prefix, no timestamp) lets arbitrary body bytes reach the
    // 20-byte length gate and HMAC comparison; without it the loop above
    // mostly fails earlier on malformed/missing header fields.
    attempt(
        Provider::Vercel,
        &[(
            "x-vercel-signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c4".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Adyen: a well-formed-shaped `HmacSignature` (valid base64 sig, no prefix,
    // no timestamp) paired with a hex Customer Area key lets arbitrary body
    // bytes reach the 32-byte length gate and HMAC comparison. The key *must*
    // be hex (Adyen's key is hex-decoded), so this attempt uses a hex secret
    // rather than the base64-shaped `WELL_FORMED_SECRET`.
    attempt(
        Provider::Adyen,
        &[(
            "HmacSignature".to_string(),
            "hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
        )],
        body,
        ADYEN_HEX_SECRET,
        &url_scoped_options,
    );

    // DocuSign: a well-formed-shaped `X-Docusign-Signature-1` (valid base64
    // sig, no prefix, no timestamp) lets arbitrary body bytes reach the
    // 32-byte length gate and HMAC comparison. The key model is verbatim, so
    // the base64-shaped `WELL_FORMED_SECRET` works directly as the HMAC key.
    attempt(
        Provider::DocuSign,
        &[(
            "X-Docusign-Signature-1".to_string(),
            "hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // PagerDuty: a well-formed-shaped `X-PagerDuty-Signature` (`v1=` prefix,
    // valid hex sig, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison, including the comma-split rotation-list
    // parsing path when a second `v1=` element is appended.
    attempt(
        Provider::PagerDuty,
        &[(
            "X-PagerDuty-Signature".to_string(),
            "v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e,v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Pusher: a well-formed-shaped `X-Pusher-Signature` (valid hex sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::Pusher,
        &[(
            "X-Pusher-Signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Shopify: a well-formed-shaped `X-Shopify-Hmac-Sha256` (valid base64 sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::Shopify,
        &[(
            "X-Shopify-Hmac-Sha256".to_string(),
            "hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Line: a well-formed-shaped `x-line-signature` (valid base64 sig, no
    // prefix, no timestamp, verbatim string key) lets arbitrary body bytes
    // reach the 32-byte length gate and HMAC comparison.
    attempt(
        Provider::Line,
        &[(
            "x-line-signature".to_string(),
            "hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // WooCommerce: a well-formed-shaped `X-WC-Webhook-Signature` (valid base64
    // sig, no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::WooCommerce,
        &[(
            "X-WC-Webhook-Signature".to_string(),
            "hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Calendly: a well-formed-shaped `Calendly-Webhook-Signature` (digit t,
    // valid-hex 32-byte v1) lets arbitrary body bytes reach the 32-byte length
    // gate and HMAC comparison; without it the loop above mostly fails earlier
    // on malformed/missing header fields.
    attempt(
        Provider::Calendly,
        &[(
            "Calendly-Webhook-Signature".to_string(),
            "t=1700000000,v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e"
                .to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Klaviyo: a well-formed-shaped two-header delivery (valid-hex 32-byte
    // `Klaviyo-Signature` + valid IMF-fixdate `Klaviyo-Timestamp`) lets
    // arbitrary body bytes reach the RFC 1123 timestamp parse, the 32-byte
    // length gate, and the `{raw_body}{timestamp}` concatenation HMAC
    // comparison; without it the loop above mostly fails earlier on
    // malformed/missing header fields.
    attempt(
        Provider::Klaviyo,
        &[
            (
                "Klaviyo-Signature".to_string(),
                "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
            ),
            (
                "Klaviyo-Timestamp".to_string(),
                "Thu, 04 Jan 2024 18:05:25 GMT".to_string(),
            ),
        ],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Linear: a well-formed-shaped `linear-signature` (valid hex sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::Linear,
        &[(
            "linear-signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // LaunchDarkly: a well-formed-shaped `X-LD-Signature` (valid hex sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::LaunchDarkly,
        &[(
            "X-LD-Signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // LemonSqueezy: a well-formed-shaped `X-Signature` (valid hex sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::LemonSqueezy,
        &[(
            "X-Signature".to_string(),
            "5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // Xero: a well-formed-shaped `x-xero-signature` (valid base64 sig,
    // no prefix, no timestamp) lets arbitrary body bytes reach the 32-byte
    // length gate and HMAC comparison.
    attempt(
        Provider::Xero,
        &[(
            "x-xero-signature".to_string(),
            "hnekiT0GuNX9rRmSlg0oxCxyBHwzBcb0J24w8gQbXo0=".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // X: a well-formed-shaped `x-twitter-webhooks-signature` (valid base64
    // sig behind the `sha256=` prefix, no timestamp) lets arbitrary body
    // bytes reach the prefix-match, 32-byte length gate, and HMAC
    // comparison.
    attempt(
        Provider::X,
        &[(
            "x-twitter-webhooks-signature".to_string(),
            "sha256=wKAeP9GiJsaFuQJdxOljWIpG7W4b0IJshW59aJtfNZ0=".to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    // WorkOS: a well-formed-shaped `WorkOS-Signature` (digit epoch-ms t,
    // valid-hex 32-byte v1) lets arbitrary body bytes reach the 32-byte length
    // gate and HMAC comparison, and the `t` digits reach the ms→s replay
    // handling; without it the loop above mostly fails earlier on
    // malformed/missing header fields.
    attempt(
        Provider::WorkOS,
        &[(
            "WorkOS-Signature".to_string(),
            "t=1720000000554,v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e"
                .to_string(),
        )],
        body,
        WELL_FORMED_SECRET,
        &url_scoped_options,
    );

    for &provider in IMPLEMENTED {
        attempt(
            provider,
            &headers,
            body,
            WELL_FORMED_SECRET,
            &url_scoped_options,
        );
        // Arbitrary secret bytes exercise the key-decoding failure paths
        // (e.g. Standard Webhooks' lenient base64) without panicking.
        let arbitrary_secret = String::from_utf8_lossy(body);
        attempt(
            provider,
            &headers,
            body,
            &arbitrary_secret,
            &url_scoped_options,
        );
    }

    // `verify_any` (cross-secret rotation) is public API wrapping the same
    // `verify()` calls fuzzed above, with error-aggregation logic of its own:
    // per-secret `InvalidSecret` tracking, `SignatureMismatch` aggregation,
    // structural-error short-circuit, and empty-slice handling. Fuzz the
    // slice-shape variations so that loop gets the same "no panic, no hang"
    // guarantee as the single-secret path: an empty slice (immediate
    // `SignatureMismatch`), a garbage-then-well-formed slice (aggregation must
    // keep trying past the `InvalidSecret` and reach the well-formed key), and
    // an all-garbage slice (aggregation across every unusable key).
    let arbitrary_secret = String::from_utf8_lossy(body);
    let mixed_secrets = [
        Secret::new(arbitrary_secret.as_ref()),
        Secret::new(WELL_FORMED_SECRET),
    ];
    let all_garbage_secrets = [
        Secret::new("not-hex-!"),
        Secret::new("deadbeef"),
        Secret::new(arbitrary_secret.as_ref()),
    ];

    for &provider in IMPLEMENTED {
        attempt_any(provider, &headers, body, &[], &url_scoped_options);
        attempt_any(
            provider,
            &headers,
            body,
            &mixed_secrets,
            &url_scoped_options,
        );
        attempt_any(
            provider,
            &headers,
            body,
            &all_garbage_secrets,
            &url_scoped_options,
        );
    }
});
