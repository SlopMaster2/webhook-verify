//! Provider-specific signing schemes and the [`verify`] dispatch.
//!
//! Each provider lives in its own module implementing exactly the scheme
//! documented in `spec.md` §3, backed by that provider's official test
//! vectors. Feature-disabled providers fail closed with
//! [`VerifyError::UnsupportedProvider`].

#![deny(clippy::unwrap_used, clippy::expect_used)]

mod adyen;
mod airwallex;
mod bitbucket;
mod box_webhooks;
mod calendly;
mod circleci;
mod cloudflare;
mod coinbase;
mod contentful;
mod custom;
mod discord;
mod docusign;
mod dropbox;
mod expo;
mod fastspring;
mod fintoc;
/// `application/x-www-form-urlencoded` decoding, shared by the two schemes that
/// sign parsed form fields rather than the body bytes. Not a provider itself:
/// it has no `Provider` variant and no dispatch arm, only the two callers
/// below.
mod form;
mod github;
mod gocardless;
mod hubspot;
mod intercom;
/// Header-name constants re-exported publicly for Klaviyo's caller-side
/// webhook-id pair check ([`crate::klaviyo`]). `pub` so the crate root can
/// re-export them without traversing a private module path; the enclosing
/// `providers` module stays crate-private.
pub mod klaviyo;
mod launchdarkly;
mod lemonsqueezy;
mod line;
mod linear;
mod mandrill;
mod meta;
mod mollie;
mod mux;
mod notion;
mod nylas;
mod paddle;
mod pagerduty;
#[cfg(feature = "paypal")]
mod paypal;
mod paystack;
mod pusher;
mod razorpay;
mod recharge;
mod ripple;
#[cfg(feature = "sendgrid")]
mod sendgrid;
mod sentry;
mod shopify;
mod slack;
mod square;
mod standard_webhooks;
mod stripe;
mod tailscale;
mod tally;
mod twilio;
mod twitch;
mod typeform;
mod vercel;
mod webflow;
mod woocommerce;
mod workos;
mod x_twitter;
mod xero;
mod zendesk;
mod zoom;

pub use custom::{CustomScheme, Encoding, HashAlg, TimestampUnit};

use core::fmt;

// Needed by `signature_header_names`, which the `spec.md` §4.4 ambiguity check
// needs for every caller: under the `http` feature, under both adapters, and
// through the pair-table entry point, which is compiled unconditionally.
use alloc::vec;
use alloc::vec::Vec;

// Contentful's self-describing signed-header list: the header whose *value*
// names the other headers folded into the canonical string (`spec.md` §3,
// Contentful row). `core::adapter_utils`'s `spec.md` §4.4 dynamic ambiguity
// half has to read this exact header to enumerate those names, so it is
// re-exported here instead of being re-spelled as a second literal in
// `adapter_utils` — otherwise renaming `SIGNED_HEADERS_HEADER` would leave the
// ambiguity scan following a name no request carries any more, silently
// disabling Contentful's dynamic ambiguity protection with a green test suite.
//
// The *delimiter* is shared for the identical reason, and the two are
// re-exported together on purpose: a scan that reads the right header but
// splits its value on the wrong character enumerates names no request carries,
// so a separator change reaching only `contentful::verify` degrades the dynamic
// half to a silent no-op just as thoroughly as a header rename would.
pub(crate) use contentful::SIGNED_HEADERS_HEADER as CONTENTFUL_SIGNED_HEADERS_HEADER;
pub(crate) use contentful::SIGNED_HEADERS_SEPARATOR as CONTENTFUL_SIGNED_HEADERS_SEPARATOR;

use crate::core::VerifyOptions;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// A webhook provider whose signature scheme this crate knows how to verify.
///
/// All variants have an implementation. PayPal and SendGrid are feature-gated
/// (`paypal` / `sendgrid`); calling [`verify()`] with a feature-disabled
/// variant returns [`VerifyError::UnsupportedProvider`] (fail-closed).
///
/// Providers can also be selected by name for config-driven setups (e.g.
/// `"stripe".parse::<Provider>()`) — see the
/// [`core::str::FromStr`] implementation.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// Stripe (`Stripe-Signature`, HMAC-SHA256 over `t.body`).
    Stripe,
    /// GitHub (`X-Hub-Signature-256`, HMAC-SHA256 over the raw body).
    GitHub,
    /// Bitbucket Cloud (`X-Hub-Signature`, HMAC-SHA256 over the raw body,
    /// `sha256=` prefix; no timestamp).
    Bitbucket,
    /// Contentful (`x-contentful-signature`, hex HMAC-SHA256 of
    /// `[method, requestPath, signedHeaders, body].join('\n')`, where the
    /// signed headers are named by the self-describing
    /// `x-contentful-signed-headers` list; `x-contentful-timestamp` carries an
    /// epoch-**milliseconds** signing instant with a tolerance window).
    ///
    /// Callers pass the delivery's method and URL via
    /// [`VerifyOptions::request_method`] / [`VerifyOptions::request_url`] —
    /// without them verification fails closed with [`VerifyError::MissingContext`]
    /// (see the Contentful module docs).
    Contentful,
    /// Box (`BOX-SIGNATURE-PRIMARY` / `BOX-SIGNATURE-SECONDARY`,
    /// base64-encoded HMAC-SHA256 over `{raw_body}{BOX-DELIVERY-TIMESTAMP}`).
    ///
    /// Box sends **two** signatures on every delivery — one per configured
    /// key — so a delivery verifies when **either** header matches the caller's
    /// single [`Secret`]. Both headers are required (Box always sends both).
    /// The delivery timestamp is RFC 3339 (e.g. `-07:00` offsets) and is
    /// HMAC-covered, so the shared `max_age` replay window applies; Box's docs
    /// recommend a ten-minute window while the crate default is 300s.
    Box,
    /// Intercom (`X-Hub-Signature`, `sha1=`-prefixed hex HMAC-SHA1 over the
    /// raw body, keyed by the app's `client_secret`; no timestamp).
    ///
    /// Intercom is, like Twilio, a scheme that still legitimately mandates
    /// SHA-1: the HMAC is keyed with the shared secret, which is immune to
    /// SHA-1's collision attacks.
    Intercom,
    /// Expo EAS (`expo-signature`, `sha1=`-prefixed hex HMAC-SHA1 over the
    /// raw body, keyed by the webhook signing secret; no timestamp).
    ///
    /// Covers EAS Build and EAS Submit webhook deliveries: the header value is
    /// `sha1=` + lowercase hex of `HMAC-SHA1(secret, raw_body)` — the same
    /// shape as Intercom's `X-Hub-Signature`. Expo, like Twilio and Intercom,
    /// still legitimately mandates SHA-1: the HMAC is keyed with the shared
    /// secret, which is immune to SHA-1's collision attacks.
    Expo,
    /// Meta (`X-Hub-Signature-256`, HMAC-SHA256 over the raw body, `sha256=`
    /// prefix; no timestamp).
    ///
    /// Covers Meta Graph API webhooks (Facebook Pages, Messenger, Instagram),
    /// including WhatsApp Cloud API deliveries: the app's **App Secret** keys
    /// an HMAC-SHA256 over the raw payload, hex-encoded behind a `sha256=`
    /// prefix in the `X-Hub-Signature-256` header — the same construction as
    /// GitHub but with Meta's App Secret as the key. Meta signs the payload's
    /// escaped-unicode serialization, which for ASCII-only JSON is
    /// byte-identical to the raw body; callers must pass the untouched request
    /// bytes (`spec.md` §3). Meta signs no timestamp, so `max_age` has no
    /// effect for this provider.
    Meta,
    /// HubSpot (`X-HubSpot-Signature-V3`, HMAC-SHA256 over
    /// `{method}{uri}{raw_body}{timestamp}` with `X-HubSpot-Request-Timestamp`
    /// in epoch ms; needs `VerifyOptions::request_method` and
    /// `VerifyOptions::request_url`).
    HubSpot,
    /// Klaviyo (`Klaviyo-Signature`, HMAC-SHA256 over the raw body followed by
    /// the `Klaviyo-Timestamp` header value *exactly as sent* — no separator).
    ///
    /// `Klaviyo-Timestamp` is an IMF-fixdate / RFC 1123 value such as
    /// `Thu, 04 Jan 2024 18:05:25 GMT` and is HMAC-covered, so the shared
    /// `max_age` replay window applies. `Klaviyo-Webhook-Id` is not part of
    /// the HMAC; Klaviyo directs integrators to match it against the body's
    /// `meta.klaviyo_webhook_id` (a payload-parsing check this crate leaves to
    /// the caller).
    Klaviyo,
    /// Mailchimp Transactional (formerly Mandrill)
    /// (`X-Mandrill-Signature`, base64-encoded HMAC-SHA1 over the webhook URL
    /// followed by the sorted `name value` form fields, no delimiters).
    ///
    /// Needs `VerifyOptions::request_url` (the URL exactly as configured in
    /// Mailchimp Transactional, including any query string) and nothing else:
    /// the form fields it signs (`mandrill_events`, historically the only
    /// field) are decoded from `raw_body` when `VerifyOptions::form_params`
    /// is unset, which is the normal case and the only one that works through
    /// an adapter, because that option is the per-delivery form body —
    /// configuring it on a layer or a config pins every delivery to one
    /// delivery's field set and rejects the rest. Set it only to override the
    /// derivation, from a framework's own parser. The scheme signs no
    /// timestamp, so `max_age` has no effect. Same construction family as
    /// `Twilio`, with Mailchimp's generic `test-webhook` key used for
    /// webhook-URL-check POSTs.
    Mandrill,
    /// LINE (`x-line-signature`, base64-encoded HMAC-SHA256 over the raw
    /// body, keyed by the channel secret).
    ///
    /// LINE (Messaging API) signs the exact request-body string — any
    /// deserialization or formatting before verification breaks the digest —
    /// so the crate hashes `raw_body` verbatim. The scheme signs no timestamp,
    /// so `max_age` has no effect. The provider's official docs publish a
    /// byte-exact confirmation-webhook example, used here as the primary test
    /// vector.
    Line,
    /// Shopify (`X-Shopify-Hmac-Sha256`, base64-encoded HMAC-SHA256).
    Shopify,
    /// Slack (`X-Slack-Signature`, `v0=` scheme with timestamp).
    Slack,
    /// Square (`x-square-hmacsha256-signature`, HMAC-SHA256 over notification
    /// URL + body, base64; needs `VerifyOptions::request_url`).
    Square,
    /// Tally (`Tally-Signature`, base64-encoded HMAC-SHA256 over the raw
    /// body).
    ///
    /// Tally (form webhooks) signs the request body with the per-webhook
    /// signing secret — used verbatim as its UTF-8 bytes — behind a bare
    /// base64 digest, the same shape as Shopify, Xero, and WooCommerce. The
    /// signing secret is optional: when none is set, Tally sends unsigned
    /// requests (`spec.md` §3). Tally signs no timestamp, so `max_age` has no
    /// effect for this provider.
    Tally,
    /// FastSpring (`X-FS-Signature`, base64-encoded HMAC-SHA256 over the raw
    /// body).
    ///
    /// FastSpring (commerce subscription/webhook platform) signs the request
    /// body with the per-webhook "HMAC SHA256 Secret" — used verbatim as its
    /// UTF-8 bytes — behind a bare base64 digest, the same shape as Tally,
    /// Shopify, Xero, and WooCommerce. The signing secret is optional: when
    /// none is set, FastSpring sends unsigned requests (`spec.md` §3).
    /// FastSpring's docs note the header may arrive with varying case;
    /// lookup is case-insensitive. FastSpring signs no timestamp, so `max_age`
    /// has no effect for this provider.
    FastSpring,
    /// GoCardless (`Webhook-Signature`, bare lowercase hex HMAC-SHA256 over
    /// the raw body).
    ///
    /// GoCardless (direct debit) signs the raw request body with the webhook
    /// endpoint's secret — used verbatim as its UTF-8 bytes, never decoded —
    /// behind a bare lowercase hex digest, the same shape as Razorpay and
    /// Lemon Squeezy. GoCardless's docs are explicit that the raw, unparsed
    /// body must be hashed ("do not parse the JSON and re-serialise it, as
    /// this may change the byte sequence and break the digest"), so the crate
    /// hashes `raw_body` verbatim. GoCardless signs no timestamp, so `max_age`
    /// has no effect for this provider.
    GoCardless,
    /// Mollie next-gen webhooks (`X-Mollie-Signature`, HMAC-SHA256 over the
    /// raw body, hex, `sha256=` prefix).
    ///
    /// Mollie signs the webhook request body with the signing secret
    /// configured at webhook setup — used verbatim as its UTF-8 bytes — and
    /// ships the hex digest behind a `sha256=` prefix in the single
    /// `X-Mollie-Signature` header, the same shape as GitHub but keyed by the
    /// Mollie signing secret. The `sha256=` prefix is matched
    /// case-sensitively, exactly like GitHub. Mollie's *classic* payment
    /// webhooks (a bare `id=<resource_id>` form field, no signature header)
    /// are unsigned and are **not** covered by this variant. The scheme signs
    /// no timestamp, so `max_age` has no effect. During the documented 24h
    /// rotation window two signature headers ride along; this crate reads the
    /// first, so rotating callers keep the previous secret until the window
    /// closes and verify against each (`spec.md` §3).
    Mollie,
    /// Twilio (HMAC-SHA1 over full URL + sorted form params; the only option it
    /// requires is `VerifyOptions::request_url` — the form fields are
    /// decoded from `raw_body` unless `VerifyOptions::form_params`
    /// overrides that, and an adapter user should leave the option
    /// unset; see the `Provider::Mandrill` doc).
    Twilio,
    /// Twitch EventSub (`Twitch-Eventsub-Message-Signature`, HMAC-SHA256 over
    /// `{message_id}{message_timestamp}{raw_body}`, hex, `sha256=` prefix).
    ///
    /// Three headers participate (`Twitch-Eventsub-Message-Id`,
    /// `Twitch-Eventsub-Message-Timestamp` in RFC 3339, and the signature
    /// itself); the signed string concatenates the message id, the timestamp
    /// *exactly as sent*, and the raw body — no separators. The timestamp is
    /// HMAC-covered, so the shared `max_age` replay window applies.
    Twitch,
    /// Typeform (`Typeform-Signature`, HMAC-SHA256 over the raw body, base64,
    /// `sha256=` prefix).
    Typeform,
    /// Discord (Ed25519 public-key signatures; `Secret` holds a public key).
    ///
    /// Unlike the shared-secret schemes, verification here proves the payload
    /// was signed with the private key corresponding to the *public* key in
    /// [`crate::Secret`] — see the provider module's security-model notes.
    Discord,
    /// PayPal (certificate-based RSASSA-PKCS1-v1_5 SHA-256; webhook ID and
    /// certificate via `VerifyOptions::webhook_id` /
    /// `VerifyOptions::verifying_material`).
    ///
    /// Requires the `paypal` crate feature; without it this variant fails
    /// closed with [`VerifyError::UnsupportedProvider`].
    PayPal,
    /// SendGrid (ECDSA P-256; key via `VerifyOptions::verifying_material`).
    ///
    /// Requires the `sendgrid` crate feature; without it this variant fails
    /// closed with [`VerifyError::UnsupportedProvider`].
    SendGrid,
    /// Paystack (`x-paystack-signature`, HMAC-SHA512 over the raw body, bare
    /// hex — no prefix, no timestamp).
    ///
    /// The signing key is the Paystack secret key from the dashboard
    /// ("Settings → API Keys & Webhooks"). Paystack is the built-in providers'
    /// only HMAC-SHA512 scheme (`spec.md` §3); it reuses the same audited
    /// constant-time HMAC-SHA512 helper `CustomScheme` uses, so the
    /// security guarantees stay in one place.
    Paystack,
    /// Paddle (`Paddle-Signature`, HMAC-SHA256 over `{ts}:{raw_body}`, with
    /// timestamp replay protection; multiple `h1=` values accepted).
    ///
    /// Paddle signs a local timestamp into the header, so requests are
    /// rejected when the included timestamp differs from the verifying
    /// clock's "now" by more than [`VerifyOptions::max_age`] (default 300s).
    Paddle,
    /// PagerDuty v3 webhooks (`X-PagerDuty-Signature`, HMAC-SHA256 over the
    /// raw body, hex, `v1=` prefix; no timestamp).
    ///
    /// Multiple `v1=` values may be present, comma-separated, during secret
    /// rotation; a match on *any* is accepted (matching PagerDuty's official
    /// Go SDK). No timestamp rides in the header, so `max_age` has no effect
    /// for this provider.
    PagerDuty,
    /// Pusher Channels (`X-Pusher-Signature`, HMAC-SHA256 over the raw POST
    /// body, bare lowercase hex — no prefix, no timestamp).
    ///
    /// Keyed by the **secret** of the app token named in the `X-Pusher-Key`
    /// header; the key itself is not part of the signed content. Pusher signs
    /// no timestamp, so `max_age` has no effect for this provider.
    Pusher,
    /// Linear (`linear-signature`, HMAC-SHA256).
    Linear,
    /// LaunchDarkly (`X-LD-Signature`, HMAC-SHA256 over the raw body, bare
    /// hex — no `sha256=` prefix, no timestamp). The signing key is the
    /// webhook secret configured on the integration.
    LaunchDarkly,
    /// Notion (`X-Notion-Signature`, HMAC-SHA256 over the raw body, hex,
    /// `sha256=` prefix). The signing key is the subscription's
    /// `verification_token` from the one-time handshake.
    Notion,
    /// Nylas (`x-nylas-signature`, HMAC-SHA256 over the raw body, bare hex —
    /// no `sha256=` prefix, no timestamp). The signing key is the endpoint's
    /// `webhook_secret`, generated after the `challenge` handshake.
    Nylas,
    /// Zoom (`x-zm-signature`, HMAC-SHA256 with timestamp).
    Zoom,
    /// Cloudflare (`Webhook-Signature`, HMAC-SHA256 over `time.body`).
    ///
    /// Covers Cloudflare **Stream** webhook notifications specifically: the
    /// `time` and `sig1` fields ride inside the single `Webhook-Signature`
    /// header, signed-string is `{time}.{raw_body}`, hex-encoded. Cloudflare
    /// has other webhook schemes (e.g. the legacy Apps
    /// `X-Signature-HMAC-SHA256-HEX` raw-body scheme); those are not this
    /// variant — see the provider module for the exact scheme.
    Cloudflare,
    /// CircleCI (outbound webhooks; `circleci-signature`, HMAC-SHA256 over
    /// the raw body, `v1=` prefix, comma-separated versioned list).
    ///
    /// Covers CircleCI's outbound webhooks (pipeline, workflow, job, and
    /// project events; `app.circleci.com/webhooks`). The
    /// `circleci-signature` header is a comma-separated list of *versioned*
    /// signatures (`v1=<hex>[,v2=...]`); the docs define `v1` as the current
    /// scheme — HMAC-SHA256 of the raw request body keyed by the webhook's
    /// signing secret, hex-encoded — and direct integrators to check only the
    /// latest signature type to prevent downgrade attacks. Other versions are
    /// discarded for forward compatibility. CircleCI signs no timestamp, so
    /// `max_age` has no effect.
    CircleCi,
    /// Coinbase (`X-Hook0-Signature`, HMAC-SHA256 over `t.body`).
    ///
    /// Covers Coinbase CDP webhooks (wallets, transfers, onchain activity;
    /// `docs.cdp.coinbase.com/webhooks`). Verifies the `v0` path the docs
    /// recommend for most use cases: the `t` and `v0` fields ride inside the
    /// single `X-Hook0-Signature` header, the signed string is
    /// `{t}.{raw_body}`, hex-encoded, with timestamp replay protection. The
    /// `h`/`v1` fields (which bind additional HTTP headers into the
    /// signature) are tolerated but not interpreted, matching the docs'
    /// guidance to use `v0` unless header binding is needed.
    Coinbase,
    /// Dropbox (`X-Dropbox-Signature`, HMAC-SHA256 over the raw body).
    Dropbox,
    /// DocuSign Connect (`X-Docusign-Signature-1`, HMAC-SHA256 over the raw
    /// body, base64; no timestamp).
    ///
    /// Covers Connect's header-based HMAC for the *first* configured key
    /// (`-1`); accounts with several active keys send one numbered header per
    /// key and DocuSign accepts a match against any of them, but this crate's
    /// single-header model reads `-1` only (`spec.md` §3). DocuSign signs no
    /// timestamp, so `max_age` has no effect for this provider.
    DocuSign,
    /// Fintoc (`Fintoc-Signature`, HMAC-SHA256 over `{t}.{raw_body}`, hex,
    /// `t=...,v1=...`).
    ///
    /// Covers Fintoc account webhooks (links, subscriptions, moves): the `t`
    /// and `v1` fields ride inside the single `Fintoc-Signature` header, the
    /// signed string reuses the `t` value *exactly as sent*, a literal dot,
    /// then the raw body, hex-encoded. The timestamp is HMAC-covered, so the
    /// shared `max_age` replay window applies (Fintoc's docs recommend a
    /// five-minute tolerance, matching the crate default). The webhook
    /// endpoint secret keys the HMAC verbatim as UTF-8; Fintoc's docs define
    /// exactly one `v1` element and no rotation list.
    Fintoc,
    /// Razorpay (`X-Razorpay-Signature`, HMAC-SHA256 over the raw body, bare
    /// hex — no `sha256=` prefix, no timestamp).
    Razorpay,
    /// Recharge (`X-Recharge-Hmac-Sha256`, bare hex **plain SHA-256** over
    /// `{secret}{raw_body}` — secret first, no separator; no timestamp).
    ///
    /// Despite the `Hmac-Sha256` header name, the scheme is **not** an HMAC:
    /// Recharge's docs hash the client secret concatenated with the raw
    /// request body with a bare SHA-256 (their OpenSSL/Python/PHP/Ruby
    /// reference recipes agree), keyed by the per-token **API Client Secret**
    /// used verbatim as its UTF-8 bytes (never the API token). The secret must
    /// be prepended to the body — Recharge warns the reverse order
    /// deliberately fails. Recharge signs no timestamp, so `max_age` has no
    /// effect. This variant is this crate's only non-HMAC shared-secret
    /// scheme (`spec.md` §3).
    Recharge,
    /// Ripple (Collections) webhooks (`X-Webhook-Signature`, HMAC-SHA256 with
    /// timestamp replay protection).
    ///
    /// Ripple signals Collections webhook deliveries with two headers —
    /// `X-Webhook-Signature: t=<timestamp>,v1=<hex_hmac_sha256>` and
    /// `X-Webhook-Timestamp: <epoch_ms>` — and both must match verbatim. The
    /// signed string is a **double-hash**: `{timestamp}.{sha256_hex(raw_body)}`
    /// HMAC-SHA256 keyed by the base64-decoded `signature_verification_key`
    /// (`spec.md` §3). The timestamp is HMAC-covered, so the shared `max_age`
    /// replay window applies after the millisecond value is floored to whole
    /// seconds (as with WorkOS and HubSpot).
    Ripple,
    /// Lemon Squeezy (`X-Signature`, HMAC-SHA256 over the raw body, bare hex —
    /// no `sha256=` prefix, no timestamp).
    LemonSqueezy,
    /// Xero (`x-xero-signature`, base64-encoded HMAC-SHA256 over the raw body).
    Xero,
    /// Sentry (Integration Platform webhooks; `Sentry-Hook-Signature`,
    /// HMAC-SHA256 over the raw body, bare hex — no `sha256=` prefix, no
    /// timestamp). The signing key is the integration's Client Secret.
    Sentry,
    /// Adyen (`HmacSignature`, HMAC-SHA256 over the raw body, base64; no
    /// timestamp).
    ///
    /// Covers Adyen's **header-based** HMAC scheme (Adyen for Platforms /
    /// Banking, Management API, Recurring token lifecycle, classic-platform
    /// notifications). The Customer Area HMAC key is a hex string and is
    /// hex-decoded to raw key bytes, matching Adyen's official libraries; a
    /// non-hex key fails closed with [`VerifyError::InvalidSecret`]. Adyen's
    /// Standard payments webhooks carry the signature *inside* the JSON body
    /// (`additionalData.hmacSignature`) and sign a colon-joined field subset
    /// rather than the raw body, so they are not covered by this variant —
    /// see the provider module for the exact scheme.
    Adyen,
    /// Airwallex (`x-signature`, HMAC-SHA256 over `{timestamp}{raw_body}`, hex,
    /// with `x-timestamp` in epoch milliseconds).
    ///
    /// The signed string is the `x-timestamp` value exactly as sent, directly
    /// concatenated with the raw body (no separators), hex-HMAC-SHA256 keyed by
    /// the notification URL's secret used verbatim. The timestamp is
    /// HMAC-covered, so the shared `max_age` replay window applies after the
    /// millisecond value is floored to whole seconds (as with WorkOS and
    /// HubSpot).
    Airwallex,
    /// Mux (`Mux-Signature`, HMAC-SHA256 over `t.body`).
    ///
    /// Covers Mux webhook notifications (video assets, live streams, uploads,
    /// ...): the `t` and `v1` fields ride inside the single `Mux-Signature`
    /// header, the signed string is `{t}.{raw_body}`, hex-encoded, with
    /// timestamp replay protection. Multiple `v1=` values are accepted during
    /// signing-secret rotation (a match on any is accepted). The signing
    /// secret is the per-webhook `signing_secret` from the Mux Webhooks API.
    Mux,
    /// Zendesk (`X-Zendesk-Webhook-Signature`, HMAC-SHA256 over
    /// `{timestamp}{raw_body}`, base64, `X-Zendesk-Webhook-Signature-Timestamp`
    /// in RFC 3339).
    ///
    /// The signed string concatenates the timestamp *exactly as sent* with the
    /// raw body — no separators (`base64(HMACSHA256(TIMESTAMP + BODY))`). The
    /// timestamp is HMAC-covered, so the shared `max_age` replay window
    /// applies. The signing secret is used verbatim as the HMAC key (the docs'
    /// reference code never base64-decodes it).
    Zendesk,
    /// WorkOS (`WorkOS-Signature`, HMAC-SHA256 over `{t}.{raw_body}`, hex,
    /// `t=...,v1=...` list with the timestamp in epoch milliseconds).
    ///
    /// The signed string reuses the `t` value *exactly as sent* (milliseconds
    /// included), a literal dot, then the raw body. The timestamp is
    /// HMAC-covered, so the shared `max_age` replay window applies after the
    /// millisecond value is floored to whole seconds (as with HubSpot).
    WorkOS,
    /// WooCommerce (`X-WC-Webhook-Signature`, base64-encoded HMAC-SHA256 over
    /// the raw body).
    ///
    /// The signing key is the webhook's configured `secret`, used verbatim as
    /// its UTF-8 bytes. No timestamp rides in the header, so `max_age` has no
    /// effect for this provider.
    WooCommerce,
    /// Calendly (`Calendly-Webhook-Signature`, HMAC-SHA256 over `t.body`, hex,
    /// `t=...,v1=...` list).
    ///
    /// The signed string reuses the `t` value *exactly as sent*, a literal
    /// dot, then the raw body. The timestamp is HMAC-covered, so the shared
    /// `max_age` replay window applies. Calendly's docs use a 180-second
    /// tolerance; callers can match it with
    /// `VerifyOptions::with_max_age(Duration::from_secs(180))` (the crate
    /// default is 300s). Only a single `v1` signature is accepted — Calendly's
    /// docs define no rotation list.
    Calendly,
    /// Vercel (`x-vercel-signature`, HMAC-SHA1 over the raw body, bare hex —
    /// no `sha1=` prefix, no timestamp).
    ///
    /// Covers webhook deliveries from Webhooks, Log Drains, and integration
    /// webhooks alike: the header holds a bare lowercase hex HMAC-SHA1 of the
    /// raw request body keyed by the webhook secret (account webhooks) or the
    /// Integration Secret (integration webhooks), both used verbatim as UTF-8
    /// bytes. Vercel signs no timestamp, so `max_age` has no effect. This is
    /// the built-in providers' only bare-hex raw-body SHA-1 scheme — the
    /// crate's other built-in SHA-1 schemes are Twilio and Mailchimp
    /// Transactional (URL + form params, base64), Intercom (raw body behind
    /// a `sha1=` prefix), and Expo EAS (raw body behind a `sha1=` prefix). A
    /// `CustomScheme`
    /// configured with [`HashAlg::Sha1`], [`Encoding::Hex`], no prefix, and
    /// the identity signed-string can reproduce the same bare-hex shape
    /// (`spec.md` §3, §2.2).
    Vercel,
    /// Webflow site webhooks (`x-webflow-signature`, HMAC-SHA256 over
    /// `{timestamp}:{raw_body}`, hex, with `x-webflow-timestamp` in epoch
    /// milliseconds).
    ///
    /// The signed string is the timestamp parsed to an integer, canonical
    /// decimal form (matching the docs' `parseInt`/`int` reference verifiers),
    /// a literal colon, then the raw body — hex-HMAC-SHA256 keyed by the
    /// webhook's signing key (a site token secret or the OAuth app's client
    /// secret) used verbatim. The timestamp is HMAC-covered, so the shared
    /// `max_age` replay window applies after the millisecond value is floored
    /// to whole seconds (as with WorkOS and Airwallex). Webflow recommends a
    /// 5-minute window, matching the crate's default `max_age`.
    Webflow,
    /// X (formerly Twitter) webhook signatures
    /// (`x-twitter-webhooks-signature`, HMAC-SHA256 over the raw body, base64,
    /// `sha256=` prefix; no timestamp).
    ///
    /// Covers delivery POSTs from X's webhook APIs, which register and
    /// secure the endpoint through the Challenge-Response Check (CRC) and
    /// then sign every delivery with HMAC-SHA256 keyed by the app's
    /// **consumer secret** (the API secret key, never the bearer or access
    /// token). The header value is `sha256=` + a base64 encoding of the
    /// digest over the exact raw body. The scheme signs no timestamp, so
    /// `max_age` has no effect. The CRC `response_token` uses the same
    /// primitive over the `crc_token` but is a response the caller computes
    /// (out of scope: this crate verifies inbound deliveries only).
    X,
    /// Tailscale webhook events (`Tailscale-Webhook-Signature`, HMAC-SHA256
    /// over `t.body`, hex, `t=,v1=` list; rotation-safe on multiple `v1=`).
    ///
    /// Covers the HTTPS POSTs Tailscale sends to a configured webhook endpoint
    /// (network events like `nodeCreated`, `policyUpdate`, `userRoleUpdated`,
    /// and the `test` probe). The header is a comma-separated `key=value` list
    /// carrying the event's unix-seconds epoch instant as `t` and the
    /// HMAC-SHA256 over `{t}.{raw_body}` as `v1` (hex, the only defined
    /// scheme). The docs recommend treating any event older than five minutes
    /// as a replay attack, so the shared `max_age` window applies.
    Tailscale,
    /// Standard Webhooks spec (`webhook-*` headers; Svix, Clerk, Resend,
    /// Bird/MessageBird, GitLab 19.0+ signing tokens, Supabase, Etsy, Sardine, ...).
    StandardWebhooks,
    /// A caller-configured HMAC scheme (`spec.md` §2.2): covers long-tail
    /// providers and internal senders without waiting on a crate release,
    /// with the same constant-time and fail-closed guarantees as the
    /// built-ins. See [`CustomScheme`].
    ///
    /// **Equality caveat.** [`CustomScheme`]'s `PartialEq`/`Eq`/`Hash`
    /// compare the declarative configuration *only*: `signed_string` is a
    /// function pointer and is excluded (it has no reliable equality). Two
    /// `Provider::Custom` values can therefore compare equal while building
    /// entirely different signed strings — so `Provider` equality must not
    /// be used to dispatch or deduplicate custom schemes. Rely on
    /// [`fmt::Display`], which *does* reflect the full declarative
    /// configuration, to identify one custom scheme in logs and config.
    Custom(CustomScheme),
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Provider::Stripe => f.write_str("Stripe"),
            Provider::GitHub => f.write_str("GitHub"),
            Provider::Bitbucket => f.write_str("Bitbucket"),
            Provider::Contentful => f.write_str("Contentful"),
            Provider::Box => f.write_str("Box"),
            Provider::Intercom => f.write_str("Intercom"),
            Provider::Expo => f.write_str("Expo"),
            Provider::Meta => f.write_str("Meta"),
            Provider::HubSpot => f.write_str("HubSpot"),
            Provider::Klaviyo => f.write_str("Klaviyo"),
            Provider::Mandrill => f.write_str("Mandrill"),
            Provider::Line => f.write_str("LINE"),
            Provider::Shopify => f.write_str("Shopify"),
            Provider::Slack => f.write_str("Slack"),
            Provider::Square => f.write_str("Square"),
            Provider::Tally => f.write_str("Tally"),
            Provider::FastSpring => f.write_str("FastSpring"),
            Provider::GoCardless => f.write_str("GoCardless"),
            Provider::Mollie => f.write_str("Mollie"),
            Provider::Twilio => f.write_str("Twilio"),
            Provider::Twitch => f.write_str("Twitch"),
            Provider::Typeform => f.write_str("Typeform"),
            Provider::Discord => f.write_str("Discord"),
            Provider::PayPal => f.write_str("PayPal"),
            Provider::SendGrid => f.write_str("SendGrid"),
            Provider::Paystack => f.write_str("Paystack"),
            Provider::Paddle => f.write_str("Paddle"),
            Provider::PagerDuty => f.write_str("PagerDuty"),
            Provider::Pusher => f.write_str("Pusher"),
            Provider::Linear => f.write_str("Linear"),
            Provider::LaunchDarkly => f.write_str("LaunchDarkly"),
            Provider::Notion => f.write_str("Notion"),
            Provider::Nylas => f.write_str("Nylas"),
            Provider::Zoom => f.write_str("Zoom"),
            Provider::Cloudflare => f.write_str("Cloudflare"),
            Provider::CircleCi => f.write_str("CircleCI"),
            Provider::Coinbase => f.write_str("Coinbase"),
            Provider::Dropbox => f.write_str("Dropbox"),
            Provider::DocuSign => f.write_str("DocuSign"),
            Provider::Fintoc => f.write_str("Fintoc"),
            Provider::Razorpay => f.write_str("Razorpay"),
            Provider::Recharge => f.write_str("Recharge"),
            Provider::Ripple => f.write_str("Ripple"),
            Provider::LemonSqueezy => f.write_str("Lemon Squeezy"),
            Provider::Xero => f.write_str("Xero"),
            Provider::Sentry => f.write_str("Sentry"),
            Provider::Adyen => f.write_str("Adyen"),
            Provider::Airwallex => f.write_str("Airwallex"),
            Provider::Mux => f.write_str("Mux"),
            Provider::Zendesk => f.write_str("Zendesk"),
            Provider::WorkOS => f.write_str("WorkOS"),
            Provider::WooCommerce => f.write_str("WooCommerce"),
            Provider::Calendly => f.write_str("Calendly"),
            Provider::Vercel => f.write_str("Vercel"),
            Provider::Webflow => f.write_str("Webflow"),
            Provider::X => f.write_str("X"),
            Provider::Tailscale => f.write_str("Tailscale"),
            Provider::StandardWebhooks => f.write_str("Standard Webhooks"),
            Provider::Custom(scheme) => {
                write!(f, "Custom({}", scheme.signature_header)?;
                write!(f, ", {}, {}", scheme.hash, scheme.encoding)?;
                if let Some(prefix) = scheme.prefix {
                    write!(f, ", prefix `{prefix}`")?;
                }
                if let Some(timestamp) = scheme.timestamp_header {
                    write!(f, ", timestamp header `{timestamp}`")?;
                    // Only the non-default unit is spelled out, so a seconds
                    // scheme's rendering stays byte-identical to what it was
                    // before the field existed. A log line still tells the
                    // two apart, which matters because picking the wrong unit
                    // is the footgun `TimestampUnit` exists to prevent.
                    if scheme.timestamp_unit != TimestampUnit::Seconds {
                        write!(f, ", timestamp unit {}", scheme.timestamp_unit)?;
                    }
                }
                f.write_str(")")
            }
        }
    }
}

/// Error returned when a string does not name a known [`Provider`] (from
/// the [`core::str::FromStr`] implementation).
///
/// Parsing is case-insensitive and accepts exactly the canonical
/// [`fmt::Display`] spelling of each provider (e.g. `"github"`, `"GitHub"`,
/// `"GITHUB"`), plus the space-separated and hyphenated human-readable forms
/// for the providers whose brand name runs several words together:
/// `"lemon squeezy"`/`"lemon-squeezy"` ↔ [`Provider::LemonSqueezy`],
/// `"standard webhooks"`/`"standard-webhooks"` ↔
/// [`Provider::StandardWebhooks`], `"hub spot"`/`"hub-spot"` ↔
/// [`Provider::HubSpot`], etc. — the spellings operators actually write in
/// config files.
/// [`Provider::StandardWebhooks`] additionally accepts the brand names of the
/// signers that serve it: `"svix"`, `"resend"`, `"messagebird"`, `"bird"`,
/// `"gitlab"`, `"clerk"`, `"openai"`, `"warp"`, `"loops"`, `"anthropic"`,
/// `"gemini"`, `"brex"`, `"bigcommerce"` (also `"big commerce"`/
/// `"big-commerce"`), `"lithic"`, `"incident.io"` (also `"incident"`),
/// `"supabase"`, `"etsy"`, `"sardine"`, `"dodo"`, `"dodopayments"`,
/// `"zapier"`, `"vanta"`, `"safetykit"`, `"prescience"`, `"taskrabbit"`,
/// `"liveblocks"`, `"flip"`, `"replicate"`, `"inai"`, `"drata"`, `"nash"`,
/// `"render"`, `"yoco"`, `"novu"`, `"crossmint"`, `"daytona"`, `"polar"`,
/// `"helcim"`, `"celitech"`, `"360learning"`, `"natural"`, `"origami"`,
/// `"parallel"`, `"openlayer"`, `"acolad"`, `"allo"`, and `"lexe"` all parse
/// to it.
/// Both header spellings are accepted in real deliveries: the canonical
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` names or the
/// Svix-branded aliases `svix-id`/`svix-timestamp`/`svix-signature` (an
/// alias Svix spells out in its verification docs; the canonical name wins
/// when a delivery carries both).
/// (Svix is
/// the reference implementation whose scheme StandardWebhooks implements;
/// Resend signs every delivery with the same `svix-signature` construction and
/// Svix-form secret, per its official docs; Bird — formerly MessageBird —
/// likewise states its webhook deliveries follow the Standard Webhooks
/// specification, per its official docs; GitLab's webhook delivery follows the
/// Standard Webhooks specification when a "signing token" is configured, per
/// its official docs; Clerk's official backend SDK maps Svix headers onto the
/// Standard Webhooks header names and verifies them with the reference
/// Standard Webhooks verifier, per its official source; OpenAI delivers
/// webhooks using the same `webhook-id`/`webhook-timestamp`/`webhook-signature`
/// (`v1,<base64>`) construction and `whsec_`-prefixed secret, and its official
/// docs verify them with the reference Standard Webhooks libraries; Warp's
/// webhook documentation states its deliveries implement the Standard Webhooks
/// specification, signing with the same construction and `whsec_`-prefixed
/// secrets, and recommends verifying with a standard verification library;
/// Loops signs every delivery with the same `webhook-id`/`webhook-timestamp`/
/// `webhook-signature` (`v1,<base64>`) construction and `whsec_`-prefixed
/// secret, per its official docs' verification snippet; Anthropic's official
/// webhook docs state that every delivery carries the same
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` construction keyed by
/// a `whsec_`-prefixed signing secret and verify with their SDK's reference
/// Standard Webhooks verifier; Google Gemini's official webhook docs state
/// that static webhook deliveries strictly follow the Standard Webhooks
/// specification, signing every delivery with the same
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` construction keyed by
/// a `whsec_`-prefixed signing secret returned by the WebhookService API;
/// Brex's official webhook docs describe the exact same construction —
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` headers, an
/// HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{raw_body}` keyed by a
/// base64-decoded signing secret and a space-delimited versioned signature
/// list — and Brex is listed as a Standard Webhooks-compatible sender on the
/// official site; BigCommerce's official webhook docs tell merchants to
/// verify callbacks with the official Standard Webhooks libraries and show
/// `wh.verify(payload, headers)` against the same three `webhook-*` headers,
/// behind a signature plus a replay-protected timestamp; Lithic's official
/// events API docs describe the exact same construction — the
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` headers, an HMAC-SHA256
/// over `{webhook-id}.{webhook-timestamp}.{raw_body}` keyed by the base64 part
/// of a `whsec_`-prefixed signing secret, a space-delimited versioned
/// signature list, and a five-minute replay tolerance window — and publish a
/// byte-exact worked example. incident.io's official webhook docs state that
/// its deliveries are "powered by Svix", carry the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, describe the signature as an HMAC of
/// `$WEBHOOK_ID.$WEBHOOK_TIMESTAMP.$REQUEST_BODY` keyed by the endpoint's
/// signing secret, and direct receivers to verify with the Svix/Standard
/// Webhooks client libraries; incident.io is also listed as a Standard
/// Webhooks-compatible sender on the official site.
/// Supabase's official auth-hooks docs state that HTTP hooks "follow the
/// Standard Webhooks Specification", attach the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers with a symmetric `whsec_`-prefixed base64 signing secret, and
/// direct receivers to verify with the reference Standard Webhooks
/// libraries; Supabase is also listed as a Standard Webhooks-compatible
/// sender on the official site.
/// Etsy's official webhook docs describe the exact same construction — the
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, a "signed content" string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, and a
/// 300-second replay tolerance window; Etsy is also listed as a Standard
/// Webhooks-compatible sender on the official site.
/// Sardine's official webhook docs describe the exact same construction — the
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, a signed content string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, and a
/// constant-time comparison; Sardine is also listed as a Standard
/// Webhooks-compatible sender on the official site.
/// Dodo Payments' official webhook docs state that its deliveries follow the
/// Standard Webhooks specification, attaching the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` headers and signing a
/// message built by concatenating the id, timestamp, and raw payload with `.`
/// joins using HMAC-SHA256 keyed by the endpoint's signing secret; the docs
/// verify deliveries with the reference Standard Webhooks libraries and
/// publish an Express handler that does exactly that.
/// Zapier's official webhook docs state that its connection-webhook deliveries
/// follow the Standard Webhooks specification, attaching the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` headers, signing a
/// message built by concatenating the id, timestamp, and raw payload with `.`
/// joins using HMAC-SHA256 keyed by the endpoint's `whsec_`-prefixed signing
/// secret, and recommending the spec's five-minute tolerance window and the
/// reference Standard Webhooks libraries.
/// Vanta's official webhook docs state that its event deliveries are "powered
/// by Svix", attaching the same signed content — the `svix-id`/`svix-timestamp`/
/// `svix-signature` (Svix-branded aliases of the spec's `webhook-*` names)
/// headers, a message built by concatenating id, timestamp, and raw body with
/// `.` joins, HMAC-SHA256 keyed by the base64-decoded remainder of a
/// `whsec_`-prefixed signing secret, a space-delimited `v1,` list, and a
/// five-minute replay window — and direct receivers to verify with the
/// Svix/Standard Webhooks client libraries; Vanta is also listed as a Standard
/// Webhooks-compatible sender on the official site.
/// SafetyKit's official webhook docs describe the exact same construction —
/// the `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, a signed content string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, a
/// space-delimited `v1,` signature list, a five-minute replay tolerance
/// window, and a constant-time comparison recommendation — and direct
/// receivers to verify with the Svix/Standard Webhooks client libraries.
/// Prescience's official webhook docs state that signatures "follow the
/// standard-webhooks scheme", describe the same `{webhook-id}.{webhook-
/// timestamp}.{raw_body}` HMAC-SHA256 construction keyed by the base64-decoded
/// remainder of a `whsec_`-prefixed signing secret, and publish a byte-exact
/// worked example whose claimed signature verifies.
/// TaskRabbit's official webhook docs state that its deliveries are "delivered
/// via Svix", that "Svix signs every webhook payload with a secret key unique
/// to your endpoint", and that receivers "should always verify the signature
/// before processing the payload" with the Svix verification libraries;
/// TaskRabbit is also listed as a Standard Webhooks-compatible sender on the
/// official site.
/// Liveblocks' official webhook docs describe the exact same construction —
/// the `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, a signed content string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, a
/// space-delimited versioned signature list, a five-minute replay tolerance
/// window, and a constant-time comparison recommendation — and point receivers
/// at the Svix end-to-end tooling to test their endpoint.
/// Flip Energy's official webhook docs state that its deliveries follow the
/// Standard Webhooks specification, attaching the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers and a signed content string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, and
/// directing receivers to reject any request whose timestamp is more than
/// five minutes older than local time.
/// Replicate's official webhook docs describe the exact same construction —
/// the `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, a signed content string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, a
/// space-delimited versioned signature list, a timestamp tolerance window for
/// replay protection, and a constant-time comparison recommendation.
/// inai's official webhook docs describe the exact same construction — the
/// `webhook-id`/`webhook-timestamp`/`webhook-signature`
/// (`v1,<base64>`) headers, a signed content string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, a
/// space-delimited versioned signature list, and a ±300-second replay
/// tolerance window — and publish a byte-exact worked example that verifies
/// against this implementation.
/// Drata's official workflow docs state that its outbound webhook deliveries
/// are sent "using Svix" — the exact Svix-served Standard Webhooks
/// construction this provider implements — and Drata is also listed as a
/// Standard Webhooks-compatible sender on the official site.
/// Nash's official webhook docs likewise state "We use a service called Svix
/// to send webhooks", directing receivers to verify with the Svix libraries
/// or manually against the `svix-id`/`svix-timestamp`/`svix-signature`
/// headers and the endpoint signing secret, and Nash is listed as a Standard
/// Webhooks-compatible sender on the official site.
/// Render's official webhook docs state that "Render's webhook implementation
/// follows the specification defined by the Standard Webhooks project",
/// attaching the same three `webhook-id`/`webhook-timestamp`/`webhook-signature`
/// (`v1,<base64>`) headers and an HMAC-SHA256 signature over
/// `{webhook-id}.{webhook-timestamp}.{body}` keyed by the endpoint's signing
/// secret, and recommending the Standard Webhooks client libraries; Render is
/// also listed as a Standard Webhooks-compatible sender on the official site.
/// Yoco's official webhook docs direct receivers to verify deliveries with the
/// open-source Standard Webhooks libraries and describe the exact same
/// construction — the `webhook-id`/`webhook-timestamp`/`webhook-signature`
/// (`v1,<base64>`) headers, a signed-content string of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256 keyed by the
/// base64-decoded remainder of a `whsec_`-prefixed signing secret, a
/// space-delimited versioned signature list, a constant-time comparison, and a
/// replay-protection timestamp window; Yoco is also listed as a Standard
/// Webhooks-compatible sender on the official site.
/// Novu's official webhook docs state that "Novu signs webhook requests so you
/// can verify that payloads were sent by Novu", attach the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, publish the reference Svix example payload as the shape of a real
/// delivery, and direct receivers to verify with the Svix/Standard Webhooks
/// client libraries (whose verification snippet and delivery examples this
/// provider's [`Provider::StandardWebhooks`] implementation reproduces
/// byte-for-byte); Novu is an open-source notification platform whose outbound
/// webhooks are delivered through the same Svix-served construction the
/// reference implementation ships.
/// Crossmint's official webhook docs state that "Crossmint signs every webhook
/// and its metadata with a unique key for each endpoint", deliver every call
/// with the same three `svix-id`/`svix-timestamp`/`svix-signature`
/// (`v1,<base64>`) headers, document signing `{svix-id}.{svix-timestamp}.{body}`
/// (the raw request body) with HMAC-SHA256 keyed by the base64-decoded
/// remainder of a `whsec_`-prefixed signing secret, recommend a constant-time
/// comparison and a timestamp-tolerance check, and direct receivers to verify
/// with the Svix/Standard Webhooks client libraries — the exact construction
/// this provider's [`Provider::StandardWebhooks`] implementation reproduces
/// byte-for-byte, with the same reference Svix example payload its vector suite
/// pins.
/// Daytona's official webhook docs describe webhook delivery configured in the
/// Daytona dashboard, and its official open-source server delivers those
/// webhooks through the Svix SDK (`new Svix(authToken, { serverUrl })`,
/// `svix.message.create(...)`) — the exact Svix-served Standard Webhooks
/// construction this provider implements — and Daytona is also listed as a
/// Standard Webhooks-compatible sender on the official site.
/// Polar's official webhook docs state that "Our webhook implementation
/// follows the Standard Webhooks specification", attach the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers and a single versioned signature over
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, tell receivers to "use a
/// Standard Webhooks library or follow the specification" and to pass the
/// `whsec_`-prefixed secret to that library as-is, and its official SDKs
/// sign and verify exactly this — HMAC-SHA256 keyed by the base64-decoded
/// remainder of the signing secret, a space-delimited versioned signature
/// list, and a five-minute replay window — which is the same construction
/// this provider implements byte-for-byte; Polar is an open-source funding
/// platform (source: <https://polar.sh/docs/integrate/webhooks/delivery>).
/// Helcim's official connected-account webhooks docs
/// (<https://devdocs.helcim.com/docs/connected-account-webhooks>) describe the
/// exact same construction — the `webhook-id`/`webhook-timestamp`/
/// `webhook-signature` (`v1,<base64>`) headers, a verification payload of
/// `{webhook_id}.{webhook_timestamp}.{request_body}`, HMAC-SHA256 keyed by the
/// base64-decoded "Verifier Token" handed out during onboarding, and a note to
/// strip the `v1,` prefix only when not using "the SVIX library" — so Helcim
/// is a Standard Webhooks sender and `helcim` is accepted as a brand alias for
/// this provider.
/// 360Learning's official webhook security docs
/// (<https://360learning.readme.io/docs/security-and-signature-verification>)
/// describe the exact same construction — the `webhook-id`/`webhook-timestamp`/
/// `webhook-signature` (`v1,<base64>`) headers, a signed content of
/// `{webhook-id}.{webhook-timestamp}.{raw_body}`, HMAC-SHA256, and state the
/// deliveries are sent by Svix ("We use Svix to deliver webhook events") — so
/// 360Learning is a Standard Webhooks sender and `360learning` is accepted as a
/// brand alias for this provider.
/// CELITECH's official webhook security docs
/// (<https://docs.celitech.com/webhooks/security>) describe the exact same
/// construction — every delivery carries the Svix-branded
/// `svix-id`/`svix-timestamp`/`svix-signature` headers, verification is an
/// HMAC-SHA256 over the delivery's `svix-id`, `svix-timestamp`, and raw body
/// computed with the endpoint's per-endpoint signing secret and compared in
/// constant time, and deliveries whose `svix-timestamp` is too far in the past
/// or future should be rejected against replay attacks — so CELITECH is a
/// Standard Webhooks sender and `celitech` is accepted as a brand alias for
/// this provider.
/// Natural's official webhook integration guide states that "Natural signs
/// every delivery with the Standard Webhooks spec", attaching the same three
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, a signed content of `{webhook-id}.{webhook-timestamp}.{body}`,
/// HMAC-SHA256 keyed by the base64-decoded remainder of a `whsec_`-prefixed
/// signing secret, and a space-delimited versioned signature list for secret
/// rotation — so Natural is a Standard Webhooks sender and `natural` is
/// accepted as a brand alias for this provider.
/// Origami's official webhook docs describe the signature as an "HMAC-SHA256
/// over the literal string `{webhook-id}.{webhook-timestamp}.{raw-body}` using
/// your `whsec_…` secret as the HMAC key", with the prefix stripped and the
/// remainder base64-decoded exactly per the canonical Standard Webhooks spec,
/// a space-delimited `v1,` list (two values during a 24-hour secret rotation),
/// and a ±300-second replay window — so Origami is a Standard Webhooks sender
/// and `origami` is accepted as a brand alias for this provider.
/// Parallel's official webhook setup guide states that its webhooks follow the
/// "standard webhook conventions" — every delivery carries the canonical
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`)
/// headers, signed over `{webhook-id}.{webhook-timestamp}.{payload}` with
/// HMAC-SHA256 keyed by the base64-decoded remainder of a `whsec_`-prefixed
/// signing secret, space-delimited for rotation (source:
/// <https://docs.parallel.ai/resources/webhook-setup>); the docs also publish
/// a worked header example. So Parallel is a Standard Webhooks sender and
/// `parallel` is accepted as a brand alias for this provider. (Note:
/// Parallel's same guide documents a *legacy* signing variant — the entire
/// `whsec_…` string used raw as the HMAC key — still supported for earlier
/// integrations; new deliveries follow the Standard Webhooks construction,
/// and this provider verifies those.)
/// Openlayer's official webhook security docs
/// (<https://docs.openlayer.com/security/webhooks/verify-signatures>) describe
/// the exact same construction — every delivery carries the canonical
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`) headers,
/// the signed content is `{webhook-id}.{webhook-timestamp}.{raw_body}`, the key
/// is the subscription's signing secret with the `whsec_` prefix removed and the
/// remainder base64-decoded, and deliveries outside a ±5-minute tolerance
/// window should be rejected against replay — so Openlayer is a Standard
/// Webhooks sender and `openlayer` is accepted as a brand alias for this
/// provider.
/// Acolad's official Public API webhook docs state that it "uses a webhook
/// service called Svix" to deliver events, that receivers "strongly
/// recommended" verify every delivery, and that "Svix provides a number of
/// libraries to easily verify events" plus manual-verification instructions
/// (sources: <https://eu1.anypoint.mulesoft.com/exchange/portals/acolad/24e64f00-e5a9-4989-a410-e8cc1c143297/public-x-api/minor/2.2/pages/4u7-it6/Webhooks/>
/// and the Svix scheme those pages defer to, <https://docs.svix.com/receiving/verifying-payloads/how-manual>)
/// — Svix-hosted senders sign with the exact Standard Webhooks construction
/// this provider implements, so `acolad` is accepted as a brand alias for it.
/// Allo's official webhook signature docs state that every delivery carries the
/// canonical `webhook-id`/`webhook-timestamp`/`webhook-signature` (`v1,<base64>`,
/// space-delimited during rotation) headers, that the signed content is the
/// string `{webhook-id}.{webhook-timestamp}.{raw_body}`, that the signing
/// secret has the `whsec_<base64key>` format with the prefix stripped and the
/// remainder base64-decoded for the HMAC-SHA256 key, and that a ±5-minute
/// replay window applies
/// (source: <https://help.withallo.com/en/v2/api-reference/webhooks/verifying-signatures>)
/// — the exact Standard Webhooks construction this provider implements, so
/// `allo` is accepted as a brand alias for it.
/// Lexe's official sidecar webhook docs state that "Lexe's sidecar signs
/// outbound webhooks using the Standard Webhooks HMAC-SHA256 scheme", that
/// when a shared secret is configured every delivery carries the canonical
/// `webhook-id`/`webhook-timestamp`/`webhook-signature` headers, that the
/// shared secret is a random 24–64 byte string base64-encoded and
/// "conventionally prefixed with `whsec_`", and that the
/// `webhook-signature` value is `"v1," + base64(HMAC-SHA256(<secret>,
/// "<webhook-id>.<webhook-timestamp>.<raw body>"))`
/// (source: <https://docs.lexe.tech/sidecar/webhooks/>) — the exact Standard
/// Webhooks construction this provider implements, so `lexe` is accepted as a
/// brand alias for it.
/// [`Provider::Mandrill`] additionally accepts its current documented brand
/// name, `"mailchimp"`/`"mailchimp transactional"`/`"mailchimp-transactional"`
/// (Mailchimp Transactional is the name the docs/README use for the
/// formerly-Mandrill provider).
/// [`Provider::Custom`] cannot be parsed from a bare name — constructing one
/// requires a [`CustomScheme`] — so `"custom"` is rejected like any unknown
/// name.
impl core::str::FromStr for Provider {
    type Err = ProviderParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            n if n.eq_ignore_ascii_case("stripe") => Ok(Provider::Stripe),
            n if n.eq_ignore_ascii_case("github") => Ok(Provider::GitHub),
            n if n.eq_ignore_ascii_case("bitbucket") => Ok(Provider::Bitbucket),
            n if n.eq_ignore_ascii_case("contentful") => Ok(Provider::Contentful),
            n if n.eq_ignore_ascii_case("box") => Ok(Provider::Box),
            n if n.eq_ignore_ascii_case("intercom") => Ok(Provider::Intercom),
            n if n.eq_ignore_ascii_case("expo") => Ok(Provider::Expo),
            n if n.eq_ignore_ascii_case("meta") => Ok(Provider::Meta),
            n if n.eq_ignore_ascii_case("hubspot")
                || n.eq_ignore_ascii_case("hub spot")
                || n.eq_ignore_ascii_case("hub-spot") =>
            {
                Ok(Provider::HubSpot)
            }
            n if n.eq_ignore_ascii_case("klaviyo") => Ok(Provider::Klaviyo),
            n if n.eq_ignore_ascii_case("mandrill")
                || n.eq_ignore_ascii_case("mailchimp")
                || n.eq_ignore_ascii_case("mailchimp transactional")
                || n.eq_ignore_ascii_case("mailchimp-transactional") =>
            {
                Ok(Provider::Mandrill)
            }
            n if n.eq_ignore_ascii_case("line") => Ok(Provider::Line),
            n if n.eq_ignore_ascii_case("shopify") => Ok(Provider::Shopify),
            n if n.eq_ignore_ascii_case("slack") => Ok(Provider::Slack),
            n if n.eq_ignore_ascii_case("square") => Ok(Provider::Square),
            n if n.eq_ignore_ascii_case("tally") => Ok(Provider::Tally),
            n if n.eq_ignore_ascii_case("fastspring") => Ok(Provider::FastSpring),
            n if n.eq_ignore_ascii_case("gocardless") => Ok(Provider::GoCardless),
            n if n.eq_ignore_ascii_case("mollie") => Ok(Provider::Mollie),
            n if n.eq_ignore_ascii_case("twilio") => Ok(Provider::Twilio),
            n if n.eq_ignore_ascii_case("twitch") => Ok(Provider::Twitch),
            n if n.eq_ignore_ascii_case("typeform") => Ok(Provider::Typeform),
            n if n.eq_ignore_ascii_case("discord") => Ok(Provider::Discord),
            n if n.eq_ignore_ascii_case("paypal") => Ok(Provider::PayPal),
            n if n.eq_ignore_ascii_case("sendgrid") => Ok(Provider::SendGrid),
            n if n.eq_ignore_ascii_case("paystack") => Ok(Provider::Paystack),
            n if n.eq_ignore_ascii_case("paddle") => Ok(Provider::Paddle),
            n if n.eq_ignore_ascii_case("pagerduty")
                || n.eq_ignore_ascii_case("pager duty")
                || n.eq_ignore_ascii_case("pager-duty") =>
            {
                Ok(Provider::PagerDuty)
            }
            n if n.eq_ignore_ascii_case("pusher") => Ok(Provider::Pusher),
            n if n.eq_ignore_ascii_case("linear") => Ok(Provider::Linear),
            n if n.eq_ignore_ascii_case("launchdarkly")
                || n.eq_ignore_ascii_case("launch darkly")
                || n.eq_ignore_ascii_case("launch-darkly") =>
            {
                Ok(Provider::LaunchDarkly)
            }
            n if n.eq_ignore_ascii_case("notion") => Ok(Provider::Notion),
            n if n.eq_ignore_ascii_case("nylas") => Ok(Provider::Nylas),
            n if n.eq_ignore_ascii_case("zoom") => Ok(Provider::Zoom),
            n if n.eq_ignore_ascii_case("cloudflare") => Ok(Provider::Cloudflare),
            n if n.eq_ignore_ascii_case("circleci")
                || n.eq_ignore_ascii_case("circle ci")
                || n.eq_ignore_ascii_case("circle-ci") =>
            {
                Ok(Provider::CircleCi)
            }
            n if n.eq_ignore_ascii_case("coinbase") => Ok(Provider::Coinbase),
            n if n.eq_ignore_ascii_case("dropbox") => Ok(Provider::Dropbox),
            n if n.eq_ignore_ascii_case("docusign") => Ok(Provider::DocuSign),
            n if n.eq_ignore_ascii_case("fintoc") => Ok(Provider::Fintoc),
            n if n.eq_ignore_ascii_case("razorpay") => Ok(Provider::Razorpay),
            n if n.eq_ignore_ascii_case("recharge") => Ok(Provider::Recharge),
            n if n.eq_ignore_ascii_case("ripple") => Ok(Provider::Ripple),
            n if n.eq_ignore_ascii_case("lemonsqueezy")
                || n.eq_ignore_ascii_case("lemon squeezy")
                || n.eq_ignore_ascii_case("lemon-squeezy") =>
            {
                Ok(Provider::LemonSqueezy)
            }
            n if n.eq_ignore_ascii_case("xero") => Ok(Provider::Xero),
            n if n.eq_ignore_ascii_case("sentry") => Ok(Provider::Sentry),
            n if n.eq_ignore_ascii_case("adyen") => Ok(Provider::Adyen),
            n if n.eq_ignore_ascii_case("airwallex") => Ok(Provider::Airwallex),
            n if n.eq_ignore_ascii_case("mux") => Ok(Provider::Mux),
            n if n.eq_ignore_ascii_case("zendesk") => Ok(Provider::Zendesk),
            n if n.eq_ignore_ascii_case("workos") => Ok(Provider::WorkOS),
            n if n.eq_ignore_ascii_case("woocommerce")
                || n.eq_ignore_ascii_case("woo commerce")
                || n.eq_ignore_ascii_case("woo-commerce") =>
            {
                Ok(Provider::WooCommerce)
            }
            n if n.eq_ignore_ascii_case("calendly") => Ok(Provider::Calendly),
            n if n.eq_ignore_ascii_case("vercel") => Ok(Provider::Vercel),
            n if n.eq_ignore_ascii_case("webflow") => Ok(Provider::Webflow),
            n if n.eq_ignore_ascii_case("x")
                || n.eq_ignore_ascii_case("twitter")
                || n.eq_ignore_ascii_case("x twitter")
                || n.eq_ignore_ascii_case("x-twitter") =>
            {
                Ok(Provider::X)
            }
            n if n.eq_ignore_ascii_case("tailscale") => Ok(Provider::Tailscale),
            n if n.eq_ignore_ascii_case("standardwebhooks")
                || n.eq_ignore_ascii_case("standard webhooks")
                || n.eq_ignore_ascii_case("standard-webhooks")
                || n.eq_ignore_ascii_case("svix")
                || n.eq_ignore_ascii_case("resend")
                || n.eq_ignore_ascii_case("messagebird")
                || n.eq_ignore_ascii_case("bird")
                || n.eq_ignore_ascii_case("gitlab")
                || n.eq_ignore_ascii_case("clerk")
                || n.eq_ignore_ascii_case("openai")
                || n.eq_ignore_ascii_case("warp")
                || n.eq_ignore_ascii_case("loops")
                || n.eq_ignore_ascii_case("anthropic")
                || n.eq_ignore_ascii_case("gemini")
                || n.eq_ignore_ascii_case("brex")
                || n.eq_ignore_ascii_case("bigcommerce")
                || n.eq_ignore_ascii_case("big commerce")
                || n.eq_ignore_ascii_case("big-commerce")
                || n.eq_ignore_ascii_case("lithic")
                || n.eq_ignore_ascii_case("incident.io")
                || n.eq_ignore_ascii_case("incident")
                || n.eq_ignore_ascii_case("supabase")
                || n.eq_ignore_ascii_case("etsy")
                || n.eq_ignore_ascii_case("sardine")
                || n.eq_ignore_ascii_case("dodo")
                || n.eq_ignore_ascii_case("dodopayments")
                || n.eq_ignore_ascii_case("zapier")
                || n.eq_ignore_ascii_case("vanta")
                || n.eq_ignore_ascii_case("safetykit")
                || n.eq_ignore_ascii_case("prescience")
                || n.eq_ignore_ascii_case("taskrabbit")
                || n.eq_ignore_ascii_case("liveblocks")
                || n.eq_ignore_ascii_case("flip")
                || n.eq_ignore_ascii_case("replicate")
                || n.eq_ignore_ascii_case("inai")
                || n.eq_ignore_ascii_case("drata")
                || n.eq_ignore_ascii_case("nash")
                || n.eq_ignore_ascii_case("render")
                || n.eq_ignore_ascii_case("yoco")
                || n.eq_ignore_ascii_case("novu")
                || n.eq_ignore_ascii_case("crossmint")
                || n.eq_ignore_ascii_case("daytona")
                || n.eq_ignore_ascii_case("polar")
                || n.eq_ignore_ascii_case("helcim")
                || n.eq_ignore_ascii_case("celitech")
                || n.eq_ignore_ascii_case("360learning")
                || n.eq_ignore_ascii_case("natural")
                || n.eq_ignore_ascii_case("origami")
                || n.eq_ignore_ascii_case("parallel")
                || n.eq_ignore_ascii_case("openlayer")
                || n.eq_ignore_ascii_case("acolad")
                || n.eq_ignore_ascii_case("allo")
                || n.eq_ignore_ascii_case("lexe") =>
            {
                Ok(Provider::StandardWebhooks)
            }
            _ => Err(ProviderParseError),
        }
    }
}

/// The error type for [`Provider`]'s [`core::str::FromStr`] implementation.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderParseError;

impl fmt::Display for ProviderParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "unknown provider name: expected one of `stripe`, `github`, `bitbucket`, `contentful`, `box`, `intercom`, `expo`, `meta`, `hubspot`, `klaviyo`, `mandrill`, `line`, `shopify`, \
             `slack`, `square`, `tally`, `fastspring`, `gocardless`, `mollie`, `twilio`, `twitch`, `typeform`, `discord`, `paypal`, `sendgrid`, `paystack`, `paddle`, `pagerduty`, `pusher`, `linear`, \
             `launchdarkly`, `notion`, `nylas`, `zoom`, `cloudflare`, `circleci`, `coinbase`, `dropbox`, `docusign`, `fintoc`, `razorpay`, `recharge`, `ripple`, `lemonsqueezy` (or `lemon squeezy`), \
             `xero`, `sentry`, `adyen`, `airwallex`, `mux`, `zendesk`, `workos`, `woocommerce`, `calendly`, `vercel`, `webflow`, `tailscale`, `x` (or `twitter`), \
             or `standardwebhooks` (or `standard webhooks`) \
             (case-insensitive; hyphenated/space-separated multi-word spellings like `standard-webhooks` or \
             `mailchimp-transactional` are also accepted, as are the brand aliases `mailchimp` (for `mandrill`), \
             `svix`, `resend`, `messagebird`, `bird`, `gitlab`, `clerk`, `openai`, `warp`, `loops`, `anthropic`, `gemini`, `brex`, `bigcommerce`, `lithic`, `incident.io`/`incident`, `supabase`, `etsy`, `sardine`, `dodo`/`dodopayments`, `zapier`, `vanta`, `safetykit`, `prescience`, `taskrabbit`, `liveblocks`, `flip`, `replicate`, `inai`, `drata`, `nash`, `render`, `yoco`, `novu`, `crossmint`, `daytona`, `polar`, `helcim`, `celitech`, `360learning`, `natural`, `origami`, `parallel`, `openlayer`, `acolad`, `allo`, `lexe` (for `standardwebhooks`)); `custom` requires a `CustomScheme` and must be built directly",
        )
    }
}

/// Unconditional for the same reason as [`VerifyError`]'s impl: `core`'s
/// `Error` trait is stable since Rust 1.81 (MSRV 1.85) and is the very trait
/// `std::error::Error` re-exports, so gating it on `feature = "std"` only
/// cost `no_std` callers an error type (issue #261).
impl core::error::Error for ProviderParseError {}

/// Header names that carry signing material for `provider`, per its row in
/// `spec.md` §3.
///
/// For [`Provider::Custom`] there is no §3 row, so the names come from the
/// scheme itself: `signature_header`, `timestamp_header`, and every entry the
/// caller declared in `CustomScheme::signed_headers` — the declaration that
/// brings a closure's extra reads into the scan at all (issue #395),
/// de-duplicated in list order.
///
/// Used by the `spec.md` §4.4 ambiguity check — by the framework adapters
/// (behind the `tower`/`actix` features) and, since the `http` feature, by
/// `webhook_verify::ambiguous_signature_header` for callers doing their own
/// header extraction. The check rejects requests whose signature headers arrive
/// duplicated with conflicting values — see the ambiguity contract on
/// [`crate::HeaderMap`], which the first-match-only lookup cannot detect on its
/// own. (Named as plain text rather than an intra-doc link because both the
/// `http`-feature entry point and this list are feature-gated in slightly
/// different combinations, and a link here would break `cargo doc` for some of
/// them.)
///
/// Returns an empty list for providers whose implementation is disabled by a
/// feature flag; their verification fails closed with
/// [`VerifyError::UnsupportedProvider`] regardless.
pub(crate) fn signature_header_names(provider: &Provider) -> Vec<&'static str> {
    match provider {
        Provider::Stripe => vec![stripe::SIGNATURE_HEADER],
        Provider::GitHub => vec![github::SIGNATURE_HEADER],
        Provider::Bitbucket => vec![bitbucket::SIGNATURE_HEADER],
        Provider::Contentful => vec![
            contentful::SIGNATURE_HEADER,
            contentful::SIGNED_HEADERS_HEADER,
            contentful::TIMESTAMP_HEADER,
        ],
        Provider::Box => vec![
            box_webhooks::PRIMARY_SIGNATURE_HEADER,
            box_webhooks::SECONDARY_SIGNATURE_HEADER,
            box_webhooks::TIMESTAMP_HEADER,
            box_webhooks::SIGNATURE_VERSION_HEADER,
            box_webhooks::SIGNATURE_ALGORITHM_HEADER,
        ],
        Provider::Intercom => vec![intercom::SIGNATURE_HEADER],
        Provider::Expo => vec![expo::SIGNATURE_HEADER],
        Provider::Meta => vec![meta::SIGNATURE_HEADER],
        Provider::HubSpot => {
            vec![hubspot::SIGNATURE_HEADER, hubspot::TIMESTAMP_HEADER]
        }
        Provider::Klaviyo => vec![klaviyo::SIGNATURE_HEADER, klaviyo::TIMESTAMP_HEADER],
        Provider::Mandrill => vec![mandrill::SIGNATURE_HEADER],
        Provider::Line => vec![line::SIGNATURE_HEADER],
        Provider::Shopify => vec![shopify::SIGNATURE_HEADER],
        Provider::Slack => vec![slack::SIGNATURE_HEADER, slack::TIMESTAMP_HEADER],
        Provider::Square => vec![square::SIGNATURE_HEADER],
        Provider::Tally => vec![tally::SIGNATURE_HEADER],
        Provider::FastSpring => vec![fastspring::SIGNATURE_HEADER],
        Provider::GoCardless => vec![gocardless::SIGNATURE_HEADER],
        Provider::Mollie => vec![mollie::SIGNATURE_HEADER],
        Provider::Twilio => vec![twilio::SIGNATURE_HEADER],
        Provider::Twitch => vec![
            twitch::MESSAGE_ID_HEADER,
            twitch::TIMESTAMP_HEADER,
            twitch::SIGNATURE_HEADER,
        ],
        Provider::Typeform => vec![typeform::SIGNATURE_HEADER],
        Provider::Paystack => vec![paystack::SIGNATURE_HEADER],
        Provider::Discord => {
            vec![discord::SIGNATURE_HEADER, discord::TIMESTAMP_HEADER]
        }
        Provider::Linear => vec![linear::SIGNATURE_HEADER],
        Provider::LaunchDarkly => vec![launchdarkly::SIGNATURE_HEADER],
        Provider::Notion => vec![notion::SIGNATURE_HEADER],
        Provider::Nylas => vec![nylas::SIGNATURE_HEADER],
        Provider::Cloudflare => vec![cloudflare::SIGNATURE_HEADER],
        Provider::CircleCi => vec![circleci::SIGNATURE_HEADER],
        Provider::Coinbase => vec![coinbase::SIGNATURE_HEADER],
        Provider::Dropbox => vec![dropbox::SIGNATURE_HEADER],
        Provider::DocuSign => vec![docusign::SIGNATURE_HEADER],
        Provider::Fintoc => vec![fintoc::SIGNATURE_HEADER],
        Provider::Razorpay => vec![razorpay::SIGNATURE_HEADER],
        Provider::Recharge => vec![recharge::SIGNATURE_HEADER],
        Provider::Ripple => vec![ripple::SIGNATURE_HEADER, ripple::TIMESTAMP_HEADER],
        Provider::LemonSqueezy => vec![lemonsqueezy::SIGNATURE_HEADER],
        Provider::Xero => vec![xero::SIGNATURE_HEADER],
        Provider::Sentry => vec![sentry::SIGNATURE_HEADER],
        Provider::Adyen => vec![adyen::SIGNATURE_HEADER],
        Provider::Airwallex => vec![airwallex::SIGNATURE_HEADER, airwallex::TIMESTAMP_HEADER],
        Provider::Mux => vec![mux::SIGNATURE_HEADER],
        Provider::Zendesk => vec![zendesk::SIGNATURE_HEADER, zendesk::TIMESTAMP_HEADER],
        Provider::WorkOS => vec![workos::SIGNATURE_HEADER],
        Provider::WooCommerce => vec![woocommerce::SIGNATURE_HEADER],
        Provider::Calendly => vec![calendly::SIGNATURE_HEADER],
        Provider::Vercel => vec![vercel::SIGNATURE_HEADER],
        Provider::Webflow => {
            vec![webflow::SIGNATURE_HEADER, webflow::TIMESTAMP_HEADER]
        }
        Provider::X => vec![x_twitter::SIGNATURE_HEADER],
        Provider::Tailscale => vec![tailscale::SIGNATURE_HEADER],
        Provider::Zoom => vec![zoom::SIGNATURE_HEADER, zoom::TIMESTAMP_HEADER],
        Provider::StandardWebhooks => vec![
            standard_webhooks::ID_HEADER,
            standard_webhooks::TIMESTAMP_HEADER,
            standard_webhooks::SIGNATURE_HEADER,
            standard_webhooks::SVIX_ID_HEADER,
            standard_webhooks::SVIX_TIMESTAMP_HEADER,
            standard_webhooks::SVIX_SIGNATURE_HEADER,
        ],
        Provider::Custom(scheme) => {
            // The two headers every scheme declares, plus whatever extra
            // headers `signed_string` reads and the scheme listed in
            // `signed_headers` (issue #395). A name the closure reads but did
            // not declare here is *not* covered — see the CustomScheme
            // struct-level safety note — because nothing outside the closure
            // can enumerate it.
            //
            // Duplicates of an already-listed name are dropped, comparing
            // ASCII-case-insensitively the way header names compare: a scheme
            // that names `signature_header` again (in any case) is scanned
            // once and reported under its `signature_header` spelling rather
            // than under the repeat.
            let mut names = Vec::with_capacity(2 + scheme.signed_headers.len());
            names.push(scheme.signature_header);
            if let Some(timestamp) = scheme.timestamp_header {
                names.push(timestamp);
            }
            for name in scheme.signed_headers {
                if !names.iter().any(|listed| listed.eq_ignore_ascii_case(name)) {
                    names.push(name);
                }
            }
            names
        }
        #[cfg(feature = "sendgrid")]
        Provider::SendGrid => {
            vec![sendgrid::SIGNATURE_HEADER, sendgrid::TIMESTAMP_HEADER]
        }
        #[cfg(feature = "paypal")]
        Provider::PayPal => vec![
            paypal::TRANSMISSION_ID_HEADER,
            paypal::TRANSMISSION_TIME_HEADER,
            paypal::TRANSMISSION_SIG_HEADER,
            paypal::CERT_URL_HEADER,
            paypal::AUTH_ALGO_HEADER,
        ],
        #[cfg(not(feature = "paypal"))]
        Provider::PayPal => Vec::new(),
        #[cfg(not(feature = "sendgrid"))]
        Provider::SendGrid => Vec::new(),
        Provider::Paddle => vec![paddle::SIGNATURE_HEADER],
        Provider::PagerDuty => vec![pagerduty::SIGNATURE_HEADER],
        Provider::Pusher => vec![pusher::SIGNATURE_HEADER],
    }
}

/// Header names the `spec.md` §4.4 ambiguity scan must **skip** for `provider`,
/// because the provider itself sends them more than once with differing values.
///
/// The scan exists to catch a *smuggled* duplicate: a second value some
/// intermediary added, which the verifier's first-match lookup will not read, so
/// an upstream validator checks one signature while the verifier accepts
/// another. A duplicate the **provider** puts there itself carries no such
/// intent, and treating it as smuggled rejects deliveries the provider
/// sanctions — an outage during, for example, a key-rotation window, which is
/// the worst moment for one.
///
/// The list is deliberately a separate, tiny, per-provider declaration rather
/// than a name filtered out inline at the scan site: it is a security-relevant
/// exemption, so it has to be enumerable in one place and pinned by a test
/// against [`signature_header_names`] (a stale name that is no longer one of the
/// provider's signing headers would silently stop exempting anything).
///
/// Empty for every provider whose scheme keeps all its candidates out of the
/// scan's reach — a multi-candidate list packed inside a single header value
/// (Stripe, Paddle, PagerDuty, Mux, Tailscale, Standard Webhooks; the separator
/// is the provider's own, not the scan's concern) or two *distinctly named*
/// headers with one value each (Box's `BOX-SIGNATURE-PRIMARY` /
/// `BOX-SIGNATURE-SECONDARY`), neither of which is a duplicate at all.
pub(crate) fn provider_sent_duplicate_headers(provider: &Provider) -> &'static [&'static str] {
    match provider {
        // Mollie's documented 24-hour signing-secret rotation window sends
        // **two** `X-Mollie-Signature` header lines on every event, one per
        // active secret, with different values — verbatim from Mollie's own
        // docs ("Updating a live signing secret",
        // <https://docs.mollie.com/reference/webhooks-new>). `mollie::verify`
        // reads the first value, and its module docs plus `spec.md` §3 promise
        // that a caller rotating secrets verifies against each in turn; without
        // this exemption the scan rejects the request before `verify()` is
        // reached, so that promise holds only on the direct-`verify()` path and
        // every adapter user gets a body-less 400 for the whole window.
        //
        // The scan cannot tell Mollie's second signature from a smuggled one —
        // both are just two differing values — so the exemption is scoped to
        // this provider's single header rather than taught to the scan. Nothing
        // is loosened about what `verify()` accepts: it still reads the first
        // value and verifies it, so an appended third line changes nothing an
        // attacker can leverage, and a *prepended* forged value still fails
        // verification (a denial, not a bypass).
        Provider::Mollie => &[mollie::SIGNATURE_HEADER],
        _ => &[],
    }
}

/// Verifies that a webhook request was sent by `provider` and was not tampered
/// with in transit.
///
/// * `headers` — request headers via [`HeaderMap`] (any framework's map works).
/// * `raw_body` — the **exact bytes** received. Never re-serialize or
///   re-encode the body before calling this.
/// * `secret` — the shared secret configured with the provider. For Discord it
///   holds the Ed25519 public key instead, and PayPal and SendGrid ignore it
///   entirely in favour of [`VerifyOptions::verifying_material`]; each
///   provider's docs state which applies.
/// * `options` — tolerance/clock knobs; see [`VerifyOptions`].
///
/// Errors are structured ([`VerifyError`]) and never contain secret material.
///
/// # Errors
///
/// Returns [`VerifyError::MissingHeader`] when a required signature header is
/// absent, [`VerifyError::MalformedHeader`] when a header is present but
/// unparseable, and [`VerifyError::BadEncoding`] when a hex or base64 value
/// fails to decode. [`VerifyError::SignatureMismatch`] is returned when the
/// decoded signature does not match the expected value. Providers with
/// timestamp-based replay protection return
/// [`VerifyError::TimestampOutOfTolerance`] when the signed timestamp is too
/// old. [`VerifyError::UnsupportedProvider`] is returned for providers whose
/// implementation is disabled by a crate feature (PayPal without `paypal`,
/// SendGrid without `sendgrid`). [`VerifyError::InvalidSecret`]
/// is returned when the secret is not in the format the provider requires.
/// [`VerifyError::MissingContext`] is returned when provider-specific request
/// context (e.g. Square's notification URL) was not supplied via
/// [`VerifyOptions`].
///
/// A `secret` that is empty, that consists only of whitespace, or that consists
/// only of NUL bytes, is rejected with [`VerifyError::InvalidSecret`] before any
/// request parsing, for every provider whose scheme is keyed by it (all but
/// PayPal and SendGrid, which verify against
/// [`VerifyOptions::verifying_material`] instead): such a key is not a weak key
/// but no usable key at all, since the signature it produces is within a couple
/// of guesses for anyone who can read the request. An all-NUL key is not even
/// that guessable — RFC 2104 zero-pads it to the block size, so it *is* the
/// empty key and yields the empty key's publicly computable MAC.
///
/// This check reads the **raw** secret, which is the same bytes the MAC is
/// keyed with for every provider except the three that hex- or base64-decode
/// it into HMAC key material (Adyen, Ripple, Standard Webhooks). Those
/// re-apply the all-NUL rule to the *decoded* key at their key-derivation
/// sites, since a secret that is not itself all-NUL (`"0000"`, `"AAAA"`,
/// `"whsec_AAAA"`) can decode to an
/// all-NUL key and so is the empty key one encoding layer deeper. Discord
/// hex-decodes its secret too, but into an Ed25519 *public key* rather than
/// MAC key material, so the rule does not reach it; its degenerate shape is
/// the low-order point `spec.md` §4.8 rejects.
///
/// Only those shapes are rejected. A secret that merely *contains* whitespace
/// or a NUL is used exactly as configured, byte for byte — the key is never
/// trimmed before the MAC, because that would silently break every deployment
/// that signs with a padded secret instead of reporting the problem.
#[must_use = "ignoring the verification result can let forged webhooks through"]
#[inline]
pub fn verify(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    opts: VerifyOptions,
) -> Result<(), VerifyError> {
    // The by-value signature is pure ergonomics: no provider mutates its
    // options, so delegate to the borrowing dispatch below immediately rather
    // than ever cloning the caller's options.
    verify_ref(provider, headers, raw_body, secret, &opts)
}

/// The shared verification dispatch, taking `options` by reference.
///
/// [`verify`] and [`verify_any`] accept [`VerifyOptions`] by value for API
/// ergonomics but never mutate them; both delegate here, and the tower/actix
/// adapters call this directly. That keeps repeated verifications from
/// deep-cloning the caller's options on every call — the per-secret loop
/// inside `verify_any` and every request through a framework adapter would
/// otherwise copy `request_url`, `form_params`, `webhook_id`, and the
/// `verifying_material` key/certificate bytes each time, despite `verify`
/// only ever reading them.
#[inline]
#[must_use = "ignoring the verification result can let forged webhooks through"]
pub(crate) fn verify_ref(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    if uses_secret(provider) {
        if let Some(reason) = unusable_secret_reason(secret) {
            return Err(VerifyError::InvalidSecret { reason });
        }
    }
    match provider {
        Provider::Discord => discord::verify(headers, raw_body, secret, options),
        Provider::GitHub => github::verify(headers, raw_body, secret, options),
        Provider::Bitbucket => bitbucket::verify(headers, raw_body, secret, options),
        Provider::Contentful => contentful::verify(headers, raw_body, secret, options),
        Provider::Box => box_webhooks::verify(headers, raw_body, secret, options),
        Provider::Intercom => intercom::verify(headers, raw_body, secret, options),
        Provider::Expo => expo::verify(headers, raw_body, secret, options),
        Provider::Meta => meta::verify(headers, raw_body, secret, options),
        Provider::HubSpot => hubspot::verify(headers, raw_body, secret, options),
        Provider::Klaviyo => klaviyo::verify(headers, raw_body, secret, options),
        Provider::Mandrill => mandrill::verify(headers, raw_body, secret, options),
        Provider::Line => line::verify(headers, raw_body, secret, options),
        Provider::Linear => linear::verify(headers, raw_body, secret, options),
        Provider::LaunchDarkly => launchdarkly::verify(headers, raw_body, secret, options),
        Provider::Notion => notion::verify(headers, raw_body, secret, options),
        Provider::Nylas => nylas::verify(headers, raw_body, secret, options),
        Provider::Zoom => zoom::verify(headers, raw_body, secret, options),
        Provider::Shopify => shopify::verify(headers, raw_body, secret, options),
        Provider::Slack => slack::verify(headers, raw_body, secret, options),
        Provider::Square => square::verify(headers, raw_body, secret, options),
        Provider::Tally => tally::verify(headers, raw_body, secret, options),
        Provider::FastSpring => fastspring::verify(headers, raw_body, secret, options),
        Provider::GoCardless => gocardless::verify(headers, raw_body, secret, options),
        Provider::Mollie => mollie::verify(headers, raw_body, secret, options),
        Provider::Stripe => stripe::verify(headers, raw_body, secret, options),
        Provider::StandardWebhooks => standard_webhooks::verify(headers, raw_body, secret, options),
        Provider::Twilio => twilio::verify(headers, raw_body, secret, options),
        Provider::Twitch => twitch::verify(headers, raw_body, secret, options),
        Provider::Typeform => typeform::verify(headers, raw_body, secret, options),
        Provider::Cloudflare => cloudflare::verify(headers, raw_body, secret, options),
        Provider::CircleCi => circleci::verify(headers, raw_body, secret, options),
        Provider::Coinbase => coinbase::verify(headers, raw_body, secret, options),
        Provider::Dropbox => dropbox::verify(headers, raw_body, secret, options),
        Provider::DocuSign => docusign::verify(headers, raw_body, secret, options),
        Provider::Fintoc => fintoc::verify(headers, raw_body, secret, options),
        Provider::Razorpay => razorpay::verify(headers, raw_body, secret, options),
        Provider::Recharge => recharge::verify(headers, raw_body, secret, options),
        Provider::Ripple => ripple::verify(headers, raw_body, secret, options),
        Provider::LemonSqueezy => lemonsqueezy::verify(headers, raw_body, secret, options),
        Provider::Xero => xero::verify(headers, raw_body, secret, options),
        Provider::Sentry => sentry::verify(headers, raw_body, secret, options),
        Provider::Adyen => adyen::verify(headers, raw_body, secret, options),
        Provider::Airwallex => airwallex::verify(headers, raw_body, secret, options),
        Provider::Mux => mux::verify(headers, raw_body, secret, options),
        Provider::Zendesk => zendesk::verify(headers, raw_body, secret, options),
        Provider::WorkOS => workos::verify(headers, raw_body, secret, options),
        Provider::WooCommerce => woocommerce::verify(headers, raw_body, secret, options),
        Provider::Calendly => calendly::verify(headers, raw_body, secret, options),
        Provider::Vercel => vercel::verify(headers, raw_body, secret, options),
        Provider::Webflow => webflow::verify(headers, raw_body, secret, options),
        Provider::X => x_twitter::verify(headers, raw_body, secret, options),
        Provider::Tailscale => tailscale::verify(headers, raw_body, secret, options),
        #[cfg(feature = "paypal")]
        Provider::PayPal => paypal::verify(headers, raw_body, secret, options),
        #[cfg(not(feature = "paypal"))]
        Provider::PayPal => Err(VerifyError::UnsupportedProvider),
        #[cfg(feature = "sendgrid")]
        Provider::SendGrid => sendgrid::verify(headers, raw_body, secret, options),
        #[cfg(not(feature = "sendgrid"))]
        Provider::SendGrid => Err(VerifyError::UnsupportedProvider),
        Provider::Paystack => paystack::verify(headers, raw_body, secret, options),
        Provider::Paddle => paddle::verify(headers, raw_body, secret, options),
        Provider::PagerDuty => pagerduty::verify(headers, raw_body, secret, options),
        Provider::Pusher => pusher::verify(headers, raw_body, secret, options),
        Provider::Custom(scheme) => custom::verify(&scheme, headers, raw_body, secret, options),
    }
}

/// Whether `provider`'s scheme is keyed by the [`Secret`] argument at all.
///
/// PayPal and SendGrid are the two providers that ignore `Secret` entirely:
/// they check a signature against caller-supplied key material in
/// [`VerifyOptions::verifying_material`], so an
/// unusable `Secret` is neither a misconfiguration nor a security problem for
/// them (a test in `paypal`'s module pins that "any (even pathological)
/// secret is accepted and unused"). Every other provider keys its MAC — or,
/// for Discord, its Ed25519 verifying key — with `Secret`, so an unusable one
/// is always operator misconfiguration. Discord's scheme is asymmetric too,
/// so this exclusion is keyed on "ignores `Secret`" rather than on the
/// scheme's crypto: those are not the same set, and a count of public-key
/// schemes goes stale the next time one ships.
///
/// **A provider added here that ignores `Secret` must be added to this
/// `matches!`**, and a provider added here that does use `Secret` needs no
/// change: the exclusion list is the whole maintenance burden, and it is
/// deliberately the short side.
fn uses_secret(provider: Provider) -> bool {
    !matches!(provider, Provider::PayPal | Provider::SendGrid)
}

/// Why `secret` may not be used as signing material, or `None` if it may
/// (`spec.md` §4.7).
///
/// Three shapes are rejected, and only those three:
///
/// * **empty** — no key at all, so the signature is reproducible by anyone who
///   can read the request;
/// * **entirely whitespace** — the same failure reached one character over.
///   The candidates that produce one are not "all possible strings" but the
///   handful of shapes an ordinary operator mistake produces, and the two most
///   likely are single characters: a `"\n"` from a secret file written with
///   `echo` rather than `printf`, or a `" "` from a CI/CD variable defined as a
///   literal space (`env::var(..).unwrap_or_default()` on a blank-but-present
///   variable). A deployment keyed with one of them is forgeable by anyone who
///   tries three signatures, and the failure is indistinguishable from a
///   working integration;
/// * **entirely NUL** — the *same* key as the empty one, reached a third way.
///   RFC 2104 zero-pads any key shorter than the block size, so `"\0"`,
///   `"\0\0"`, … up to the block size all produce exactly the empty key's MAC.
///   Unlike whitespace this is not even a guessable-but-unlikely key: it is
///   *literally the same MAC*, so the attacker-computable empty-key signature
///   is the one that gets accepted. The reachable shapes are an operator who
///   never noticed a trailing `\0` (a fixed-size `read_exact` into a record
///   padded with zeros, a config value decoded from a fixed-width field), and
///   NUL is not whitespace, so the check above cannot catch it.
///
/// This reads the **raw** secret, which is the same byte string the MAC is
/// keyed with for every provider except the three that hex- or base64-decode
/// it into HMAC key material (Adyen, Ripple, Standard Webhooks). RFC 2104 pads
/// the *decoded* bytes there, and a secret that is not itself all-NUL text —
/// `"0000"`, `"AAAA"`, `"whsec_AAAA"` — can still decode to an all-NUL key,
/// which is the empty key one encoding layer deeper and accepts its publicly
/// computable signature. Those three re-apply the predicate to the decoded
/// key at their key-derivation sites via `core::crypto::is_all_nul_key`.
/// Discord's hex-decoded secret is an Ed25519 *public key*, not MAC key
/// material, so it is deliberately not one of the three; RFC 2104 cannot pad
/// it into anything, and its degenerate shape is the low-order point
/// `spec.md` §4.8 rejects instead.
///
/// "Entirely" is load-bearing and the *only* line drawn here: a secret that
/// merely contains whitespace or a NUL (`"hunter2 "`, `"hunter2\n"`,
/// `"hunter2\0"`) is a perfectly good key and is used exactly as configured.
/// Nothing is trimmed before keying — changing the bytes fed to the MAC would
/// silently break every deployment that legitimately signs with a padded
/// secret, which is the opposite of this crate's bias toward failing loudly.
/// Rejecting is likewise the loud option: it surfaces as
/// [`VerifyError::InvalidSecret`], which the adapters report as operator
/// misconfiguration (500) rather than as a forgery (401).
///
/// The whitespace test is `str::trim`'s (Unicode `White_Space`), matching what
/// an operator can write in their own fix — `secret.trim().is_empty()` — and
/// `Secret` is a `String`, so the test cannot be defeated by a non-UTF-8 key.
/// NUL is tested as bytes, for the same reason: it is the one byte RFC 2104
/// pads with, and a `String` of nothing but NULs is valid UTF-8, so the check
/// sees exactly the bytes the MAC would.
fn unusable_secret_reason(secret: &Secret) -> Option<&'static str> {
    if secret.as_str().is_empty() {
        Some("secret is empty")
    } else if secret.as_str().trim().is_empty() {
        Some("secret is only whitespace")
    } else if secret.as_str().bytes().all(|byte| byte == 0) {
        Some("secret is only NUL bytes")
    } else {
        None
    }
}

/// Tries multiple secrets during a zero-downtime rotation window.
///
/// Stripe and Standard Webhooks allow multiple valid signatures during secret
/// rotation (e.g. `v1=...,v1=...`). This function accepts a slice of
/// [`Secret`]s — each representing an active signing key — and returns
/// `Ok(())` if *any* of them verifies. On total failure it returns
/// `Err(VerifyError::SignatureMismatch)` when at least one key was usable
/// (no timing leak about which key was closest); it returns
/// `Err(VerifyError::InvalidSecret)` only when *every* key was rejected for
/// its own formatting.
///
/// An unusable element — an empty, whitespace-only, or NUL-only secret, the
/// three shapes `spec.md` §4.7 rejects — is one of those unusable keys rather
/// than a forgery, so it is skipped exactly like a garbled one: a slice holding
/// both one and the live key still verifies, and a slice of nothing but
/// unusable secrets reports `InvalidSecret` naming which shape it was.
///
/// For providers whose signing scheme itself embeds multiple signatures
/// (Stripe's `v1=` list, Standard Webhooks' space-delimited `v1,<sig>`
/// list), prefer [`verify()`] with a single secret — the per-provider
/// multi-sig logic already accepts any matching element. `verify_any` is
/// for the *separate* case where the provider's config allows *multiple
/// distinct keys* to be valid simultaneously (e.g. during key rotation).
///
/// # Providers that ignore `Secret`
///
/// Rotation via a slice of [`Secret`]s is only meaningful for providers
/// whose scheme is keyed by the [`Secret`] argument. PayPal and SendGrid
/// ignore it entirely: they verify against
/// [`VerifyOptions::verifying_material`] (and for PayPal, `webhook_id`),
/// so every element of the slice behaves identically and `verify_any` gives
/// them no rotation semantics. It still degrades safely: structural errors
/// (`MissingContext` for absent key material, `MissingHeader`, etc.) are
/// returned immediately, so passing one of them here cannot silently panic
/// or loop. Discord's scheme is asymmetric as well, but its Ed25519
/// verifying key travels in `Secret`, so a Discord key rotation works
/// through `verify_any` like a shared-secret one. For genuine rotation of
/// PayPal/SendGrid key material, supply the current key via
/// [`VerifyOptions::verifying_material`] and re-verify when it rotates,
/// rather than using `verify_any`.
///
/// # Empty slice
///
/// Passing an empty `secrets` slice returns `SignatureMismatch` immediately
/// — there is nothing to try and no attacker-controlled input to parse.
///
/// # Example
///
/// A Stripe delivery signed with the *new* key while the *old* key is still
/// being rotated out — only the new key matches, and `verify_any` returns
/// `Ok(())`:
///
/// ```
/// use webhook_verify::{verify_any, VerifyOptions, Provider, Secret};
///
/// let headers: Vec<(String, String)> = vec![(
///     "Stripe-Signature".to_string(),
///     "t=1700000000,v1=d95c6b7477fbd7e9f90b1b0ef5f9c7ac25abca5382460e0d988c2b2a5b71b990".to_string(),
/// )];
/// let raw_body = b"{\"id\":\"evt_test_webhook\",\"object\":\"event\"}";
///
/// let secrets = [
///     Secret::new("whsec_old_key_being_rotated_out"),
///     Secret::new("whsec_test_secret"), // the key that actually signed this delivery
/// ];
///
/// let result = verify_any(
///     Provider::Stripe,
///     &headers,
///     raw_body,
///     &secrets,
///     // The example uses a fixed historical timestamp; disable the replay
///     // window so the real wall clock during a `cargo test` run doesn't matter.
///     VerifyOptions::default().without_replay_protection(),
/// );
///
/// assert_eq!(result, Ok(()));
/// ```
///
/// # Errors
///
/// Structural errors ([`VerifyError::MissingHeader`],
/// [`VerifyError::MalformedHeader`], [`VerifyError::BadEncoding`],
/// [`VerifyError::UnsupportedProvider`], [`VerifyError::MissingContext`])
/// are returned immediately regardless of how many secrets remain, because
/// they are deterministic across all secrets.
/// [`VerifyError::TimestampOutOfTolerance`] is also returned immediately
/// when encountered — but it can only be encountered *after* some secret's
/// signature verifies, since every timestamped provider checks the replay
/// window after the signature comparison. A stale request with no matching
/// key therefore reports [`VerifyError::SignatureMismatch`] instead; both
/// outcomes reject the request.
/// [`VerifyError::InvalidSecret`] is *not* returned immediately: a secret
/// rejected for its own formatting is unusable for this request, but a
/// later key in the slice may still be correct — which is the point of
/// iterating during a rotation window. [`VerifyError::SignatureMismatch`]
/// is returned once every secret has been tried without a match, provided
/// at least one of them was well-formed; only when *every* secret was
/// invalid does `verify_any` return the first
/// [`VerifyError::InvalidSecret`], so an all-garbled configuration is
/// reported as an operator-configuration error rather than disguised as a
/// forgery.
#[must_use = "ignoring the verification result can let forged webhooks through"]
#[inline]
pub fn verify_any(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secrets: &[Secret],
    opts: VerifyOptions,
) -> Result<(), VerifyError> {
    // The by-value signature is pure ergonomics (no provider mutates its
    // options), so delegate to the borrowing dispatch below immediately rather
    // than ever cloning the caller's options.
    verify_any_ref(provider, headers, raw_body, secrets, &opts)
}

/// The shared multi-secret dispatch, taking `options` by reference.
///
/// Mirrors the [`verify`]/[`verify_ref`] split: [`verify_any`] takes
/// [`VerifyOptions`] by value for API ergonomics and never mutates them, so it
/// delegates here. The framework adapters call this directly — their key ring
/// (`core::adapter_utils::KeyRing`, issue #259) may try several secrets per
/// request, and the by-value form would deep-clone the shared options, plus the
/// heap-allocated request context they carry (`verifying_material`,
/// `request_url`, `form_params`, `webhook_id`), on every one of those attempts.
///
/// The aggregation rules documented on [`verify_any`] live here, so a
/// caller-supplied secret list and an adapter-supplied one cannot diverge.
#[inline]
#[must_use = "ignoring the verification result can let forged webhooks through"]
pub(crate) fn verify_any_ref(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secrets: &[Secret],
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    // First InvalidSecret seen, reported only if *every* secret turns out
    // to be unusable. Not a structural error: it is specific to one secret,
    // so it must not abort the rotation search.
    let mut first_invalid_secret: Option<VerifyError> = None;
    // Set once a well-formed key fails to match. A signature that fails
    // against a usable key is the definitive total-failure signal and takes
    // precedence over InvalidSecret in the final report.
    let mut any_well_formed_mismatch = false;

    for secret in secrets {
        // Verify against the caller's single borrow of `options`, not a fresh
        // deep clone per secret: rotation lists are iterated on the hot path
        // (issue #259 puts one in every adapter request), and the options may
        // carry heap-allocated context (`verifying_material`, `request_url`,
        // `form_params`) that costs a redundant allocation to copy per key.
        match verify_ref(provider, headers, raw_body, secret, options) {
            // A match on any active key is enough during rotation.
            Ok(()) => return Ok(()),
            // A well-formed key that simply doesn't match: keep trying the
            // remaining keys, but remember that the signature failed against
            // a usable key in case nothing else matches either.
            Err(VerifyError::SignatureMismatch) => any_well_formed_mismatch = true,
            // A garbled/undecodable key is unusable for *this* secret only;
            // keep trying the rest and remember the first rejection in case
            // none of them are usable either.
            Err(invalid @ VerifyError::InvalidSecret { .. }) => {
                first_invalid_secret.get_or_insert(invalid);
            }
            Err(other) => {
                // Errors that are deterministic across all secrets
                // (MissingHeader, MalformedHeader, BadEncoding,
                // UnsupportedProvider, MissingContext) occur before any
                // secret-dependent work; return them immediately so callers
                // can distinguish a malformed request from a forged
                // signature. TimestampOutOfTolerance is reached only once a
                // signature verifies, but returning it immediately is safe:
                // the timestamp is the provider's own field, so every other
                // matching key would reject it identically.
                return Err(other);
            }
        }
    }
    // All secrets exhausted without a match. Prefer the definitive
    // SignatureMismatch once at least one key was usable; report the first
    // InvalidSecret only when no usable key existed at all.
    if !any_well_formed_mismatch {
        if let Some(invalid) = first_invalid_secret {
            return Err(invalid);
        }
    }
    Err(VerifyError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::VerifyError;
    use crate::core::headers::is_valid_field_name;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use std::collections::BTreeSet;
    use std::time::Duration;

    /// Locally constructs a Slack `v0=` signature over `v0:{ts}:{body}` with
    /// the given secret (HMAC-SHA256, hex-encoded) — mirrors the construction
    /// in `src/providers/slack.rs` (spec.md §3, Slack row). Test-only.
    fn slack_signature(secret: &str, ts: u64, body: &[u8]) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
            Ok(mac) => mac,
            // Unreachable for a constant test secret (HMAC accepts
            // arbitrary-length keys); kept panic-free to honor the crate-wide
            // clippy deny on unwrap/expect.
            Err(_) => panic!("HMAC-SHA256 with a constant test secret cannot fail"),
        };
        mac.update(format!("v0:{ts}:").as_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    /// GitHub's documented example vector
    /// (<https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>).
    const GITHUB_SECRET: &str = "It's a Secret to Everybody";
    const GITHUB_BODY: &[u8] = b"Hello, World!";
    const GITHUB_SIGNATURE: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    fn github_headers() -> Vec<(String, String)> {
        vec![(
            "X-Hub-Signature-256".to_string(),
            GITHUB_SIGNATURE.to_string(),
        )]
    }

    #[test]
    fn verify_any_accepts_first_matching_secret() {
        // First verify that verify() itself works.
        let direct = super::verify(
            Provider::GitHub,
            &github_headers(),
            GITHUB_BODY,
            &Secret::new(GITHUB_SECRET),
            Default::default(),
        );
        assert_eq!(direct, Ok(()), "direct verify: {direct:?}");

        let secrets = [
            Secret::new("wrong-key"),
            Secret::new(GITHUB_SECRET),
            Secret::new("another-wrong-key"),
        ];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_any_accepts_single_secret() {
        let secrets = [Secret::new(GITHUB_SECRET)];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_any_rejects_when_no_secret_matches() {
        let secrets = [Secret::new("wrong-1"), Secret::new("wrong-2")];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_any_rejects_empty_slice() {
        let secrets: [Secret; 0] = [];
        let headers: Vec<(String, String)> = github_headers().to_vec();
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &headers,
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_any_fails_closed_on_malformed_input() {
        // Missing header — error comes from parsing, not the secret check.
        let secrets = [Secret::new(GITHUB_SECRET)];
        let empty_headers: Vec<(String, String)> = vec![];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &empty_headers,
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: "X-Hub-Signature-256"
            })
        );
    }

    #[test]
    fn verify_any_non_first_secret_matches() {
        // Only the second key is correct; first is wrong.
        let secrets = [Secret::new("bad"), Secret::new(GITHUB_SECRET)];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &github_headers(),
                GITHUB_BODY,
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_any_returns_timestamp_tolerance_immediately_across_secrets() {
        // spec.md §2.1 / verify_any docs: TimestampOutOfTolerance is
        // returned immediately once a secret's signature matches and the
        // timestamp is stale, rather than continuing the rotation search.
        // Here the *last* secret is correct, but the timestamp is stale.
        let slack_secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let slack_body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J";
        let stale_ts = 1_531_420_618u64;
        // Sign `v0:{ts}:{body}` with the secret (HMAC-SHA256, hex).
        let sig = slack_signature(slack_secret, stale_ts, slack_body);
        let sig_value = format!("v0={sig}");
        let ts_value = stale_ts.to_string();
        let headers = [
            ("X-Slack-Signature", sig_value.as_str()),
            ("X-Slack-Request-Timestamp", ts_value.as_str()),
        ];

        // Wall-clock "now" is irrelevant here; use a clock far in the future
        // so the old timestamp is out of tolerance regardless of real time.
        let options = clocked_at(stale_ts + 3600, Some(Duration::from_secs(300)));

        // First confirm the single-secret direct call rejects on tolerance.
        assert!(
            matches!(
                verify(
                    Provider::Slack,
                    &headers,
                    slack_body,
                    &Secret::new(slack_secret),
                    options.clone(),
                ),
                Err(VerifyError::TimestampOutOfTolerance { .. })
            ),
            "direct verify must reject a stale timestamp"
        );

        // Even though the last secret is correct, verify_any must return the
        // deterministic tolerance error, not Ok(()).
        let secrets = [
            Secret::new("wrong-key-1"),
            Secret::new("wrong-key-2"),
            Secret::new(slack_secret),
        ];
        assert!(matches!(
            verify_any(Provider::Slack, &headers, slack_body, &secrets, options,),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
    }

    #[test]
    fn verify_any_multiple_secrets_affect_only_matching_not_timestamp() {
        // Sanity counterpart: with a *fresh* timestamp the last correct secret
        // must verify Ok, proving the immediate tolerance return above is due
        // to time, not to any interaction with the secret slice.
        let slack_secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let slack_body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J";
        let ts = 1_531_420_618u64;
        let sig = slack_signature(slack_secret, ts, slack_body);
        let sig_value = format!("v0={sig}");
        let ts_value = ts.to_string();
        let headers = [
            ("X-Slack-Signature", sig_value.as_str()),
            ("X-Slack-Request-Timestamp", ts_value.as_str()),
        ];
        let options = clocked_at(ts, None);

        let secrets = [
            Secret::new("wrong-key-1"),
            Secret::new("wrong-key-2"),
            Secret::new(slack_secret),
        ];
        assert_eq!(
            verify_any(Provider::Slack, &headers, slack_body, &secrets, options),
            Ok(())
        );
    }

    #[test]
    fn verify_any_all_wrong_secrets_with_fresh_timestamp_is_mismatch() {
        // Guard against the two tests above accidentally passing because
        // verify_any returned SignatureMismatch for the wrong reason: fresh
        // timestamp but every key wrong must be a plain SignatureMismatch. This
        // pins down that the mismatch branch is exercised with timestamps in
        // tolerance, distinct from the tolerance path.
        let slack_secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let slack_body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J";
        let ts = 1_531_420_618u64;
        let sig = slack_signature(slack_secret, ts, slack_body);
        let sig_value = format!("v0={sig}");
        let ts_value = ts.to_string();
        let headers = [
            ("X-Slack-Signature", sig_value.as_str()),
            ("X-Slack-Request-Timestamp", ts_value.as_str()),
        ];
        let options = clocked_at(ts, Some(Duration::from_secs(300)));

        let secrets = [Secret::new("wrong-1"), Secret::new("wrong-2")];
        assert_eq!(
            verify_any(Provider::Slack, &headers, slack_body, &secrets, options),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_any_all_wrong_keys_report_mismatch_even_when_timestamp_stale() {
        // spec.md §2.1: every timestamped provider checks the replay window
        // *after* the signature comparison, so TimestampOutOfTolerance can
        // only be reached once some secret's signature matches. A stale
        // request with NO matching key therefore reports SignatureMismatch,
        // not TimestampOutOfTolerance — pins the actual behavior so the
        // docs stay honest if the ordering is ever reconsidered.
        let slack_secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let slack_body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J";
        let stale_ts = 1_531_420_618u64;
        let sig = slack_signature(slack_secret, stale_ts, slack_body);
        let sig_value = format!("v0={sig}");
        let ts_value = stale_ts.to_string();
        let headers = [
            ("X-Slack-Signature", sig_value.as_str()),
            ("X-Slack-Request-Timestamp", ts_value.as_str()),
        ];
        let options = clocked_at(stale_ts + 3600, Some(Duration::from_secs(300)));

        // Control: with the correct key, the same stale request rejects on
        // tolerance, proving the window/clock are the deciding factor.
        assert!(matches!(
            verify_any(
                Provider::Slack,
                &headers,
                slack_body,
                &[Secret::new(slack_secret)],
                options.clone(),
            ),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));

        // All keys wrong: the signature never verifies, the replay check is
        // never reached, and the stale request reports as a plain forgery.
        assert_eq!(
            verify_any(
                Provider::Slack,
                &headers,
                slack_body,
                &[Secret::new("wrong-1"), Secret::new("wrong-2")],
                options,
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    /// Length in hex characters of a 64-byte Ed25519 signature (as signed over
    /// `{timestamp}{body}` by Discord's scheme).
    const DISCORD_SIGNATURE_LEN_HEX: usize = 128;

    #[test]
    fn verify_any_returns_first_invalid_secret_when_every_secret_is_garbled() {
        // spec.md §2.1 / verify_any docs: `InvalidSecret` is *secret-specific*,
        // so a rotation slice whose keys are all unusable must report the first
        // such rejection as an operator-configuration error, not a forgery.
        // Discord validates the public key's format before any signature work,
        // which cleanly exercises this branch with well-formed headers.
        let headers: Vec<(String, String)> = vec![
            (
                "X-Signature-Ed25519".to_string(),
                "a".repeat(DISCORD_SIGNATURE_LEN_HEX), // valid-shaped hex signature
            ),
            (
                "X-Signature-Timestamp".to_string(),
                "1234567890".to_string(),
            ),
        ];

        // First key: not hex at all. Second key: hex that decodes to the wrong
        // length. Both reject as InvalidSecret, with distinct reasons — so the
        // returned reason proves the *first* garbled key wins.
        let secrets = [Secret::new("not-hex-!"), Secret::new("deadbeef")];

        assert_eq!(
            verify_any(
                Provider::Discord,
                &headers,
                b"{}",
                &secrets,
                Default::default()
            ),
            Err(VerifyError::InvalidSecret {
                reason: "public key is not valid hexadecimal"
            })
        );
    }

    #[test]
    fn verify_any_asymmetric_provider_ignores_secrets_and_returns_structural_error() {
        // PayPal (and SendGrid) ignore the `Secret` slice entirely — they
        // verify against `VerifyOptions::verifying_material` / `webhook_id`.
        // With that context absent, `verify_any` must return the structural
        // `MissingContext` immediately (it is secret-independent) rather
        // than treating any secret as a match or looping meaninglessly.
        #[cfg(feature = "paypal")]
        {
            // PayPal checks its five required headers before the context
            // check, so give them non-empty values to reach `webhook_id`
            // resolution — the point is that verification is secret-
            // independent and fails on the operator-context error, not that
            // any slice element "matches".
            let headers: Vec<(String, String)> = vec![
                ("PayPal-Transmission-Id".to_string(), "AB".to_string()),
                (
                    "PayPal-Transmission-Time".to_string(),
                    "2026-01-01T00:00:00Z".to_string(),
                ),
                ("PayPal-Transmission-Sig".to_string(), "AA==".to_string()),
                (
                    "PayPal-Cert-Url".to_string(),
                    "https://example.test/cert.pem".to_string(),
                ),
                ("PayPal-Auth-Algo".to_string(), "SHA256withRSA".to_string()),
            ];
            let secrets = [Secret::new("irrelevant-1"), Secret::new("irrelevant-2")];
            assert!(matches!(
                verify_any(
                    Provider::PayPal,
                    &headers,
                    b"{}",
                    &secrets,
                    Default::default(),
                ),
                Err(VerifyError::MissingContext { .. })
            ));
        }
    }

    /// `HMAC-SHA256(key = b"", msg = b"Hello, World!")`, hex.
    ///
    /// Independently computed with Python's `hmac`/`hashlib` (`hmac.new(b"",
    /// b"Hello, World!", hashlib.sha256).hexdigest()`) — an *attacker* can
    /// reproduce this value with no access to the deployment, which is exactly
    /// why an empty secret may not be accepted as an HMAC key.
    const EMPTY_KEY_HMAC_SHA256_HEX: &str =
        "2bbcfa9524f3218c7a34b30e6936f8b1a4516cb097f1a85a1c7d98b5977ec769";

    /// SHA-256's block size in bytes, the length RFC 2104 zero-pads a shorter
    /// HMAC key to. Spelled out here rather than taken from `sha2`, which does
    /// not export it, and pinned by `nul_only_secret_is_the_same_key_as_the_empty_one`.
    const SHA256_BLOCK_SIZE: usize = 64;

    /// Every `spec.md` §4.7 unusable secret shape, as
    /// `(secret, HMAC-SHA256(key = secret, msg = b"Hello, World!"), reason)`.
    ///
    /// The MACs are computed independently with Python's `hmac`/`hashlib`
    /// (`hmac.new(secret, b"Hello, World!", hashlib.sha256).hexdigest()`), so
    /// an *attacker* can reproduce every row with no access to the
    /// deployment — which is the whole reason none of them may be accepted as
    /// an HMAC key. The first row is the empty key of
    /// `EMPTY_KEY_HMAC_SHA256_HEX`; the single-character rows are the
    /// realistic shapes, a secret file written with `echo` rather than `printf`
    /// and a CI/CD variable defined as a literal space.
    ///
    /// The `"\u{a0}"` row pins *Unicode* whitespace rather than just ASCII: an
    /// operator can paste a non-breaking space from a web page or a document,
    /// and the check is `str::trim`'s for exactly that reason.
    ///
    /// The NUL rows carry the *same* MAC as the empty row on purpose, because
    /// they are the same key: RFC 2104 zero-pads a short key to the block
    /// size, so every all-NUL key up to SHA-256's 64-byte block produces
    /// literally the empty key's MAC. That is why they are not merely
    /// guessable but *identical* to the no-key forgery, and why NUL — not
    /// whitespace — is the predicate that catches them.
    const UNUSABLE_SECRETS: [(&str, &str, &str); 8] = [
        (
            "",
            "sha256=2bbcfa9524f3218c7a34b30e6936f8b1a4516cb097f1a85a1c7d98b5977ec769",
            "secret is empty",
        ),
        (
            " ",
            "sha256=32c26866a95ba2351872780a2def18864f6229d0d5e1fd63b3d56ee6cedf828a",
            "secret is only whitespace",
        ),
        (
            "\n",
            "sha256=31fb072035916891c35c0d7587a6478d7f31b6a0ccd469dc50f1896fb04ad526",
            "secret is only whitespace",
        ),
        (
            "  ",
            "sha256=ebf949ba1ed25054c40bd913e8027ca9c67ffb90172fafccbd121f2050b9bba6",
            "secret is only whitespace",
        ),
        (
            "\t",
            "sha256=514066f0012099dc4ab8486a64bbbb5195e6072a4fcd63a9dd4954fa8acedf1c",
            "secret is only whitespace",
        ),
        (
            "\u{a0}",
            "sha256=18160da9439d39428128f05d7d6a73df50032fb8fac1c6bb32e35c6fba4d809d",
            "secret is only whitespace",
        ),
        (
            "\0",
            "sha256=2bbcfa9524f3218c7a34b30e6936f8b1a4516cb097f1a85a1c7d98b5977ec769",
            "secret is only NUL bytes",
        ),
        (
            "\0\0\0\0",
            "sha256=2bbcfa9524f3218c7a34b30e6936f8b1a4516cb097f1a85a1c7d98b5977ec769",
            "secret is only NUL bytes",
        ),
    ];

    /// Secrets that merely *contain* whitespace, as
    /// `(secret, HMAC-SHA256(key = secret, msg = b"Hello, World!"))` — the
    /// boundary `unusable_secret_reason` must not cross, since a padded
    /// secret is legitimate key material and is never trimmed.
    const PADDED_SECRETS: [(&str, &str); 3] = [
        (
            "It's a Secret to Everybody\n",
            "sha256=59105a2da8182e5e7d6b699ca7f738081e03db4f55149c9af1ec7d424ca3e19c",
        ),
        (
            "  padded key \t",
            "sha256=d70fd48012d793e247cf9614cb807e8fd3f391fa28b89c3f6d52b358707b16bc",
        ),
        (
            "hunter2 \u{a0}",
            "sha256=91538b1b6293be88e5e1983fbde8f3ed94024ed949e7402573fb18cb8fbfd866",
        ),
    ];

    /// Secrets that merely *contain* a NUL, as
    /// `(secret, HMAC-SHA256(key = secret, msg = b"Hello, World!"))` — the same
    /// boundary for the all-NUL rule. A NUL is the byte RFC 2104 pads with, but
    /// only a key made of *nothing but* NULs collapses to the empty key; one
    /// real byte anywhere makes it an ordinary key, and the MACs below confirm
    /// it is a different one from the empty key's.
    const NUL_PADDED_SECRETS: [(&str, &str); 3] = [
        (
            "hunter2\0",
            "sha256=2a3c60a1804275884b52271f818a890fc5e8d6360c2a17b6a50e35e953301e74",
        ),
        (
            "\0hunter2",
            "sha256=660a73b3e6dc1c2f408174292fc1a09beccbcc72e59f124ce3d30038ce183566",
        ),
        (
            "hunter2\0\0",
            "sha256=2a3c60a1804275884b52271f818a890fc5e8d6360c2a17b6a50e35e953301e74",
        ),
    ];

    #[test]
    fn empty_key_hmac_vector_is_a_genuine_empty_key_mac() {
        // Non-vacuity check for the vector above: the crate's own audited
        // helper must agree that it is a valid HMAC-SHA256 under the *empty*
        // key. If this ever fails, the constant was mistyped and the
        // fail-open test below would be asserting nothing.
        let Ok(signature) = hex::decode(EMPTY_KEY_HMAC_SHA256_HEX) else {
            panic!("the hardcoded empty-key HMAC vector must be valid hex");
        };
        assert!(crate::core::crypto::verify_hmac_sha256(
            b"",
            b"Hello, World!",
            &signature,
        ));
    }

    #[test]
    fn empty_secret_fails_closed_instead_of_accepting_a_forgery() {
        // The bug this guards: with an empty secret every HMAC key is
        // attacker-known, so `verify` used to return `Ok(())` for the
        // publicly computable signature below — a forged delivery accepted.
        // It must now fail closed as operator misconfiguration, which the
        // adapters map to 500 rather than 401 ("attacker").
        let headers = vec![(
            "X-Hub-Signature-256".to_string(),
            format!("sha256={EMPTY_KEY_HMAC_SHA256_HEX}"),
        )];
        assert_eq!(
            verify(
                Provider::GitHub,
                &headers,
                b"Hello, World!",
                &Secret::new(""),
                Default::default(),
            ),
            Err(VerifyError::InvalidSecret {
                reason: "secret is empty"
            })
        );
    }

    #[test]
    fn empty_secret_is_rejected_for_every_provider_that_uses_one() {
        // Drift guard: iterating `provider_list()` means a provider added
        // later is covered by this contract the moment it is listed there.
        // No headers are supplied on purpose — the empty secret is an operator
        // misconfiguration regardless of the request, so it is reported
        // before any request parsing (and therefore before `MissingHeader`).
        let no_headers: Vec<(&str, &str)> = Vec::new();
        for provider in provider_list() {
            if !uses_secret(provider) {
                continue;
            }
            assert_eq!(
                verify(
                    provider,
                    &no_headers,
                    b"{}",
                    &Secret::new(""),
                    Default::default(),
                ),
                Err(VerifyError::InvalidSecret {
                    reason: "secret is empty"
                }),
                "{provider} must reject an empty secret"
            );
        }
    }

    #[test]
    fn uses_secret_excludes_exactly_the_providers_that_ignore_it() {
        // `uses_secret` is a hand-maintained exclusion list, so pin both
        // directions: PayPal and SendGrid ignore `Secret` entirely, and every
        // other named provider keys its scheme with it — Discord included,
        // whose scheme is asymmetric but whose verifying key travels in
        // `Secret`.
        for provider in provider_list() {
            let expected = !matches!(provider, Provider::PayPal | Provider::SendGrid);
            assert_eq!(
                uses_secret(provider),
                expected,
                "{provider}: update `uses_secret` if this provider's treatment \
                 of `Secret` changed"
            );
        }
    }

    #[test]
    fn verify_any_skips_an_empty_secret_and_uses_the_rest() {
        // An empty key in a rotation slice is unusable, not a forgery: a
        // slice that also holds the real key must still verify, exactly as
        // `verify_any`'s documented `InvalidSecret` aggregation rule requires.
        let headers = vec![(
            "X-Hub-Signature-256".to_string(),
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_string(),
        )];
        let secrets = [Secret::new(""), Secret::new("It's a Secret to Everybody")];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &headers,
                b"Hello, World!",
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_any_reports_invalid_secret_when_every_secret_is_empty() {
        // No usable key remains, so the result is the operator-configuration
        // error — never a `SignatureMismatch`, which would read as a forgery
        // and log every rotated-out delivery as an attack.
        let headers = vec![(
            "X-Hub-Signature-256".to_string(),
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_string(),
        )];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &headers,
                b"Hello, World!",
                &[Secret::new(""), Secret::new("")],
                Default::default(),
            ),
            Err(VerifyError::InvalidSecret {
                reason: "secret is empty"
            })
        );
    }

    #[test]
    fn empty_secret_does_not_mask_a_disabled_feature() {
        // `UnsupportedProvider` (a 4xx-class "this crate cannot verify that
        // provider" signal) must win over the empty-secret configuration
        // error, so a build without the feature keeps reporting the missing
        // feature rather than blaming the operator's secret.
        #[cfg(not(feature = "paypal"))]
        assert_eq!(
            verify(
                Provider::PayPal,
                &Vec::<(&str, &str)>::new(),
                b"{}",
                &Secret::new(""),
                Default::default(),
            ),
            Err(VerifyError::UnsupportedProvider)
        );
        #[cfg(not(feature = "sendgrid"))]
        assert_eq!(
            verify(
                Provider::SendGrid,
                &Vec::<(&str, &str)>::new(),
                b"{}",
                &Secret::new(""),
                Default::default(),
            ),
            Err(VerifyError::UnsupportedProvider)
        );

        // The other direction, for the builds where the feature *is* on: the
        // empty-secret guard must not fire for a provider that ignores the
        // secret, or it would invent a configuration error out of an argument
        // the scheme never reads. The error has to be the real, missing key
        // material instead.
        #[cfg(feature = "paypal")]
        assert_eq!(
            verify(
                Provider::PayPal,
                &Vec::<(&str, &str)>::new(),
                b"{}",
                &Secret::new(""),
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: "PayPal-Transmission-Id"
            })
        );
        #[cfg(feature = "sendgrid")]
        assert_eq!(
            verify(
                Provider::SendGrid,
                &Vec::<(&str, &str)>::new(),
                b"{}",
                &Secret::new(""),
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: "X-Twilio-Email-Event-Webhook-Signature"
            })
        );
    }

    /// Decodes a `sha256=<hex>` table entry to the raw bytes `verify_hmac_sha256`
    /// compares against, so the vectors can be checked against the crate's own
    /// audited helper rather than only asserted as literals.
    fn table_mac(mac: &str) -> Vec<u8> {
        let Some(hex) = mac.strip_prefix("sha256=") else {
            panic!("table vectors are stored as `sha256=<hex>`");
        };
        let Ok(bytes) = hex::decode(hex) else {
            panic!("table vectors must be valid hex");
        };
        bytes
    }

    #[test]
    fn unusable_secret_hmac_vectors_are_genuine_macs_for_those_keys() {
        // Non-vacuity check for `UNUSABLE_SECRETS`, the same way
        // `empty_key_hmac_vector_is_a_genuine_empty_key_mac` is for the empty
        // key: the crate's own audited helper must agree that each vector is a
        // valid HMAC-SHA256 under the key in its own row. If this ever fails,
        // the constants were mistyped and the fail-closed tests below would be
        // asserting nothing — the point of the table is that an attacker can
        // compute these values, not that they are arbitrary hex.
        for (secret, mac, _reason) in UNUSABLE_SECRETS {
            assert!(
                crate::core::crypto::verify_hmac_sha256(
                    secret.as_bytes(),
                    b"Hello, World!",
                    &table_mac(mac),
                ),
                "the table's MAC for this secret is not an HMAC under that key"
            );
        }
    }

    #[test]
    fn whitespace_only_secret_fails_closed_instead_of_accepting_a_forgery() {
        // The bug this guards: #222 rejected the *empty* key, but a key one
        // character over is just as guessable and still verified. `"\n"` (a
        // secret file written with `echo` rather than `printf`) and `" "` (a
        // CI/CD variable defined as a literal space) both used to return
        // `Ok(())` for the publicly computable signature below, so a
        // deployment keyed with one was forgeable by anyone who tried three
        // signatures — and indistinguishable from a working integration.
        // Each must now fail closed as operator misconfiguration, which the
        // adapters map to 500 rather than 401 ("attacker").
        for (secret, mac, reason) in UNUSABLE_SECRETS {
            let headers = vec![("X-Hub-Signature-256".to_string(), mac.to_string())];
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    b"Hello, World!",
                    &Secret::new(secret),
                    Default::default(),
                ),
                Err(VerifyError::InvalidSecret { reason }),
                "this unusable secret must fail closed, reported as {reason}"
            );
        }
    }

    #[test]
    fn unusable_secret_is_rejected_for_every_provider_that_uses_one() {
        // Drift guard: iterating `provider_list()` means a provider added
        // later is covered by this contract the moment it is listed there, and
        // iterating the table means both §4.7 shapes are. No headers are
        // supplied on purpose — an unusable secret is an operator
        // misconfiguration regardless of the request, so it is reported before
        // any request parsing (and therefore before `MissingHeader`).
        let no_headers: Vec<(&str, &str)> = Vec::new();
        for provider in provider_list() {
            if !uses_secret(provider) {
                continue;
            }
            for (secret, _mac, reason) in UNUSABLE_SECRETS {
                assert_eq!(
                    verify(
                        provider,
                        &no_headers,
                        b"{}",
                        &Secret::new(secret),
                        Default::default(),
                    ),
                    Err(VerifyError::InvalidSecret { reason }),
                    "{provider} must reject this unusable secret"
                );
            }
        }
    }

    #[test]
    fn a_secret_that_merely_contains_whitespace_still_verifies() {
        // The boundary the rule must not cross. Whitespace *inside* a secret is
        // legitimate key material: a real key pasted with a trailing newline is
        // a different key from the unpasted one, and the provider signs with
        // whatever the operator configured. Rejecting it would break a working
        // integration, and trimming it would silently break every deployment
        // that signs with a padded secret — so the bytes must go into the MAC
        // exactly as configured.
        for (row, (secret, mac)) in PADDED_SECRETS.into_iter().enumerate() {
            let headers = vec![("X-Hub-Signature-256".to_string(), mac.to_string())];
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    b"Hello, World!",
                    &Secret::new(secret),
                    Default::default(),
                ),
                Ok(()),
                "PADDED_SECRETS row {row} must still verify"
            );
        }
    }

    #[test]
    fn nul_only_secret_is_the_same_key_as_the_empty_one() {
        // The claim #225 rests on, checked against the crate's own audited
        // helper rather than just the RFC text: RFC 2104 zero-pads a key
        // shorter than the block size, so an all-NUL key produces *literally*
        // the empty key's MAC. That makes it worse than the whitespace shape
        // rather than a new guessable-key shape — the empty-key signature
        // already published in `EMPTY_KEY_HMAC_SHA256_HEX` is the one a
        // NUL-keyed deployment would accept, so a forgery needs no guessing at
        // all.
        let Ok(signature) = hex::decode(EMPTY_KEY_HMAC_SHA256_HEX) else {
            panic!("the hardcoded empty-key HMAC vector must be valid hex");
        };
        for nul in 1..=SHA256_BLOCK_SIZE {
            let key = vec![0u8; nul];
            assert!(
                crate::core::crypto::verify_hmac_sha256(&key, b"Hello, World!", &signature),
                "a {nul}-NUL key must produce the empty key's MAC, or the \
                 zero-padding this rule relies on does not hold"
            );
        }
    }

    #[test]
    fn nul_only_secret_fails_closed_instead_of_accepting_a_forgery() {
        // The bug this guards: #222 rejected the empty key and #224 the
        // whitespace ones, but a key of NULs is the *same* key as the empty one
        // and used to return `Ok(())` for the publicly computable signature
        // carried in the `UNUSABLE_SECRETS` rows above. Each must now fail
        // closed as operator misconfiguration, which the adapters map to 500
        // rather than 401 ("attacker").
        for (secret, mac, reason) in UNUSABLE_SECRETS {
            let headers = vec![("X-Hub-Signature-256".to_string(), mac.to_string())];
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    b"Hello, World!",
                    &Secret::new(secret),
                    Default::default(),
                ),
                Err(VerifyError::InvalidSecret { reason }),
                "this unusable secret must fail closed, reported as {reason}"
            );
        }
    }

    #[test]
    fn nul_only_secret_is_rejected_past_the_block_size_too() {
        // Only an all-NUL key up to SHA-256's 64-byte block is *the same key* as
        // the empty one — a longer one gets hashed and is no longer publicly
        // computable. Rejecting it anyway is deliberate: the crate's bias is
        // toward failing loudly, and a 65-NUL key is not a key an operator
        // configured on purpose. `NUL_PADDED_SECRETS` keeps the guard from
        // widening any further.
        let over_block_size = "\0".repeat(SHA256_BLOCK_SIZE + 1);
        assert_eq!(
            verify(
                Provider::GitHub,
                &Vec::<(&str, &str)>::new(),
                b"Hello, World!",
                &Secret::new(&over_block_size),
                Default::default(),
            ),
            Err(VerifyError::InvalidSecret {
                reason: "secret is only NUL bytes"
            })
        );
    }

    #[test]
    fn a_secret_that_merely_contains_a_nul_still_verifies() {
        // The boundary the all-NUL rule must not cross, and the reason the
        // predicate is "all bytes are NUL" rather than "contains a NUL": one
        // real byte makes an ordinary key whose MAC is a different value, so
        // the operator's configured bytes must go into the MAC untouched.
        // Rejecting these would break a working integration, and stripping the
        // NUL would silently change the key — the same two options already
        // declined for padded secrets.
        for (row, (secret, mac)) in NUL_PADDED_SECRETS.into_iter().enumerate() {
            let headers = vec![("X-Hub-Signature-256".to_string(), mac.to_string())];
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    b"Hello, World!",
                    &Secret::new(secret),
                    Default::default(),
                ),
                Ok(()),
                "NUL_PADDED_SECRETS row {row} must still verify"
            );
        }
    }

    #[test]
    fn verify_any_skips_an_unusable_secret_and_uses_the_rest() {
        // An unusable key in a rotation slice is unusable, not a forgery: a
        // slice that also holds the real key must still verify, exactly as
        // `verify_any`'s documented `InvalidSecret` aggregation rule requires.
        let headers = vec![(
            "X-Hub-Signature-256".to_string(),
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_string(),
        )];
        let secrets = [
            Secret::new("\n"),
            Secret::new(" "),
            Secret::new("\0"),
            Secret::new("It's a Secret to Everybody"),
        ];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &headers,
                b"Hello, World!",
                &secrets,
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_any_reports_invalid_secret_when_every_secret_is_unusable() {
        // No usable key remains, so the result is the operator-configuration
        // error — never a `SignatureMismatch`, which would read as a forgery
        // and log every rotated-out delivery as an attack.
        let headers = vec![(
            "X-Hub-Signature-256".to_string(),
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_string(),
        )];
        let secrets = [Secret::new("\n"), Secret::new(" "), Secret::new("")];
        assert_eq!(
            verify_any(
                Provider::GitHub,
                &headers,
                b"Hello, World!",
                &secrets,
                Default::default(),
            ),
            Err(VerifyError::InvalidSecret {
                reason: "secret is only whitespace"
            })
        );
    }

    #[test]
    fn an_unusable_secret_is_not_reported_to_a_provider_that_ignores_it() {
        // The mirror of `empty_secret_does_not_mask_a_disabled_feature` for the
        // wider §4.7 rule: the guard exists because these two schemes *key*
        // with the secret, so it must not invent a configuration error for an
        // argument the other 56 schemes never read. Whichever error these
        // actually produce (a disabled feature, a missing header, missing key
        // material), it is the honest one.
        let no_headers: Vec<(&str, &str)> = Vec::new();
        for provider in [Provider::PayPal, Provider::SendGrid] {
            for (secret, _mac, reason) in UNUSABLE_SECRETS {
                assert_ne!(
                    verify(
                        provider,
                        &no_headers,
                        b"{}",
                        &Secret::new(secret),
                        Default::default(),
                    ),
                    Err(VerifyError::InvalidSecret { reason }),
                    "{provider} must not be told its secret is unusable"
                );
            }
        }
    }

    #[test]
    fn provider_display_names() {
        use super::CustomScheme;
        use crate::{Encoding, HashAlg, TimestampUnit};

        assert_eq!(Provider::Stripe.to_string(), "Stripe");
        assert_eq!(Provider::GitHub.to_string(), "GitHub");
        assert_eq!(Provider::Bitbucket.to_string(), "Bitbucket");
        assert_eq!(Provider::Contentful.to_string(), "Contentful");
        assert_eq!(Provider::Box.to_string(), "Box");
        assert_eq!(Provider::Intercom.to_string(), "Intercom");
        assert_eq!(Provider::Expo.to_string(), "Expo");
        assert_eq!(Provider::Meta.to_string(), "Meta");
        assert_eq!(Provider::HubSpot.to_string(), "HubSpot");
        assert_eq!(Provider::Klaviyo.to_string(), "Klaviyo");
        assert_eq!(Provider::Mandrill.to_string(), "Mandrill");
        assert_eq!(Provider::Line.to_string(), "LINE");
        assert_eq!(Provider::Shopify.to_string(), "Shopify");
        assert_eq!(Provider::Slack.to_string(), "Slack");
        assert_eq!(Provider::Square.to_string(), "Square");
        assert_eq!(Provider::Tally.to_string(), "Tally");
        assert_eq!(Provider::FastSpring.to_string(), "FastSpring");
        assert_eq!(Provider::GoCardless.to_string(), "GoCardless");
        assert_eq!(Provider::Mollie.to_string(), "Mollie");
        assert_eq!(Provider::Twilio.to_string(), "Twilio");
        assert_eq!(Provider::Twitch.to_string(), "Twitch");
        assert_eq!(Provider::Typeform.to_string(), "Typeform");
        assert_eq!(Provider::Discord.to_string(), "Discord");
        assert_eq!(Provider::PayPal.to_string(), "PayPal");
        assert_eq!(Provider::SendGrid.to_string(), "SendGrid");
        assert_eq!(Provider::Paystack.to_string(), "Paystack");
        assert_eq!(Provider::Paddle.to_string(), "Paddle");
        assert_eq!(Provider::PagerDuty.to_string(), "PagerDuty");
        assert_eq!(Provider::Pusher.to_string(), "Pusher");
        assert_eq!(Provider::Linear.to_string(), "Linear");
        assert_eq!(Provider::LaunchDarkly.to_string(), "LaunchDarkly");
        assert_eq!(Provider::Notion.to_string(), "Notion");
        assert_eq!(Provider::Nylas.to_string(), "Nylas");
        assert_eq!(Provider::Zoom.to_string(), "Zoom");
        assert_eq!(Provider::Cloudflare.to_string(), "Cloudflare");
        assert_eq!(Provider::CircleCi.to_string(), "CircleCI");
        assert_eq!(Provider::Coinbase.to_string(), "Coinbase");
        assert_eq!(Provider::Dropbox.to_string(), "Dropbox");
        assert_eq!(Provider::DocuSign.to_string(), "DocuSign");
        assert_eq!(Provider::Fintoc.to_string(), "Fintoc");
        assert_eq!(Provider::Razorpay.to_string(), "Razorpay");
        assert_eq!(Provider::Recharge.to_string(), "Recharge");
        assert_eq!(Provider::Ripple.to_string(), "Ripple");
        assert_eq!(Provider::LemonSqueezy.to_string(), "Lemon Squeezy");
        assert_eq!(Provider::Xero.to_string(), "Xero");
        assert_eq!(Provider::Sentry.to_string(), "Sentry");
        assert_eq!(Provider::Adyen.to_string(), "Adyen");
        assert_eq!(Provider::Airwallex.to_string(), "Airwallex");
        assert_eq!(Provider::Mux.to_string(), "Mux");
        assert_eq!(Provider::Zendesk.to_string(), "Zendesk");
        assert_eq!(Provider::WorkOS.to_string(), "WorkOS");
        assert_eq!(Provider::WooCommerce.to_string(), "WooCommerce");
        assert_eq!(Provider::Calendly.to_string(), "Calendly");
        assert_eq!(Provider::Vercel.to_string(), "Vercel");
        assert_eq!(Provider::Webflow.to_string(), "Webflow");
        assert_eq!(Provider::X.to_string(), "X");
        assert_eq!(Provider::Tailscale.to_string(), "Tailscale");
        assert_eq!(Provider::StandardWebhooks.to_string(), "Standard Webhooks");

        let custom = Provider::Custom(CustomScheme {
            hash: HashAlg::Sha256,
            signature_header: "X-My-Sig",
            timestamp_header: None,
            timestamp_unit: TimestampUnit::Seconds,
            encoding: Encoding::Hex,
            prefix: None,
            signed_headers: &[],
            signed_string: |_h, b| b.to_vec(),
        });
        assert_eq!(custom.to_string(), "Custom(X-My-Sig, SHA-256, hex)");

        // A scheme sharing the header but differing in encoding, prefix, or
        // timestamp header must render differently so operators can tell two
        // configurations apart even when they share a header name.
        let prefixed = Provider::Custom(CustomScheme {
            hash: HashAlg::Sha512,
            signature_header: "X-My-Sig",
            timestamp_header: Some("X-My-Ts"),
            timestamp_unit: TimestampUnit::Seconds,
            encoding: Encoding::Base64,
            prefix: Some("v1="),
            signed_headers: &[],
            signed_string: |_h, b| b.to_vec(),
        });
        assert_eq!(
            prefixed.to_string(),
            "Custom(X-My-Sig, SHA-512, base64, prefix `v1=`, timestamp header `X-My-Ts`)"
        );

        // A millisecond scheme shares every other field with `prefixed`, so
        // the declared unit is the only thing that can tell the two
        // configurations apart in a log line. Only the non-default unit is
        // spelled out, leaving the seconds rendering above byte-identical to
        // what it was before the field existed.
        let millis = Provider::Custom(match prefixed {
            Provider::Custom(scheme) => CustomScheme {
                timestamp_unit: TimestampUnit::Millis,
                ..scheme
            },
            other => panic!("expected a Custom provider, got {other:?}"),
        });
        assert_eq!(
            millis.to_string(),
            "Custom(X-My-Sig, SHA-512, base64, prefix `v1=`, timestamp header `X-My-Ts`, timestamp unit milliseconds)"
        );
        assert_ne!(prefixed.to_string(), millis.to_string());
    }

    #[test]
    fn provider_from_str_accepts_canonical_names_case_insensitively() {
        use core::str::FromStr;

        let cases = [
            ("stripe", Provider::Stripe),
            ("github", Provider::GitHub),
            ("bitbucket", Provider::Bitbucket),
            ("contentful", Provider::Contentful),
            ("box", Provider::Box),
            ("intercom", Provider::Intercom),
            ("expo", Provider::Expo),
            ("meta", Provider::Meta),
            ("hubspot", Provider::HubSpot),
            ("klaviyo", Provider::Klaviyo),
            ("mandrill", Provider::Mandrill),
            ("line", Provider::Line),
            ("shopify", Provider::Shopify),
            ("slack", Provider::Slack),
            ("square", Provider::Square),
            ("tally", Provider::Tally),
            ("fastspring", Provider::FastSpring),
            ("gocardless", Provider::GoCardless),
            ("mollie", Provider::Mollie),
            ("twilio", Provider::Twilio),
            ("twitch", Provider::Twitch),
            ("typeform", Provider::Typeform),
            ("discord", Provider::Discord),
            ("paypal", Provider::PayPal),
            ("sendgrid", Provider::SendGrid),
            ("paystack", Provider::Paystack),
            ("paddle", Provider::Paddle),
            ("pagerduty", Provider::PagerDuty),
            ("pusher", Provider::Pusher),
            ("linear", Provider::Linear),
            ("launchdarkly", Provider::LaunchDarkly),
            ("notion", Provider::Notion),
            ("nylas", Provider::Nylas),
            ("zoom", Provider::Zoom),
            ("cloudflare", Provider::Cloudflare),
            ("circleci", Provider::CircleCi),
            ("coinbase", Provider::Coinbase),
            ("dropbox", Provider::Dropbox),
            ("docusign", Provider::DocuSign),
            ("fintoc", Provider::Fintoc),
            ("razorpay", Provider::Razorpay),
            ("recharge", Provider::Recharge),
            ("ripple", Provider::Ripple),
            ("lemonsqueezy", Provider::LemonSqueezy),
            ("lemon squeezy", Provider::LemonSqueezy),
            ("xero", Provider::Xero),
            ("sentry", Provider::Sentry),
            ("adyen", Provider::Adyen),
            ("airwallex", Provider::Airwallex),
            ("mux", Provider::Mux),
            ("zendesk", Provider::Zendesk),
            ("workos", Provider::WorkOS),
            ("woocommerce", Provider::WooCommerce),
            ("calendly", Provider::Calendly),
            ("vercel", Provider::Vercel),
            ("webflow", Provider::Webflow),
            ("x", Provider::X),
            ("tailscale", Provider::Tailscale),
            ("standardwebhooks", Provider::StandardWebhooks),
            ("standard webhooks", Provider::StandardWebhooks),
        ];
        for (name, expected) in cases {
            assert_eq!(Provider::from_str(name), Ok(expected), "lowercase `{name}`");
            let upper = name.to_ascii_uppercase();
            assert_eq!(
                Provider::from_str(&upper),
                Ok(expected),
                "uppercase `{upper}`"
            );
            let mixed = format!("{}{}", name[..1].to_ascii_uppercase(), &name[1..]);
            assert_eq!(Provider::from_str(&mixed), Ok(expected), "mixed `{mixed}`");
        }
    }

    #[test]
    fn provider_from_str_accepts_multiword_and_rebrand_aliases() {
        use core::str::FromStr;

        // The space-separated and hyphenated spellings operators write in
        // config files, plus the current documented brand name for the
        // formerly-Mandrill provider. Verbatim (no trim), case-insensitive.
        let cases = [
            ("hub spot", Provider::HubSpot),
            ("hub-spot", Provider::HubSpot),
            ("HUB SPOT", Provider::HubSpot),
            ("launch darkly", Provider::LaunchDarkly),
            ("launch-darkly", Provider::LaunchDarkly),
            ("lemon-squeezy", Provider::LemonSqueezy),
            ("pager duty", Provider::PagerDuty),
            ("pager-duty", Provider::PagerDuty),
            ("woo commerce", Provider::WooCommerce),
            ("woo-commerce", Provider::WooCommerce),
            ("circle ci", Provider::CircleCi),
            ("circle-ci", Provider::CircleCi),
            ("standard-webhooks", Provider::StandardWebhooks),
            ("svix", Provider::StandardWebhooks),
            ("resend", Provider::StandardWebhooks),
            ("messagebird", Provider::StandardWebhooks),
            ("bird", Provider::StandardWebhooks),
            ("MESSAGEBIRD", Provider::StandardWebhooks),
            ("Bird", Provider::StandardWebhooks),
            ("gitlab", Provider::StandardWebhooks),
            ("GitLab", Provider::StandardWebhooks),
            ("clerk", Provider::StandardWebhooks),
            ("CLERK", Provider::StandardWebhooks),
            ("openai", Provider::StandardWebhooks),
            ("OpenAI", Provider::StandardWebhooks),
            ("OPENAI", Provider::StandardWebhooks),
            ("warp", Provider::StandardWebhooks),
            ("Warp", Provider::StandardWebhooks),
            ("WARP", Provider::StandardWebhooks),
            ("loops", Provider::StandardWebhooks),
            ("Loops", Provider::StandardWebhooks),
            ("LOOPS", Provider::StandardWebhooks),
            ("anthropic", Provider::StandardWebhooks),
            ("Anthropic", Provider::StandardWebhooks),
            ("ANTHROPIC", Provider::StandardWebhooks),
            ("gemini", Provider::StandardWebhooks),
            ("Gemini", Provider::StandardWebhooks),
            ("GEMINI", Provider::StandardWebhooks),
            ("brex", Provider::StandardWebhooks),
            ("Brex", Provider::StandardWebhooks),
            ("BREX", Provider::StandardWebhooks),
            ("bigcommerce", Provider::StandardWebhooks),
            ("BigCommerce", Provider::StandardWebhooks),
            ("BIGCOMMERCE", Provider::StandardWebhooks),
            ("big commerce", Provider::StandardWebhooks),
            ("big-commerce", Provider::StandardWebhooks),
            ("lithic", Provider::StandardWebhooks),
            ("Lithic", Provider::StandardWebhooks),
            ("LITHIC", Provider::StandardWebhooks),
            ("incident.io", Provider::StandardWebhooks),
            ("Incident.io", Provider::StandardWebhooks),
            ("INCIDENT.IO", Provider::StandardWebhooks),
            ("incident", Provider::StandardWebhooks),
            ("Incident", Provider::StandardWebhooks),
            ("INCIDENT", Provider::StandardWebhooks),
            ("supabase", Provider::StandardWebhooks),
            ("Supabase", Provider::StandardWebhooks),
            ("SUPABASE", Provider::StandardWebhooks),
            ("etsy", Provider::StandardWebhooks),
            ("Etsy", Provider::StandardWebhooks),
            ("ETSY", Provider::StandardWebhooks),
            ("sardine", Provider::StandardWebhooks),
            ("Sardine", Provider::StandardWebhooks),
            ("SARDINE", Provider::StandardWebhooks),
            ("dodo", Provider::StandardWebhooks),
            ("Dodo", Provider::StandardWebhooks),
            ("DODO", Provider::StandardWebhooks),
            ("dodopayments", Provider::StandardWebhooks),
            ("DodoPayments", Provider::StandardWebhooks),
            ("DODOPAYMENTS", Provider::StandardWebhooks),
            ("zapier", Provider::StandardWebhooks),
            ("Zapier", Provider::StandardWebhooks),
            ("ZAPIER", Provider::StandardWebhooks),
            ("vanta", Provider::StandardWebhooks),
            ("Vanta", Provider::StandardWebhooks),
            ("VANTA", Provider::StandardWebhooks),
            ("safetykit", Provider::StandardWebhooks),
            ("SafetyKit", Provider::StandardWebhooks),
            ("SAFETYKIT", Provider::StandardWebhooks),
            ("prescience", Provider::StandardWebhooks),
            ("Prescience", Provider::StandardWebhooks),
            ("PRESCIENCE", Provider::StandardWebhooks),
            ("taskrabbit", Provider::StandardWebhooks),
            ("TaskRabbit", Provider::StandardWebhooks),
            ("TASKRABBIT", Provider::StandardWebhooks),
            ("liveblocks", Provider::StandardWebhooks),
            ("Liveblocks", Provider::StandardWebhooks),
            ("LIVEBLOCKS", Provider::StandardWebhooks),
            ("flip", Provider::StandardWebhooks),
            ("Flip", Provider::StandardWebhooks),
            ("FLIP", Provider::StandardWebhooks),
            ("replicate", Provider::StandardWebhooks),
            ("Replicate", Provider::StandardWebhooks),
            ("REPLICATE", Provider::StandardWebhooks),
            ("inai", Provider::StandardWebhooks),
            ("Inai", Provider::StandardWebhooks),
            ("INAI", Provider::StandardWebhooks),
            ("drata", Provider::StandardWebhooks),
            ("Drata", Provider::StandardWebhooks),
            ("DRATA", Provider::StandardWebhooks),
            ("nash", Provider::StandardWebhooks),
            ("Nash", Provider::StandardWebhooks),
            ("NASH", Provider::StandardWebhooks),
            ("render", Provider::StandardWebhooks),
            ("Render", Provider::StandardWebhooks),
            ("RENDER", Provider::StandardWebhooks),
            ("yoco", Provider::StandardWebhooks),
            ("Yoco", Provider::StandardWebhooks),
            ("YOCO", Provider::StandardWebhooks),
            ("novu", Provider::StandardWebhooks),
            ("Novu", Provider::StandardWebhooks),
            ("NOVU", Provider::StandardWebhooks),
            ("crossmint", Provider::StandardWebhooks),
            ("Crossmint", Provider::StandardWebhooks),
            ("CROSSMINT", Provider::StandardWebhooks),
            ("daytona", Provider::StandardWebhooks),
            ("Daytona", Provider::StandardWebhooks),
            ("DAYTONA", Provider::StandardWebhooks),
            ("polar", Provider::StandardWebhooks),
            ("Polar", Provider::StandardWebhooks),
            ("POLAR", Provider::StandardWebhooks),
            ("helcim", Provider::StandardWebhooks),
            ("Helcim", Provider::StandardWebhooks),
            ("HELCIM", Provider::StandardWebhooks),
            ("celitech", Provider::StandardWebhooks),
            ("Celitech", Provider::StandardWebhooks),
            ("CELITECH", Provider::StandardWebhooks),
            ("360learning", Provider::StandardWebhooks),
            ("360Learning", Provider::StandardWebhooks),
            ("360LEARNING", Provider::StandardWebhooks),
            ("natural", Provider::StandardWebhooks),
            ("Natural", Provider::StandardWebhooks),
            ("NATURAL", Provider::StandardWebhooks),
            ("origami", Provider::StandardWebhooks),
            ("Origami", Provider::StandardWebhooks),
            ("ORIGAMI", Provider::StandardWebhooks),
            ("parallel", Provider::StandardWebhooks),
            ("Parallel", Provider::StandardWebhooks),
            ("PARALLEL", Provider::StandardWebhooks),
            ("openlayer", Provider::StandardWebhooks),
            ("Openlayer", Provider::StandardWebhooks),
            ("OPENLAYER", Provider::StandardWebhooks),
            ("acolad", Provider::StandardWebhooks),
            ("Acolad", Provider::StandardWebhooks),
            ("ACOLAD", Provider::StandardWebhooks),
            ("allo", Provider::StandardWebhooks),
            ("Allo", Provider::StandardWebhooks),
            ("ALLO", Provider::StandardWebhooks),
            ("lexe", Provider::StandardWebhooks),
            ("Lexe", Provider::StandardWebhooks),
            ("LEXE", Provider::StandardWebhooks),
            ("twitter", Provider::X),
            ("x twitter", Provider::X),
            ("x-twitter", Provider::X),
            ("mailchimp", Provider::Mandrill),
            ("mailchimp transactional", Provider::Mandrill),
            ("mailchimp-transactional", Provider::Mandrill),
        ];
        for (name, expected) in cases {
            assert_eq!(Provider::from_str(name), Ok(expected), "alias `{name}`");
        }
    }

    #[test]
    fn provider_display_round_trips_through_from_str() {
        for provider in provider_list() {
            assert_eq!(
                provider.to_string().parse::<Provider>(),
                Ok(provider),
                "display string must re-parse to the same provider"
            );
        }
    }

    #[test]
    fn provider_from_str_rejects_unknown_names_and_custom() {
        use core::str::FromStr;

        for bad in [
            "",
            "githubs",
            "stripey",
            "stripe ",
            " stripe",
            "custom",
            "Custom",
            "unknown-provider",
        ] {
            assert_eq!(
                Provider::from_str(bad),
                Err(ProviderParseError),
                "must reject `{bad}`"
            );
        }
    }

    #[test]
    fn provider_parse_error_implements_core_error_in_every_configuration() {
        // Unconditional `core::error::Error` impl, mirroring
        // `VerifyError`'s — see issue #261. Not `#[cfg(feature = "std")]`:
        // the `test-nostd` runs of spec.md §6 are what catch a re-gate.
        fn boxed<E: core::error::Error + 'static>(
            e: E,
        ) -> alloc::boxed::Box<dyn core::error::Error> {
            alloc::boxed::Box::new(e)
        }

        let err = boxed(ProviderParseError);
        assert_eq!(
            err.to_string(),
            ProviderParseError.to_string(),
            "boxing must preserve Display"
        );
    }

    #[test]
    fn provider_parse_error_display_lists_every_provider() {
        // The `ProviderParseError` message hardcodes the provider list; this
        // guard keeps it from drifting out of sync with `FromStr`/`Display`
        // when a provider is added. Every canonical lowercase name must be
        // present so the error actually guides operators back to a parseable
        // value. `Provider::Custom` is intentionally not listed (it cannot be
        // parsed from a bare name), matching the message's own wording.
        let message = ProviderParseError.to_string();
        for provider in provider_list() {
            let name = provider.to_string().to_ascii_lowercase();
            assert!(
                message.contains(&name),
                "error message should list `{name}` so operators can recover"
            );
        }
        // The `FromStr` impl also accepts rebrand/signer aliases (`mailchimp`
        // ↔ Mandrill; `svix`/`resend`/`messagebird`/`bird`/`gitlab`/`clerk`/
        // `openai`/`warp`/`loops`/`anthropic`/`gemini`/`brex`/`bigcommerce`/
        // `lithic`/`incident.io`/`incident`/`supabase`/`etsy`/`sardine`/
        // `dodo`/`dodopayments`/`zapier`/`vanta`/`safetykit`/`prescience`/
        // `taskrabbit`/`liveblocks`/`flip`/`replicate`/`inai`/`drata`/`nash`/`render`/`yoco`/`novu`/`crossmint`/`daytona`/`polar`/`helcim`/`celitech`/`360learning`/`natural`/`origami`/`parallel`/`openlayer`/`acolad`/`allo`/`lexe` ↔ StandardWebhooks); the
        // message names them too so an operator who typed a rejected alias
        // sees it echoed back, instead of only the canonical spellings.
        for alias in [
            "mailchimp",
            "svix",
            "resend",
            "messagebird",
            "bird",
            "gitlab",
            "clerk",
            "openai",
            "warp",
            "loops",
            "anthropic",
            "gemini",
            "brex",
            "bigcommerce",
            "lithic",
            "incident.io",
            "incident",
            "supabase",
            "etsy",
            "sardine",
            "dodo",
            "dodopayments",
            "zapier",
            "vanta",
            "safetykit",
            "prescience",
            "taskrabbit",
            "liveblocks",
            "flip",
            "replicate",
            "inai",
            "drata",
            "nash",
            "render",
            "yoco",
            "novu",
            "crossmint",
            "daytona",
            "polar",
            "helcim",
            "celitech",
            "360learning",
            "natural",
            "origami",
            "parallel",
            "openlayer",
            "acolad",
            "allo",
            "lexe",
        ] {
            assert!(
                message.contains(&format!("`{alias}`")),
                "error message should list the `{alias}` alias so operators can recover"
            );
        }
    }

    #[test]
    fn provider_parse_error_display_lists_every_brand_alias_from_str_accepts() {
        // The alias half of the guard above runs in one direction only: it
        // asserts that a hardcoded list of brand aliases appears in the
        // `Display` string, but nothing asserted the reverse — that every
        // brand alias `from_str` actually accepts reaches that list. Roughly two
        // dozen Standard Webhooks adopter aliases (`svix`, `resend`, `helcim`,
        // `lexe`, …) were appended to `from_str` one at a time across a long
        // series of PRs, each also added to `spec.md` §2 and to the
        // README/crate-doc tables, so the parser and the spec could not drift
        // from each other — but the `Display` string is hand-written prose and
        // nothing tied it to the parser, so an alias that reached `from_str`
        // without a matching line in the message would have shipped silently.
        // The message is the one surface an operator sees when the name in
        // their config is rejected, so it is the wrong place for that to go
        // unnoticed: the whole point of echoing the accepted spellings back is
        // that a typo'd name is recoverable from the error alone.
        //
        // The alias set is read out of this module's own `from_str` source
        // rather than a second test table, so the guard cannot drift from the
        // parser it guards — the same technique
        // `spec_section_two_documents_every_accepted_alias` uses. Two kinds of
        // name are deliberately not required to be named here: the canonical
        // `Display`/`Debug` spellings (owned by the test above, and named in
        // the message's leading list), and the multi-word spellings (`hub
        // spot`, `pager-duty`, `big-commerce`, …), which the message covers
        // once generically by saying that "hyphenated/space-separated
        // multi-word spellings … are also accepted". Requiring each of those
        // individually would only restate that clause.
        let this = include_str!("mod.rs");
        let Some(fn_start) = this.find("fn from_str(name: &str) -> Result<Self, Self::Err>") else {
            panic!("`Provider::from_str` must keep its documented signature");
        };
        let Some(fn_end) = this[fn_start..].find("\n    }\n") else {
            panic!("`Provider::from_str` must close with a `}}` at four-space indent");
        };
        let body = &this[fn_start..fn_start + fn_end];

        let canonical: Vec<String> = provider_list()
            .into_iter()
            .flat_map(|provider| {
                [
                    provider.to_string().to_lowercase(),
                    format!("{provider:?}").to_lowercase(),
                ]
            })
            .collect();

        let message = ProviderParseError.to_string();
        let mut unnamed: Vec<&str> = Vec::new();
        let mut rest = body;
        while let Some(at) = rest.find("eq_ignore_ascii_case(\"") {
            let after = &rest[at + "eq_ignore_ascii_case(\"".len()..];
            let Some(quote) = after.find('"') else {
                panic!("`from_str` match arm must close its quoted name");
            };
            let name = &after[..quote];
            rest = &after[quote + 1..];
            if name.contains(' ') || name.contains('-') {
                continue;
            }
            if canonical.iter().any(|canonical| canonical == name) {
                continue;
            }
            if !message.contains(&format!("`{name}`")) {
                unnamed.push(name);
            }
        }
        unnamed.sort_unstable();
        unnamed.dedup();
        assert!(
            unnamed.is_empty(),
            "`ProviderParseError`'s message must name every brand alias \
             `Provider::from_str` accepts, so an operator who typed one sees it \
             echoed back; accepted but unnamed: {unnamed:?}"
        );
    }

    #[test]
    fn readme_and_crate_docs_provider_tables_cover_every_provider() {
        // The README and crate-doc provider tables (spec.md §3's prose rows,
        // mirrored into `README.md`'s "Supported providers" table and the
        // `lib.rs` crate docs) are hand-maintained. Nothing re-checked them
        // against the `Provider` enum, so both a stale row count and a
        // provider omitted from one table but present in the other shipped
        // silently. This guard pins each table to `provider_list()`: a
        // provider counts as listed when its `Display` brand name appears in
        // that table's first column (optionally with a parenthetical
        // qualifier or a rebrand spelling — e.g. `Mandrill` inside
        // `Mailchimp Transactional (Mandrill)`). `Custom` is listed in both
        // tables but is not in `provider_list()` (it cannot be parsed from a
        // bare name, matching the `FromStr` docs), so its row is asserted
        // separately.
        for (label, markdown) in [
            ("README.md", include_str!("../../README.md")),
            ("crate docs", include_str!("../lib.rs")),
        ] {
            let cells = provider_table_cells(markdown);
            assert_eq!(
                cells.len(),
                provider_list().len() + 1,
                "`{label}` provider table must list every provider plus `Custom`"
            );
            for provider in provider_list() {
                let brand = provider.to_string();
                let hits = cells
                    .iter()
                    .filter(|cell| brand_cell_matches(cell, &brand))
                    .count();
                assert_eq!(
                    hits, 1,
                    "`{label}` table must list `{brand}` exactly once (found {hits})"
                );
            }
            assert!(
                cells.iter().any(|cell| cell == "Custom"),
                "`{label}` provider table must include a row for `Custom`"
            );
            for cell in &cells {
                if cell == "Custom" {
                    continue;
                }
                let hits = provider_list()
                    .iter()
                    .filter(|provider| brand_cell_matches(cell, &provider.to_string()))
                    .count();
                assert!(
                    hits >= 1,
                    "`{label}` table row `{cell}` matches no known provider"
                );
            }
        }
    }

    /// Phrases the provider tables use to say "this provider recency-checks
    /// the timestamp it signs". Matched case-insensitively against the whole
    /// row so a row need not use one canonical wording — `replay window`,
    /// `tolerance window`, and a row that names the timestamp header and calls
    /// the following term a tolerance window all count.
    const REPLAY_WINDOW_PHRASES: &[&str] = &["replay", "tolerance"];

    #[test]
    fn provider_tables_state_replay_protection_where_the_code_enforces_it() {
        // The README and crate-doc provider tables are where a caller goes to
        // learn which providers reject stale deliveries, and both tables are
        // hand-maintained with nothing re-checking that claim against the
        // code. They shipped rows that understate it for exactly the providers
        // whose replay protection is least visible: the three asymmetric
        // (public-key) providers sign a timestamp header like every other
        // timestamped provider and recency-check it through the shared
        // `max_age` window, but their rows were written around the key
        // material and never mentioned the window. Three rows in `README.md`
        // (Discord, PayPal, SendGrid) and six in the crate docs (those three
        // plus Slack, Zoom, and Cloudflare, whose rows named the timestamp
        // but not the tolerance) therefore told a reader that no replay
        // protection applied where one does. `spec.md` §3 states it correctly
        // in every one of those cases, so the drift was confined to the two
        // summary tables — and spec.md §5.4 already requires a tolerance for
        // timestamped schemes, so this is a claim the crate's own normative
        // contract contradicts.
        //
        // Both directions are checked, and the reverse one is the load-bearing
        // half: a provider that calls `check_replay` must have its row say so
        // (the shipped bug), *and* a row that says so must belong to a
        // provider that calls it. Without the second check the first could be
        // silenced by appending "replay window" to all 59 rows.
        for (label, markdown) in [
            ("README.md", include_str!("../../README.md")),
            ("crate docs", include_str!("../lib.rs")),
        ] {
            let rows = provider_table_rows(markdown);
            assert_eq!(
                rows.len(),
                provider_list().len() + 1,
                "`{label}` provider table must list every provider plus `Custom`"
            );
            for (cell, row) in &rows {
                let lowered = row.to_lowercase();
                let claims = REPLAY_WINDOW_PHRASES
                    .iter()
                    .any(|phrase| lowered.contains(phrase));
                if cell == "Custom" {
                    assert!(
                        claims,
                        "`{label}` row for `Custom` must state that replay protection \
                         applies when a `timestamp_header` is configured, which is \
                         what `Provider::Custom`'s implementation does"
                    );
                    continue;
                }
                let provider = provider_list()
                    .into_iter()
                    .find(|provider| brand_cell_matches(cell, &provider.to_string()))
                    .unwrap_or_else(|| {
                        panic!("`{label}` table row `{cell}` matches no known provider")
                    });
                let enforces = provider_replay_protected(&provider);
                assert_eq!(
                    claims,
                    enforces,
                    "`{label}` table row `{cell}` and the code disagree about replay \
                     protection: the row {}, and the implementation of `{provider}` {}",
                    if claims {
                        "claims a replay window"
                    } else {
                        "does not claim a replay window"
                    },
                    if enforces {
                        "recency-checks the signed timestamp through the shared \
                         `max_age` window (`check_replay`)"
                    } else {
                        "signs the timestamp without recency-checking it"
                    }
                );
            }
        }
    }

    #[test]
    fn spec_two_provider_enum_sketch_matches_declaration_order() {
        // The `spec.md` §2 `pub enum Provider { ... }` sketch is a hand-written
        // mirror of the shipped enum's variant list in declaration order, and
        // it has drifted twice — Fintoc/Ripple/X shipped without their sketch
        // lines (CHANGELOG), and Webflow did too (PRs #142/#158, each needing
        // a follow-up doc PR to catch up). The README/crate-doc guards above
        // pin the "Supported providers" tables; this guard pins the §2 sketch
        // itself to `provider_list()`, so a variant added, reordered, or
        // renamed in the sketch fails CI instead of being chased later.
        // `Provider`'s `Debug` prints the exact variant identifier (`Line`,
        // `CircleCi`, `LemonSqueezy`, `X`, `StandardWebhooks` — the spelling
        // the sketch uses, no Display-name normalization needed).
        let spec = include_str!("../../spec.md");
        let lines = spec
            .lines()
            .skip_while(|line| !line.contains("pub enum Provider {"));
        let sketch: Vec<&str> = lines
            .skip(1)
            .take_while(|line| line.trim_end() != "}")
            .map(|line| {
                let name = line.trim();
                let end = name.find('(').unwrap_or(name.len());
                name[..end].trim_end_matches(',')
            })
            .collect();
        assert_eq!(
            sketch.len(),
            provider_list().len() + 1,
            "spec.md §2 `Provider` enum sketch must list every variant plus `Custom`"
        );
        for (i, provider) in provider_list().iter().enumerate() {
            let sketch_ident = sketch.get(i).copied().unwrap_or("");
            let provider_ident = format!("{provider:?}");
            assert_eq!(
                sketch_ident,
                provider_ident.as_str(),
                "spec.md §2 sketch entry {i} must be `{provider_ident}` (the enum variant, in declaration order)"
            );
        }
        assert_eq!(
            sketch.last().copied().unwrap_or(""),
            "Custom",
            "spec.md §2 sketch must end with `Custom(CustomScheme)`"
        );
    }

    #[test]
    fn spec_section_two_documents_every_accepted_alias() {
        // `spec.md` §2 documents the spellings `Provider::from_str` accepts
        // ("Case-insensitive match on the canonical Display name of each
        // variant … plus the space-separated and hyphenated human-readable
        // forms … Brand aliases are also accepted: …"). The canonical
        // spellings are covered by that prose, but every *alias* has to be
        // named literally, and the list had drifted: the Standard Webhooks
        // adopters Helcim, CELITECH, 360Learning, Natural, Origami, Parallel,
        // Openlayer, Acolad, Allo, and Lexe all shipped as accepted aliases
        // (and as §3 adopter entries) without ever being added to the §2 list,
        // so the normative contract silently under-described the parser.
        // `AGENTS.md` §6 requires spec.md and the code not to drift, and every
        // other hand-maintained doc surface here (the §2 enum sketch, the
        // README/crate-doc tables, the fuzz pool) already has a guard — this
        // pins the last one.
        //
        // The alias set is read out of this module's own `from_str` source
        // rather than duplicated in a test table, so the guard cannot drift
        // from the parser it guards. The spellings that are *canonical*
        // rather than aliases are excluded by construction — every `Display`
        // name (`"Lemon Squeezy"`) and every variant identifier
        // (`LemonSqueezy`, `StandardWebhooks`), which is what §2's
        // "case-insensitive match on the canonical Display name" prose
        // already covers. Anything else the match arms accept is an alias and
        // must appear as a quoted string in §2.
        let spec = include_str!("../../spec.md");
        let Some(start) = spec.find("impl core::str::FromStr for Provider") else {
            panic!("spec.md §2 must keep its `FromStr` sketch");
        };
        let Some(end) = spec[start..].find("pub trait HeaderMap") else {
            panic!("spec.md §2 `FromStr` sketch must precede `pub trait HeaderMap`");
        };
        let section = &spec[start..start + end];

        let this = include_str!("mod.rs");
        let Some(fn_start) = this.find("fn from_str(name: &str) -> Result<Self, Self::Err>") else {
            panic!("`Provider::from_str` must keep its documented signature");
        };
        let Some(fn_end) = this[fn_start..].find("\n    }\n") else {
            panic!("`Provider::from_str` must close with a `}}` at four-space indent");
        };
        let body = &this[fn_start..fn_start + fn_end];

        let mut canonical: Vec<String> = Vec::new();
        for provider in provider_list() {
            canonical.push(provider.to_string().to_lowercase());
            canonical.push(format!("{provider:?}").to_lowercase());
        }

        let mut undocumented: Vec<&str> = Vec::new();
        let mut rest = body;
        while let Some(at) = rest.find("eq_ignore_ascii_case(\"") {
            let after = &rest[at + "eq_ignore_ascii_case(\"".len()..];
            let Some(quote) = after.find('"') else {
                panic!("`from_str` match arm must close its quoted name");
            };
            let name = &after[..quote];
            rest = &after[quote + 1..];
            if canonical.iter().any(|canonical| canonical == name) {
                continue;
            }
            if !section.contains(&format!("\"{name}\"")) {
                undocumented.push(name);
            }
        }
        undocumented.sort_unstable();
        undocumented.dedup();
        assert!(
            undocumented.is_empty(),
            "spec.md §2 must name every alias `Provider::from_str` accepts; \
             undocumented: {undocumented:?}"
        );

        // The check above runs in one direction only — every accepted spelling
        // must be named — and that is what let a claim about a variant that
        // does not ship survive: §2 listed `"big commerce"/"big-commerce" →
        // BigCommerce` in the multi-word-variant parenthetical, but there is no
        // `Provider::BigCommerce`; those spellings are Standard Webhooks
        // *adopter* aliases and resolve to `Provider::StandardWebhooks`
        // (issue #239). The two quoted spellings were present, so the
        // one-directional guard passed. Close the other direction: every `→ X`
        // in this sketch must name a variant that actually exists, so an
        // adopter brand can never again be documented as though it were its
        // own scheme.
        let mut phantom_variants: Vec<String> = Vec::new();
        let mut cursor = 0usize;
        while let Some(found) = section[cursor..].find('→') {
            let arrow = cursor + found;
            cursor = arrow + '→'.len_utf8();
            let name: String = section[cursor..]
                .trim_start()
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect();
            if name.is_empty() {
                continue;
            }
            let exists = provider_list()
                .iter()
                .any(|provider| format!("{provider:?}") == name);
            if !exists {
                // Report the whole line the arrow sits on, so the failure names
                // the claim rather than an unrelated offset.
                let line_start = section[..arrow].rfind('\n').map_or(0, |at| at + 1);
                let line = section[line_start..]
                    .split('\n')
                    .next()
                    .unwrap_or("")
                    .trim();
                phantom_variants.push(line.to_string());
            }
        }
        phantom_variants.sort_unstable();
        phantom_variants.dedup();
        assert!(
            phantom_variants.is_empty(),
            "every `→ Variant` claim in spec.md §2's `FromStr` sketch must name a \
             variant that ships; claims about variants that do not exist: \
             {phantom_variants:?}"
        );
    }

    /// Whether `clause` names `provider` as a word of its own — in the variant
    /// ident or the `Display` brand — rather than as a substring of a longer
    /// word (`except` must not count as a mention of `Provider::X`).
    fn clause_names(clause: &str, provider: &Provider) -> bool {
        for needle in [format!("{provider:?}"), provider.to_string()] {
            let mut from = 0usize;
            while let Some(found) = clause[from..].find(needle.as_str()) {
                let at = from + found;
                let before = clause[..at].chars().next_back();
                let after = clause[at + needle.len()..].chars().next();
                let on_a_boundary = match (before, after) {
                    (None, None) => true,
                    (None, Some(after)) => !after.is_alphanumeric(),
                    (Some(before), None) => !before.is_alphanumeric(),
                    (Some(before), Some(after)) => {
                        !before.is_alphanumeric() && !after.is_alphanumeric()
                    }
                };
                if on_a_boundary {
                    return true;
                }
                from = at + needle.len();
            }
        }
        false
    }

    /// The word immediately before byte `at` in `text`, with punctuation
    /// stripped from both ends (`"… the only asymmetric"` → `only`).
    fn word_before(text: &str, at: usize) -> &str {
        let trimmed = text[..at].trim_end_matches(|c: char| !c.is_alphanumeric());
        let start = trimmed
            .char_indices()
            .rev()
            .find(|(_, c)| !c.is_alphanumeric())
            .map_or(0, |(index, c)| index + c.len_utf8());
        &trimmed[start..]
    }

    #[test]
    fn spec_section_four_scopes_the_secret_exemption_by_who_ignores_secret() {
        // `spec.md` §4.7's item 7 scopes the entry-point empty/whitespace/NUL
        // secret rule by naming the providers exempt from it, and it used to
        // name them as "the two asymmetric schemes, PayPal and SendGrid" — a
        // count that went stale the moment PayPal and SendGrid shipped, while
        // §4.8 of the same document still called Discord "the only
        // asymmetric-scheme provider". Discord *is* asymmetric and is *not*
        // exempt: its Ed25519 verifying key travels in `Secret`, so the check
        // reaches it like any HMAC key. The criterion is `uses_secret`, not the
        // crypto, so this pins the clause to `uses_secret` in both directions
        // and keeps it from being re-scoped by a count that a fourth
        // public-key scheme would invalidate.
        let spec = include_str!("../../spec.md");
        let section_start = match spec.find("## 4. Security requirements (non-negotiable)") {
            Some(at) => at,
            None => panic!("spec.md must keep its `## 4. Security requirements` heading"),
        };
        let section = match spec[section_start..].find("\n## ") {
            Some(offset) => &spec[section_start..section_start + offset],
            None => &spec[section_start..],
        };
        // Whitespace-flattened, so a guard's anchors are stable against the
        // prose being re-flowed to a different line width.
        let flat = section.split_whitespace().collect::<Vec<_>>().join(" ");

        const CLAUSE_START: &str = "every provider except";
        const CLAUSE_END: &str = "which ignore `Secret`";
        let clause_start = match flat.find(CLAUSE_START) {
            Some(at) => at + CLAUSE_START.len(),
            None => panic!(
                "spec.md §4.7 must scope the empty/whitespace/NUL-secret rule with \
                 `{CLAUSE_START} … {CLAUSE_END} …` so this guard can find the \
                 exemption clause"
            ),
        };
        let after_start = &flat[clause_start..];
        let clause_end = match after_start.find(CLAUSE_END) {
            Some(at) => at,
            None => panic!(
                "spec.md §4.7 must end its exemption clause with `{CLAUSE_END}` so \
                 this guard can find it"
            ),
        };
        let clause = after_start[..clause_end].trim();

        let mut named: Vec<String> = provider_list()
            .iter()
            .filter(|provider| clause_names(clause, provider))
            .map(|provider| format!("{provider:?}"))
            .collect();
        let mut exempt: Vec<String> = provider_list()
            .iter()
            .filter(|provider| !uses_secret(**provider))
            .map(|provider| format!("{provider:?}"))
            .collect();
        named.sort_unstable();
        exempt.sort_unstable();
        assert_eq!(
            named, exempt,
            "spec.md §4.7's exemption clause (`{clause}`) must name exactly the \
             providers `uses_secret` excludes — the ones that ignore `Secret` — \
             spelled with their variant names, so a third one cannot ship in \
             silence"
        );
        assert!(
            !clause.contains("asymmetric"),
            "spec.md §4.7's exemption clause (`{clause}`) must scope the rule by \
             who ignores `Secret`, not by the scheme being asymmetric: Discord is \
             asymmetric and is *not* exempt (its verifying key travels in \
             `Secret`)"
        );

        // The same document paired §4.7's count of two with §4.8's claim that
        // Discord was the only asymmetric-scheme provider, and both were wrong
        // for the same reason: a count of public-key schemes goes stale the
        // next time one ships. No sentence in the spec may scope that set by a
        // count; scope by who ignores `Secret`, which `uses_secret` pins above.
        const COUNT_WORDS: &[&str] = &[
            "only", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
            "both", "all", "each", "every",
        ];
        for (at, _) in spec.match_indices("asymmetric") {
            let word = word_before(spec, at);
            assert!(
                !COUNT_WORDS.contains(&word),
                "spec.md scopes the crate's asymmetric schemes by a count (`… {word} \
                 asymmetric …`, byte {at}); scope the claims that matter by who \
                 ignores `Secret` instead, so a newly shipped public-key scheme \
                 cannot leave the sentence wrong"
            );
        }
    }

    /// The text of `spec.md` §3, the per-provider signing-scheme section.
    ///
    /// The section is delimited by its own `## ` heading and the next top-level
    /// `## ` heading, so a guard that only needs the section's prose does not
    /// have to attribute its `### ` entries to providers — which is what
    /// [`spec_section_three_entries`] exists for, and which is gated behind the
    /// adapters because its caller checks `signature_header_names`. Ungated, so
    /// a guard that scans §3 as one blob runs in every feature configuration
    /// rather than only the adapter ones; the `panic!` names the section marker
    /// this depends on.
    fn spec_section_three(spec: &str) -> &str {
        let start = match spec.find("## 3. Per-provider signing schemes") {
            Some(start) => start,
            None => panic!("spec.md must keep its `## 3. Per-provider signing schemes` heading"),
        };
        let end = spec[start..]
            .find("\n## ")
            .map_or(spec.len(), |at| start + at);
        &spec[start..end]
    }

    /// One `spec.md` §3 entry: its `### ` heading, the provider brand it
    /// documents (`None` when the heading names no single provider), and its
    /// body.
    #[cfg(any(feature = "tower", feature = "actix"))]
    struct SpecEntry {
        heading: String,
        owner: Option<String>,
        body: String,
    }

    /// Parses §3's `### ` entries and attributes each to the provider it
    /// documents.
    ///
    /// The section is delimited by [`spec_section_three`], so the guard reads
    /// only the provider entries and not §2 or §4. An entry's body runs from
    /// its heading to the next `### ` (or the end of §3). Attribution uses the
    /// same `Display`-brand matching as the README/crate-doc table guard, so a
    /// heading may qualify the brand (`Tally (form webhooks)`, `X (formerly
    /// Twitter)`, `Standard Webhooks spec`, `Mailchimp Transactional
    /// (Mandrill)`) but must not name two providers or none. Test helper over
    /// compile-time `include_str!` data.
    #[cfg(any(feature = "tower", feature = "actix"))]
    fn spec_section_three_entries(spec: &str) -> Vec<SpecEntry> {
        let mut entries: Vec<SpecEntry> = Vec::new();
        let mut pending: Option<String> = None;
        let mut body = String::new();
        for line in spec_section_three(spec).lines() {
            if let Some(heading) = line.strip_prefix("### ") {
                if let Some(previous) = pending.take() {
                    entries.push(spec_entry(previous, core::mem::take(&mut body)));
                }
                pending = Some(heading.trim().to_string());
            } else if pending.is_some() {
                body.push_str(line);
                body.push('\n');
            }
        }
        if let Some(previous) = pending {
            entries.push(spec_entry(previous, body));
        }
        entries
    }

    /// Attributes one §3 entry to the provider whose `Display` brand its
    /// heading names, or to none when the match is not unique.
    #[cfg(any(feature = "tower", feature = "actix"))]
    fn spec_entry(heading: String, body: String) -> SpecEntry {
        let mut owners = provider_list()
            .iter()
            .map(|provider| provider.to_string())
            .filter(|brand| brand_cell_matches(&heading, brand))
            .collect::<Vec<_>>();
        let owner = if owners.len() == 1 {
            Some(owners.remove(0))
        } else {
            None
        };
        SpecEntry {
            heading,
            owner,
            body,
        }
    }

    #[cfg(any(feature = "tower", feature = "actix"))]
    #[test]
    fn spec_section_three_documents_every_signature_header() {
        // §3 is the one hand-maintained doc surface in this crate with no drift
        // guard: the §2 enum sketch, the §2 alias list, the README/crate-doc
        // provider tables, the fuzz `IMPLEMENTED` pool, and
        // `signature_header_names`' own coverage are all pinned, but nothing
        // checked §3. The failure mode is concrete. A provider can ship with a
        // §3 entry that omits a header its implementation reads, and the
        // normative contract then under-describes the wire format — the reason
        // `AGENTS.md` §4.2 asks for the spec entry *before* the implementation
        // and §6 for the two not to drift. A *renamed or added* header constant
        // is the sharper case: the adapters' §4.4 ambiguity scan is built from
        // `signature_header_names`, so a header §3 does not name is a header a
        // reader of the spec would not know to check for conflicting duplicates.
        //
        // The header set is read from `signature_header_names` — the same
        // canonical list the adapters scan — rather than from a duplicated test
        // table, so the guard cannot drift from the code it guards, and
        // feature-disabled providers contribute an empty list and are checked
        // for entry coverage only.
        let entries = spec_section_three_entries(include_str!("../../spec.md"));
        assert_eq!(
            entries.len(),
            provider_list().len(),
            "spec.md §3 must have exactly one entry per provider"
        );

        for entry in &entries {
            assert!(
                entry.owner.is_some(),
                "spec.md §3 entry `{}` must name exactly one provider's brand",
                entry.heading,
            );
        }

        for provider in provider_list() {
            let brand = provider.to_string();
            let entry = entries
                .iter()
                .find(|entry| entry.owner.as_deref() == Some(brand.as_str()))
                .unwrap_or_else(|| panic!("spec.md §3 must have an entry documenting `{brand}`"));
            for header in signature_header_names(&provider) {
                assert!(
                    entry.body.contains(header),
                    "spec.md §3 entry `{brand}` must name the `{header}` header its \
                     implementation reads (spec.md is the normative per-provider contract, \
                     and the framework adapters scan it for conflicting duplicates per §4.4)"
                );
            }
        }
    }

    /// Box's `- Headers:` bullet is the one place in the repo where a
    /// provider's *reason for requiring* a header is spelled out as a security
    /// property, and the two copies of it — the normative `spec.md` §3 entry
    /// and `box_webhooks.rs`'s module doc — had drifted into making different
    /// claims. `spec.md` named the attacker who holds one of Box's two keys;
    /// the module doc named one who holds neither, which is vacuous (an
    /// attacker with neither key cannot forge a signature at all, with or
    /// without the requirement) and so understated the property that
    /// requirement actually buys.
    ///
    /// Pinned on the threat model rather than on the surrounding prose, which
    /// the two documents legitimately word differently. Both must name the
    /// single-key attacker; neither may name the vacuous one.
    #[test]
    fn box_both_headers_required_names_the_single_key_attacker_in_both_copies() {
        let spec = include_str!("../../spec.md");
        let start = spec.find("### Box").unwrap_or_else(|| {
            panic!("spec.md §3 must keep a `### Box` heading naming Box's entry")
        });
        let spec_entry = &spec[start..];
        let spec_entry = spec_entry
            .split_once("\n### ")
            .map_or(spec_entry, |(entry, _)| entry);
        let module = module_doc("box_webhooks");

        for (label, text) in [
            ("spec.md §3's Box entry", spec_entry),
            ("box_webhooks.rs's module doc", &module),
        ] {
            assert!(
                text.contains("knows only one key") || text.contains("one of Box's two keys"),
                "{label} must name the attacker who holds one of Box's two signing keys but not \
                 the key the caller holds — that is the threat model requiring both signature \
                 headers actually defends against"
            );
            assert!(
                !text.contains("neither key"),
                "{label} says an attacker who knows neither key is stopped by requiring both \
                 headers, which is vacuous: with neither key there is no signature to forge, \
                 with or without the requirement"
            );
        }
    }

    /// The header a provider's signature is actually **read from** — the
    /// subset of the §4.4 ambiguity list that a caller has to look up.
    ///
    /// Spelled out per provider rather than derived from
    /// [`signature_header_names`] (whose first entry is *not* always the
    /// signature: Twitch's list leads with the message id, and PayPal's and
    /// SendGrid's are feature-gated) for two reasons. It must run in every
    /// feature configuration, because the two tables it checks are
    /// unconditional documentation, whereas `signature_header_names` only
    /// exists behind `http`/`tower`/`actix`. And "first entry" is the wrong
    /// question anyway — it asks where a *duplicate-detection scan* happens to
    /// start, not where the signature is.
    ///
    /// Every constant referenced is the provider module's own, so a renamed
    /// header fails this guard instead of leaving a stale literal in a table.
    /// `None` for `Custom`, whose header is caller-declared and named by the
    /// row's own text.
    fn primary_signature_header(provider: &Provider) -> Option<&'static str> {
        Some(match provider {
            Provider::Adyen => adyen::SIGNATURE_HEADER,
            Provider::Airwallex => airwallex::SIGNATURE_HEADER,
            Provider::Bitbucket => bitbucket::SIGNATURE_HEADER,
            Provider::Box => box_webhooks::PRIMARY_SIGNATURE_HEADER,
            Provider::Calendly => calendly::SIGNATURE_HEADER,
            Provider::CircleCi => circleci::SIGNATURE_HEADER,
            Provider::Cloudflare => cloudflare::SIGNATURE_HEADER,
            Provider::Coinbase => coinbase::SIGNATURE_HEADER,
            Provider::Contentful => contentful::SIGNATURE_HEADER,
            Provider::Custom(_) => return None,
            Provider::Discord => discord::SIGNATURE_HEADER,
            Provider::DocuSign => docusign::SIGNATURE_HEADER,
            Provider::Dropbox => dropbox::SIGNATURE_HEADER,
            Provider::Expo => expo::SIGNATURE_HEADER,
            Provider::FastSpring => fastspring::SIGNATURE_HEADER,
            Provider::Fintoc => fintoc::SIGNATURE_HEADER,
            Provider::GitHub => github::SIGNATURE_HEADER,
            Provider::GoCardless => gocardless::SIGNATURE_HEADER,
            Provider::HubSpot => hubspot::SIGNATURE_HEADER,
            Provider::Intercom => intercom::SIGNATURE_HEADER,
            Provider::Klaviyo => klaviyo::SIGNATURE_HEADER,
            Provider::LaunchDarkly => launchdarkly::SIGNATURE_HEADER,
            Provider::LemonSqueezy => lemonsqueezy::SIGNATURE_HEADER,
            Provider::Line => line::SIGNATURE_HEADER,
            Provider::Linear => linear::SIGNATURE_HEADER,
            Provider::Mandrill => mandrill::SIGNATURE_HEADER,
            Provider::Meta => meta::SIGNATURE_HEADER,
            Provider::Mollie => mollie::SIGNATURE_HEADER,
            Provider::Mux => mux::SIGNATURE_HEADER,
            Provider::Notion => notion::SIGNATURE_HEADER,
            Provider::Nylas => nylas::SIGNATURE_HEADER,
            Provider::Paddle => paddle::SIGNATURE_HEADER,
            Provider::PagerDuty => pagerduty::SIGNATURE_HEADER,
            // Unconditional: the header name is a documented constant of the
            // scheme and is documented in the table whether or not the
            // `paypal`/`sendgrid` features are compiled in — the row notes the
            // feature separately.
            Provider::PayPal => "PayPal-Transmission-Sig",
            Provider::Paystack => paystack::SIGNATURE_HEADER,
            Provider::Pusher => pusher::SIGNATURE_HEADER,
            Provider::Razorpay => razorpay::SIGNATURE_HEADER,
            Provider::Recharge => recharge::SIGNATURE_HEADER,
            Provider::Ripple => ripple::SIGNATURE_HEADER,
            Provider::SendGrid => "X-Twilio-Email-Event-Webhook-Signature",
            Provider::Sentry => sentry::SIGNATURE_HEADER,
            Provider::Shopify => shopify::SIGNATURE_HEADER,
            Provider::Slack => slack::SIGNATURE_HEADER,
            Provider::Square => square::SIGNATURE_HEADER,
            // The Svix spelling is the documented alternative of the same field,
            // so the standard name alone satisfies the row.
            Provider::StandardWebhooks => standard_webhooks::SIGNATURE_HEADER,
            Provider::Stripe => stripe::SIGNATURE_HEADER,
            Provider::Tailscale => tailscale::SIGNATURE_HEADER,
            Provider::Tally => tally::SIGNATURE_HEADER,
            Provider::Twitch => twitch::SIGNATURE_HEADER,
            Provider::Twilio => twilio::SIGNATURE_HEADER,
            Provider::Typeform => typeform::SIGNATURE_HEADER,
            Provider::Vercel => vercel::SIGNATURE_HEADER,
            Provider::Webflow => webflow::SIGNATURE_HEADER,
            Provider::WorkOS => workos::SIGNATURE_HEADER,
            Provider::WooCommerce => woocommerce::SIGNATURE_HEADER,
            Provider::X => x_twitter::SIGNATURE_HEADER,
            Provider::Xero => xero::SIGNATURE_HEADER,
            Provider::Zendesk => zendesk::SIGNATURE_HEADER,
            Provider::Zoom => zoom::SIGNATURE_HEADER,
        })
    }

    #[test]
    fn provider_tables_name_the_header_the_signature_is_read_from() {
        // The two summary tables already have two drift guards — one for
        // coverage, one for the replay claim — but nothing checked the thing a
        // caller opens the table to learn: *which header carries the
        // signature*. `spec.md` §3 pins that for the spec; these tables did not,
        // and the rows drifted. They failed in the worst possible direction,
        // naming a *companion* header while omitting the signature one, so a
        // reader scanning for the signature found something else:
        //
        //   * `Stripe` named no header at all — in the table's most prominent
        //     row, leaving a reader no way to find the signature.
        //   * `Discord` named `X-Signature-Timestamp` and not
        //     `X-Signature-Ed25519`, which is worse than naming nothing: the
        //     two differ by one suffix, and reading the row as written
        //     suggests a shared-secret HMAC over a timestamp, obscuring the
        //     fact that the scheme is asymmetric and keyless.
        //   * `PayPal` and `SendGrid` had the same shape (the RFC 3339 /
        //     unix-seconds timestamp in place of the signature header).
        //   * The crate-doc table additionally dropped `X-Slack-Signature`
        //     and `x-zm-signature` for their timestamp companions, so the two
        //     tables disagreed about the same provider.
        //
        // Only the signature header is required, not every name in the §4.4
        // ambiguity list: several rows legitimately describe companion headers
        // loosely ("+ timestamp + replay window"), and requiring all 85 names
        // across 59 rows would make them unreadable. `spec.md` §3 remains the
        // surface that enumerates every header (and is pinned to do so by
        // `spec_section_three_documents_every_signature_header`); the value here
        // is only that a reader can find the signature header.
        for (label, markdown) in [
            ("README.md", include_str!("../../README.md")),
            ("crate docs", include_str!("../lib.rs")),
        ] {
            let rows = provider_table_rows(markdown);
            for (cell, row) in &rows {
                if cell == "Custom" {
                    continue;
                }
                let provider = provider_list()
                    .iter()
                    .find(|provider| brand_cell_matches(cell, &provider.to_string()))
                    .copied();
                let provider = provider.unwrap_or_else(|| {
                    panic!("`{label}` table row `{cell}` matches no known provider")
                });
                let Some(header) = primary_signature_header(&provider) else {
                    continue;
                };
                assert!(
                    row.contains(header),
                    "`{label}` table row `{cell}` must name the `{header}` header its \
                     signature is read from; a reader opening the table to configure \
                     an endpoint cannot otherwise tell which header carries the \
                     signature (companion headers such as timestamps are not a \
                     substitute)"
                );
            }
        }
    }

    /// Every row of both "Supported providers" tables must render to the same
    /// number of cells as its own header row.
    ///
    /// The other two table guards here check what a row *says* (that it names
    /// the signature header, that its replay claim matches the code). Neither
    /// can see a row that is structurally broken, and the most natural way to
    /// break one of these tables is to quote a construction containing a `|` —
    /// PayPal's signed string is
    /// `{transmission_id}|{transmission_time}|{webhook_id}|{crc32}`, three of
    /// them. Unescaped, GFM splits the row on each: the scheme cell renders
    /// truncated after the first element, the remainder spills into phantom
    /// columns, and the `Status` cell is lost. Nothing in the tree failed,
    /// because `README.md` is prose as far as `cargo` is concerned and the
    /// three existing guards all match on the *first* cell, which the
    /// truncation leaves intact. Hence a check on the cell count, driven off
    /// each table's own header so it holds for both shapes present today
    /// (`README.md` has a `Status` column, the crate docs do not).
    #[test]
    fn provider_table_rows_are_not_split_by_unescaped_pipes() {
        for (label, markdown) in [
            ("README.md", include_str!("../../README.md")),
            ("crate docs", include_str!("../lib.rs")),
        ] {
            let rows = provider_table_row_cell_counts(markdown);
            // A vacuity floor: the header plus a body row, and at least the
            // two columns the tables have always had. A guard that found
            // nothing would assert everything trivially, so a change to the
            // section heading has to fail loudly rather than pass vacuously.
            assert!(
                rows.len() > 1,
                "`{label}` must still contain a '## Supported providers' table; \
                 found {} row(s) — if the heading moved, update the lookup in \
                 `provider_table_rows`/`provider_table_row_cell_counts` rather \
                 than deleting this guard",
                rows.len()
            );

            let (header, expected) = &rows[0];
            assert!(
                *expected >= 2,
                "`{label}`'s provider table header `{header}` renders to {expected} \
                 cell(s), so the table has no body column to lose"
            );

            for (row, cells) in &rows[1..] {
                assert_eq!(
                    cells, expected,
                    "`{label}`'s provider table row renders to {cells} cells but its \
                     header declares {expected}. A literal `|` in a cell's content \
                     splits the row (GFM splits on every unescaped pipe, inside a \
                     code span too) and silently truncates the row's text — write \
                     it `\\|`, which renders as a bare `|`: {row}"
                );
            }
        }
    }

    /// The doc block on every `Provider` enum variant, as `(variant
    /// identifier, doc text)`, in declaration order.
    ///
    /// Read out of this module's own source so the guard cannot check a
    /// variant that no longer exists, and so a doc comment is checked where it
    /// is written rather than through a second copy of it. Only the `pub enum
    /// Provider { … }` block is walked: doc lines accumulate until the variant
    /// declaration they document, which is what lets a doc be any number of
    /// lines long.
    fn provider_variant_docs(this: &str) -> Vec<(String, String)> {
        let mut variants = Vec::new();
        let mut doc: Vec<&str> = Vec::new();
        let mut in_enum = false;
        for line in this.lines() {
            if !in_enum {
                in_enum = line.trim_end() == "pub enum Provider {";
                continue;
            }
            let line = line.trim();
            if line == "}" {
                break;
            }
            if let Some(text) = line.strip_prefix("///") {
                doc.push(text.trim());
                continue;
            }
            // A blank line or an attribute carries no doc text, so it belongs
            // to neither the variant above nor the one below it.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // `Name,` or `Name(Scheme),`; the payload of a tuple variant is
            // not part of the identifier the guards key on.
            let name = line
                .split_once('(')
                .map_or(line, |(name, _)| name)
                .trim_end_matches(',');
            variants.push((String::from(name), doc.join(" ")));
            doc.clear();
        }
        assert!(
            in_enum,
            "this module must keep its `pub enum Provider` declaration for the guards below"
        );
        variants
    }

    /// `Provider::{ident}`'s doc text, panicking when the enum no longer
    /// declares that variant — the shape every other guard in this module
    /// already assumes of `provider_list()`.
    fn provider_variant_doc(ident: &str) -> String {
        let variants = provider_variant_docs(include_str!("mod.rs"));
        let Some((_, doc)) = variants.iter().find(|(name, _)| name == ident) else {
            panic!("`Provider::{ident}` must be declared in this module's enum");
        };
        doc.clone()
    }

    /// Every header in `declared` that `doc` spells with different casing,
    /// phrased for the failure message, plus the number of backticked header
    /// names `doc` spells exactly as the code declares them.
    ///
    /// Split out over caller-supplied text so the extraction can be exercised
    /// over a synthetic doc as well as the real ones — the caller-supplied
    /// shape is what keeps the real run from passing vacuously, since a parser
    /// that stopped extracting spans would report nothing for any provider.
    fn header_spelling_offenders(doc: &str, declared: &[&str]) -> (usize, Vec<String>) {
        let mut exact = 0;
        let mut offenders = Vec::new();
        // Odd-indexed chunks are the text *between* backticks, i.e. the code
        // spans a reader copies a header name out of.
        for span in doc.split('`').skip(1).step_by(2) {
            for header in declared {
                if span == *header {
                    exact += 1;
                } else if span.eq_ignore_ascii_case(header) {
                    offenders.push(format!(
                        "`{span}` where the implementation declares `{header}`"
                    ));
                }
            }
        }
        (exact, offenders)
    }

    /// The `//` run directly above the vacuity-floor assertion in
    /// `provider_variant_docs_spell_their_own_headers_the_way_the_code_does`,
    /// as joined comment text. `None` when the assertion, or a comment above
    /// it, is not there to be read.
    ///
    /// The region is located from the assertion rather than from the claim's
    /// wording on purpose: reading the whole file would find this guard's own
    /// synthetic comments — or, if the real one is deleted, *only* those — and
    /// report a count that still verifies, which is the vacuous pass this guard
    /// exists to prevent. The needle carries a leading newline for the same
    /// reason `line_test_vector_provenance_comment`'s does: so this helper's
    /// own copy of it cannot be the thing that matches.
    fn vacuity_floor_comment(source: &str) -> Option<String> {
        const NEEDLE: &str = "\n            named * 2 >= provider_list().len(),";
        let before_assertion = &source[..source.find(NEEDLE)?];

        // Walk back over the contiguous comment run directly above the
        // assertion. `str::Lines` is not a `DoubleEndedIterator` under `core`,
        // so the scan is over a collected, index-addressable list.
        let mut lines: Vec<&str> = before_assertion.lines().collect();
        // The needle starts at the newline that ends the `assert!(` line, so
        // that line arrives unterminated. It is the start of the assertion
        // rather than part of the run, and leaving it in would stop the walk
        // below before it read anything.
        if let Some(last) = lines.last() {
            if !last.trim_start().starts_with("//") {
                lines.pop();
            }
        }
        let mut start = None;
        for index in (0..lines.len()).rev() {
            let trimmed = lines[index].trim();
            if trimmed.starts_with("//") {
                start = Some(index);
            } else if !trimmed.is_empty() {
                break;
            }
        }
        let start = start?;
        Some(
            lines[start..]
                .iter()
                // Drop the `//` marker so a reported claim reads as prose, not
                // as source lines glued together.
                .map(|line| line.trim().trim_start_matches("//").trim())
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    /// The `N` out of `M` count in a vacuity-floor comment, as `(N, M)`.
    /// `None` when the comment does not state one.
    ///
    /// A missing or unreadable sentence is a failure the caller must report,
    /// not a silent pass: a guard whose own account of *how much it actually
    /// checks* is deleted, reworded, or made wrong leaves the rest of the suite
    /// just as green as a lying one did. The measurement it is checked against
    /// is otherwise untested prose, the same shape as the comments
    /// `line_test_vector_provenance_comment` (issue #307) and
    /// `std_feature_comment` (`src/core/error.rs`, issue #262) read back out
    /// for their own claims.
    fn named_header_doc_count_claim(comment: &str) -> Option<(usize, usize)> {
        // Anchored on the fixed tail of the sentence, so the read is tied to
        // the claim's wording rather than to a bare number that could match any
        // digit in the comment.
        const TAIL: &str = " variants name at least one of their own headers";
        let before_tail = &comment[..comment.find(TAIL)?];
        // "... 52 of the 58 <TAIL>" — digits are read backwards off the tail,
        // one field at a time, each bounded by a non-digit so `58` cannot
        // swallow the `52` and a stray number earlier in the comment cannot
        // stand in for either.
        let (before_total, total) = trailing_digits(before_tail)?;
        let (_, named) = trailing_digits(before_total.strip_suffix(" of the ")?)?;
        Some((named.parse().ok()?, total.parse().ok()?))
    }

    /// The maximal run of ASCII digits ending `text`, and everything before it.
    ///
    /// `None` when `text` does not end in a digit, so a claim read that ran off
    /// the end of a sentence cannot borrow the next word.
    fn trailing_digits(text: &str) -> Option<(&str, &str)> {
        let start = text
            .rfind(|character: char| !character.is_ascii_digit())
            .map_or(0, |at| at + 1);
        (start < text.len()).then_some((&text[..start], &text[start..]))
    }

    #[test]
    fn provider_variant_docs_spell_their_own_headers_the_way_the_code_does() {
        // `Provider::Shopify`'s doc named the header `X-Shopify-Hmac-SHA256`
        // while `shopify::SIGNATURE_HEADER` — the name the code looks up, and
        // the name every other spelling in the repo uses (`shopify.rs`'s module
        // and function docs, `README.md`, the crate docs, and `spec.md` §3,
        // which notes it "matches the casing in Shopify's own docs") reads
        // `X-Shopify-Hmac-Sha256`. The two resolve to the same field: HTTP
        // header lookup is ASCII-case-insensitive, so the failure direction is
        // a documentation defect, not a wrong answer. It is still worth a
        // build failure, because the doc is the prose a reader copies a
        // `HeaderName` out of, and it is the only one of the six surfaces that
        // disagreed — the existing guards cross-check `README.md`, the crate
        // docs and `spec.md` against the provider constants and never the
        // variant docs, which is how this one drifted past them. (A seventh
        // surface, each module's own `- Header:` bullet, was likewise uncovered
        // until Adyen's drifted the same way; that one is now checked by
        // `provider_module_docs_spell_their_header_bullet_the_way_the_code_does`
        // below.)
        //
        // Only the provider's *own* declared headers are checked, and only for
        // casing. A doc legitimately names another provider's header to say a
        // scheme shares a shape with it (`Provider::Expo`'s "the same shape as
        // Intercom's `X-Hub-Signature`"), and a backticked span that is not a
        // header at all (`test-webhook`, a key name) is not this guard's
        // business; both stay quiet. That is the same rule
        // `provider_tables_name_the_header_the_signature_is_read_from` applies
        // to the summary tables, extended from "does the row name the header"
        // to "does it name it the way the code does".
        let mut offenders: Vec<String> = Vec::new();
        let mut named = 0usize;
        for provider in provider_list() {
            let ident = format!("{provider:?}");
            let doc = provider_variant_doc(&ident);
            let stem = provider_module_stem(provider);
            let implementation = module_implementation(&stem);
            let declared: Vec<&str> = declared_header_constants(&implementation)
                .into_iter()
                .map(|(_, name)| name)
                .collect();
            assert!(
                !declared.is_empty(),
                "`src/providers/{stem}.rs` declares no `*_HEADER: &str` constant in its \
                 implementation, so this guard checks nothing for `{provider}` — either the \
                 constants lost their `_HEADER` suffix or the module reads header names in a \
                 shape the derivation does not follow"
            );
            let (exact, wrong) = header_spelling_offenders(&doc, &declared);
            if exact > 0 {
                named += 1;
            }
            offenders.extend(
                wrong
                    .into_iter()
                    .map(|wrong| format!("`Provider::{ident}`'s doc names {wrong}")),
            );
        }
        assert!(
            offenders.is_empty(),
            "a `Provider` variant doc must spell a header exactly as its module declares it — \
             lookup is case-insensitive, so a different casing verifies identically, but it is \
             the spelling a reader copies and the one every other surface in the repo uses: \
             {offenders:?}"
        );

        // Vacuity floor. 53 of the 58 variants name at least one of their own headers today,
        // so a derivation that stopped finding them fails here instead of reporting a clean
        // run over an empty set.
        assert!(
            named * 2 >= provider_list().len(),
            "only {named} of the {} variant docs name one of their own headers, so this guard \
             has almost nothing to compare — a broken `provider_variant_docs` or \
             `declared_header_constants` derivation reads the same as docs that lost their header \
             names",
            provider_list().len()
        );

        // The count in the sentence above, checked against the derivation it
        // reports on. The floor above is deliberately loose, so it stayed green
        // while the sentence read 52 and the docs measured 53: a `//` comment is
        // neither built nor tested, and this comment is the only place a
        // maintainer can see how much of the enum the guard really covers. The
        // five that name none are `Twilio`, `Discord`, `PayPal`, `SendGrid` and
        // `StandardWebhooks` — all five confirmed by hand against their modules'
        // declared headers, not by re-running this test.
        let comment = match vacuity_floor_comment(include_str!("mod.rs")) {
            Some(found) => found,
            None => panic!(
                "this guard's vacuity-floor assertion must be directly below a `//` comment, and \
                 the claim in it is read back out of this file so neither a wrong number nor a \
                 deleted sentence can pass unnoticed"
            ),
        };
        assert_eq!(
            named_header_doc_count_claim(&comment),
            Some((named, provider_list().len())),
            "the vacuity-floor comment above must state this guard's own count, \"N of the M \
             variants name at least one of their own headers\"; it said 52 of the 58 while the \
             docs measured 53, and it is read back out of this file so neither a wrong number nor \
             a reworded sentence can pass unnoticed"
        );

        // The comparison itself, over synthetic text: the shipped defect is
        // reported, an exact mention is not, a header the provider does not
        // declare is not, and a doc that names no header at all is not.
        let (exact, quiet) = header_spelling_offenders(
            "Shopify (`X-Shopify-Hmac-Sha256`, base64) and Intercom's `X-Hub-Signature`.",
            &["X-Shopify-Hmac-Sha256"],
        );
        assert_eq!(
            exact, 1,
            "an exact mention must count as checked, not as drift"
        );
        assert!(quiet.is_empty(), "{quiet:?}");

        let (exact, quiet) = header_spelling_offenders(
            "Shopify (base64-encoded HMAC-SHA256 over the raw body).",
            &["X-Shopify-Hmac-Sha256"],
        );
        assert_eq!(exact, 0, "a doc that names no header checks nothing");
        assert!(quiet.is_empty(), "{quiet:?}");

        let (_, drifted) = header_spelling_offenders(
            "Shopify (`X-Shopify-Hmac-SHA256`, base64) and Intercom's `X-Hub-Signature`.",
            &["X-Shopify-Hmac-Sha256"],
        );
        assert_eq!(drifted.len(), 1, "{drifted:?}");
        assert!(
            drifted[0].contains("`X-Shopify-Hmac-SHA256`")
                && drifted[0].contains("`X-Shopify-Hmac-Sha256`"),
            "the report must name both the spelling in the doc and the one the code declares: \
             {drifted:?}"
        );

        // The claim reader, over synthetic comments. Without these the read
        // above could stop matching the shipped sentence and report a mismatch
        // that reads as a wrong count, or — worse — the assertion could be
        // deleted along with a comment reworded into a shape it no longer
        // finds, leaving the sentence unchecked with nothing failing.
        for (text, claim) in [
            // The shipped sentence, with the rest of the comment following it.
            (
                "// Vacuity floor. 53 of the 58 variants name at least one of their own headers \
                 today,\n// so a derivation that stopped finding them fails here.",
                Some((53, 58)),
            ),
            // A zero count and a fully-covering count both read, so a future
            // enum that loses or gains coverage is not silently mis-read as a
            // missing sentence.
            (
                "// 0 of the 58 variants name at least one of their own headers today.",
                Some((0, 58)),
            ),
            (
                "// 58 of the 58 variants name at least one of their own headers today.",
                Some((58, 58)),
            ),
            // Absent, reworded, and truncated: none of these may borrow a digit
            // from a neighbouring field, an earlier number in the comment, or
            // the next word.
            (
                "// 53 of the 58 variants mention their own headers today.",
                None,
            ),
            (
                "// 53 of the variants name at least one of their own headers.",
                None,
            ),
            (
                "// of the 58 variants name at least one of their own headers.",
                None,
            ),
            (
                "// 53 of the 58 variants name at least one of their own.",
                None,
            ),
            // A bare number elsewhere in the comment must not stand in for the
            // count, which is why the read is anchored on the fixed tail.
            (
                "// 42 unrelated digits, then prose that never states the claim.",
                None,
            ),
        ] {
            assert_eq!(
                named_header_doc_count_claim(text),
                claim,
                "synthetic comment: {text:?}"
            );
        }
    }

    /// A provider module's leading `//!` module-doc block, with the `//!`
    /// marker and one following space stripped from each line and blank lines
    /// preserved.
    ///
    /// Reading stops at the first line that is neither a `//!` doc line nor
    /// blank, which is what keeps a `//!` comment inside the *body* from being
    /// mistaken for module-doc prose. Every provider module opens with `//!`,
    /// so a module that stopped doing so surfaces in the caller as a missing
    /// `- Header:` bullet rather than as a silently empty scan.
    ///
    /// Split from [`module_doc`] so this stripping — the one extraction that
    /// needs real module source rather than already-stripped text — is
    /// exercised over synthetic input too.
    fn stripped_module_doc(source: &str) -> String {
        let mut lines = Vec::new();
        for line in source.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("//!") {
                lines.push(rest.strip_prefix(' ').unwrap_or(rest));
            } else if line.trim().is_empty() {
                lines.push("");
            } else {
                break;
            }
        }
        lines.join("\n")
    }

    /// [`stripped_module_doc`] applied to `src/providers/{stem}.rs` as it
    /// stands on disk.
    fn module_doc(stem: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/providers")
            .join(format!("{stem}.rs"));
        let source = std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "reading {} to determine its module doc failed: {err} — every provider in \
                 `provider_list()` must have a module",
                path.display()
            )
        });
        stripped_module_doc(&source)
    }

    /// A provider module doc's `- Header:` / `- Headers:` bullet, together with
    /// its continuation lines, joined into one line. `None` when the module doc
    /// has no such bullet.
    ///
    /// Continuation lines are what makes joining necessary rather than
    /// incidental: several providers wrap the bullet over three or more lines,
    /// and `square`, `tailscale`, and `x_twitter` all break *inside* the
    /// `name: <format>` span itself, so a single-line read would truncate the
    /// very header name the guard is checking. A continuation is any following
    /// line indented by at least two spaces, which is how these modules set
    /// them; the bullet ends at the first line that is not one.
    fn module_doc_header_bullet(doc: &str) -> Option<String> {
        let mut lines = Vec::new();
        for line in doc.lines() {
            let trimmed = line.trim_start();
            let starts_bullet =
                trimmed.starts_with("- Header:") || trimmed.starts_with("- Headers:");
            let continues_bullet =
                !lines.is_empty() && line.starts_with("  ") && !line.trim().is_empty();
            if starts_bullet || continues_bullet {
                lines.push(trimmed);
            } else if !lines.is_empty() {
                break;
            }
        }
        (!lines.is_empty()).then(|| lines.join(" "))
    }

    /// Occurrences of a name in `declared` that appear in `text` with different
    /// casing than declared, phrased for the failure message, plus how many
    /// spell it exactly as declared.
    ///
    /// Matches on a token boundary — a run of ASCII alphanumerics, `-`, and `_`
    /// — rather than on the backticked spans
    /// [`header_spelling_offenders`] keys on. A module doc's `- Header:` bullet
    /// wraps freely and routinely carries the header name inside a
    /// `<base64(HMAC-SHA256(key, raw_body))>` format description rather than in
    /// a code span of its own, so span extraction would silently miss some
    /// providers and catch others. Searching the ASCII-lowercased text and then
    /// re-checking the matched slice of the original case-sensitively keeps the
    /// comparison honest without depending on where the backticks fell.
    ///
    /// An empty name in `declared` is skipped. `str::find("")` always succeeds
    /// at the cursor, so an empty needle would leave `from` where it is and spin
    /// forever — a test-suite hang rather than a test failure, the worst outcome
    /// for a guard. The caller rejects such a constant outright, so skipping here
    /// costs no coverage; it only keeps this helper total over whatever
    /// `declared` it is handed.
    fn header_casing_in_text(text: &str, declared: &[&str]) -> (usize, Vec<String>) {
        fn is_token_char(byte: u8) -> bool {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
        }

        let lowered = text.to_ascii_lowercase();
        let mut exact = 0;
        let mut offenders = Vec::new();
        for header in declared {
            let needle = header.to_ascii_lowercase();
            if needle.is_empty() {
                continue;
            }
            let mut from = 0;
            while let Some(offset) = lowered
                .get(from..)
                .and_then(|rest| rest.find(needle.as_str()))
            {
                let start = from + offset;
                let end = start + needle.len();
                from = end;
                // `lowered` is an ASCII-lowercased copy of `text`, so it is the
                // same length and the byte offsets below address both. `header`
                // is an ASCII field name, so a match is a whole-token match in
                // `lowered` and therefore ASCII — hence a char boundary in both.
                let before_ok = start == 0 || !is_token_char(lowered.as_bytes()[start - 1]);
                let after_ok = end == lowered.len() || !is_token_char(lowered.as_bytes()[end]);
                if !before_ok || !after_ok {
                    continue;
                }
                let found = &text[start..end];
                if found == *header {
                    exact += 1;
                } else {
                    offenders.push(format!(
                        "`{found}` where the implementation declares `{header}`"
                    ));
                }
            }
        }
        (exact, offenders)
    }

    /// Every provider's own module doc must spell its `- Header:` bullet the way
    /// the module's `*_HEADER` constant declares it.
    ///
    /// This is the sixth spelling surface, and the one closest to the code.
    /// [`provider_variant_docs_spell_their_own_headers_the_way_the_code_does`]
    /// exists precisely because the others missed the variant docs, and its own
    /// rationale enumerates the covered set — the provider constants,
    /// `README.md`, the crate docs, `spec.md` §3, and the variant docs — which
    /// leaves `src/providers/<name>.rs`'s `//!` block out of it. Adyen's is the
    /// one that drifted: its bullet read `hmacsignature` while
    /// `SIGNATURE_HEADER`, the README row, the variant doc, and `spec.md` §3
    /// all read `HmacSignature` (issue #325).
    ///
    /// The failure direction is documentation, not verification: lookup is
    /// ASCII-case-insensitive, so a delivery using either spelling verifies
    /// identically. It is still a build failure, because the bullet is the
    /// copy-paste line — it opens the module's doc block and mirrors the
    /// `spec.md` §3 bullet beside it, so it is where a reader takes a
    /// `HeaderName` from, and a name that agrees with nothing else is the
    /// spelling most likely to be pasted into a `HeaderName` literal or an
    /// allowlist.
    ///
    /// The bar is `exact >= 1` and *not* "no wrongly-cased spelling anywhere":
    /// `nylas` and `docusign` deliberately quote an alternate casing inside the
    /// bullet's own prose to document that Adyen/Nylas-style lowercase headers
    /// resolve, which is accurate and must stay quiet. Failing on any alternate
    /// mention would break the modules that are correct. `exact >= 1` still
    /// catches `adyen`, whose bullet named the header in no other casing.
    #[test]
    fn provider_module_docs_spell_their_header_bullet_the_way_the_code_does() {
        let mut offenders: Vec<String> = Vec::new();
        for provider in provider_list() {
            let stem = provider_module_stem(provider);
            let implementation = module_implementation(&stem);
            let declared: Vec<&str> = declared_header_constants(&implementation)
                .into_iter()
                .map(|(_, name)| name)
                .collect();
            assert!(
                !declared.is_empty(),
                "`src/providers/{stem}.rs` declares no `*_HEADER: &str` constant in its \
                 implementation, so this guard checks nothing for `{provider}` — either the \
                 constants lost their `_HEADER` suffix or the module reads header names in a \
                 shape the derivation does not follow"
            );
            assert!(
                declared.iter().all(|name| !name.is_empty()),
                "`src/providers/{stem}.rs` declares an empty `*_HEADER` constant — an empty \
                 header name matches nothing and would also make `header_casing_in_text`'s \
                 scan non-terminating, so fix the constant rather than the guard"
            );
            let Some(bullet) = module_doc_header_bullet(&module_doc(&stem)) else {
                panic!(
                    "`src/providers/{stem}.rs`'s module doc has no `- Header:` bullet naming \
                     `{provider}`'s signature header"
                );
            };
            let (exact, wrong) = header_casing_in_text(&bullet, &declared);
            if exact == 0 {
                offenders.push(format!(
                    "`src/providers/{stem}.rs`'s `- Header:` bullet never spells {} as \
                     declared, only {:?} — every other surface reads the declared spelling, so \
                     this module doc is the only one a reader cannot reconcile",
                    declared.join("`/`"),
                    wrong
                ));
            }
        }
        assert!(
            offenders.is_empty(),
            "a provider module doc must spell its `- Header:` bullet the way the module \
             declares the constant — the bullet is the copy-paste line, and lookup is \
             case-insensitive, so a different casing verifies identically but is the spelling \
             no other surface in the repo uses: {offenders:?}"
        );
    }

    /// The scan above is only as good as its three extractions —
    /// [`stripped_module_doc`], [`module_doc_header_bullet`], and
    /// [`header_casing_in_text`] — so each is exercised over synthetic input:
    /// raw module source whose `//!` block ends at the first body line, a
    /// bullet whose only spelling is wrongly cased, the legitimate
    /// alternate-casing prose `nylas`/`docusign` write, the wrapped bullet that
    /// breaks inside its code span, and a token that merely *contains* the
    /// header name. Without this the real run is the only evidence the scan
    /// works, which is the vacuous pass
    /// `provider_module_docs_spell_their_header_bullet_the_way_the_code_does`
    /// cannot detect from the outside.
    #[test]
    fn module_doc_header_bullet_scan_is_exercised_over_synthetic_docs() {
        const DECLARED: &[&str] = &["X-Example-Signature", "X-Example-Timestamp"];

        /// `stripped_module_doc` + `module_doc_header_bullet` as a total
        /// function for these fixtures, run over raw module source so the
        /// `//!` stripping is exercised too. `unwrap_or_else(panic)` rather than
        /// `.expect` because `clippy::expect_used` is denied crate-wide, tests
        /// included.
        fn bullet(source: &str) -> String {
            let doc = stripped_module_doc(source);
            module_doc_header_bullet(&doc)
                .unwrap_or_else(|| panic!("expected a `- Header:` bullet in {doc:?}"))
        }

        // The shape `adyen` shipped: only one spelling, and it is not the
        // declared one. Must be reported.
        let adyen_shaped = bullet(
            "//! Scheme, per the docs:\n\
             //!\n\
             //! - Header: `x-example-signature: <hex_hmac>`\n\
             //! - Signed string: the raw body bytes, unmodified\n\
             //! The rest of the module:\n\
             //! \n\
             //! use core::fmt;\n",
        );
        let (exact, wrong) = header_casing_in_text(&adyen_shaped, DECLARED);
        assert_eq!(
            exact, 0,
            "a wrongly-cased-only bullet must not count as spelled"
        );
        assert_eq!(
            wrong,
            vec![
                "`x-example-signature` where the implementation declares \
                 `X-Example-Signature`"
                    .to_string()
            ]
        );

        // The shape `nylas` and `docusign` write: the bullet names the declared
        // header, and its continuation prose quotes an alternate casing to
        // explain that lookup is case-insensitive. Accepted, because the bullet
        // does spell the header the way the code declares it.
        let alternate_casing_prose = bullet(
            "//! - Header: `X-Example-Signature: <hex_hmac>` — bare hex. The docs\n\
             //!   state it arrives as either `X-Example-Signature` or\n\
             //!   `x-example-signature`; lookup is case-insensitive, so either\n\
             //!   spelling works.\n\
             //! - Signed string: raw body\n",
        );
        let (exact, wrong) = header_casing_in_text(&alternate_casing_prose, DECLARED);
        assert!(
            exact >= 1,
            "the declared spelling in the bullet must count as exact"
        );
        assert_eq!(
            wrong.len(),
            1,
            "the prose's alternate spelling is reported for the message but must not fail: \
             {wrong:?}"
        );

        // `square`, `tailscale`, and `x_twitter` break inside the code span, so
        // the header name is the first thing on the bullet's first line and the
        // continuation must not cost the scan the match.
        let wrapped = bullet(
            "//! - Header: `X-Example-Signature: <base64(HMAC-SHA256(key,\n\
             //!   notification_url ++ raw_body))>`\n\
             //! - Signed string: the notification URL\n",
        );
        let (exact, wrong) = header_casing_in_text(&wrapped, DECLARED);
        assert_eq!(exact, 1, "a wrapped bullet still yields its header name");
        assert!(
            wrong.is_empty(),
            "the wrapped bullet spells the header as declared"
        );

        // A longer token that merely contains a declared name is not a spelling
        // of it: `X-Example-Signature-V2` must not satisfy the
        // `X-Example-Signature` constant.
        let superstring = bullet(
            "//! - Header: `x-example-signature-v2: <hex_hmac>`\n\
             //! - Signed string: raw body\n",
        );
        assert_eq!(
            header_casing_in_text(&superstring, DECLARED).0,
            0,
            "a token that merely contains a declared name is not a spelling of it"
        );

        // A module doc with no bullet at all is a panic, not a silent pass.
        assert_eq!(
            module_doc_header_bullet(&stripped_module_doc("//! Scheme, per the docs.\n")),
            None
        );
        // Indentation does not hide the bullet: the scan trims before matching,
        // so a module that nests its `- Header:` line inside a list is still
        // checked rather than silently skipped.
        assert_eq!(
            bullet("//!   - Header: `X-Example-Signature: <hex_hmac>`\n"),
            "- Header: `X-Example-Signature: <hex_hmac>`"
        );
        // `stripped_module_doc` stops at the first non-`//!`, non-blank line, so
        // a `//!` comment in the module *body* is never read as module-doc prose.
        let body_only = stripped_module_doc(
            "//! Scheme, per the docs.\n\
             \n\
             //! - Header: `X-Example-Signature: <hex_hmac>`\n\
             \n\
             const SIGNATURE_HEADER: &str = \"X-Example-Signature\";\n\
             //! a body comment that mentions X-EXAMPLE-SIGNATURE\n",
        );
        assert!(
            !body_only.contains("body comment"),
            "the body comment must not be read as module-doc prose: {body_only:?}"
        );

        // An empty declared name terminates instead of spinning: `str::find("")`
        // always matches at the cursor, so an unskipped empty needle would never
        // advance the search and hang the suite. The guard rejects an empty
        // `*_HEADER` constant outright, so this only pins that the helper itself
        // cannot be the thing that hangs.
        assert_eq!(
            header_casing_in_text("- Header: `x-example-signature`", &[""]),
            (0, Vec::new()),
            "an empty declared name must be skipped, not matched at every position"
        );
        // …and it must not stop the *real* names in the same slice from being
        // scanned.
        assert_eq!(
            header_casing_in_text(
                "- Header: `X-Example-Signature`",
                &["", "X-Example-Signature"]
            )
            .0,
            1,
            "an empty name must not suppress the names beside it"
        );
    }

    /// The provenance comment `src/providers/line.rs` places immediately above
    /// the first `const` in its test module, as `(1-based first line, joined
    /// comment text)`. `None` when no comment block precedes that `const`.
    fn line_test_vector_provenance_comment(source: &str) -> Option<(usize, String)> {
        let test_module = source.find("#[cfg(test)]")?;
        let after = &source[test_module..];
        let first_const = after.find("\n    const ")? + 1;
        let before_const = &after[..first_const];

        // Walk back over the contiguous comment run directly above the `const`.
        // `str::Lines` is not a `DoubleEndedIterator` under `core`, so the
        // scan is over a collected, index-addressable list.
        let lines: Vec<&str> = before_const.lines().collect();
        let mut start = None;
        for index in (0..lines.len()).rev() {
            let trimmed = lines[index].trim();
            if trimmed.starts_with("//") {
                start = Some(index);
            } else if !trimmed.is_empty() {
                break;
            }
        }
        let start = start?;
        let comment = lines[start..]
            .iter()
            // Drop the `//` marker so a reported claim reads as prose, not as
            // source lines glued together.
            .map(|line| line.trim().trim_start_matches("//").trim())
            .collect::<Vec<_>>()
            .join(" ");
        // `test_module` is a byte offset at a line start, so the `const`'s
        // module-relative line indices are `source`'s, offset by the lines
        // before the test module.
        let first_line = source[..test_module].lines().count() + 1 + start;
        Some((first_line, comment))
    }

    /// `line.rs` claimed its docs example was "the only official vector in this
    /// crate that needs no local construction". It is not, on two counts: the
    /// claim is mislabelled — `line.rs`'s happy-path `SIGNATURE` and both
    /// boundary vectors *are* locally constructed, and only the separate
    /// `OFFICIAL_*` triple is LINE's own published example — and it is not
    /// unique, since GitHub's, Mux's, Slack's and Adyen's primary vectors are
    /// likewise their own providers' published triples, used as published.
    ///
    /// Nothing verifies a test module's provenance comment, so a claim like this
    /// one survives every other guard in this file: the rest read module
    /// *behavior* (which headers are scanned, how timestamps are floored) or
    /// doc surfaces that name a header or a provider, and none of them reads a
    /// module's account of where its own test values came from. It is a
    /// provenance claim, so it is checked where it is written.
    #[test]
    fn line_test_vector_provenance_does_not_claim_a_crate_wide_exclusive_vector() {
        let source = include_str!("line.rs");
        let (line, comment) = match line_test_vector_provenance_comment(source) {
            Some(found) => found,
            None => panic!(
                "src/providers/line.rs's test module must document its vectors above the first \
                 `const`; with the comment removed this guard reads nothing and a crate-wide \
                 exclusivity claim could be reintroduced undetected"
            ),
        };

        // Both halves are required. A module-scoped "the only" is true and stays
        // quiet (LINE publishes one docs example, and this crate carries one
        // module per provider), and so is a crate-scoped sentence that asserts
        // no uniqueness. The shipped claim has both, split across two lines,
        // which is why this reads the joined comment rather than single lines.
        assert!(
            !comment_reads_as_crate_wide_exclusive(&comment),
            "src/providers/line.rs:{line} claims its test vector is unique in this crate: \
             {comment:?} — GitHub's, Mux's, Slack's and Adyen's primary vectors are their own \
             providers' published triples too, used as published, and line.rs's own \
             `SIGNATURE`/boundary vectors are locally constructed"
        );

        // The half of the claim that is true, pinned here rather than left to
        // `line.rs`'s own test: LINE's published example verifies through the
        // public entry point with nothing computed at test time. Adyen's and
        // Slack's (equally provider-published, and the two remaining
        // counterexamples) are pinned by their own modules'
        // `official_vector_verifies`; their vectors carry multi-hundred-byte
        // bodies, so they are not duplicated here.
        assert_eq!(
            verify(
                Provider::Line,
                &[(
                    "x-line-signature",
                    "GhRKmvmHys4Pi8DxkF4+EayaH0OqtJtaZxgTD9fMDLs=",
                )],
                br#"{"destination":"U8e742f61d673b39c7fff3cecb7536ef0","events":[]}"#,
                &Secret::new("8c570fa6dd201bb328f1c1eac23a96d8"),
                Default::default(),
            ),
            Ok(()),
            "LINE's own published example must keep verifying: it is the one provider-published \
             vector this guard does rest on"
        );

        // ... and the refutation, the same way: Mux's own published test vector
        // (`Mux.Webhooks.TestUtils.generate_signature("payload",
        // "SuperSecret123")`) verifies as published, with no local construction
        // and no locally computed value anywhere in this test.
        assert_eq!(
            verify(
                Provider::Mux,
                &[(
                    "Mux-Signature",
                    "t=1591664030,v1=e43496b6aae982c4c2fd6f8e92935f1d90216f1f64d56024e72390acfb988272",
                )],
                b"payload",
                &Secret::new("SuperSecret123"),
                clocked_at(1_591_664_030, Some(Duration::from_secs(300))),
            ),
            Ok(()),
            "Mux publishes a byte-exact vector of its own, so line.rs's vector is never the only \
             one in this crate that needs no local construction"
        );

        // The derivation itself, over synthetic comment blocks: a module-scoped
        // "only" is not flagged, and a crate-scoped sentence that claims no
        // uniqueness is not flagged. Without these the joined-comment read
        // could silently stop matching and the real run would pass vacuously.
        for (text, flagged) in [
            (
                "docs example — the only official vector this module carries, used as published",
                false,
            ),
            (
                "every provider in this crate re-checks its own OFFICIAL_* triple",
                false,
            ),
            (
                "the only official vector in this crate that needs no local construction",
                true,
            ),
            (
                "the crate's sole docs-published vector needs no local construction",
                true,
            ),
            // An "only" that opens a clause, and a marker that only appears
            // inside a longer word: both must still be read, or the derivation
            // is narrower than the claim it guards.
            (
                "only the OFFICIAL_* triple in this crate is the provider's own example",
                true,
            ),
            ("the crate's console-shaped word is not a marker", false),
        ] {
            assert_eq!(
                comment_reads_as_crate_wide_exclusive(text),
                flagged,
                "synthetic comment: {text:?}"
            );
        }
    }

    /// Whether a joined provenance comment asserts that something is unique in
    /// the crate rather than in its own module. Split out from the assertion
    /// above so the synthetic cases below exercise the same read the real run
    /// does.
    fn comment_reads_as_crate_wide_exclusive(comment: &str) -> bool {
        // Token-wise on the exclusivity marker, substring-wise on the scope
        // phrase. A plain `contains("sole ")` would also match inside "console
        // ", and a plain `contains("the only")` would miss an "only" that opens
        // a clause — the shipped claim's marker happens to sit mid-sentence, so
        // a narrower read than either would have shipped the defect.
        const EXCLUSIVE: [&str; 3] = ["only", "unique", "sole"];
        let lower = comment.to_ascii_lowercase();
        let exclusive = lower
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|token| EXCLUSIVE.contains(&token));
        let crate_wide = lower.contains("this crate") || lower.contains("the crate");
        exclusive && crate_wide
    }

    /// Which `spec.md` §5 clause a provider module's test *names* have to read
    /// as (issue #410).
    ///
    /// §5.1–§5.5 are the one part of the testing bar with no drift guard:
    /// §5.6's fuzz pool, the header-name rules and the README/crate-docs tables
    /// are all pinned, and nothing checked that a provider module still shipped
    /// a vector/negative/tamper/replay/malformed-header test at all. A scan can
    /// only see names, not the assertion each test makes — but presence is
    /// exactly the part that decays silently when a module is refactored or a
    /// new one is written from a template.
    ///
    /// The recognisers are deliberately loose rather than renaming every
    /// existing test to fit one scheme: the shipped spellings are not uniform
    /// (Box's replay tests say `rejects_old_timestamp_outside_window` with no
    /// "replay" in them, Discord's happy path is `ping_delivery_verifies`,
    /// Mandrill's is `official_check_scenario_verifies`). Loose is only safe if
    /// the looseness is bounded, so
    /// `test_category_recognisers_match_shipped_names_and_reject_prose` pins
    /// every recogniser on both the irregular shipped spellings and on names
    /// that must *not* count: a recogniser that stops matching fails there
    /// first, instead of passing every module vacuously.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestCategory {
        /// §5.1 — an official (or documented-recipe) vector that verifies.
        Vector,
        /// §5.2 — one byte flipped in the signature, reported as a mismatch.
        Negative,
        /// §5.3 — `raw_body` (or the signed fields) modified after signing.
        Tamper,
        /// §5.4 — a correctly signed delivery outside the replay window.
        Replay,
        /// §5.5 — a missing, empty or garbage header rejected distinctly.
        MalformedHeader,
    }

    /// Every category, in `spec.md` §5 order.
    const TEST_CATEGORIES: [TestCategory; 5] = [
        TestCategory::Vector,
        TestCategory::Negative,
        TestCategory::Tamper,
        TestCategory::Replay,
        TestCategory::MalformedHeader,
    ];

    /// Words that make a test assert a *rejection*, in any category — the
    /// shared half of every recogniser, since §5.2–§5.5 are all "this must
    /// fail" and only §5.1 is "this must pass".
    const REJECTION_WORDS: [&str; 5] = ["fail", "reject", "mismatch", "satisf", "error"];

    /// Whether `needle`-style markers occur verbatim in a snake_case test name.
    fn name_contains_any(name: &str, markers: &[&str]) -> bool {
        markers.iter().any(|marker| name.contains(marker))
    }

    impl TestCategory {
        /// The clause plus an accepted spelling, so a failure says what is
        /// missing and what the scanner would recognise.
        fn clause_and_hint(self) -> &'static str {
            match self {
                Self::Vector => {
                    "§5.1, an accepting vector test (`official_*`, \
                                 `*_vector_*`, `constructed_*`, `documented_*`, \
                                 `*_delivery_verifies`, …)"
                }
                Self::Negative => {
                    "§5.2, a rejected signature forgery \
                                   (`negative_flipped_*`, `flipped_*`, \
                                   `*wrong_*_fails`, `rejects_wrong_key`, …)"
                }
                Self::Tamper => {
                    "§5.3, a rejected modified body or signed field \
                                 (`tampered_body_fails`, `rejects_tampered_body`, \
                                 `tampered_field_value_is_rejected`, …)"
                }
                Self::Replay => {
                    "§5.4, a rejected out-of-window timestamp \
                                 (`replay_*_out_of_tolerance`, \
                                 `rejects_*_outside_window`, \
                                 `stale_timestamp_rejected`, …)"
                }
                Self::MalformedHeader => {
                    "§5.5, a rejected missing/empty/garbage \
                                          header (`missing_*_errors_distinctly`, \
                                          `*_is_malformed`, `*bad_encoding*`, …)"
                }
            }
        }

        /// Whether `name` reads as a test of this category. Loose by design —
        /// see [`TestCategory`]'s doc comment, and the synthetic-name test that
        /// bounds the looseness.
        fn recognises(self, name: &str) -> bool {
            match self {
                // The vector test must *accept*, and must say where its values
                // came from: a boundary case alone is locally constructed with
                // no provenance, so `boundary_bodies_verify` does not stand in
                // for §5.1 even though it asserts the same `Ok(())`.
                Self::Vector => {
                    name_contains_any(
                        name,
                        &[
                            "vector",
                            "official",
                            "constructed",
                            "documented",
                            "docs_example",
                            "reproduces",
                            "construction",
                            "recipe",
                            "scenario",
                            "delivery",
                            "sdk",
                            "rfc",
                            "example",
                        ],
                    ) && name_contains_any(name, &["verif", "accept"])
                        && !name_contains_any(
                            name,
                            &[
                                "fail",
                                "reject",
                                "mismatch",
                                "wrong",
                                "tamper",
                                "flip",
                                "missing",
                                "malformed",
                                "bad_encoding",
                                "out_of_tolerance",
                                "stale",
                                "garbage",
                                "not_",
                                "cannot",
                                "does_not",
                                "never",
                                "bypass",
                                "invalid",
                                "broken",
                                "satisf",
                                "omitted",
                                "swapped",
                                "altered",
                            ],
                        )
                }
                // §5.2 is the flip, so the marker names the forgery rather than
                // the body: `tampered_body_fails` is §5.3's and must not be
                // credited here.
                Self::Negative => {
                    name_contains_any(
                        name,
                        &[
                            "flipped",
                            "flip",
                            "negative",
                            "wrong",
                            "forgery",
                            "mismatch",
                            "tampered_signature",
                            "altered_signature",
                            "swapped_signature",
                        ],
                    ) && name_contains_any(name, &REJECTION_WORDS)
                }
                // The body/field half of "modified after signing": a tampered
                // *timestamp* or *signature* is the timestamp/signature-binding
                // check, not §5.3's re-serialization check.
                Self::Tamper => {
                    name_contains_any(name, &["tamper", "altered", "swapped", "re_serialized"])
                        && name_contains_any(
                            name,
                            &[
                                "body",
                                "field",
                                "url",
                                "request",
                                "payload",
                                "value",
                                "content",
                                "re_serialized",
                            ],
                        )
                        && name_contains_any(name, &REJECTION_WORDS)
                }
                // §5.4's own error text, Box's `outside_window` spelling, a
                // `stale` rejection, or a `replay_*` test that rejects rather
                // than `replay_within_tolerance_verifies` (an acceptance) or
                // `disabled_max_age_accepts_stale_signatures` (the opt-out).
                Self::Replay => {
                    name_contains_any(name, &["out_of_tolerance", "outside_window"])
                        || (name.contains("stale") && name_contains_any(name, &REJECTION_WORDS))
                        || (name.contains("replay") && name_contains_any(name, &REJECTION_WORDS))
                }
                // `malformed`/`bad_encoding` are themselves parse failures;
                // `missing`/`empty`/`garbage` need the rejection half so that
                // e.g. contentful's `empty_bare_path_request_url_canonicalizes…`
                // is not read as §5.5 coverage.
                Self::MalformedHeader => {
                    name.contains("malformed")
                        || name.contains("bad_encoding")
                        || (name_contains_any(
                            name,
                            &["missing", "empty", "garbage", "unparseable", "absent"],
                        ) && name_contains_any(name, &REJECTION_WORDS))
                }
            }
        }

        /// Whether a provider module must carry this category: §5.4 applies
        /// only "for providers with timestamps", so it is scoped by the
        /// implementation's own `check_replay` call rather than by a table.
        fn required_for(self, stem: &str) -> bool {
            self != Self::Replay || module_calls_check_replay(stem)
        }
    }

    /// §5.1–§5.5 guarded by a scan over every provider module's test names
    /// (spec.md §5, issue #410).
    ///
    /// The scan reads `src/` from disk rather than the compiled crate, so it
    /// holds in every feature configuration — including the ones where the
    /// feature-gated `paypal`/`sendgrid` modules are not compiled at all — and
    /// in a crates.io checkout, where `src/` ships (the same reason the §4
    /// no-panic guard can walk the directories). `form.rs` is deliberately not
    /// walked: it is a parsing helper shared by Twilio and Mandrill, not a
    /// provider, and `provider_module_stems()` is already exactly the set of
    /// modules that implement a `Provider`.
    #[test]
    fn every_provider_module_covers_the_five_test_categories() {
        let mut checked = 0_usize;
        for stem in provider_module_stems() {
            let names = module_test_names(&stem);
            assert!(
                !names.is_empty(),
                "src/providers/{stem}.rs declares no `#[test]` functions, so none of \
                 spec.md §5.1–§5.5 can be covered there",
            );

            let missing: Vec<&'static str> = TEST_CATEGORIES
                .iter()
                .copied()
                .filter(|category| category.required_for(&stem))
                .filter(|category| !names.iter().any(|name| category.recognises(name)))
                .map(TestCategory::clause_and_hint)
                .collect();
            assert!(
                missing.is_empty(),
                "src/providers/{stem}.rs has no test reading as each spec.md §5 \
                 category it must cover — add the missing test, and if it is already \
                 there under a name this scanner does not read, teach \
                 `TestCategory::recognises` the spelling and pin it in \
                 `test_category_recognisers_match_shipped_names_and_reject_prose`: {}",
                missing.join("; "),
            );
            checked += 1;
        }

        // A walk that found nothing would make every assertion above pass
        // vacuously, which is the one way a source-scanning guard can report
        // coverage it does not have.
        assert!(
            checked > 0,
            "the §5.1–§5.5 coverage scan found no provider modules to check"
        );
    }

    /// The recognisers above are heuristics over names nobody enforceably
    /// spells the same way, so they are pinned here on the irregular shipped
    /// spellings they exist to catch (Box's `outside_window`, Discord's
    /// `ping_delivery_verifies`, Mandrill's `official_check_scenario_verifies`,
    /// Custom's `stale_timestamp_rejected`) *and* on names that must not count:
    /// adjacent tests, the neighbouring category, and prose. Without the
    /// negative half a recogniser widened to match everything would still pass
    /// every provider module and this suite would be claiming a guard it no
    /// longer had.
    #[test]
    fn test_category_recognisers_match_shipped_names_and_reject_prose() {
        fn assert_cases(category: TestCategory, cases: &[(&str, bool)]) {
            for (name, expected) in cases {
                assert_eq!(
                    category.recognises(name),
                    *expected,
                    "{category:?} recogniser must {} the shipped-shaped name {name:?}",
                    if *expected { "credit" } else { "not credit" },
                );
            }
        }

        assert_cases(
            TestCategory::Vector,
            &[
                ("official_vector_verifies", true),
                ("ping_delivery_verifies", true),
                ("official_check_scenario_verifies", true),
                ("documented_construction_verifies", true),
                (
                    "docs_example_event_with_constructed_signature_verifies",
                    true,
                ),
                ("base64_variants_verify_the_rfc_vectors", true),
                // A boundary case is locally constructed and carries no
                // provenance, so it is not §5.1's vector even though it asserts
                // the same acceptance.
                ("boundary_bodies_verify", false),
                ("docs_example_header_is_well_formed_but_mismatches", false),
                ("official_mismatch_vector_fails", false),
            ],
        );
        assert_cases(
            TestCategory::Negative,
            &[
                ("negative_flipped_signature_byte_fails", true),
                ("rejects_wrong_key", true),
                ("flipped_bit_in_signature_is_rejected", true),
                ("wrong_public_key_fails", true),
                ("tampered_body_fails", false),
                ("missing_header_errors_distinctly", false),
                ("boundary_bodies_verify", false),
            ],
        );
        assert_cases(
            TestCategory::Tamper,
            &[
                ("tampered_body_fails", true),
                ("rejects_tampered_body", true),
                ("tampered_field_value_is_rejected", true),
                ("json_body_variant_rejects_an_altered_signed_body", true),
                // Signature/timestamp binding, not a re-serialization check.
                ("tampered_signature_fails", false),
                ("tampered_timestamp_fails_signature_check", false),
                ("boundary_bodies_verify", false),
            ],
        );
        assert_cases(
            TestCategory::Replay,
            &[
                ("replay_old_timestamp_out_of_tolerance", true),
                ("rejects_old_timestamp_outside_window", true),
                ("stale_timestamp_rejected", true),
                // The window edges and the opt-out are not the rejection.
                ("replay_within_tolerance_verifies_at_window_edges", false),
                ("disabled_max_age_accepts_stale_signatures", false),
                ("max_age_has_no_effect_for_github", false),
                ("boundary_bodies_verify", false),
            ],
        );
        assert_cases(
            TestCategory::MalformedHeader,
            &[
                ("missing_headers_error_distinctly", true),
                ("empty_signature_is_malformed", true),
                ("non_base64_signature_is_bad_encoding", true),
                (
                    "a_body_field_that_cannot_be_decoded_is_rejected_as_malformed",
                    true,
                ),
                (
                    "empty_bare_path_request_url_canonicalizes_to_the_root_path",
                    false,
                ),
                ("tampered_body_fails", false),
                ("boundary_bodies_verify", false),
            ],
        );
    }

    /// The names of every `#[test]` function in `src/providers/{stem}.rs`, in
    /// source order. Read from the `#[cfg(test)]` region onward, so a `fn`
    /// mentioned in the module's docs is never credited as a test.
    fn module_test_names(stem: &str) -> Vec<String> {
        let source = module_source(stem);
        let test_module = match source.find("#[cfg(test)]") {
            Some(at) => &source[at..],
            None => "",
        };

        let mut names = Vec::new();
        let mut pending = false;
        for line in test_module.lines() {
            let rest = if pending {
                line
            } else if line.contains("#[test]") {
                pending = true;
                line.split_once("#[test]").map_or("", |(_, after)| after)
            } else {
                continue;
            };
            let rest = rest.trim();
            // Doc comments are skipped rather than ending the search: a test
            // function may document itself between `#[test]` and `fn`.
            if rest.starts_with("//") {
                continue;
            }
            if let Some(rest) = rest.strip_prefix("fn ") {
                names.push(
                    rest.split(['(', ' ', '\t'])
                        .next()
                        .unwrap_or(rest)
                        .to_string(),
                );
                pending = false;
            }
        }
        names
    }

    #[test]
    fn fuzz_implemented_pool_covers_every_nameable_provider() {
        use std::fs;
        use std::path::Path;

        // The fuzz target's `IMPLEMENTED` pool (`spec.md` §5.6) is the one
        // provider listing with no drift guard, and it has drifted twice —
        // Mollie's corpus seed shipped missing (PR #147) and PayPal shipped
        // without a row in the pool (PR #161, where the fix was still
        // manual). The README/crate-doc tables and the §2 enum sketch are
        // pinned by the guards above; pin the fuzz pool to the same
        // `provider_list()` source of truth so a provider that ships without
        // fuzz coverage fails CI instead of shrinking the fuzz surface
        // silently. `Custom` is deliberately absent: it is not
        // name-constructible and the target exercises it through dedicated
        // `attempt()` calls, so the pool must list exactly `provider_list()`.
        //
        // `fuzz/` is excluded from the crates.io tarball (Cargo.toml
        // `exclude`), so in a packaged checkout the file does not exist and
        // the guard is skipped — it is a repo-internal test, not part of the
        // shipped crate's contract.
        let target = {
            let fuzz_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
            let path = fuzz_dir.join("fuzz_targets/parse_and_verify.rs");
            match fs::read_to_string(path) {
                Ok(src) => src,
                // `fuzz/` not present (e.g. the publish tarball): nothing to
                // guard against here, and the crate's own tests must not fail
                // on a file it does not ship.
                Err(_) => return,
            }
        };

        let listed = fuzz_implemented_providers(&target);
        assert_eq!(
            listed.len(),
            provider_list().len(),
            "fuzz IMPLEMENTED pool must list every name-constructible provider exactly once ({} in `provider_list()`, {listed:?} found)",
            provider_list().len(),
        );
        for provider in provider_list() {
            let ident = format!("{provider:?}");
            let hits = listed
                .iter()
                .filter(|listed| listed.as_str() == ident)
                .count();
            assert_eq!(
                hits, 1,
                "fuzz IMPLEMENTED pool must list `{ident}` exactly once (found {hits})"
            );
        }
        assert!(
            !listed.contains(&"Custom".to_string()),
            "fuzz IMPLEMENTED pool must not list `Custom` (it is not name-constructible)"
        );
    }

    #[test]
    fn fuzz_target_configures_the_custom_millis_timestamp_unit() {
        use std::fs;
        use std::path::Path;

        // The `IMPLEMENTED` pool guard above pins which *providers* the fuzz
        // target drives, but `Provider::Custom` is not name-constructible and
        // so is exercised only through the target's hand-written
        // `CustomScheme` configurations — nothing pinned *which* ones.
        // `TimestampUnit::Millis` (issues #273/#274) is the concrete gap: the
        // target shipped with a seconds-unit and a timestamp-less
        // configuration, so `src/providers/custom.rs`'s millisecond branch
        // (`parse_millis(...)? / MILLIS_PER_SECOND`) had no fuzz coverage at
        // all. The six built-in millisecond providers do exercise
        // `parse_millis`, which is exactly why this rotted unnoticed: the
        // shared parser is covered while the caller-declared unit dispatch
        // around it is not. `spec.md` §5.6 asks for each provider's
        // header-parsing path to be reachable from this target, and a
        // millisecond-stamping long-tail sender — the case `Custom` exists for
        // — is the one a panic or an overflow in that branch would hit.
        //
        // Checked on the *variant* rather than an exact field spelling so both
        // the struct-literal (`timestamp_unit: TimestampUnit::Millis`) and the
        // builder (`.with_timestamp_unit(TimestampUnit::Millis)`) forms
        // satisfy it, and so re-pointing the configuration at a different
        // `CustomScheme` field set does not produce a false failure. A floor of
        // one, not an exact count: what matters is that the unit is configured
        // at all, and a second millisecond configuration is a gain, not drift.
        //
        // `fuzz/` is excluded from the crates.io tarball (Cargo.toml
        // `exclude`), so in a packaged checkout the file does not exist and
        // the guard is skipped — it is a repo-internal test, not part of the
        // shipped crate's contract.
        let target = {
            let path =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets/parse_and_verify.rs");
            match fs::read_to_string(path) {
                Ok(src) => src,
                // `fuzz/` not present (e.g. the publish tarball): nothing to
                // guard against here, and the crate's own tests must not fail
                // on files it does not ship.
                Err(_) => return,
            }
        };

        let hits = fuzz_millis_timestamp_unit_hits(&target);
        assert!(
            hits > 0,
            "fuzz target must configure at least one `CustomScheme` with `TimestampUnit::Millis` — the millisecond unit is never set by any other configuration, so `src/providers/custom.rs`'s `parse_millis(...)? / MILLIS_PER_SECOND` branch has no fuzz coverage and `spec.md` §5.6 is unmet for it"
        );
    }

    /// The count of code (non-comment) lines in the fuzz target that name
    /// `TimestampUnit::Millis`. Whole-line `//` comments and trailing `// …`
    /// comments are dropped first: the target documents each configuration's
    /// rationale in prose that names the very variant this counts, so a raw
    /// line count would be satisfied by a comment alone. A `//` inside a
    /// string literal would be mis-trimmed; the fuzz target has none, and this
    /// is a floor check over a repo-internal file, not a parser. Test-only
    /// helper over the target's source text.
    fn fuzz_millis_timestamp_unit_hits(target: &str) -> usize {
        target
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                !line.starts_with("//")
                    && match line.find("//") {
                        Some(at) => &line[..at],
                        None => line,
                    }
                    .contains("TimestampUnit::Millis")
            })
            .count()
    }

    #[test]
    fn fuzz_millis_timestamp_unit_hits_ignores_prose() {
        // The positive side: a struct-literal configuration, the builder form,
        // and a code line that mentions the variant only in a trailing comment.
        let target = "\
            let a = CustomScheme { timestamp_unit: TimestampUnit::Millis, ..d };
            let b = scheme.with_timestamp_unit(TimestampUnit::Millis);
            let c = other.with_timestamp_unit(TimestampUnit::Seconds); // was TimestampUnit::Millis
        ";
        assert_eq!(fuzz_millis_timestamp_unit_hits(target), 2);

        // The negative side: only a module-doc bullet, a prose comment, and a
        // seconds-unit configuration — none of which configure the unit.
        let target = "\
//! - `custom-millis-timestamp-delivery` — the millisecond-unit TimestampUnit::Millis path.
// The Millis branch floors via parse_millis(..) / MILLIS_PER_SECOND.
            let d = CustomScheme { timestamp_unit: TimestampUnit::Seconds, ..e };
        ";
        assert_eq!(fuzz_millis_timestamp_unit_hits(target), 0);
    }

    /// Every `Encoding` variant is a decoder the fuzz target must configure
    /// (issue #360).
    ///
    /// The sibling guard above pins `TimestampUnit::Millis`; this one pins the
    /// other `CustomScheme` enum, which rotted the same way and for the same
    /// reason. `src/providers/custom.rs` dispatches `Encoding` over four decoder
    /// arms — `hex::decode`, and the `STANDARD` / `URL_SAFE` /
    /// `STANDARD_NO_PAD` base64 engines — but the target's three
    /// `CustomScheme` configurations each pinned `encoding` to a single variant
    /// (`Hex` twice, `Base64` once), so the two base64 variants added in #330
    /// were driven by no fuzz configuration at all. `spec.md` §5.6 asks for each
    /// provider's *encoding-decoding* path to be reachable from this target, and
    /// those two arms are the ones whose alphabet and padding rules differ from
    /// the third, which is exactly where a decoder mishandles adversarial bytes.
    /// Their unit tests are hand-written tables of well-formed digests, so
    /// arbitrary input is what they do not cover.
    ///
    /// The requirement is checked against the `Encoding` dispatch's own arm
    /// count rather than against a hand-written list alone, so a *further*
    /// variant added later cannot land with no fuzz coverage: adding an arm to
    /// `src/providers/custom.rs` without adding it to the list fails
    /// [`custom_encoding_dispatch_arm_count_matches_the_variant_list`], which
    /// runs even where this one cannot (it needs `fuzz/`). That matters because
    /// the list has already had to grow twice: `Base64NoPad` in #330, and
    /// `Base64UrlNoPad` in #366 — the cell the former's docs had recorded as an
    /// anticipated one-line follow-up.
    ///
    /// Per variant it is a floor of one, not an exact count: what matters is
    /// that the decoder is driven, and a second configuration is a gain, not
    /// drift.
    ///
    /// `fuzz/` is excluded from the crates.io tarball (Cargo.toml `exclude`), so
    /// in a packaged checkout the file does not exist and this guard is skipped —
    /// it is a repo-internal test, not part of the shipped crate's contract.
    #[test]
    fn fuzz_target_configures_every_custom_encoding_variant() {
        use std::fs;
        use std::path::Path;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let target = match fs::read_to_string(root.join("fuzz/fuzz_targets/parse_and_verify.rs")) {
            Ok(src) => src,
            // `fuzz/` not present (e.g. the publish tarball): nothing to guard
            // against here, and the crate's own tests must not fail on a file it
            // does not ship.
            Err(_) => return,
        };

        for variant in custom_encoding_variant_names() {
            assert!(
                fuzz_encoding_variant_hits(&target, variant) > 0,
                "fuzz target must configure at least one `CustomScheme` with \
                 `Encoding::{variant}` — no other configuration sets it, so that decoder arm in \
                 `src/providers/custom.rs` is driven by no fuzz input at all and `spec.md` §5.6 is \
                 unmet for it"
            );
        }
    }

    /// Every variant `src/providers/custom.rs`'s `Encoding` dispatch decodes
    /// with, as `Variant` spellings.
    ///
    /// Hand-maintained, and pinned against the dispatch's own arm count by
    /// [`fuzz_target_configures_every_custom_encoding_variant`] so it cannot fall
    /// behind the enum. Written as strings rather than matched on the enum
    /// because Rust offers no way to enumerate an enum's variants, and the target
    /// names them textually (`Encoding::Base64Url`), which is what the fuzz
    /// coverage is actually expressed in.
    fn custom_encoding_variant_names() -> Vec<&'static str> {
        vec![
            "Hex",
            "Base64",
            "Base64Url",
            "Base64NoPad",
            "Base64UrlNoPad",
        ]
    }

    /// How many arms `src/providers/custom.rs`'s `Encoding` decode dispatch has.
    ///
    /// Counted from the source rather than asserted as a literal, because the
    /// literal is the thing that rots: an arm added to the `match` is the change
    /// that needs new fuzz coverage, and this is what notices. Scoped to the
    /// dispatch by its two anchors so the `Display` impl's arms over the same
    /// enum — and every other mention of a variant in the module — are not
    /// counted in. Both anchors are load-bearing: losing the opening one means
    /// this silently reports zero arms and the list-length check fails loudly
    /// rather than passing.
    fn custom_encoding_dispatch_arm_count() -> usize {
        use std::fs;
        use std::path::Path;

        const OPEN: &str = "let bytes = match scheme.encoding {";
        const CLOSE: &str = "    };";

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/providers/custom.rs");
        let Ok(src) = fs::read_to_string(path) else {
            // The crate's own module: unreadable only if the manifest dir is
            // wrong, which no other test in this file survives either.
            return 0;
        };
        let Some(start) = src.find(OPEN) else {
            return 0;
        };
        let after_open = &src[start + OPEN.len()..];
        let Some(end) = after_open.find(CLOSE) else {
            return 0;
        };
        after_open[..end]
            .lines()
            .filter(|line| strip_comment(line).contains("Encoding::"))
            .count()
    }

    /// The count of code (non-comment) lines in the fuzz target that name
    /// `Encoding::<variant>`. Whole-line `//` comments and trailing `// …`
    /// comments are dropped first: the target documents each configuration's
    /// rationale in prose that names the very variants this counts, so a raw line
    /// count would be satisfied by a comment alone. A `//` inside a string
    /// literal would be mis-trimmed; the fuzz target has none, and this is a
    /// floor check over a repo-internal file, not a parser.
    fn fuzz_encoding_variant_hits(target: &str, variant: &str) -> usize {
        target
            .lines()
            .filter(|line| names_encoding_variant(strip_comment(line), variant))
            .count()
    }

    /// Whether `line` names `Encoding::<variant>` as a whole path segment.
    ///
    /// A plain substring search is not enough here, and the failure it allows is
    /// exactly the one this guard exists to catch: `Encoding::Base64` is a
    /// prefix of both `Encoding::Base64Url` and `Encoding::Base64NoPad`, so a
    /// target that configured only the two variants would satisfy a
    /// substring-based check for the third — under-reporting coverage rather
    /// than over-reporting it, which is the direction a reader would never
    /// notice. Requiring the next character to not continue an identifier makes
    /// each variant independently required.
    fn names_encoding_variant(line: &str, variant: &str) -> bool {
        let needle = format!("Encoding::{variant}");
        line.match_indices(&needle).any(|(at, _)| {
            line[at + needle.len()..]
                .chars()
                .next()
                .is_none_or(|next| !next.is_alphanumeric() && next != '_')
        })
    }

    /// `line` reduced to its code: a whole-line `//` comment and a trailing
    /// `// …` comment are both removed, so the result is the empty string when
    /// the line is nothing but prose and a substring search over it comes back
    /// false.
    ///
    /// Shared by [`fuzz_encoding_variant_hits`] and
    /// [`custom_encoding_dispatch_arm_count`], which both need to ignore prose.
    fn strip_comment(line: &str) -> &str {
        let line = line.trim_start();
        if line.starts_with("//") {
            return "";
        }
        match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        }
    }

    #[test]
    fn fuzz_encoding_variant_hits_ignores_prose() {
        // The positive side: a struct-literal configuration and a list element
        // naming the variant in code.
        let target = "\
            let a = CustomScheme { encoding: Encoding::Base64Url, ..d };
            for encoding in [Encoding::Base64, Encoding::Base64NoPad] {
        ";
        assert_eq!(fuzz_encoding_variant_hits(target, "Base64Url"), 1);
        assert_eq!(fuzz_encoding_variant_hits(target, "Base64NoPad"), 1);
        // A prefix is not a variant: `Base64Url` must not satisfy `Base64`.
        assert_eq!(fuzz_encoding_variant_hits(target, "Base64"), 1);

        // The negative side: only a module-doc bullet, a prose comment, and a
        // trailing mention — none of which configure the variant.
        let target = "\
//! - `custom-raw-base64-signature` — also reaching Encoding::Base64Url.
// The Base64Url arm picks up the URL_SAFE engine.
            let d = CustomScheme { encoding: Encoding::Base64, ..e }; // was Encoding::Base64Url
        ";
        assert_eq!(fuzz_encoding_variant_hits(target, "Base64Url"), 0);
        assert_eq!(fuzz_encoding_variant_hits(target, "Base64NoPad"), 0);
    }

    /// The positive side of [`custom_encoding_dispatch_arm_count`]: the real
    /// dispatch has one arm per listed variant today, and comments mentioning
    /// variants inside the match are not counted as extra arms.
    #[test]
    fn custom_encoding_dispatch_arm_count_matches_the_variant_list() {
        assert_eq!(
            custom_encoding_variant_names().len(),
            custom_encoding_dispatch_arm_count(),
            "the hand-maintained variant list must match `src/providers/custom.rs`'s `Encoding` \
             decode dispatch — `Display`'s arms over the same enum must not be counted, and a new \
             decoder arm must be added to the list"
        );
    }

    #[test]
    fn fuzz_seed_bullets_and_corpus_agree() {
        use std::fs;
        use std::path::Path;

        // The fuzz target's module-doc seed-corpus section (`spec.md` §5.6)
        // opens with one `//! - `name`` bullet per committed seed in
        // `fuzz/corpus/parse_and_verify/`. The IMPLEMENTED pool guard above
        // pins that section's *provider* list, but nothing pinned the *seeds*
        // themselves: a doc bullet naming a file that is never committed, or
        // a committed seed file with no doc bullet, ships silently and shrinks
        // the nightly fuzz surface or rots the seed docs without CI noticing —
        // the same class of miss as Mollie's corpus seed shipping absent
        // (PR #147, which the pool guard was written for but which this seam
        // never protected). This guard pins the two inventories to each other:
        // the sorted doc-bullet names must equal the sorted *committed* seed
        // names exactly, so adding, renaming, or dropping either side fails CI
        // instead of drifting. `Custom`-shaped seeds are covered too — they
        // are explicit target configurations, not name-constructible
        // providers, but their seeds are documented the same way.
        //
        // "Committed" is what the directory is asked for, not what it is: the
        // fuzzer appends its own digest-named working-corpus entries there on
        // every run (see [`is_fuzzer_discovered_input`]), so those are filtered
        // out — otherwise any local `cargo fuzz run` left the next `cargo test`
        // failing on a diff that is entirely fuzzer state (issue #241).
        //
        // Like the pool guard above, `fuzz/` is excluded from the crates.io
        // tarball (Cargo.toml `exclude`), so in a packaged checkout the
        // directory does not exist and the guard is skipped — it is a
        // repo-internal test, not part of the shipped crate's contract.
        let target = {
            let path =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets/parse_and_verify.rs");
            match fs::read_to_string(path) {
                Ok(src) => src,
                // `fuzz/` not present (e.g. the publish tarball): nothing to
                // guard against here, and the crate's own tests must not fail
                // on files it does not ship.
                Err(_) => return,
            }
        };
        let seed_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/parse_and_verify");

        let mut bullets: Vec<String> = target
            .lines()
            .filter_map(|line| {
                let rest = line.trim_start().strip_prefix("//! - `")?;
                let name = rest.split('`').next()?;
                Some(name.to_string())
            })
            .collect();
        bullets.sort();
        bullets.dedup();

        let mut files: Vec<String> = match fs::read_dir(&seed_dir) {
            Ok(entries) => entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| !is_fuzzer_discovered_input(name))
                .collect(),
            // `fuzz/corpus/parse_and_verify/` not present (e.g. the publish
            // tarball): same skip as above.
            Err(_) => return,
        };
        files.sort();

        assert_eq!(
            bullets,
            files,
            "fuzz seed doc bullets ({} in `fuzz_targets/parse_and_verify.rs`) must mirror the committed `fuzz/corpus/parse_and_verify/` seeds ({} found, ignoring the fuzzer's own digest-named working-corpus entries) exactly — a bullet for a never-committed seed or a committed seed with no doc bullet both fail here",
            bullets.len(),
            files.len(),
        );
    }

    /// Whether `name` is a file libFuzzer discovered and wrote for itself, as
    /// opposed to a seed this repository committed.
    ///
    /// `fuzz/corpus/parse_and_verify/` is the fuzzer's **working** corpus, not
    /// a read-only fixture directory: a plain `cargo fuzz run
    /// parse_and_verify` — the command `fuzz.yml` and `spec.md` §5.6/§6 use —
    /// appends every newly-interesting input it finds straight into it. Those
    /// entries are named after the hex digest of the input's contents (40
    /// lowercase hex digits, SHA-1; libFuzzer used MD5's 32 before that) and
    /// carry no extension, and `fuzz/.gitignore` ignores them so they are never
    /// committed. Counting them as seeds made this guard fail on the very next
    /// `cargo test` after any local fuzz run, with a ~1400-entry diff that
    /// says nothing about drift. Seeds carry descriptive names instead, so an
    /// entry that is entirely lowercase hex and at least 32 characters long is
    /// the fuzzer's own state.
    ///
    /// The bound is deliberately loose, and the failure direction is loud
    /// rather than silent: should libFuzzer ever change its naming so generated
    /// entries stop looking like digests, they land back in the comparison and
    /// [`fuzz_seed_bullets_and_corpus_agree`] fails again — the only way this
    /// predicate could hide drift is a *committed* seed named with 32+ hex
    /// characters, which no one writes by hand.
    fn is_fuzzer_discovered_input(name: &str) -> bool {
        name.len() >= 32
            && name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    #[test]
    fn fuzzer_discovered_inputs_are_told_apart_from_committed_seeds() {
        // The positive side: libFuzzer's own corpus entries, in the SHA-1 (40)
        // and MD5 (32) namings. The predicate keys off a *floor* rather than
        // an exact length, so any hash width at or above 128 bits is covered.
        assert!(is_fuzzer_discovered_input(
            "003ab18a2744aa4c3440c597ac82163be5ac2106"
        ));
        assert!(is_fuzzer_discovered_input(
            "d95c6b7477fbd7e9f90b1b0ef5f9c7ac"
        ));

        // The negative side: every committed seed is descriptive, so a real
        // seed must never be classified as fuzzer state — that would silently
        // drop an undocumented seed from the guard instead of failing on it.
        for seed in [
            "github-valid-delivery",
            "standard-webhooks-shape",
            "zoom-timestamped-delivery",
            // Short and near-miss names: descriptive, not digests.
            "box-two-signature-delivery",
            "circleci-signature",
            "deadbeef",
            "0badc0de",
            // Digest-shaped but not lowercase-hex throughout.
            "003AB18A2744AA4C3440C597AC82163BE5AC2106",
            "003ab18a2744aa4c3440c597ac82163be5ac210g",
            "003ab18a-2744aa4c-3440c597-ac82163b-e5ac2106",
            "003ab18a2744aa4c3440c597ac82163be5ac2106.bin",
        ] {
            assert!(!is_fuzzer_discovered_input(seed), "seed: {seed}");
        }
    }

    /// The `Provider::<Variant>` identifiers in the fuzz target's
    /// `const IMPLEMENTED: &[Provider] = &[ ... ];` block, in list order.
    /// Comments inside the block are skipped because only `Provider::`
    /// identifiers are collected. Test-only helper over the target's source
    /// text; the block delimiters are pinned by the assertion messages.
    fn fuzz_implemented_providers(target: &str) -> Vec<String> {
        let Some(start) = target.find("const IMPLEMENTED: &[Provider] = &[") else {
            panic!("fuzz target must declare `const IMPLEMENTED: &[Provider] = &[ ... ];`");
        };
        let Some(end) = target[start..].find("];") else {
            panic!("fuzz target's `const IMPLEMENTED` must close with `];`");
        };
        let block = &target[start..start + end];
        let mut listed: Vec<String> = Vec::new();
        let mut rest = block;
        while let Some(at) = rest.find("Provider::") {
            let after = &rest[at + "Provider::".len()..];
            let end = after
                .char_indices()
                .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
                .map_or(after.len(), |(idx, _)| idx);
            listed.push(after[..end].into());
            rest = &after[end..];
        }
        listed
    }

    /// The "Supported providers" table in `markdown` as
    /// `(brand cell, full row)` pairs, with the header and separator rows
    /// excluded (the crate-doc tables live in `//!` doc comments). Test
    /// helper over compile-time `include_str!` data, so the `.unwrap_or` fall
    /// back is unreachable.
    fn provider_table_rows(markdown: &str) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        let mut in_section = false;
        let mut collecting = false;
        for line in markdown.lines() {
            let line = line.strip_prefix("//!").unwrap_or(line).trim();
            if !in_section {
                if line.contains("## Supported providers") {
                    in_section = true;
                }
                continue;
            }
            if !collecting {
                if line.starts_with('|') {
                    collecting = true;
                } else {
                    continue;
                }
            }
            if let Some(rest) = line.strip_prefix('|') {
                let cell = rest.split('|').next().unwrap_or("").trim();
                if !cell.is_empty() && cell != "Provider" && !cell.starts_with('-') {
                    rows.push((String::from(cell), String::from(line)));
                }
            } else {
                break;
            }
        }
        rows
    }

    /// How many cells a GFM table row renders to: its *unescaped* `|`
    /// delimiters, less one.
    ///
    /// `n` delimiters open `n - 1` cells — the leading pipe opens the first,
    /// each interior one closes one cell and opens the next, and the trailing
    /// one closes the last. For `| A | B | C |` that is 4 pipes and 3 cells.
    ///
    /// The escaping is the whole point. GFM splits a row into cells on every
    /// `|`, **including one inside a code span** — a literal pipe in a cell's
    /// content has to be written `\|`, which renders as a bare `|` even inside
    /// a code span. A row that quotes a `|`-joined construction without
    /// escaping (PayPal's signed string is three of them) therefore does not
    /// render as a slightly-odd row: it splits, spilling the rest of the text
    /// into phantom columns and dropping the trailing ones, and nothing
    /// anywhere complains. Counting the `|` bytes the way a renderer would is
    /// what makes that visible, so `\|` is skipped and `\` is consumed as the
    /// escape it is (so `\\|` still counts — an escaped backslash leaves the
    /// pipe live).
    fn gfm_row_cell_count(row: &str) -> usize {
        let mut delimiters = 0_usize;
        let mut escaped = false;
        for byte in row.as_bytes() {
            match byte {
                b'\\' => escaped = !escaped,
                b'|' if !escaped => delimiters += 1,
                _ => escaped = false,
            }
        }
        delimiters.saturating_sub(1)
    }

    /// Every row of the "Supported providers" table in `markdown` — header,
    /// separator, and body — as `(row, rendered cell count)`.
    ///
    /// Unlike [`provider_table_rows`] nothing is excluded, because the header
    /// is what the body rows are compared *against*: a table's shape is
    /// declared by its header, and the check is "every row renders to the same
    /// number of cells as that header". Walks the section and normalizes
    /// crate-doc lines the same way (strip the `//!` marker, then trim). Test
    /// helper over compile-time `include_str!` data.
    fn provider_table_row_cell_counts(markdown: &str) -> Vec<(String, usize)> {
        let mut rows = Vec::new();
        let mut in_section = false;
        for line in markdown.lines() {
            let line = line.strip_prefix("//!").unwrap_or(line).trim();
            if !in_section {
                in_section = line.contains("## Supported providers");
                continue;
            }
            if !line.starts_with('|') {
                // The table is one contiguous run of `|`-prefixed lines; the
                // first line that is not one has ended it.
                if !rows.is_empty() {
                    break;
                }
                continue;
            }
            rows.push((String::from(line), gfm_row_cell_count(line)));
        }
        rows
    }

    /// The first-column brand-name cells of [`provider_table_rows`].
    fn provider_table_cells(markdown: &str) -> Vec<String> {
        provider_table_rows(markdown)
            .into_iter()
            .map(|(cell, _)| cell)
            .collect()
    }

    /// Whether a table cell's brand-name entry refers to `brand`. The cell is
    /// a human-readable name that may carry a parenthetical qualifier
    /// ("Expo (EAS ...)") or a rebrand spelling ("Mailchimp Transactional
    /// (Mandrill)"), so the match requires the brand to sit on a word
    /// boundary rather than be a bare substring — which would otherwise let
    /// e.g. `X` match `Xero` or `Expo`. Test helper.
    fn brand_cell_matches(cell: &str, brand: &str) -> bool {
        let mut search_from = 0;
        while let Some(hit) = cell[search_from..].find(brand) {
            let hit = search_from + hit;
            let before_ok = hit == 0 || matches!(cell.as_bytes()[hit - 1], b' ' | b'(');
            let after = hit + brand.len();
            let after_ok =
                after == cell.len() || matches!(cell.as_bytes()[after], b' ' | b'(' | b')');
            if before_ok && after_ok {
                return true;
            }
            search_from = hit + brand.len();
        }
        false
    }

    /// Whether `provider`'s *implementation* recency-checks the timestamp it
    /// signs, i.e. whether it calls the shared [`check_replay`] helper against
    /// `options.max_age` (spec.md §3's "Replay protection" claim).
    ///
    /// Read from the module's own source rather than from a duplicated test
    /// table so the guard cannot drift from the code it guards. Only the
    /// pre-`#[cfg(test)]` text counts: several providers exercise
    /// `check_replay` directly in their tests, which is not a claim about
    /// `verify()`. The brand/module stem mismatches are spelled out; every
    /// other module is named after its `Display` brand lowercased.
    /// `Custom` is included — it recency-checks only when a `timestamp_header`
    /// is configured, which is what its table row says.
    fn provider_replay_protected(provider: &Provider) -> bool {
        let stem = match provider {
            Provider::Box => "box_webhooks",
            Provider::LemonSqueezy => "lemonsqueezy",
            Provider::PayPal => "paypal",
            Provider::SendGrid => "sendgrid",
            Provider::StandardWebhooks => "standard_webhooks",
            Provider::X => "x_twitter",
            other => return module_calls_check_replay(&other.to_string().to_lowercase()),
        };
        module_calls_check_replay(stem)
    }

    /// Whether `src/providers/{stem}.rs`'s implementation calls [`check_replay`].
    fn module_calls_check_replay(stem: &str) -> bool {
        module_implementation(stem).contains("check_replay(")
    }

    /// The *implementation* half of `src/providers/{stem}.rs` — everything
    /// before its `#[cfg(test)]` module, so a provider that exercises a helper
    /// in its own tests does not masquerade as one whose `verify()` uses it.
    fn module_implementation(stem: &str) -> String {
        let source = module_source(stem);
        match source.find("#[cfg(test)]") {
            Some(at) => source[..at].to_string(),
            None => source,
        }
    }

    /// The whole source of `src/providers/{stem}.rs`, read from disk.
    ///
    /// Shared by the guards that scan a provider module
    /// ([`module_implementation`], [`module_test_names`]) so the path and the
    /// fail-closed read live in one place instead of drifting apart — the same
    /// anti-duplication reason the guards exist at all. Fail-closed rather than
    /// skipped: a provider module the suite cannot read is a module no scan can
    /// vouch for, so a read failure must fail the run instead of quietly
    /// reducing the covered set.
    fn module_source(stem: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/providers")
            .join(format!("{stem}.rs"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "reading {} for a source-scanning guard failed: {err} — every \
                 provider in `provider_list()` must have a module, and `src/` is \
                 shipped in the crates.io tarball so the guards can read it",
                path.display()
            )
        })
    }

    /// The `src/providers` module stem one provider's implementation lives in.
    ///
    /// Named after each provider's `Display` brand lowercased apart from the
    /// handful whose module name differs. Split out of
    /// [`provider_module_stems`] so a test that has to go from a stem back to
    /// the provider that owns it does not have to re-spell this map — a second
    /// copy of the provider-to-module map is a second thing to drift.
    fn provider_module_stem(provider: Provider) -> String {
        match provider {
            Provider::Box => "box_webhooks".to_string(),
            Provider::LemonSqueezy => "lemonsqueezy".to_string(),
            Provider::PayPal => "paypal".to_string(),
            Provider::SendGrid => "sendgrid".to_string(),
            Provider::StandardWebhooks => "standard_webhooks".to_string(),
            Provider::X => "x_twitter".to_string(),
            other => other.to_string().to_lowercase(),
        }
    }

    /// The `src/providers` module stem for every provider, in module order.
    fn provider_module_stems() -> Vec<String> {
        let mut stems: Vec<String> = provider_list()
            .into_iter()
            .map(provider_module_stem)
            .collect();
        // `provider_list()` cannot name `Provider::Custom` (it is not
        // name-constructible — it needs a `CustomScheme`), but the module
        // floors millisecond timestamps exactly as the built-ins do once
        // `TimestampUnit::Millis` is configured, so it belongs here by stem.
        stems.push("custom".to_string());
        stems
    }

    /// Every provider module that reads an epoch-*milliseconds* timestamp and
    /// so has to floor it to whole seconds before [`check_replay`].
    ///
    /// Derived from the modules themselves rather than a hand-written list, so a
    /// new millisecond-timestamp provider is covered by the floor guard below
    /// the moment it calls [`parse_millis`], with nobody remembering to extend
    /// a table. Read from source for the same reason as
    /// [`module_calls_check_replay`]: a duplicated list is a list that drifts.
    fn millisecond_timestamp_providers() -> Vec<String> {
        provider_module_stems()
            .into_iter()
            .filter(|stem| module_implementation(stem).contains("parse_millis("))
            .collect()
    }

    /// The reasons `millisecond_floors_use_the_shared_divisor` should fail, for
    /// one provider module's implementation text.
    fn millisecond_floor_offenders_in(stem: &str, implementation: &str) -> Vec<String> {
        // Comments are dropped first: a module doc that *describes* the floor
        // as `millis / 1000` is accurate prose, not a second spelling of the
        // divisor in code, and the guards would otherwise fail on the
        // documentation that explains them. Text up to a line's first `//` is
        // kept, so a trailing comment cannot hide a real floor but a `//` inside
        // a string literal only ever shortens what is scanned.
        let code: String = implementation
            .lines()
            .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n");
        let mut offenders = Vec::new();
        if code.contains("const MILLIS_PER_SECOND") {
            offenders.push(format!(
                "`src/providers/{stem}.rs` redeclares `MILLIS_PER_SECOND` instead of \
                 importing `core::replay::MILLIS_PER_SECOND`"
            ));
        }
        if code.contains("/ 1000") {
            offenders.push(format!(
                "`src/providers/{stem}.rs` floors with a literal `/ 1000` instead of \
                 `MILLIS_PER_SECOND`"
            ));
        }
        offenders
    }

    #[test]
    fn millisecond_floors_use_the_shared_divisor() {
        // A millisecond timestamp must reach `check_replay` (which compares
        // whole seconds, spec.md §3) divided by one shared divisor,
        // `core::replay::MILLIS_PER_SECOND`, living beside the `parse_millis`
        // that produces the value. Getting the divisor wrong is not a cosmetic
        // error: a millisecond value compared *without* flooring sits ~5.7e10
        // seconds in the future, so every delivery fails the window with a
        // `skew` that reads like a `max_age` misconfiguration and invites
        // widening the tolerance until the check is vacuous. That is exactly
        // the failure `TimestampUnit` (issue #273) was added to prevent.
        //
        // The drift this removes was real, not hypothetical: seven provider
        // modules each had their own copy — five named `const`s and two bare
        // `1000` literals — and only a human reading all seven kept them in
        // agreement.
        //
        // Two independent shapes, because either alone is satisfiable by the
        // wrong thing: a module may not *declare* the divisor, and a module
        // that reads millisecond timestamps may not spell it inline at all.
        // Both are keyed on the module's own `parse_millis(` call rather than a
        // fixed provider list, so the next millisecond-timestamp provider is
        // covered without editing a table.
        let offenders: Vec<String> = millisecond_timestamp_providers()
            .iter()
            .flat_map(|stem| millisecond_floor_offenders_in(stem, &module_implementation(stem)))
            .collect();
        assert!(
            offenders.is_empty(),
            "the millisecond→second floor must go through \
             `core::replay::MILLIS_PER_SECOND` — {}",
            offenders.join("; ")
        );
    }

    #[test]
    fn millisecond_floor_offenders_separates_agreeing_from_drifting() {
        // The list is derived from the modules themselves, so pin that
        // derivation: every provider that reads millisecond timestamps must be
        // found (one silently dropping out would make the guard above vacuous
        // for it), and nothing that reads whole-second timestamps may be swept
        // in (which would have the guard fail on an unrelated literal).
        let providers = millisecond_timestamp_providers();
        for expected in [
            "airwallex",
            "contentful",
            "custom",
            "hubspot",
            "ripple",
            "webflow",
            "workos",
        ] {
            assert!(
                providers.iter().any(|stem| stem == expected),
                "`{expected}.rs` reads epoch-millisecond timestamps, so the floor guard must \
                 cover it; derived list is {providers:?}"
            );
        }
        assert!(
            !providers.iter().any(|stem| stem == "stripe"),
            "Stripe's timestamp is whole seconds and must not be swept into the millisecond \
             floor guard; derived list is {providers:?}"
        );

        // The reporting itself, over synthetic module text: an implementation
        // that imports the shared constant and floors with it reports nothing,
        // and each drift shape is reported on its own. Merely *mentioning* the
        // constant is not a redeclaration, so the first case must stay quiet.
        let agree = "use crate::core::replay::{MILLIS_PER_SECOND, check_replay, parse_millis};\n\
                     fn verify() { check_replay(parse_millis(h, v)? / MILLIS_PER_SECOND, o) }";
        assert!(millisecond_floor_offenders_in("airwallex", agree).is_empty());

        // Prose that *describes* the floor is documentation, not a second
        // spelling of the divisor in code, and must not trip the guard.
        let documented = "//! floored to whole seconds (`millis / 1000`) before the shared check\n\
                          /// Mirrors `MILLIS_PER_SECOND`.\n\
                          fn verify() { check_replay(parse_millis(h, v)? / MILLIS_PER_SECOND, o) }";
        assert!(millisecond_floor_offenders_in("airwallex", documented).is_empty());

        let literal = "fn verify() { check_replay(parse_millis(h, v)? / 1000, o) }";
        let literal_offenders = millisecond_floor_offenders_in("airwallex", literal);
        assert_eq!(literal_offenders.len(), 1, "{literal_offenders:?}");
        assert!(
            literal_offenders[0].contains("/ 1000"),
            "{literal_offenders:?}"
        );

        let redeclared = "const MILLIS_PER_SECOND: u64 = 1000;\n\
                          fn verify() { check_replay(parse_millis(h, v)? / MILLIS_PER_SECOND, o) }";
        let redeclared_offenders = millisecond_floor_offenders_in("airwallex", redeclared);
        assert_eq!(redeclared_offenders.len(), 1, "{redeclared_offenders:?}");
        assert!(
            redeclared_offenders[0].contains("redeclares"),
            "{redeclared_offenders:?}"
        );
    }

    /// The number of providers a piece of prose claims timestamp in
    /// milliseconds, read from the spelled-out number that opens its "… N
    /// providers timestamp in milliseconds" clause.
    ///
    /// `None` when the prose states no count, which is the case for the
    /// `parse_millis` / `timestamp_unit` docs — they name the providers and let
    /// the list speak for itself. Number *words* only: the clause also
    /// contains the crate's fixed "58 built-in" total, and a reader looking at
    /// "Six of the 58 built-in providers" is reading a count, not a total.
    fn claimed_millisecond_provider_count(prose: &str) -> Option<usize> {
        const NUMBER_WORDS: [(&str, usize); 10] = [
            ("one", 1),
            ("two", 2),
            ("three", 3),
            ("four", 4),
            ("five", 5),
            ("six", 6),
            ("seven", 7),
            ("eight", 8),
            ("nine", 9),
            ("ten", 10),
        ];

        // Bounded to one..ten deliberately: that covers any provider count this
        // crate could reach, so a wider table would only add number words a
        // "… providers timestamp in milliseconds" clause never contains.
        let lower = prose.to_lowercase();
        let mut found: Vec<(usize, usize)> = Vec::new();
        for (word, value) in NUMBER_WORDS {
            let mut from = 0;
            while let Some(offset) = lower[from..].find(word) {
                let at = from + offset;
                from = at + word.len();
                // A whole word on both sides, so "one" is not found inside
                // "money" and "six" is not found inside "sixteen".
                let starts_a_word = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphabetic();
                let ends_a_word = lower[from..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_alphabetic());
                if starts_a_word && ends_a_word {
                    found.push((at, value));
                }
            }
        }
        // Each claim is the clause its number opens, running to the next
        // number word, so a count is never read across two claims.
        found.sort_unstable();
        let mut counts = Vec::new();
        for (index, (at, value)) in found.iter().enumerate() {
            let end = found.get(index + 1).map_or(lower.len(), |(next, _)| *next);
            if lower[*at..end].contains("provider") {
                counts.push(*value);
            }
        }
        counts.into_iter().min()
    }

    /// Every provider that reads an epoch-milliseconds timestamp is named in
    /// the prose that tells a caller to declare [`TimestampUnit::Millis`].
    ///
    /// `TimestampUnit` (issue #273) exists because the shared replay window
    /// compares whole seconds, so a scheme's timestamp header has to declare
    /// which unit it is in. The only thing that tells a caller which unit a
    /// given sender uses is these hand-written lists of the millisecond
    /// providers, and there are six of them, spread over
    /// `src/providers/custom.rs`, `src/core/replay.rs` and `spec.md` §2. Nothing
    /// tied them to the code: `millisecond_floors_use_the_shared_divisor`
    /// verifies *how* each module floors, never *which* modules floor, so a
    /// provider that adopts millisecond timestamps would ship with every one of
    /// those lists still saying six — the same failure shape as issues #235,
    /// #267 and #268, where a re-spelled literal silently disabled a guard.
    ///
    /// The reader list is derived from the modules, exactly as
    /// `millisecond_timestamp_providers` derives it for the floor guard, so a
    /// new millisecond-timestamp provider fails CI until the prose names it.
    /// `custom` is excluded from both the names and the count: it floors only
    /// once a caller configures `TimestampUnit::Millis`, so it is the mechanism
    /// being documented here rather than a sender somebody would prototype.
    ///
    /// The count is checked only where the prose states one, for the same
    /// reason only the forward direction is checked: a region that names all
    /// seven but still says "Six" is a real defect, but a region that names
    /// none and states no count says nothing false either. The reverse of the
    /// name check is deliberately not asserted, matching
    /// `context_option_field_docs_name_every_provider_that_reads_the_option`:
    /// these regions cite providers for other reasons too — the `parse_millis`
    /// doc pairs each with its header name, and a "whole-second provider's"
    /// aside is not a claim to be a millisecond one.
    #[test]
    fn millisecond_timestamp_docs_name_every_millisecond_provider() {
        use std::collections::BTreeSet;

        /// The contiguous run of `///` / `//!` comment lines immediately above
        /// the line containing `declaration`, joined into one string.
        fn doc_above(source: &str, declaration: &str) -> String {
            let is_doc = |line: &str| {
                let trimmed = line.trim_start();
                trimmed.starts_with("///") || trimmed.starts_with("//!")
            };
            let lines: Vec<&str> = source.lines().collect();
            let at = lines
                .iter()
                .position(|line| line.contains(declaration))
                .unwrap_or_else(|| {
                    panic!("no line contains {declaration:?}, so its docs cannot be checked")
                });
            let start = lines[..at]
                .iter()
                .rposition(|line| !is_doc(line))
                .map_or(0, |last_code| last_code + 1);
            lines[start..at].join(" ")
        }

        /// A module's leading `//!` documentation, joined into one string.
        fn module_doc(source: &str) -> String {
            source
                .lines()
                .map_while(|line| line.trim_start().starts_with("//!").then_some(line.trim()))
                .collect::<Vec<_>>()
                .join(" ")
        }

        /// The blank-line-delimited `spec.md` paragraph containing `needle`.
        fn spec_paragraph(spec: &str, needle: &str) -> String {
            let lines: Vec<&str> = spec.lines().collect();
            let at = lines
                .iter()
                .position(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("spec.md has no paragraph containing {needle:?}"));
            let start = lines[..at]
                .iter()
                .rposition(|line| line.trim().is_empty())
                .map_or(0, |last_blank| last_blank + 1);
            let end = lines[at..]
                .iter()
                .position(|line| line.trim().is_empty())
                .map_or(lines.len(), |first_blank| at + first_blank);
            lines[start..end].join(" ")
        }

        let custom = include_str!("custom.rs");
        let replay = include_str!("../core/replay.rs");
        let spec = include_str!("../../spec.md");

        // Same derivation the floor guard uses, mapped to the `Display` brand
        // the prose has to spell.
        let flooring: BTreeSet<String> = millisecond_timestamp_providers()
            .iter()
            .filter(|stem| stem.as_str() != "custom")
            .map(|stem| {
                provider_list()
                    .into_iter()
                    .find(|provider| provider_module_stem(*provider) == *stem)
                    .unwrap_or_else(|| {
                        panic!("{stem}.rs reads millisecond timestamps but is not a provider")
                    })
                    .to_string()
            })
            .collect();

        // A vacuity guard: an empty derivation would make the naming loop
        // assert nothing at all.
        assert!(
            flooring.len() > 1,
            "expected several providers to read epoch-millisecond timestamps, but the modules \
             yielded {flooring:?} — the `parse_millis(` scan behind \
             `millisecond_timestamp_providers` has stopped matching, so this guard would pass \
             without checking anything"
        );

        let regions: [(&str, String); 6] = [
            ("src/providers/custom.rs module docs", module_doc(custom)),
            (
                "`TimestampUnit::Millis` docs",
                doc_above(custom, "    Millis,"),
            ),
            (
                "`CustomScheme::timestamp_unit` docs",
                doc_above(custom, "    pub timestamp_unit: TimestampUnit,"),
            ),
            (
                "core::replay `parse_millis` docs",
                doc_above(replay, "pub(crate) fn parse_millis("),
            ),
            (
                "core::replay `parse_unsigned_decimal` docs",
                doc_above(replay, "fn parse_unsigned_decimal("),
            ),
            (
                "spec.md §2 `CustomScheme` timestamp-unit requirement",
                spec_paragraph(spec, "millisecond providers do"),
            ),
        ];

        for (label, prose) in &regions {
            for brand in &flooring {
                assert!(
                    prose.contains(brand.as_str()),
                    "{label} does not name {brand}, whose module reads an epoch-millisecond \
                     timestamp (`parse_millis`). A caller choosing between `TimestampUnit::Seconds` \
                     and `TimestampUnit::Millis` from this prose would pick the wrong unit, and \
                     every such delivery would then fail the replay window with an implausible \
                     `skew` that reads like a `max_age` misconfiguration"
                );
            }
            if let Some(claimed) = claimed_millisecond_provider_count(prose) {
                assert_eq!(
                    claimed,
                    flooring.len(),
                    "{label} says {claimed} provider(s) timestamp in milliseconds, but {} \
                     modules call `parse_millis` ({}); the count and the list have to agree, or a \
                     reader is told the list is exhaustive when it is not",
                    flooring.len(),
                    flooring.iter().cloned().collect::<Vec<_>>().join(", "),
                );
            }
        }

        // The readers themselves, over synthetic text: each helper has to pick
        // the one region it is meant to pick. A helper that silently returned
        // the whole file would make every naming assertion above vacuous.
        let source = "\
//! module doc

/// item doc
pub struct S {
    /// field doc
    pub f: u8,
}
";
        assert_eq!(module_doc(source), "//! module doc");
        assert_eq!(doc_above(source, "    pub f: u8,"), "    /// field doc");
        // A declaration's docs stop at the last line of code above them, so
        // the module doc is not absorbed into the item's.
        assert_eq!(doc_above(source, "pub struct S {"), "/// item doc");
        // A code line ending a run of comments is the only thing that
        // separates two docs; without one they are a single region.
        assert_eq!(
            doc_above("/// a\n/// b\npub struct S {}", "pub struct S {"),
            "/// a /// b"
        );

        assert_eq!(
            claimed_millisecond_provider_count(
                "Six of the 58 built-in providers timestamp in milliseconds (HubSpot)."
            ),
            Some(6)
        );
        assert_eq!(
            claimed_millisecond_provider_count("exactly as the six millisecond providers do."),
            Some(6)
        );
        // The "58 built-in" total is a provider count but not *this* count, and
        // a region that names the providers without counting them states none.
        assert_eq!(
            claimed_millisecond_provider_count("58 built-in providers in total."),
            None
        );
        assert_eq!(
            claimed_millisecond_provider_count("as HubSpot and Webflow all do."),
            None
        );
        // A number word that appears only *inside* a longer word is not a
        // count claim, on either side of the word — and a number word outside
        // `one..=ten` is not read at all.
        assert_eq!(
            claimed_millisecond_provider_count("Seventeen providers timestamp in milliseconds."),
            None
        );
        assert_eq!(
            claimed_millisecond_provider_count("the phone-provider survey"),
            None
        );
        assert_eq!(
            claimed_millisecond_provider_count("Sixteen providers timestamp in milliseconds."),
            None
        );
    }

    #[cfg(any(feature = "http", feature = "tower", feature = "actix"))]
    #[test]
    fn signature_header_names_cover_every_provider_header() {
        // `signature_header_names` is the list the tower/actix adapters — and,
        // since the `http` feature, the public `ambiguous_signature_header` —
        // scan for conflicting duplicate headers (spec.md §4.4). It is the
        // mechanism that stops a proxy from smuggling a forged value in a
        // duplicate header the verifier reads while the validator does not.
        // This guard pins each provider's scan-visible headers to the exact
        // constants its implementation reads, so a header dropped from the
        // list — say `HubSpot` losing its timestamp — is caught instead of
        // silently weakening the ambiguity check. Keep this table in lockstep
        // with `signature_header_names` when a provider changes.
        let cases: &[(Provider, &[&str])] = &[
            (Provider::Stripe, &[stripe::SIGNATURE_HEADER]),
            (Provider::GitHub, &[github::SIGNATURE_HEADER]),
            (Provider::Bitbucket, &[bitbucket::SIGNATURE_HEADER]),
            (
                Provider::Contentful,
                &[
                    contentful::SIGNATURE_HEADER,
                    contentful::SIGNED_HEADERS_HEADER,
                    contentful::TIMESTAMP_HEADER,
                ],
            ),
            (
                Provider::Box,
                &[
                    box_webhooks::PRIMARY_SIGNATURE_HEADER,
                    box_webhooks::SECONDARY_SIGNATURE_HEADER,
                    box_webhooks::TIMESTAMP_HEADER,
                    box_webhooks::SIGNATURE_VERSION_HEADER,
                    box_webhooks::SIGNATURE_ALGORITHM_HEADER,
                ],
            ),
            (Provider::Intercom, &[intercom::SIGNATURE_HEADER]),
            (Provider::Expo, &[expo::SIGNATURE_HEADER]),
            (Provider::Meta, &[meta::SIGNATURE_HEADER]),
            (
                Provider::HubSpot,
                &[hubspot::SIGNATURE_HEADER, hubspot::TIMESTAMP_HEADER],
            ),
            (
                Provider::Klaviyo,
                &[klaviyo::SIGNATURE_HEADER, klaviyo::TIMESTAMP_HEADER],
            ),
            (Provider::Mandrill, &[mandrill::SIGNATURE_HEADER]),
            (Provider::Line, &[line::SIGNATURE_HEADER]),
            (Provider::Shopify, &[shopify::SIGNATURE_HEADER]),
            (
                Provider::Slack,
                &[slack::SIGNATURE_HEADER, slack::TIMESTAMP_HEADER],
            ),
            (Provider::Square, &[square::SIGNATURE_HEADER]),
            (Provider::Tally, &[tally::SIGNATURE_HEADER]),
            (Provider::FastSpring, &[fastspring::SIGNATURE_HEADER]),
            (Provider::GoCardless, &[gocardless::SIGNATURE_HEADER]),
            (Provider::Mollie, &[mollie::SIGNATURE_HEADER]),
            (Provider::Twilio, &[twilio::SIGNATURE_HEADER]),
            (
                Provider::Twitch,
                &[
                    twitch::MESSAGE_ID_HEADER,
                    twitch::TIMESTAMP_HEADER,
                    twitch::SIGNATURE_HEADER,
                ],
            ),
            (Provider::Typeform, &[typeform::SIGNATURE_HEADER]),
            (Provider::Paystack, &[paystack::SIGNATURE_HEADER]),
            (
                Provider::Discord,
                &[discord::SIGNATURE_HEADER, discord::TIMESTAMP_HEADER],
            ),
            (Provider::Linear, &[linear::SIGNATURE_HEADER]),
            (Provider::LaunchDarkly, &[launchdarkly::SIGNATURE_HEADER]),
            (Provider::Notion, &[notion::SIGNATURE_HEADER]),
            (Provider::Nylas, &[nylas::SIGNATURE_HEADER]),
            (Provider::Cloudflare, &[cloudflare::SIGNATURE_HEADER]),
            (Provider::CircleCi, &[circleci::SIGNATURE_HEADER]),
            (Provider::Coinbase, &[coinbase::SIGNATURE_HEADER]),
            (Provider::Dropbox, &[dropbox::SIGNATURE_HEADER]),
            (Provider::DocuSign, &[docusign::SIGNATURE_HEADER]),
            (Provider::Fintoc, &[fintoc::SIGNATURE_HEADER]),
            (Provider::Razorpay, &[razorpay::SIGNATURE_HEADER]),
            (Provider::Recharge, &[recharge::SIGNATURE_HEADER]),
            (
                Provider::Ripple,
                &[ripple::SIGNATURE_HEADER, ripple::TIMESTAMP_HEADER],
            ),
            (Provider::LemonSqueezy, &[lemonsqueezy::SIGNATURE_HEADER]),
            (Provider::Xero, &[xero::SIGNATURE_HEADER]),
            (Provider::Sentry, &[sentry::SIGNATURE_HEADER]),
            (Provider::Adyen, &[adyen::SIGNATURE_HEADER]),
            (
                Provider::Airwallex,
                &[airwallex::SIGNATURE_HEADER, airwallex::TIMESTAMP_HEADER],
            ),
            (Provider::Mux, &[mux::SIGNATURE_HEADER]),
            (Provider::Paddle, &[paddle::SIGNATURE_HEADER]),
            (Provider::PagerDuty, &[pagerduty::SIGNATURE_HEADER]),
            (Provider::Pusher, &[pusher::SIGNATURE_HEADER]),
            (
                Provider::Zendesk,
                &[zendesk::SIGNATURE_HEADER, zendesk::TIMESTAMP_HEADER],
            ),
            (Provider::WorkOS, &[workos::SIGNATURE_HEADER]),
            (Provider::WooCommerce, &[woocommerce::SIGNATURE_HEADER]),
            (Provider::Calendly, &[calendly::SIGNATURE_HEADER]),
            (Provider::Vercel, &[vercel::SIGNATURE_HEADER]),
            (
                Provider::Webflow,
                &[webflow::SIGNATURE_HEADER, webflow::TIMESTAMP_HEADER],
            ),
            (Provider::X, &[x_twitter::SIGNATURE_HEADER]),
            (Provider::Tailscale, &[tailscale::SIGNATURE_HEADER]),
            (
                Provider::Zoom,
                &[zoom::SIGNATURE_HEADER, zoom::TIMESTAMP_HEADER],
            ),
            (
                Provider::StandardWebhooks,
                &[
                    standard_webhooks::ID_HEADER,
                    standard_webhooks::TIMESTAMP_HEADER,
                    standard_webhooks::SIGNATURE_HEADER,
                    standard_webhooks::SVIX_ID_HEADER,
                    standard_webhooks::SVIX_TIMESTAMP_HEADER,
                    standard_webhooks::SVIX_SIGNATURE_HEADER,
                ],
            ),
            // Custom covers its declared headers: `signature_header`,
            // `timestamp_header`, and whatever `signed_headers` adds (issue
            // #395) — deduplicated against the first two, so the repeat of the
            // signature header below must not show up twice. A header the
            // closure reads but the scheme did not declare stays outside the
            // scan (documented caveat on `CustomScheme`).
            (
                Provider::Custom(CustomScheme {
                    hash: HashAlg::Sha256,
                    signature_header: "X-Acme-Signature",
                    timestamp_header: Some("X-Acme-Timestamp"),
                    timestamp_unit: TimestampUnit::Seconds,
                    encoding: Encoding::Hex,
                    prefix: None,
                    signed_headers: &[],
                    signed_string: |_headers, raw_body| raw_body.to_vec(),
                }),
                &["X-Acme-Signature", "X-Acme-Timestamp"],
            ),
            (
                Provider::Custom(CustomScheme {
                    hash: HashAlg::Sha256,
                    signature_header: "X-Acme-Signature",
                    timestamp_header: None,
                    timestamp_unit: TimestampUnit::Seconds,
                    encoding: Encoding::Hex,
                    prefix: None,
                    signed_headers: &[],
                    signed_string: |_headers, raw_body| raw_body.to_vec(),
                }),
                &["X-Acme-Signature"],
            ),
            (
                Provider::Custom(
                    CustomScheme::new(
                        HashAlg::Sha256,
                        "X-Acme-Signature",
                        Encoding::Hex,
                        |_headers, raw_body| raw_body.to_vec(),
                    )
                    .with_timestamp_header("X-Acme-Timestamp")
                    .with_signed_headers(&["X-Acme-Nonce", "x-acme-signature"]),
                ),
                &["X-Acme-Signature", "X-Acme-Timestamp", "X-Acme-Nonce"],
            ),
        ];
        for &(ref provider, expected) in cases {
            assert_eq!(
                signature_header_names(provider),
                expected,
                "must cover every header `{provider}` reads"
            );
        }

        #[cfg(feature = "sendgrid")]
        assert_eq!(
            signature_header_names(&Provider::SendGrid),
            vec![sendgrid::SIGNATURE_HEADER, sendgrid::TIMESTAMP_HEADER],
            "must cover every header `SendGrid` reads"
        );
        #[cfg(feature = "paypal")]
        assert_eq!(
            signature_header_names(&Provider::PayPal),
            vec![
                paypal::TRANSMISSION_ID_HEADER,
                paypal::TRANSMISSION_TIME_HEADER,
                paypal::TRANSMISSION_SIG_HEADER,
                paypal::CERT_URL_HEADER,
                paypal::AUTH_ALGO_HEADER,
            ],
            "must cover every header `PayPal` reads"
        );
        // Feature-disabled providers report an empty list: verification fails
        // closed with `UnsupportedProvider`, so the adapters have nothing to
        // scan for.
        #[cfg(not(feature = "sendgrid"))]
        assert!(
            signature_header_names(&Provider::SendGrid).is_empty(),
            "feature-disabled `SendGrid` must expose no headers to scan"
        );
        #[cfg(not(feature = "paypal"))]
        assert!(
            signature_header_names(&Provider::PayPal).is_empty(),
            "feature-disabled `PayPal` must expose no headers to scan"
        );

        // Every name-constructible provider must expose a non-empty,
        // non-duplicated list, so a future provider whose verification reads
        // headers through a path this table does not cover cannot silently
        // produce an empty or self-conflicting scan. `PayPal`/`SendGrid` are
        // covered by the cfg-specific assertions above.
        for provider in provider_list() {
            if matches!(provider, Provider::PayPal | Provider::SendGrid) {
                continue;
            }
            let names = signature_header_names(&provider);
            assert!(
                !names.is_empty(),
                "`{provider}` must expose headers to scan"
            );
            let mut deduped = names.clone();
            deduped.sort();
            deduped.dedup();
            assert_eq!(
                names.len(),
                deduped.len(),
                "`{provider}` must not list a header more than once"
            );
        }
    }

    /// The header names `src/providers/{stem}.rs` declares, as
    /// `(constant, header name)`, read from the module's own implementation
    /// text ([`module_implementation`]).
    ///
    /// Source-derived for the reason [`millisecond_timestamp_providers`] is: a
    /// duplicated list is a list that drifts, and a guard over a *table* can
    /// only catch a table that disagrees with the code, not code that both the
    /// table and the guard forgot. Three shapes are deliberately not matched:
    ///
    /// - Anything that is not a `&str` — `contentful::SIGNED_HEADERS_SEPARATOR`
    ///   is a `char`, and the millisecond helpers declare `u64`/`usize`.
    /// - Anything whose name does not end in `_HEADER`: `SIGNATURE_PREFIX`,
    ///   `SCHEME`, and `SECRET_PREFIX` are scheme vocabulary, and adding one to
    ///   the scan list would be a name no header map could even look up.
    /// - Test-module constants, which are excluded for free — they live after
    ///   the `#[cfg(test)]` cut, and several (`DOCS_EXAMPLE_HEADER` and
    ///   friends) carry a header *value* rather than a name.
    fn declared_header_constants(implementation: &str) -> Vec<(&str, &str)> {
        implementation
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let declaration = line
                    .strip_prefix("pub(crate) const ")
                    .or_else(|| line.strip_prefix("pub const "))
                    .or_else(|| line.strip_prefix("const "))?;
                let (constant, rest) = declaration.split_once(": &str = \"")?;
                if !constant.ends_with("_HEADER") {
                    return None;
                }
                let (name, tail) = rest.split_once('"')?;
                // Require the closing quote to end the declaration, so a line
                // that merely *mentions* a `&str` constant cannot be mistaken
                // for one.
                if !tail.trim_start().starts_with(';') {
                    return None;
                }
                Some((constant, name))
            })
            .collect()
    }

    /// Header names `provider` declares but deliberately keeps out of the
    /// §4.4 ambiguity scan, each with a reason recorded in the match arm.
    ///
    /// Security-relevant in the same way as
    /// [`provider_sent_duplicate_headers`]: a name here is one the scan never
    /// inspects. So the list is asserted in both directions by
    /// `every_declared_provider_header_is_scanned_for_ambiguity` below —
    /// without the stale-entry check, a renamed constant would leave an
    /// exemption that exempts nothing, which is the failure mode a reviewer
    /// would never notice.
    fn declared_headers_outside_the_scan(provider: &Provider) -> &'static [&'static str] {
        match provider {
            // Klaviyo's `Klaviyo-Webhook-Id` is **not signing material**.
            // Klaviyo directs integrators to compare it against the body's
            // `meta.klaviyo_webhook_id` *after* verification, which needs the
            // body deserialized — a non-goal for this crate (`spec.md` §1, and
            // the Klaviyo row of §3). The constant is `pub` so a caller can
            // spell that pair check, and `verify()` never reads the header, so
            // there is no first-match lookup for a duplicate to hide from.
            // §4.4 requires the scan to cover "every header the *scheme*
            // declares", and this header is not part of the signed string, so
            // scanning it would be inert at best.
            Provider::Klaviyo => &[klaviyo::WEBHOOK_ID_HEADER],
            _ => &[],
        }
    }

    // Ungated, like `signature_header_names_are_valid_http_field_names` below:
    // this reads only module sources and `signature_header_names`, both
    // unconditional, so it runs in the base `no_std` build too.
    #[test]
    fn every_declared_provider_header_is_scanned_for_ambiguity() {
        use std::collections::BTreeSet;

        // `signature_header_names_cover_every_provider_header` above pins the
        // scan list to a hand-written table, so it catches a *list* that
        // disagrees with the table. What it cannot catch is a table and a list
        // that agree with each other and both forget a header the
        // implementation reads — which is precisely the state a new signing
        // header is added in. This guard closes that hole by reading the
        // constant each module declares instead of a table, so the §4.4 claim
        // it defends ("for built-in providers the scan covers every header the
        // scheme declares") fails the build the moment a provider grows a
        // timestamp, a per-delivery id, or an algorithm tag that the scan list
        // does not follow. Nothing else in the suite notices that gap: the
        // provider still verifies correctly, because the duplicate is a
        // smuggling vector rather than a wrong signature.
        let mut checked = 0usize;
        for provider in provider_list() {
            // `paypal.rs`/`sendgrid.rs` are compiled out without their feature
            // and their scan lists are empty by design (`UnsupportedProvider`
            // fails closed before a header is read), so there is nothing to
            // compare in that configuration. `Provider::Custom` is not in
            // `provider_list()` at all — it is not name-constructible, and its
            // two scanned names are caller-typed rather than in-crate
            // constants, so there is no declaration to derive them from.
            // Two feature-gated providers, one feature each, so this reads as
            // two independent tests rather than a match on `provider`: the
            // match form collapsed to a literal `match` once `cfg!` expanded
            // both arms to `false`, and clippy's `match_like_matches_macro`
            // fired on any build without `sendgrid`/`paypal` — including
            // `--features actix` and `--features tower`, the two adapter
            // configurations CI did not build (issue #335). The rewrite keeps
            // the same per-provider semantics: a variant is compiled in unless
            // it is the feature-gated one whose feature is off.
            let compiled_in = (provider != Provider::PayPal || cfg!(feature = "paypal"))
                && (provider != Provider::SendGrid || cfg!(feature = "sendgrid"));
            if !compiled_in {
                continue;
            }

            let stem = provider_module_stem(provider);
            let implementation = module_implementation(&stem);
            let declared = declared_header_constants(&implementation);
            assert!(
                !declared.is_empty(),
                "`src/providers/{stem}.rs` declares no `*_HEADER: &str` constant in its \
                 implementation, so this guard checks nothing for `{provider}` — either the \
                 constants lost their `_HEADER` suffix or the module reads header names in a \
                 shape the derivation does not follow"
            );

            let scan: BTreeSet<&str> = signature_header_names(&provider)
                .into_iter()
                .collect::<BTreeSet<&str>>();
            let exempt: BTreeSet<&str> = declared_headers_outside_the_scan(&provider)
                .iter()
                .copied()
                .collect::<BTreeSet<&str>>();

            for &(constant, name) in &declared {
                if exempt.contains(name) {
                    continue;
                }
                assert!(
                    scan.contains(name),
                    "`src/providers/{stem}.rs` declares `{constant}` = `{name}`, but \
                     `signature_header_names` does not list it — the §4.4 ambiguity scan \
                     would ignore a conflicting duplicate of a header `{provider}` reads, so \
                     add it to `signature_header_names` (spec.md §4.4)"
                );
                checked += 1;
            }

            for name in &exempt {
                assert!(
                    declared
                        .iter()
                        .any(|(_, declared_name)| *declared_name == *name),
                    "`{provider}` is exempt from the ambiguity scan for `{name:?}`, but \
                     `src/providers/{stem}.rs` no longer declares that header — the exemption \
                     now exempts nothing and the reason recorded for it no longer applies"
                );
            }
        }

        // Vacuity guard: the count must rise with every header a provider
        // grows, so a derivation that quietly stops matching declarations
        // fails the build instead of passing over an empty set. One per
        // provider is the floor the count can never drop below without a
        // provider actually losing a header.
        assert!(
            checked >= provider_list().len(),
            "expected at least one scanned header per provider, but only {checked} \
             declarations were matched across {} providers — the `declared_header_constants` \
             derivation has stopped matching",
            provider_list().len()
        );
    }

    // Ungated: `signature_header_names` and `is_valid_field_name` are both
    // unconditional now (the pair-table entry point ships with no features), so
    // this guard runs in the base `no_std` build too rather than only in the
    // configurations that happened to compile the scan when it was written.
    #[test]
    fn signature_header_names_are_valid_http_field_names() {
        // The guard above pins *which* headers each provider's ambiguity scan
        // covers; this one pins that every one of those names is a name the
        // `http`/`actix-web` header maps can actually represent. The adapters
        // and the public `ambiguous_signature_header` all turn the scan list
        // into a `HeaderName` via `HeaderName::from_bytes`, and an unparseable
        // name there is **indistinguishable from a smuggled duplicate**:
        // `MultiValueHeaders::get_all_bytes` returns `None` and
        // `has_conflicting_duplicates` reports the header as ambiguous
        // (pinned by `unparseable_scan_name_reads_as_ambiguous` below). So a
        // single typo'd constant — a space, a stray `\r`, a non-ASCII byte —
        // does not merely weaken the check, it makes the scan reject
        // *every* delivery for that provider: with a 400 whose body is empty by
        // design ("no error detail leaks over the wire") in the adapters, and
        // with a `Some(_)` a `http`-feature caller is told to reject, leaving
        // an operator with a total, undiagnosable outage. `verify()` called
        // directly would still pass, because the crate's own `HeaderMap` impls
        // compare header names as plain case-insensitive strings.
        //
        // RFC 9110 §5.1 `field-name = token` is checked here through the scan's
        // *own* predicate rather than through `HeaderName::from_bytes`, so the
        // guard and the scan cannot disagree about what a field name is, and
        // the check holds in every configuration (the `actix`-only build has
        // the `http` feature off, and actix pins `http` 0.2; `PairHeaders` has
        // neither).
        for provider in provider_list() {
            for name in signature_header_names(&provider) {
                assert!(
                    is_valid_field_name(name),
                    "`{provider}` lists `{name:?}`, which is not a valid HTTP field \
                     name (RFC 9110 §5.1 `field-name = token`); the framework adapters \
                     would fail to parse it and reject every delivery as an ambiguous \
                     duplicate header"
                );
            }
        }
    }

    /// A scan name the framework's header map cannot parse must read as
    /// *ambiguous*, not as "nothing to scan".
    ///
    /// This is the fail-closed contract that makes the guard above necessary
    /// rather than cosmetic: an unparseable name can never be read, so it can
    /// never be proven unambiguous, and the only safe answer is to reject.
    /// Pinned because the tempting "fix" — returning `false` for an
    /// unparseable name — would silently disable the ambiguity check for that
    /// header instead of failing loudly.
    #[cfg(feature = "http")]
    #[test]
    fn unparseable_scan_name_reads_as_ambiguous() {
        use crate::core::adapter_utils::has_conflicting_duplicates;

        // A well-formed, single-valued request: nothing here is ambiguous.
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            ::http::HeaderValue::from_static("sha256=ab"),
        );
        assert!(!has_conflicting_duplicates(&headers, "X-Hub-Signature-256"));

        // The same request scanned under a name the header map cannot parse
        // (a space is not a `tchar`) must be reported ambiguous rather than
        // passing the scan — the "reject everything" behavior that makes a
        // typo'd constant an outage instead of a silent hole.
        assert!(has_conflicting_duplicates(&headers, "X-Hub-Signature 256"));
        // ...and so must a parseable name, when the request really does carry
        // it twice with differing values — the actual smuggling case the §4.4
        // check exists to catch.
        let mut duplicated = ::http::HeaderMap::new();
        duplicated.append(
            "X-Hub-Signature-256",
            ::http::HeaderValue::from_static("sha256=ab"),
        );
        duplicated.append(
            "X-Hub-Signature-256",
            ::http::HeaderValue::from_static("sha256=cd"),
        );
        assert!(has_conflicting_duplicates(
            &duplicated,
            "X-Hub-Signature-256"
        ));
        // Identical duplicates are not ambiguous: nothing is being smuggled.
        let mut identical = ::http::HeaderMap::new();
        identical.append(
            "X-Hub-Signature-256",
            ::http::HeaderValue::from_static("sha256=ab"),
        );
        identical.append(
            "X-Hub-Signature-256",
            ::http::HeaderValue::from_static("sha256=ab"),
        );
        assert!(!has_conflicting_duplicates(
            &identical,
            "X-Hub-Signature-256"
        ));
    }

    /// Every header the ambiguity scan is *exempted* from must be a header that
    /// provider's scan list actually contains (issue #245).
    ///
    /// `provider_sent_duplicate_headers` is a security-relevant exemption: a
    /// name in it stops the `spec.md` §4.4 duplicate check from running. The
    /// scan intersects that list with `signature_header_names`, so a stale entry
    /// cannot disable a check that is still needed — it just silently exempts
    /// nothing, which is the failure mode a reviewer would never notice. This
    /// guard turns that into a build failure.
    #[cfg(any(feature = "http", feature = "tower", feature = "actix"))]
    #[test]
    fn provider_sent_duplicate_headers_are_a_subset_of_the_scanned_headers() {
        for provider in provider_list() {
            let scanned = signature_header_names(&provider);
            for name in provider_sent_duplicate_headers(&provider) {
                assert!(
                    scanned.contains(name),
                    "`{provider}` is exempt from the ambiguity scan for `{name:?}`, \
                     but that is not one of its scanned headers, so the exemption \
                     silently does nothing — a renamed or dropped header constant"
                );
                assert!(
                    is_valid_field_name(name),
                    "`{provider}` is exempt for `{name:?}`, which is not a valid HTTP \
                     field name (RFC 9110 §5.1); the exemption would be unreadable"
                );
            }
        }
    }

    /// Only Mollie legitimately sends its signature header twice (issue #245).
    ///
    /// Mollie's 24-hour rotation window ships two `X-Mollie-Signature` lines
    /// with different values, which the §4.4 scan would otherwise read as a
    /// smuggled duplicate. Every other provider keeps its candidates out of the
    /// scan's reach (a comma-delimited list in one value, or two distinctly
    /// named headers), so a new entry here means a new exemption, which is a
    /// security decision that has to be made deliberately — with a linked
    /// provider source, not by extending a match arm. `Provider::Custom` is
    /// pinned separately below because `provider_list()` never reaches it.
    #[cfg(any(feature = "http", feature = "tower", feature = "actix"))]
    #[test]
    fn only_mollie_is_exempt_from_the_ambiguity_scan() {
        let exempt: Vec<_> = provider_list()
            .into_iter()
            .filter(|provider| !provider_sent_duplicate_headers(provider).is_empty())
            .collect();
        assert_eq!(
            exempt,
            vec![Provider::Mollie],
            "only Mollie sends its own signature header duplicated; a new entry here \
             needs a linked provider source in the exemption's own doc comment"
        );
        assert_eq!(
            provider_sent_duplicate_headers(&Provider::Mollie),
            &[mollie::SIGNATURE_HEADER],
            "the exemption is scoped to Mollie's one header, read from the provider's \
             own constant rather than re-spelled"
        );

        // `provider_list()` never yields `Provider::Custom`, so its half of the
        // "Mollie is the only exemption" claim needs its own assertion: a
        // `Custom` scheme declares what it signs in `signature_header`,
        // `timestamp_header`, and `signed_headers`, and nothing in a request
        // sanctions a duplicate of any of them — an exemption here would be a
        // new security decision with no provider source behind it (issue #395).
        let custom = Provider::Custom(CustomScheme::new(
            HashAlg::Sha256,
            "X-Webhook-Sig",
            Encoding::Hex,
            |_headers, raw_body| raw_body.to_vec(),
        ));
        assert!(
            provider_sent_duplicate_headers(&custom).is_empty(),
            "`Provider::Custom` must have no ambiguity-scan exemption: its declared \
             headers are caller-typed signing material, and no provider source sanctions \
             a duplicate of them (issue #395)"
        );
    }

    /// No provider may recompute the HMAC once per candidate signature
    /// (`spec.md` §4.1).
    ///
    /// A provider that accepts a delivery when *any* of several candidate
    /// signatures matches — the rotation lists (Stripe, Paddle, PagerDuty, Mux,
    /// Tailscale, Standard Webhooks) and Box, whose two candidates arrive in
    /// two headers rather than one list — must compute the digest once and
    /// compare every candidate against it, which is what `verify_hmac_sha256_any`
    /// exists for. Calling `verify_hmac_sha256` once per candidate instead
    /// is the exact shape §4.1 forbids, and it is easy to write by accident: the
    /// per-candidate call still looks correct, still compares in constant time,
    /// and no behavioral test fails. Box shipped that way for its whole life
    /// (two calls over the same key and the same signed string) because the
    /// rotation-list conversion that fixed the other six providers only covered
    /// comma-delimited headers, and nothing in the suite or the spec noticed
    /// (§4.1's enumeration did not name Box at all).
    ///
    /// The guard is textual, so it cannot see a call laundered through a local
    /// wrapper; what it does buy is that a *second direct* call in a provider
    /// module — the shape this actually regressed to — fails CI instead of
    /// shipping. At most one call site is allowed per module, which every
    /// provider satisfies today (the multi-candidate ones route through the
    /// `_any` helper instead). A scheme that genuinely needs two independent
    /// HMACs over *different* signed strings would have to widen this, and the
    /// failure message says so.
    #[test]
    fn no_provider_recomputes_the_hmac_per_candidate_signature() {
        use std::fs;
        use std::path::Path;

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/providers");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            // `src/providers` is shipped in the crates.io tarball, so this is
            // only a guard against a packaging surprise: a repo-internal
            // directory this crate's own tests must not fail on.
            Err(_) => return,
        };

        let mut checked = 0_usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            // `mod.rs` is the dispatch table and the test module itself, not a
            // provider implementation, and it legitimately calls the single
            // candidate helper from its own unit tests.
            if path.file_stem().is_some_and(|stem| stem == "mod") {
                continue;
            }
            let source = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(_) => continue,
            };
            // Only the implementation counts: a test may re-derive a vector
            // through the single-candidate helper to cross-check it.
            let implementation = match source.find("#[cfg(test)]") {
                Some(at) => &source[..at],
                None => source.as_str(),
            };
            let calls = implementation.matches("verify_hmac_sha256(").count();
            assert!(
                calls <= 1,
                "{} calls `verify_hmac_sha256` {calls} times; a provider that compares \
                 several candidate signatures against one key and one signed string must \
                 pass them all to `verify_hmac_sha256_any` so the digest is computed once \
                 (spec.md §4.1)",
                path.display(),
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "the HMAC-per-candidate scan found no provider modules to check under {}",
            dir.display()
        );
    }

    /// The rotation lists are not uniform in separator, and the prose that
    /// describes them must say so.
    ///
    /// `verify_hmac_sha256_any`'s doc comment used to introduce all six
    /// rotation-list providers as "any comma-separated signature in one header
    /// matches", and `provider_sent_duplicate_headers` above repeated it as the
    /// *reason* six providers are exempt from the ambiguity scan. Two of the six
    /// never split on a comma: Paddle's list is `;`-separated and Standard
    /// Webhooks' is space-separated. A reader auditing the exemption list was
    /// handed a wrong reason for those two — the conclusion survives (all six
    /// pack their candidates into one header value, so none is a duplicate), but
    /// the stated mechanism did not.
    ///
    /// The guard closes the class of drift rather than the one sentence: for
    /// every provider module that routes its candidates through
    /// `verify_hmac_sha256_any`, read the separator it actually splits on, and
    /// require the helper's doc comment to name that separator in backticks. A
    /// future rotation list on a new delimiter (say `|`) therefore fails CI
    /// until the prose is updated, instead of being quietly described as
    /// comma-separated. An unknown separator is reported as a hard failure
    /// rather than skipped so the map below cannot rot either.
    #[test]
    fn rotation_lists_prose_names_every_separator_the_code_actually_splits_on() {
        use std::fs;
        use std::path::Path;

        // Only these characters are known separators. An unmapped one means a
        // provider introduced a new delimiter, which needs a human to decide
        // how to render it in the doc comment.
        fn renders_in_prose(separator: char) -> Option<&'static str> {
            match separator {
                ',' => Some(","),
                ';' => Some(";"),
                ' ' => Some(" "),
                _ => None,
            }
        }

        let providers_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/providers");
        let entries = match fs::read_dir(&providers_dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        let mut found = BTreeSet::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            if path.file_stem().is_some_and(|stem| stem == "mod") {
                continue;
            }
            let source = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(_) => continue,
            };
            // Box's two candidates are two distinct header names, not a list, so
            // it is deliberately not a rotation list and has no separator.
            if !source.contains("verify_hmac_sha256_any")
                || path.file_stem().is_some_and(|stem| stem == "box_webhooks")
            {
                continue;
            }
            // Only the implementation counts: a test that re-derives a vector
            // through the `_any` helper may split its own fixture header value,
            // and that is not the scheme's separator.
            let implementation = match source.find("#[cfg(test)]") {
                Some(at) => &source[..at],
                None => source.as_str(),
            };
            // The candidate loop is the only `split` in these modules that takes
            // a bare char; `split_once` / `splitn` are field parsing, not the
            // rotation list.
            let separator = implementation
                .lines()
                .find_map(|line| line.split("value.split(").nth(1))
                .and_then(|rest| rest.trim_start().strip_prefix('\''))
                .and_then(|rest| rest.chars().next());
            let (Some(separator), Some(rendered)) =
                (separator, separator.and_then(renders_in_prose))
            else {
                panic!(
                    "{} routes candidates through `verify_hmac_sha256_any` but no \
                     single-character `value.split(..)` separator could be read from it; \
                     add it to `renders_in_prose` so the prose can name it",
                    path.display(),
                );
            };
            found.insert((separator, rendered));
        }

        assert!(
            found.len() > 1,
            "expected the rotation lists to disagree on their separator, but every \
             `_any` provider resolved to one: {found:?} — if the schemes really did \
             converge, delete this guard instead of loosening it"
        );

        let crypto = match fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/crypto.rs"),
        ) {
            Ok(source) => source,
            Err(_) => return,
        };
        let doc = match crypto.find("/// Verifies `provided_signatures`") {
            Some(at) => &crypto[at..],
            None => &crypto[..],
        };
        for (separator, rendered) in &found {
            let named = format!("`{rendered}`");
            assert!(
                doc.contains(&named),
                "verify_hmac_sha256_any's doc comment does not name the `{separator}` \
                 separator that a rotation-list provider actually splits on (expected it to \
                 contain {named}); the rotation lists are not comma-uniform — see spec.md §4.1"
            );
        }
    }

    /// The prose name `verify_hmac_sha1`'s doc comment has to use for a
    /// provider module, given the module's file stem, lowercased to match the
    /// words the caller scan compares against.
    ///
    /// Every provider module is named after its file, so a module whose stem is
    /// its prose name needs no entry here. `custom.rs` is the one module that
    /// is not: it implements `CustomScheme`, which is how the sibling
    /// `verify_hmac_sha512` doc comment names the same file. A stem that needs
    /// a spelling of its own (say `box_webhooks`, or `x_twitter` for `Provider::X`)
    /// fails the guard's assertion rather than passing vacuously, so it shows up
    /// here instead of quietly searching the doc for a name no reader would use.
    fn sha1_caller_prose_name(stem: &str) -> String {
        match stem {
            "custom" => String::from("customscheme"),
            other => other.to_lowercase(),
        }
    }

    /// The words of a `///` doc run, lowercased, so a provider can be recognized
    /// by name without the comparison being fooled by punctuation or casing
    /// (`Provider::Twilio`, "Twilio", and "twilio" all tokenize to `twilio`).
    fn doc_run_words(source: &str, from: usize) -> BTreeSet<String> {
        source[from..]
            .lines()
            // A non-`///` line ends the run: the function signature and body
            // below it are not prose, and crypto.rs's own tests name providers
            // for unrelated reasons.
            .take_while(|line| line.starts_with("///"))
            .flat_map(|line| line.strip_prefix("///").map(str::trim))
            .flat_map(|line| line.split(|c: char| !c.is_ascii_alphanumeric()))
            .filter(|word| !word.is_empty())
            .map(str::to_lowercase)
            .collect()
    }

    /// `verify_hmac_sha1`'s doc comment must name every provider that calls it.
    ///
    /// SHA-1 collision exposure is the one question nearly every reader brings
    /// to an HMAC-SHA1 implementation, and in this crate the answer lives on
    /// the shared helper rather than in each provider's own module. The doc
    /// comment said only "Used by Twilio's scheme" while five built-in
    /// providers called the helper, so a reader tracing it to assess collision
    /// exposure found one provider and moved on (issue #319). The sibling
    /// helpers already enumerate their callers — `verify_hmac_sha512` names the
    /// one built-in provider that uses it, and `verify_hmac_sha256_any` lists
    /// its six multi-candidate providers — which is what made the omission read
    /// as a mistake rather than a stylistic choice.
    ///
    /// The scan is textual, so it cannot see a call laundered through a local
    /// wrapper; what it buys is that a *direct* call in a provider module fails
    /// CI until the doc names it, which is the shape this actually regressed
    /// to. Only the implementation region counts, so a test re-deriving a
    /// vector through the helper is not a caller.
    ///
    /// One direction only. A provider that *stopped* calling the helper leaves
    /// its name behind, and nothing here notices: the check reads the callers
    /// out of the code and looks each one up in the doc, never the reverse.
    /// That is the direction worth guarding — the unlisted caller is what hides
    /// a scheme from a reader auditing SHA-1 exposure — but it is not "the list
    /// is exact", and the helper's doc comment says so rather than implying
    /// otherwise.
    #[test]
    fn verify_hmac_sha1_doc_names_every_provider_that_calls_it() {
        use std::fs;
        use std::path::Path;

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/providers");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            // `src/providers` is shipped in the crates.io tarball, so this is
            // only a guard against a packaging surprise: a repo-internal
            // directory this crate's own tests must not fail on.
            Err(_) => return,
        };

        let mut scanned = 0_usize;
        let mut callers = BTreeSet::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            // `mod.rs` is the dispatch table and the test module itself, not a
            // provider implementation, and the helper it documents lives in
            // `core/crypto.rs`, which is not scanned here.
            if stem == "mod" {
                continue;
            }
            let source = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(_) => continue,
            };
            let implementation = match source.find("#[cfg(test)]") {
                Some(at) => &source[..at],
                None => source.as_str(),
            };
            scanned += 1;
            // The `use` line that imports the helper has no `(`, so only a
            // call site matches.
            if implementation.contains("verify_hmac_sha1(") {
                callers.insert(String::from(stem));
            }
        }
        assert!(
            scanned > 0,
            "the HMAC-SHA1 caller scan found no provider modules to check under {}",
            dir.display()
        );
        assert!(
            callers.len() > 1,
            "expected several providers to call `verify_hmac_sha1`, but the scan found \
             {callers:?} — if the schemes really had converged on one, delete this guard \
             instead of loosening it"
        );

        let crypto = match fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/crypto.rs"),
        ) {
            Ok(source) => source,
            Err(_) => return,
        };
        let Some(at) = crypto.find("/// Verifies `provided_signature` against HMAC-SHA1(") else {
            panic!("`verify_hmac_sha1`'s doc comment must keep its first line");
        };
        let words = doc_run_words(&crypto, at);
        for caller in &callers {
            let name = sha1_caller_prose_name(caller);
            assert!(
                words.contains(&name),
                "verify_hmac_sha1's doc comment does not name `{caller}.rs`, which calls it; \
                 add `{name}` to that doc comment so the set of HMAC-SHA1 schemes stays \
                 auditable (spec.md §3)"
            );
        }
    }

    /// Every provider module that decodes the configured `Secret` into bytes
    /// before using it, as the `src/providers` module stem.
    ///
    /// Derived from the modules rather than listed, for the same reason
    /// [`millisecond_timestamp_providers`] is: a fourth decoding provider added
    /// later is the case that matters, and a hand-written list is a list
    /// somebody has to remember to extend. The scan is a function taking
    /// `secret: &[u8]` whose *body* calls a hex or base64 decode — which is the
    /// shape every key-derivation site here has, and is what separates it from
    /// a decode of a *header* value (those functions take `value`/`encoded`) and
    /// from the five providers that use the secret's bytes verbatim (their
    /// key-derivation function returns `secret` untouched).
    ///
    /// The body is scoped to the current function: it ends at the next `///`
    /// doc run or the next top-level `fn`, whichever comes first, and `//`
    /// comments are dropped from it. Without those boundaries a verbatim-key
    /// provider can come back as a decoder — Contentful's `signing_key` is
    /// followed directly by `parse_signature`, whose body hex-decodes its
    /// *header*, and a scan that read past the function would report the secret
    /// as decoded. The test asserts on the resulting set, so a scan that
    /// quietly widened would not fail on its own.
    fn secret_decoding_providers() -> Vec<String> {
        provider_module_stems()
            .into_iter()
            .filter(|stem| {
                let implementation = module_implementation(stem);
                let mut rest = implementation.as_str();
                while let Some(at) = rest.find("secret: &[u8]") {
                    let body = &rest[at..];
                    let end = body
                        .find("\n/// ")
                        .or_else(|| body.find("\nfn "))
                        .or_else(|| body.find("\npub fn "))
                        .unwrap_or(body.len());
                    let code: String = body[..end]
                        .lines()
                        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
                        .collect::<Vec<_>>()
                        .join("\n");
                    if code.contains("hex::decode(") || code.contains(".decode(") {
                        return true;
                    }
                    rest = &body[end..];
                }
                false
            })
            .collect()
    }

    /// The prose block a doc claim lives in: a `///` / `//!` list bullet in a
    /// Rust source, or a blank-line-delimited paragraph in Markdown.
    ///
    /// Narrower than the surrounding file on purpose — the claim being checked
    /// is a *scoped* one ("these three, not the four that decode"), so the
    /// evidence has to be the sentence that scopes it. A whole-file search
    /// would let a name appearing anywhere in the same document stand in for
    /// the qualifier this guard exists to keep.
    fn prose_block(source: &str, anchor: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(anchor))
            .unwrap_or_else(|| panic!("no prose block contains the anchor {anchor:?}"));
        let is_doc = |line: &&str| {
            line.trim_start().starts_with("///") || line.trim_start().starts_with("//!")
        };
        let (start, end) = if is_doc(&lines[at]) {
            let bullet = |line: &&str| {
                let trimmed = line.trim_start();
                trimmed.starts_with("/// - ") || trimmed.starts_with("//! - ")
            };
            (
                (0..at).rev().find(|i| bullet(&lines[*i])).unwrap_or(at),
                // Exclusive of the next bullet: its first line is a
                // different claim, and letting it satisfy this one would
                // mean a name one bullet away counted as evidence.
                ((at + 1)..lines.len())
                    .find(|i| bullet(&lines[*i]))
                    .unwrap_or(lines.len()),
            )
        } else {
            let start = (0..at)
                .rev()
                .find(|i| lines[*i].trim().is_empty())
                .map_or(0, |i| i + 1);
            let end = ((at + 1)..lines.len())
                .find(|i| lines[*i].trim().is_empty())
                .unwrap_or(lines.len());
            (start, end)
        };
        lines[start..end]
            .iter()
            .map(|line| {
                let trimmed = line.trim_start();
                for prefix in ["///", "//!"] {
                    if let Some(rest) = trimmed.strip_prefix(prefix) {
                        return rest.trim();
                    }
                }
                line.trim()
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Every prose site stating the `spec.md` §4.7 decoded-key rule must scope
    /// it to HMAC key material, and name the providers it does not cover.
    ///
    /// Four sites spelled this rule out — the crate docs, `verify`'s own doc,
    /// `unusable_secret_reason`'s, and `core::crypto::is_all_nul_key`'s — plus
    /// the README, and all five said "the three providers that hex- or
    /// base64-decode it" without saying *what they decode it into*. Four
    /// modules decode the secret, not three: Discord hex-decodes too. Its
    /// decoded value is an Ed25519 *public key*, so RFC 2104's zero-padding has
    /// no bearing on it and the all-NUL predicate genuinely does not apply —
    /// but a reader auditing "which providers re-apply the rule to the decoded
    /// key", which is the question a security review actually asks of §4.7,
    /// had to grep four files to learn that the count excluded a decoder. The
    /// count was right and the scoping was missing (issue #320).
    ///
    /// Both directions are checked, and the derived set is what makes them
    /// checkable. [`secret_decoding_providers`] reads the modules, so a fourth
    /// decoder has to be *named* as covered or *named* as excluded — a silent
    /// one fails either way. The exclusion half is the load-bearing one: it is
    /// the direction that regressed, and the direction where a bare count is
    /// wrong rather than merely incomplete.
    ///
    /// One per surface, so each of the five is fixed at its own site rather
    /// than leaving a reader to infer the rule from the others. The anchors are
    /// the sentence that carries the claim, so the evidence is the scoping
    /// sentence and not a name elsewhere in the same document.
    #[test]
    fn the_decoded_key_all_nul_rule_is_scoped_to_hmac_key_material() {
        let sites: [(&str, String, &str); 5] = [
            (
                "crate docs",
                include_str!("../lib.rs").to_string(),
                "hex- or base64-decode it into HMAC key material",
            ),
            (
                "verify() docs",
                include_str!("mod.rs").to_string(),
                "This check reads the **raw** secret",
            ),
            (
                "unusable_secret_reason() docs",
                include_str!("mod.rs").to_string(),
                "This reads the **raw** secret",
            ),
            (
                "core::crypto::is_all_nul_key docs",
                include_str!("../core/crypto.rs").to_string(),
                "into HMAC key material first",
            ),
            (
                "README.md",
                include_str!("../../README.md").to_string(),
                "re-apply the rule to the decoded bytes",
            ),
        ];

        let decoders = secret_decoding_providers();
        // A vacuity guard: with no decoder found, "every decoder is named"
        // holds for an empty set and the whole test asserts nothing. Discord
        // alone fixes the floor at two; a real scheme change should trip it
        // loudly rather than quietly emptying the check.
        assert!(
            decoders.len() >= 2,
            "expected several providers to decode the configured secret, but the scan found \
             {decoders:?} — if the schemes really stopped decoding, delete this guard instead \
             of loosening it"
        );

        // The two sets the prose has to account for. `is_all_nul_key` is the
        // shared decoded-key predicate from `core::crypto`, so calling it *is*
        // "re-applies the rule to the decoded bytes" — the same derivation
        // `verify_hmac_sha1_doc_names_every_provider_that_calls_it` uses for
        // its own caller set.
        let reapplies: Vec<String> = provider_module_stems()
            .into_iter()
            .filter(|stem| module_implementation(stem).contains("is_all_nul_key("))
            .collect();
        let excluded: Vec<String> = decoders
            .iter()
            .filter(|stem| !reapplies.contains(stem))
            .cloned()
            .collect();

        // The predicate's own callers must be decoders. A module that applied
        // the all-NUL rule to a key it did not decode would make both prose
        // sets wrong in a way the naming checks below cannot see.
        for stem in &reapplies {
            assert!(
                decoders.contains(stem),
                "`src/providers/{stem}.rs` calls `is_all_nul_key` but does not decode the \
                 configured secret, so it is in neither prose set; the scan behind \
                 `secret_decoding_providers` has stopped matching its shape"
            );
        }
        // And the sets must be disjoint and non-trivial on the exclusion side,
        // which is the half that regressed: a guard that passed with no
        // exclusions would not notice a decoder joining the covered set
        // unmentioned.
        assert!(
            !excluded.is_empty(),
            "every secret-decoding provider re-applies the all-NUL rule to the decoded key \
             ({reapplies:?}), so no site has an exclusion left to state — if Discord's decoded \
             Ed25519 public key is now covered, delete this guard instead of loosening it"
        );

        for (label, source, anchor) in &sites {
            let block = prose_block(source, anchor);
            for stem in reapplies.iter().chain(&excluded) {
                let brand = provider_list()
                    .into_iter()
                    .find(|provider| provider_module_stem(*provider) == *stem)
                    .unwrap_or_else(|| {
                        panic!("`{stem}.rs` is not a provider, so its prose name is undefined")
                    })
                    .to_string();
                assert!(
                    block.contains(&brand),
                    "the {label} prose block stating the spec.md §4.7 decoded-key rule does \
                     not name {brand}, whose module decodes the secret — it must be named as \
                     one of the {reapplies:?} that re-apply the all-NUL rule to the decoded \
                     key, or, for {excluded:?}, as excluded and why. \"{block}\""
                );
            }
            // The qualifier itself, not just the names. Naming Discord without
            // saying what its decoded bytes are would leave the reader to
            // re-derive the distinction the sentence exists to state, which is
            // the gap this guard closes.
            assert!(
                block.contains("public key"),
                "the {label} prose block naming the secret-decoding providers must say that the \
                 one it excludes decodes to a *public key* rather than HMAC key material, so \
                 the count reads as scoped rather than short; \"{block}\""
            );
        }
    }

    /// The words a scheme's encoding is spelled with, as the prose writes them.
    ///
    /// Only the two this crate ever emits for a signature: `base64` and `hex`.
    /// An encoding spelled some other way would not be scanned for, which is why
    /// the guard's vacuity floor requires `spec.md` to keep naming both of
    /// these — a scheme documenting a third encoding has to be added here rather
    /// than silently skipped.
    const ENCODING_WORDS: [&str; 2] = ["base64", "hex"];

    /// The offending phrase if `text` attaches an encoding to a *key*'s bytes
    /// rather than to the digest.
    ///
    /// The shape is `…bytes, <encoding>` — a comma directly after the word
    /// "bytes", then the encoding. That reads as "the key's bytes, base64", so
    /// the base64 lands on the key; the constructions this crate verifies all
    /// encode the *digest* and use the key verbatim. The offending clause is
    /// returned so the failing assertion can quote the sentence a reader would
    /// have misread.
    ///
    /// Rust doc comments and Markdown both wrap prose across lines, and
    /// `spec.md` marks emphasis with `**` while every module doc carries a
    /// `//!` prefix per line. Both are stripped first, because a scan matching
    /// the raw source sees `bytes,\n//!   **hex**-encoded` and finds neither
    /// `*` nor `hex` where it expects them — it would pass on the exact shape
    /// this guard exists to reject. Every site this catches spelled the
    /// encoding on the line *after* the "bytes,", so the wrapping is the
    /// normal case, not an edge one.
    ///
    /// The quoted clause stops at the end of the bullet or paragraph it sits
    /// in, not at the next `". "`. The scheme bullets run several claims deep —
    /// Razorpay's says "keyed with the webhook secret's UTF-8 bytes; the digest
    /// is hex-encoded, no `sha256=` prefix, no timestamp" — so splitting on
    /// `". "` ran the quote through the end of the bullet into the paragraph
    /// after it, and the failure named a sentence the reader would not find on
    /// the page. Markdown emphasis is dropped from the quote for the same
    /// reason: `**hex**-encoded` renders as `hex-encoded`, and quoting the
    /// markers — doubled, when the line join split the pair — showed the reader
    /// something the source does not literally say (issue #339).
    fn encoding_attached_to_key_bytes(source: &str) -> Option<String> {
        // One bullet's worth of context, quoted on failure. Bullets carry
        // several claims each, so quoting to the end of the file would bury the
        // offending clause under the rest of the module's documentation.
        let (flat, unit_starts) = flatten_prose_with_unit_starts(source);
        let lower = flat.to_lowercase();

        let mut from = 0;
        while let Some(at) = lower[from..].find("bytes,") {
            let after = from + at + "bytes,".len();
            // Only emphasis and wrapping may separate the two words; anything
            // else means this "bytes," is not the key's, so keep looking. The
            // gap is quoted from `flat`, not `lower`, so the failure message
            // shows the sentence as it is written.
            let gap = flat[after..].trim_start_matches([' ', '*']);
            if ENCODING_WORDS
                .iter()
                .any(|word| gap.to_lowercase().starts_with(word))
            {
                return Some(format!(
                    "bytes, {}",
                    clause_within_unit(&flat, &unit_starts, after)
                ));
            }
            from = after;
        }
        None
    }

    /// The rest of the prose unit containing byte `at`: from `at` to whichever
    /// comes first, the next unit's start or the next `". "`.
    ///
    /// The unit boundaries come from the flattening rather than from the text,
    /// so a quote cannot run past the end of the bullet or paragraph it sits in.
    /// Markdown emphasis is dropped, so the quote reads as the rendered page
    /// does (issue #339).
    fn clause_within_unit(flat: &str, unit_starts: &[usize], at: usize) -> String {
        let unit_end = unit_starts
            .iter()
            .copied()
            .find(|start| *start > at)
            .unwrap_or(flat.len());
        let end = flat[at..]
            .find(". ")
            .map_or(unit_end, |dot| at + dot)
            .min(unit_end);
        flat[at..end.min(flat.len())]
            .replace("**", "")
            .trim()
            .trim_end_matches('.')
            .trim()
            .to_string()
    }

    /// `source`'s prose flattened into one string, plus the byte offsets in it
    /// at which a new bullet (`- `/`* `) or a new paragraph begins.
    ///
    /// The `//!`/`///` prefix is stripped per line so wrapped prose reads as a
    /// reader sees it, and a blank line contributes no space, so a paragraph
    /// break stays a boundary instead of flattening into a run of spaces. The
    /// offsets are what let [`clause_within_unit`] stop a quote at the end of
    /// its bullet.
    fn flatten_prose_with_unit_starts(source: &str) -> (String, Vec<usize>) {
        let mut flat = String::with_capacity(source.len());
        let mut unit_starts = Vec::new();
        let mut previous_blank = true;
        for line in source.lines() {
            let text = line
                .trim_start()
                .trim_start_matches("//!")
                .trim_start_matches("///");
            if !flat.is_empty() {
                let starts_unit =
                    text.starts_with("- ") || text.starts_with("* ") || previous_blank;
                if !previous_blank {
                    flat.push(' ');
                }
                if starts_unit {
                    unit_starts.push(flat.len());
                }
            }
            flat.push_str(text);
            previous_blank = text.is_empty();
        }
        (flat, unit_starts)
    }

    /// The quoted clause stops at the end of its bullet, and reads without the
    /// emphasis markers the flattening may split (issue #339).
    ///
    /// This is a property of the *message*, not of the verdict: the guard still
    /// rejects the same shapes. Razorpay's pre-#337 module doc is the case that
    /// produced a quote spanning the bullet into the paragraph after it, and the
    /// `**hex**` there split across the join into `hex**-encoded`, so both
    /// artifacts are pinned on one input shaped like that module's.
    #[test]
    fn encoding_on_key_quotes_only_its_own_bullet() {
        let source = "\
//! - Algorithm: HMAC-SHA256 keyed with the webhook secret's UTF-8
//!   bytes, hex**-encoded, no `sha256=` prefix, no timestamp
//!
//! The signing key is the webhook secret configured in the dashboard — not the
//! API `key_id`/`key_secret` pair, per the docs and the FAQ.
";
        assert_eq!(
            encoding_attached_to_key_bytes(source).as_deref(),
            Some("bytes, hex-encoded, no `sha256=` prefix, no timestamp"),
            "the quote must stop at the end of the bullet that carries the offending clause, \
             and must not carry the `**` that the line join split"
        );

        // Prose that attaches the encoding to the digest is not this guard's
        // business, however its bullet wraps.
        assert_eq!(
            encoding_attached_to_key_bytes(
                "\
//! - Algorithm: HMAC-SHA256 keyed with the webhook secret's UTF-8 bytes;
//!   the digest is hex-encoded, no timestamp follows
"
            ),
            None
        );
    }

    /// No provider's scheme prose may attach the signature's encoding to the
    /// HMAC key instead of to the digest.
    ///
    /// Nine prose sites described the construction as "HMAC-SHA256 keyed with
    /// *key* as its UTF-8 bytes, **base64**-encoded" — two in `spec.md` §3 (X
    /// and Typeform) and seven module docs. Read literally, and a reader
    /// implementing from the spec reads it literally, the encoding attaches to
    /// the *key*: the recipe becomes `base64(consumer_secret)` as the HMAC key.
    /// Every one of these providers keys the HMAC with the secret's raw bytes
    /// and encodes the *digest*, so that recipe rejects every legitimate
    /// delivery.
    ///
    /// It fails *quietly*, which is the sharp end. No provider errors, no
    /// header is malformed, no test vector turns red — the integration just
    /// looks installed and accepts nothing (issue #336).
    ///
    /// Both encodings are checked, because the same sentence shape appears for
    /// hex-schemes: Cloudflare, Coinbase, Razorpay, and Sentry all spelled their
    /// key as `…UTF-8 bytes, hex-encoded`, which reads as the key being
    /// hex-encoded. `spec.md`'s own Cloudflare and Coinbase rows were never
    /// affected — they already split `- Algorithm:` from `- Key:` — so outside
    /// Typeform and X this was the module-doc template's shape, not the spec's.
    ///
    /// Both prose surfaces a scheme is described in are scanned: `spec.md` §3
    /// (via [`spec_section_three`]) and each provider module doc. They drift
    /// independently — the X entry and `x_twitter.rs`'s module doc carried the
    /// identical sentence, so fixing only the spec would have left the rustdoc
    /// copy wrong. §3 is scanned as one blob rather than entry by entry: this
    /// guard reads prose, never attributes an entry to a provider, and taking
    /// the entries would have pinned the whole guard to the configurations
    /// where [`spec_section_three_entries`] is compiled (issue #353).
    ///
    /// Textual, so it cannot know what a sentence *means*: it rejects one shape
    /// because the shape is what carries the misreading. A rewording that
    /// moves the encoding onto the digest passes; one that re-attaches it to the
    /// key in different words ("the secret's bytes, base64") is caught, but a
    /// genuinely different phrasing would need this read by eye.
    #[test]
    fn no_scheme_prose_attaches_the_encoding_to_the_key() {
        let mut sites: Vec<(String, String)> = vec![(
            "spec.md §3".to_string(),
            spec_section_three(include_str!("../../spec.md")).to_string(),
        )];
        for stem in provider_module_stems() {
            sites.push((
                format!("`src/providers/{stem}.rs` module docs"),
                module_implementation(&stem),
            ));
        }

        for (label, source) in &sites {
            if let Some(offending) = encoding_attached_to_key_bytes(source) {
                panic!(
                    "the {label} prose attaches the signature's encoding to the HMAC key \
                     instead of the digest — \"{offending}\" reads as \"the key's bytes, \
                     base64\", i.e. keying the HMAC with the base64/hex of the secret. This \
                     crate uses the key verbatim and encodes the *digest*: say \"as its UTF-8 \
                     bytes; the digest is base64-encoded\" instead. The provider tables in \
                     README.md and the crate docs state the same schemes and must agree \
                     (spec.md §3)"
                );
            }
        }

        // The vacuity floor: if the scheme prose stopped naming an encoding
        // altogether, or spelled it some other way, the scan above would find
        // nothing and pass while checking nothing. Both encodings must still be
        // described, so an emptied check is a loud failure rather than a silent
        // one.
        let spec = include_str!("../../spec.md").to_lowercase();
        for word in ENCODING_WORDS {
            assert!(
                spec.contains(word),
                "spec.md no longer contains `{word}`, so \
                 `no_scheme_prose_attaches_the_encoding_to_the_key` cannot be finding anything \
                 — if the encodings really changed, update `ENCODING_WORDS` and this guard \
                 together rather than deleting the check"
            );
        }
    }

    /// Whether a provider module's implementation region reads
    /// `VerifyOptions::field`, found by scanning for a field access `<some
    /// receiver>.<field>`.
    ///
    /// The receiver is matched as a **whole token of any name**, not as the
    /// literal identifier `options`, and that is load-bearing. Every reader in
    /// the tree today happens to name its parameter `options`, so matching that
    /// one word produced the same reader set — but the guard's per-field
    /// assertions only run over the readers the scan *found*, so pinning the
    /// name turned a rename into a silent hole: renaming `options` to `opts` in
    /// one provider dropped that provider out of the set, and as long as some
    /// other provider still read the option every assertion still passed. Only
    /// `webhook_id`, read solely by `paypal.rs`, failed loudly — via the
    /// non-emptiness check, not because of the scan. Matching any receiver
    /// closes the hole for all five options with no second list to maintain and
    /// no change to today's result; issue #271.
    ///
    /// Two shapes have to be recognized, because rustfmt introduces both:
    ///
    /// ```text
    ///     let url = options.request_url.as_deref();   // on one line
    ///     let url = options                            // receiver at line end
    ///         .request_url                             // field on the next line
    /// ```
    ///
    /// The receiver must be a whole token, so a path is not mistaken for a
    /// read. In `VerifyOptions::request_url` the walk-back stops at the `::`,
    /// making `VerifyOptions` the receiver — and the receiver already has a `.`
    /// before it, so there is no field access to report.
    ///
    /// Comment lines are skipped outright, so prose that happens to name
    /// `options.request_url` cannot put a module into the reader set. What
    /// remains is an over-approximation: a *non*-`VerifyOptions` value with a
    /// field of the same name would still count as a read. That is the safe
    /// direction — the caller's per-field assertion then fails loudly and
    /// names the module, instead of a provider being silently skipped, which is
    /// the failure this function exists to make impossible.
    fn reads_context_option_field(implementation: &str, field: &str) -> bool {
        let is_identifier_char = |c: char| c.is_alphanumeric() || c == '_';

        let needle = format!(".{field}");
        // Whether the previous line ended in a bare identifier, so a chain
        // split across two lines is still seen as one read.
        let mut receiver_continues = false;
        for line in implementation.lines() {
            let line = line.trim();
            if line.starts_with("//") {
                receiver_continues = false;
                continue;
            }
            if receiver_continues && line.starts_with(&needle) {
                return true;
            }
            for (dot, _) in line.match_indices(&needle) {
                // A field access needs an identifier immediately before the
                // `.`; a bare `.field` line with no receiver is a chain
                // continuation, already handled above.
                if !line[..dot]
                    .chars()
                    .next_back()
                    .is_some_and(is_identifier_char)
                {
                    continue;
                }
                // Walk back over the rest of that identifier: the receiver is
                // the whole token, not the tail of a longer one, so `a.b.field`
                // still resolves to the `b` token and its `.` boundary holds.
                let token_start = match line[..dot]
                    .char_indices()
                    .rev()
                    .find(|(_, c)| !is_identifier_char(*c))
                {
                    Some((after_token, _)) => after_token + 1,
                    // Nothing but identifier characters precede it.
                    None => 0,
                };
                if !line[..token_start]
                    .chars()
                    .next_back()
                    .is_some_and(is_identifier_char)
                {
                    return true;
                }
            }
            receiver_continues = line.chars().next_back().is_some_and(is_identifier_char);
        }
        false
    }

    /// `reads_context_option_field` is not tied to the name of the parameter
    /// holding the [`VerifyOptions`], so a module that renames it stays in the
    /// scan.
    ///
    /// Issue #271: the scan used to look for the literal token `options`, and
    /// the comment above the caller claimed a rename "turns into a loud failure
    /// rather than a silently skipped provider". It did not — the per-field
    /// assertions iterate the readers the scan found, so a renamed provider
    /// simply dropped out and the remaining reader's `assert!` still passed.
    /// These cases pin the property the comment claims, so the two cannot
    /// diverge again; the provider-level guard is
    /// `context_option_field_docs_name_every_provider_that_reads_the_option`.
    #[test]
    fn context_option_reader_scan_is_independent_of_the_parameter_name() {
        for receiver in ["options", "opts", "cfg", "self.options", "context"] {
            // Same line, and the two-line chain split rustfmt produces.
            assert!(
                reads_context_option_field(
                    &format!("    let url = {receiver}.request_url.as_deref();"),
                    "request_url"
                ),
                "receiver `{receiver}`"
            );
            assert!(
                reads_context_option_field(
                    &format!("    let params = {receiver}\n        .form_params\n"),
                    "form_params"
                ),
                "receiver `{receiver}`"
            );
        }

        // A dotted receiver path is one token, not two: `a.b.field` is a read
        // of `b`'s field, and the walk-back has to find the `b` boundary.
        assert!(reads_context_option_field(
            "    let url = self.options.request_url.clone();",
            "request_url"
        ));

        for not_a_read in [
            // An intra-doc link, and prose that names the access outright: both
            // are on comment lines, which the scan skips.
            "/// See [`VerifyOptions::request_url`] for the context.",
            "/// Fails unless `options.request_url` is set.",
            // The same `::` shape on real code rather than in a comment, so the
            // whole-token walk-back is exercised on the line path too.
            "    let url = VerifyOptions::request_url.clone();",
            // A local binding named after the field, with no access at all.
            "    let request_url = ctx.url.clone();",
            // A continuation line with no receiver before it: the previous line
            // ends in `;`, so there is nothing for `.request_url` to hang off.
            "    let header = headers.get(NAME);\n        .request_url\n",
            // A different option.
            "    let method = options.request_method;",
        ] {
            assert!(
                !reads_context_option_field(not_a_read, "request_url"),
                "{not_a_read:?}"
            );
        }
    }

    /// Every provider that reads a `VerifyOptions` context option is named in
    /// that option's own field docs.
    ///
    /// The five context options (`request_url`, `request_method`, `form_params`,
    /// `verifying_material`, `webhook_id`) are the only place a caller learns
    /// *which* providers need them. A provider that requires one and is not
    /// named there fails every delivery with `MissingContext` — a 500 from the
    /// tower/actix adapters, and nothing in the error points at the option that
    /// was never set. Nothing else in the crate cross-checks that prose against
    /// the code: the other guards cover the README table, the crate docs and
    /// `spec.md` §3, all of which describe the scheme but not the context
    /// option the scheme needs.
    ///
    /// The risk is not hypothetical: seven of the 58 providers sign
    /// caller-supplied context, and each one added a sentence to the relevant
    /// field doc by hand. Nothing in the build, the tests, or review forces
    /// that edit, and a reviewer has no way to notice it was skipped — unlike
    /// a signing-scheme change, which shows up as a diff in the provider's own
    /// `spec.md` row and README table line. This guard reads the readers out
    /// of the provider sources themselves, so a new provider that touches
    /// `options.request_url` fails CI until the field doc names it.
    ///
    /// Only the forward direction is checked (readers must be named). The
    /// reverse is deliberately not asserted: these fields also cite *other*
    /// providers when explaining a failure mode — `webhook_id` says "mirroring
    /// Square/Twilio's URL context" — so "names a provider that does not read
    /// this field" is not a defect, only "fails to name one that does" is.
    #[test]
    fn context_option_field_docs_name_every_provider_that_reads_the_option() {
        use std::collections::BTreeSet;
        use std::fs;
        use std::path::Path;

        /// The `///` block immediately above `field`'s declaration, joined back
        /// into one string.
        fn field_doc(options: &str, field: &str) -> String {
            let lines: Vec<&str> = options.lines().collect();
            let declaration = lines
                .iter()
                .position(|line| line.starts_with(&format!("    pub {field}:")))
                .unwrap_or_else(|| panic!("no `pub {field}:` declaration found in options.rs"));
            let start = lines[..declaration]
                .iter()
                .rposition(|line| !line.trim_start().starts_with("///"))
                .map_or(0, |last_non_doc| last_non_doc + 1);
            lines[start..declaration].join(" ")
        }

        // Both the dispatch table and the option docs are compile-time inputs,
        // so a failure to read them cannot be confused with "nothing to check".
        let this = include_str!("mod.rs");
        let options = include_str!("../core/options.rs");
        let providers_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/providers");

        // Each provider's `Display` brand (what the field docs must name) and
        // module file stem (what the failure message must point at), paired
        // with its implementation region. Read once for all five options:
        // re-walking 58 files per option would dominate the suite's wall time.
        let mut implementations = Vec::with_capacity(provider_list().len());
        for provider in provider_list() {
            // The dispatch arm is the crate's own provider-to-module map, so
            // the test needs no second copy of it to drift.
            let arm = this
                .lines()
                .find(|line| {
                    // `::verify(` distinguishes the dispatch arm from the
                    // identically shaped `Display` arm above it.
                    line.trim_start()
                        .starts_with(&format!("Provider::{provider:?} =>"))
                        && line.contains("::verify(")
                })
                .unwrap_or_else(|| panic!("{provider} has no dispatch arm in providers/mod.rs"));
            let callee = arm
                .split_once("::verify(")
                .map(|(callee, _)| callee)
                .and_then(|callee| callee.rsplit_once("=>").map(|(_, callee)| callee))
                .map(str::trim)
                .unwrap_or_else(|| panic!("could not read {provider}'s dispatch arm: {arm:?}"));
            // The callee is a module path; its last segment is the file.
            let module = callee.rsplit("::").next().unwrap_or(callee);
            let source = fs::read_to_string(providers_dir.join(format!("{module}.rs")))
                .unwrap_or_else(|error| {
                    panic!("{provider}'s module {module}.rs could not be read: {error}")
                });
            // Only the implementation counts: a test that builds
            // `VerifyOptions::default().with_request_url(..)` is not the scheme
            // requiring the option.
            let implementation = match source.find("#[cfg(test)]") {
                Some(at) => &source[..at],
                None => source.as_str(),
            };
            implementations.push((
                provider.to_string(),
                module.to_string(),
                implementation.to_string(),
            ));
        }

        for field in [
            "request_url",
            "request_method",
            "form_params",
            "verifying_material",
            "webhook_id",
        ] {
            let doc = field_doc(options, field);
            let readers: BTreeSet<(&str, &str)> = implementations
                .iter()
                .filter(|(_, _, implementation)| reads_context_option_field(implementation, field))
                .map(|(brand, module, _)| (brand.as_str(), module.as_str()))
                .collect();

            // Guards against a silent vacuous pass: if the read scan ever
            // stopped matching, the reader set would be empty and every
            // assertion below would pass vacuously.
            assert!(
                !readers.is_empty(),
                "no provider reads `options.{field}`, so the guard has nothing to check — \
                 either the dispatch-parse in this test broke, or `VerifyOptions::{field}` \
                 became dead configuration that should be removed"
            );
            for (brand, module) in &readers {
                assert!(
                    doc.contains(brand),
                    "providers/{module}.rs reads `options.{field}`, but the \
                     `VerifyOptions::{field}` field docs do not name {brand}; a caller reading \
                     them would not know to set the option, and every {brand} delivery would \
                     fail closed with `VerifyError::MissingContext`"
                );
            }
        }
    }

    /// Both framework adapters' module docs name every provider whose scheme
    /// requires caller-supplied request context, and name the adapter's own
    /// `with_options` constructor alongside them.
    ///
    /// [`context_option_field_docs_name_every_provider_that_reads_the_option`]
    /// covers the *field* docs and `spec.md` §3 plus the README provider table
    /// cover the *scheme*, but neither reaches the page a framework user
    /// actually reads: `webhook_verify::tower` and `webhook_verify::actix`.
    /// Those two module docs described the buffering, the ambiguity check, the
    /// status-code table, rotation, and the body-size limit, and mentioned the
    /// context options only in passing — as the reason
    /// `VerifyLayer::with_options` takes an `options` argument. A reader
    /// configuring Square, Twilio, Mandrill, HubSpot, or Contentful through an
    /// adapter therefore had no way to learn from the adapter's own docs that
    /// the context must be supplied *at construction*, or that omitting it is a
    /// `500`, not a `401`.
    ///
    /// The second half of the gap was worse than an omission, because the docs
    /// invited the wrong fix. Unlike `request_url` and `request_method` — one
    /// endpoint and one method, i.e. constants of the deployment —
    /// `form_params` is the parsed `application/x-www-form-urlencoded` **body**,
    /// so it differs on every delivery, while both adapters hold their
    /// `VerifyOptions` behind one `Arc` fixed when the layer/config is built.
    /// Configuring fields there pins every delivery to one delivery's field set
    /// and rejects the rest, which reads like a broken integration rather than
    /// a design limitation. It is now not merely documented away: the two
    /// providers decode those fields from the `raw_body` the adapter already
    /// buffers (`src/providers/form.rs`), so both verify through an adapter with
    /// only `request_url` set (issue #363). What the docs must therefore state
    /// is the *instruction* — leave `form_params` unset — because a reader who
    /// configures it gets one delivery's field set pinned, and nothing at
    /// runtime says so. This guard keeps both adapters and the README's adapter
    /// section in step with the code, so a provider that starts reading a
    /// context option cannot ship undocumented.
    ///
    /// The two key-material options are in scope for the same reason the three
    /// request-shape ones are: the sections are where an adapter user learns
    /// what has to be configured *at construction*, and both sections already
    /// claimed to cover key material while naming only the five
    /// URL/method readers. PayPal carries a certificate URL in the request, but
    /// this crate performs no network calls (`spec.md` §7), so that URL cannot
    /// be the supply route — and PayPal's `webhook_id` travels nowhere near the
    /// request at all. Absent either, `verify()` fails closed with
    /// `MissingContext`, which both adapters answer as a `500` (issue #397).
    #[test]
    fn framework_adapter_docs_name_every_provider_that_needs_request_context() {
        /// A provider's `Display` brand, its module stem, and which of the
        /// five `VerifyOptions` context fields its implementation reads.
        fn readers() -> Vec<(String, String, Vec<&'static str>)> {
            provider_list()
                .into_iter()
                .map(|provider| {
                    let stem = provider_module_stem(provider);
                    let implementation = module_implementation(&stem);
                    let mut reads = Vec::new();
                    for field in [
                        "request_url",
                        "request_method",
                        "form_params",
                        "verifying_material",
                        "webhook_id",
                    ] {
                        if reads_context_option_field(&implementation, field) {
                            reads.push(field);
                        }
                    }
                    (provider.to_string(), stem, reads)
                })
                .filter(|(_, _, reads)| !reads.is_empty())
                .collect()
        }

        let readers = readers();
        // Vacuity floor: the scan must find the seven providers it finds today,
        // or a broken derivation turns every assertion below into a pass. Kept
        // as an exact count so a *new* reader is also a failure here rather
        // than only tripping the per-provider assertions.
        assert_eq!(
            readers.len(),
            7,
            "expected exactly the seven providers that require caller-supplied \
             request context (Contentful, HubSpot, Square, Twilio, Mandrill, \
             PayPal, SendGrid), found: {readers:?}"
        );

        // Both adapter module docs, plus the README's adapter section. The
        // module docs are the landing page for `webhook_verify::tower` /
        // `webhook_verify::actix`; the README section is what a reader
        // skims before choosing an integration.
        let tower_doc = stripped_module_doc(include_str!("../tower.rs"));
        let actix_doc = stripped_module_doc(include_str!("../actix.rs"));
        let readme = include_str!("../../README.md");
        let adapters_section = readme
            .split_once("\n## Framework adapters\n")
            .map(|(_, rest)| rest.split_once("\n## ").map_or(rest, |(end, _)| end))
            .unwrap_or_else(|| {
                panic!("README.md no longer has a top-level `## Framework adapters` section")
            });

        for (brand, stem, reads) in &readers {
            for (surface, text) in [
                ("src/tower.rs module doc", tower_doc.as_str()),
                ("src/actix.rs module doc", actix_doc.as_str()),
                ("README.md `## Framework adapters`", adapters_section),
            ] {
                assert!(
                    text.contains(brand.as_str()),
                    "providers/{stem}.rs requires caller-supplied request context ({reads:?}), \
                     but the {surface} never names {brand}. An adapter user configuring {brand} \
                     has no way to learn the context must be supplied when the layer/config is \
                     built, and every delivery fails closed with \
                     `VerifyError::MissingContext` — a 500, not a 401"
                );
            }
        }

        for (surface, text, constructor) in [
            (
                "src/tower.rs module doc",
                tower_doc.as_str(),
                "VerifyLayer::with_options",
            ),
            (
                "src/actix.rs module doc",
                actix_doc.as_str(),
                "WebhookConfig::with_options",
            ),
            (
                "README.md `## Framework adapters`",
                adapters_section,
                "with_options",
            ),
        ] {
            for needle in [constructor, "form_params"] {
                assert!(
                    text.contains(needle),
                    "the {surface} must mention `{needle}`: it is the only place an adapter \
                     user learns how to supply the request context, and `form_params` is the \
                     one context option an adapter user must leave unset (it is the per-request \
                     form body, and the adapter decodes it from the buffered bytes itself)"
                );
            }
        }

        // The per-request option is the part a reader will get wrong, so both
        // adapter docs must give the instruction rather than only naming the
        // option: configuring it pins every delivery to one delivery's field
        // set. Checked as a phrase the prose cannot lose without also dropping
        // the words around it, and required of the README section too — that is
        // the page a reader skims before choosing an integration.
        for (surface, text) in [
            ("src/tower.rs module doc", tower_doc.as_str()),
            ("src/actix.rs module doc", actix_doc.as_str()),
            ("README.md `## Framework adapters`", adapters_section),
        ] {
            assert!(
                text.contains("Do not** set"),
                "the {surface} must say not to configure `form_params` on an adapter, not \
                 merely which options the providers need: it is the per-request form body, and \
                 an adapter's options are fixed at construction, so configuring it there pins \
                 every delivery to one delivery's field set and rejects the rest — which reads \
                 like a provider-side misconfiguration rather than a configuration mistake"
            );
        }
    }

    /// Every provider whose `verify()` reads a [`VerifyOptions`] context option
    /// names that option in its own [`Provider`] enum variant doc — and where
    /// the option is optional, says where the value comes from instead of
    /// listing it as required.
    ///
    /// The variant docs are what docs.rs shows for a variant, and no other
    /// guard could see them drift.
    /// [`context_option_field_docs_name_every_provider_that_reads_the_option`]
    /// reads the `VerifyOptions` *field* docs,
    /// [`framework_adapter_docs_name_every_provider_that_needs_request_context`]
    /// reads the two adapter module docs plus the README, and
    /// `spec_two_provider_enum_sketch_matches_declaration_order` reads the
    /// `spec.md` §2 variant *list*.
    /// [`provider_variant_docs_spell_their_own_headers_the_way_the_code_does`]
    /// is the one guard already reading the variant prose, and it checks
    /// header casing in it — nothing about options.
    ///
    /// The drift was on exactly the axis issues #363/#364 moved. Both
    /// form-signed variants still told a reader `form_params` was needed —
    /// `Provider::Twilio` "needs `VerifyOptions::request_url` and
    /// `VerifyOptions::form_params`" and `Provider::Mandrill` "Needs
    /// `VerifyOptions::request_url` … and `VerifyOptions::form_params`" —
    /// after those two providers started decoding the fields from `raw_body`
    /// themselves. A reader following those docs configures `form_params`,
    /// which is the *per-delivery form body*: through an adapter, which fixes
    /// one `VerifyOptions` for every delivery, that pins every delivery to one
    /// delivery's field set and rejects the rest, and nothing at runtime says
    /// so. The field doc and both adapter docs already say to leave it unset;
    /// the variant docs contradicted all three.
    ///
    /// Both directions are checked. Forward, so a provider that starts reading
    /// a context option cannot ship undocumented: each option it reads must be
    /// named. Backward only for `form_params`, the one option that is
    /// *optional* — `request_url`, `request_method`, `verifying_material`, and
    /// `webhook_id` all fail closed when absent, so "needs" is the right word
    /// for them, while `form_params` unset means "derive from the body". Its
    /// doc must therefore name `raw_body` as that source, checked as a phrase
    /// the wording cannot lose without dropping the words around it — the same
    /// shape as the adapter guard's `"Do not** set"` check. "Decoded" is the
    /// verb used for that derivation in `twilio.rs`, `mandrill.rs` and the
    /// `form_params` field doc, so the three surfaces are held to one word.
    #[test]
    fn provider_variant_docs_name_their_own_context_options() {
        // The providers reading each option today, as `(option, brands)`. Held
        // as one table rather than a bare count so a failure says *which* read
        // moved and a new reader is reported here instead of only tripping the
        // per-provider assertion below.
        let expected: [(&str, &[Provider]); 5] = [
            (
                "request_url",
                &[
                    Provider::Contentful,
                    Provider::HubSpot,
                    Provider::Mandrill,
                    Provider::Square,
                    Provider::Twilio,
                ],
            ),
            ("request_method", &[Provider::Contentful, Provider::HubSpot]),
            ("form_params", &[Provider::Mandrill, Provider::Twilio]),
            (
                "verifying_material",
                &[Provider::PayPal, Provider::SendGrid],
            ),
            ("webhook_id", &[Provider::PayPal]),
        ];

        for (field, expected_brands) in expected {
            let found: Vec<Provider> = provider_list()
                .into_iter()
                .filter(|provider| {
                    reads_context_option_field(
                        &module_implementation(&provider_module_stem(*provider)),
                        field,
                    )
                })
                .collect();
            assert_eq!(
                found, expected_brands,
                "the providers whose `verify()` reads `options.{field}` changed; \
                 `framework_adapter_docs_name_every_provider_that_needs_request_context` pins \
                 the same scan for the three request-context options, so update this table and \
                 that guard's own count in the same change"
            );
            for provider in &found {
                let doc = provider_variant_doc(&format!("{provider:?}"));
                assert!(
                    doc.contains(field),
                    "the `Provider::{provider:?}` variant doc does not name \
                     `VerifyOptions::{field}`, which providers/{}.rs reads; a reader on the \
                     docs.rs page for that variant has no way to learn the option exists, and \
                     every delivery fails closed with `VerifyError::MissingContext`",
                    provider_module_stem(*provider)
                );
            }
        }

        // The one context option whose absence is not a misconfiguration. A
        // reader told it is needed will set it, and setting it on a layer pins
        // every delivery to one delivery's body — so the doc has to say where
        // the fields come from instead.
        for provider in [Provider::Twilio, Provider::Mandrill] {
            let doc = provider_variant_doc(&format!("{provider:?}"));
            assert!(
                doc.contains("decoded from `raw_body`"),
                "the `Provider::{provider:?}` variant doc lists `VerifyOptions::form_params` \
                 among the options the provider needs, but it is optional: the fields are \
                 decoded from `raw_body` when it is unset, which is what makes the provider \
                 verifiable through a framework adapter (issue #363). A reader who configures \
                 it there pins every delivery to one delivery's field set and rejects the rest, \
                 and nothing at runtime says so — say where the fields come from instead"
            );
        }
    }

    /// The providers that ignore [`Secret`] name each other in their own
    /// `# Security model` prose.
    ///
    /// The claim under test is *negative* — "no other provider here does this" —
    /// which is why no existing guard could see it drift. Every other prose
    /// guard pins a positive name list derived from the code
    /// ([`context_option_field_docs_name_every_provider_that_reads_the_option`],
    /// [`millisecond_timestamp_docs_name_every_millisecond_provider`], …); this
    /// shape asserts that a list does **not** exist, so a broken derivation
    /// makes it pass silently. Discord's module doc headed its section
    /// "Security model difference from every other provider here" while
    /// `uses_secret` excluded two providers, and SendGrid's doc said "Like
    /// Discord" without naming PayPal — a reader consulting the section to
    /// decide whether `Secret` is load-bearing for a scheme got the wrong
    /// answer from both.
    ///
    /// [`uses_secret_excludes_exactly_the_providers_that_ignore_it`] pins the
    /// code side of that same fact; this guard pins the prose side, and derives
    /// the set from `uses_secret` so a fourth public-key scheme is covered the
    /// next time one is added.
    ///
    /// Only members of the set are checked, and only for naming the *other*
    /// members. Discord holds its public key in `Secret`, so it is not in the
    /// set and its doc is not forced to enumerate peers; a reader opening a
    /// Discord doc has no use for a list of the two providers that take their
    /// key material somewhere else entirely.
    #[test]
    fn public_key_module_docs_name_their_peers() {
        use std::fs;
        use std::path::Path;

        /// A module's leading `//!` documentation, joined into one string.
        fn module_doc(source: &str) -> String {
            source
                .lines()
                .map_while(|line| line.trim_start().starts_with("//!").then_some(line.trim()))
                .collect::<Vec<_>>()
                .join(" ")
        }

        let public_key: Vec<(String, String)> = provider_list()
            .into_iter()
            .filter(|provider| !uses_secret(*provider))
            .map(|provider| (provider.to_string(), provider_module_stem(provider)))
            .collect();

        // A vacuity guard: with at most one member, "every peer is named"
        // asserts nothing at all, and a scan that silently stopped matching
        // would leave this test green.
        assert!(
            public_key.len() > 1,
            "expected several providers to ignore `Secret` in favour of caller-supplied key \
             material, but `uses_secret` excluded {:?} — this guard has nothing to check, so \
             either a provider's treatment of `Secret` changed or `provider_list` has stopped \
             covering it",
            public_key
                .iter()
                .map(|(brand, _)| brand.as_str())
                .collect::<Vec<_>>()
        );

        let providers_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/providers");
        for (brand, module) in &public_key {
            let source = fs::read_to_string(providers_dir.join(format!("{module}.rs")))
                .unwrap_or_else(|error| {
                    panic!("{brand}'s module {module}.rs could not be read: {error}")
                });
            let doc = module_doc(&source);
            for (peer, _) in &public_key {
                if peer == brand {
                    continue;
                }
                assert!(
                    doc.contains(peer.as_str()),
                    "providers/{module}.rs ignores `Secret` and so shares the public-key \
                     security model with {peer}, but its module docs never name {peer}; the \
                     `# Security model` section is where a reader decides whether `Secret` is \
                     load-bearing for a scheme, so a half-named peer list — or an unqualified \
                     \"differs from every other provider\" — points them at the wrong model"
                );
            }
        }
    }

    /// Every name-constructible [`Provider`] variant, in declaration order.
    ///
    /// The single source of truth for the provider-bookkeeping tests: both the
    /// `Display`/`FromStr` round-trip test and the parse-error message guard
    /// iterate this list, so a newly added provider is covered by both the
    /// moment it is listed here. Each test used to keep its own copy, which
    /// let one list drift out of sync unnoticed (a provider once shipped
    /// missing from the round-trip list while present here). `Provider::Custom`
    /// is intentionally absent: it needs a `CustomScheme` and cannot be parsed
    /// from a bare name.
    fn provider_list() -> [Provider; 58] {
        [
            Provider::Stripe,
            Provider::GitHub,
            Provider::Bitbucket,
            Provider::Contentful,
            Provider::Box,
            Provider::Intercom,
            Provider::Expo,
            Provider::Meta,
            Provider::HubSpot,
            Provider::Klaviyo,
            Provider::Mandrill,
            Provider::Line,
            Provider::Shopify,
            Provider::Slack,
            Provider::Square,
            Provider::Tally,
            Provider::FastSpring,
            Provider::GoCardless,
            Provider::Mollie,
            Provider::Twilio,
            Provider::Twitch,
            Provider::Typeform,
            Provider::Discord,
            Provider::PayPal,
            Provider::SendGrid,
            Provider::Paystack,
            Provider::Paddle,
            Provider::PagerDuty,
            Provider::Pusher,
            Provider::Linear,
            Provider::LaunchDarkly,
            Provider::Notion,
            Provider::Nylas,
            Provider::Zoom,
            Provider::Cloudflare,
            Provider::CircleCi,
            Provider::Coinbase,
            Provider::Dropbox,
            Provider::DocuSign,
            Provider::Fintoc,
            Provider::Razorpay,
            Provider::Recharge,
            Provider::Ripple,
            Provider::LemonSqueezy,
            Provider::Xero,
            Provider::Sentry,
            Provider::Adyen,
            Provider::Airwallex,
            Provider::Mux,
            Provider::Zendesk,
            Provider::WorkOS,
            Provider::WooCommerce,
            Provider::Calendly,
            Provider::Vercel,
            Provider::Webflow,
            Provider::X,
            Provider::Tailscale,
            Provider::StandardWebhooks,
        ]
    }
}
