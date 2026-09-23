//! Provider-specific signing schemes and the [`verify`] dispatch.
//!
//! Each provider lives in its own module implementing exactly the scheme
//! documented in `spec.md` §3, backed by that provider's official test
//! vectors. Feature-disabled providers fail closed with
//! [`VerifyError::UnsupportedProvider`].

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

pub use custom::{CustomScheme, Encoding, HashAlg};

use core::fmt;

#[cfg(any(feature = "tower", feature = "actix"))]
use alloc::vec;

#[cfg(any(feature = "tower", feature = "actix"))]
use alloc::vec::Vec;

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
    /// Mailchimp Transactional, including any query string) and
    /// `VerifyOptions::form_params` (`mandrill_events` — a JSON array of
    /// batched events — historically the only field). The scheme signs no
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
    /// Shopify (`X-Shopify-Hmac-SHA256`, base64-encoded HMAC-SHA256).
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
    /// Twilio (HMAC-SHA1 over full URL + sorted form params; needs
    /// `VerifyOptions::request_url` and `VerifyOptions::form_params`).
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
    /// `VerifyOptions::with_max_age(Some(Duration::from_secs(180)))` (the crate
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
    /// crate's other built-in SHA-1 schemes are Twilio (URL + form params),
    /// Intercom (raw body behind a `sha1=` prefix), and Expo EAS (raw body
    /// behind a `sha1=` prefix). A `CustomScheme`
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
/// `"zapier"`, `"vanta"`, and `"safetykit"` all parse to it.
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
                || n.eq_ignore_ascii_case("safetykit") =>
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
             `svix`, `resend`, `messagebird`, `bird`, `gitlab`, `clerk`, `openai`, `warp`, `loops`, `anthropic`, `gemini`, `brex`, `bigcommerce`, `lithic`, `incident.io`/`incident`, `supabase`, `etsy`, `sardine`, `dodo`/`dodopayments`, `zapier`, `vanta`, `safetykit` (for `standardwebhooks`)); `custom` requires a `CustomScheme` and must be built directly",
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProviderParseError {}

/// Header names that carry signing material for `provider`, per its row in
/// `spec.md` §3.
///
/// Used by framework adapters (behind the `tower`/`actix` features) to reject
/// requests whose signature headers arrive duplicated with conflicting values
/// — see the ambiguity contract on [`crate::HeaderMap`] and `spec.md` §4.4,
/// which the first-match-only lookup cannot detect on its own.
///
/// Returns an empty list for providers whose implementation is disabled by a
/// feature flag; their verification fails closed with
/// [`VerifyError::UnsupportedProvider`] regardless.
#[cfg(any(feature = "tower", feature = "actix"))]
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
        ],
        Provider::Custom(scheme) => {
            // Only the two declared headers are scanned for duplicates.
            // Additional headers read by signed_string are *not* covered —
            // see the CustomScheme struct-level safety note.
            let mut names = vec![scheme.signature_header];
            if let Some(timestamp) = scheme.timestamp_header {
                names.push(timestamp);
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

/// Verifies that a webhook request was sent by `provider` and was not tampered
/// with in transit.
///
/// * `headers` — request headers via [`HeaderMap`] (any framework's map works).
/// * `raw_body` — the **exact bytes** received. Never re-serialize or
///   re-encode the body before calling this.
/// * `secret` — the shared secret configured with the provider. For asymmetric
///   schemes (Discord) it holds the public key instead; each provider's docs
///   state which applies.
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
pub fn verify(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: VerifyOptions,
) -> Result<(), VerifyError> {
    // The by-value signature is pure ergonomics: no provider mutates its
    // options, so delegate to the borrowing dispatch below immediately rather
    // than ever cloning the caller's options.
    verify_ref(provider, headers, raw_body, secret, &options)
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
pub(crate) fn verify_ref(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
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
/// For providers whose signing scheme itself embeds multiple signatures
/// (Stripe's `v1=` list, Standard Webhooks' space-delimited `v1,<sig>`
/// list), prefer [`verify()`] with a single secret — the per-provider
/// multi-sig logic already accepts any matching element. `verify_any` is
/// for the *separate* case where the provider's config allows *multiple
/// distinct keys* to be valid simultaneously (e.g. during key rotation).
///
/// # Asymmetric providers
///
/// Rotation via a slice of [`Secret`]s is only meaningful for providers
/// whose scheme is keyed by a shared secret. The asymmetric providers —
/// PayPal and SendGrid — ignore the `Secret` entirely: they verify against
/// [`VerifyOptions::verifying_material`] (and for PayPal, `webhook_id`),
/// so every element of the slice behaves identically and `verify_any` gives
/// them no rotation semantics. It still degrades safely: structural errors
/// (`MissingContext` for absent key material, `MissingHeader`, etc.) are
/// returned immediately, so passing an asymmetric provider here cannot
/// silently panic or loop. For genuine rotation of asymmetric key material,
/// supply the current key via [`VerifyOptions::verifying_material`] and
/// re-verify when it rotates, rather than using `verify_any`.
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
///     VerifyOptions::default().with_max_age(None),
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
pub fn verify_any(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secrets: &[Secret],
    options: VerifyOptions,
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
        // Verify against a single borrow of `options`, not a fresh deep clone
        // per secret: rotation slices are iterated on the hot path, and the
        // options may carry heap-allocated context (`verifying_material`,
        // `request_url`, `form_params`) that costs a redundant allocation to
        // copy for every key.
        match verify_ref(provider, headers, raw_body, secret, &options) {
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
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
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

    #[test]
    fn provider_display_names() {
        use super::CustomScheme;
        use crate::{Encoding, HashAlg};

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
            encoding: Encoding::Hex,
            prefix: None,
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
            encoding: Encoding::Base64,
            prefix: Some("v1="),
            signed_string: |_h, b| b.to_vec(),
        });
        assert_eq!(
            prefixed.to_string(),
            "Custom(X-My-Sig, SHA-512, base64, prefix `v1=`, timestamp header `X-My-Ts`)"
        );
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
        // `dodo`/`dodopayments`/`zapier`/`vanta`/`safetykit` ↔ StandardWebhooks); the
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
        ] {
            assert!(
                message.contains(&format!("`{alias}`")),
                "error message should list the `{alias}` alias so operators can recover"
            );
        }
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
        // the sorted doc-bullet names must equal the sorted committed file
        // names exactly, so adding, renaming, or dropping either side fails CI
        // instead of drifting. `Custom`-shaped seeds are covered too — they
        // are explicit target configurations, not name-constructible providers,
        // but their seeds are documented the same way.
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
                .collect(),
            // `fuzz/corpus/parse_and_verify/` not present (e.g. the publish
            // tarball): same skip as above.
            Err(_) => return,
        };
        files.sort();

        assert_eq!(
            bullets,
            files,
            "fuzz seed doc bullets ({} in `fuzz_targets/parse_and_verify.rs`) must mirror the committed `fuzz/corpus/parse_and_verify/` files ({} found) exactly — a bullet for a never-committed seed or a committed seed with no doc bullet both fail here",
            bullets.len(),
            files.len(),
        );
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

    /// The first-column brand-name cells of the "Supported providers" table
    /// in `markdown` (the crate-doc tables live in `//!` doc comments), with
    /// the header and separator rows excluded. Test helper over compile-time
    /// `include_str!` data, so the `.unwrap_or` fall back is unreachable.
    fn provider_table_cells(markdown: &str) -> Vec<String> {
        let mut cells = Vec::new();
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
                    cells.push(String::from(cell));
                }
            } else {
                break;
            }
        }
        cells
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

    #[cfg(any(feature = "tower", feature = "actix"))]
    #[test]
    fn signature_header_names_cover_every_provider_header() {
        // `signature_header_names` is the list the tower/actix adapters scan
        // for conflicting duplicate headers (spec.md §4.4) — the mechanism
        // that stops a proxy from smuggling a forged value in a duplicate
        // header the verifier reads while the validator does not. This guard
        // pins each provider's adapter-visible headers to the exact constants
        // its implementation reads, so a header dropped from the list — say
        // `HubSpot` losing its timestamp — is caught instead of silently
        // weakening the ambiguity check. Keep this table in lockstep with
        // `signature_header_names` when a provider changes.
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
                ],
            ),
            // Custom covers exactly its two declared headers — additional
            // headers read by `signed_string` are outside the adapters' scan
            // (documented caveat on `CustomScheme`).
            (
                Provider::Custom(CustomScheme {
                    hash: HashAlg::Sha256,
                    signature_header: "X-Acme-Signature",
                    timestamp_header: Some("X-Acme-Timestamp"),
                    encoding: Encoding::Hex,
                    prefix: None,
                    signed_string: |_headers, raw_body| raw_body.to_vec(),
                }),
                &["X-Acme-Signature", "X-Acme-Timestamp"],
            ),
            (
                Provider::Custom(CustomScheme {
                    hash: HashAlg::Sha256,
                    signature_header: "X-Acme-Signature",
                    timestamp_header: None,
                    encoding: Encoding::Hex,
                    prefix: None,
                    signed_string: |_headers, raw_body| raw_body.to_vec(),
                }),
                &["X-Acme-Signature"],
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
