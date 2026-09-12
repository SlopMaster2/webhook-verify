//! Provider-specific signing schemes and the [`verify`] dispatch.
//!
//! Each provider lives in its own module implementing exactly the scheme
//! documented in `spec.md` §3, backed by that provider's official test
//! vectors. Feature-disabled providers fail closed with
//! [`VerifyError::UnsupportedProvider`].

mod cloudflare;
mod coinbase;
mod custom;
mod discord;
mod dropbox;
mod github;
mod linear;
mod notion;
mod paddle;
#[cfg(feature = "paypal")]
mod paypal;
#[cfg(feature = "sendgrid")]
mod sendgrid;
mod shopify;
mod slack;
mod square;
mod standard_webhooks;
mod stripe;
mod twilio;
mod xero;
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
    /// Shopify (`X-Shopify-Hmac-SHA256`, base64-encoded HMAC-SHA256).
    Shopify,
    /// Slack (`X-Slack-Signature`, `v0=` scheme with timestamp).
    Slack,
    /// Square (HMAC-SHA256 over notification URL + body, base64).
    Square,
    /// Twilio (HMAC-SHA1 over full URL + sorted form params; needs
    /// `VerifyOptions::request_url` and `VerifyOptions::form_params`).
    Twilio,
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
    /// Paddle (`Paddle-Signature`, HMAC-SHA256 over `{ts}:{raw_body}`, with
    /// timestamp replay protection; multiple `h1=` values accepted).
    ///
    /// Paddle signs a local timestamp into the header, so requests are
    /// rejected when the included timestamp differs from the verifying
    /// clock's "now" by more than [`VerifyOptions::max_age`] (default 300s).
    Paddle,
    /// Linear (`linear-signature`, HMAC-SHA256).
    Linear,
    /// Notion (`X-Notion-Signature`, HMAC-SHA256 over the raw body, hex,
    /// `sha256=` prefix). The signing key is the subscription's
    /// `verification_token` from the one-time handshake.
    Notion,
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
    /// Xero (`x-xero-signature`, base64-encoded HMAC-SHA256 over the raw body).
    Xero,
    /// Standard Webhooks spec (`webhook-*` headers; Svix, Clerk, Resend, ...).
    StandardWebhooks,
    /// A caller-configured HMAC scheme (`spec.md` §2.2): covers long-tail
    /// providers and internal senders without waiting on a crate release,
    /// with the same constant-time and fail-closed guarantees as the
    /// built-ins. See [`CustomScheme`].
    Custom(CustomScheme),
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Provider::Stripe => f.write_str("Stripe"),
            Provider::GitHub => f.write_str("GitHub"),
            Provider::Shopify => f.write_str("Shopify"),
            Provider::Slack => f.write_str("Slack"),
            Provider::Square => f.write_str("Square"),
            Provider::Twilio => f.write_str("Twilio"),
            Provider::Discord => f.write_str("Discord"),
            Provider::PayPal => f.write_str("PayPal"),
            Provider::SendGrid => f.write_str("SendGrid"),
            Provider::Paddle => f.write_str("Paddle"),
            Provider::Linear => f.write_str("Linear"),
            Provider::Notion => f.write_str("Notion"),
            Provider::Zoom => f.write_str("Zoom"),
            Provider::Cloudflare => f.write_str("Cloudflare"),
            Provider::Coinbase => f.write_str("Coinbase"),
            Provider::Dropbox => f.write_str("Dropbox"),
            Provider::Xero => f.write_str("Xero"),
            Provider::StandardWebhooks => f.write_str("StandardWebhooks"),
            Provider::Custom(scheme) => {
                write!(f, "Custom({})", scheme.signature_header)
            }
        }
    }
}

/// Error returned when a string does not name a known [`Provider`] (from
/// the [`core::str::FromStr`] implementation).
///
/// Parsing is case-insensitive and accepts exactly the canonical
/// [`fmt::Display`] spelling of each provider (e.g. `"github"`, `"GitHub"`,
/// `"GITHUB"`).
/// [`Provider::Custom`] cannot be parsed from a bare name — constructing one
/// requires a [`CustomScheme`] — so `"custom"` is rejected like any unknown
/// name.
impl core::str::FromStr for Provider {
    type Err = ProviderParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            n if n.eq_ignore_ascii_case("stripe") => Ok(Provider::Stripe),
            n if n.eq_ignore_ascii_case("github") => Ok(Provider::GitHub),
            n if n.eq_ignore_ascii_case("shopify") => Ok(Provider::Shopify),
            n if n.eq_ignore_ascii_case("slack") => Ok(Provider::Slack),
            n if n.eq_ignore_ascii_case("square") => Ok(Provider::Square),
            n if n.eq_ignore_ascii_case("twilio") => Ok(Provider::Twilio),
            n if n.eq_ignore_ascii_case("discord") => Ok(Provider::Discord),
            n if n.eq_ignore_ascii_case("paypal") => Ok(Provider::PayPal),
            n if n.eq_ignore_ascii_case("sendgrid") => Ok(Provider::SendGrid),
            n if n.eq_ignore_ascii_case("paddle") => Ok(Provider::Paddle),
            n if n.eq_ignore_ascii_case("linear") => Ok(Provider::Linear),
            n if n.eq_ignore_ascii_case("notion") => Ok(Provider::Notion),
            n if n.eq_ignore_ascii_case("zoom") => Ok(Provider::Zoom),
            n if n.eq_ignore_ascii_case("cloudflare") => Ok(Provider::Cloudflare),
            n if n.eq_ignore_ascii_case("coinbase") => Ok(Provider::Coinbase),
            n if n.eq_ignore_ascii_case("dropbox") => Ok(Provider::Dropbox),
            n if n.eq_ignore_ascii_case("xero") => Ok(Provider::Xero),
            n if n.eq_ignore_ascii_case("standardwebhooks") => Ok(Provider::StandardWebhooks),
            _ => Err(ProviderParseError),
        }
    }
}

/// The error type for [`Provider`]'s [`core::str::FromStr`] implementation.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderParseError;

impl fmt::Display for ProviderParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "unknown provider name: expected one of `stripe`, `github`, `shopify`, `slack`, \
             `square`, `twilio`, `discord`, `paypal`, `sendgrid`, `paddle`, `linear`, `notion`, \
             `zoom`, `cloudflare`, `coinbase`, `dropbox`, `xero`, or `standardwebhooks` \
             (case-insensitive); `custom` requires a `CustomScheme` and must be built directly",
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
        Provider::Shopify => vec![shopify::SIGNATURE_HEADER],
        Provider::Slack => vec![slack::SIGNATURE_HEADER, slack::TIMESTAMP_HEADER],
        Provider::Square => vec![square::SIGNATURE_HEADER],
        Provider::Twilio => vec![twilio::SIGNATURE_HEADER],
        Provider::Discord => {
            vec![discord::SIGNATURE_HEADER, discord::TIMESTAMP_HEADER]
        }
        Provider::Linear => vec![linear::SIGNATURE_HEADER],
        Provider::Notion => vec![notion::SIGNATURE_HEADER],
        Provider::Cloudflare => vec![cloudflare::SIGNATURE_HEADER],
        Provider::Coinbase => vec![coinbase::SIGNATURE_HEADER],
        Provider::Dropbox => vec![dropbox::SIGNATURE_HEADER],
        Provider::Xero => vec![xero::SIGNATURE_HEADER],
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
    match provider {
        Provider::Discord => discord::verify(headers, raw_body, secret, &options),
        Provider::GitHub => github::verify(headers, raw_body, secret, &options),
        Provider::Linear => linear::verify(headers, raw_body, secret, &options),
        Provider::Notion => notion::verify(headers, raw_body, secret, &options),
        Provider::Zoom => zoom::verify(headers, raw_body, secret, &options),
        Provider::Shopify => shopify::verify(headers, raw_body, secret, &options),
        Provider::Slack => slack::verify(headers, raw_body, secret, &options),
        Provider::Square => square::verify(headers, raw_body, secret, &options),
        Provider::Stripe => stripe::verify(headers, raw_body, secret, &options),
        Provider::StandardWebhooks => {
            standard_webhooks::verify(headers, raw_body, secret, &options)
        }
        Provider::Twilio => twilio::verify(headers, raw_body, secret, &options),
        Provider::Cloudflare => cloudflare::verify(headers, raw_body, secret, &options),
        Provider::Coinbase => coinbase::verify(headers, raw_body, secret, &options),
        Provider::Dropbox => dropbox::verify(headers, raw_body, secret, &options),
        Provider::Xero => xero::verify(headers, raw_body, secret, &options),
        #[cfg(feature = "paypal")]
        Provider::PayPal => paypal::verify(headers, raw_body, secret, &options),
        #[cfg(not(feature = "paypal"))]
        Provider::PayPal => Err(VerifyError::UnsupportedProvider),
        #[cfg(feature = "sendgrid")]
        Provider::SendGrid => sendgrid::verify(headers, raw_body, secret, &options),
        #[cfg(not(feature = "sendgrid"))]
        Provider::SendGrid => Err(VerifyError::UnsupportedProvider),
        Provider::Paddle => paddle::verify(headers, raw_body, secret, &options),
        Provider::Custom(scheme) => custom::verify(&scheme, headers, raw_body, secret, &options),
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
        match verify(provider, headers, raw_body, secret, options.clone()) {
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
        assert_eq!(Provider::Shopify.to_string(), "Shopify");
        assert_eq!(Provider::Slack.to_string(), "Slack");
        assert_eq!(Provider::Square.to_string(), "Square");
        assert_eq!(Provider::Twilio.to_string(), "Twilio");
        assert_eq!(Provider::Discord.to_string(), "Discord");
        assert_eq!(Provider::PayPal.to_string(), "PayPal");
        assert_eq!(Provider::SendGrid.to_string(), "SendGrid");
        assert_eq!(Provider::Paddle.to_string(), "Paddle");
        assert_eq!(Provider::Linear.to_string(), "Linear");
        assert_eq!(Provider::Notion.to_string(), "Notion");
        assert_eq!(Provider::Zoom.to_string(), "Zoom");
        assert_eq!(Provider::Cloudflare.to_string(), "Cloudflare");
        assert_eq!(Provider::Coinbase.to_string(), "Coinbase");
        assert_eq!(Provider::Dropbox.to_string(), "Dropbox");
        assert_eq!(Provider::Xero.to_string(), "Xero");
        assert_eq!(Provider::StandardWebhooks.to_string(), "StandardWebhooks");

        let custom = Provider::Custom(CustomScheme {
            hash: HashAlg::Sha256,
            signature_header: "X-My-Sig",
            timestamp_header: None,
            encoding: Encoding::Hex,
            prefix: None,
            signed_string: |_h, b| b.to_vec(),
        });
        assert_eq!(custom.to_string(), "Custom(X-My-Sig)");
    }

    #[test]
    fn provider_from_str_accepts_canonical_names_case_insensitively() {
        use core::str::FromStr;

        let cases = [
            ("stripe", Provider::Stripe),
            ("github", Provider::GitHub),
            ("shopify", Provider::Shopify),
            ("slack", Provider::Slack),
            ("square", Provider::Square),
            ("twilio", Provider::Twilio),
            ("discord", Provider::Discord),
            ("paypal", Provider::PayPal),
            ("sendgrid", Provider::SendGrid),
            ("paddle", Provider::Paddle),
            ("linear", Provider::Linear),
            ("notion", Provider::Notion),
            ("zoom", Provider::Zoom),
            ("cloudflare", Provider::Cloudflare),
            ("coinbase", Provider::Coinbase),
            ("dropbox", Provider::Dropbox),
            ("xero", Provider::Xero),
            ("standardwebhooks", Provider::StandardWebhooks),
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
    fn provider_display_round_trips_through_from_str() {
        let providers = [
            Provider::Stripe,
            Provider::GitHub,
            Provider::Shopify,
            Provider::Slack,
            Provider::Square,
            Provider::Twilio,
            Provider::Discord,
            Provider::PayPal,
            Provider::SendGrid,
            Provider::Paddle,
            Provider::Linear,
            Provider::Notion,
            Provider::Zoom,
            Provider::Cloudflare,
            Provider::Coinbase,
            Provider::Dropbox,
            Provider::Xero,
            Provider::StandardWebhooks,
        ];
        for provider in providers {
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
    }

    /// Every name-constructible [`Provider`] variant. Kept beside the
    /// parse-error guard it serves; the display/round-trip tests retain their
    /// own explicit lists so a mismatch between the two is caught, not
    /// masked by shared state.
    fn provider_list() -> [Provider; 18] {
        [
            Provider::Stripe,
            Provider::GitHub,
            Provider::Shopify,
            Provider::Slack,
            Provider::Square,
            Provider::Twilio,
            Provider::Discord,
            Provider::PayPal,
            Provider::SendGrid,
            Provider::Paddle,
            Provider::Linear,
            Provider::Notion,
            Provider::Zoom,
            Provider::Cloudflare,
            Provider::Coinbase,
            Provider::Dropbox,
            Provider::Xero,
            Provider::StandardWebhooks,
        ]
    }
}
