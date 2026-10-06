//! Verification options: timestamp tolerance, clock injection, and asymmetric
//! verification material for public-key providers.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::SystemTime;

/// Source of "now", injectable so replay-protection tests are deterministic.
///
/// Returns unix seconds (the number of whole seconds since the Unix epoch);
/// this keeps the crate `no_std + alloc` compatible (`spec.md` §1) — there is
/// no wall clock in the no_std ecosystem, so callers on such targets supply
/// their own implementation (e.g. from a platform RTC or NTP-synced counter).
///
/// Only providers whose scheme signs a timestamp use a clock; for others
/// (GitHub, Shopify) no `Clock` is consulted.
///
/// # Testing a replay window
///
/// A built-in timestamped provider's signature covers its own timestamp, so a
/// test cannot exercise the window by rewriting the header alone — the HMAC
/// stops matching. Injecting a clock is what makes both halves of the window
/// assertable, and [`FixedClock`] is the ready-made clock for it: pin "now"
/// to the instant the signature was minted over, then move it and watch the
/// delivery go stale.
///
/// ```
/// use std::sync::Arc;
/// use webhook_verify::{FixedClock, Provider, Secret, VerifyError, VerifyOptions, verify};
///
/// // A Stripe delivery signed at unix 1700000000. The signature is the
/// // crate's own locally constructed vector (see `src/providers/stripe.rs`):
/// // HMAC-SHA256("whsec_test_secret", "1700000000.{...}").
/// let headers: Vec<(&str, &str)> = vec![(
///     "Stripe-Signature",
///     "t=1700000000,v1=d95c6b7477fbd7e9f90b1b0ef5f9c7ac25abca5382460e0d988c2b2a5b71b990",
/// )];
/// let body = br#"{"id":"evt_test_webhook","object":"event"}"#;
/// let secret = Secret::new("whsec_test_secret");
///
/// // Inside the default 300s window: "now" is 5s after the signed timestamp.
/// let at = VerifyOptions::default().with_clock(Some(Arc::new(FixedClock(1_700_000_005))));
/// assert_eq!(verify(Provider::Stripe, &headers, body, &secret, at), Ok(()));
///
/// // The very same bytes, replayed ten minutes later, are refused — and as a
/// // replay rejection rather than a signature mismatch, which is the
/// // distinction a caller counts and logs differently.
/// let stale = VerifyOptions::default().with_clock(Some(Arc::new(FixedClock(1_700_000_600))));
/// assert!(matches!(
///     verify(Provider::Stripe, &headers, body, &secret, stale),
///     Err(VerifyError::TimestampOutOfTolerance { .. }),
/// ));
/// ```
pub trait Clock: Send + Sync {
    /// The current time as unix seconds.
    #[must_use]
    fn now(&self) -> u64;
}

/// The default [`Clock`]: real wall-clock time. Only available under the
/// `std` feature, which is on by default.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// A [`Clock`] pinned to a fixed instant, for deterministic tests.
///
/// Every built-in timestamped provider HMACs its own timestamp into the signed
/// string, so a test cannot age a delivery by editing the header — the
/// signature stops matching and the replay window is never reached. Injecting
/// the clock is what makes the window assertable: sign at `t`, pin "now" to
/// `t + 5` and the delivery verifies, pin it to `t + 600` and the same bytes
/// come back
/// [`VerifyError::TimestampOutOfTolerance`](crate::VerifyError::TimestampOutOfTolerance)
/// instead of verifying.
///
/// [`Clock`]'s own docs have the worked example; this type is what makes it
/// three lines rather than a hand-rolled impl. It is the same type the
/// crate's own provider tests use, so a downstream test and an upstream one
/// read the same.
///
/// Deliberately not feature-gated (unlike `SystemClock`, which needs `std`):
/// it is a bare `u64` wrapper that touches nothing outside `core`, so it is
/// available in every configuration this crate builds — including the
/// `no_std + alloc` ones, where it is the *only* clock a test can use because
/// `SystemClock` is absent and a real wall clock does not exist. (Spelled as
/// plain text for the same reason the crate's other feature-gated mentions are:
/// a link from an unconditionally-compiled doc context to a `std`-gated item
/// resolves under `--all-features` and fails as an unresolved link without it.)
///
/// Not for production: a [`FixedClock`] never advances, so it accepts a
/// timestamp exactly `max_age` old forever. Use `SystemClock` (or your own
/// [`Clock`]) in anything that faces real traffic.
///
/// [`FixedClock::default`] is the unix epoch, which fails the other way — every
/// realistic delivery timestamp reads as decades stale and comes back
/// `TimestampOutOfTolerance`. Both directions are refusals, so neither default
/// can widen what `verify()` accepts.
///
/// ```
/// use webhook_verify::{Clock, FixedClock};
///
/// let clock = FixedClock(1_700_000_000);
/// assert_eq!(clock.now(), 1_700_000_000);
/// // Two reads are two identical answers — that is the point.
/// assert_eq!(clock.now(), clock.now());
/// ```
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

/// Caller-supplied asymmetric verification material (`spec.md` §7).
///
/// Providers that verify against a configured public key or certificate
/// (currently SendGrid and PayPal) take their key material here
/// rather than in a [`Secret`](crate::Secret), because unlike the shared
/// symmetric schemes the signing key is never a private value this crate
/// holds — it is the provider's own *public* key. This crate **never** fetches
/// key material over the network (`spec.md` §1); the caller supplies bytes
/// already vetted (allow-listed certificate URL, checked key, etc.).
#[must_use]
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum VerifyingKeyMaterial {
    /// DER- or PEM-encoded X.509 certificate (PayPal scheme). Only the embedded
    /// public key is used; this crate performs no chain validation, so callers
    /// needing chain/pin enforcement supply an already-validated certificate.
    X509Certificate(Vec<u8>),
    /// DER bytes of an ECDSA P-256 `SubjectPublicKeyInfo` public key (SendGrid
    /// scheme), decoded by the caller from the provider's published base64
    /// form (the dashboard "Verification Key").
    EcdsaP256PublicKey(Vec<u8>),
}

impl fmt::Debug for VerifyingKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact key/certificate bytes: consistent with the crate-wide rule
        // that no secret-bearing material appears in `Debug` output. The
        // variant name and byte length are enough to diagnose configuration.
        match self {
            VerifyingKeyMaterial::X509Certificate(bytes) => f
                .debug_tuple("X509Certificate")
                .field(&format_args!("<{} bytes>", bytes.len()))
                .finish(),
            VerifyingKeyMaterial::EcdsaP256PublicKey(bytes) => f
                .debug_tuple("EcdsaP256PublicKey")
                .field(&format_args!("<{} bytes>", bytes.len()))
                .finish(),
        }
    }
}

/// Tuning knobs for [`crate::verify()`].
///
/// `#[non_exhaustive]`: new knobs are expected to arrive, and adding a field
/// must never break downstream callers. Outside this crate the fields are
/// therefore configured only through [`Default`] and the `with_*` builder
/// methods — struct-literal construction is intentionally unavailable.
///
/// ```
/// use std::time::Duration;
/// use webhook_verify::VerifyOptions;
///
/// let opts = VerifyOptions::default().with_max_age(Some(Duration::from_secs(600)));
/// assert_eq!(opts.max_age, Some(Duration::from_secs(600)));
/// ```
#[must_use]
#[non_exhaustive]
#[derive(Clone)]
pub struct VerifyOptions {
    /// Maximum allowed age between a signed timestamp and "now", for providers
    /// whose scheme includes a timestamp. `None` disables the check (not
    /// recommended) — reach for
    /// [`VerifyOptions::without_replay_protection`] rather than
    /// `with_max_age(None)`, so the call site says so. Default: 300 seconds,
    /// matching Stripe's and Slack's own SDK defaults.
    ///
    /// Providers that do not sign timestamps document explicitly that this
    /// option has no effect on them (see `spec.md` §3).
    pub max_age: Option<Duration>,
    /// Clock used for "now". `None` means real system time under the `std`
    /// feature; on a `no_std + alloc` target with no clock injected,
    /// [`VerifyOptions::now`] has no wall clock to consult and reads 0, so
    /// replay-protected providers fail closed on every realistic delivery
    /// timestamp until the caller supplies a [`Clock`] (`spec.md` §1, §7).
    /// Injectable for deterministic tests of timestamp-based providers.
    pub clock: Option<Arc<dyn Clock>>,
    /// Full URL of the receiving endpoint, required by providers whose
    /// signature incorporates it (currently Square, whose scheme signs the
    /// notification URL followed by the raw body; Twilio, which signs the full
    /// request URL; HubSpot's v3 scheme, which signs the request method + full
    /// request URI + body + timestamp; Contentful, which signs the request path
    /// derived from this URL as the second element of its canonical string; and
    /// Mailchimp Transactional (Mandrill), which signs the webhook URL followed
    /// by the sorted form params). The
    /// value must match the URL configured with the provider **exactly** — a
    /// differing trailing slash or scheme makes every signature fail.
    /// Providers whose scheme does not sign the URL document that this option
    /// has no effect on them.
    ///
    /// HubSpot itself **URL-decodes certain characters** in the URI when
    /// computing its signature (the list is in `spec.md` §3, HubSpot row).
    /// The crate treats `request_url` as an exact verbatim constant — it
    /// neither adds nor removes encoding — so a proxied or configured URI
    /// carrying percent-encoding must be passed in the same decoded form
    /// HubSpot signed, or every delivery fails with `SignatureMismatch`.
    ///
    /// Supplying the configured constant from the provider dashboard is the
    /// intended use; reconstructing the URL from request headers behind a
    /// proxy is a common source of verification failures.
    ///
    /// Twilio has one extra trap here that is worth knowing about: its signing
    /// backend is known to be inconsistent about whether the port appears in
    /// the URL it signs, and the official SDKs sign both the port-qualified and
    /// port-stripped spellings, accepting either. This crate signs the value
    /// here verbatim and retries no alternate URL, so a Twilio integration
    /// whose `request_url` port spelling differs from the signed one fails
    /// every delivery with `SignatureMismatch`. That reads like an active
    /// attack rather than a configuration mismatch, so if a Twilio receiver
    /// rejects all traffic, try the other port spelling before suspecting
    /// forgery. See `spec.md` §3's Twilio entry.
    pub request_url: Option<String>,
    /// HTTP request method (uppercase, e.g. `POST`), required by providers
    /// whose scheme signs it (currently HubSpot's v3 scheme, which signs
    /// `{method}{uri}{raw_body}{timestamp}`, and Contentful, whose canonical
    /// string leads with the method). Must match the method the provider
    /// actually sent for the delivery. Providers whose scheme does not sign
    /// the method document that this option has no effect on them.
    pub request_method: Option<String>,
    /// Form fields for the two schemes that sign *parsed* fields rather than
    /// the body bytes (Twilio and Mailchimp Transactional/Mandrill): their
    /// signatures cover the request URL concatenated with the sorted form-field
    /// names/values.
    ///
    /// **Leaving this unset is the normal case.** When it is `None` the fields
    /// are decoded from the `raw_body` argument, which is the same bytes every
    /// raw-body scheme verifies — `application/x-www-form-urlencoded`, one
    /// field per `&`-separated element, `+` read as a space and `%XX` as the
    /// byte it names, then sorted as below. That is what makes those two
    /// providers verifiable through a framework adapter: both adapters hold
    /// **one** `VerifyOptions` for every delivery, so a field list configured
    /// on a layer could only ever describe one delivery's body (issue #363).
    /// Set it only to override the derivation — to supply fields from a
    /// framework's own parser, or to express "this body is not fields".
    ///
    /// Whichever source is used, pass **every** field as received — Twilio's
    /// docs explicitly warn against verifying against a hardcoded subset,
    /// since providers may add parameters without notice. Sorting is applied
    /// here (it is part of the signing scheme), so fields arrive in any order.
    /// Under a repeated field name the values are sorted and de-duplicated as
    /// well, matching the providers' reference implementations; the same
    /// multiset of fields therefore verifies regardless of the order it
    /// arrived in.
    ///
    /// An explicitly empty list is meaningful and is *not* the same as leaving
    /// the option out: it is how Twilio's JSON-body variant is expressed (the
    /// body is not form fields, so the signature covers the URL alone, leaving
    /// the body authenticated only by the `bodySHA256` query parameter Twilio
    /// appends to the URL — which is then verified against `raw_body`).
    /// Decoding a JSON body as form fields instead produces a different signed
    /// string, so that variant still has to ask for the empty list.
    pub form_params: Option<Vec<(String, String)>>,
    /// Verification material for providers whose scheme checks a signature
    /// against a configured public key/certificate rather than a shared secret
    /// (currently SendGrid and PayPal). See [`VerifyingKeyMaterial`].
    ///
    /// Required-but-absent fails closed with [`crate::VerifyError::MissingContext`]
    /// (caller misconfiguration, mirroring Square/Twilio's context options);
    /// malformed material fails with [`crate::VerifyError::InvalidSecret`].
    ///
    /// This crate never fetches key material itself (`spec.md` §7): the caller
    /// supplies bytes that were already obtained and vetted out-of-band.
    pub verifying_material: Option<VerifyingKeyMaterial>,
    /// PayPal's webhook ID, required by PayPal's signed-string construction
    /// (`spec.md` §3). It is *not* a request header or body field — it is the
    /// ID of the webhook subscription (shown in the PayPal Developer Portal
    /// for the listener URL) and must be supplied by the caller, mirroring
    /// Square/Twilio's URL context.
    ///
    /// Required-but-absent for `Provider::PayPal` fails closed with
    /// [`crate::VerifyError::MissingContext`]; an explicitly empty value is
    /// treated the same way, so operator misconfiguration is never surfaced
    /// as an attack-looking signature mismatch. Providers whose scheme does
    /// not sign a webhook ID document that this option has no effect on them.
    pub webhook_id: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            max_age: Some(Duration::from_secs(300)),
            clock: None,
            request_url: None,
            request_method: None,
            form_params: None,
            verifying_material: None,
            webhook_id: None,
        }
    }
}

impl VerifyOptions {
    /// Sets [`VerifyOptions::request_url`], for URL-scoped schemes.
    pub fn with_request_url(mut self, url: impl Into<String>) -> Self {
        self.request_url = Some(url.into());
        self
    }

    /// Sets [`VerifyOptions::request_method`], the HTTP request method
    /// (uppercase) for schemes that sign it (currently HubSpot's v3 scheme
    /// and Contentful).
    pub fn with_request_method(mut self, method: impl Into<String>) -> Self {
        self.request_method = Some(method.into());
        self
    }

    /// Sets [`VerifyOptions::form_params`] for the schemes that sign parsed
    /// form fields (currently Twilio and Mandrill), overriding the derivation
    /// from `raw_body` described on the field. Fields are sorted into signing
    /// order during verification of those signed strings, so fields may be
    /// passed in any order. Under a repeated field name the values are sorted
    /// and de-duplicated too, matching the providers' reference
    /// implementations, so the same multiset of same-named values signs the
    /// same string however it arrived. Passing no items is the explicit
    /// *empty* field set — Twilio's JSON-body variant — which is not the same
    /// as leaving the option unset.
    pub fn with_form_params<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.form_params = Some(
            params
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        );
        self
    }

    /// Sets [`VerifyOptions::max_age`], the maximum allowed clock skew for
    /// providers whose scheme signs a timestamp. The default is
    /// `Some(Duration::from_secs(300))`.
    ///
    /// **Passing `None` disables replay protection.** That spelling reads like
    /// ordinary configuration at the call site while its effect is permanent
    /// acceptance: every timestamped provider stops enforcing
    /// `|now - t| <= max_age` for as long as this options object is in place, a
    /// replayed capture verifies forever, and `TimestampOutOfTolerance` can no
    /// longer be produced, so nothing signals it. Use
    /// [`VerifyOptions::without_replay_protection`] to spell that — the name
    /// greps, and the intent is readable at the call site rather than only in
    /// a doc comment.
    ///
    /// ```
    /// use std::time::Duration;
    /// use webhook_verify::VerifyOptions;
    ///
    /// // Widening the window is ordinary configuration and stays a bare value.
    /// let lenient = VerifyOptions::default().with_max_age(Some(Duration::from_secs(600)));
    /// assert_eq!(lenient.max_age, Some(Duration::from_secs(600)));
    ///
    /// // Turning the window *off* has a name that says so.
    /// let off = VerifyOptions::default().without_replay_protection();
    /// assert_eq!(off.max_age, None);
    /// ```
    ///
    /// Providers that do not sign timestamps document explicitly that this
    /// option has no effect on them (see `spec.md` §3).
    pub fn with_max_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    /// Turns timestamp-based replay protection **off**, i.e. sets
    /// [`VerifyOptions::max_age`] to `None`. Same state as
    /// `with_max_age(None)`, under a name that states the consequence where it
    /// is written rather than only in a doc comment.
    ///
    /// This is the dangerous direction, which is why it gets its own builder.
    /// Once `max_age` is `None`, every provider whose scheme signs a timestamp
    /// stops rejecting an old delivery: a captured request replays forever, and
    /// `VerifyError::TimestampOutOfTolerance` can no longer be produced for
    /// this options object, so there is no wire-level signal that the window
    /// is gone — the failure mode is silence, not a rejection. `spec.md` §4
    /// states the crate's bias as loud over silent.
    ///
    /// Before calling this, check that the real problem is replay protection
    /// rather than clock skew: a legitimate delivery arriving late is the
    /// symptom a *wider* [`VerifyOptions::with_max_age`] fixes, and widening
    /// keeps the check in place. Injecting a [`Clock`] (see
    /// [`VerifyOptions::with_clock`]) is how to reproduce the window in a test
    /// that needs to assert the difference.
    ///
    /// ```
    /// use webhook_verify::VerifyOptions;
    ///
    /// assert!(VerifyOptions::default().max_age.is_some());
    /// assert_eq!(
    ///     VerifyOptions::default().without_replay_protection().max_age,
    ///     None,
    /// );
    /// ```
    pub fn without_replay_protection(mut self) -> Self {
        self.max_age = None;
        self
    }

    /// Sets [`VerifyOptions::clock`], the source of "now" used for replay
    /// protection. `None` uses real system time under the `std` feature; on a
    /// `no_std` target it leaves [`VerifyOptions::now`] reading 0, which
    /// fail-closes replay-protected providers until a [`Clock`] is injected.
    /// Injectable for deterministic tests of timestamp-based providers —
    /// [`FixedClock`] is the ready-made clock for that, and [`Clock`]'s docs
    /// show a replay window asserted end to end.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use webhook_verify::{FixedClock, VerifyOptions};
    ///
    /// let opts = VerifyOptions::default().with_clock(Some(Arc::new(FixedClock(1_700_000_000))));
    /// assert_eq!(opts.now(), 1_700_000_000);
    /// ```
    pub fn with_clock(mut self, clock: Option<Arc<dyn Clock>>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets [`VerifyOptions::verifying_material`], the asymmetric public-key
    /// /certificate material required by public-key schemes (currently
    /// SendGrid's ECDSA P-256 key and PayPal's X.509 certificate).
    pub fn with_verifying_material(mut self, material: VerifyingKeyMaterial) -> Self {
        self.verifying_material = Some(material);
        self
    }

    /// Sets [`VerifyOptions::webhook_id`], PayPal's webhook-subscription ID,
    /// required by PayPal's signed-string construction (see the field docs).
    pub fn with_webhook_id(mut self, webhook_id: impl Into<String>) -> Self {
        self.webhook_id = Some(webhook_id.into());
        self
    }

    /// Resolves "now" in unix seconds from the injected clock, falling back to
    /// the real wall clock under `std`. On a `no_std` target with no clock
    /// injected there is no wall clock to consult, so this returns 0 — replay
    /// protection then fail-closes on any realistic delivery timestamp
    /// (`spec.md` §7); supply a [`Clock`] on such targets.
    #[must_use]
    pub fn now(&self) -> u64 {
        match &self.clock {
            Some(clock) => clock.now(),
            #[cfg(feature = "std")]
            None => SystemClock.now(),
            #[cfg(not(feature = "std"))]
            None => 0,
        }
    }
}

impl fmt::Debug for VerifyOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("max_age", &self.max_age)
            .field("clock", &self.clock.as_ref().map(|_| "<injected>"))
            .field("request_url_set", &self.request_url.is_some())
            .field("request_method_set", &self.request_method.is_some())
            .field(
                "form_params_count",
                &self.form_params.as_ref().map(|p| p.len()),
            )
            // VerifyingKeyMaterial has its own redacted Debug (variant name +
            // byte length only; never the key/certificate bytes).
            .field("verifying_material", &self.verifying_material)
            // The webhook ID is not secret, but Debug stays minimal and
            // presence-only, like request_url.
            .field("webhook_id_set", &self.webhook_id.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use std::sync::Arc;
    use std::time::Duration;

    use super::{VerifyOptions, VerifyingKeyMaterial};
    use crate::core::options::Clock;
    use crate::test_helpers::{FixedClock, epoch};

    // --- FixedClock (public; the crate's own tests use the exported type) -----

    #[test]
    fn fixed_clock_never_advances() {
        let clock = FixedClock(epoch(1_700_000_000));
        // Three reads, one answer: that non-advancement is the whole property,
        // and it is what makes a replay-window assertion reproducible.
        assert_eq!(clock.now(), epoch(1_700_000_000));
        assert_eq!(clock.now(), clock.now());
        assert_eq!(clock.now(), clock.now());
    }

    #[test]
    fn fixed_clock_default_is_the_epoch() {
        assert_eq!(FixedClock::default().now(), 0);
    }

    #[test]
    fn fixed_clock_satisfies_the_clock_bounds_without_an_arc() {
        // `Clock: Send + Sync`, so `Arc<dyn Clock>` accepts it and a caller can
        // share one pinned instant across a whole test's verifications.
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(epoch(1_700_000_000)));
        assert_eq!(clock.now(), epoch(1_700_000_000));
    }

    #[test]
    fn default_is_five_minutes_without_injected_clock() {
        let opts = VerifyOptions::default();
        assert_eq!(opts.max_age, Some(Duration::from_secs(300)));
        assert!(opts.clock.is_none());
    }

    #[test]
    fn injected_clock_is_used_for_now() {
        let fixed = FixedClock(epoch(1_700_000_000));
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(epoch(1_700_000_000)))),
            request_url: None,
            request_method: None,
            form_params: None,
            verifying_material: None,
            webhook_id: None,
        };
        assert_eq!(opts.now(), fixed.0);
    }

    #[test]
    fn builder_sets_request_url() {
        let opts = VerifyOptions::default().with_request_url("https://example.com/webhook");
        assert_eq!(
            opts.request_url.as_deref(),
            Some("https://example.com/webhook")
        );
    }

    #[test]
    fn builder_sets_request_method() {
        let opts = VerifyOptions::default().with_request_method("POST");
        assert_eq!(opts.request_method.as_deref(), Some("POST"));
        assert!(VerifyOptions::default().request_method.is_none());
    }

    #[test]
    fn debug_does_not_print_request_url_value() {
        let opts = VerifyOptions::default().with_request_url("https://internal.example/hook");
        assert!(!format!("{opts:?}").contains("internal.example"));
    }

    #[test]
    fn builder_sets_verifying_material() {
        let key = b"\x30\x59\x13".to_vec();
        let opts = VerifyOptions::default()
            .with_verifying_material(VerifyingKeyMaterial::EcdsaP256PublicKey(key.clone()));
        assert_eq!(
            opts.verifying_material,
            Some(VerifyingKeyMaterial::EcdsaP256PublicKey(key))
        );
        assert!(VerifyOptions::default().verifying_material.is_none());
    }

    #[test]
    fn builder_sets_webhook_id() {
        let opts = VerifyOptions::default().with_webhook_id("0NH55953DH663215D");
        assert_eq!(opts.webhook_id.as_deref(), Some("0NH55953DH663215D"));
        assert!(VerifyOptions::default().webhook_id.is_none());
    }

    #[test]
    fn debug_redacts_verifying_material_bytes() {
        // Key/certificate bytes must not leak through Debug — only the variant
        // name and byte length are shown.
        let opts = VerifyOptions::default()
            .with_verifying_material(VerifyingKeyMaterial::EcdsaP256PublicKey(vec![0xde, 0xad]));
        let debug = format!("{opts:?}");
        assert!(!debug.contains("222")); // 0xde, 0xad decimal concatenated
        assert!(debug.contains("<2 bytes>"));
    }

    #[test]
    fn builder_sets_form_params_in_any_order() {
        let opts = VerifyOptions::default()
            .with_request_url("https://example.com/myapp")
            .with_form_params([("Digits", "1234"), ("CallSid", "CA123")]);
        assert_eq!(
            opts.form_params,
            Some(vec![
                ("Digits".to_string(), "1234".to_string()),
                ("CallSid".to_string(), "CA123".to_string())
            ])
        );
    }

    #[test]
    fn debug_does_not_print_form_param_values() {
        // Form fields are attacker-controlled request content; like the URL,
        // their values must not leak through `Debug` (only the count does).
        let opts = VerifyOptions::default().with_form_params([("Body", "s3cr3t-message")]);
        let debug = format!("{opts:?}");
        assert!(!debug.contains("s3cr3t-message"));
        assert!(debug.contains("form_params_count: Some(1)"));
    }

    #[test]
    fn builder_sets_max_age() {
        let opts = VerifyOptions::default().with_max_age(Some(Duration::from_secs(600)));
        assert_eq!(opts.max_age, Some(Duration::from_secs(600)));
    }

    #[test]
    fn builder_disables_max_age() {
        let opts = VerifyOptions::default().with_max_age(None);
        assert!(opts.max_age.is_none());
    }

    #[test]
    fn without_replay_protection_clears_max_age() {
        // The loud spelling and the quiet one must land in the same state, or
        // `without_replay_protection` would be a different configuration from
        // `with_max_age(None)` — which its own docs promise it is.
        let loud = VerifyOptions::default().without_replay_protection();
        let quiet = VerifyOptions::default().with_max_age(None);
        assert_eq!(loud.max_age, None);
        assert_eq!(loud.max_age, quiet.max_age);
    }

    #[test]
    fn without_replay_protection_keeps_the_other_options() {
        // It sets exactly one field: turning the window off must not silently
        // drop the request context a URL-signed provider needs.
        let opts = VerifyOptions::default()
            .with_request_url("https://example.com/hook")
            .with_request_method("POST")
            .with_webhook_id("sub_123")
            .without_replay_protection();
        assert_eq!(opts.max_age, None);
        assert_eq!(
            opts.request_url.as_deref(),
            Some("https://example.com/hook")
        );
        assert_eq!(opts.request_method.as_deref(), Some("POST"));
        assert_eq!(opts.webhook_id.as_deref(), Some("sub_123"));
    }

    #[test]
    fn without_replay_protection_can_be_re_enabled() {
        // Builder order is the ordinary one: turning the window off and then
        // back on must restore a real window, since `max_age` is a plain field.
        let opts = VerifyOptions::default()
            .without_replay_protection()
            .with_max_age(Some(Duration::from_secs(60)));
        assert_eq!(opts.max_age, Some(Duration::from_secs(60)));
    }

    #[test]
    fn without_replay_protection_lets_a_stale_timestamp_verify() {
        // The consequence, pinned so it cannot change silently later: with no
        // window, an arbitrarily old delivery verifies, and
        // `TimestampOutOfTolerance` is no longer producible. Same Stripe
        // vector and same "now" the `Clock` doc example uses, moved well past
        // the default 300s window.
        use crate::{Provider, Secret, VerifyError, verify};

        let headers: Vec<(&str, &str)> = vec![(
            "Stripe-Signature",
            "t=1700000000,v1=d95c6b7477fbd7e9f90b1b0ef5f9c7ac25abca5382460e0d988c2b2a5b71b990",
        )];
        let body = br#"{"id":"evt_test_webhook","object":"event"}"#;
        let secret = Secret::new("whsec_test_secret");
        let now = VerifyOptions::default()
            .with_clock(Some(Arc::new(FixedClock(epoch(1_700_000_600)))))
            .without_replay_protection();

        assert_eq!(
            verify(Provider::Stripe, &headers, body, &secret, now),
            Ok(())
        );

        // The very same bytes with the window restored are refused as a replay,
        // which is the difference the loud spelling exists to make visible.
        let protected =
            VerifyOptions::default().with_clock(Some(Arc::new(FixedClock(epoch(1_700_000_600)))));
        assert!(matches!(
            verify(Provider::Stripe, &headers, body, &secret, protected),
            Err(VerifyError::TimestampOutOfTolerance { .. }),
        ));
    }

    #[test]
    fn builder_sets_clock() {
        let fixed = FixedClock(epoch(1_700_000_000));
        let opts =
            VerifyOptions::default().with_clock(Some(Arc::new(FixedClock(epoch(1_700_000_000)))));
        assert_eq!(opts.now(), fixed.0);
    }

    #[test]
    fn builder_disables_clock() {
        // Start with an injected clock, then clear it.
        let fixed = epoch(1_700_000_000);
        let opts = VerifyOptions::default()
            .with_clock(Some(Arc::new(FixedClock(fixed))))
            .with_clock(None);
        // With no clock, `now()` falls back to system time — just verify it
        // doesn't panic and the clock field is None.
        assert!(opts.clock.is_none());
        let _ = opts.now();
    }

    #[cfg(not(feature = "std"))]
    #[test]
    fn no_std_without_a_clock_reads_zero() {
        // On a `no_std + alloc` target there is no wall clock; with no `Clock`
        // injected, `now()` must read 0 so replay checks fail closed on any
        // realistic delivery until the caller supplies one (`spec.md` §7, and
        // the `clock`/`now`/`with_clock` doc contract above).
        let opts = VerifyOptions::default();
        assert_eq!(opts.now(), 0);
    }
}
