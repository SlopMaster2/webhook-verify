//! Verification options: timestamp tolerance, clock injection, and asymmetric
//! verification material for public-key providers.

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
#[derive(Clone, PartialEq, Eq)]
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
    /// recommended). Default: 300 seconds, matching Stripe's and Slack's own
    /// SDK defaults.
    ///
    /// Providers that do not sign timestamps document explicitly that this
    /// option has no effect on them (see `spec.md` §3).
    pub max_age: Option<Duration>,
    /// Clock used for "now". `None` means real system time. Injectable for
    /// deterministic tests of timestamp-based providers.
    pub clock: Option<Arc<dyn Clock>>,
    /// Full URL of the receiving endpoint, required by providers whose
    /// signature incorporates it (currently Square, whose scheme signs the
    /// notification URL followed by the raw body, and Twilio, which signs the
    /// full request URL). The value must match the URL configured with the
    /// provider **exactly** — a differing trailing slash or scheme makes every
    /// signature fail. Providers whose scheme does not sign the URL document
    /// that this option has no effect on them.
    ///
    /// Supplying the configured constant from the provider dashboard is the
    /// intended use; reconstructing the URL from request headers behind a
    /// proxy is a common source of verification failures.
    pub request_url: Option<String>,
    /// Parsed `application/x-www-form-urlencoded` fields, required by Twilio:
    /// its signature covers the request URL concatenated with the sorted
    /// form-field names/values, not the raw body. Pass **every** field as
    /// received — Twilio's own docs warn against verifying against a hardcoded
    /// subset, since providers may add parameters without notice. Sorting is
    /// applied here (it is part of the signing scheme), so callers pass fields
    /// in any order. A duplicate field name keeps its received relative order.
    ///
    /// An explicitly empty list is meaningful (Twilio's JSON-body variant signs
    /// the URL alone); omitting the option entirely fails closed with
    /// [`crate::VerifyError::MissingContext`] so a caller that forgot to parse
    /// the body cannot be confused with an attacker-supplied input.
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

    /// Sets [`VerifyOptions::form_params`], for schemes that sign parsed form
    /// fields (currently Twilio). Order does not matter; fields are sorted
    /// into signing order during verification of Twilio's signed string.
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
    /// providers whose scheme signs a timestamp. `None` disables the check
    /// (not recommended); the default is `Some(Duration::from_secs(300))`.
    ///
    /// Providers that do not sign timestamps document explicitly that this
    /// option has no effect on them (see `spec.md` §3).
    pub fn with_max_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    /// Sets [`VerifyOptions::clock`], the source of "now" used for replay
    /// protection. `None` uses real system time. Injectable for deterministic
    /// tests of timestamp-based providers.
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
    /// the real wall clock under `std`.
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
    use std::sync::Arc;
    use std::time::Duration;

    use super::{VerifyOptions, VerifyingKeyMaterial};
    use crate::test_helpers::{FixedClock, epoch};

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
}
