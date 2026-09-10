//! [`actix-web`] 4 adapter: a [`FromRequest`] extractor that verifies inbound
//! webhook signatures with [`crate::verify()`] and yields the exact raw body
//! bytes on success.
//!
//! actix-web 4 is built on `actix-http` 3, which uses the `http` **0.2** types
//! internally. It therefore cannot reuse this crate's `http` 1.x `HeaderMap`
//! impl; this module provides its own bridge ([`crate::HeaderMap`] for
//! actix's header map) plus the extractor below.
//!
//! # Why an extractor and not a guard
//!
//! Guards run during routing, before any body bytes are read — but signature
//! verification *requires* the raw body (`spec.md` §4.2), so a guard cannot
//! perform it. The idiomatic actix-web equivalent is a body extractor: it runs
//! during handler-argument extraction (after routing, before your handler
//! logic) and consumes the payload itself.
//!
//! # What the extractor guarantees
//!
//! - **Raw-body fidelity** (`spec.md` §4.2): the body is buffered exactly as
//!   received off the wire and those bytes — nothing else — are both verified
//!   and handed to the handler as [`VerifiedBody`]. No JSON parsing or
//!   re-serialization happens in between. Do not also take `web::Json<T>` in
//!   the same handler: extractors run left-to-right and `Json` would consume
//!   (and re-parse) the body first. Take [`VerifiedBody`] alone and parse from
//!   its exact bytes yourself if you need structured data.
//! - **Ambiguous duplicate headers rejected** (`spec.md` §4.4): the
//!   [`crate::HeaderMap`] trait only sees first values, so the extractor
//!   inspects the raw actix header map and rejects any request whose
//!   scheme-relevant signature headers appear multiple times with *differing*
//!   values (`400 Bad Request`) before any signature work. Identical repeats
//!   are not ambiguous and verify normally against the first value.
//! - **Fail closed**: every failure — including a missing
//!   [`WebhookConfig`] — produces an error response; handler logic never
//!   sees unverified bytes.
//! - **Optional body size limit** (DoS hardening): use
//!   [`WebhookConfig::with_max_body_size`] to reject oversized request bodies
//!   with `413 Payload Too Large` before any signature work, preventing a
//!   malicious client from forcing the server to buffer and HMAC an
//!   arbitrarily large payload.
//!
//! # Status codes
//!
//! Identical to the tower adapter:
//!
//! | `VerifyError` class | Status |
//! |---|---|
//! | Body exceeds [`WebhookConfig::with_max_body_size`] limit (not a `VerifyError`) | `413 Payload Too Large` |
//! | `MissingHeader`, `MalformedHeader`, `BadEncoding` (malformed request) | `400 Bad Request` |
//! | `SignatureMismatch`, `TimestampOutOfTolerance` (auth signals) | `401 Unauthorized` |
//! | `UnsupportedProvider`, `InvalidSecret`, `MissingContext` (operator misconfiguration) | `500 Internal Server Error` |
//!
//! Bodies are deliberately empty: distinguishing detail belongs in
//! server-side logging keyed off the structured [`crate::VerifyError`], whose
//! `Display`/`Debug` never carry secret material (`spec.md` §2.1). A failure
//! to read the body at transport level (e.g. client disconnect mid-stream)
//! surfaces as `400 Bad Request` — an incomplete request, never a
//! verification outcome.
//!
//! # Example
//!
//! ```no_run
//! use actix_web::{App, HttpResponse, web};
//! use webhook_verify::actix::{VerifiedBody, WebhookConfig};
//! use webhook_verify::{Provider, Secret};
//!
//! let app = App::new()
//!     .app_data(WebhookConfig::new(
//!         Provider::GitHub,
//!         Secret::new("It's a Secret to Everybody"),
//!     ))
//!     .route(
//!         "/webhooks/github",
//!         web::post().to(|body: VerifiedBody| async move {
//!             // `body` holds the exact bytes off the wire, already verified.
//!             // Parse them here (never re-extract via web::Json).
//!             HttpResponse::Ok().finish()
//!         }),
//!     );
//! ```
//!
//! # Header lookup without the extractor
//!
//! The bridge makes actix's own header map work with [`crate::verify()`]
//! directly. Note that actix's inherent case-insensitive `get(&str)` shadows
//! the trait method in method-call position (same caveat as `BTreeMap` on the
//! [`crate::HeaderMap`] docs); pass the map through the trait explicitly or,
//! preferably, just call [`crate::verify()`] with it. Duplicate detection
//! remains the caller's job outside the extractor — see §4.4.
//!
//! [`actix-web`]: https://crates.io/crates/actix-web

use std::{
    fmt,
    future::{Future, ready},
    pin::Pin,
    sync::Arc,
};

use actix_web::{
    FromRequest, HttpRequest, ResponseError,
    dev::Payload,
    http::{
        StatusCode,
        header::{HeaderMap as ActixHeaderMap, HeaderName},
    },
    web::Bytes,
};

use crate::core::adapter_utils::rejection_status;
use crate::{
    HeaderMap, Provider, Secret, VerifyError, VerifyOptions, providers::signature_header_names,
};

/// Configuration used by the [`VerifiedBody`] extractor: provider, secret,
/// and verification options.
///
/// Register it once per app (or per scoped webhook route) with
/// `App::app_data(...)`. Requests arriving at routes without a registered
/// config fail closed with `500 Internal Server Error`.
#[must_use]
#[derive(Clone)]
pub struct WebhookConfig {
    provider: Provider,
    secret: Arc<Secret>,
    options: Arc<VerifyOptions>,
    max_body_size: Option<usize>,
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Provider name only; `Secret`'s Debug is redacted and
        // `VerifyOptions`' Debug omits URL/form values (spec.md §4.3).
        f.debug_struct("WebhookConfig")
            .field("provider", &self.provider)
            .field("secret", &self.secret)
            .field("options", &self.options)
            .field("max_body_size", &self.max_body_size)
            .finish()
    }
}

impl WebhookConfig {
    /// Verifies `provider` signatures using the shared `secret`.
    pub fn new(provider: Provider, secret: Secret) -> Self {
        Self::with_options(provider, secret, VerifyOptions::default())
    }

    /// Like [`WebhookConfig::new`], with explicit [`VerifyOptions`]
    /// (timestamp tolerance, injected clock, URL-scoped schemes such as
    /// Square/Twilio).
    pub fn with_options(provider: Provider, secret: Secret, options: VerifyOptions) -> Self {
        Self {
            provider,
            secret: Arc::new(secret),
            options: Arc::new(options),
            max_body_size: None,
        }
    }

    /// Sets an optional maximum body size in bytes (DoS hardening).
    ///
    /// When set, requests whose body exceeds this limit are rejected with
    /// `413 Payload Too Large` *before* any signature verification work,
    /// preventing a malicious client from forcing the server to buffer an
    /// arbitrarily large payload and compute HMACs over it.
    ///
    /// When `None` (the default), the body is buffered without a
    /// crate-level size limit (actix-web's own extractor bound still
    /// applies unless a custom [`actix_web::web::PayloadConfig`] is
    /// registered).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use actix_web::{App, HttpResponse, web};
    /// use webhook_verify::actix::{VerifiedBody, WebhookConfig};
    /// use webhook_verify::{Provider, Secret};
    ///
    /// // 256 KiB limit, matching actix-web's default body-extractor bound.
    /// let app = App::new()
    ///     .app_data(WebhookConfig::new(Provider::GitHub, Secret::new("secret"))
    ///         .with_max_body_size(256 * 1024))
    ///     .route("/", web::post().to(|_body: VerifiedBody| async move {
    ///         HttpResponse::Ok().finish()
    ///     }));
    /// ```
    pub fn with_max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = Some(max);
        self
    }
}

/// The exact raw request body, verified against the route's
/// [`WebhookConfig`] before the handler runs.
///
/// Produced by the [`FromRequest`] implementation; see the [module docs](self)
/// for the security contract and status-code table.
#[must_use]
pub struct VerifiedBody(Bytes);

impl VerifiedBody {
    /// The verified raw body bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the extractor, yielding the verified [`Bytes`].
    #[must_use]
    pub fn into_inner(self) -> Bytes {
        self.0
    }
}

impl fmt::Debug for VerifiedBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the body itself (spec.md §3: no body material in
        // Debug output).
        f.debug_struct("VerifiedBody")
            .field("len", &self.0.len())
            .finish()
    }
}

impl std::ops::Deref for VerifiedBody {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Why a request was rejected by the [`VerifiedBody`] extractor.
#[derive(Debug)]
enum Rejection {
    /// Verification failed with the structured error.
    Verify(VerifyError),
    /// The body could not be read to completion (transport-level failure,
    /// e.g. client disconnect mid-stream). Carries no detail by design.
    BodyRead,
    /// The body exceeds the configured [`WebhookConfig::with_max_body_size`]
    /// limit (DoS hardening); rejected before any signature work.
    BodyTooLarge,
}

/// Rejection produced when webhook verification fails; renders as an
/// empty-bodied response whose status follows the [module table](self#status-codes).
#[must_use]
#[derive(Debug)]
pub struct WebhookVerificationError(Rejection);

impl fmt::Display for WebhookVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            // `VerifyError`'s Display carries only header names, static
            // reasons, and durations (spec.md §2.1) — safe to surface.
            Rejection::Verify(error) => write!(f, "webhook verification failed: {error}"),
            Rejection::BodyRead => f.write_str("webhook body could not be read"),
            Rejection::BodyTooLarge => {
                f.write_str("webhook body exceeds the configured size limit")
            }
        }
    }
}

impl std::error::Error for WebhookVerificationError {}

impl ResponseError for WebhookVerificationError {
    fn status_code(&self) -> StatusCode {
        match &self.0 {
            Rejection::BodyRead => StatusCode::BAD_REQUEST,
            Rejection::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            // The status class is a hard-coded constant (400/401/500), so
            // conversion cannot fail; the fallback still fails closed with
            // 500 if it ever did.
            Rejection::Verify(error) => StatusCode::from_u16(rejection_status(error))
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    // The default `error_response` builds an empty-bodied response from
    // `status_code`; that is exactly what we want (spec.md §2.1 / tower
    // adapter parity), so it is not overridden.
}

/// Returns the name of the first header in `names` that occurs in `headers`
/// more than once with *differing* values — the ambiguity `spec.md` §4.4
/// requires rejecting — or `None` when none is ambiguous.
///
/// Static header-name constants always parse, so the parse-error arm is
/// unreachable in practice and simply fails closed (reported as ambiguous).
fn conflicting_signature_header(
    headers: &ActixHeaderMap,
    names: &[&'static str],
) -> Option<&'static str> {
    names.iter().copied().find(|name| {
        let Ok(key) = HeaderName::from_bytes(name.as_bytes()) else {
            return true;
        };
        let mut values = headers.get_all(&key);
        let Some(first) = values.next() else {
            return false;
        };
        values.any(|value| value != first)
    })
}

type ExtractFuture = Pin<Box<dyn Future<Output = Result<VerifiedBody, WebhookVerificationError>>>>;

impl FromRequest for VerifiedBody {
    type Error = WebhookVerificationError;
    type Future = ExtractFuture;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // Fail closed when no config is registered for this app/scope:
        // operator misconfiguration, never a requester fault.
        let Some(config) = req.app_data::<WebhookConfig>() else {
            return Box::pin(ready(Err(WebhookVerificationError(Rejection::Verify(
                VerifyError::MissingContext {
                    reason: "no WebhookConfig registered via app_data",
                },
            )))));
        };

        // Ambiguity check first: it needs no body bytes, so conflicting
        // duplicates are rejected without buffering or signature work.
        let names = signature_header_names(&config.provider);
        if let Some(header) = conflicting_signature_header(req.headers(), &names) {
            return Box::pin(ready(Err(WebhookVerificationError(Rejection::Verify(
                VerifyError::MalformedHeader {
                    header,
                    reason: "header present multiple times with different values",
                },
            )))));
        }

        let config = config.clone();
        let mut payload = payload.take();
        let req = req.clone();

        Box::pin(async move {
            // Buffer the exact wire bytes once; these are what gets verified
            // and what the handler receives (spec.md §4.2).
            let raw_body = match Bytes::from_request(&req, &mut payload).await {
                Ok(bytes) => bytes,
                Err(_) => return Err(WebhookVerificationError(Rejection::BodyRead)),
            };

            // DoS hardening: reject oversized bodies before any signature
            // work (parity with `VerifyLayer::with_max_body_size` in the
            // tower adapter). CPU amplification (HMAC over an arbitrarily
            // large body) is the primary vector this defends against.
            if let Some(limit) = config.max_body_size {
                if raw_body.len() > limit {
                    return Err(WebhookVerificationError(Rejection::BodyTooLarge));
                }
            }

            match crate::verify(
                config.provider,
                req.headers(),
                raw_body.as_ref(),
                &config.secret,
                (*config.options).clone(),
            ) {
                Ok(()) => Ok(VerifiedBody(raw_body)),
                Err(error) => Err(WebhookVerificationError(Rejection::Verify(error))),
            }
        })
    }
}

// --- header bridge ----------------------------------------------------------

/// Bridge for actix-web 4's internal `http` 0.2 header map: enables passing
/// `req.headers()` straight into [`crate::verify()`].
///
/// Lookup mirrors the `http` 1.x impl in `src/core/headers.rs`: typed-name
/// lookups are ASCII case-insensitive and first-value-wins; a value that is
/// not visible ASCII (which `http` permits but this crate cannot treat as a
/// signature) is reported as absent, failing closed downstream. Duplicate
/// detection stays with the adapter — see the trait's ambiguity contract.
impl HeaderMap for ActixHeaderMap {
    fn get(&self, name: &str) -> Option<&str> {
        // `HeaderName::from_bytes` normalizes to lowercase and rejects names
        // with invalid bytes, so an unparseable lookup name is simply a miss.
        let key = HeaderName::from_bytes(name.as_bytes()).ok()?;
        // UFCS reaches the map's *inherent* case-insensitive lookup rather
        // than recursing into this trait method.
        let value = ActixHeaderMap::get(self, &key)?;
        value.to_str().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Aliased: a plain `use ..::test` would make `#[test]` resolve to the
    // actix module instead of the built-in attribute.
    #[cfg(feature = "paypal")]
    use crate::VerifyingKeyMaterial;
    use crate::test_helpers::{FixedClock, clocked_at, epoch};
    use actix_web::{App, HttpResponse, http, test as aw_test, web};

    /// GitHub's documented example vector
    /// (<https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>),
    /// same one used across the crate's tests.
    const GITHUB_SECRET: &str = "It's a Secret to Everybody";
    const GITHUB_BODY: &[u8] = b"Hello, World!";
    const GITHUB_SIGNATURE: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    /// Slack's documented worked example
    /// (<https://docs.slack.dev/authentication/verifying-requests-from-slack>),
    /// same constants used in the tower adapter tests.
    const SLACK_SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    const SLACK_TIMESTAMP: u64 = 1_531_420_618;
    const SLACK_BODY: &[u8] =
        b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    const SLACK_SIGNATURE: &str =
        "a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";

    /// Handler echoing how many body bytes it received, so tests assert the
    /// verified bytes reach handlers byte-for-byte.
    async fn echo_len(body: VerifiedBody) -> HttpResponse {
        HttpResponse::Ok().body(body.len().to_string())
    }

    async fn echo_len_slack(_body: VerifiedBody) -> HttpResponse {
        unreachable!("only called where extraction should succeed")
    }

    /// App under test: GitHub config + echo handler. Each test initializes
    /// its own service instance (actix services are single-use per request
    /// pipeline in `init_service` tests).
    macro_rules! github_app {
        () => {
            aw_test::init_service(
                App::new()
                    .app_data(WebhookConfig::new(
                        Provider::GitHub,
                        Secret::new(GITHUB_SECRET),
                    ))
                    .route("/", web::post().to(echo_len)),
            )
            .await
        };
    }

    fn github_request(body: &'static [u8]) -> aw_test::TestRequest {
        aw_test::TestRequest::post()
            .insert_header(("X-Hub-Signature-256", GITHUB_SIGNATURE))
            .set_payload(Bytes::from_static(body))
    }

    // --- happy path ---------------------------------------------------------

    #[actix_web::test]
    async fn valid_signature_reaches_handler_with_exact_bytes() {
        let app = github_app!();
        let res = aw_test::call_service(&app, github_request(GITHUB_BODY).to_request()).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(aw_test::read_body(res).await, Bytes::from_static(b"13"));
    }

    #[actix_web::test]
    async fn empty_and_unicode_bodies_round_trip_byte_exactly() {
        // Boundary bodies through the same buffered pipeline. Digests
        // computed locally with GitHub's recipe:
        // printf '<body>' | openssl dgst -sha256 -hmac <secret>
        const EMPTY_SIG: &str =
            "sha256=66a0c074deaa0f489ead6537e0d32f9a344b90bbeda705b6ed45ecd3b413fb40";
        const UNICODE_BODY: &[u8] = "héllo, 🦀 world!".as_bytes();
        const UNICODE_SIG: &str =
            "sha256=815772f88bf8950c7457b57856f4b33ca9d07e7ef7a50646b067b4a613f735c4";

        for (body, signature) in [
            (&b""[..], EMPTY_SIG),
            (UNICODE_BODY, UNICODE_SIG),
            (GITHUB_BODY, GITHUB_SIGNATURE),
        ] {
            let expected_len = body.len().to_string();
            let app = github_app!();
            let req = aw_test::TestRequest::post()
                .insert_header(("X-Hub-Signature-256", signature))
                .set_payload(Bytes::copy_from_slice(body))
                .to_request();
            let res = aw_test::call_service(&app, req).await;
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(aw_test::read_body(res).await, Bytes::from(expected_len));
        }
    }

    // --- negative: tampered payload -----------------------------------------

    #[actix_web::test]
    async fn tampered_body_is_unauthorized_and_never_reaches_handler() {
        let app = github_app!();
        let res = aw_test::call_service(&app, github_request(b"Hello, World?").to_request()).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // --- negative: malformed / ambiguous headers -----------------------------

    #[actix_web::test]
    async fn missing_signature_header_is_bad_request() {
        let app = github_app!();
        let req = aw_test::TestRequest::post()
            .set_payload(Bytes::from_static(GITHUB_BODY))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn conflicting_duplicate_signature_headers_are_rejected() {
        // Second value differs from the first: ambiguous under spec §4.4 even
        // though each value alone would just fail verification normally.
        let app = github_app!();
        let req = aw_test::TestRequest::post()
            .append_header(("X-Hub-Signature-256", GITHUB_SIGNATURE))
            .append_header((
                "x-hub-signature-256",
                "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            ))
            .set_payload(Bytes::from_static(GITHUB_BODY))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn identical_duplicate_signature_headers_still_verify() {
        let app = github_app!();
        let req = aw_test::TestRequest::post()
            .append_header(("X-Hub-Signature-256", GITHUB_SIGNATURE))
            .append_header(("x-hub-signature-256", GITHUB_SIGNATURE))
            .set_payload(Bytes::from_static(GITHUB_BODY))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn conflicting_duplicate_timestamp_header_is_rejected_for_slack() {
        // Valid-shaped signature plus two conflicting timestamps: ambiguity
        // lives in the timestamp header, not the signature header itself.
        let app = aw_test::init_service(
            App::new()
                .app_data(WebhookConfig::new(
                    Provider::Slack,
                    Secret::new(SLACK_SECRET),
                ))
                .route("/", web::post().to(echo_len_slack)),
        )
        .await;
        let req = aw_test::TestRequest::post()
            .insert_header(("X-Slack-Signature", format!("v0={SLACK_SIGNATURE}")))
            .append_header(("X-Slack-Request-Timestamp", SLACK_TIMESTAMP.to_string()))
            .append_header(("x-slack-request-timestamp", "1700000001"))
            .set_payload(Bytes::from_static(SLACK_BODY))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    // --- replay protection through the adapter -------------------------------

    #[actix_web::test]
    async fn stale_timestamp_is_unauthorized_through_adapter() {
        // "Now" ten minutes after signing: outside the default 300s window.
        let late = epoch(SLACK_TIMESTAMP + 600);

        let app = aw_test::init_service(
            App::new()
                .app_data(WebhookConfig::with_options(
                    Provider::Slack,
                    Secret::new(SLACK_SECRET),
                    crate::VerifyOptions {
                        clock: Some(Arc::new(FixedClock(late))),
                        ..crate::VerifyOptions::default()
                    },
                ))
                .route("/", web::post().to(echo_len_slack)),
        )
        .await;

        let req = aw_test::TestRequest::post()
            .insert_header(("X-Slack-Signature", format!("v0={SLACK_SIGNATURE}")))
            .insert_header(("X-Slack-Request-Timestamp", SLACK_TIMESTAMP.to_string()))
            .set_payload(Bytes::from_static(SLACK_BODY))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // --- custom schemes and unsupported providers ----------------------------

    #[actix_web::test]
    async fn custom_scheme_headers_are_dup_checked_too() {
        // HMAC-SHA256 hex of the body with key "k":
        // printf 'Hello, World!' | openssl dgst -sha256 -hmac "k"
        const DIGEST: &str = "11316937114e6970aa59bd5326a6f38dd525f4ade64670e402bff41e2f7c4071";
        let scheme = crate::CustomScheme {
            hash: crate::HashAlg::Sha256,
            signature_header: "X-My-Sig",
            timestamp_header: None,
            encoding: crate::Encoding::Hex,
            prefix: Some("sha256="),
            signed_string: |_headers, body| body.to_vec(),
        };

        // Conflicting duplicates of the custom scheme's signature header are
        // caught before any verification work.
        let ambiguous_app = aw_test::init_service(
            App::new()
                .app_data(WebhookConfig::new(
                    Provider::Custom(scheme),
                    Secret::new("k"),
                ))
                .route("/", web::post().to(echo_len_slack)),
        )
        .await;
        let req = aw_test::TestRequest::post()
            .append_header(("X-My-Sig", format!("sha256={DIGEST}")))
            .append_header(("x-my-sig", "sha256=00"))
            .set_payload(Bytes::from_static(GITHUB_BODY))
            .to_request();
        let res = aw_test::call_service(&ambiguous_app, req).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // A single well-formed value verifies end to end.
        let good_app = aw_test::init_service(
            App::new()
                .app_data(WebhookConfig::new(
                    Provider::Custom(scheme),
                    Secret::new("k"),
                ))
                .route("/", web::post().to(echo_len)),
        )
        .await;
        let req = aw_test::TestRequest::post()
            .insert_header(("X-My-Sig", format!("sha256={DIGEST}")))
            .set_payload(Bytes::from_static(GITHUB_BODY))
            .to_request();
        let res = aw_test::call_service(&good_app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    // PayPal stays "unsupported" only when the `paypal` feature is off; the
    // mapping of that error class to 500 lives in core::adapter_utils tests.
    #[cfg(not(feature = "paypal"))]
    #[actix_web::test]
    async fn unsupported_provider_maps_to_internal_server_error() {
        let app = aw_test::init_service(
            App::new()
                .app_data(WebhookConfig::new(Provider::PayPal, Secret::new("unused")))
                .route("/", web::post().to(echo_len_slack)),
        )
        .await;
        let req = aw_test::TestRequest::post()
            .set_payload(Bytes::from_static(b"{}"))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[cfg(feature = "paypal")]
    #[actix_web::test]
    async fn paypal_verifies_through_the_extractor() {
        let cert = include_bytes!("../tests/data/paypal_test_cert.pem");
        // Reuse the documented PayPal construction's options plus the vector's
        // headers (see src/providers/paypal.rs tests). The clock is pinned to
        // the vector's transmission time so the replay window is satisfied.
        let config = WebhookConfig::with_options(
            Provider::PayPal,
            Secret::new("unused"),
            clocked_at(1_715_836_763, None)
                .with_webhook_id("0NH55953DH663215D")
                .with_verifying_material(VerifyingKeyMaterial::X509Certificate(cert.to_vec())),
        );
        let app = aw_test::init_service(
            App::new()
                .app_data(config)
                .route("/", web::post().to(echo_len)),
        )
        .await;
        let body = include_bytes!("../tests/data/paypal_docs_body.json");
        let req = aw_test::TestRequest::post()
            .insert_header(("PayPal-Transmission-Id", "db49fb10-1343-11ef-ac58-e32457403f67"))
            .insert_header(("PayPal-Transmission-Time", "2024-05-16T05:19:23Z"))
            .insert_header((
                "PayPal-Transmission-Sig",
                "aGYe/s6lwrASh2zyTRIAz8Edo705ezMKekirejT08ev3VXdWAkq4JWADiNPUGelx5qrEKxC7mPIHmAwQ5hOT6unhY9n33M/DbXTKGsuITPdXRA7qYVmc2wsIp68BpzB6pC6+5vt/YLQvflsrwrutGa0KyZc5FinuYNN8pTNomv4uiygasWqfnDyKViKQPNZecowag6tY/9pj7+bgBu/joBpYUq0+cQxfGqNnlvywBJ7HCOf4edeTIvM/c1CvvAHGtNTU54kLjWGue640twn6iXPL8tnaABZ8Fr9m0z87v8oY0vBobERV0Yu8thUToKhvQEFF26Rckqy07VVddg1CmA==",
            ))
            .insert_header(("PayPal-Cert-Url", "https://example.invalid/cert-url"))
            .insert_header(("PayPal-Auth-Algo", "SHA256withRSA"))
            .set_payload(Bytes::from_static(body))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn missing_config_fails_closed_with_internal_server_error() {
        let app = aw_test::init_service(App::new().route("/", web::post().to(echo_len))).await;
        let req = aw_test::TestRequest::post()
            .insert_header(("X-Hub-Signature-256", GITHUB_SIGNATURE))
            .set_payload(Bytes::from_static(GITHUB_BODY))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // --- max_body_size (DoS hardening) ---------------------------------------

    /// GitHub HMAC-SHA256 over arbitrary bytes, computed inline for
    /// size-boundary tests (mirrors the tower adapter's approach).
    fn github_sig_for(body: &[u8]) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type H = Hmac<Sha256>;
        let mut mac = H::new_from_slice(GITHUB_SECRET.as_bytes())
            .unwrap_or_else(|_| unreachable!("valid key"));
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[actix_web::test]
    async fn body_within_limit_is_accepted() {
        // GITHUB_BODY is 13 bytes; limit is 1024.
        let app = aw_test::init_service(
            App::new()
                .app_data(
                    WebhookConfig::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                        .with_max_body_size(1024),
                )
                .route("/", web::post().to(echo_len)),
        )
        .await;
        let req = github_request(GITHUB_BODY).to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn body_exceeding_limit_is_rejected_with_413() {
        // GITHUB_BODY is 13 bytes; limit is 10 — body exceeds limit.
        let app = aw_test::init_service(
            App::new()
                .app_data(
                    WebhookConfig::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                        .with_max_body_size(10),
                )
                .route("/", web::post().to(echo_len)),
        )
        .await;
        let req = github_request(GITHUB_BODY).to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[actix_web::test]
    async fn body_exactly_at_limit_is_accepted() {
        // A body whose length matches the limit exactly — a valid signature
        // still verifies at the boundary.
        let body = vec![b'x'; 13];
        let sig = { github_sig_for(&body) };

        let app = aw_test::init_service(
            App::new()
                .app_data(
                    WebhookConfig::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                        .with_max_body_size(13),
                )
                .route("/", web::post().to(echo_len)),
        )
        .await;
        let req = aw_test::TestRequest::post()
            .insert_header(("X-Hub-Signature-256", sig))
            .set_payload(Bytes::from(body))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn body_one_byte_over_limit_is_rejected() {
        let body = vec![b'x'; 14];
        let sig = { github_sig_for(&body) };

        let app = aw_test::init_service(
            App::new()
                .app_data(
                    WebhookConfig::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                        .with_max_body_size(13),
                )
                .route("/", web::post().to(echo_len)),
        )
        .await;
        let req = aw_test::TestRequest::post()
            .insert_header(("X-Hub-Signature-256", sig))
            .set_payload(Bytes::from(body))
            .to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[actix_web::test]
    async fn default_no_limit_still_works() {
        // Ensure the default (no max_body_size) path is unchanged.
        let app = github_app!();
        let req = github_request(GITHUB_BODY).to_request();
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn zero_limit_rejects_nonempty_body() {
        let app = aw_test::init_service(
            App::new()
                .app_data(
                    WebhookConfig::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                        .with_max_body_size(0),
                )
                .route("/", web::post().to(echo_len)),
        )
        .await;
        let req = github_request(GITHUB_BODY).to_request(); // 13 bytes
        let res = aw_test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[actix_web::test]
    async fn config_debug_never_contains_secrets_with_max_body_size() {
        let config = WebhookConfig::new(Provider::GitHub, Secret::new("super-secret-key"))
            .with_max_body_size(1024);
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret-key"));
        assert!(debug.contains("max_body_size: Some(1024)"));
    }

    // --- unit-level checks ----------------------------------------------------

    #[test]
    fn identical_opaque_duplicate_values_are_not_ambiguous_but_fail_verification() {
        // Two identical opaque-byte values are not ambiguous per §4.4 (same
        // value); downstream lookup reports them absent and fails closed.
        let name = HeaderName::from_static("x-hub-signature-256");
        let mut headers = ActixHeaderMap::new();
        let value = http::header::HeaderValue::from_bytes(&[0xFF])
            .unwrap_or_else(|_| unreachable!("permitted"));
        headers.append(name.clone(), value.clone());
        headers.append(name, value);
        assert!(conflicting_signature_header(&headers, &["X-Hub-Signature-256"]).is_none());
    }

    #[test]
    fn unparseable_header_name_fails_closed_as_ambiguous() {
        // A header-name string actix's http crate refuses to parse (embedded
        // whitespace) must fail closed as "ambiguous" per §4.4 — the parse-
        // error arm exists precisely so attacker-supplied garbage can never
        // turn into a permissive lookup.
        let headers = ActixHeaderMap::new();
        assert_eq!(
            conflicting_signature_header(&headers, &["x-hub-signature-256 invalid"]),
            Some("x-hub-signature-256 invalid")
        );
    }

    #[test]
    fn bridge_lookup_is_ascii_case_insensitive_and_fail_closed() {
        let mut headers = ActixHeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-hub-signature-256"),
            http::header::HeaderValue::from_static(GITHUB_SIGNATURE),
        );
        assert_eq!(
            HeaderMap::get(&headers, "x-hub-signature-256"),
            Some(GITHUB_SIGNATURE)
        );
        assert_eq!(
            HeaderMap::get(&headers, "X-HUB-SIGNATURE-256"),
            Some(GITHUB_SIGNATURE)
        );
        assert_eq!(HeaderMap::get(&headers, "bad name\n"), None);
        // Opaque-byte values cannot be signatures; reported absent.
        let mut opaque = ActixHeaderMap::new();
        opaque.insert(
            HeaderName::from_static("x-webhook-sig"),
            http::header::HeaderValue::from_bytes(&[0xFF])
                .unwrap_or_else(|_| unreachable!("permitted")),
        );
        assert_eq!(HeaderMap::get(&opaque, "X-Webhook-Sig"), None);
    }

    #[test]
    fn bridge_verifies_github_delivery_end_to_end() {
        let mut headers = ActixHeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-hub-signature-256"),
            http::header::HeaderValue::from_static(GITHUB_SIGNATURE),
        );
        let result = crate::verify(
            Provider::GitHub,
            &headers,
            GITHUB_BODY,
            &Secret::new(GITHUB_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));

        let result = crate::verify(
            Provider::GitHub,
            &headers,
            b"Hello, World?",
            &Secret::new(GITHUB_SECRET),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn debug_output_never_contains_secrets_or_bodies() {
        let config = WebhookConfig::with_options(
            Provider::GitHub,
            Secret::new("super-secret-hmac-key"),
            crate::VerifyOptions::default().with_request_url("https://internal.example/hook"),
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret-hmac-key"));
        assert!(!debug.contains("internal.example"));

        let body = VerifiedBody(Bytes::from_static(b"raw-secret-payload-bytes"));
        let debug = format!("{body:?}");
        assert!(!debug.contains("raw-secret-payload-bytes"));
        assert!(debug.contains("len: 24"));
    }

    #[test]
    fn rejection_display_never_contains_secret_material() {
        let e = WebhookVerificationError(Rejection::Verify(VerifyError::MissingHeader {
            header: "X-Hub-Signature-256",
        }));
        assert_eq!(
            e.to_string(),
            "webhook verification failed: missing header `X-Hub-Signature-256`"
        );
        let e = WebhookVerificationError(Rejection::BodyRead);
        assert_eq!(e.to_string(), "webhook body could not be read");
        assert_eq!(e.status_code(), StatusCode::BAD_REQUEST);

        let e = WebhookVerificationError(Rejection::BodyTooLarge);
        assert_eq!(
            e.to_string(),
            "webhook body exceeds the configured size limit"
        );
        assert_eq!(e.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
