//! Generic [`tower`] adapter: a [`tower_layer::Layer`] /
//! [`tower_service::Service`] middleware that verifies inbound webhook
//! signatures with [`crate::verify()`] before the request reaches your
//! handler.
//!
//! Because axum routers are tower services, this layer also drops straight
//! into `Router::layer(...)` — see the framework note below.
//!
//! # What the middleware guarantees
//!
//! - **Raw-body fidelity** (`spec.md` §4.2): the body is buffered *exactly*
//!   as received off the wire (`http_body_util` collects the raw frame bytes)
//!   and those bytes — and nothing else — go both to [`crate::verify()`] and
//!   onward to the inner service. No JSON parsing or re-serialization happens
//!   anywhere in between, so handlers can deserialize freely after
//!   verification.
//! - **Ambiguous duplicate headers rejected** (`spec.md` §4.4): the
//!   [`crate::HeaderMap`] trait only sees first values, so this middleware
//!   inspects the raw `http::HeaderMap` itself and rejects any request whose
//!   scheme-relevant signature headers appear multiple times with *differing*
//!   values (`400 Bad Request`) before any signature work. Identical repeats
//!   are not ambiguous and verify normally against the first value.
//! - **Fail closed**: every verification failure produces an empty-bodied
//!   error response; the request never reaches the inner service.
//! - **Optional body size limit** (DoS hardening): use
//!   [`VerifyLayer::with_max_body_size`] to reject oversized request bodies
//!   with `413 Payload Too Large` before any signature work, so a malicious
//!   client cannot force an arbitrarily large HMAC/verification computation.
//!   The body is always fully buffered (verification requires the exact wire
//!   bytes); the limit bounds the signature work, not the buffering itself.
//!
//! # Status codes
//!
//! | Class | Status |
//! |---|---|
//! | Body exceeds [`VerifyLayer::with_max_body_size`] limit (not a `VerifyError`) | `413 Payload Too Large` |
//! | `MissingHeader`, `MalformedHeader`, `BadEncoding` (malformed request) | `400 Bad Request` |
//! | `SignatureMismatch`, `TimestampOutOfTolerance` (auth signals) | `401 Unauthorized` |
//! | `UnsupportedProvider`, `InvalidSecret`, `MissingContext` (operator misconfiguration) | `500 Internal Server Error` |
//!
//! Bodies are deliberately empty: distinguishing detail belongs in
//! server-side logging keyed off the structured [`crate::VerifyError`], whose
//! `Display`/`Debug` never carry secret material (`spec.md` §2.1).
//!
//! # Example
//!
//! ```rust
//! use bytes::Bytes;
//! use futures_executor::block_on;
//! use http::{Request, Response};
//! use http_body_util::Full;
//! use tower::{Layer, Service, service_fn};
//! use webhook_verify::tower::VerifyLayer;
//! use webhook_verify::{Provider, Secret};
//!
//! // GitHub's documented example vector.
//! const SIGNATURE: &str =
//!     "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let mut svc = VerifyLayer::new(Provider::GitHub, Secret::new("It's a Secret to Everybody"))
//!     .layer(service_fn(|req: Request<Bytes>| async move {
//!         Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
//!     }));
//!
//! let request = Request::builder()
//!     .header("X-Hub-Signature-256", SIGNATURE)
//!     .body(Full::new(Bytes::from_static(b"Hello, World!")))?;
//!
//! let response = block_on(svc.call(request))?;
//! assert_eq!(response.status(), 200);
//! # Ok(())
//! # }
//! # run().unwrap_or_else(|error| panic!("example must be self-contained: {error}"));
//! ```
//!
//! # Framework note (downstream body type)
//!
//! After buffering, the inner service receives the request body as `Bytes`
//! by default. The type parameter picks another body type — anything that
//! converts from [`Bytes`] — without retyping the middleware; for axum
//! that is `axum::body::Body`, inferred automatically by `Router::layer`:
//!
//! ```ignore
//! let app = Router::new()
//!     .route("/webhooks/github", post(handler))
//!     .layer(webhook_verify::tower::VerifyLayer::new(Provider::GitHub, secret));
//! ```
//!
//! # Axum: verifying without the middleware
//!
//! If you call [`crate::verify()`] directly instead of using this layer,
//! verify *before* any extractor consumes the request. Extractors run
//! top-down and body-consuming ones (`Json`, `Bytes`, `String`) drain the
//! request; once they have run, the original wire bytes are gone and any
//! signature computed over re-serialized data will (correctly) fail. Capture
//! the body first (`Bytes` as your first extractor), verify those exact
//! bytes against an `http::HeaderMap` via the `http` feature, then
//! deserialize from a copy. Prefer the layer: it makes this ordering
//! impossible to get wrong.
//!
//! # Errors
//!
//! Transport-level failures while reading the request body (e.g. the client
//! disconnected mid-stream) surface through the middleware's `Err` half,
//! matching tower conventions — they are connection problems, not
//! verification outcomes.
//!
//! [`tower`]: https://crates.io/crates/tower

use std::{
    error::Error,
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use ::bytes::Bytes;
use ::http::{Request, Response, StatusCode};
use ::http_body_util::BodyExt;
use ::tower_layer::Layer;
use ::tower_service::Service;

use crate::core::adapter_utils::{conflicting_signature_header, rejection_status};
use crate::{Provider, Secret, VerifyError, VerifyOptions, providers::signature_header_names};

/// Boxed error type used by the middleware, per tower conventions.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// Shared configuration handed to every service built from a [`VerifyLayer`].
///
/// `Secret` and `VerifyOptions` live behind `Arc`s so cloning the layer (or
/// the resulting middleware, as tower runners routinely do) never copies key
/// material around.
#[derive(Clone)]
struct Config {
    provider: Provider,
    secret: Arc<Secret>,
    options: Arc<VerifyOptions>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Provider name only; `Secret`'s own Debug is redacted and
        // `VerifyOptions`' Debug omits URL/form values (spec.md §4.3).
        f.debug_struct("Config")
            .field("provider", &self.provider)
            .field("secret", &self.secret)
            .field("options", &self.options)
            .finish()
    }
}

/// A [`tower_layer::Layer`] verifying webhook signatures with
/// [`crate::verify()`] before passing the request to the inner service.
///
/// See the [module docs](self) for the security contract, status-code table,
/// and framework notes. The type parameter selects the body type the inner
/// service receives after buffering (default [`Bytes`]); anything convertible
/// from `Bytes` works, e.g. `axum::body::Body`.
///
/// Use [`VerifyLayer::with_max_body_size`] to reject oversized request bodies
/// (`413 Payload Too Large`) before any signature verification work, so a
/// malicious client cannot force an arbitrarily large HMAC/verification
/// computation. The body is buffered regardless (verification requires the
/// exact wire bytes); the limit bounds the verification work, not memory.
#[must_use]
#[derive(Clone, Debug)]
pub struct VerifyLayer<B = Bytes> {
    config: Config,
    max_body_size: Option<usize>,
    _body: PhantomData<B>,
}

impl<B> VerifyLayer<B> {
    /// Verifies `provider` signatures using the shared `secret`.
    pub fn new(provider: Provider, secret: Secret) -> Self {
        Self::with_options(provider, secret, VerifyOptions::default())
    }

    /// Like [`VerifyLayer::new`], with explicit [`VerifyOptions`] (timestamp
    /// tolerance, injected clock, URL-scoped schemes such as Square/Twilio).
    pub fn with_options(provider: Provider, secret: Secret, options: VerifyOptions) -> Self {
        Self {
            config: Config {
                provider,
                secret: Arc::new(secret),
                options: Arc::new(options),
            },
            max_body_size: None,
            _body: PhantomData,
        }
    }

    /// Sets an optional maximum body size in bytes.
    ///
    /// When set, requests whose body exceeds this limit are rejected with
    /// `413 Payload Too Large` *before* any signature verification work, so a
    /// malicious client cannot force an arbitrarily large HMAC/verification
    /// computation. The body is fully buffered regardless (verification
    /// requires the exact wire bytes); the limit bounds the verification
    /// work, not the buffering itself.
    ///
    /// When `None` (the default), the body is buffered without a size limit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bytes::Bytes;
    /// use webhook_verify::tower::VerifyLayer;
    /// use webhook_verify::{Provider, Secret};
    ///
    /// // 256 KiB limit, matching actix-web's default body-extractor bound.
    /// let layer: VerifyLayer<Bytes> = VerifyLayer::new(Provider::GitHub, Secret::new("secret"))
    ///     .with_max_body_size(256 * 1024);
    /// ```
    pub fn with_max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = Some(max);
        self
    }
}

// `Layer::layer` takes `&self`, so the layer acts as its own factory: every
// application clones the shared config rather than moving key material.
impl<S, B> Layer<S> for VerifyLayer<B> {
    type Service = VerifyMiddleware<S, B>;

    fn layer(&self, inner: S) -> Self::Service {
        VerifyMiddleware {
            inner,
            config: self.config.clone(),
            max_body_size: self.max_body_size,
            _body: PhantomData,
        }
    }
}

/// The [`Service`] produced by [`VerifyLayer`]; see the [module docs](self).
#[must_use]
pub struct VerifyMiddleware<S, B = Bytes> {
    inner: S,
    config: Config,
    max_body_size: Option<usize>,
    _body: PhantomData<B>,
}

impl<S: Clone, B> Clone for VerifyMiddleware<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
            max_body_size: self.max_body_size,
            _body: PhantomData,
        }
    }
}

impl<S: fmt::Debug, B> fmt::Debug for VerifyMiddleware<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyMiddleware")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .field("max_body_size", &self.max_body_size)
            .finish()
    }
}

/// Empty-bodied rejection response; no error detail leaks over the wire.
fn rejection_response<ResB: Default>(error: &VerifyError) -> Response<ResB> {
    let mut response = Response::new(ResB::default());
    // The status class is a hard-coded constant (400/401/500), so conversion
    // cannot fail; the fallback still fails closed with 500 if it ever did.
    *response.status_mut() =
        StatusCode::from_u16(rejection_status(error)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response
}

impl<S, ReqB, ResB, OutB> Service<Request<ReqB>> for VerifyMiddleware<S, OutB>
where
    S: Service<Request<OutB>, Response = Response<ResB>> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    ReqB: ::http_body::Body<Data = Bytes> + Send + 'static,
    ReqB::Error: Into<BoxError>,
    ResB: Default + Send + 'static,
    OutB: From<Bytes> + Send + 'static,
{
    type Response = Response<ResB>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResB>, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        // Ambiguity check first: it needs no body bytes, so conflicting
        // duplicates are rejected without buffering or signature work.
        let names = signature_header_names(&self.config.provider);
        if let Some(header) = conflicting_signature_header(req.headers(), &names) {
            let response = rejection_response::<ResB>(&VerifyError::MalformedHeader {
                header,
                reason: "header present multiple times with different values",
            });
            return Box::pin(async { Ok(response) });
        }

        let mut inner = self.inner.clone();
        let config = self.config.clone();
        let max_body_size = self.max_body_size;

        Box::pin(async move {
            let (parts, body) = req.into_parts();

            // Buffer the exact wire bytes once; these are both what gets
            // verified and what the inner service receives (spec.md §4.2).
            let raw_body = match BodyExt::collect(body).await {
                Ok(collected) => collected.to_bytes(),
                // Transport-level read failure (client disconnect, body
                // decode error): a connection problem, not a verification
                // outcome — surfaced per tower conventions.
                Err(error) => return Err(error.into()),
            };

            // DoS hardening: reject oversized bodies before any signature
            // work. CPU amplification (HMAC over an arbitrarily large body)
            // is the primary vector this defends against; a streaming body-
            // size guard (e.g. `http_body_util::Limited`) would additionally
            // bound memory, but this crate's verification semantics require
            // the full raw bytes, so the body must be collected regardless.
            if let Some(limit) = max_body_size {
                if raw_body.len() > limit {
                    let mut response = Response::new(ResB::default());
                    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                    return Ok(response);
                }
            }

            if let Err(error) = crate::verify(
                config.provider,
                &parts.headers,
                raw_body.as_ref(),
                &config.secret,
                (*config.options).clone(),
            ) {
                return Ok(rejection_response::<ResB>(&error));
            }

            let request = Request::from_parts(parts, OutB::from(raw_body));
            inner.call(request).await.map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "paypal")]
    use crate::VerifyingKeyMaterial;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::test_helpers::{FixedClock, clocked_at, epoch};
    use ::http_body_util::Full;
    use ::tower::ServiceExt;
    use futures_executor::block_on;

    /// GitHub's documented example vector
    /// (<https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>).
    const GITHUB_SECRET: &str = "It's a Secret to Everybody";
    const GITHUB_BODY: &[u8] = b"Hello, World!";
    const GITHUB_SIGNATURE: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    /// Slack's documented worked example
    /// (<https://docs.slack.dev/authentication/verifying-requests-from-slack>),
    /// same constants used in the provider's own tests.
    const SLACK_SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    const SLACK_TIMESTAMP: u64 = 1_531_420_618;
    const SLACK_BODY: &[u8] =
        b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    const SLACK_SIGNATURE: &str =
        "a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";

    /// Standard Webhooks official test-suite vector (same constants as
    /// `src/providers/standard_webhooks.rs`, which links the source).
    const STANDARD_WEBHOOKS_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const STANDARD_WEBHOOKS_ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const STANDARD_WEBHOOKS_TIMESTAMP: u64 = 1_614_265_330;
    const STANDARD_WEBHOOKS_BODY: &[u8] = br#"{"test": 2432232314}"#;
    const STANDARD_WEBHOOKS_SIGNATURE: &str = "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

    type TestBody = Full<Bytes>;

    /// Inner service echoing how many body bytes it saw, so tests assert the
    /// buffered bytes survive the round trip byte-for-byte.
    #[derive(Clone)]
    struct EchoLen;

    impl Service<Request<Bytes>> for EchoLen {
        type Response = Response<TestBody>;
        type Error = BoxError;
        type Future = std::future::Ready<Result<Response<TestBody>, BoxError>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Bytes>) -> Self::Future {
            let len = req.body().len();
            std::future::ready(Ok(Response::new(TestBody::new(Bytes::from(
                len.to_string(),
            )))))
        }
    }

    fn github_service() -> VerifyMiddleware<EchoLen, Bytes> {
        VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET)).layer(EchoLen)
    }

    fn github_request(body: &'static [u8]) -> Request<TestBody> {
        Request::builder()
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .body(TestBody::new(Bytes::from_static(body)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"))
    }

    // --- happy path ---------------------------------------------------------

    #[test]
    fn valid_signature_reaches_inner_service_with_exact_bytes() {
        block_on(async {
            let svc = github_service();
            let response = svc
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
            // EchoLen reports how many raw bytes reached the inner service.
            assert_eq!(
                response.into_body().into_inner().unwrap_or_default(),
                Bytes::from_static(b"13")
            );
        });
    }

    #[test]
    fn empty_and_unicode_bodies_round_trip_byte_exactly() {
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
            let request = Request::builder()
                .header("X-Hub-Signature-256", signature)
                .body(TestBody::new(Bytes::copy_from_slice(body)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
            let svc = github_service();
            block_on(async {
                let response = svc
                    .oneshot(request)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response.into_body().into_inner().unwrap_or_default(),
                    Bytes::from(body.len().to_string())
                );
            });
        }
    }

    // --- negative: tampered payload -----------------------------------------

    #[test]
    fn tampered_body_is_unauthorized_and_never_reaches_handler() {
        let request = github_request(b"Hello, World?");
        block_on(async {
            let svc = github_service();
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        });
    }

    // --- negative: malformed / ambiguous headers -----------------------------

    #[test]
    fn missing_signature_header_is_bad_request() {
        let request = Request::builder()
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("no headers to misbuild"));
        block_on(async {
            let svc = github_service();
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn conflicting_duplicate_signature_headers_are_rejected() {
        // Second value differs from the first: ambiguous under spec §4.4 even
        // though each value alone would just fail verification normally.
        let request = Request::builder()
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .header(
                "x-hub-signature-256",
                "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            )
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let svc = github_service();
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn identical_duplicate_signature_headers_still_verify() {
        let request = Request::builder()
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .header("x-hub-signature-256", GITHUB_SIGNATURE)
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let svc = github_service();
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn conflicting_duplicate_timestamp_header_is_rejected_for_slack() {
        // Valid-shaped signature plus two conflicting timestamps: ambiguity
        // lives in the timestamp header, not the signature header itself.
        let request = Request::builder()
            .header("X-Slack-Signature", format!("v0={SLACK_SIGNATURE}"))
            .header("X-Slack-Request-Timestamp", SLACK_TIMESTAMP.to_string())
            .header("x-slack-request-timestamp", "1700000001")
            .body(TestBody::new(Bytes::from_static(SLACK_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));

        let svc = VerifyLayer::new(Provider::Slack, Secret::new(SLACK_SECRET)).layer(EchoLen);
        block_on(async {
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn conflicting_duplicate_id_header_is_rejected_for_standard_webhooks() {
        // Standard Webhooks reads three headers (webhook-id,
        // webhook-timestamp, webhook-signature); the ambiguity scan covers
        // all three. The signature below is the official vector's over the
        // *first* id and the clock is pinned to the vector timestamp, so if
        // the duplicate `webhook-id` were not flagged this request would
        // verify — 400 therefore proves the ambiguity check itself fired.
        let request = Request::builder()
            .header("webhook-id", STANDARD_WEBHOOKS_ID)
            .header("webhook-timestamp", STANDARD_WEBHOOKS_TIMESTAMP.to_string())
            .header(
                "webhook-signature",
                format!("v1,{STANDARD_WEBHOOKS_SIGNATURE}"),
            )
            .header("webhook-id", "msg_forged")
            .body(TestBody::new(Bytes::from_static(STANDARD_WEBHOOKS_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));

        // Clock pinned to the vector's timestamp so replay accepts the
        // single-header form (assertion below) and cannot be the rejector.
        let svc = VerifyLayer::with_options(
            Provider::StandardWebhooks,
            Secret::new(STANDARD_WEBHOOKS_SECRET),
            crate::VerifyOptions {
                clock: Some(Arc::new(FixedClock(epoch(STANDARD_WEBHOOKS_TIMESTAMP)))),
                ..crate::VerifyOptions::default()
            },
        )
        .layer(EchoLen);
        block_on(async {
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });

        // Sanity: the same headers without the duplicate verify end to end.
        let good = Request::builder()
            .header("webhook-id", STANDARD_WEBHOOKS_ID)
            .header("webhook-timestamp", STANDARD_WEBHOOKS_TIMESTAMP.to_string())
            .header(
                "webhook-signature",
                format!("v1,{STANDARD_WEBHOOKS_SIGNATURE}"),
            )
            .body(TestBody::new(Bytes::from_static(STANDARD_WEBHOOKS_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let svc = VerifyLayer::with_options(
                Provider::StandardWebhooks,
                Secret::new(STANDARD_WEBHOOKS_SECRET),
                crate::VerifyOptions {
                    clock: Some(Arc::new(FixedClock(epoch(STANDARD_WEBHOOKS_TIMESTAMP)))),
                    ..crate::VerifyOptions::default()
                },
            )
            .layer(EchoLen);
            let response = svc
                .oneshot(good)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn conflicting_third_signature_value_is_rejected() {
        // [valid, valid, forged]: the differing value is not adjacent to the
        // first one. The scan must compare every value against the first, not
        // just the first pair — a "first-two-only" implementation would let
        // this verify against the valid first value.
        let request = Request::builder()
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .header(
                "X-Hub-Signature-256",
                "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            )
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let svc = github_service();
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn comma_joined_signature_value_fails_closed() {
        // A single header *line* carrying comma-joined values is one HTTP
        // value, so the ambiguity scan does not (and must not) split it.
        // Rejection is guaranteed downstream: GitHub hex-decodes the whole
        // remainder after `sha256=` as one unit and the comma is not hex.
        // The invariant this pins is "never verifies" — today that is 400.
        let request = Request::builder()
            .header(
                "X-Hub-Signature-256",
                format!(
                    "{GITHUB_SIGNATURE},sha256=0000000000000000000000000000000000000000000000000000000000000000"
                ),
            )
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let svc = github_service();
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    // --- replay protection through the adapter -------------------------------

    #[test]
    fn stale_timestamp_is_unauthorized_through_adapter() {
        let request = Request::builder()
            .header("X-Slack-Signature", format!("v0={SLACK_SIGNATURE}"))
            .header("X-Slack-Request-Timestamp", SLACK_TIMESTAMP.to_string())
            .body(TestBody::new(Bytes::from_static(SLACK_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));

        // "Now" ten minutes after signing: outside the default 300s window.
        let late = epoch(SLACK_TIMESTAMP + 600);
        let svc = VerifyLayer::with_options(
            Provider::Slack,
            Secret::new(SLACK_SECRET),
            crate::VerifyOptions {
                clock: Some(Arc::new(FixedClock(late))),
                ..crate::VerifyOptions::default()
            },
        )
        .layer(EchoLen);

        block_on(async {
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        });
    }

    // --- custom schemes and unsupported providers ----------------------------

    #[test]
    fn custom_scheme_headers_are_dup_checked_too() {
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
        let ambiguous = Request::builder()
            .header("X-My-Sig", format!("sha256={DIGEST}"))
            .header("x-my-sig", "sha256=00")
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        let svc = VerifyLayer::new(Provider::Custom(scheme), Secret::new("k")).layer(EchoLen);
        block_on(async {
            let response = svc
                .oneshot(ambiguous)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });

        // A single well-formed value verifies end to end.
        let good = Request::builder()
            .header("X-My-Sig", format!("sha256={DIGEST}"))
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let svc = VerifyLayer::new(Provider::Custom(scheme), Secret::new("k")).layer(EchoLen);
            let response = svc
                .oneshot(good)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn conflicting_timestamp_header_is_rejected_for_custom_scheme() {
        // A CustomScheme's `timestamp_header` participates in the ambiguity
        // scan like a built-in provider's. The clock is pinned to the
        // timestamp and the digest is valid, so the single-header form would
        // verify — 400 proves the duplicate timestamp was flagged, not a
        // replay or signature failure.
        const DIGEST: &str = "11316937114e6970aa59bd5326a6f38dd525f4ade64670e402bff41e2f7c4071";
        let scheme = crate::CustomScheme {
            hash: crate::HashAlg::Sha256,
            signature_header: "X-My-Sig",
            timestamp_header: Some("X-My-Ts"),
            encoding: crate::Encoding::Hex,
            prefix: Some("sha256="),
            signed_string: |_headers, body| body.to_vec(),
        };
        let options = crate::VerifyOptions {
            clock: Some(Arc::new(FixedClock(epoch(1_700_000_000)))),
            ..crate::VerifyOptions::default()
        };

        let ambiguous = Request::builder()
            .header("X-My-Sig", format!("sha256={DIGEST}"))
            .header("X-My-Ts", "1700000000")
            .header("x-my-ts", "1700000001")
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        let svc =
            VerifyLayer::with_options(Provider::Custom(scheme), Secret::new("k"), options.clone())
                .layer(EchoLen);
        block_on(async {
            let response = svc
                .oneshot(ambiguous)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });

        // Sanity: a single timestamp verifies end to end under the same clock.
        let good = Request::builder()
            .header("X-My-Sig", format!("sha256={DIGEST}"))
            .header("X-My-Ts", "1700000000")
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let svc =
                VerifyLayer::with_options(Provider::Custom(scheme), Secret::new("k"), options)
                    .layer(EchoLen);
            let response = svc
                .oneshot(good)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn unsupported_provider_maps_to_internal_server_error() {
        // PayPal stays "unsupported" only when the `paypal` feature is off;
        // see the feature-gated variant below for the implemented path.
        #[cfg(not(feature = "paypal"))]
        {
            let svc = VerifyLayer::new(Provider::PayPal, Secret::new("unused")).layer(EchoLen);
            let request = Request::builder()
                .body(TestBody::new(Bytes::from_static(b"{}")))
                .unwrap_or_else(|_| unreachable!("no headers to misbuild"));
            block_on(async {
                let response = svc
                    .oneshot(request)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            });
        }
        #[cfg(feature = "paypal")]
        {
            let cert = include_bytes!("../tests/data/paypal_test_cert.pem");
            // Clock pinned to the vector's transmission time (replay window).
            let options = clocked_at(1_715_836_763, None)
                .with_webhook_id("0NH55953DH663215D")
                .with_verifying_material(VerifyingKeyMaterial::X509Certificate(cert.to_vec()));
            let svc = VerifyLayer::with_options(Provider::PayPal, Secret::new("unused"), options)
                .layer(EchoLen);
            let body = include_bytes!("../tests/data/paypal_docs_body.json");
            let request = Request::builder()
                .header(
                    "PayPal-Transmission-Id",
                    "db49fb10-1343-11ef-ac58-e32457403f67",
                )
                .header("PayPal-Transmission-Time", "2024-05-16T05:19:23Z")
                .header(
                    "PayPal-Transmission-Sig",
                    "aGYe/s6lwrASh2zyTRIAz8Edo705ezMKekirejT08ev3VXdWAkq4JWADiNPUGelx5qrEKxC7mPIHmAwQ5hOT6unhY9n33M/DbXTKGsuITPdXRA7qYVmc2wsIp68BpzB6pC6+5vt/YLQvflsrwrutGa0KyZc5FinuYNN8pTNomv4uiygasWqfnDyKViKQPNZecowag6tY/9pj7+bgBu/joBpYUq0+cQxfGqNnlvywBJ7HCOf4edeTIvM/c1CvvAHGtNTU54kLjWGue640twn6iXPL8tnaABZ8Fr9m0z87v8oY0vBobERV0Yu8thUToKhvQEFF26Rckqy07VVddg1CmA==",
                )
                .header("PayPal-Cert-Url", "https://example.invalid/cert-url")
                .header("PayPal-Auth-Algo", "SHA256withRSA")
                .body(TestBody::new(Bytes::from_static(body)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
            block_on(async {
                let response = svc
                    .oneshot(request)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                assert_eq!(response.status(), StatusCode::OK);
            });
        }
    }

    // --- unit-level checks ----------------------------------------------------

    #[test]
    fn identical_opaque_duplicate_values_are_not_ambiguous_but_fail_verification() {
        // Two identical opaque-byte values are not ambiguous per §4.4 (same
        // value); downstream lookup reports them absent and fails closed.
        let mut headers = ::http::HeaderMap::new();
        let value = ::http::HeaderValue::from_bytes(&[0xFF])
            .unwrap_or_else(|_| unreachable!("0xFF is permitted"));
        headers.append("X-Hub-Signature-256", value.clone());
        headers.append("X-Hub-Signature-256", value);
        assert!(conflicting_signature_header(&headers, &["X-Hub-Signature-256"]).is_none());
    }

    #[test]
    fn mixed_opaque_and_parsed_signature_values_are_rejected_as_ambiguous() {
        // One opaque-byte value plus a parsable one: distinct underlying
        // bytes, so §4.4 ambiguity applies even though only the parsable
        // value could ever verify. The scan compares bytes, not decoded
        // signatures.
        let mut headers = ::http::HeaderMap::new();
        let opaque = ::http::HeaderValue::from_bytes(&[0xFF])
            .unwrap_or_else(|_| unreachable!("0xFF is permitted"));
        headers.append("X-Hub-Signature-256", opaque);
        headers.append(
            "X-Hub-Signature-256",
            ::http::HeaderValue::from_static(GITHUB_SIGNATURE),
        );
        assert_eq!(
            conflicting_signature_header(&headers, &["X-Hub-Signature-256"]),
            Some("X-Hub-Signature-256")
        );
    }

    #[test]
    fn unparseable_header_name_fails_closed_as_ambiguous() {
        // A header-name string the http crate refuses to parse (embedded
        // whitespace) must fail closed as "ambiguous" per §4.4 — the parse-
        // error arm exists precisely so attacker-supplied garbage can never
        // turn into a permissive lookup.
        let headers = ::http::HeaderMap::new();
        assert_eq!(
            conflicting_signature_header(&headers, &["x-hub-signature-256 invalid"]),
            Some("x-hub-signature-256 invalid")
        );
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let layer = VerifyLayer::<Bytes>::with_options(
            Provider::GitHub,
            Secret::new("super-secret-hmac-key"),
            crate::VerifyOptions::default().with_request_url("https://internal.example/hook"),
        );
        let debug = format!("{layer:?}");
        assert!(!debug.contains("super-secret-hmac-key"));
        assert!(!debug.contains("internal.example"));
    }

    // --- max_body_size (DoS hardening) ------------------------------------

    #[test]
    fn body_within_limit_is_accepted() {
        block_on(async {
            // GITHUB_BODY is 13 bytes; limit is 1024.
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(1024)
                .layer(EchoLen);
            let response = svc
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn body_exceeding_limit_is_rejected_with_413() {
        block_on(async {
            // GITHUB_BODY is 13 bytes; limit is 10 — body exceeds limit.
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(10)
                .layer(EchoLen);
            let response = svc
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        });
    }

    #[test]
    fn body_exactly_at_limit_is_accepted() {
        // Construct a body whose length matches the limit exactly.
        let body = vec![0u8; 13];
        let sig = {
            use hmac::{Hmac, KeyInit, Mac};
            use sha2::Sha256;
            type H = Hmac<Sha256>;
            let mut mac = H::new_from_slice(GITHUB_SECRET.as_bytes())
                .unwrap_or_else(|_| unreachable!("valid key"));
            mac.update(&body);
            let result = mac.finalize().into_bytes();
            format!("sha256={}", hex::encode(result))
        };

        let request = Request::builder()
            .header("X-Hub-Signature-256", sig)
            .body(TestBody::new(Bytes::from(body)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));

        block_on(async {
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(13)
                .layer(EchoLen);
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn body_one_byte_over_limit_is_rejected() {
        // Construct a body that is one byte over the limit.
        let body = vec![0u8; 14];
        let sig = {
            use hmac::{Hmac, KeyInit, Mac};
            use sha2::Sha256;
            type H = Hmac<Sha256>;
            let mut mac = H::new_from_slice(GITHUB_SECRET.as_bytes())
                .unwrap_or_else(|_| unreachable!("valid key"));
            mac.update(&body);
            let result = mac.finalize().into_bytes();
            format!("sha256={}", hex::encode(result))
        };

        let request = Request::builder()
            .header("X-Hub-Signature-256", sig)
            .body(TestBody::new(Bytes::from(body)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));

        block_on(async {
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(13)
                .layer(EchoLen);
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        });
    }

    #[test]
    fn default_no_limit_still_works() {
        // Ensure the default (no max_body_size) path is unchanged.
        block_on(async {
            let svc = VerifyLayer::<Bytes>::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .layer(EchoLen);
            let response = svc
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn zero_limit_rejects_nonempty_body() {
        // A zero limit means no non-empty body is accepted.
        block_on(async {
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(0)
                .layer(EchoLen);
            let response = svc
                .oneshot(github_request(GITHUB_BODY)) // 13 bytes
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        });
    }

    #[test]
    fn debug_output_never_contains_secrets_with_max_body_size() {
        let layer = VerifyLayer::<Bytes>::new(Provider::GitHub, Secret::new("super-secret-key"))
            .with_max_body_size(1024);
        let debug = format!("{layer:?}");
        assert!(!debug.contains("super-secret-key"));
    }
}
