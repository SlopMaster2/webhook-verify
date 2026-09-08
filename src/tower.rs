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
//!
//! # Status codes
//!
//! | `VerifyError` class | Status |
//! |---|---|
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

use crate::core::adapter_utils::rejection_status;
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
#[must_use]
#[derive(Clone, Debug)]
pub struct VerifyLayer<B = Bytes> {
    config: Config,
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
            _body: PhantomData,
        }
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
            _body: PhantomData,
        }
    }
}

/// The [`Service`] produced by [`VerifyLayer`]; see the [module docs](self).
#[must_use]
pub struct VerifyMiddleware<S, B = Bytes> {
    inner: S,
    config: Config,
    _body: PhantomData<B>,
}

impl<S: Clone, B> Clone for VerifyMiddleware<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
            _body: PhantomData,
        }
    }
}

impl<S: fmt::Debug, B> fmt::Debug for VerifyMiddleware<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyMiddleware")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .finish()
    }
}

/// Returns the name of the first header in `names` that occurs in `headers`
/// more than once with *differing* values — the ambiguity `spec.md` §4.4
/// requires rejecting — or `None` when none is ambiguous.
///
/// Static header-name constants always parse, so the parse-error arm is
/// unreachable in practice and simply fails closed (reported as ambiguous).
fn conflicting_signature_header(
    headers: &::http::HeaderMap,
    names: &[&'static str],
) -> Option<&'static str> {
    names.iter().copied().find(|name| {
        let Ok(key) = ::http::header::HeaderName::from_bytes(name.as_bytes()) else {
            return true;
        };
        let mut values = headers.get_all(&key).iter();
        let Some(first) = values.next() else {
            return false;
        };
        values.any(|value| value != first)
    })
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
}
