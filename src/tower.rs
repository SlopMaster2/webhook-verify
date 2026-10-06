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
//! - **Secret rotation**: [`VerifyLayer::with_fallback_secrets`] makes the
//!   layer try a second (and further) keys after the primary one, with the same
//!   `verify_any()` aggregation rules (`spec.md` §2.1) — a delivery signed by
//!   either side of a rotation window reaches the inner service, and a
//!   well-formed key that matches nothing is still a `401`. Without it, a
//!   rotation window meant dropping out of the layer entirely.
//! - **Optional body size limit** (DoS hardening): use
//!   [`VerifyLayer::with_max_body_size`] to reject oversized request bodies
//!   with `413 Payload Too Large` before any signature work, so a malicious
//!   client cannot force an arbitrarily large HMAC/verification computation —
//!   or an arbitrarily large buffered body. A request whose `Content-Length`
//!   already exceeds the limit is rejected before a single byte is read;
//!   otherwise the read itself is bounded by the limit, so a body sent without
//!   a length (`Transfer-Encoding: chunked`) is stopped as soon as it exceeds
//!   it rather than after being buffered whole. A body *within* the limit is
//!   still buffered in full (verification requires the exact wire bytes) and
//!   reaches the inner service byte-for-byte.
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
//! `Display`/`Debug` never carry secret material (`spec.md` §2.1). The status
//! code alone cannot supply that detail — it collapses three variants into one
//! `400` and three into one `500` — and this middleware runs *before* your
//! handler, so unlike actix's extractor there is no object to hand the error to
//! afterwards. [`VerifyLayer::on_rejection`] is the surface: it hands your
//! callback a [`Rejection`] — [`crate::verify()`]'s own error, or
//! `BodyTooLarge` for either `413` path — with nothing put on the wire.
//!
//! # Providers that need request context
//!
//! The layer verifies with the single [`VerifyOptions`] it was built with —
//! [`VerifyLayer::new`] supplies [`VerifyOptions::default()`],
//! [`VerifyLayer::with_options`] whatever you pass — and **no endpoint URL,
//! method, or key material is read out of the incoming request**. The URL and
//! the method are not derived from the request being verified, because what
//! those schemes sign is the value **the provider signed**, not the one this
//! process received: behind a reverse proxy, a path-prefix mount, or an
//! https-terminating load balancer the request's own URI is not the webhook
//! URL the provider signed, so deriving it would verify a different string
//! than the signer produced. Key material has no equivalent derivation to
//! reject — it is simply not in the request to begin with, except as PayPal's
//! certificate *URL*, which this crate will not fetch (see below).
//!
//! Seven built-in providers need that context configured, and omitting a
//! required value fails closed with [`VerifyError::MissingContext`] — the `500`
//! row above, never a `401` that would read as a forgery:
//!
//! - `Contentful` and `HubSpot` need both
//!   [`VerifyOptions::request_method`] and [`VerifyOptions::request_url`];
//! - `Square` needs [`VerifyOptions::request_url`];
//! - `Twilio` and `Mandrill` need [`VerifyOptions::request_url`];
//! - `SendGrid` needs [`VerifyOptions::verifying_material`];
//! - `PayPal` needs [`VerifyOptions::verifying_material`] **and**
//!   [`VerifyOptions::webhook_id`].
//!
//! `PayPal` and `SendGrid` ignore the `Secret` entirely and verify against
//! that key material instead, so a default [`VerifyOptions`] leaves them
//! nothing to check. PayPal does carry a certificate URL in the request, but
//! this crate performs no network calls (`spec.md` §7) — the certificate is
//! yours to fetch, allow-list and supply — and PayPal's webhook-subscription ID
//! travels nowhere near the request at all. Both sit behind crate features
//! (`paypal`, `sendgrid`); without one, `verify()` fails closed with
//! [`VerifyError::UnsupportedProvider`].
//!
//! Every one of the seven is a constant of the deployment — one endpoint, one
//! method, one key — so [`VerifyLayer::with_options`] covers it:
//!
//! ```rust
//! use bytes::Bytes;
//! use webhook_verify::tower::VerifyLayer;
//! use webhook_verify::{Provider, Secret, VerifyOptions};
//!
//! // Square signs the public webhook URL plus the raw body.
//! let options = VerifyOptions::default().with_request_url("https://example.com/webhooks/square");
//! let layer: VerifyLayer<Bytes> =
//!     VerifyLayer::with_options(Provider::Square, Secret::new("sq0csp-..."), options);
//!
//! // Twilio signs the public webhook URL plus the sorted POST form fields.
//! // Leave `form_params` unset: see below.
//! let options = VerifyOptions::default().with_request_url("https://example.com/webhooks/twilio");
//! let layer: VerifyLayer<Bytes> =
//!     VerifyLayer::with_options(Provider::Twilio, Secret::new("auth-token"), options);
//! ```
//!
//! [`VerifyOptions::form_params`] is the one context option to leave alone. It
//! is the parsed `application/x-www-form-urlencoded` **body**, so it differs on
//! every delivery while this layer's options are fixed once at construction —
//! so configuring fields there would pin every delivery to one delivery's field
//! set and reject the rest, which reads like a broken integration rather than a
//! design limitation. Left unset, `Twilio` and `Mandrill` decode those fields
//! from the request body this layer already buffers verbatim
//! (`application/x-www-form-urlencoded`: one field per `&`-separated element,
//! `+` read as a space, `%XX` read as the byte it names), so **both providers
//! verify through this layer** with only `request_url` configured.
//!
//! **Do not** set `form_params` on a layer: it pins every delivery to one
//! delivery's field set and rejects the rest. Set it only when calling
//! [`crate::verify()`] yourself — to use your own parser, or for Twilio's
//! JSON-body variant, which signs the URL alone and so needs an explicitly
//! empty field list (issue #363).
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
//! verification outcomes. Those are the only request failures an
//! [`on_rejection`](VerifyLayer::on_rejection) hook does not see: the middleware
//! answered no response for them.
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
use ::http_body_util::{BodyExt, LengthLimitError, Limited};
use ::tower_layer::Layer;
use ::tower_service::Service;

use crate::core::adapter_utils::{
    KeyRing, declared_content_length, find_ambiguous_signature_header,
};
use crate::{Provider, Secret, VerifyError, VerifyOptions};

/// Boxed error type used by the middleware, per tower conventions.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// A request this middleware rejected before it reached the inner service.
///
/// Handed to the [`VerifyLayer::on_rejection`] callback. It is the structured
/// counterpart of the [status code](Rejection::status) the rejection response
/// carries, and exists because that status code cannot carry the class on its
/// own: the status mapping deliberately collapses `MissingHeader`,
/// `MalformedHeader`, and `BadEncoding` into one `400`, and
/// `UnsupportedProvider`, `InvalidSecret`, and `MissingContext` into one `500`.
///
/// Nothing here is sent to the client — the response body stays empty
/// ([`spec.md`] §2.1's redaction discipline) — and the `VerifyError` is
/// `crate::verify()`'s own value, unchanged.
///
/// [`spec.md`]: https://github.com/SlopMaster2/webhook-verify/blob/master/spec.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// Verification failed with this error; the status is derived from it, so
    /// [`Rejection::status`] and the response can never disagree.
    Verify(VerifyError),
    /// The body exceeded the [`VerifyLayer::with_max_body_size`] limit (`413`).
    ///
    /// Not a `VerifyError` — no signature work was done at all, because the
    /// whole point of the limit is to bound that work — so
    /// [`Rejection::verify_error`] is `None` here, matching the "not a
    /// `VerifyError`" row of the module's [status
    /// table](crate::tower#status-codes).
    BodyTooLarge,
}

impl Rejection {
    /// The verification error behind this rejection, when there is one.
    ///
    /// `Some` for [`Rejection::Verify`] — [`crate::verify()`]'s own value, so
    /// `match`ing on it gives the full §2.1 granularity — and `None` for
    /// [`Rejection::BodyTooLarge`], which never reached verification.
    #[must_use]
    pub fn verify_error(&self) -> Option<&VerifyError> {
        match self {
            Self::Verify(error) => Some(error),
            Self::BodyTooLarge => None,
        }
    }

    /// The status the rejection response carries: the same value the response
    /// itself is built from, so a hook and the response cannot disagree.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Verify(error) => {
                // The status class is a fixed `u16` (400/401/500) from
                // `VerifyError::rejection_status` — the same classification a
                // direct `verify()` caller reads — so conversion cannot fail;
                // the fallback still fails closed with 500 if it ever did.
                StatusCode::from_u16(error.rejection_status())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }
}

/// Callback invoked on every request the middleware rejects.
///
/// Stored behind an `Arc` — the layer's shared configuration, which every
/// service built from that layer holds — so cloning a layer, or the middleware
/// tower runners routinely clone, stays cheap.
pub type RejectionHook = Arc<dyn Fn(&Rejection) + Send + Sync>;

/// Shared configuration handed to every service built from a [`VerifyLayer`].
///
/// The key ring and `VerifyOptions` live behind `Arc`s so cloning the layer (or
/// the resulting middleware, as tower runners routinely do) never copies key
/// material around.
#[derive(Clone)]
struct Config {
    provider: Provider,
    keys: KeyRing,
    options: Arc<VerifyOptions>,
    on_rejection: Option<RejectionHook>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Provider name only; `KeyRing`'s Debug lists the configured keys
        // through `Secret`'s redacted `Debug`, and `VerifyOptions`' Debug omits
        // URL/form values (spec.md §4.3).
        f.debug_struct("Config")
            .field("provider", &self.provider)
            .field("keys", &self.keys)
            .field("options", &self.options)
            // Whether a hook is configured, never anything about it: a closure's
            // Debug is not ours to define and may capture whatever it likes.
            .field("on_rejection", &self.on_rejection.is_some())
            .finish()
    }
}

impl Config {
    /// The one place a rejection becomes a response: the configured hook is
    /// given the structured reason first, then the empty-bodied, status-coded
    /// response is built from *that same* reason — so the two can never drift,
    /// and a new rejection site cannot forget one of the two.
    ///
    /// The body stays empty: no error detail leaks over the wire
    /// (`spec.md` §2.1's redaction discipline).
    fn reject<ResB: Default>(&self, rejection: Rejection) -> Response<ResB> {
        if let Some(hook) = &self.on_rejection {
            hook(&rejection);
        }
        let mut response = Response::new(ResB::default());
        *response.status_mut() = rejection.status();
        response
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
/// computation — or an arbitrarily large buffered body. Requests declaring an
/// oversized `Content-Length` are rejected before any body bytes are buffered;
/// every other request is read under the limit itself, so a body sent without a
/// length (`Transfer-Encoding: chunked`) is rejected as soon as it exceeds it
/// rather than after being buffered whole (issue #368).
///
/// A rejection is answered with an empty body and a status code, so the class
/// of failure is only observable if you ask for it: use
/// [`VerifyLayer::on_rejection`] to have the structured [`Rejection`] handed to
/// a callback (issue #379).
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
    /// tolerance, injected clock, URL-scoped schemes such as Square/Twilio,
    /// and the key material PayPal/SendGrid verify against — see the module
    /// docs' "Providers that need request context" list).
    pub fn with_options(provider: Provider, secret: Secret, options: VerifyOptions) -> Self {
        Self {
            config: Config {
                provider,
                keys: KeyRing::new(secret),
                options: Arc::new(options),
                on_rejection: None,
            },
            max_body_size: None,
            _body: PhantomData,
        }
    }

    /// Also accepts signatures made with any of `fallbacks`, tried after the
    /// primary `secret` — the signing-key rotation window of `verify_any()`
    /// (`spec.md` §2.1), reachable through the layer.
    ///
    /// A delivery verifies if *any* configured key matches, and the error
    /// aggregation is the one `verify_any()` documents: structural errors
    /// (`MissingHeader`, `MalformedHeader`, `BadEncoding`, …) return
    /// immediately; a key rejected for its own shape (`InvalidSecret` — empty,
    /// whitespace-only, or NUL-only) is *skipped* rather than aborting the
    /// search, so one garbled entry cannot take the whole ring down; a
    /// well-formed key that does not match yields `SignatureMismatch` once every
    /// key has been tried; and `InvalidSecret` is reported only when *every*
    /// key is unusable. A ring of exactly one key behaves exactly as before
    /// this method existed.
    ///
    /// Order only matters for cost — the first match wins, and each attempt is
    /// one HMAC — and for which key is blamed when none matches. Put the key
    /// most deliveries arrive with first, so the common case stops at one
    /// attempt.
    ///
    /// The keys stay valid for as long as they are configured: drop a key once
    /// the provider's window has closed, and the old deliveries signed with it
    /// stop verifying. This is only meaningful for the shared-secret providers;
    /// PayPal and SendGrid ignore the `Secret` entirely and verify against
    /// [`VerifyOptions::verifying_material`](crate::VerifyOptions), so
    /// fallbacks give them no rotation semantics (see
    /// [`verify_any`](crate::verify_any)).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bytes::Bytes;
    /// use webhook_verify::tower::VerifyLayer;
    /// use webhook_verify::{Provider, Secret};
    ///
    /// let layer: VerifyLayer<Bytes> = VerifyLayer::new(
    ///     Provider::GitHub,
    ///     Secret::new("the new secret"),
    /// )
    /// .with_fallback_secrets([Secret::new("the previous secret")]);
    /// ```
    pub fn with_fallback_secrets(mut self, fallbacks: impl IntoIterator<Item = Secret>) -> Self {
        self.config.keys = self.config.keys.with_fallbacks(fallbacks);
        self
    }

    /// Sets an optional maximum body size in bytes.
    ///
    /// When set, requests whose body exceeds this limit are rejected with
    /// `413 Payload Too Large` *before* any signature verification work, so a
    /// malicious client cannot force an arbitrarily large HMAC/verification
    /// computation. Requests that declare an oversized `Content-Length` are
    /// rejected before any body bytes are read; every other request is read
    /// under the limit itself, so a body sent without a length
    /// (`Transfer-Encoding: chunked`) is rejected as soon as it exceeds it
    /// rather than after being buffered whole (issue #368).
    ///
    /// A body within the limit is buffered in full — verification requires the
    /// exact wire bytes — and forwarded unchanged.
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

    /// Calls `hook` with the structured [`Rejection`] for every request this
    /// middleware refuses, so a tower/axum user can log or count the *class* of
    /// failure (issue #379).
    ///
    /// The middleware runs before your handler, so unlike actix's extractor
    /// there is no object to hand the error to afterwards — and the response is
    /// deliberately bodiless, so the class never reaches the wire. This hook is
    /// the surface that makes the module's logging contract actionable: it is
    /// the only place the [`VerifyError`] behind a `400`/`401`/`500` is
    /// observable, which matters because the status code collapses three
    /// variants into each of `400` and `500` (see [`Rejection::verify_error`]).
    ///
    /// Invoked for every rejection the middleware answers, and only those:
    ///
    /// - [`Rejection::Verify`] with [`crate::verify()`]'s own error — including
    ///   the `400` the ambiguity scan raises for conflicting duplicate signature
    ///   headers (`spec.md` §4.4) before any signature work;
    /// - [`Rejection::BodyTooLarge`] on **both** `413` paths — a declared
    ///   `Content-Length` over the limit and a body that exceeds it while being
    ///   read — so DoS metrics see the refusals the size limit exists to make,
    ///   not just verification outcomes.
    ///
    /// A transport-level body read failure (client disconnect mid-stream) is
    /// *not* reported here: that request is answered through the service's
    /// `Err` half rather than a response, per tower conventions, and is a
    /// connection problem rather than a rejection of the request's contents.
    ///
    /// # Cost and failure mode
    ///
    /// One `Arc` deref and one indirect call per *rejected* request, inline
    /// with producing the response — synchronously in `call()` for the
    /// ambiguity and declared-length rejections, and inside the future just
    /// before the response is returned for the rest. Nothing is added to a
    /// request that verifies. The hook therefore runs on the hot path, so it
    /// must be cheap and non-blocking: a hook that blocks delays that request,
    /// and a hook that panics turns a rejection into a panic. Keep it to
    /// incrementing a counter, opening a `tracing` span, or forwarding to a
    /// non-blocking channel. (This is the one cost actix's
    /// `WebhookVerificationError` accessor does not have — there, the handler is
    /// already running.)
    ///
    /// A hook is server-side observation only: whatever it logs, the error it
    /// receives is already redacted of secret material (`spec.md` §2.1), and
    /// nothing it does can change what the client is told.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bytes::Bytes;
    /// use std::sync::atomic::{AtomicU64, Ordering};
    /// use webhook_verify::tower::{Rejection, VerifyLayer};
    /// use webhook_verify::{Provider, Secret, VerifyError};
    ///
    /// static FORGED: AtomicU64 = AtomicU64::new(0);
    /// static MISCONFIGURED: AtomicU64 = AtomicU64::new(0);
    ///
    /// let layer: VerifyLayer<Bytes> =
    ///     VerifyLayer::new(Provider::GitHub, Secret::new("secret")).on_rejection(|rejection| {
    ///         match rejection.verify_error() {
    ///             // An operator mistake, not an attacker: page on these.
    ///             Some(VerifyError::InvalidSecret { .. } | VerifyError::MissingContext { .. }) => {
    ///                 MISCONFIGURED.fetch_add(1, Ordering::Relaxed);
    ///             }
    ///             Some(VerifyError::SignatureMismatch) => {
    ///                 FORGED.fetch_add(1, Ordering::Relaxed);
    ///             }
    ///             // A request we could not use, or an oversize body.
    ///             Some(_) | None => {}
    ///         }
    ///     });
    /// ```
    pub fn on_rejection(mut self, hook: impl Fn(&Rejection) + Send + Sync + 'static) -> Self {
        self.config.on_rejection = Some(Arc::new(hook));
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
        // duplicates are rejected without buffering or signature work. Covers
        // the provider's static signature headers plus any header the request
        // itself enumerates as signing material (Contentful's
        // `x-contentful-signed-headers`) — see `spec.md` §4.4.
        if let Some(header) = find_ambiguous_signature_header(req.headers(), &self.config.provider)
        {
            let response = self
                .config
                .reject(Rejection::Verify(VerifyError::MalformedHeader {
                    header,
                    reason: VerifyError::AMBIGUOUS_HEADER_REASON,
                }));
            return Box::pin(async { Ok(response) });
        }

        // Pre-buffer DoS guard: a declared `Content-Length` over the limit is
        // rejected with 413 before a single body byte is read, which no
        // read-time guard can do — this one costs no I/O at all. Requests
        // without a usable declared length (chunked transfer, a non-numeric
        // length) are caught by the streaming limit below, which bounds the
        // buffering itself.
        if let Some(limit) = self.max_body_size {
            if declared_content_length(req.headers()).is_some_and(|len| len > limit) {
                let response = self.config.reject(Rejection::BodyTooLarge);
                return Box::pin(async { Ok(response) });
            }
        }

        let mut inner = self.inner.clone();
        let config = self.config.clone();
        let max_body_size = self.max_body_size;

        Box::pin(async move {
            let (parts, body) = req.into_parts();

            // Buffer the exact wire bytes once; these are both what gets
            // verified and what the inner service receives (spec.md §4.2).
            //
            // With a limit configured, the read is bounded while it happens
            // rather than checked after it: `Limited` forwards every data
            // frame untouched until one would push the total past the limit,
            // so a body that fits is byte-identical to an unlimited read, and
            // one that does not fit can never force the allocation it was
            // trying to provoke (issue #368). It is the same limit the
            // post-buffer check used to apply, applied earlier, which is why
            // there is no length check on the collected bytes below: `Limited`
            // cannot yield more than `limit` of them.
            let raw_body = match max_body_size {
                Some(limit) => match BodyExt::collect(Limited::new(body, limit)).await {
                    Ok(collected) => collected.to_bytes(),
                    // The one body read failure that is a request outcome
                    // rather than a connection problem: this adapter's own
                    // size limit, reported the same way as every other
                    // oversize rejection — including to an `on_rejection`
                    // hook, so a DoS counter sees both `413` paths. Answering
                    // it here means the rest of an oversize body is never read,
                    // so the connection cannot be reused for it — the usual
                    // trade for refusing a request before consuming it.
                    Err(error) if error.is::<LengthLimitError>() => {
                        return Ok(config.reject(Rejection::BodyTooLarge));
                    }
                    // Transport-level read failure (client disconnect, body
                    // decode error) — surfaced per tower conventions.
                    Err(error) => return Err(error),
                },
                None => match BodyExt::collect(body).await {
                    Ok(collected) => collected.to_bytes(),
                    Err(error) => return Err(error.into()),
                },
            };

            if let Err(error) = config.keys.verify(
                config.provider,
                &parts.headers,
                raw_body.as_ref(),
                // Borrow the shared options straight out of the `Arc`; the
                // by-value `crate::verify()` would deep-clone them on every
                // request (copying `verifying_material`, `request_url`, ...),
                // which is exactly the copying the `Config` `Arc`s exist to
                // avoid.
                config.options.as_ref(),
            ) {
                return Ok(config.reject(Rejection::Verify(error)));
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
    use crate::core::adapter_utils::has_conflicting_duplicates;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::test_helpers::{FixedClock, epoch, flattened};
    // Only the PayPal vector sets a clock, and that test is `paypal`-gated;
    // importing this unconditionally made `--features tower` (no `paypal`)
    // warn, and no CI job built that combination (issue #335).
    #[cfg(feature = "paypal")]
    use crate::test_helpers::clocked_at;
    use ::http_body_util::Full;
    use ::tower::ServiceExt;
    use futures_executor::block_on;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// A Contentful delivery whose `x-contentful-signed-headers` list names
    /// `content-type`, `x-contentful-timestamp`, and `x-contentful-topic` —
    /// the set Contentful's own signer emits. Locally constructed over the
    /// documented `[method, path, headers, body].join('\n')` construction
    /// (`spec.md` §3, Contentful row; Contentful publishes no frozen vector);
    /// see `src/providers/contentful.rs` for the full test-vector provenance.
    const CONTENTFUL_SECRET: &str =
        "c4a1f2b8d3e95a7f0b6c1d8e4f2a9b3c7d0e5f1a8b4c6d2e9f3a7b1c5d8e2f60";
    const CONTENTFUL_BODY: &[u8] = br#"{"sys":{"type":"Entry"}}"#;
    const CONTENTFUL_TIMESTAMP: &str = "1704391525000";
    const CONTENTFUL_UNIX: u64 = 1_704_391_525;
    const CONTENTFUL_SIGNATURE: &str =
        "f1562694dd6b6582839a8fbe7ad9881e5c1feb68d3206be9b49385f7c080f1d4";

    /// Twilio's documented worked example
    /// (<https://www.twilio.com/docs/usage/security#validating-requests>) as a
    /// delivery the layer receives: Auth Token `12345`, the configured webhook
    /// URL, and the five documented fields as the form body Twilio POSTs for
    /// them — `+` percent-escaped, since a bare `+` in a form body is a space.
    const TWILIO_TOKEN: &str = "12345";
    const TWILIO_URL: &str = "https://example.com/myapp.php?foo=1&bar=2";
    const TWILIO_CALL_BODY: &str = "CallSid=CA1234567890ABCDE&To=%2B18005551212\
                                    &From=%2B14158675310&Caller=%2B14158675310&Digits=1234";
    const TWILIO_CALL_SIGNATURE: &str = "L/OH5YylLD5NRKLltdqwSvS0BnU=";
    /// A second, *different* delivery over the same URL — the one that could
    /// never be configured on a layer. Locally constructed with Twilio's
    /// documented recipe (`printf '%s' \
    /// 'https://example.com/myapp.php?foo=1&bar=2Bodyhello' | openssl dgst
    /// -sha1 -hmac '12345' -binary | base64`).
    const TWILIO_MESSAGE_BODY: &str = "Body=hello";
    const TWILIO_MESSAGE_SIGNATURE: &str = "auPCBlqYuOXiaJO3vsvFsrY0XQU=";

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

    /// A body that hands out one data frame per poll and counts the frames it
    /// has produced, so a test can prove *how much of the request was read*
    /// rather than only what the response ended up being.
    ///
    /// A single-frame `Full` body cannot show that: whether the adapter
    /// buffered all of it or stopped at the limit, it saw the same one frame.
    /// Counting frames is what distinguishes "bounded while reading" from
    /// "checked after buffering" (issue #368).
    struct CountedBody {
        chunks: std::vec::IntoIter<Bytes>,
        yielded: Arc<AtomicUsize>,
    }

    impl CountedBody {
        /// A body delivering exactly `chunks` frames, plus the counter of how
        /// many of them have been handed out.
        fn of_chunks(chunks: &[&[u8]]) -> (Self, Arc<AtomicUsize>) {
            let yielded = Arc::new(AtomicUsize::new(0));
            let body = Self {
                chunks: chunks
                    .iter()
                    .map(|chunk| Bytes::copy_from_slice(chunk))
                    .collect::<Vec<_>>()
                    .into_iter(),
                yielded: Arc::clone(&yielded),
            };
            (body, yielded)
        }

        /// A body of `count` frames of `chunk_len` bytes each — the chunked
        /// shape the pre-buffer `Content-Length` guard cannot see, and the one
        /// an attacker would use to make the adapter buffer without declaring
        /// a length.
        fn oversized(count: usize, chunk_len: usize) -> (Self, Arc<AtomicUsize>) {
            let chunk = vec![b'x'; chunk_len];
            let chunks: Vec<&[u8]> = (0..count).map(|_| chunk.as_slice()).collect();
            Self::of_chunks(&chunks)
        }
    }

    impl ::http_body::Body for CountedBody {
        type Data = Bytes;
        type Error = core::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<::http_body::Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            Poll::Ready(this.chunks.next().map(|chunk| {
                this.yielded.fetch_add(1, Ordering::SeqCst);
                Ok(::http_body::Frame::data(chunk))
            }))
        }
    }

    /// A request carrying `chunks` as its body — with **no** declared length,
    /// so the pre-buffer guard cannot reject it and only what the adapter does
    /// while reading stands between it and the inner service.
    fn chunked_request(body: CountedBody) -> Request<CountedBody> {
        Request::builder()
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .body(body)
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
    fn svix_header_names_verify_and_conflicting_duplicate_is_rejected() {
        // Svix-hosted senders deliver under the Svix-branded `svix-*` header
        // names (Svix's docs state they are aliases of the spec's `webhook-*`
        // names with identical values). Those names must verify end-to-end
        // through the layer, and the ambiguity scan must cover them too: with
        // a duplicate `svix-id` carrying a forged value the request must be
        // rejected even though the signature below is valid over the *first*
        // id and the clock is pinned to the vector timestamp.
        let build = |with_forged_dup: bool| {
            let mut builder = Request::builder()
                .header("svix-id", STANDARD_WEBHOOKS_ID)
                .header("svix-timestamp", STANDARD_WEBHOOKS_TIMESTAMP.to_string())
                .header(
                    "svix-signature",
                    format!("v1,{STANDARD_WEBHOOKS_SIGNATURE}"),
                );
            if with_forged_dup {
                builder = builder.header("svix-id", "msg_forged");
            }
            builder
                .body(TestBody::new(Bytes::from_static(STANDARD_WEBHOOKS_BODY)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"))
        };
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
                .clone()
                .oneshot(build(false))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
            let response = svc
                .oneshot(build(true))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn contentful_dynamically_named_header_ambiguity_is_rejected() {
        // Contentful's `x-contentful-signed-headers` is self-describing: the
        // headers it names are folded into the canonical string, so the
        // ambiguity scan has to follow the list into the request rather than
        // stopping at the three fixed headers. The signature below is valid
        // over the *first* `content-type` and the clock is pinned to the
        // vector's timestamp, so a 400 can only come from the ambiguity check.
        let build = |extra_content_type: Option<&'static str>| {
            let mut builder = Request::builder()
                .header("x-contentful-signature", CONTENTFUL_SIGNATURE)
                .header(
                    "x-contentful-signed-headers",
                    "content-type,x-contentful-timestamp,x-contentful-topic",
                )
                .header("x-contentful-timestamp", CONTENTFUL_TIMESTAMP)
                .header("content-type", "application/json")
                .header("x-contentful-topic", "ContentManagement.Entry.publish");
            if let Some(value) = extra_content_type {
                builder = builder.header("content-type", value);
            }
            builder
                .body(TestBody::new(Bytes::from_static(CONTENTFUL_BODY)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"))
        };
        let svc = VerifyLayer::with_options(
            Provider::Contentful,
            Secret::new(CONTENTFUL_SECRET),
            VerifyOptions {
                request_method: Some("POST".to_string()),
                request_url: Some("https://example.com/webhooks/content-management".to_string()),
                clock: Some(Arc::new(FixedClock(epoch(CONTENTFUL_UNIX)))),
                ..VerifyOptions::default()
            },
        )
        .layer(EchoLen);

        block_on(async {
            // Baseline: the delivery verifies, so the vector and the pinned
            // clock are sound and rejection below is attributable to the
            // duplicate alone.
            let response = svc
                .clone()
                .oneshot(build(None))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);

            // A conflicting duplicate of a header the list names is ambiguous
            // and must be rejected before any signature work.
            let response = svc
                .clone()
                .oneshot(build(Some("text/plain")))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // An *identical* repeat is not ambiguous and still verifies.
            let response = svc
                .oneshot(build(Some("application/json")))
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

    // --- secret rotation through the adapter (issue #259) -------------------

    /// The primary key of a rotation layer. Deliberately *not* the secret that
    /// signed [`GITHUB_SIGNATURE`], so the vector above can only verify when a
    /// fallback is reached.
    const ROTATION_PRIMARY_SECRET: &str = "the new secret, not the one that signed this";

    /// Any second secret that is still not the one that signed the vector, so
    /// a ring built from these two cannot verify it.
    const ROTATION_OTHER_SECRET: &str = "an unrelated older secret";

    /// A rotation layer whose primary is [`ROTATION_PRIMARY_SECRET`].
    fn rotating_service(
        fallbacks: impl IntoIterator<Item = Secret>,
    ) -> VerifyMiddleware<EchoLen, Bytes> {
        VerifyLayer::new(Provider::GitHub, Secret::new(ROTATION_PRIMARY_SECRET))
            .with_fallback_secrets(fallbacks)
            .layer(EchoLen)
    }

    #[test]
    fn a_delivery_signed_by_a_fallback_key_reaches_the_inner_service() {
        // The bug: with a single `Arc<Secret>` there was no way to configure a
        // second key, so every delivery signed by the not-yet-retired key was
        // a 401 and the only workaround was dropping out of the layer.
        block_on(async {
            let svc =
                rotating_service([Secret::new(GITHUB_SECRET)]).oneshot(github_request(GITHUB_BODY));
            let response = svc
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().into_inner().unwrap_or_default(),
                Bytes::from_static(b"13"),
                "the verified bytes still reach the inner service byte-for-byte"
            );
        });
    }

    #[test]
    fn a_delivery_signed_by_the_primary_key_still_verifies_with_fallbacks_configured() {
        // Fallbacks are additive: adding one must not shadow the primary.
        block_on(async {
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_fallback_secrets([Secret::new(ROTATION_OTHER_SECRET)])
                .layer(EchoLen)
                .oneshot(github_request(GITHUB_BODY));
            let response = svc
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn a_delivery_matching_no_key_in_the_ring_is_unauthorized() {
        // The security-relevant half: a rotation list must not become a way to
        // accept *more* than the keys configured in it.
        block_on(async {
            let svc = rotating_service([Secret::new(ROTATION_OTHER_SECRET)])
                .oneshot(github_request(GITHUB_BODY));
            let response = svc
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        });
    }

    #[test]
    fn an_unusable_key_in_the_ring_is_skipped_rather_than_aborting_the_search() {
        // `spec.md` §2.1: an empty/whitespace-only/NUL-only key is unusable for
        // that attempt only, so a garbled entry in a rotation list must not
        // take the whole layer down with a 500.
        for unusable in ["", "   ", "\0\0\0"] {
            block_on(async {
                let svc = rotating_service([Secret::new(unusable), Secret::new(GITHUB_SECRET)])
                    .oneshot(github_request(GITHUB_BODY));
                let response = svc.await.unwrap_or_else(|error| {
                    panic!("middleware should respond, not error: {error}")
                });
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "an unusable key must be skipped, not reported: {unusable:?}"
                );
            });
        }
    }

    #[test]
    fn a_ring_of_only_unusable_keys_is_operator_misconfiguration() {
        // Nothing usable at all: `InvalidSecret` → 500, so a broken key
        // configuration is never disguised as a forgery.
        block_on(async {
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(""))
                .with_fallback_secrets([Secret::new(" \t ")])
                .layer(EchoLen)
                .oneshot(github_request(GITHUB_BODY));
            let response = svc
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        });
    }

    #[test]
    fn a_ring_with_no_fallbacks_behaves_exactly_as_before() {
        // The additive-promise check: an empty fallback list is a single-key
        // ring, so the layer must verify the documented vector and reject a
        // tampered one — the same two answers it has always given.
        block_on(async {
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_fallback_secrets([])
                .layer(EchoLen)
                .oneshot(github_request(GITHUB_BODY));
            let response = svc
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);

            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_fallback_secrets([])
                .layer(EchoLen)
                .oneshot(github_request(b"Hello, World?"));
            let response = svc
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
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
            timestamp_unit: crate::TimestampUnit::Seconds,
            encoding: crate::Encoding::Hex,
            prefix: Some("sha256="),
            signed_headers: &[],
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
            timestamp_unit: crate::TimestampUnit::Seconds,
            encoding: crate::Encoding::Hex,
            prefix: Some("sha256="),
            signed_headers: &[],
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
    fn a_declared_extra_signed_header_is_dup_checked_too() {
        // Issue #395. `CustomScheme::signed_headers` is how a scheme brings a
        // header its `signed_string` reads into the `spec.md` §4.4 scan. The
        // closure below signs the body only, so the declaration is the sole
        // difference between the three deliveries — which is exactly what the
        // scan keys on: declared → duplicate rejected, undeclared → the
        // documented residual, still verified.
        //
        // HMAC-SHA256 hex of the body with key "k":
        // printf 'Hello, World!' | openssl dgst -sha256 -hmac "k"
        const DIGEST: &str = "11316937114e6970aa59bd5326a6f38dd525f4ade64670e402bff41e2f7c4071";
        let scheme = crate::CustomScheme {
            hash: crate::HashAlg::Sha256,
            signature_header: "X-My-Sig",
            timestamp_header: None,
            timestamp_unit: crate::TimestampUnit::Seconds,
            encoding: crate::Encoding::Hex,
            prefix: Some("sha256="),
            signed_headers: &["X-My-Nonce"],
            signed_string: |_headers, body| body.to_vec(),
        };
        let build = |extra: &[(&str, &str)]| {
            let mut builder = Request::builder().header("X-My-Sig", format!("sha256={DIGEST}"));
            for (name, value) in extra {
                builder = builder.header(*name, *value);
            }
            builder
                .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"))
        };

        // A conflicting duplicate of the *declared* extra header is a 400 —
        // the scan reaches it through `signed_headers`, not only through the
        // signature/timestamp pair.
        block_on(async {
            let svc = VerifyLayer::new(Provider::Custom(scheme), Secret::new("k")).layer(EchoLen);
            let response = svc
                .oneshot(build(&[("x-my-nonce", "one"), ("X-My-Nonce", "two")]))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });

        // One value for the same declared header: unambiguous, verifies.
        block_on(async {
            let svc = VerifyLayer::new(Provider::Custom(scheme), Secret::new("k")).layer(EchoLen);
            let response = svc
                .oneshot(build(&[("X-My-Nonce", "one")]))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });

        // The documented residual: a duplicate of a header the scheme did *not*
        // declare is invisible to the scan, so the delivery verifies. The
        // declaration is what closes this door.
        block_on(async {
            let svc = VerifyLayer::new(Provider::Custom(scheme), Secret::new("k")).layer(EchoLen);
            let response = svc
                .oneshot(build(&[("x-unrelated", "one"), ("X-Unrelated", "two")]))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn twilio_deliveries_verify_with_only_the_url_configured() {
        // Issue #363. `VerifyOptions::form_params` is the *body*, so before the
        // field list was decoded per request this layer could not verify Twilio
        // at all: unset, every delivery failed closed as `MissingContext` (500);
        // set, the layer pinned one delivery's field set and rejected the rest.
        // Both deliveries below go through the same configured layer, which is
        // the property that is missing otherwise.
        let options = VerifyOptions::default().with_request_url(TWILIO_URL);
        let svc = VerifyLayer::with_options(Provider::Twilio, Secret::new(TWILIO_TOKEN), options)
            .layer(EchoLen);
        block_on(async {
            for (body, signature) in [
                (TWILIO_CALL_BODY, TWILIO_CALL_SIGNATURE),
                (TWILIO_MESSAGE_BODY, TWILIO_MESSAGE_SIGNATURE),
            ] {
                let request = Request::builder()
                    .header("X-Twilio-Signature", signature)
                    .body(TestBody::new(Bytes::from(body.to_string())))
                    .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
                let response = svc
                    .clone()
                    .oneshot(request)
                    .await
                    .unwrap_or_else(|error| panic!("{body} should verify: {error}"));
                assert_eq!(response.status(), StatusCode::OK, "body {body}");
            }
        });
    }

    #[test]
    fn a_twilio_delivery_whose_body_was_changed_in_transit_is_unauthorized() {
        // The per-request field list must still be checked, not merely parsed:
        // one byte of a signed field changed after signing, signature and URL
        // untouched.
        let options = VerifyOptions::default().with_request_url(TWILIO_URL);
        let svc = VerifyLayer::with_options(Provider::Twilio, Secret::new(TWILIO_TOKEN), options)
            .layer(EchoLen);
        let request = Request::builder()
            .header("X-Twilio-Signature", TWILIO_MESSAGE_SIGNATURE)
            .body(TestBody::new(Bytes::from(
                TWILIO_MESSAGE_BODY.replace("hello", "HELLO"),
            )))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
        assert!(!has_conflicting_duplicates(&headers, "X-Hub-Signature-256"));
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
        assert!(has_conflicting_duplicates(&headers, "X-Hub-Signature-256"));
    }

    #[test]
    fn unparseable_header_name_fails_closed_as_ambiguous() {
        // A header-name string the http crate refuses to parse (embedded
        // whitespace) must fail closed as "ambiguous" per §4.4 — the parse-
        // error arm exists precisely so attacker-supplied garbage can never
        // turn into a permissive lookup.
        let headers = ::http::HeaderMap::new();
        assert!(has_conflicting_duplicates(
            &headers,
            "x-hub-signature-256 invalid"
        ));
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let layer = VerifyLayer::<Bytes>::with_options(
            Provider::GitHub,
            Secret::new("super-secret-hmac-key"),
            crate::VerifyOptions::default().with_request_url("https://internal.example/hook"),
        )
        .with_fallback_secrets([Secret::new("previous-secret-hmac-key")]);
        let debug = format!("{layer:?}");
        assert!(!debug.contains("super-secret-hmac-key"));
        assert!(
            !debug.contains("previous-secret-hmac-key"),
            "a rotation key must not render any more than the primary: {debug}"
        );
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
    fn declared_oversized_content_length_rejected_before_buffering() {
        // The declared length exceeds the limit even though the actual body is
        // small and its signature is valid: the pre-buffer Content-Length
        // guard must reject with 413, proving no body bytes were read or
        // buffered and the inner service never ran.
        block_on(async {
            let request = Request::builder()
                .header("x-hub-signature-256", GITHUB_SIGNATURE)
                .header("content-length", "1000000")
                .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(10)
                .layer(EchoLen);
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        });
    }

    #[test]
    fn declared_content_length_at_or_below_limit_buffers_and_verifies() {
        // A declared length within the limit still reaches the buffered
        // verification path byte-for-byte.
        block_on(async {
            let request = Request::builder()
                .header("x-hub-signature-256", GITHUB_SIGNATURE)
                .header("content-length", "13")
                .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(1024)
                .layer(EchoLen);
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().into_inner().unwrap_or_default(),
                Bytes::from_static(b"13")
            );
        });
    }

    #[test]
    fn unparseable_declared_content_length_falls_through_to_the_body_limit() {
        // A non-numeric Content-Length cannot drive the pre-buffer guard; the
        // request must still be processed (and, if within limit, verify).
        block_on(async {
            let request = Request::builder()
                .header("x-hub-signature-256", GITHUB_SIGNATURE)
                .header(
                    "content-length",
                    ::http::HeaderValue::from_bytes(b"not-a-number")
                        .unwrap_or_else(|_| unreachable!("visible ASCII header value")),
                )
                .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
                .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(1024)
                .layer(EchoLen);
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn oversized_chunked_body_is_stopped_before_it_is_fully_read() {
        // The point of the streaming limit (issue #368): a body sent without a
        // `Content-Length` — the shape the pre-buffer guard cannot see — is
        // read only until it exceeds the limit. 100 frames of 1 KiB are 100
        // KiB, and the limit is 2 KiB, so an adapter that buffered the request
        // first would have taken all 100 frames before answering 413 at all.
        block_on(async {
            let (body, yielded) = CountedBody::oversized(100, 1024);
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(2 * 1024)
                .layer(EchoLen);
            let response = svc
                .oneshot(chunked_request(body))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(
                response.into_body().into_inner().unwrap_or_default(),
                Bytes::new()
            );
            let read = yielded.load(Ordering::SeqCst);
            assert!(
                read <= 3,
                "the read must stop at the limit (2 frames fit, the third trips it), \
                 but it took {read} of 100 frames — the body was buffered before the limit \
                 was applied"
            );
        });
    }

    #[test]
    fn chunked_body_within_the_limit_is_read_whole_and_verifies() {
        // The other half of the same contract, and the reason the streaming
        // limit is safe: `Limited` never truncates a body that fits. GITHUB_BODY
        // is 13 bytes, delivered here as three frames with no declared length,
        // and it must reach the inner service byte-for-byte.
        block_on(async {
            let (body, yielded) = CountedBody::of_chunks(&[b"Hello", b", ", b"World!"]);
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(1024)
                .layer(EchoLen);
            let response = svc
                .oneshot(chunked_request(body))
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().into_inner().unwrap_or_default(),
                Bytes::from_static(b"13")
            );
            assert_eq!(yielded.load(Ordering::SeqCst), 3);
        });
    }

    #[test]
    fn chunked_body_exactly_at_the_limit_is_read_whole() {
        // The boundary: a body whose total length equals the limit is not an
        // oversize body, so it must still be buffered whole and verified.
        block_on(async {
            let (body, yielded) = CountedBody::oversized(13, 1);
            let svc = VerifyLayer::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .with_max_body_size(13)
                .layer(EchoLen);
            // No valid signature over this body, so it cannot reach 200 — the
            // rejection is what proves the bytes were collected rather than
            // refused at the limit.
            let response = svc
                .oneshot(chunked_request(body))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(yielded.load(Ordering::SeqCst), 13);
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

    // --- on_rejection observation hook (issue #379) ---------------------------

    /// Collects what an [`on_rejection`](VerifyLayer::on_rejection) hook saw.
    ///
    /// The hook runs inline on the request path, so it has to be
    /// `Send + Sync + 'static`; this hands it somewhere to put the value.
    #[derive(Clone, Default)]
    struct Observed(std::sync::Arc<std::sync::Mutex<Vec<Rejection>>>);

    impl Observed {
        fn new() -> Self {
            Self::default()
        }

        /// The callback to hand to `on_rejection`.
        fn hook(&self) -> impl Fn(&Rejection) + Send + Sync + 'static {
            let seen = self.0.clone();
            move |rejection| {
                if let Ok(mut seen) = seen.lock() {
                    seen.push(*rejection);
                }
            }
        }

        /// A `GitHub` layer signing-keyed by `secret`, wired to this recorder.
        fn layer(&self, secret: &str) -> VerifyLayer<Bytes> {
            VerifyLayer::<Bytes>::new(Provider::GitHub, Secret::new(secret))
                .on_rejection(self.hook())
        }

        fn get(&self) -> Vec<Rejection> {
            self.0
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_else(|_| unreachable!("nothing else holds the lock"))
        }
    }

    #[test]
    fn the_hook_sees_the_structured_error_behind_each_collapsed_status() {
        // The point of the hook (issue #379): the status code cannot separate
        // these three classes, so a page-on-misconfiguration or per-class metric
        // keyed off it could not. The error itself can.
        let observed = Observed::new();
        let svc = observed.layer(GITHUB_SECRET).layer(EchoLen);
        // Operator misconfiguration, which must never read as an attack.
        let misconfigured = observed.layer("\0\0").layer(EchoLen);

        // 400 row — no signature header at all.
        let no_signature = Request::builder()
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("no headers to misbuild"));
        // 401 row — correctly spelled header, well-formed digest, wrong one.
        let forged = Request::builder()
            .header("X-Hub-Signature-256", format!("sha256={}", "0".repeat(64)))
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));

        block_on(async {
            let response = svc
                .clone()
                .oneshot(no_signature)
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let response =
                svc.clone().oneshot(forged).await.unwrap_or_else(|error| {
                    panic!("middleware should respond, not error: {error}")
                });
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            let response = misconfigured
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        });

        let seen = observed.get();
        assert_eq!(
            seen.len(),
            3,
            "one hook call per rejected request: {seen:?}"
        );
        assert_eq!(
            seen[0].verify_error(),
            Some(&VerifyError::MissingHeader {
                header: "X-Hub-Signature-256"
            })
        );
        assert_eq!(seen[0].status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            seen[1].verify_error(),
            Some(&VerifyError::SignatureMismatch)
        );
        assert_eq!(seen[1].status(), StatusCode::UNAUTHORIZED);
        assert!(matches!(
            seen[2].verify_error(),
            Some(VerifyError::InvalidSecret { .. })
        ));
        assert_eq!(seen[2].status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn the_hook_stays_quiet_when_a_delivery_verifies() {
        // A hook that cannot distinguish rejection from success is useless as a
        // counter: the happy path must produce no call at all.
        let observed = Observed::new();
        let svc = observed.layer(GITHUB_SECRET).layer(EchoLen);
        block_on(async {
            let response = svc
                .clone()
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
            let response = svc
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
        });
        assert!(
            observed.get().is_empty(),
            "a verified request is not a rejection: {:?}",
            observed.get()
        );
    }

    #[test]
    fn the_hook_sees_both_body_too_large_paths() {
        // `413` is not a `VerifyError`, so a hook typed only for verification
        // outcomes would silently miss it — and `413` is precisely the class
        // an operator hardens against. Both ways into it must report: the
        // pre-buffer `Content-Length` guard and the streaming limit.
        let observed = Observed::new();
        let svc = observed
            .layer("valid")
            .with_max_body_size(2 * 1024)
            .layer(EchoLen);

        let declared_oversize = Request::builder()
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .header("content-length", "1000000")
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));

        block_on(async {
            let response = svc
                .clone()
                .oneshot(declared_oversize)
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

            // The streaming path: no declared length, so only the read can
            // catch it.
            let (body, _yielded) = CountedBody::oversized(100, 1024);
            let response = svc
                .oneshot(chunked_request(body))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        });

        let seen = observed.get();
        assert_eq!(
            seen,
            vec![Rejection::BodyTooLarge, Rejection::BodyTooLarge],
            "both `413` paths report, once each"
        );
        // No signature work happened, so there is no `VerifyError` to report —
        // the same answer actix's `verify_error()` gives for its `413` row.
        assert!(seen.iter().all(|r| r.verify_error().is_none()));
        assert!(
            seen.iter()
                .all(|r| r.status() == StatusCode::PAYLOAD_TOO_LARGE),
            "the hook's status and the response's must agree"
        );
    }

    #[test]
    fn the_hook_sees_the_ambiguity_rejection_before_any_signature_work() {
        // The `400` the ambiguity scan raises is a `VerifyError` like any other
        // and carries a fixed reason (`spec.md` §4.4), so a caller keying off
        // the class can tell it from a parse failure of the same status.
        let observed = Observed::new();
        let svc = observed.layer(GITHUB_SECRET).layer(EchoLen);
        let request = Request::builder()
            .header("X-Hub-Signature-256", GITHUB_SIGNATURE)
            .header(
                "x-hub-signature-256",
                "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            )
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("static parts build a valid request"));
        block_on(async {
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
        assert_eq!(
            observed.get(),
            vec![Rejection::Verify(VerifyError::MalformedHeader {
                header: "X-Hub-Signature-256",
                reason: VerifyError::AMBIGUOUS_HEADER_REASON,
            })]
        );
    }

    #[test]
    fn the_hook_is_shared_by_every_service_a_layer_builds() {
        // `Layer::layer` takes `&self`, so a tower runner routinely clones one
        // layer into many services. The hook lives in the shared `Config`, so a
        // clone cannot lose it — the alternative would be observers silently
        // attached to only some of a process's routes.
        let observed = Observed::new();
        let layer = observed.layer(GITHUB_SECRET);
        let first = layer.clone().layer(EchoLen);
        let second = layer.clone().layer(EchoLen);
        block_on(async {
            let response = first
                .clone()
                .oneshot(github_request(b"Hello, World?"))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let response = second
                .oneshot(github_request(b"Hello, World?"))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        });
        assert_eq!(observed.get().len(), 2, "both services reported");
    }

    #[test]
    fn a_layer_without_a_hook_behaves_exactly_as_before() {
        // The additive-promise check: `on_rejection` unset is the configuration
        // that has always existed — same status codes, same empty bodies.
        block_on(async {
            let svc = VerifyLayer::<Bytes>::new(Provider::GitHub, Secret::new(GITHUB_SECRET))
                .layer(EchoLen);
            let response = svc
                .clone()
                .oneshot(github_request(GITHUB_BODY))
                .await
                .unwrap_or_else(|error| panic!("verification should pass: {error}"));
            assert_eq!(response.status(), StatusCode::OK);
            let response = svc
                .oneshot(github_request(b"Hello, World?"))
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(
                response
                    .into_body()
                    .into_inner()
                    .unwrap_or_default()
                    .is_empty()
            );
        });
    }

    #[test]
    fn a_rejection_status_never_carries_detail_over_the_wire() {
        // The hook is server-side only: the client's answer stays an empty
        // body, so a hook cannot become a channel that tells a caller whether
        // its secret, its header name, or its provider configuration is right.
        let observed = Observed::new();
        let svc = observed.layer(GITHUB_SECRET).layer(EchoLen);
        let request = Request::builder()
            .body(TestBody::new(Bytes::from_static(GITHUB_BODY)))
            .unwrap_or_else(|_| unreachable!("no headers to misbuild"));
        block_on(async {
            let response = svc
                .oneshot(request)
                .await
                .unwrap_or_else(|error| panic!("middleware should respond, not error: {error}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = response.into_body().into_inner().unwrap_or_default();
            assert!(body.is_empty(), "rejection body leaked: {body:?}");
        });
        // ...while the same rejection is fully available server-side.
        assert_eq!(observed.get().len(), 1);
    }

    /// The module's "Status codes" section promises that the distinguishing
    /// detail "belongs in server-side logging keyed off the structured
    /// `VerifyError`" — a promise the API did not deliver until
    /// `on_rejection` (issue #379), and which a future change could silently
    /// un-deliver by removing the pointer. Both the module docs and the README
    /// have to keep naming the hook; the README guard reads it for the same
    /// reason it reads its own paragraph back.
    #[test]
    fn the_docs_point_at_the_hook_for_the_logging_contract() {
        const SOURCE: &str = include_str!("tower.rs");
        const README: &str = include_str!("../README.md");

        assert!(
            flattened(
                &SOURCE[..SOURCE
                    .find("/// Boxed error type")
                    .unwrap_or_else(|| unreachable!(
                        "the module docs must still precede the first item"
                    ))]
            )
            .contains("on_rejection"),
            "the module docs promise server-side logging keyed off the structured \
             VerifyError, so they must name the hook that makes it possible: the \
             tower adapter has no extractor to hand the error to afterwards"
        );
        assert!(
            README.contains("on_rejection"),
            "README.md must point a tower/axum user at `on_rejection` too — it \
             otherwise promised logging keyed off the structured `VerifyError` \
             that this adapter cannot deliver"
        );
    }

    /// `VerifyLayer`'s *type* doc is the one docs.rs renders for the type, and
    /// it is the page an operator actually reads — the builder method's doc is
    /// one scroll further down. It had drifted: it still claimed the limit
    /// "bounds the signature work, not the buffering itself", the pre-#368
    /// statement, while the implementation reads through a streaming `Limited`
    /// that bounds the buffering too. `oversized_chunked_body_is_stopped_before_it_is_fully_read`
    /// pins the behavior; this pins the doc to it, so the next change to the read
    /// path cannot leave the type page promising a weaker DoS bound than the code
    /// provides (issue #372).
    #[test]
    fn verify_layer_type_doc_promises_the_streaming_limit() {
        const SOURCE: &str = include_str!("tower.rs");

        // The struct's own doc block: from the first line of the `///` comment
        // above it back to the end of the previous item.
        let decl = SOURCE
            .find("pub struct VerifyLayer")
            .unwrap_or_else(|| unreachable!("VerifyLayer must still be declared"));
        let doc_start = SOURCE[..decl]
            .rfind("/// A [`tower_layer::Layer`]")
            .unwrap_or_else(|| unreachable!("VerifyLayer must keep a doc comment above it"));
        let doc = flattened(&SOURCE[doc_start..decl]);

        assert!(
            doc.contains("under the limit itself"),
            "VerifyLayer's doc must state that a request with no usable declared \
             length is read under the limit, which is what the streaming `Limited` \
             does: {doc}"
        );
        assert!(
            doc.contains("Transfer-Encoding: chunked"),
            "VerifyLayer's doc must name the chunked case — it is the only body shape \
             the pre-buffer 413 guard cannot see, and the reason the streaming limit \
             exists: {doc}"
        );
        assert!(
            !doc.contains("not the buffering"),
            "VerifyLayer's doc must not claim the limit leaves buffering unbounded; \
             that was the pre-#368 statement and the opposite of what the code does"
        );
    }
}
