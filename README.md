# webhook-verify

[![CI](https://github.com/SlopMaster2/webhook-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/SlopMaster2/webhook-verify/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/webhook-verify)](https://crates.io/crates/webhook-verify)
[![docs.rs](https://img.shields.io/docsrs/webhook-verify)](https://docs.rs/webhook-verify)

**One function to verify inbound webhooks from any provider.**

Every backend that accepts webhooks ends up hand-rolling HMAC verification for
Stripe, GitHub, Shopify, Slack, and a dozen other services — and getting subtle
details wrong (raw body vs. re-serialized JSON, non-constant-time comparison,
missing replay protection, provider-specific encoding quirks). `webhook-verify`
is a small, dependency-light, audited-primitive-backed crate that does this
once, correctly, for every major provider, behind a single API.

```rust
use webhook_verify::{verify, Provider, Secret};

let headers: Vec<(String, String)> = vec![
    ("Stripe-Signature".to_string(), "t=1234567890,v1=abc...".to_string()),
];
let raw_body = b"{\"id\": \"evt_test\"}";

let result = verify(
    Provider::Stripe,
    &headers,        // anything implementing HeaderMap
    raw_body,         // &[u8] — MUST be the untouched request body
    &Secret::new("whsec_..."),  // your real webhook signing secret
    Default::default(),
);

match result {
    Ok(()) => { /* trusted: safe to process the event */ }
    Err(e) => { /* reject with 400/401, log e */ }
}
```

That's it. No client SDK to pull in, no per-provider crate to learn, no
hand-copied signing-string logic to get wrong.

## Why this exists

- **The pain is universal.** Nearly every SaaS integrates *outbound* webhooks
  from payment processors, source control, chat platforms, and e-commerce
  tools. Verifying them correctly is small in code size but easy to get
  wrong, and wrong verification is a real security hole (forged
  `payment.succeeded` / `order.created` events).
- **Rust has no incumbent.** Go (`trusthook`) and TypeScript
  (`webhook-signature`, `hookinbox-verify`) both grew "one API, many
  providers" webhook verifiers in the last year. Rust still doesn't have one
  — only heavyweight per-vendor SDKs (`async-stripe`, `shopify-sdk`, ...)
  that happen to include verification as a minor feature, plus a handful of
  single-provider crates.
- **This should be a library, not a tutorial.** Search "verify \[provider\]
  webhook signature" for any provider and you'll find blog posts re-teaching
  the same HMAC recipe. That volume of repeated how-to content is the
  classic signal that the logic belongs in a dependency, not a copy-pasted
  snippet.

## Design principles

1. **Correctness over cleverness.** Every provider implementation is backed
   by test vectors taken from that provider's own documentation where they
   exist, and locally-constructed deterministic vectors over exactly the
   documented signed-string construction where a provider publishes none.
   No provider ships without them.
2. **No custom cryptography.** All primitives come from
   [RustCrypto](https://github.com/RustCrypto) (`hmac`, `sha2`, `sha1`,
   `ed25519-dalek`, `subtle` for constant-time comparison). This crate only
   owns *parsing and orchestration*, never hashing or signature math.
3. **Headless core, thin adapters.** The value is in `verify()`, a pure,
   synchronous, allocation-light function. Framework integration (Axum,
   Actix Web, Tower) is optional sugar behind feature flags, not the point
   of the crate.
4. **Fail closed, explain why.** Errors are structured
   (`VerifyError::{MissingHeader, BadEncoding, SignatureMismatch,
   TimestampOutOfTolerance, UnsupportedProvider, ...}`) so callers can log
   and alert meaningfully instead of getting a bare `false`.
5. **No unbounded scope creep.** This crate verifies signatures. It does not
   deserialize event payloads, manage retries, store idempotency keys, or
   proxy webhooks. Those are separate, composable concerns (and separate
   crates) on purpose.

## Supported providers (target v0.1 matrix)

| Provider | Scheme | Status |
|---|---|---|
| GitHub | HMAC-SHA256, `X-Hub-Signature-256` | ✅ |
| Stripe | HMAC-SHA256 over `timestamp.body`, tolerance window | ✅ |
| Shopify | HMAC-SHA256, base64, `X-Shopify-Hmac-Sha256` | ✅ |
| Slack | HMAC-SHA256 `v0=` scheme, `X-Slack-Signature` + timestamp | ✅ |
| Linear | HMAC-SHA256, `linear-signature` | ✅ |
| Square | HMAC-SHA256 over notification URL + body, base64, `X-Square-HmacSha256-Signature` (needs `VerifyOptions::request_url`) | ✅ |
| Twilio | HMAC-SHA1 over URL + sorted form params, `X-Twilio-Signature` (needs `VerifyOptions::request_url` + `form_params`) | ✅ |
| Discord | Ed25519 (public-key), no shared secret | ✅ |
| PayPal | RSASSA-PKCS1-v1_5 SHA-256 over `transmission_id|time|webhook_id|crc32(body)`, X.509 cert + webhook ID via `VerifyOptions::verifying_material` + `webhook_id` (needs `paypal` feature) | ✅ |
| SendGrid | ECDSA P-256 over `timestamp.body`, public key via `VerifyOptions::verifying_material` (needs `sendgrid` feature) | ✅ |
| Zoom | HMAC-SHA256, `v0=` scheme, `x-zm-signature` + timestamp | ✅ |
| Dropbox | HMAC-SHA256, `X-Dropbox-Signature` | ✅ |
| Standard Webhooks spec (Svix, Clerk, Resend, ...) | HMAC-SHA256, `webhook-signature` (`v1,` base64, rotation list) + replay window | ✅ |
| Custom | User-supplied HMAC scheme via `Provider::Custom(..)` (SHA-256/SHA-1/SHA-512, hex/base64, optional prefix + timestamp replay window) | ✅ |

Some providers ship behind crate features: calling `verify()` on `PayPal`
or `SendGrid` without the corresponding feature compiled in fails closed
with `VerifyError::UnsupportedProvider`. See [`spec.md`](./spec.md) for the
exact signed-string construction, header names, and encoding for each
provider, and the process for adding new ones.

SendGrid verification is compiled only with the crate feature:

```toml
[dependencies]
webhook-verify = { version = "0.1", features = ["sendgrid"] }
```

For `no_std + alloc` targets, keep `default-features = false` together with
`features = ["sendgrid"]`.

PayPal verification is compiled only with the crate feature:

```toml
[dependencies]
webhook-verify = { version = "0.1", features = ["paypal"] }
```

It verifies against the caller-supplied certificate (the crate never fetches
`PayPal-Cert-Url` — see `spec.md` §7) and needs both the webhook
subscription ID and the certificate to be configured:

```rust,ignore
let opts = VerifyOptions::default()
    .with_webhook_id("your-webhook-subscription-id")
    .with_verifying_material(VerifyingKeyMaterial::X509Certificate(cert_pem_bytes.to_vec()));

let result = verify(Provider::PayPal, &headers, raw_body, &Secret::new("unused"), opts);
```

## Secret rotation

During a signing-key rotation window, Stripe and other standard-webhook
providers accept requests signed by either the old or the new key.
`verify_any()` tries each secret in turn and accepts the request if any one
of them verifies:

```rust,ignore
use webhook_verify::{verify_any, Provider, Secret};

let result = verify_any(
    Provider::Stripe,
    &headers,
    raw_body,
    &[Secret::new(new_secret), Secret::new(old_secret)],  // try new first
    Default::default(),
);
```

- A match on **any** key returns `Ok(())`; the request is safe to process.
- Structural errors (`MissingHeader`, `MalformedHeader`, `BadEncoding`,
  `UnsupportedProvider`, `MissingContext`, `TimestampOutOfTolerance`) are
  deterministic across all secrets and return immediately.
- A garbled/undecodable key (`InvalidSecret`) does **not** abort the search —
  a still-healthy key later in the slice can verify. If every key is
  well-formed but wrong, you get `SignatureMismatch`; only when *every* key
  is malformed do you get `InvalidSecret` (an operator-configuration signal,
  not a forgery). Full decision record in `spec.md` §2.1.

## Installation

```toml
[dependencies]
webhook-verify = "0.1"

# verify straight against http::HeaderMap (axum, tower, hyper, ...)
webhook-verify = { version = "0.1", features = ["http"] }

# generic tower middleware (works with axum routers too)
webhook-verify = { version = "0.1", features = ["tower"] }

# actix-web 4 extractor + header bridge
webhook-verify = { version = "0.1", features = ["actix"] }
```

With the `http` feature enabled, any `http::HeaderMap` (from axum, tower, or
hyper requests) implements `HeaderMap` and can be passed to `verify()` directly.

### `no_std` support

The core verification path is `no_std + alloc` compatible (validated against
`wasm32-unknown-unknown`). The `std` feature (on by default) provides the wall
clock used for replay protection and the `std::error::Error` impl. Disable it
for constrained targets:

```toml
# no wall clock; supply your own Clock for timestamped providers
webhook-verify = { version = "0.1", default-features = false }
```

Without `std`, [`Clock::now`] returns unix seconds directly, `SystemClock` is
unavailable, and `VerifyError` does not implement `std::error::Error` — see
`spec.md` §7.

## Framework adapters

### Tower (also Axum)

`webhook-verify::tower::VerifyLayer` is a generic `tower::Layer`. It buffers
the request body as raw bytes, rejects requests whose signature headers arrive
duplicated with conflicting values (`400`, see spec §4.4), verifies with
`verify()`, and forwards the exact buffered bytes downstream — handlers can
then deserialize freely. Verification failures never reach your handler:

| Failure class | Status |
|---|---|
| Body exceeds `max_body_size` limit | `413 Payload Too Large` |
| Missing / malformed signature headers | `400 Bad Request` |
| Signature mismatch / stale timestamp | `401 Unauthorized` |
| Operator misconfiguration | `500 Internal Server Error` |

By default the body is buffered with no size limit. To prevent a malicious
client from streaming an arbitrarily large payload (a memory/CPU amplification
vector), configure an optional maximum body size with
`VerifyLayer::with_max_body_size(bytes)`:

```rust
use webhook_verify::{Provider, Secret};
use webhook_verify::tower::VerifyLayer;

// 2 MiB limit, matching actix-web's default extractor bound.
let layer = VerifyLayer::new(Provider::Stripe, Secret::new("whsec_..."))
    .with_max_body_size(2 * 1024 * 1024);
```

Requests whose body exceeds the limit are rejected with `413 Payload Too
Large` before any signature verification work.

Plain tower stacks receive `Request<Bytes>`; axum users get their own body
type back automatically via type inference:

```rust
use webhook_verify::{Provider, Secret};
use webhook_verify::tower::VerifyLayer;

let layer = VerifyLayer::new(Provider::Stripe, Secret::new("whsec_..."));

// Plain tower: inner service takes http::Request<Bytes>.
// let svc = layer.clone().layer(my_handler_service);

// Axum: same layer, inferred as axum::body::Body.
// Router::new()
//     .route("/webhooks/stripe", post(handle_stripe))
//     .layer(layer);
```

#### Axum

Axum routers are tower services, so `VerifyLayer` is the supported axum
integration — no separate feature or module is needed:

```rust,ignore
use axum::{routing::post, Router};
use webhook_verify::{Provider, Secret};
use webhook_verify::tower::VerifyLayer;

let app = Router::new()
    .route("/webhooks/github", post(handle_github))
    .layer(VerifyLayer::new(Provider::GitHub, Secret::new(secret)));
```

The layer buffers and verifies the raw body before routing, so handlers can
use extractors freely (`Json`, `Bytes`, ...) — the bytes they receive are
already verified.

> ⚠️ **If you bypass the middleware**, verify before any extractor touches the
> body. Extractors run top-down and body-consuming ones (`Json`, `Bytes`,
> `String`) drain the request; once they have run, the original wire bytes are
> gone. Capture the body first (e.g. `Bytes` as your first extractor), call
> `verify()` on those exact bytes with an `http::HeaderMap` (the `http`
> feature), and only then deserialize a copy.

### Actix Web

Enable the `actix` feature and register a `WebhookConfig` on your app; the
`VerifiedBody` extractor then verifies the signature and hands your handler
the exact raw bytes:

```rust,ignore
use actix_web::{App, HttpResponse, web};
use webhook_verify::actix::{VerifiedBody, WebhookConfig};
use webhook_verify::{Provider, Secret};

App::new()
    .app_data(WebhookConfig::new(Provider::GitHub, Secret::new(secret)))
    .route(
        "/webhooks/github",
        web::post().to(|body: VerifiedBody| async move {
            // `body` is the exact wire payload, already verified.
            HttpResponse::Ok().finish()
        }),
    );
```

Because actix-web 4 reads the body only during extraction, `VerifiedBody`
captures it *before* anything else can touch it — do **not** also take
`web::Json<T>` in the same handler (extractors run left-to-right and `Json`
would consume the body first); deserialize from `body`'s exact bytes instead.
Requests whose scheme headers arrive duplicated with conflicting values are
rejected with `400` before verification (spec §4.4). Failure statuses match
the tower table above. A guard is intentionally not provided: guards run
before the body is read, but verification requires those bytes.

> ⚠️ **Raw body required.** All frameworks buffer and re-parse JSON by
> default, which changes byte-for-byte content (key ordering, whitespace).
> The tower adapter and actix extractor capture the exact bytes off the wire
> before anything else touches them; if you call `verify()` directly instead,
> make sure you pass those same untouched bytes (with the `http` feature for
> axum/tower/hyper maps, or the bridge provided by the `actix` feature).

## Security notes

- All signature comparisons use constant-time equality (`subtle::ConstantTimeEq`).
- A dudect-style statistical timing assertion on the comparison step runs in
  CI as a non-blocking informational job (spec §5.7); run it locally with
  `cargo test --release --all-features -- constant_time_comparison --ignored`.
- Timestamp-based replay protection is enabled by default wherever the
  provider supports it (`VerifyOptions::max_age`, default 5 minutes).
- This crate does not log secrets, request bodies, or computed signatures
  under any log level.
- Secrets are wrapped in a `Secret` type that redacts `Debug`/`Display` output.

## Non-goals

- Sending/registering webhooks (that's the provider's own SDK's job).
- Event payload parsing/typing.
- Idempotency / deduplication of already-verified events.
- A hosted or proxying service (this is a plain library).

## Versioning & MSRV

Semantic versioning. New providers are additive (minor version bumps).
Changes to an existing provider's verification logic that could reject
previously-accepted requests are treated as breaking (major version bump),
except where required to fix a genuine security defect, which will be
called out explicitly in the changelog and a security advisory.

MSRV: **1.85** (first Rust release with edition 2024 support), checked in CI.

## Releasing

To publish a new version to crates.io:

1. Bump `version` in `Cargo.toml` (semver rules above) and commit.
2. Build and inspect the exact tarball that crates.io would host:

   ```sh
   cargo package --allow-dirty && cargo publish
   ```

   (`CARGO_REGISTRY_TOKEN` must be set in your crates.io session.)
3. Tag the release commit and push it, which documents the release point
   and gives consumers a stable reference:

   ```sh
   git tag v0.2.0
   git push origin master --tags
   ```

## Contributing

New providers, corrected test vectors, and encoding edge cases are the
highest-value contributions. See [`AGENTS.md`](./AGENTS.md) for the
step-by-step process (used by both human and AI contributors) and
[`spec.md`](./spec.md) for the technical contract each provider
implementation must satisfy.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
