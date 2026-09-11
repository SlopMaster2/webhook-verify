# webhook-verify — Technical Specification

Status: draft v0.1
Audience: contributors and implementers (human or AI agent)

This document defines the contract the crate must satisfy: the public API,
the per-provider signing schemes, error semantics, security requirements,
and the testing bar every provider implementation must clear before merge.

---

## 1. Goals and non-goals

**Goals**

- Verify that an inbound HTTP request genuinely originated from a given
  webhook provider and was not tampered with in transit.
- Provide one consistent API across all supported providers.
- Be correct by construction: every provider backed by vendor-sourced test
  vectors, constant-time comparison, and (where applicable) replay
  protection.
- Be embeddable: no required async runtime, no required web framework, no
  network calls, `no_std + alloc` compatible for the core verification path
  where the underlying crypto crates allow it.

**Non-goals**

- Parsing/deserializing the webhook event payload into typed structs.
- Registering, sending, or replaying webhooks.
- Idempotency / deduplication of events (a signature-verified request can
  still be a legitimate retry — that's a separate concern).
- Acting as a proxy, gateway, or hosted service.

---

## 2. Core API

```rust
pub enum Provider {
    Stripe,
    GitHub,
    Shopify,
    Slack,
    Square,
    Twilio,
    Discord,
    PayPal,
    SendGrid,
    Paddle,
    Linear,
    Notion,
    Zoom,
    Cloudflare,
    Coinbase,
    Dropbox,
    Xero,
    StandardWebhooks,
    Custom(CustomScheme),
}

pub struct Secret(/* redacted */);
impl Secret {
    pub fn new(value: impl Into<String>) -> Self;
}
// Debug/Display for Secret print "Secret(**redacted**)" only.

/// Caller-supplied asymmetric verification material (spec §7).
#[non_exhaustive]
pub enum VerifyingKeyMaterial {
    X509Certificate(Vec<u8>),         // PayPal (shipped, feature `paypal`)
    EcdsaP256PublicKey(Vec<u8>),      // SendGrid (shipped, feature `sendgrid`)
}
// Debug redacts the key/certificate bytes (variant name + byte length only).

pub struct VerifyOptions {  // #[non_exhaustive]: configure via Default + the
                            //   `with_*` builders so new fields stay non-breaking
    /// Maximum allowed age between the signed timestamp and "now",
    /// for providers whose scheme includes a timestamp. `None` disables
    /// the check (not recommended). Default: Some(Duration::from_secs(300)).
    pub max_age: Option<Duration>,
    /// Clock used for "now", injectable for deterministic tests.
    pub clock: Option<Arc<dyn Clock>>,
    /// Full URL of the receiving endpoint, for URL-scoped schemes
    /// (currently Square, Twilio). See §3.
    pub request_url: Option<String>,
    /// Parsed `application/x-www-form-urlencoded` fields, required by
    /// schemes that sign form fields rather than the raw body
    /// (currently Twilio). Pass every field as received; sorting into
    /// signing order happens here. See §3.
    pub form_params: Option<Vec<(String, String)>>,
    /// Asymmetric public-key/certificate material for schemes that verify
    /// against a configured key rather than a shared secret (currently
    /// SendGrid's ECDSA P-256 key, PayPal's X.509 certificate).
    /// Required-but-absent fails closed with `MissingContext`; malformed
    /// material with `InvalidSecret`. This crate never fetches key material
    /// (§7). See §3.
    pub verifying_material: Option<VerifyingKeyMaterial>,
    /// Merchant/webhook-subscription ID required by PayPal's signed-string
    /// construction (`{transmission_id}|{transmission_time}|{webhook_id}|
    /// {crc32}`). The webhook ID does not travel in the request — it is the
    /// subscription ID configured in the PayPal Developer Portal — so the
    /// caller supplies it here. Required-but-absent for `Provider::PayPal`
    /// fails closed with `MissingContext`. No effect on other providers.
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

impl core::str::FromStr for Provider {
    type Err = ProviderParseError;
    // Case-insensitive match on the canonical Display name of each variant
    // ("github", "GitHub", "GITHUB", ...). `custom` is rejected: a
    // CustomScheme requires configuration and must be built directly.
}

pub trait HeaderMap {
    /// Case-insensitive header lookup. Returns the first matching value.
    fn get(&self, name: &str) -> Option<&str>;
}
// Blanket impls provided for the built-in collections (Vec<(String,String)>,
// Vec<(&str,&str)>, fixed-size arrays of (String,String) and (&str,&str),
// borrowed slices of both, BTreeMap<String,String>, HashMap<String,String>),
// unconditionally; the http::HeaderMap impl is provided behind the "http"
// feature flag.

pub fn verify(
    provider: Provider,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: VerifyOptions,
) -> Result<(), VerifyError>;
```

Implementation status (kept in sync with the code — do not let this drift):

- All `Provider` variants ship up front so adding providers later is
  non-breaking. A variant whose implementation is disabled by a crate
  feature flag fails closed: `verify()` returns `UnsupportedProvider` for it
  (currently PayPal/SendGrid without their features).
- `Custom(CustomScheme)` ships per §2.2: declarative hash/encoding/prefix/
  header configuration plus a caller-supplied signed-string function, with
  the same constant-time comparison and fail-closed parsing guarantees as
  built-in providers. When `timestamp_header` is set, replay protection
  applies with the shared symmetric tolerance semantics (`|now - t| <=
  max_age`) used by the built-in timestamped schemes; when it is `None`,
  no clock is consulted (mirroring GitHub/Linear).

### 2.1 `VerifyError`

```rust
#[non_exhaustive]
pub enum VerifyError {
    MissingHeader { header: &'static str },
    MalformedHeader { header: &'static str, reason: &'static str },
    BadEncoding { reason: &'static str },
    SignatureMismatch,
    TimestampOutOfTolerance { skew: Duration, max_age: Duration },
    UnsupportedProvider,
    InvalidSecret { reason: &'static str },
    MissingContext { reason: &'static str },
}
```

Design rules for errors:

- `VerifyError` **never** includes the secret, the raw body, or the computed
  signature in its `Display` output. It may include header *names* and
  numeric skew values.
- `SignatureMismatch` must be returned in exactly the same way regardless of
  *how close* the provided signature was to correct (no early-return that
  could leak timing information about which byte differed).
- Distinguish `MissingHeader` / `MalformedHeader` from `SignatureMismatch`
  in the type system (useful for callers who want to log malformed-request
  noise differently from active-attack signals), but treat both as "reject
  the request" outcomes — never treat a malformed header as "skip
  verification."
- `MissingContext` signals caller misconfiguration (required request context,
  such as Square's notification URL, absent from `VerifyOptions`) rather than
  malformed or forged input. It exists so configuration errors are not
  disguised as `SignatureMismatch` attack signals; the request is still
  rejected.

#### `verify_any` aggregation (decision record, issue #64)

`verify_any()` iterates a slice of secrets during a rotation window and
returns `Ok(())` if any one of them verifies. Its error aggregation rules:

- **Structural errors** (`MissingHeader`, `MalformedHeader`, `BadEncoding`,
  `UnsupportedProvider`, `MissingContext`) are deterministic across all
  secrets — they occur before any secret-dependent work — so `verify_any`
  returns them immediately.
- **`TimestampOutOfTolerance` is only reachable after a signature
  verifies.** Every timestamped provider checks the replay window *after*
  the signature comparison (§3), so this error is surfaced only once some
  secret's signature matches. `verify_any` returns it immediately when
  encountered — a stale timestamp is the provider's own field, so any other
  matching key would reject it identically — but a stale request with **no**
  matching key reports `SignatureMismatch` instead, because replay is never
  reached. Both outcomes reject the request; only the reported variant
  differs.
- **`InvalidSecret` is secret-specific, not deterministic.** A key rejected
  for its own formatting is unusable for the current request, but a later key
  in the slice may still be correct. `verify_any` therefore *continues*
  past an `InvalidSecret` rather than aborting, so a rotation slice with one
  garbled/truncated live key still verifies against the healthy one.
- On total failure, `verify_any` returns `SignatureMismatch` if at least one
  key was well-formed but wrong; it returns the first `InvalidSecret` only
  when *every* key was rejected for its own formatting (an all-garbled
  configuration is an operator error, not a forgery). Returning
  `InvalidSecret` in that case cannot help an attacker — a forged request
  already yields `SignatureMismatch` whenever a usable key exists — and it
  gives operators an honest signal that their key configuration is broken.

`verify_any` is meaningful only for **shared-secret** providers. The
asymmetric providers (PayPal, SendGrid) ignore the `Secret` argument and
verify against `VerifyOptions::verifying_material` (plus `webhook_id` for
PayPal), so every element of the slice behaves identically and `verify_any`
gives them no rotation semantics; it still degrades safely because their
errors are structural (`MissingContext` for absent key material,
`MissingHeader`, ...) and returned immediately. Rotating asymmetric key
material is the caller's job: supply the current key via
`VerifyOptions::verifying_material` and re-verify when it rotates.

### 2.2 `CustomScheme`

For providers not yet built in, or self-hosted/internal webhook senders:

```rust
pub struct CustomScheme {
    pub hash: HashAlg,                 // Sha256 | Sha1 | Sha512
    pub signature_header: &'static str,
    pub timestamp_header: Option<&'static str>,
    pub encoding: Encoding,            // Hex | Base64
    pub prefix: Option<&'static str>,  // e.g. "sha256=" or "v0="
    pub signed_string: fn(&dyn HeaderMap, &[u8]) -> Vec<u8>,
}
```

Construction: `CustomScheme::new(hash, signature_header, encoding,
signed_string)` sets the required fields with `timestamp_header`/`prefix`
left `None`, and the `with_timestamp_header(_)` / `with_prefix(_)` builders
set those optional fields (struct-literal construction also remains
available since the fields are public). The declarative fields participate in
`PartialEq`/`Hash`; `signed_string` is excluded (function pointers have no
meaningful equality).

This lets callers cover a long-tail provider today without waiting on a
crate release, and it's how new built-in providers get prototyped before
being promoted into the `Provider` enum.

---

## 3. Per-provider signing schemes

Each entry below is the normative definition an implementation must match.
Every row must ship with at least one test vector taken from the provider's
own published documentation (linked in code comments) plus at least one
locally-constructed vector covering a boundary case (empty body, unicode
body, multi-value headers, etc.).

### Stripe

- Header: `Stripe-Signature: t=<unix_ts>,v1=<hex_hmac>[,v0=<legacy>]`
- Signed string: `"{t}.{raw_body}"` (literal dot join, UTF-8 bytes)
- Algorithm: HMAC-SHA256, hex-encoded
- Replay protection: compare `t` against `max_age` (Stripe's own SDKs
  default to 5 minutes)
- Multiple `v1=` values may be present during secret rotation; a match on
  *any* is accepted.
- Timestamp validation: `t` must be a pure ASCII-digit unix-seconds value,
  validated through the shared timestamp parser. Sign-prefixed
  (`t=+1700000000`), whitespace-padded, empty, or overflowing values are
  rejected as `MalformedHeader` — the same fail-closed policy every other
  timestamped provider applies (`spec.md` §4.4), regardless of whether a
  signature over the non-canonical string would verify.

### GitHub

- Header: `X-Hub-Signature-256: sha256=<hex_hmac>`
- Signed string: raw body bytes, unmodified
- Algorithm: HMAC-SHA256, hex-encoded
- No built-in timestamp; GitHub does not include replay protection at the
  signature layer. `max_age` has no effect for this provider — document
  this explicitly rather than silently ignoring the option.
- Legacy `X-Hub-Signature` (SHA1) supported only via `CustomScheme` — not a
  default path, since GitHub itself deprecated SHA1.

### Shopify

Source: <https://shopify.dev/docs/apps/build/webhooks/subscribe/https>
(Shopify's HTTPS webhook subscription and verification documentation).

- Header: `X-Shopify-Hmac-Sha256: <base64_hmac>` (lookup is case-insensitive;
  this matches the casing in Shopify's own docs)
- Signed string: raw body bytes, unmodified
- Algorithm: HMAC-SHA256, **base64**-encoded (not hex — a common bug source)
- No timestamp in the signature scheme.
- Test-vector provenance: Shopify's docs describe the scheme but publish no
  concrete test vector, so the implementation is validated against locally
  constructed, deterministic vectors over the documented recipe (base64 of
  the exact construction above). Replace them if Shopify ever publishes
  fixed vectors.

### Dropbox

Source: <https://www.dropbox.com/developers/reference/webhooks> ("Webhooks"
documentation, signature verification guidance and Python example code).

- Header: `X-Dropbox-Signature: <hex_hmac>`
- Signed string: raw body bytes, unmodified
- Algorithm: HMAC-SHA256, hex-encoded
- No timestamp in the signature scheme (`max_age` has no effect).
- Test-vector provenance: Dropbox's docs and Python example code describe the
  construction but publish no byte-exact example signature, so the
  implementation is validated against locally constructed, deterministic
  vectors over exactly the documented construction. Replace them if Dropbox
  ever publishes fixed vectors.

### Linear

Source: <https://developers.linear.app/docs/graphql/working-with-the-graphql-api/webhooks>
(Linear's webhook signature verification documentation).

- Header: `linear-signature: <hex_hmac>`
- Signed string: raw body bytes, unmodified
- Algorithm: HMAC-SHA256, hex-encoded
- No timestamp in the signature scheme.
- Test-vector provenance: Linear's docs describe the construction but publish
  no byte-exact example signature, so the implementation is validated against
  locally constructed, deterministic vectors over exactly the documented
  construction. Replace them if Linear ever publishes fixed vectors.

### Notion

Source: <https://developers.notion.com/reference/webhooks>
(Notion's webhook signature documentation) and the official JS SDK
`@notionhq/client` `verifyWebhookSignature()` helper
(<https://github.com/makenotion/notion-sdk-js/blob/main/src/webhooks.ts>,
introduced v5.23.0; matches the server-side delivery code
`sendWebhookRequest.ts`).

- Header: `X-Notion-Signature: sha256=<hex_hmac>`
- Signed string: raw body bytes, unmodified — Notion's docs warn that
  re-serializing the JSON payload changes the bytes and fails verification
- Algorithm: HMAC-SHA256, hex-encoded, with the subscription's
  `verification_token` as the key (the token from the one-time handshake, not
  the integration's API token)
- The `sha256=` prefix is matched case-sensitively, exactly like GitHub
  (`spec.md` §3); Notion's docs and SDK emit only the literal lowercase form.
- No timestamp in the signature scheme (`max_age` has no effect); Notion
  recommends deduping/replay detection from the payload's own `timestamp`/`id`
  fields, which is outside this crate's scope (payload parsing is a non-goal,
  §1).
- The one-time subscription *handshake* request carries no
  `X-Notion-Signature` header; callers special-case it before calling
  `verify()` (which reports `MissingHeader` for it).
- Test-vector provenance: the docs publish the exact `X-Notion-Signature`
  sample value for the worked-example `verification_token` + handshake body;
  the signature reproduced from that construction (independently with
  `openssl dgst`) matches the documented sample byte-for-byte. Boundary-vector
  bodies are locally constructed over the same documented recipe.

### Slack

- Headers: `X-Slack-Signature: v0=<hex_hmac>`, `X-Slack-Request-Timestamp`
- Signed string: `"v0:{timestamp}:{raw_body}"`
- Algorithm: HMAC-SHA256, hex-encoded
- Replay protection required: Slack explicitly recommends rejecting
  requests where `|now - timestamp| > 300s`.

### Square

Source: <https://developer.squareup.com/docs/webhooks/step3validate> ("Verify
and Validate an Event Notification") and the reference implementations in
Square's official SDKs (e.g. `square-python-sdk`
`square/utils/webhooks_helper.py`, `square-php-sdk` `WebhooksHelper`).

- Header: `x-square-hmacsha256-signature: <base64_hmac>`
- Signed string: `"{notification_url}{raw_body}"` — the webhook subscription's
  notification URL concatenated directly with the raw body, no separator.
  Verification cannot proceed from headers + body + secret alone, so the
  caller supplies the URL via
  [`VerifyOptions::request_url`] (decided API shape; a missing or empty URL
  fails closed with `MissingContext`). The value must be the exact
  dashboard-configured constant — reconstructing it from request headers
  behind a proxy is the classic failure mode.
- Secret is the subscription's signature key used **as its UTF-8 bytes**.
  Provenance note: earlier drafts of this spec said the key arrives
  hex-encoded and must be decoded first. That matched Square's retired key
  format but not any current official source: every current SDK hashes the key
  string as UTF-8 directly, and the docs' own example key (`asdf1234`) is not
  valid hexadecimal. An empty key fails closed with `InvalidSecret`.
- Algorithm: HMAC-SHA256 over the signed string, base64-encoded
- No timestamp in the signature scheme (`max_age` has no effect).

### Twilio

Source: <https://www.twilio.com/docs/usage/security#validating-requests>
("Validating requests are coming from Twilio", including the docs' own
worked example) and the reference implementations in Twilio's official SDKs
(e.g. `twilio-python`'s `twilio/request_validator.py`).

- Header: `X-Twilio-Signature: <base64_hmac_sha1>`
- Signed string: the full request URL (protocol through query string,
  exactly as configured with Twilio), followed by the `POST` form fields
  sorted alphabetically by name in Unix-style byte order, each field's name
  and value concatenated directly to the string with no delimiter.
- Algorithm: HMAC-SHA1, base64-encoded. HMAC construction is not affected by
  SHA-1's collision attacks given a secret key, which is why the scheme
  remains SHA-1.
- Key: the account's Auth Token as its UTF-8 bytes; an empty token fails
  closed with `InvalidSecret`.
- Not a raw-body scheme: the signature covers the parsed form fields, not
  the body bytes. Callers pass every received field via
  [`VerifyOptions::form_params`] (decided API shape; the URL goes in
  `VerifyOptions::request_url`). Sorting is applied by this crate — callers
  pass fields in any order. A duplicate field name keeps its received
  relative order (the official SDKs use keyed dicts, which cannot represent
  duplicates). Omitting either option fails closed with `MissingContext`.
  An explicitly empty parameter list is meaningful (the JSON-body variant
  carries a `bodySHA256` query parameter and signs the URL alone).
- No timestamp in the signature scheme (`max_age` has no effect).

### Discord

Source: <https://docs.discord.com/developers/interactions/overview>
("Validating Security Request Headers") and the reference implementations in
Discord's official SDKs (`discord-interactions-js`,
`discord-interactions-python`).

- Headers: `X-Signature-Ed25519`, `X-Signature-Timestamp`
- Signed message: `"{timestamp}{raw_body}"` — the timestamp verbatim from
  its header, immediately followed by the raw body bytes
- Algorithm: Ed25519 signature verification against Discord's provided
  **public key** (not a shared secret — `Secret` here holds the hex-encoded
  public key, not an HMAC key; document this distinction prominently since
  it changes the security model). Malformed keys (non-hex, wrong length)
  fail closed with `InvalidSecret`.
- Replay protection: enforced with the shared default tolerance
  (symmetric `|now - t| <= max_age`). Discord's docs define no recommended
  window; the timestamp exists so receivers *can* reject stale deliveries,
  and spec §5.4 requires a tolerance for timestamped schemes. Callers can
  widen or disable via `max_age`.
- Test vectors: Discord publishes no frozen vectors today (their SDK tests
  generate ephemeral keypairs; the docs show placeholder keys). The
  implementation is validated against locally constructed, deterministic
  vectors over exactly the officially documented construction. Replace them
  if Discord ever publishes fixed vectors.

### PayPal

Source: PayPal's official "Self verification method" documentation
(<https://developer.paypal.com/api/rest/webhooks/rest/#message-verification>)
and the sample postback code in that same doc page. The crate never performs
a postback or any network I/O (see the resolved design question in §7): the
certificate is supplied by the caller, mirroring SendGrid (§3).

- Headers: `PayPal-Transmission-Id`, `PayPal-Transmission-Time` (RFC 3339
  instant, e.g. `2024-05-16T05:19:23Z`), `PayPal-Transmission-Sig` (base64,
  standard alphabet, padded), `PayPal-Cert-Url`, `PayPal-Auth-Algo`. All five
  are required; any missing header fails closed with `MissingHeader`, and any
  present-but-empty value fails closed with `MalformedHeader` ("header is
  empty") rather than surfacing a guaranteed mismatch as `SignatureMismatch`.
- `PayPal-Auth-Algo` must equal `SHA256withRSA` (matched case-insensitively);
  anything else fails closed with `MalformedHeader` so a future algorithm
  change is rejected rather than silently mis-verified.
- Signed string: `"{transmission_id}|{transmission_time}|{webhook_id}|{crc32}"`
  — the first two fields verbatim from their headers, the webhook ID from
  `VerifyOptions::webhook_id` (it does not travel in the request; see below),
  and the CRC-32 checksum rendered in **decimal**. The CRC-32 is the IEEE
  802.3/zlib polynomial (as the official sample code computes) over the
  **raw body bytes** (§4.2).
- Algorithm: RSASSA-PKCS1-v1_5 with SHA-256, i.e. Java-style
  `SHA256withRSA`, over the signed string. The signature bytes are exactly
  the modulus length; other lengths fail closed with `BadEncoding`.
- Key material: the X.509 certificate at `PayPal-Cert-Url`. It is a
  required *header* (fail-closed on `MissingHeader` if absent) but it is
  **never fetched**: the caller supplies an already vetted certificate
  (typically downloaded from a personally allow-listed `PayPal-Cert-Url`) as
  `VerifyingKeyMaterial::X509Certificate` (DER or PEM; only the embedded RSA
  public key is used; no chain validation or hostname checking). Missing
  material fails closed with `MissingContext`; unparseable certificates or
  non-RSA certificates fail closed with `InvalidSecret`.
- `VerifyOptions::webhook_id` is the PayPal webhook-subscription ID shown in
  the Developer Portal — required for `Provider::PayPal`; missing or empty
  (`MissingContext`) fails closed. It is part of the signed string, so a
  wrong non-empty ID rejects as a signature mismatch.
- The shared `Secret` argument is accepted for API uniformity and ignored
  (public-key scheme, like Discord).
- Replay protection: PayPal's docs ["Compare timestamps to prevent replay
  attacks"](https://developer.paypal.com/community/blog/paypal-has-updated-its-webhook-verification-endpoint/)
  recommend rejecting stale `PayPal-Transmission-Time` values but define no
  numeric window, so the shared default tolerance (symmetric
  `|now - t| <= max_age`, 300s, injectable clock) is applied. The RFC 3339
  instant is normalized to UTC (offsets and fractional seconds — truncated,
  not rounded — are supported) before the window applies.
- Feature gate: shipped behind `features = ["paypal"]` (optional `rsa`,
  `x509-parser`, `crc32fast`; `no_std`-compatible). Without the feature,
  `Provider::PayPal` fails closed with `UnsupportedProvider`.
- Test-vector provenance: PayPal publishes no byte-exact *signed* test vector
  (their example signature covers a transmission string built from a body the
  docs stress must be the exact received bytes, which cannot be reconstructed
  from the docs). The ci tests therefore freeze a locally generated
  certificate + signature over exactly the documented construction, using
  PayPal's own published example body, transmission ID, transmission time,
  and webhook ID; the CRC-32 is cross-checked independently (Python
  `zlib.crc32`). The private key is never committed.

### SendGrid

Source: Twilio's official "Signature Verification" documentation for the
Email Event Webhook
(<https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-signature-verification>)
and the canonical server-side implementation in `sendgrid-go`
`helpers/eventwebhook/eventwebhook.go`
(<https://github.com/sendgrid/sendgrid-go/blob/main/helpers/eventwebhook/eventwebhook.go>).

- Headers: `X-Twilio-Email-Event-Webhook-Signature` and
  `X-Twilio-Email-Event-Webhook-Timestamp` (integer unix seconds)
- Signed message: `"{timestamp}{raw_body}"` — the timestamp verbatim from
  its header, immediately followed by the raw request body bytes, no
  separator. SHA-256 of the whole message is what ECDSA operatively
  verifies (matching Go's `hash.Write(ts); hash.Write(payload)`).
- Algorithm: ECDSA over NIST P-256 (secp256r1), digest SHA-256.
- Signature encoding: base64 (standard alphabet, padded) of the ASN.1 DER
  form `SEQUENCE { INTEGER r, INTEGER s }`. Non-canonical/undersized DER and
  scalars ≥ the curve order fail closed with `BadEncoding` (parsed by
  RustCrypto's `ecdsa` DER reader).
- Key material: the "Verification Key" from the dashboard is a base64
  encoding of the ECDSA P-256 public key in `SubjectPublicKeyInfo` DER
  (Go's `x509.ParsePKIXPublicKey`). Callers pass the **decoded DER bytes**
  as `VerifyingKeyMaterial::EcdsaP256PublicKey`; the base64 string is **not**
  accepted (documented in the provider module docs). Algorithm/certificate
  OIDs in the SPKI must match `id-ecPublicKey` + `prime256v1`: a key for a
  different curve/algorithm fails closed with `InvalidSecret`, not
  `SignatureMismatch`.
- The shared `Secret` argument is accepted for API uniformity and ignored
  (this is a public-key scheme, like Discord).
- Replay protection: enforced with the shared default tolerance (symmetric
  `|now - t| <= max_age`). Twilio's docs define no numeric window; the
  timestamp exists so receivers can reject stale events. Callers can widen
  or disable via `max_age`.
- Feature gate: shipped behind `features = ["sendgrid"]` (optional `p256`
  dependency, `no_std`-compatible). Without the feature, `Provider::SendGrid`
  fails closed with `UnsupportedProvider`.
- Test vectors: the primary vector is SendGrid's own (`sendgrid-go`
  `helpers/eventwebhook/eventwebhook_test.go`): key, signature, and
  timestamp reproduced verbatim, body byte-identical to Go's `json.Marshal`
  output plus trailing `\r\n`. Additional vectors are locally constructed
  with deterministic seeds over exactly the documented construction.

### Paddle

Source: <https://developer.paddle.com/webhooks/about/signature-verification>
("Verify webhook signatures") and Paddle's official Go SDK `WebhookVerifier`
(<https://github.com/PaddleHQ/paddle-go-sdk/blob/main/webhook_verifier.go>).

- Header: `Paddle-Signature: ts=<unix_ts>;h1=<hex_hmac>[;h1=<hex_hmac>...]` —
  a semicolon-separated `key=value` list. During zero-downtime secret
  rotation Paddle sends one `h1` per active secret; a match on *any* `h1` is
  accepted. Unknown keys are ignored; the header must carry a single `ts` and
  at least one well-formed `h1` or it fails closed as `MalformedHeader`.
- Signed string: `"{timestamp}:{raw_body}"` — the timestamp exactly as it
  appears in the header, a literal colon, then the raw request body bytes,
  unmodified. ("Every byte in the request body must remain unaltered for
  successful signature verification.")
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded
- Key: the notification destination's secret key as a plain UTF-8 string (not
  decoded), matching the SDK (`hmac.New(sha256.New, []byte(secret))`).
- Replay protection: compare `|now - t|` against [`VerifyOptions::max_age`]
  (default 300s), using the shared symmetric tolerance semantics. Paddle's
  docs recommend discarding events over a few seconds old but define no
  numeric window, so the shared default applies as with Slack and Zoom.
- Duplicate `ts` elements are rejected as ambiguous — never last-wins,
  following the crate-wide rule that malformed/ambiguous signing material
  fails closed rather than defaulting to valid.
- Test vectors: the primary vector is Paddle's own published worked example
  (Go SDK `example_webhook_verifier_test.go`): secret key, request body, and
  signature reproduced verbatim. Additional vectors cover the empty and
  UTF-8 body boundary cases, constructed locally with `openssl` over exactly
  the documented construction.

### Zoom

Source: <https://developers.zoom.us/docs/api/webhooks/> ("Verify webhook
events") and Zoom's official sample app
(<https://github.com/zoom/webhook-sample-node.js>).

- Headers: `x-zm-signature: v0=<hex_hmac>`, `x-zm-request-timestamp`
- Signed string: `"v0:{timestamp}:{raw_body}"` — the version prefix, the
  timestamp exactly as it appears in its header, and the raw request body
  bytes, joined by literal colons. Identical construction to Slack's scheme.
- Algorithm: HMAC-SHA256, hex-encoded, prefixed `v0=` in the header
- Key: the webhook secret token as a plain UTF-8 string (not decoded).
- Replay protection: compare `|now - t|` against [`VerifyOptions::max_age`]
  (default 300s), using the shared symmetric tolerance semantics. Zoom's
  docs do not define a recommended window; the timestamp exists so receivers
  *can* reject stale deliveries.
- Test-vector provenance: Zoom's docs and sample app publish example headers
  but no byte-exact example signature, so the implementation is validated
  against locally constructed, deterministic vectors over exactly the
  documented construction (the vector's timestamp mirrors the docs' example
  headers). Replace them if Zoom ever publishes fixed vectors.

### Xero

Source: <https://developer.xero.com/documentation/best-practices/data-integrity/overview>
("Webhooks — Xero Developer": "If the payload is hashed using HMACSHA256 with
your webhook signing key and base64 encoded, it should match the signature in
the header"), <https://developer.xero.com/documentation/guides/webhooks/overview/>
(the `x-xero-signature` header), and the reference implementation in Xero's
official sample app
(<https://github.com/XeroAPI/xero-node-oauth2-app/blob/master/src/app.ts>).

- Header: `x-xero-signature: <base64_hmac>`
- Signed string: raw body bytes, unmodified
- Algorithm: HMAC-SHA256, base64-encoded (standard alphabet with padding)
- Key: the webhook signing key as a plain UTF-8 string (not decoded), matching
  Xero's official sample app (`crypto.createHmac('sha256', WEBHOOK_KEY)`).
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/Linear.
- Test-vector provenance: Xero's docs describe the construction and publish a
  verbatim "Intent to Receive" example payload but no byte-exact example
  signature, so the implementation is validated against locally constructed,
  deterministic vectors over the documented ITR payload and exactly the
  documented construction (plus the same empty/unicode boundary cases as the
  other local-vector providers). Replace them if Xero ever publishes fixed
  vectors.

### Cloudflare

Source: <https://developers.cloudflare.com/stream/manage-video-library/using-webhooks/>
("Verify webhook authenticity") and the reference verification code in
Cloudflare's docs
(<https://github.com/cloudflare/cloudflare-docs/blob/production/src/content/docs/stream/examples/test-webhooks-locally.mdx>).
This entry covers **Cloudflare Stream** webhook notifications specifically;
Cloudflare has other webhook schemes (e.g. the legacy Apps
`X-Signature-HMAC-SHA256-HEX` raw-body scheme) that are not this provider.

- Header: `Webhook-Signature: time=<unix_ts>,sig1=<hex_hmac>` — a
  comma-separated `key=value` list. `time` is the integer unix-seconds value
  set by the server; `sig1` is the hex-encoded signature over the body.
  Unknown fields are ignored; the header must carry both `time` and `sig1`
  fields or it fails closed as `MalformedHeader`.
- Signed string: `"{time}.{raw_body}"` — the `time` value exactly as it
  appears in the header, a literal dot, then the raw request body bytes,
  unmodified. ("Every byte in the request body must remain unaltered for
  successful signature verification.")
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded
- Key: the webhook signing secret as a plain UTF-8 string (not decoded),
  matching the docs' reference implementations (`crypto.createHmac("sha256",
  key)`).
- Replay protection: Cloudflare's docs require discarding deliveries whose
  timestamp is too old ("you should discard requests with timestamps that are
  too old for your application") but define no numeric window, so the shared
  symmetric `|now - time| > max_age` (default 300s) semantics apply, as with
  Slack and Zoom. The future-dated half of the symmetry is stricter than the
  docs mandate but cannot reject legitimate deliveries.
- Test-vector provenance: Cloudflare's docs publish the `Webhook-Signature`
  header format (including a full example header) but no byte-exact signed
  body, so the implementation is validated against locally constructed,
  deterministic vectors over exactly the documented construction (the
  vector's `time` and `secret` mirror the docs' own examples; the docs'
  example header itself is replayed as a well-formed-but-mismatching input).
  Replace them if Cloudflare ever publishes fixed vectors.

### Coinbase

Source: <https://docs.cdp.coinbase.com/webhooks/verify-signatures>
("Verify Signatures", Coinbase Developer Platform — CDP webhooks) and the
reference verification code in the docs. This entry covers Coinbase **CDP**
webhooks (wallets, transfers, onchain activity, etc.), which all share the
`X-Hook0-Signature` scheme. The legacy Coinbase Commerce product uses a
different scheme (`X-CC-Webhook-Signature`, bare hex HMAC of the body — cover
with [`CustomScheme`] if needed) and is not this provider.

- Header: `X-Hook0-Signature: t=<unix_ts>,v0=<hex_hmac>,h=<header names>,v1=<hex_hmac>`
  — a comma-separated `key=value` list. `t` is the integer unix-seconds value
  set by the server; `v0` is HMAC-SHA256 over `{t}.{raw_body}` ("protects the
  body and timestamp only"); `h`/`v1` additionally bind the listed HTTP
  headers. Unknown fields are ignored; the header must carry both `t` and `v0`
  fields or it fails closed as `MalformedHeader`.
- Verified variant: `v0`. The docs' own guidance is "unless you want to bind
  the headers, which is unnecessary for most use cases, use `v0`", so only
  `v0` is interpreted and verified; `h` and `v1` (and any future fields) are
  tolerated but ignored. A `t`+`v1`-only header fails closed as missing `v0`.
- Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears in
  the header, a literal dot, then the raw request body bytes, unmodified
  (the docs warn that parsing the JSON payload before verification breaks the
  signature).
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded
- Key: the webhook subscription secret as a plain UTF-8 string (not decoded),
  matching the docs' reference implementations
  (`crypto.createHmac("sha256", secret)`).
- Replay protection: the docs' reference code rejects webhooks older than a
  `maxAgeMinutes` window (default 5 minutes), so the shared symmetric
  `|now - t| > max_age` (default 300s) semantics apply, as with Slack, Zoom,
  and Cloudflare. The future-dated half of the symmetry is stricter than the
  docs' example enforces but cannot reject legitimate deliveries.
- Test-vector provenance: Coinbase publishes the `X-Hook0-Signature` header
  format (including a full example header) and an example payload, but no
  byte-exact signed `v0` value, so the implementation is validated against
  locally constructed, deterministic vectors over exactly the documented
  construction (the vector's `t` and `secret` mirror the docs' own examples;
  the docs' example header shape is replayed as a well-formed-but-mismatching
  input). Replace them if Coinbase ever publishes fixed vectors.

### Standard Webhooks spec

Source: <https://www.standardwebhooks.com> and the canonical spec at
<https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md>
(reference implementations in that repo are the tie-breaker for any
ambiguity).

- Headers: `webhook-id`, `webhook-timestamp` (integer unix seconds),
  `webhook-signature`
- Signature header format: space-delimited list of versioned signatures;
  symmetric signatures are `v1,<base64_hmac>` (standard alphabet, padded).
  During zero-downtime secret rotation a match on *any* `v1` element is
  accepted; non-`v1` elements (e.g. asymmetric `v1a`) are ignored, matching
  the reference libraries' forward-compatible behavior.
- Signed string: `"{webhook-id}.{webhook-timestamp}.{raw_body}"` — literal
  dot joins, with the id and timestamp taken verbatim from their headers
- Algorithm: HMAC-SHA256 over the signed string, base64-encoded
- Secret serialization: `whsec_`-prefixed base64; strip the prefix (if
  present) and base64-decode — leniently, tolerating unpadded input and
  non-canonical trailing bits as the official libraries do — before use as
  the HMAC key. An empty or undecodable secret fails closed with
  `InvalidSecret`.
- Replay protection required: reject when `|now - webhook-timestamp| >
  max_age` (default 300s, matching the reference libraries' tolerance)
- Used by Svix, Clerk, Resend, and a growing list of adopters — implementing
  this once covers all of them.

---

## 4. Security requirements (non-negotiable)

1. **Constant-time comparison.** All signature comparisons use
   `subtle::ConstantTimeEq` (or equivalent) — never `==` on the decoded
   bytes or the encoded strings.
2. **Verify against raw bytes only.** No implementation may re-serialize,
   re-encode, or normalize the body before hashing. The `raw_body: &[u8]`
   passed in is hashed exactly as received.
3. **No secret material in errors, logs, panics, or `Debug` output.**
   Enforced by the `Secret` wrapper type and by a clippy lint / grep check
   in CI (see §6).
4. **Reject on ambiguity, not accept.** If a header is present multiple
   times with different values, or a required header is malformed, return
   an error — never fall back to "treat as valid" behavior. The first-match
   `HeaderMap` lookup cannot see duplicates, so framework adapters (the
   `tower` and `actix` features) check the raw header map against the
   provider's scheme-relevant signature headers before verifying; identical
   repeats are not ambiguous and verify normally.
5. **No panics on attacker-controlled input.** Every parsing path
   (`base64::decode`, `hex::decode`, header splitting, integer parsing of
   timestamps) must return `Result`, not `unwrap()`/`expect()`, and this is
   enforced by `#![deny(clippy::unwrap_used, clippy::expect_used)]` in the
   provider modules.
6. **Timing of the whole function should not vary meaningfully based on
   *why* verification failed.** Structurally this is hard to guarantee
   perfectly (header lookups are not constant-time), but the security-
   relevant step — signature comparison — must be, and is the one that
   matters for known real-world timing attacks.

---

## 5. Testing bar for every provider

A provider implementation is not mergeable until it has:

1. **At least one official test vector**, sourced from the provider's own
   docs/SDK/test suite, with a comment linking to the source.
2. **A negative test**: same inputs, one byte flipped in the signature →
   must return `Err(VerifyError::SignatureMismatch)`.
3. **A tamper test**: valid signature, but `raw_body` modified after
   signing → must fail.
4. **A replay test** (for providers with timestamps): valid signature, but
   timestamp outside `max_age` → must return
   `Err(VerifyError::TimestampOutOfTolerance { .. })`.
5. **A malformed-header test** for each required header: missing, empty,
   and garbage-value cases each return a distinct, documented error variant
   (never a panic, never `SignatureMismatch` masquerading as a parse
   error).
6. **Fuzz coverage**: the header-parsing and encoding-decoding paths for
   each provider are included in the shared `cargo fuzz` target
   (`fuzz/fuzz_targets/parse_and_verify.rs`), which feeds arbitrary bytes as
   headers/body and asserts only "no panic, no timeout" — correctness is
   covered by the vector tests above, fuzzing exists purely to catch
   panics/hangs on adversarial input.
7. **Constant-time assertion** where feasible: a `dudect`-style statistical
   timing test on the comparison step, run in CI as a non-blocking
   (informational) job. *Implemented (2026-09): `constant_time_comparison` in
   `src/core/crypto.rs` times the exact `subtle::ConstantTimeEq` slice
   comparison between two classes of unequal inputs (first-byte vs last-byte
   difference), reporting Welch's t-statistic against a threshold of 10 —
   ~10x the observed noise floor for constant-time code, while a leaked
   early-exit comparison produces |t| in the hundreds. `#[ignore]`d because
   timing tests are noisy on shared runners; run it locally in release mode
   with `cargo test --release --all-features -- constant_time_comparison
   --ignored`. Running it as an informational CI job is tracked separately.*

---

## 6. CI requirements

- `cargo test --all-features` on stable, MSRV, and beta.
- `cargo clippy --all-features -- -D warnings`.
- `cargo fuzz build` (build-only in normal CI; timed fuzz runs in a
  scheduled nightly job).
- A grep-based CI check that fails the build if any of `println!`,
  `dbg!`, `log::`, or `tracing::` macros appear inside a `Secret`'s scope in
  a way that could print its inner value (supplemented by the `Secret`
  type's own redacted `Debug`/`Display` impls as the primary defense).
- `cargo semver-checks` against the last published version to catch
  accidental breaking changes to the public API. Until the first version
  publishes there is no baseline to compare against, so this check is
  informational/non-blocking.

---

## 7. Open questions / future work

- **Certificate/public-key providers (PayPal, SendGrid).** *Resolved
  (2026-08): caller-supplied key material only.* The crate never performs
  network I/O — certificate fetching, URL allow-listing, and caching stay
  with the caller. Rationale:
  1. A fetcher inside `verify()` breaks two §1 goals at once ("no network
     calls", "no required async runtime") and makes the security-critical
     path impure and much harder to audit.
  2. Trusting a cert URL is a deployment-specific decision (PayPal's
     `Paypal-Cert-Url` must be validated against the caller's own
     allowlist before use). Getting it wrong silently weakens verification
     more thoroughly than any crypto bug; the crate should not make that
     choice on callers' behalf.
  3. A synchronous fetcher would drag in blocking HTTP + TLS dependencies;
     an async one would force a runtime choice on all users.

  Status: **SendGrid shipped (2026-09) behind `features = ["sendgrid"]`**
  — `VerifyingKeyMaterial::EcdsaP256PublicKey`, the `verifying_material`
  option, and the ECDSA P-256 verification path are implemented with the
  provider's own test vector (see §3 SendGrid row). **PayPal shipped
  (2026-10) behind `features = ["paypal"]`** — `X509Certificate`
  certificate material, the `webhook_id` option, and the RSASSA-PKCS1-v1_5
  SHA-256 verification path over the documented
  `{transmission_id}|{transmission_time}|{webhook_id}|{crc32}` construction
  (see §3 PayPal row; RFC 3339 transmission-time parsing lives in
  `src/core/replay.rs`). The API shipped matches the 2026-08 sketch below
  (with key/certificate bytes redacted from `Debug` output on the enum):

  ```rust
  /// Caller-supplied asymmetric verification material (spec §7).
  #[non_exhaustive]
  pub enum VerifyingKeyMaterial {
      /// DER- or PEM-encoded X.509 certificate (PayPal). Only the embedded
      /// public key is used; this crate performs no chain validation, so
      /// callers needing chain/pin enforcement supply an already-validated
      /// certificate.
      X509Certificate(Vec<u8>),
      /// DER bytes of an ECDSA P-256 `SubjectPublicKeyInfo` public key
      /// (SendGrid scheme), decoded by the caller from the dashboard's
      /// base64 "Verification Key".
      EcdsaP256PublicKey(Vec<u8>),
  }

  pub struct VerifyOptions {  // #[non_exhaustive]
      // ... existing fields ...
      /// Verification material for providers whose scheme checks a
      /// signature against a configured public key/certificate rather
      /// than a shared secret (currently SendGrid and PayPal).
      /// This crate never fetches anything from the network.
      pub verifying_material: Option<VerifyingKeyMaterial>,
      /// PayPal's webhook-subscription ID, required by its signed-string
      /// construction (does not travel in the request).
      pub webhook_id: Option<String>,
  }
  ```

  Error semantics (shipped and tested): required-but-absent
  `verifying_material` fails closed with `MissingContext` (caller
  misconfiguration, mirroring Square/Twilio); malformed material (bad
  SPKI, wrong curve/algorithm) and a `X509Certificate` passed where
  SendGrid requires a bare key fail with `InvalidSecret`; undecodable
  base64 or non-DER signatures are `BadEncoding`; everything else is
  `SignatureMismatch`.

  Implementation notes: asymmetric verification uses feature-gated
  RustCrypto dependencies (`p256`, optional `no_std`-compatible; `rsa` +
  `x509-parser` + `crc32fast` behind the `paypal` feature — see the crate's
  `Cargo.toml`). The
  optional `webhook-verify-fetch` companion crate remains future work if
  automated key rotation handling is ever requested — it stays out of this
  crate either way.

- **Secret rotation UX.** *Resolved (2026-09, issue #64).* Stripe/Standard
  Webhooks allow multiple valid signatures during a rotation window
  (`v1=...,v1=...`). `verify()` keeps `Secret` singular in the core
  signature for ergonomics (multi-`v1=` rotation lists remain accepted
  inside a single `verify()`); cross-secret rotation ships as the
  `verify_any(provider, headers, body, &[Secret], opts)` wrapper, whose
  error-aggregation rules are a decision record in §2.
- **`no_std` scope.** Full `no_std` (no `alloc`) is likely infeasible given
  base64/hex decoding and header string handling; target `no_std + alloc`
  and validate against `wasm32-unknown-unknown` as the primary constrained
  target (webhook verification at the edge, e.g. Cloudflare Workers via
  `wasm-bindgen`, is a plausible real use case). *Implemented (issue #76):
  the core is `no_std + alloc` behind the `std` feature (default on). Building
  with `--no-default-features` drops the wall clock: [`Clock::now`] returns
  unix seconds directly (no `SystemTime`), [`SystemClock`] is `std`-only, and
  [`VerifyError`] does not implement `std::error::Error`. Callers on
  bare-metal/wasm targets supply their own [`Clock`] for timestamped
  (replay-protected) providers; a missing clock reads 0 and fail-closes replay
  checks. The wasm regression job ships in CI
  (`.github/workflows/ci.yml`: `cargo build --no-default-features --features
  sendgrid,paypal --target wasm32-unknown-unknown`), so this configuration
  cannot silently regress. The `no_std + alloc` scope covers the core
  verification path only: the `tower` and `actix` adapters are std-only
  framework glue and therefore imply the `std` feature when enabled —
  a `default-features = false` build with either of them simply gets `std`
  back, which keeps the combination compiling instead of surfacing raw
  `cannot find crate std` errors.*
- **Provider promotion criteria.** A `CustomScheme` recipe gets promoted to
  a first-class `Provider` variant once it has (a) official test vectors,
  (b) at least one external user request or contribution, and (c) no open
  design question from §7 blocking it.
