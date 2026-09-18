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
    Bitbucket,
    HubSpot,
    Klaviyo,
    Shopify,
    Slack,
    Square,
    Twilio,
    Twitch,
    Typeform,
    Discord,
    PayPal,
    SendGrid,
    Paystack,
    Paddle,
    PagerDuty,
    Linear,
    LaunchDarkly,
    Notion,
    Zoom,
    Cloudflare,
    Coinbase,
    Dropbox,
    Razorpay,
    LemonSqueezy,
    Xero,
    Sentry,
    Adyen,
    Mux,
    Zendesk,
    WorkOS,
    WooCommerce,
    Calendly,
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
    /// (currently Square, Twilio, HubSpot). See §3.
    pub request_url: Option<String>,
    /// HTTP request method (uppercase, e.g. `POST`), for schemes that sign
    /// the method into their source string (currently HubSpot's v3 scheme).
    /// Must match the method the provider actually sent for the delivery.
    /// No effect on providers that do not sign the method. See §3.
    pub request_method: Option<String>,
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
            request_method: None,
            form_params: None,
            verifying_material: None,
            webhook_id: None,
        }
    }
}

impl core::str::FromStr for Provider {
    type Err = ProviderParseError;
    // Case-insensitive match on the canonical Display name of each variant
    // ("github", "GitHub", "GITHUB", ...), plus the space-separated
    // human-readable forms for the multi-word-name variants
    // ("lemon squeezy" → LemonSqueezy, "standard webhooks" →
    // StandardWebhooks). `custom` is rejected: a
    // CustomScheme requires configuration and must be built directly.
}

pub trait HeaderMap {
    /// Case-insensitive header lookup. Returns the first matching value.
    fn get(&self, name: &str) -> Option<&str>;
}
// Blanket impls provided for the built-in collections (Vec<(String,String)>,
// Vec<(&str,&str)>, fixed-size arrays of (String,String) and (&str,&str),
// borrowed slices of both, BTreeMap<String,String>, BTreeMap<&str,&str>,
// HashMap<String,String>, HashMap<&str,&str>), unconditionally — the HashMap
// impls require the "std" feature, since std::collections::HashMap is itself
// std-only (BTreeMap lives in alloc); the http::HeaderMap impl is provided
// behind the "http" feature flag. The borrowed-key map impls
// (BTreeMap<&str,&str>, HashMap<&str,&str>) exist so static header tables
// built from `&'static str` pairs verify without allocating owned keys.

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

#### `verify_any` aggregation (decision record)

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

**Replay-check caveat.** Setting `timestamp_header` runs the shared replay
window (`|now - t| <= max_age`) against the header value, but the check only
*binds* when `signed_string` copies that value into the signed bytes. A
closure that signs the body alone leaves the timestamp attacker-rewriteable:
replaying a captured request with a freshened timestamp header still verifies
(the header is not part of the HMAC input), silently defeating the protection.
The built-in timestamped providers (e.g. Slack's `v0:{timestamp}:{raw_body}`)
wire the timestamp into the signed string by construction; a `Custom` scheme
must do so deliberately.

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
- Keys are compared after trimming surrounding whitespace, so the comma-space
  spelling `t=..., v1=...` (produced by proxy header-folding and hand-pasted
  values) parses like the canonical `t=...,v1=...`. Values are never trimmed —
  the timestamp rides verbatim into the signed string.
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

### Bitbucket

Source: <https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/>
(Bitbucket Cloud's "Manage webhooks" documentation: the `X-Hub-Signature`
header format, the raw-body signing rule, and the "Testing the webhook payload
validation" worked example) and the webhooks-security overview
(<https://www.atlassian.com/blog/bitbucket/enhanced-webhook-security>).

- Header: `X-Hub-Signature: sha256=<hex_hmac>` — formatted as WebSub's
  `method=signature`, with `sha256` the only method Bitbucket sends today.
- Signed string: raw body bytes, unmodified — the docs stress that "the
  payload is passed verbatim into the HMAC generation" and that reformatting
  the body produces a different signature.
- Algorithm: HMAC-SHA256, hex-encoded. Key: the webhook's configured secret
  token as its UTF-8 bytes.
- The `sha256=` prefix is matched case-sensitively, exactly like GitHub —
  WebSub method names are lowercase and Bitbucket's docs and examples emit
  only the literal lowercase form. Bitbucket's docs warn they "might use
  another hash in the future"; an unknown method then fails closed as
  `MalformedHeader`, never silently mis-verified.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub. The `X-Hub-Signature` header exists only when a secret is
  configured on the webhook (`spec.md` §1); webhooks without a secret send no
  header and `verify()` reports `MissingHeader`.
- Test-vector provenance: Bitbucket's docs publish the exact worked-example
  values for `secret`, `payload`, and expected signature (`It's a Secret to
  Everybody` / `Hello World!` / `a4771c39...263c9`), reproduced byte-for-byte;
  the docs' JavaScript sample additionally publishes a JSON payload + expected
  signature that the implementation reproduces byte-for-byte. Boundary-vector
  bodies are locally constructed over the same documented recipe, cross-checked
  with `openssl dgst`.

### HubSpot

Source: hubspot.com/docs/api/webhooks (the "webhooks" feature's
error-handling page, "Signature Version 3", and its worked
endpoint-confirmation example) — linked in the provider module docs. The
published example produces a concrete signature that the implementation
reproduces byte-for-byte.

- Headers: `X-HubSpot-Request-Timestamp` (unix **epoch milliseconds**) and
  `X-HubSpot-Signature-V3` (`<base64_hmac>`)
- Signed string: `{request_method}{request_uri}{raw_body}{timestamp}` — the
  delivery's HTTP method, then the request URI, then the raw body bytes, then
  the timestamp **exactly as it appears in its header**, all concatenated with
  no separators
- Algorithm: HMAC-SHA256, base64-encoded (standard alphabet, padded)
- Key: the app's "App secret", used as its UTF-8 bytes verbatim
- Caller-supplied context required: `VerifyOptions::request_method` **and**
  `VerifyOptions::request_url` (this is the only scheme that signs the HTTP
  method; the method must match what the provider actually sent). Missing or
  empty either fails closed with `MissingContext`. The URI must match the
  exact string HubSpot signed for the delivery; HubSpot documents that *when
  computing the signature* it decodes certain URL-encoded characters
  (`%3A`, `%2F`, `%40`, `%26`, `%3D`, `%2B`, `%24`, `%60`, `%22`, `%2C`,
  `%3B`, `%3E`, `%3C`, `%3F`) in the URI — callers behind those encodings
  pass the URI in the same decoded form.
- Replay protection required: signed-timestamp provider, shared symmetric
  tolerance (`|now - t| <= max_age`, injectable clock), with the timestamp
  converted from milliseconds to whole seconds by integer division
  (`millis / 1000`, dropping the sub-second remainder as HubSpot's official
  Java reference does). HubSpot's own reference snippets use a one-sided
  five-minute check; this crate applies its single audited symmetric replay
  backend for consistency with every other provider.
- Test-vector provenance: the docs' worked example (secret, method, URI, body,
  millisecond timestamp, expected base64 signature) is reproduced
  byte-for-byte. Boundary-vector bodies are locally constructed over the
  documented recipe, pinned against the official example first.

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

### Lemon Squeezy

Source: <https://docs.lemonsqueezy.com/help/webhooks/signing-requests> (Lemon
Squeezy's webhook signing documentation) and
<https://docs.lemonsqueezy.com/help/webhooks/webhook-requests> (webhook
requests header reference).

- Header: `X-Signature: <hex_hmac>` — a bare hex digest, no `sha256=` prefix
  (unlike GitHub/Notion); same shape as Dropbox and Linear
- Signed string: raw body bytes, unmodified — Lemon Squeezy's own docs stress
  that the exact received bytes matter (their delivery JSON escapes `/` as
  `\/` in opaquely-checked fields; re-serializing before hashing changes the
  bytes and fails verification)
- Algorithm: HMAC-SHA256, hex-encoded. Key: the webhook's signing secret as
  its UTF-8 bytes, matching the docs' reference implementations
  (`crypto.createHmac('sha256', secret).update(rawBody).digest('hex')`)
- No timestamp in the signature scheme (`max_age` has no effect); Lemon Squeezy
  recommends deduping from the payload's own `id` field, which is outside this
  crate's scope (payload parsing is a non-goal, §1)
- Test-vector provenance: Lemon Squeezy's docs describe the construction and
  ship reference code but publish no byte-exact example signature, so the
  implementation is validated against locally constructed, deterministic
  vectors over exactly the documented construction. Replace them if Lemon
  Squeezy ever publishes fixed vectors.

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

### LaunchDarkly

Source: <https://launchdarkly.com/docs/home/infrastructure/webhooks> ("Sign a
webhook": the `X-LD-Signature` header and the HMAC-SHA256 hex construction)
and <https://launchdarkly.com/docs/api/webhooks> (the webhooks API reference,
repeating the signing guidance and the "Sample payload").

- Header: `X-LD-Signature: <hex_hmac>` — a bare lowercase hex digest, no
  `sha256=` prefix and no timestamp; same shape as Dropbox, Razorpay, and
  Lemon Squeezy.
- Signed string: raw body bytes, unmodified. LaunchDarkly's docs state the
  header "will contain an HMAC SHA256 hex digest of the webhook payload",
  keyed by the webhook secret configured on the integration — re-serializing
  the JSON payload would change the bytes and fail verification.
- Algorithm: HMAC-SHA256, hex-encoded. Key: the webhook secret as its UTF-8
  bytes, matching the documented construction
  (`crypto.createHmac("sha256", secret).update(body).digest("hex")`).
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/Linear. LaunchDarkly's docs note webhooks may not be
  delivered in chronological order and recommend reordering from the
  payload's own `date` field, which is outside this crate's scope (payload
  parsing is a non-goal, §1).
- Test-vector provenance: LaunchDarkly's docs describe the construction but
  publish no byte-exact example signature, so the implementation is validated
  against locally constructed, deterministic vectors over exactly the
  documented construction (the vector's body mirrors the shape of
  LaunchDarkly's documented webhook payload). Replace them if LaunchDarkly
  ever publishes fixed vectors.

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

### Twitch

Source: <https://dev.twitch.tv/docs/eventsub/handling-webhook-events/>
("Verifying the signature": the three `Twitch-Eventsub-Message-*` headers,
the message-id + message-timestamp + message-body concatenation, the
HMAC-SHA256 algorithm, and the nanosecond RFC 3339 timestamp format).
Twitch publishes no worked HMAC example in that page, so the vector below
is locally constructed over exactly the documented construction.

- Headers: `Twitch-Eventsub-Message-Id` (opaque per-delivery id),
  `Twitch-Eventsub-Message-Timestamp` (RFC 3339 with fractional seconds,
  e.g. `2022-08-14T16:59:32.618908427Z`), and
  `Twitch-Eventsub-Message-Signature: sha256=<hex_hmac>`.
- Signed string: `"{message_id}{message_timestamp}{raw_body}"` — the message
  id and the message timestamp **verbatim as received** concatenated with the
  raw body bytes, with no separators or field labels. The timestamp must
  never be re-serialized/re-encoded before signing: its numeric grammar is
  signed byte-for-byte as sent.
- Algorithm: HMAC-SHA256, hex-encoded. Key: the webhook subscription's
  configured secret as its UTF-8 bytes.
- The `sha256=` prefix is matched case-sensitively, exactly like GitHub and
  Bitbucket; an unknown scheme fails closed as `MalformedHeader`.
- Message id has no format grammar to validate here: it is opaque, and its
  only contract is that the verifying side re-signs the exact bytes it
  received (so a garbage value verifies only against a signature made over
  that exact value, never against one made over the real id). A
  present-but-empty value is rejected as `MalformedHeader` ("header is
  empty") — an empty identifier is never a legitimate Twitch delivery, and
  this matches the fail-closed treatment of Standard Webhooks' opaque
  `webhook-id` (`spec.md` §4.4).
- Replay protection: the timestamp header is parsed through the shared RFC
  3339 parser (sub-second precision truncated; the `T`/`Z` separators are
  case-insensitive per the RFC 3339 §5.6 note) and checked against the shared
  symmetric `|now - t| <= max_age` window (default 300s), as with Zoom and
  Paddle. Twitch's docs demonstrate only the checksum comparison; applying
  the window is strictly stronger and cannot reject a fresh delivery.
- Malformed `Twitch-Eventsub-Message-Timestamp` values (empty, non-RFC-3339,
  out-of-range calendar fields, or pre-epoch) fail closed as
  `MalformedHeader`, independent of whether a signature over the raw string
  would verify — the same fail-closed timestamp policy as `spec.md` §4.4.
- Test-vector provenance: no official worked vector is published; the main
  vector is constructed over the exactly documented concatenation and
  cross-checked with `openssl dgst`, with the command recorded in the module
  tests. Boundary vectors (empty body, unicode body) follow the same recipe,
  plus a re-signing under a second message id proving the id binds into the
  signed string.

### Typeform

Source: <https://developers.typeform.com/developers/webhooks/secure-your-webhooks/>
("Secure your webhooks" — signature verification guidance and reference code
in Ruby, Node.js, Python, Swift, and PHP).

- Header: `Typeform-Signature: sha256=<base64_hmac>`
- Signed string: the raw request body bytes, unmodified
- Algorithm: HMAC-SHA256 keyed with the webhook secret's UTF-8 bytes,
  **base64**-encoded (standard alphabet, padded), with a literal `sha256=`
  prefix. The prefix is matched case-sensitively, exactly like GitHub
  (`spec.md` §3): Typeform's docs and reference code emit only the literal
  lowercase form.
- Key: the webhook secret configured via the Typeform Webhooks REST API
  (the "secret" field on the webhook), used as its UTF-8 bytes verbatim.
- No timestamp in the signature scheme (`max_age` has no effect); Typeform
  recommends deduping from the event payload's `event_id` field, which is
  outside this crate's scope (payload parsing is a non-goal, §1).
- Test-vector provenance: Typeform's docs describe the scheme and ship
  reference code (`crypto.createHmac('sha256', secret).update(payload)`
  `.digest('base64')`, prefixed `sha256=`) but publish no byte-exact
  example signature, so the implementation is validated against locally
  constructed, deterministic vectors over exactly the documented construction
  (the vector's body mirrors the shape of Typeform's documented
  `form_response` example payload). Replace them if Typeform ever publishes
  fixed vectors.

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
  not rounded — are supported; the `T`/`Z` separators are case-insensitive
  per the RFC 3339 §5.6 note) before the window applies.
- Feature gate: shipped behind `features = ["paypal"]` (optional `rsa`,
  `x509-parser`, `crc32fast`). **Std-bounded today**: the certificate path's
  transitive defaults (`der-parser` and `nom`, pulled via `x509-parser`)
  re-enable `std` in `num-traits`/`num-bigint`/`memchr`, and Cargo's union
  feature-unification means a `no_std` edge declared here cannot revoke them
  — so `paypal` cannot build for a genuinely std-less target (the wasm32 CI
  gate does not catch this; wasm32 ships std). The `no_std + alloc`
  guarantee (spec §1) is scoped to the core verification path + `sendgrid`;
  see §7 and issue #23. Without the feature, `Provider::PayPal` fails closed
  with `UnsupportedProvider`.
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
- Keys are compared after trimming surrounding whitespace, so the
  semicolon-space spelling `ts=...; h1=...` (produced by proxy header-folding
  and hand-pasted values) parses like the canonical `ts=...;h1=...`. Values
  are never trimmed — the timestamp rides verbatim into the signed string.
- Test vectors: the primary vector is Paddle's own published worked example
  (Go SDK `example_webhook_verifier_test.go`): secret key, request body, and
  signature reproduced verbatim. Additional vectors cover the empty and
  UTF-8 body boundary cases, constructed locally with `openssl` over exactly
  the documented construction.

### PagerDuty

Source: <https://developer.pagerduty.com/docs/verifying-signatures>
(PagerDuty's "Verifying signatures" documentation for v3 webhooks) and the
official Go SDK's reference implementation
(<https://github.com/PagerDuty/go-pagerduty/blob/main/webhookv3/webhookv3.go>).

- Header: `X-PagerDuty-Signature: v1=<hex_hmac>[,v1=<hex_hmac>...]` — one or
  more comma-separated `v1=` elements. During zero-downtime secret rotation
  PagerDuty sends multiple `v1=` signatures (one per active secret); a match
  on *any* is accepted. Elements without the literal lowercase `v1=` prefix
  are ignored per the SDK's downgrade protection ("Ignore any signatures
  that are not the initial v1 version"); if that leaves no signatures at
  all, the header fails closed as `MalformedHeader`.
- Signed string: the raw request body bytes, unmodified — PagerDuty signs the
  payload exactly as delivered, so re-serializing or reformatting the body
  changes the signature.
- Algorithm: HMAC-SHA256, hex-encoded.
- Key: the webhook subscription's signing secret (its
  `delivery_method.secret`) as a plain UTF-8 string (not decoded), matching
  the SDK (`hmac.New(sha256.New, []byte(secret))`).
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Bitbucket/Sentry.
- Empty `v1=` elements, non-hex `v1=` values, and `v1=` values that do not
  decode to 32 bytes fail closed as `MalformedHeader`/`BadEncoding` (never
  silently dropped): the SDK quietly swallows hex-decode failures, but this
  crate keeps that ambiguity visible via the crate-wide error granularity
  (`spec.md` §2.1).
- Test-vector provenance: the primary vector is PagerDuty's own published
  test in the official `go-pagerduty` SDK (`webhookv3/webhookv3_test.go`):
  secret `lDQHScfUeXUKaQRNF+8XIiDKZ7XX3itBAYzwU0TARw8lJqRnkKl2iB1anSb0Z+IK`,
  payload, and expected `v1=0c0b9495...5476cd` signature reproduced
  byte-for-byte, plus the same SDK's "mismatch" vector
  (`v1=7020c8a7...8bcaf5`). Additional vectors cover the empty and UTF-8 body
  boundary cases, the multi-`v1=` rotation list, and non-`v1=` elements,
  constructed locally over exactly the documented construction.

### Adyen

Source: <https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures>
("Verify HMAC signatures" — the header-based scheme:
`hmacsignature: <base64_hmac>` and the `protocol: HmacSHA256` companion
header) and
<https://docs.adyen.com/classic-platforms/configure-notifications/signing-notifications-with-hmac>
(the classic-platform worked example, including a byte-exact payload,
signature, and key). Construction corroborated by Adyen's official libraries:
Java `HMACValidator.calculateHMAC` (`Hex.decodeHex(key)`,
<https://github.com/Adyen/adyen-java-api-library/blob/master/src/main/java/com/adyen/util/HMACValidator.java>)
and Go `hmacvalidator` (`hex.DecodeString(secret)`,
<https://github.com/Adyen/adyen-go-api-library/blob/main/src/hmacvalidator/hmacvalidator.go>).

- Header: `HmacSignature: <base64_hmac>` — bare base64 (standard alphabet with
  padding), no prefix and no timestamp; same shape as Xero/Shopify. Header
  lookup is case-insensitive, so the lowercase `hmacsignature` spelling in
  current docs also resolves. The companion `protocol` header
  (`HmacSHA256`) is **not** covered by the HMAC and is not parsed: Adyen only
  ever sends `HmacSHA256`, and an algorithm downgrade would fail closed as a
  signature mismatch rather than being silently accepted.
- Signed string: raw body bytes, unmodified. Adyen's docs are explicit: "Make
  sure that the request body is as it is—do not deserialize it". This is the
  header-based scheme Adyen uses for its non-payment webhooks (Adyen for
  Platforms / Banking, the Management API, Recurring token lifecycle
  notifications, and classic-platform notifications). Adyen's **Standard
  payments** webhooks place the signature inside the JSON body at
  `notificationItems[].NotificationRequestItem.additionalData.hmacSignature`
  and sign a colon-joined field subset; a body-embedded signature over a
  parsed-field string is outside this crate's raw-body model and is **not**
  covered by `Provider::Adyen`.
- Algorithm: HMAC-SHA256, base64-encoded. Key: the Customer Area HMAC key,
  which Adyen issues as a **hex string**, **hex-decoded to raw key bytes**
  before use — matching Adyen's official Java/Go libraries. Keying the HMAC
  with the ASCII hex characters instead of the decoded bytes is the classic
  Adyen integration bug; a key that is not valid (even-length) hexadecimal, or
  that decodes to nothing, fails closed as `InvalidSecret` rather than being
  used as-is.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/Linear. Adyen delivers duplicates by design and
  recommends identifying them from the payload's own
  `eventCode`/`pspReference` fields, which is outside this crate's scope
  (payload parsing is a non-goal, §1).
- Test-vector provenance: the primary vector is Adyen's own byte-exact worked
  example from the classic-platform page — key
  `79A3EAF309C43708726A8C284C0D72618696A12E840DFA1DF3A158AFA3B577DA`, the
  complete account-holder JSON payload, and expected signature
  `A2bHr0WPlKg1fJLVEDReVAdUDWt3znmsuYvp2KdihXY=`. Additional vectors cover the
  empty and UTF-8 body boundary cases, the case-insensitive header spelling,
  an uppercase/lowercase hex key pair, and the ASCII-hex-key failure mode,
  constructed locally with `openssl` over exactly the documented construction.

### Razorpay

Source: <https://razorpay.com/docs/webhooks/validate-test/> ("Validate and Test
Webhooks": header reference, HMAC construction, and the explicit "do not parse
or cast the webhook request body" rule), and
<https://razorpay.com/docs/webhooks/faqs/> (FAQ confirming only the raw request
body may be hashed).

- Header: `X-Razorpay-Signature: <hex_hmac>` — a bare lowercase hex digest, no
  `sha256=` prefix and no timestamp; same shape as Dropbox, Lemon Squeezy, and
  Linear.
- Signed string: raw body bytes, unmodified. Razorpay's docs are explicit on
  this point: "ensure that the webhook body passed as an argument is the raw
  webhook request body. Do not parse or cast the webhook request body" —
  re-serializing JSON would change the bytes and the signature would not match.
- Algorithm: HMAC-SHA256, hex-encoded. Key: the webhook secret configured in
  the dashboard as its UTF-8 bytes (deliberately **not** the API Key
  Secret), matching the docs' construction `hmac('sha256', message,
  key)` and the official SDK helper
  `validateWebhookSignature(body, signature, secret)`.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/Linear. Razorpay's docs recommend replay/dedup
  handling from the event payload's own fields, which is outside this crate's
  scope (payload parsing is a non-goal, §1).
- Test-vector provenance: the primary vectors are the worked examples posted by
  a Razorpay maintainer in the official SDK's issue tracker
  (<https://github.com/razorpay/razorpay-node/issues/29>): secret `123456`,
  body `{a:1, b:2}` → `ee0a3edebeb4be41bafa3bc0a39069d7845a5c37760b863405049de80b5fe92d`,
  and body `{c:1, d:2}` → `58fd9fac909b57d776606e9313e83a26a9e67a3488b9ca7259134e09f4badfb1`.
  Additional vectors cover the empty and UTF-8 body boundary cases, constructed
  locally with `openssl` over exactly the documented construction.

### Paystack

Source: <https://paystack.com/docs/payments/webhooks/> ("Verify event origin →
Signature validation": the `x-paystack-signature` header, the HMAC-SHA512
construction, and the secret-key requirement).

- Header: `x-paystack-signature: <hex_hmac>` — a bare lowercase hex digest, no
  prefix and no timestamp; same shape as Dropbox, Razorpay, and Lemon Squeezy,
  but the **only built-in provider keyed with HMAC-SHA512** rather than
  SHA-256. Paystack's docs' Node sample hashes `JSON.stringify(req.body)`,
  which only works when a framework reproduces Paystack's exact bytes; this
  crate hashes the raw request bytes verbatim (`§4`), the construction that
  survives a non-normalizing proxy.
- Signed string: raw body bytes, unmodified.
- Algorithm: HMAC-SHA512, hex-encoded. Key: the Paystack secret key from the
  dashboard ("Settings → API Keys & Webhooks") as its UTF-8 bytes, matching the
  documented construction
  (`crypto.createHmac("sha512", secret).update(body).digest("hex")`).
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/Linear. Paystack's docs recommend IP allow-listing
  the documented source address ranges as a complement to signature
  validation, which is a deployment concern outside this crate's scope.
- Test-vector provenance: Paystack's docs describe the construction but publish
  no byte-exact example signature, so the implementation is validated against
  locally constructed, deterministic vectors over exactly the documented
  construction (the primary vector's body mirrors the shape of Paystack's
  documented `charge.success` event; the vectors were independently
  cross-checked with Python `hmac` against `openssl`, and the SHA-256-length
  reject case pins the 64-byte digest shape). Replace them if Paystack ever
  publishes fixed vectors.

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

### Sentry

Source: <https://docs.sentry.io/integrations/integration-platform/webhooks>
(Sentry's official Integration Platform webhook documentation, "Verifying the
Signature"), corroborated by the reference implementation in Sentry's official
example repository referenced from that page
(<https://github.com/getsentry/integration-platform-example>).

- Header: `Sentry-Hook-Signature: <hex_hmac>` — a bare lowercase hex digest,
  no `sha256=` prefix and no timestamp; same shape as Dropbox, Razorpay, and
  Lemon Squeezy.
- Signed string: raw body bytes, unmodified. Sentry's docs sign the exact
  received payload (the reference snippet HMACs the raw JSON request body;
  re-serializing it would change the bytes and fail verification).
- Algorithm: HMAC-SHA256, hex-encoded. Key: the integration's **Client
  Secret** as its UTF-8 bytes (the secret shown on the
  `sentry.io/settings/<org>/apps/<app>/` page, **not** an organization auth
  token), matching the docs' construction `createHmac("sha256", secret) ...
  digest("hex")`.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/Linear. Sentry delivers an unsigned
  `Sentry-Hook-Timestamp` header, which is not part of the signature and so
  provides no tamper-resistant replay protection.
- Test-vector provenance: Sentry's docs describe the construction and ship
  reference code but publish no byte-exact example signature, so the
  implementation is validated against locally constructed, deterministic
  vectors over exactly the documented construction (cross-checked across
  OpenSSL and Python's `hashlib`). Replace them if Sentry ever publishes fixed
  vectors.

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
- Duplicate `time` or `sig1` fields are rejected as ambiguous — never
  first-wins, following the crate-wide rule that malformed/ambiguous signing
  material fails closed rather than defaulting to valid (the reference code
  takes the first occurrence; this crate does not).
- Keys are compared after trimming surrounding whitespace, so the comma-space
  spelling `time=..., sig1=...` (produced by proxy header-folding and
  hand-pasted values) parses like the canonical `time=...,sig1=...`. Values
  are never trimmed — the timestamp rides verbatim into the signed string.
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
- Duplicate `t` or `v0` fields are rejected as ambiguous — never first-wins,
  following the crate-wide rule that malformed/ambiguous signing material
  fails closed rather than defaulting to valid (the reference code takes the
  first occurrence; this crate does not).
- Keys are compared after trimming surrounding whitespace, so the comma-space
  spelling `t=..., v0=...` (produced by proxy header-folding and hand-pasted
  values) parses like the canonical `t=...,v0=...`. Values are never trimmed —
  the timestamp rides verbatim into the signed string.
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

### Mux

Source: <https://www.mux.com/docs/core/verify-webhook-signatures> ("Verify
webhook signatures") and Mux's official server-side SDKs — the Elixir
verifier
(<https://github.com/muxinc/mux-elixir/blob/master/lib/mux/webhooks.ex>) and
the Node verifier
(<https://github.com/muxinc/mux-node-sdk/blob/main/src/resources/webhooks/webhooks.ts>).
This entry covers Mux webhook notifications (video assets, live streams,
direct uploads, etc.), which all share the `Mux-Signature` scheme.

- Header: `Mux-Signature: t=<unix_ts>,v1=<hex_hmac>[,v1=<hex_hmac>...]` — a
  comma-separated `key=value` list. `t` is the integer unix-seconds value set
  by the server; `v1` is HMAC-SHA256 over `{t}.{raw_body}` and is the only
  scheme the docs define ("Currently, the only valid signature scheme is
  `v1`"). Unknown fields and non-`v1` schemes are discarded for forward
  compatibility.
- Multiple `v1=` values are accepted during signing-secret rotation (a match
  on *any* `v1` element is accepted), matching the official SDKs.
- Duplicate `t` fields are rejected as ambiguous — never first-wins,
  following the crate-wide rule that malformed/ambiguous signing material
  fails closed rather than defaulting to valid (the SDK parsers take the last
  occurrence; this crate does not).
- Keys are compared after trimming surrounding whitespace, so the comma-space
  spelling `t=..., v1=...` (produced by proxy header-folding and hand-pasted
  values) parses like the canonical `t=...,v1=...`. Values are never trimmed —
  the timestamp rides verbatim into the signed string.
- Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears in
  the header, a literal dot, then the raw request body bytes, unmodified (the
  docs warn to pass "the raw un-parsed request body, not the parsed JSON").
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded
- Key: the per-webhook `signing_secret` from the Webhooks API as a plain
  UTF-8 string (not decoded, and distinct from the Mux API token), matching
  the docs' reference implementations.
- Timestamp validation routes through the shared pure-ASCII-digit parser:
  sign-prefixed (`t=+1591664030`), whitespace-padded, empty, or overflowing
  values fail closed as `MalformedHeader`. Mux's own SDKs use a lenient
  `parseInt`-style parse; the strict shared parser is intentionally stricter
  and cannot reject a legitimate delivery.
- Replay protection: Mux's SDKs apply a 300-second tolerance
  (`@default_tolerance 300` in the Elixir verifier; `tolerance = 300` in the
  Node verifier), so the shared symmetric `|now - t| > max_age` (default
  300s) semantics apply, as with Slack, Zoom, Cloudflare, and Coinbase. The
  future-dated half of the symmetry is stricter than the SDKs enforce but
  cannot reject legitimate deliveries.
- Test-vector provenance: the primary vector is Mux's own byte-exact
  published vector from its official Elixir SDK test utilities
  (<https://hexdocs.pm/mux/Mux.Webhooks.TestUtils.html>:
  `generate_signature("payload", "SuperSecret123")` gives
  `t=1591664030,v1=e43496b6aae982c4c2fd6f8e92935f1d90216f1f64d56024e72390acfb988272`,
  verified by the same SDK's `verify_header/3`). Additional vectors cover the
  empty and UTF-8 body boundary cases, multi-`v1` rotation, the comma-space
  spelling, and the failure modes, constructed locally over exactly the
  documented construction; Mux's published example header is replayed as a
  well-formed-but-mismatching input.

### Zendesk

Source: <https://developer.zendesk.com/documentation/webhooks/verifying>
("Verifying webhook authenticity": header reference, the exact
`base64(HMACSHA256(TIMESTAMP + BODY))` construction, and the Node reference
implementation), corroborated by the request-header reference on
<https://developer.zendesk.com/documentation/webhooks/anatomy-of-a-webhook-request>.

- Headers: `X-Zendesk-Webhook-Signature`, `X-Zendesk-Webhook-Signature-Timestamp`
  (RFC 3339, e.g. `2021-03-25T05:09:27Z`).
- Signed string: `"{timestamp}{raw_body}"` — the timestamp header value exactly
  as sent, concatenated with the raw request body bytes, no separators. The
  timestamp's numeric grammar is never re-serialized into the signed bytes
  (mirroring Twitch/PayPal, whose docs also sign the timestamp verbatim).
- Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet with padding),
  carried bare in the header — no `sha256=` prefix.
- Key: the webhook's signing secret as its UTF-8 bytes, **not** decoded. The
  docs' reference code keys the HMAC with the secret string verbatim
  (`crypto.createHmac("sha256", SIGNING_SECRET)`); Zendesk never publishes the
  raw key bytes, only the opaque secret string, so decoding it would be an
  unsupported inference.
- Replay protection: the timestamp is HMAC-covered, so the shared symmetric
  `|now - t| > max_age` (default 300s) semantics apply, as with Twitch and
  PayPal; it is parsed through the same shared RFC 3339 parser (with the
  `T`/`Z` separators case-insensitive per the RFC 3339 §5.6 note). Zendesk's
  docs only demonstrate the checksum comparison and do not
  prescribe a window; applying the shared window is strictly stronger.
- Test-vector provenance: Zendesk's docs publish example headers and a static
  test-webhook secret
  (`dGhpc19zZWNyZXRfaXNfZm9yX3Rlc3Rpbmdfb25seQ==`, decoding to
  `this_secret_is_for_testing_only`) but no byte-exact example signature over a
  body, so vectors are locally constructed against exactly the documented
  construction (`timestamp` + raw body, keyed verbatim with that static secret,
  base64-encoded): the timestamp mirrors the example on the anatomy page.
  Constructed and cross-checked across OpenSSL and Python's `hmac` module.
  Replace them if Zendesk ever publishes fixed vectors.

### WorkOS

Source: <https://workos.com/docs/events/data-syncing/webhooks> ("Sync data
with webhooks" — the manual-verification section), corroborated by the
official SDKs' webhook verifiers (e.g. `workos-go`'s `WebhookVerifier`) and
the SDK reference documentation
(<https://workos-workos-node.mintlify.app/api/webhooks>: the
`workos-signature` header value is "in format `t=,v1=`").

- Header: `WorkOS-Signature: t=<epoch_ms>,v1=<hex_hmac>` — a comma-separated
  `key=value` list. The docs: "There are two values to parse from the
  `WorkOS-Signature` header, delimited by a `,` character." `t` is the
  `issued_timestamp` — **epoch milliseconds** (13 digits), not seconds —
  `v1` is the HMAC-SHA256 signature over `{t}.{raw_body}` and is the only
  scheme defined.
- Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears in
  the header (sub-second digits included), a literal dot, then the raw request
  body bytes, unmodified (the docs build "`issued_timestamp`, the `.`
  character, the request's body as a utf-8 decoded string" and warn that
  parsing the body before signing breaks the signature).
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded, keyed by the
  webhook signing secret as a plain UTF-8 string ("using the webhook secret as
  the key" — never decoded, matching the SDK verifiers).
- Timestamp validation routes through the shared pure-ASCII-digit
  epoch-milliseconds parser (`parse_millis`, the same shape rules HubSpot's
  millisecond timestamp uses): sign-prefixed, whitespace-padded, empty, or
  overflowing values fail closed as `MalformedHeader`.
- Replay protection: WorkOS's SDKs take a tolerance window in **seconds**
  (their defaults are "usually 3–5 minutes"; the PHP SDK's example passes
  `180`, the .NET example `300`), so the shared symmetric
  `|now - t| > max_age` (default 300s) semantics apply, as with Slack, Zoom,
  Cloudflare, Coinbase, and HubSpot. Because `t` is epoch milliseconds, the
  parsed value is floored to whole seconds (`millis / 1000`) before the shared
  check — identical treatment to HubSpot's `X-HubSpot-Request-Timestamp`; the
  sub-second truncation error (< 1s) is negligible against any configured
  window. The future-dated half of the symmetry is stricter than the SDKs
  enforce but cannot reject legitimate deliveries.
- Duplicate `t` or `v1` elements are rejected as ambiguous (`spec.md` §4.4) —
  never first-wins; unknown elements are discarded for forward compatibility.
  The docs define exactly two comma-delimited elements, so a duplicate
  signature element is treated as malformed rather than rotation, matching the
  Coinbase treatment of its single `v0` field (Mux's rotation-list acceptance
  exists only because its docs/SDKs explicitly define multiple `v1` values).
- Test-vector provenance: WorkOS publishes no byte-exact example signature, so
  vectors are locally constructed over exactly the documented construction
  (`{t}.{raw_body}`, HMAC-SHA256 hex against the docs' manual-verification
  recipe), cross-checked with OpenSSL. The `t` value is a deliberate
  non-round millisecond timestamp so the sub-second-truncation boundary is
  exercised by the primary vector. The SDK reference's sample header
  (`t=1234567890,v1=...`) is replayed as a well-formed-but-mismatching input.
  Replace them if WorkOS ever publishes fixed vectors.

### WooCommerce

Source: <https://developer.woocommerce.com/docs/apis/rest-api/v3/webhooks> (the
delivery-header reference lists `X-WC-Webhook-Signature` as "a base64 encoded
HMAC-SHA256 hash of the payload") and the `WC_Webhook::generate_signature`
reference implementation
(<https://woocommerce.github.io/code-reference/classes/WC-Webhook.html>:
"Generate a base64-encoded HMAC-SHA256 signature of the payload body ... Note
that the signature is calculated after the body has already been encoded").

- Header: `X-WC-Webhook-Signature: <base64_hmac>` (lookup is case-insensitive)
- Signed string: raw body bytes, unmodified — the reference implementation
  signs the already-encoded body, so the received bytes are what must be hashed
- Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet with padding) —
  not hex, the same base64 bug class as Shopify and Xero
- Key: the webhook's configured `secret` as its UTF-8 bytes, used verbatim
  (WooCommerce never base64/hex-decodes it)
- No timestamp in the signature scheme (`max_age` has no effect); WooCommerce's
  own guidance is to respond quickly and dedupe on the payload's `id`, which is
  outside this crate's scope (payload parsing is a non-goal, §1)
- Test-vector provenance: WooCommerce's docs and reference implementation
  describe the construction but publish no byte-exact example signature, so the
  implementation is validated against locally constructed, deterministic
  vectors over exactly the documented recipe, cross-checked with OpenSSL.
  Replace them if WooCommerce ever publishes fixed vectors.

### Calendly

Source:
<https://developer.calendly.com/api-docs/overview/webhooks/webhook-signatures>
("Webhook Signatures": the `Calendly-Webhook-Signature` header format, the
`t + '.' + request.body` signed-string construction, the HMAC-SHA256 recipe,
and the 3-minute replay-tolerance example), corroborated by the webhook
subscription guide
(<https://developer.calendly.com/docs/api-guides/receive-data-from-scheduled-events-in-real-time-with-webhook-subscriptions>).

- Header: `Calendly-Webhook-Signature: t=<unix_ts>,v1=<hex_hmac>` — a
  comma-separated `key=value` list. `t` is the integer unix-seconds value set
  by the server; `v1` is the HMAC-SHA256 signature over `{t}.{raw_body}` and is
  the only scheme the docs define.
- Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears in
  the header, a literal dot, then the raw request body bytes, unmodified (the
  docs' reference implementations concatenate `t + '.' + request.body` and warn
  that parsing the JSON payload before verification breaks the signature).
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded, carried bare in
  the header (no `sha256=` prefix).
- Key: the subscription's webhook signing key as a plain UTF-8 string (never
  decoded), matching the docs' reference implementations.
- Timestamp validation routes through the shared pure-ASCII-digit parser:
  sign-prefixed (`t=+1700000000`), whitespace-padded, empty, or overflowing
  values fail closed as `MalformedHeader`.
- Duplicate `t` or `v1` elements are rejected as ambiguous (`spec.md` §4.4) —
  never last-wins like the docs' reference code. Calendly's docs define exactly
  one signature element and no rotation window, so a second `v1=` is treated as
  malformed rather than rotation (matching the WorkOS/Coinbase treatment of
  their single signature fields). Unknown elements are discarded for forward
  compatibility.
- Replay protection: Calendly's docs demonstrate a 180-second tolerance
  (`three_minutes = 180`), so the shared symmetric `|now - t| > max_age`
  semantics apply; the crate default is 300s and callers wanting the documented
  zone set `max_age` to 180s explicitly. The future-dated half of the symmetry
  is stricter than the docs' examples enforce but cannot reject legitimate
  deliveries.
- Test-vector provenance: Calendly publishes the example header
  (`t=1492774577,v1=5257a869...b8bd`) but no body or signing key, so the
  implementation is validated against locally constructed, deterministic
  vectors over exactly the documented construction, cross-checked across
  OpenSSL and Python. The docs' published example header is replayed as a
  well-formed-but-mismatching input. Replace them if Calendly ever publishes
  fixed vectors.

### Klaviyo

Source:
<https://developers.klaviyo.com/en/docs/working_with_system_webhooks>
("Working with system webhooks" — the `Klaviyo-Signature`/`Klaviyo-Timestamp`/
`Klaviyo-Webhook-Id` request-header reference, the HMAC-SHA256 recipe, the
reference Python verifier that hashes the body and then updates the HMAC with
the timestamp string, and the example delivery used below).

- Headers: `Klaviyo-Signature`, `Klaviyo-Timestamp` (IMF-fixdate / RFC 1123,
  e.g. `Thu, 04 Jan 2024 18:05:25 GMT`), and `Klaviyo-Webhook-Id`. Only the
  signature and timestamp participate in the HMAC; the webhook id is not part
  of the signed material.
- Signed string: `"{raw_body}{timestamp}"` — the raw request body bytes
  unmodified, then the `Klaviyo-Timestamp` value exactly as it appears in its
  header (concatenated, no separators). The docs' reference code computes
  `hmac.new(secret, body)` and then `update(timestamp.encode())`; the numeric
  grammar of the timestamp is never re-serialized into the signed bytes.
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded (lowercase),
  carried bare in the header (no `sha256=` prefix).
- Key: the webhook's signing secret as a plain UTF-8 string, never decoded —
  matching the docs' reference `hmac.new(hmac_secret, ...)`.
- Timestamp validation routes through a strict IMF-fixdate parser
  (RFC 7231 §7.1.1.1, RFC 1123 four-digit-year spelling only): exactly 29
  characters, a weekday name that must also match the date (as Go's
  `time.Parse` and the `httpdate` crate enforce), a valid calendar day
  (leap-year aware), 00–59 hour/minute/second (IMF-fixdate has no leap-second
  `60`), a literal `GMT` designator, and a non-negative unix instant.
  Anything else — including the RFC 3339 spelling, non-`GMT` zones, and the
  two-digit-year variants — fails closed as `MalformedHeader`.
- Replay protection: the timestamp is HMAC-covered, so the shared symmetric
  `|now - t| > max_age` window applies. Klaviyo's docs prescribe no freshness
  window; the crate default 300s is strictly stronger than their sample code
  and cannot reject a legitimate delivery.
- `Klaviyo-Webhook-Id` is intentionally not verified: binding it requires
  deserializing the body's `meta.klaviyo_webhook_id`, which is a non-goal
  (§1). Callers should perform that pair check after `verify()` succeeds,
  reading the header via the crate's public
  `klaviyo::WEBHOOK_ID_HEADER` constant (with `klaviyo::SIGNATURE_HEADER`
  and `klaviyo::TIMESTAMP_HEADER` for the HMAC-covered headers).
- Test-vector provenance: Klaviyo publishes the example delivery
  (`Klaviyo-Signature: e6c00e31...912d1`, `Klaviyo-Timestamp:
  Thu, 04 Jan 2024 18:05:25 GMT`, `Klaviyo-Webhook-Id: a8b89045...3ecb`) but no
  body or signing key, so the implementation is validated against locally
  constructed, deterministic vectors over exactly the documented
  construction, cross-checked with OpenSSL and Python. The docs' published
  example delivery is replayed as a well-formed-but-mismatching input.
  Replace them if Klaviyo ever publishes fixed vectors.

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
- Used by Svix, Clerk, Resend, GitLab (webhook "signing token", GitLab 19.0+ —
  GitLab states its webhook delivery "follows the Standard Webhooks
  specification"; source: <https://docs.gitlab.com/user/project/integrations/webhooks>),
  and a growing list of adopters — implementing this once covers all of them.

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
   repeats are not ambiguous and verify normally. For built-in providers the
   scan covers every header the scheme declares; for `Custom` providers the
   scan covers only `signature_header` and `timestamp_header` — if the
   user's `signed_string` closure reads additional headers, duplicates in
   those are **not** detected (see `CustomScheme` docs).
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
   panics/hangs on adversarial input. The multi-secret `verify_any` rotation
   path is fuzzed through the same target with empty, garbage-then-well-formed,
   and all-garbage secret slices so its error-aggregation loop (per-secret
   `InvalidSecret` tracking, `SignatureMismatch` aggregation, structural-error
   short-circuit) gets the same guarantee.
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
   --ignored`. Ships in CI as a non-blocking informational job
   (`.github/workflows/ci.yml`).*

---

## 6. CI requirements

- `cargo test --all-features` on stable, MSRV, and beta.
- `cargo clippy --all-features -- -D warnings`.
- `cargo test --no-default-features --features sendgrid,paypal` on stable, so
  the `no_std + alloc` paths (the wall-clock fallback in [`Clock::now`], the
  `std::error::Error`-less [`VerifyError`], and the `no_std` re-exports) are
  behaviorally covered rather than only build-checked for wasm32. Shipped as
  the `test-nostd` CI job (`.github/workflows/ci.yml`), paired with the `http`
  run below.
- `cargo test --no-default-features --features http` on stable as the twin
  of the run above: the `http` feature's crate (`http`) requires `std`
  itself, so the feature is std-bounded in practice (like `paypal`, §3, §7) —
  but the crate's own `http`-path code (the `http::HeaderMap` impl in
  §2 and its `verify()` end-to-end tests) must stay `no_std`-clean: it
  compiles and runs with the crate's own `std` feature off, catching a
  `std`-leak regression in *this crate's* `http` code even though the
  `http` dependency ships `std` regardless. This is a behavioral catch for
  the crate's own code, not a std-less build proof.
- `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`, so a broken
  intra-doc link is caught before merge instead of silently degrading the
  user-facing docs. (docs.rs itself builds with `-D warnings`, so a broken link
  still fails the docs.rs build; shipped as the `doc` CI job,
  `.github/workflows/ci.yml`.)
- `cargo fuzz build` (build-only in normal CI; timed fuzz runs in a
  scheduled nightly job).
- A grep-based CI backstop (`secret-leak-grep`) that fails the build if any
  of `println!`, `print!`, `eprintln!`, `eprint!`, `dbg!`, `log::`, or
  `tracing::` appears anywhere in `src/` — not just inside a `Secret`'s
  scope — so no code path, release or test, can print secret material into a
  log, error message, or panic message (supplemented by the `Secret` type's
  own redacted `Debug`/`Display` impls as the primary defense). Because the
  grep covers all of `src/`, a macro used inside `#[cfg(test)]` is still a
  build failure; there is no allowlist — the acceptable releases are the
  `Secret`/`VerifyError`/`VerifyOptions` redaction impls themselves.
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
  (2026-09) behind `features = ["paypal"]`** — `X509Certificate`
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
  RustCrypto dependencies (`p256`, optional, genuinely `no_std`-compatible —
  the `sendgrid` feature builds for a std-less target; `rsa` +
  `x509-parser` + `crc32fast` behind the `paypal` feature — see the crate's
  `Cargo.toml`). The `paypal` feature is **std-bounded in practice**:
  `x509-parser` pulls `der-parser` and `nom` with their default features,
  re-enabling `std` in `num-traits`/`num-bigint`/`memchr`, and Cargo's union
  feature-unification means this crate's `default-features = false` edge
  cannot revoke those, so `--no-default-features --features sendgrid,paypal`
  fails for a genuinely std-less target inside `num-traits` (invisible to
  the wasm32 gate, which ships std). The `no_std + alloc` scope is core +
  `sendgrid` (§3). The
  optional `webhook-verify-fetch` companion crate remains future work if
  automated key rotation handling is ever requested — it stays out of this
  crate either way.

- **Secret rotation UX.** *Resolved (2026-09).* Stripe/Standard
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
  `wasm-bindgen`, is a plausible real use case). *Implemented:
  the core is `no_std + alloc` behind the `std` feature (default on). Building
  with `--no-default-features` drops the wall clock: [`Clock::now`] returns
  unix seconds directly (no `SystemTime`), [`SystemClock`] is `std`-only, and
  [`VerifyError`] does not implement `std::error::Error`. Callers on
  bare-metal/wasm targets supply their own [`Clock`] for timestamped
  (replay-protected) providers; a missing clock reads 0 and fail-closes replay
  checks. The wasm32 regression job ships in CI
  (`.github/workflows/ci.yml`); it build-checks `cargo build
  --no-default-features --features sendgrid,paypal --target
  wasm32-unknown-unknown` and `cargo build --no-default-features --features
  http --target wasm32-unknown-unknown` on the same matrix (issue #25,
  parity with the `test-nostd` runs). The full test suite runs against the
  `--no-default-features`
  build on the host (`cargo test --no-default-features --features
  sendgrid,paypal` and — for the crate's own `http`-path code —
  `cargo test --no-default-features --features http`, §6) via the
  `test-nostd` CI job (`.github/workflows/ci.yml`). The `http` and `paypal`
  features are both **std-bounded in practice**: the `http` crate itself
  requires `std` (its `lib.rs` contains `compile_error!("std feature
  currently required, support for no_std may be added later")`), and
  `x509-parser`'s transitive defaults force `std` for `paypal` (issue #23).
  Neither feature can be included in a genuinely std-less build; the wasm32
  gate proves the core + `sendgrid` build compiles with std present, and the
  host `test-nostd` run verifies the crate's own code with the crate's `std`
  feature off — the real std-less proof is the `sendgrid`+core-only
  `riscv32imac-unknown-none-elf` build (see the Cargo.toml feature comments
  and the §3 paypal row). That build is CI-gated by the `no-std-riscv` job
  (`.github/workflows/ci.yml`): `cargo build --no-default-features
  --target riscv32imac-unknown-none-elf` (pure core) and `cargo build
  --no-default-features --features sendgrid --target
  riscv32imac-unknown-none-elf` both run on every PR, so a dependency or
  code change that leaks `std` into the `no_std + alloc` scope fails CI. The
  `no_std + alloc` scope covers the core
  verification path + `sendgrid` only: the `tower` and `actix` adapters are
  std-only framework glue and therefore imply the `std` feature when enabled —
  a `default-features = false` build with either of them simply gets `std`
  back, which keeps the combination compiling instead of surfacing raw
  `cannot find crate std` errors. Issue #23 closed as resolved-by-design;
  the `http` feature's `std`-bound is the same class of dependency-forced
  `std`.*
- **PayPal feature is intentionally `std`-bounded (design decision,
  2026-09).** *Resolved per the alternative framing in issue #23.* The
  issue's literal fix — declaring direct `num-traits`/`memchr` edges with
  `default-features = false` behind `paypal` — was checked and **cannot
  work**: Cargo's feature union is monotonic (an edge with
  `default-features = false` contributes no features but cannot *revoke*
  features other edges enable), and the std pulls are both broader and
  deeper than the issue's premise. Verified against the resolved tree for
  `--no-default-features --features paypal`:
  1. **The premise about `rsa 0.9.10` in issue #23 is wrong**: `rsa` already
     declares its `num-traits` edge with `default-features = false`, and so
     does `num-bigint-dig` (its edge enables only `i128`). Neither crate
     leaks `std`.
  2. The real enablers are `x509-parser`'s own transitive defaults:
     `der-parser` (`default = ["std"]`, pulls `num-traits`/`num-bigint`
     `std`), `asn1-rs` (`default` includes `std`), and `nom` (`default =
     ["std"]`, via `memchr/std`).
  3. Beyond the `num-*`/`memchr` layer there is `lazy_static` — an
     unconditional, `std`-only `x509-parser` dependency — so the
     whack-a-mole has no bottom without forking/patching `x509-parser`'s
     dependency graph.
  Ruling: no feature surgery (`paypal` does **not** gain `"std"` in its
  feature list — that would silently change the semantics of
  `--no-default-features --features paypal` and defeat the no_std behavioral
  coverage §6 relies on) and no `build.rs` guard (a build script cannot
  portably detect whether the *target* ships std). Instead the std-bound is
  documented in §3 (PayPal row) and `Cargo.toml`, and the `no_std + alloc`
  guarantee (§1) is core + `sendgrid` only. The honest acceptance check is
  `cargo build --no-default-features --features paypal --target
  riscv32imac-unknown-none-elf` failing inside `num-traits` with a clear
  `can't find crate std`; the wasm32 CI gate proves the core + `sendgrid`
  build is real, and is intentionally not extended to `paypal`. Issue #23
  closed as resolved-by-design.
- **Provider promotion criteria.** A `CustomScheme` recipe gets promoted to
  a first-class `Provider` variant once it has (a) official test vectors,
  (b) at least one external user request or contribution, and (c) no open
  design question from §7 blocking it.
