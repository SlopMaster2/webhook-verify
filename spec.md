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
    Contentful,
    Box,
    Intercom,
    Expo,
    Meta,
    HubSpot,
    Klaviyo,
    Mandrill,
    Line,
    Shopify,
    Slack,
    Square,
    Tally,
    Twilio,
    Twitch,
    Typeform,
    Discord,
    PayPal,
    SendGrid,
    Paystack,
    Paddle,
    PagerDuty,
    Pusher,
    Linear,
    LaunchDarkly,
    Notion,
    Nylas,
    Zoom,
    Cloudflare,
    CircleCi,
    Coinbase,
    Dropbox,
    DocuSign,
    Fintoc,
    Razorpay,
    Ripple,
    LemonSqueezy,
    Xero,
    Sentry,
    Adyen,
    Mux,
    Zendesk,
    WorkOS,
    WooCommerce,
    Calendly,
    Vercel,
    X,
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
    /// (currently Square, Twilio, HubSpot, Contentful, Mandrill). See §3.
    pub request_url: Option<String>,
    /// HTTP request method (uppercase, e.g. `POST`), for schemes that sign
    /// the method into their source string (currently HubSpot's v3 scheme
    /// and Contentful). Must match the method the provider actually sent for
    /// the delivery. No effect on providers that do not sign the method. See §3.
    pub request_method: Option<String>,
    /// Parsed `application/x-www-form-urlencoded` fields, required by
    /// schemes that sign form fields rather than the raw body
    /// (currently Twilio, Mandrill). Pass every field as received; sorting
    /// into signing order happens here. See §3.
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
    // ("github", "GitHub", "GITHUB", ...), plus the space-separated and
    // hyphenated human-readable forms for the multi-word-name variants
    // ("lemon squeezy"/"lemon-squeezy" → LemonSqueezy,
    // "standard webhooks"/"standard-webhooks" → StandardWebhooks,
    // "hub spot"/"hub-spot" → HubSpot, "pager duty"/"pager-duty" →
    // PagerDuty, "circle ci"/"circle-ci" → CircleCi, "woo commerce"/
    // "woo-commerce" → WooCommerce, "launch darkly"/"launch-darkly" →
    // LaunchDarkly). Brand aliases are also accepted: StandardWebhooks
    // takes "svix"/"resend" (adopters that sign deliveries with the same
    // scheme), Mandrill takes "mailchimp"/"mailchimp transactional"/
    // "mailchimp-transactional" (its current brand name), and X takes
    // "twitter"/"x twitter"/"x-twitter" (its pre-rebrand name, per §3).
    // `custom` is rejected: a CustomScheme requires configuration and
    // must be built directly.
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

### Contentful

Source: <https://www.contentful.com/developers/docs/webhooks/request-verification/>
("Webhook request verification", the canonical-string pseudo-code and the
"Can be used to ensure a TTL" guidance for the timestamp), the canonicalizing
helpers in Contentful's official reference SDK
(<https://github.com/contentful/node-apps-toolkit>,
`src/requests/sign-request.ts` and `verify-request.ts`), and Contentful's
official request-verification examples
(<https://github.com/contentful-labs/request-verification-examples>,
`rust/src/main.rs`). The docs page's pseudo-code is the normative contract;
the SDK and reference examples disambiguate its details.

- Headers: `x-contentful-signature` (`<hex_hmac>`), `x-contentful-signed-headers`
  (comma-separated list of the header names included in the signature),
  `x-contentful-timestamp` (unix epoch **milliseconds**). All three are present
  on every signed delivery; a space without a configured webhook signing secret
  sends none, so `verify()` reports `MissingHeader`.
- Signed string: `[method, requestPath, headers, requestBody].join('\n')`.
  `headers` is, for each name in `x-contentful-signed-headers` in list order,
  `{lowercase_name}:{value_as_sent}`, joined by `;`. The list is
  **self-describing** — it arrives with the request, and whatever (and
  whichever order) it names is what was signed. Every name it lists must be
  present in the request; a list referencing an absent header fails closed as
  `MalformedHeader`.
- Ambiguity scan carve-out: because the signed-header list is self-describing,
  the framework adapters' duplicate-ambiguity scan (§4.4) statically covers
  only the three fixed headers (`x-contentful-signature`,
  `x-contentful-signed-headers`, `x-contentful-timestamp`). Additional headers
  the list names at delivery time are read first-match and folded into the
  canonical string; duplicate-conflicting values in *those* are not detected
  by the adapter — the same carve-out granted to `CustomScheme`'s closure-read
  headers. Verification always uses the first value, matching what
  `http`/`actix` handlers read via `.get()`.
- Path encoding: the docs' pseudo-code url-encodes only the *query* portion
  (`query = urlEncode(query)`), with the pathname used as its UTF-8 bytes.
  The crate implements exactly that: the query's percent-encoding uses
  JavaScript's `encodeURIComponent` unescaped set (`A-Z a-z 0-9 - _ . ! ~ * '
  ( )`), each other byte as `%XX` uppercase, applied exactly once. The
  scheme/`userinfo`/host of a full `request_url` never enter the signed string;
  a bare path (`/webhooks/...`) is used verbatim. `#fragment` is dropped.
  (Deliberately *not* replicated: the reference SDK's double-encode corner
  when the caller passes an already percent-encoded query.)
- Algorithm: HMAC-SHA256, hex-encoded (lowercase). Key: the space's
  64-character webhook signing secret, used as its UTF-8 bytes verbatim.
  Documented secret class: `^[0-9a-zA-Z+/=_-]+$`, 64 characters.
- Context: `request_method` and `request_url` are required
  (`VerifyOptions`); omitting either fails closed as `MissingContext` — the
  method and request path are the first two elements of the canonical string.
- Replay protection: `x-contentful-timestamp`, epoch **milliseconds**, is
  recency-checked through the shared symmetric `max_age` window with the
  sub-second remainder dropped (`millis / 1000`, as the SDK's integer division
  does). Contentful's own `verifyRequest` SDK defaults to a 30s TTL; the crate
  applies the shared default 300s window unless `max_age` is tightened.
  Contentful's signer includes the timestamp among the signed headers, making
  that window HMAC-covered; if a delivery's list omits the timestamp header
  the window is best-effort rather than cryptographic (same documented caveat
  as `CustomScheme`), and the timestamp is still recency-checked.
- Test-vector provenance: Contentful publishes no frozen numeric signature
  example. The vectors in the provider tests are locally constructed over the
  documented recipe above, produced by an independent implementation (Python
  `hmac` reimplementing the docs' pseudo-code and the SDK's canonical
  construction) — see the module docs. The canonical string shapes in the
  reference examples (`rust/src/main.rs`) were reproduced first to pin the
  recipe.

### Box

Source: <https://developer.box.com/guides/webhooks/v2/signatures-v2> ("Verify
Box webhook signatures") and the reference implementation in Box's Java SDK
(the `BoxWebhookSignatureValidator` class and the `WebhookValidationTest`
test class, <https://github.com/box/box-java-sdk/blob/main/doc/webhooks.md>).

- Headers: `BOX-DELIVERY-TIMESTAMP`, `BOX-SIGNATURE-PRIMARY`,
  `BOX-SIGNATURE-SECONDARY`. Box sends **two** signatures on every delivery —
  one per configured key (primary/secondary) — so rolling from one key to the
  other needs no downtime: a delivery verifies when **either** signature
  header matches the single `Secret` the caller holds. Both headers are
  required; Box always sends both, and requiring both means an attacker who
  knows only one key cannot strip the other header to dodge a mismatch.
- Signed string: `{raw_body}{delivery_timestamp}` — the raw body bytes
  concatenated with the `BOX-DELIVERY-TIMESTAMP` header value **exactly as
  sent** (no separators; the timestamp's `-07:00`-style offset spelling is
  part of the signed bytes and must never be re-serialized). Box's reference
  implementation concatenates `payload || deliveryTimestamp`.
- Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet, padded),
  carried bare (no prefix). Key: the primary/secondary webhook signing key as
  its UTF-8 string bytes, verbatim (never base64-decoded).
- Replay protection: the timestamp is HMAC-covered, so the shared symmetric
  `max_age` window (default 300s) applies. Box's docs recommend a ten-minute
  window; the crate's default is strictly stronger (an attacker cannot
  freshen a captured delivery), and callers wanting Box's prescribed window
  can set `VerifyOptions::max_age` to 600s.
- The optional metadata headers `BOX-SIGNATURE-VERSION` (`1`) and
  `BOX-SIGNATURE-ALGORITHM` (`HmacSHA256`) are validated only when present;
  a present-but-wrong value fails closed as `MalformedHeader`, mirroring the
  reference validator's refusal to accept an unexpected algorithm.
  `BOX-DELIVERY-ID` is opaque and ignored.
- Test-vector provenance: the reference test publishes the byte-exact body,
  timestamp, and per-key signatures; the secrets it actually keys with are
  `SamplePrimaryKey`/`SampleSecondaryKey`. (The keys the docs *display* —
  `4py2I9eSFb0ezXH5iPeQRcFK1LRLCdip` / `Aq5EEEjAu4ssbz8n9UMu7EerI0LKj2TL` —
  do not reproduce the published signatures.) Boundary, tamper, and
  replay-window vectors are locally constructed over the documented recipe,
  cross-checked with `openssl dgst`.

### Intercom

Source: <https://developers.intercom.com/docs/references/2.5/webhooks/webhook-models>
(Intercom's "Webhook Topics" reference, "Signing notifications"): the
`X-Hub-Signature` header format, the raw-body signing rule, and the
`client_secret` keying are all documented on the official page; the docs also
publish an example header value (`sha1=21ff2e149e0fdcac6f947740f6177f6434bda921`)
alongside a sample delivery.

- Header: `X-Hub-Signature: sha1=<hex_hmac>` — "the hexadecimal (40-byte)
  representation of a SHA-1 signature computed using the HMAC algorithm as
  defined in RFC2104", prefixed with the literal `sha1=`.
- Signed string: the raw body bytes of the JSON request, unmodified — the docs
  stress that the signature is computed over "the body of the JSON request",
  i.e. exactly what Intercom delivers, so re-serializing or reformatting the
  payload (JSON key order, whitespace, escapes) changes the signature.
- Algorithm: HMAC-SHA1, hex-encoded (lowercase hex from Intercom; decoding is
  case-insensitive, matching every other hex provider). Intercom is, like
  Twilio, a scheme that still legitimately mandates SHA-1 — the HMAC is keyed
  with the shared secret, so SHA-1's collision attacks do not apply.
- Key: the app's `client_secret` (Developer Hub → Basic Info) as its UTF-8
  bytes verbatim.
- The `sha1=` prefix is matched case-sensitively, exactly like GitHub's and
  Bitbucket's `sha256=`: Intercom's docs and examples emit only the literal
  lowercase form, and an unknown scheme fails closed as `MalformedHeader`
  rather than silently mis-verifying.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub and Bitbucket. Intercom signs every webhook delivery, so a request
  without the header is never a legitimate delivery and `verify()` reports
  `MissingHeader`.
- Test-vector provenance: Intercom publishes the header format and an example
  header value, but no byte-exact signed body (the example header sits next to
  a sample delivery whose body is illustrative, and the `client_secret` is
  account-specific), so the vectors are locally constructed over exactly the
  documented construction (`sha1=` + lowercase hex of
  `HMAC-SHA1(client_secret, raw_body)`), cross-checked with `openssl dgst`
  and Python's `hmac` module. Replace them if Intercom ever publishes fixed
  vectors.

### Expo (EAS)

Source: <https://docs.expo.dev/eas/webhooks/> (Expo's official EAS webhooks
page, source in the `expo/expo` repo at `docs/pages/eas/webhooks.mdx`): the
`expo-signature` header, the raw-body signing rule ("the signature is a
hex-encoded HMAC-SHA1 digest of the request body, using your webhook secret as
the HMAC key"), the 16-character secret minimum, and the reference constant-time
verification sample — which compares the header against `sha1=${hmac.digest('hex')}`,
i.e. the `sha1=` prefix is part of the wire value.

- Header: `expo-signature: sha1=<hex_hmac>` — the sample's `<hash>` is
  `sha1=${hmac.digest('hex')}` over the raw body, so the value is the literal
  `sha1=` followed by the lowercase hex digest. Expo does **not** sign a
  timestamp, so replay protection cannot be provided at the signature layer
  (`max_age` has no effect).
- Signed string: the raw request body bytes, unmodified — the reference sample
  feeds the exact body text (`bodyParser.text({ type: '*/*' })` then
  `hmac.update(req.body)`) into a constant-time comparison, so any
  reformatting or re-encoding of the payload changes the signature. Callers
  must pass the untouched request bytes.
- Algorithm: HMAC-SHA1, hex-encoded (lowercase hex from Expo; decoding here is
  case-insensitive, matching every other hex provider). Expo, like Intercom and
  Twilio, still legitimately mandates SHA-1 — the HMAC is keyed with the shared
  webhook secret, which HMAC's keyed use makes immune to SHA-1's collision
  attacks.
- Key: the webhook signing secret chosen with `eas webhook:create` (at least 16
  characters per the docs) as its UTF-8 bytes verbatim.
- The `sha1=` prefix is matched case-sensitively, exactly like Intercom's
  `X-Hub-Signature` and GitHub's/Bitbucket's `sha256=`: Expo's docs and sample
  emit only the literal lowercase form, and an unknown scheme fails closed as
  `MalformedHeader` rather than silently mis-verifying.
- Covers EAS Build and EAS Submit webhook deliveries (the only two events EAS
  signs).
- Test-vector provenance: Expo documents the construction and ships a
  reference verification sample, but publishes no byte-exact example signature
  (the sample's secret is operator-chosen), so the vectors are locally
  constructed over exactly the documented construction (`sha1=` + lowercase
  hex of `HMAC-SHA1(secret, raw_body)`), cross-checked with `openssl dgst`
  and Python's `hmac` module. Replace them if Expo ever publishes fixed
  vectors.

### Meta

Source: <https://developers.facebook.com/docs/graph-api/webhooks/getting-started>
(Meta for Developers, "Validating payloads") and the WhatsApp Cloud API
endpoint walkthrough
(<https://developers.facebook.com/documentation/business-messaging/whatsapp/webhooks/create-webhook-endpoint>,
"To validate the request" — the same `X-Hub-Signature-256` algorithm across
Graph API, Messenger Platform, Instagram, and WhatsApp Cloud API, with an
example header value). The Messenger Platform docs also carry the reference
verifier (`verifyRequestSignature`, computing `createHmac("sha256",
appSecret).update(buf).digest("hex")` over the raw body).

- Header: `X-Hub-Signature-256: sha256=<hex_hmac>` — the literal `sha256=`
  prefix followed by the lowercase hex HMAC-SHA256 digest of the raw payload,
  identical in shape to GitHub's header but keyed by the Meta **App Secret**
  (notably distinct from the legacy SHA-1 `X-Hub-Signature` header, which
  this crate does not read).
- Signed string: the raw request body bytes, unmodified. Meta documents that it
  signs the payload's *escaped-unicode* serialization (`äöå` is signed as
  `\u00e4\u00f6\u00e5`), so a reparsed/re-serialized JSON value — which
  switches between escaped and literal encodings — will not match. Passing the
  untouched wire bytes (`spec.md` §4) is exactly what this crate does; for
  ASCII-only JSON the escaped-unicode form is byte-identical to the raw body.
- Algorithm: HMAC-SHA256, hex-encoded (lowercase hex from Meta; decoding is
  case-insensitive, matching every other hex provider).
- Key: the app's App Secret (App Dashboard → App settings → Basic) as its
  UTF-8 bytes verbatim.
- The `sha256=` prefix is matched case-sensitively, exactly like GitHub's:
  Meta's docs and samples emit only the literal lowercase form, and an unknown
  prefix fails closed as `MalformedHeader`.
- No timestamp in the signature scheme (`max_age` has no effect): Meta's
  payloads carry no freshness marker, so replay protection cannot be provided
  at the signature layer — mirroring GitHub/Bitbucket.
- Test-vector provenance: Meta publishes the header format, the algorithm, and
  an example header value (`sha256={super-long-SHA256-signature}`), but no
  byte-exact signed body+key pair (the App Secret is account-specific), so the
  vectors are locally constructed over exactly the documented construction
  (`sha256=` + lowercase hex of `HMAC-SHA256(app_secret, raw_body)`),
  cross-checked with `openssl dgst` and Python's `hmac` module. The primary
  vector's body mirrors the shape of a WhatsApp Cloud API `messages` delivery.
  Replace them if Meta ever publishes fixed vectors.

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
  `VerifyOptions::request_url` (one of the two schemes that sign the HTTP
  method into their source string — Contentful's canonical string also leads
  with it; the method must match what the provider actually sent). Missing or
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

### DocuSign

Source: <https://developers.docusign.com/platform/webhooks/connect/validate/>
("How to validate an HMAC signature": the raw-body/line-endings signing rule
and the base64 encoding), <https://developers.docusign.com/platform/webhooks/connect/hmac/>
("HMAC security for Docusign Connect": one numbered header per configured key,
`-1`/`-2`/... up to 100), and the official verification samples
(<https://www.docusign.com/blog/developers/hmac-verification-php>;
<https://www.docusign.com/blog/developers/manually-authenticating-hmac-signatures-docusign-connect-webhook-configurations>).

- Header: `X-Docusign-Signature-1: <base64(HMAC-SHA256(key, raw_body))>` — a
  bare base64 digest, no prefix. One numbered header is sent per configured
  HMAC key (`-1`, `-2`, ...); DocuSign accepts validation against any of
  them.
- Signed string: raw body bytes, unmodified — the docs are explicit that "the
  entire body of the POST request is used, including line endings" and that
  the signature must be verified before the body is parsed.
- Algorithm: HMAC-SHA256, base64-encoded (standard alphabet with padding).
  Key: the Connect configuration HMAC key as its UTF-8 bytes, verbatim. The
  docs note that stray `"` characters copied into the secret must be removed
  before computation; this crate uses the configured `Secret` exactly
  (`spec.md` §2).
- **Single-header scope:** this provider verifies `X-Docusign-Signature-1`
  — the first-listed currently-active key. The `-1` header ships on every
  delivery (there is one header per key), so a single-key account — the
  integration DocuSign's own guides recommend — always signs `-1`. Numbered
  headers beyond `-1` are not read (crate's single-header model, `spec.md`
  §1); during rotation, keep the first-listed key valid on each receiver or
  re-verify via `verify_any` once the rotated key holds the `-1` slot.
  The companion `x-authorization-digest` header (`HMACSHA256`) is
  informational, not HMAC-covered, and is not parsed — a future algorithm
  change fails closed as a signature mismatch.
- No timestamp in the signature scheme (`max_age` has no effect).
- Test-vector provenance: DocuSign's docs publish the algorithm, header
  layout, and reference code but **no byte-exact example body+signature
  pair** (the "Validate" guide steers integrators to verify against a live
  delivery via Postman). The vectors are therefore locally constructed over
  exactly the documented raw-body + base64 construction and cross-checked
  against two independent implementations (OpenSSL and Python's `hmac`
  module); the 32-byte digest shape is pinned by the length-reject case.
  Replace them if DocuSign ever publishes fixed vectors.

### Fintoc

Source: <https://docs.fintoc.com/docs/webhooks-validating> ("Validate webhook
signatures": the `Fintoc-Signature` header format, the
`f"{timestamp}.{request.body}"` signed-string construction, the HMAC-SHA256
recipe, the example header `t=1620870928,v1=4df951e0...f567f6d`, and the
example signed message `1626102791.{"id":"evt_DyzYBwdC07ao5MqG",...}`),
corroborated by the official `fintoc-node`/`fintoc-python` SDKs'
`WebhookSignature` verifiers
(<https://github.com/fintoc-com/fintoc-node>,
<https://github.com/fintoc-com/fintoc-python>).

- Header: `Fintoc-Signature: t=<unix_ts>,v1=<hex_hmac>` — a comma-separated
  `key=value` list. `t` is the integer Unix-seconds value set by the server;
  `v1` is the HMAC-SHA256 signature over `{t}.{raw_body}` and is the only
  scheme the docs define.
- Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears in
  the header, a literal dot, then the raw request body bytes, unmodified (the
  docs' reference code builds `f"{timestamp}.{request.get_data()}"` and warns
  that re-parsing the JSON payload before verification can alter the string
  and break the signature).
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded, carried bare in
  the header (no `sha256=` prefix).
- Key: the webhook endpoint's secret as a plain UTF-8 string (never decoded),
  matching the docs' reference `hmac.new(secret, ...)`.
- Timestamp validation routes through the shared pure-ASCII-digit parser:
  sign-prefixed (`t=+1626102791`), whitespace-padded, empty, or overflowing
  values fail closed as `MalformedHeader`.
- Duplicate `t` or `v1` elements are rejected as ambiguous (`spec.md` §4.4) —
  never last-wins like the docs' reference code. Fintoc's docs define exactly
  one signature element and no rotation window, so a second `v1=` is treated
  as malformed rather than rotation (matching the Calendly/WorkOS/Coinbase
  treatment of their single signature fields). Unknown elements are discarded
  for forward compatibility.
- Replay protection: Fintoc's docs recommend a five-minute tolerance ("Use
  five minutes as the default tolerance"), so the shared symmetric
  `|now - t| > max_age` semantics apply; the crate default is 300s, matching
  the documented zone exactly. The future-dated half of the symmetry is
  stricter than the docs' phrasing but cannot reject legitimate deliveries.
- Test-vector provenance: Fintoc publishes the example header
  (`t=1620870928,v1=4df951e0...f567f6d`) and the example signed message
  (`1626102791.{"id":"evt_DyzYBwdC07ao5MqG",...}`) as separate examples with
  no signing key, so the implementation is validated against locally
  constructed, deterministic vectors over exactly the documented
  construction — the primary vector's body and timestamp are the docs' own
  example message — cross-checked across OpenSSL and Python. The docs'
  published example header is replayed as a well-formed-but-mismatching
  input. Replace them if Fintoc ever publishes fixed vectors.

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

### LINE

Source: <https://developers.line.biz/en/docs/messaging-api/verify-webhook-signature/>
("Verify webhook signature": the required `x-line-signature` header, the
`openssl` verification command below, and the byte-exact example) and
<https://developers.line.biz/en/docs/messaging-api/receiving-messages/>
(the messaging-receipt overview, which spells the header lowercase and
documents the verification middleware contract).

- Header: `x-line-signature: <base64_hmac>` — a bare base64 digest, no
  `sha256=` prefix and no timestamp; standard alphabet with padding, same
  single-header shape as DocuSign and Shopify.
- Signed string: the exact request body. LINE's docs are explicit that
  altering the body in any way — deserialization, JSON formatting,
  escape-character interpretation, encoding changes — breaks the signature
  ("any modification to the request body string [...] means the signature
  is not successfully verified"), so the raw bytes must be hashed untouched.
- Algorithm: HMAC-SHA256, base64-encoded. Key: the channel's **channel
  secret** as its UTF-8 bytes. LINE publishes the exact verification
  construction:
  `openssl dgst -sha256 -hmac "$CHANNEL_SECRET" -binary | base64` applied to
  the raw body string.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/DocuSign. LINE's docs recommend handling replayed
  (re-delivered) webhooks at the application layer — e.g. via the message
  ID in the payload — which is outside this crate's scope.
- Test-vector provenance: LINE publishes a byte-exact example (the
  confirmation webhook body `{"destination":"U8e742f61d673b39c7fff3cecb7536ef0","events":[]}`,
  the channel secret `8c570fa6dd201bb328f1c1eac23a96d8`, and the signature
  `GhRKmvmHys4Pi8DxkF4+EayaH0OqtJtaZxgTD9fMDLs=`, exactly reproducing the
  `openssl` command above). This is the primary test vector; the remaining
  vectors are locally constructed over the same documented construction and
  cross-checked against both OpenSSL and Python's `hmac` module.

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

### Nylas

Source: <https://developer.nylas.com/docs/v3/notifications/> (Nylas "Using
webhooks with Nylas" — "Secure a webhook" and "Respond to webhook
notifications": the `x-nylas-signature`/`X-Nylas-Signature` header format, the
raw-body signing rule, the `webhook_secret` keying, and the compressed-delivery
caveat) and the signed-delivery cookbook
(<https://developer.nylas.com/docs/cookbook/use-cases/build/verify-webhook-signatures/>,
with reference Node/Python verification code and an official CLI
`nylas webhook verify` oracle).

- Header: `x-nylas-signature: <hex_hmac>` — a bare lowercase hex digest, no
  prefix and no timestamp. The docs state the header arrives as either
  `x-nylas-signature` or `X-Nylas-Signature` (capitalization depends on the
  sending SDK); header lookup is case-insensitive, so either spelling works.
  Same shape as LaunchDarkly, Dropbox, Razorpay, and Lemon Squeezy.
- Signed string: raw body bytes, unmodified — the docs stress the signature is
  for "the exact content of the request body" ("signature is for the exact
  content of the request body, so make sure that your processing code doesn't
  modify the body before checking the signature"); re-serializing or otherwise
  re-encoding the body breaks verification.
- Algorithm: HMAC-SHA256, hex-encoded. Key: the endpoint's `webhook_secret`,
  generated automatically after the endpoint passes Nylas's initial `challenge`
  query-parameter handshake, as its UTF-8 bytes verbatim — matching the
  documented construction
  (`crypto.createHmac("sha256", secret).update(rawBody).digest("hex")`).
- Compressed delivery: when `compressed_delivery` is enabled, Nylas
  gzip-compresses the notification and the HMAC is computed **over the
  compressed bytes**. `verify()` hashes `raw_body` exactly as received, so the
  caller passes the compressed wire bytes straight through; decompressing
  before verification would break it (the docs call this the single most
  common integration bug).
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub, Bitbucket, Intercom, Expo, Meta, LaunchDarkly, and the other
  bare-hex raw-body providers.
- Test-vector provenance: Nylas documents the construction and ships reference
  verification code plus a CLI verifier, but publishes no byte-exact example
  signature (the `webhook_secret` is endpoint-specific and generated at
  handshake time), so the vectors are locally constructed over exactly the
  documented construction (hex of `HMAC-SHA256(webhook_secret, raw_body)`),
  cross-checked with `openssl dgst` and Python's `hmac` module. Replace them
  if Nylas ever publishes fixed vectors.

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

### Mailchimp Transactional (Mandrill)

Source: <https://mailchimp.com/developer/transactional/guides/track-respond-activity-webhooks/>
("Authenticating webhook requests": the URL + sorted form-field construction,
HMAC-SHA1, base64, and the `X-Mandrill-Signature` header) and the official
reference implementation in the same guide (`generateSignature`, Node.js,
`crypto.createHmac('sha1', webhook_key)` with `signed_data = url` then each
sorted `key + params[key]`, `digest('base64')`). The guide also documents the
generic key Mailchimp uses for webhook-URL-check POSTs: the value
`test-webhook`.

- Header: `X-Mandrill-Signature: <base64_hmac_sha1>`.
- Signed string: the webhook's URL exactly as configured in Mailchimp
  Transactional (including any query strings), followed by each `POST` form
  field's name and value concatenated to the string **with no delimiter** —
  `"{url}{key1}{value1}{key2}{value2}..."`, the field names sorted
  alphabetically. Mailchimp's docs warn that escaping/expanding the URL
  string (e.g. unescaping slashes) breaks verification, so the URL is used
  verbatim.
- Algorithm: HMAC-SHA1, base64-encoded (standard alphabet, padded). The same
  SHA-1-secrecy argument as Twilio applies: the HMAC is keyed with the
  shared webhook authentication key, so SHA-1's collision attacks do not
  apply. Mailchimp's docs explicitly state a hex signature "will not work" —
  only base64 is accepted.
- Key: the webhook's authentication key (generated at webhook creation,
  viewable/resettable from the Webhooks page or the Transactional API) as its
  UTF-8 bytes; an empty key fails closed with `InvalidSecret`.
- Not a raw-body scheme: the signature covers the parsed form fields
  (`mandrill_events`, historically the only field), not the body bytes.
  Callers pass every received field via [`VerifyOptions::form_params`], and
  the URL via `VerifyOptions::request_url`, exactly as with Twilio. Sorting
  is applied by this crate — callers pass fields in any order. Mailchimp's
  official verifier uses keyed dicts, which cannot represent duplicate field
  names; this crate keeps a duplicate field's received relative order. Both
  options must be supplied or verification fails closed with
  `MissingContext`.
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

### Pusher

Source: <https://pusher.com/docs/channels/server_api/webhooks> (Pusher's
"Webhooks" documentation for Channels: "The signature is generated using the
POST body with the token's secret"), corroborated by Pusher's official PHP
reference implementation in the pusher-http-php SDK
(<https://github.com/pusher/pusher-http-php/blob/main/src/Webhook.php>,
`hash_hmac("sha256", $body, $app_secret, false)` — raw POST body in, lowercase
hex out).

- Header: `X-Pusher-Signature: <hex_hmac>` — bare lowercase hex digest, no
  `sha256=` prefix and no timestamp; same shape as LaunchDarkly/Dropbox/
  Razorpay/LemonSqueezy.
- Signed string: the raw request body bytes, unmodified — Pusher signs the
  POST payload exactly as delivered, so re-serializing or reformatting the
  body changes the signature.
- Algorithm: HMAC-SHA256, hex-encoded.
- Key: the **secret** of the app token named in the `X-Pusher-Key` header.
  The key value is *not* part of the signed content — it only selects which
  token's secret keys the HMAC. Because Pusher rotates tokens, callers with
  multiple active tokens must supply the `Secret` matching the one the
  delivery was signed with (verifying oldest active token first, per Pusher's
  docs); the crate's `verify()` takes exactly one `Secret` and performs no
  network lookups, so the caller resolves token→secret.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Bitbucket/Sentry/LaunchDarkly.
- Empty headers, non-hex values, and values that do not decode to 32 bytes
  fail closed as `MalformedHeader`/`BadEncoding` (crate-wide error
  granularity, `spec.md` §2.1).
- Test-vector provenance: Pusher publishes no fixed test vector; the primary
  vector is constructed locally over exactly the documented construction
  (the byte-exact `time_ms`/`events` payload shape from Pusher's docs,
  keyed with a representative token secret, cross-checked with
  `openssl dgst -sha256 -hmac`). Vectors also cover the empty and UTF-8 body
  boundary cases and the non-signed `X-Pusher-Key` header.

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

### CircleCI

Source: <https://circleci.com/docs/guides/integration/outbound-webhooks>
("Outbound webhooks", "Signature Verification" and "Test Event" sections).
Covers CircleCI's **outbound** webhooks (pipeline, workflow, job, and project
events). Events are sent to the webhook's configured endpoint with a
`circleci-signature` header.

- Header: `circleci-signature: v1=<hex_hmac>[,v2=...][,v3=...]` — a
  comma-separated list of *versioned* signatures (`v1=`, `v2=`, ...).
  CircleCI's docs describe the value as "a comma-separated list of signatures"
  and direct integrators to check only the **latest signature type**, since
  each signature type is checked against the event in the order they are
  listed and the latest one is the current scheme.
- Version policy: this crate verifies the `v1` signature only — the docs name
  `v1` as the current scheme (HMAC-SHA256 over the raw body, hex-encoded) and
  instruct integrators to "only check the latest signature type" to prevent
  downgrade attacks. Unknown versions (`v2`, `v3`, ...) and non-versioned
  elements are ignored for forward compatibility, matching the docs' example
  header which shows several versions at once.
- Duplicate `v1` fields are rejected as ambiguous — never first-wins,
  following the crate-wide rule that malformed/ambiguous signing material
  fails closed rather than defaulting to valid (the reference Python
  implementation overwrites on duplicate keys; this crate does not).
- Keys are compared after trimming surrounding whitespace, so the comma-space
  spelling `v1=..., v2=...` (produced by proxy header-folding) parses like the
  canonical form. Values are never trimmed — the hex signature must be exact.
- Signed bytes: the raw request body, unmodified.
- Algorithm: HMAC-SHA256 over the raw body, hex-encoded
- Key: the webhook's signing secret (set in the CircleCI webhook
  configuration) as a plain UTF-8 string, matching the docs' reference
  implementations (`hmac.new(bytes(secret, 'utf-8'), bytes(body, 'utf-8'), 'sha256')`).
- Replay protection: CircleCI signs **no timestamp**, so the shared `max_age`
  window has no effect for this provider — the docs recommend rate limiting
  and idempotency handling at the application level for exactly this reason.
- Test-vector provenance: CircleCI's docs publish byte-exact signed values for
  200-level and non-200-level test events; both the 200-level published pair
  (`body: "hello world"`, `signing_key: "secret"`) and the "non-200-level"
  pair are replayed verbatim, plus an added pair for coverage. The docs'
  example header format (`v1=...,v2=...,v3=...`) is used for the
  additional-versions tests.

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

### Vercel

Source: <https://vercel.com/docs/webhooks/webhooks-api> ("Securing webhooks":
the `x-vercel-signature` header and the HMAC-SHA1 construction over the raw
request body) and the request-header reference
(<https://vercel.com/docs/headers/request-headers#x-vercel-signature>, which
states the signature "contains an HMAC-SHA1 signature" and ships the reference
`crypto.createHmac('sha1', secret).update(rawBody).digest('hex')` verifier with
an explicit constant-time comparison).

- Header: `x-vercel-signature: <hex_hmac>` — a bare lowercase hex digest, no
  prefix and no timestamp; the reference code compares `digest('hex')` output
  directly against the header value. Same shape as Dropbox, Razorpay, and
  Lemon Squeezy, but keyed with **SHA-1** rather than the SHA-256 most
  providers use. Vercel, Twilio, Intercom, and Expo (EAS) are the built-in
  providers' four HMAC-SHA1 schemes; Twilio signs a different construction
  (URL + form params) and both Intercom and Expo deliver their raw-body digest
  behind a `sha1=` prefix, so Vercel's bare-hex raw-body header is the only one
  of the four without a prefix. Covers requests from Webhooks, Log Drains, and
  integration webhooks alike.
- Signed string: raw request body bytes, unmodified — Vercel's docs verify
  the signature *before* `JSON.parse`, and warn that URL-encoded or
  re-encoded bodies break the HMAC.
- Algorithm: HMAC-SHA1, hex-encoded. Key: the webhook secret (account
  webhooks) or Integration Secret (integration webhooks) as its UTF-8 bytes,
  matching the documented construction.
- No timestamp in the signature scheme (`max_age` has no effect), mirroring
  GitHub/Shopify/Dropbox/Linear.
- Test-vector provenance: Vercel's docs describe the construction and ship
  full verifier code but publish no byte-exact example signature, so the
  implementation is validated against locally constructed, deterministic
  vectors over exactly the documented construction (the primary vector's body
  mirrors the shape of a documented `project.created` event; the vectors were
  independently cross-checked with Python `hmac` against `openssl`, and the
  SHA-256-length reject case pins the 20-byte digest shape). Replace them if
  Vercel ever publishes fixed vectors.

### X (formerly Twitter)

Source: <https://docs.x.com/x-api/account-activity/guides/account-activity-webhooks>
("Securing webhooks" — HMAC-SHA256 over the request body keyed by the
consumer secret, with reference implementations in Python and Ruby) and its
API docs for the delivery payloads ("Webhook payloads"; includes the
Challenge-Response Check and sample event payloads).

- Header: `x-twitter-webhooks-signature: sha256=<base64_hmac>`
- Signed string: the raw request body bytes, unmodified — X's reference code
  hashes the request body verbatim and their docs warn that re-encoding or
  deserializing the body breaks the signature. The same scheme (and prefix)
  backs the Challenge-Response Check's `response_token`, HMAC'd over the
  `crc_token` — a response the caller computes for inbound GETs, not an
  inbound delivery signature, and out of scope (this crate verifies
  deliveries only; §4 "no network calls").
- Algorithm: HMAC-SHA256 keyed with the **consumer secret** (the "API secret
  key" of the app — never the bearer token or an access token) as its UTF-8
  bytes, **base64**-encoded (standard alphabet, padded), with a literal
  `sha256=` prefix. The prefix is matched case-sensitively, exactly like
  GitHub (`§3`): X's docs and reference code emit only the literal lowercase
  form.
- No timestamp in the signature scheme (`max_age` has no effect); X
  recommends deduping from event payloads rather than signing time.
- Test-vector provenance: X's docs describe the scheme, ship reference
  HMAC code, and document sample payloads, but publish no byte-exact example
  signature, so the implementation is validated against locally constructed,
  deterministic vectors over exactly the documented construction (the primary
  vector's body mirrors the shape of X's documented `tweet_create_event`
  example; all vectors cross-checked with Python's `hmac` and `openssl`).
  Replace them if X ever publishes fixed vectors.
- Naming: the provider is `Provider::X` (this is the current brand, and the
  crate documents it as "X (formerly Twitter)"); `from_str` also accepts the
  legacy spellings `"twitter"`, `"x twitter"`, `"x-twitter"` (all
  case-insensitive), analogous to Mailchimp Transactional's `"mailchimp"`
  alias — X's own docs still use the pre-rebrand header name.

### Ripple

Source: <https://docs.ripple.com/products/collections/guides/verifying-webhooks>
("Verifying Webhooks" — the header reference, the signed-string recipe, and
the reference Python verifier; Collections is Ripple's financial webhook
product) and the associated Collections API webhook reference. Ripple
publishes no byte-exact example signature, so there is no official fixed
vector.

- Headers: `X-Webhook-Signature: t=<timestamp>,v1=<hex_hmac_sha256>` **and**
  `X-Webhook-Timestamp: <epoch_ms>`. The timestamp rides in **both** places:
  `t` inside the signature header and as the separate
  `X-Webhook-Timestamp` header value, and the docs' pitfall table requires
  them to "match verbatim" ("Ensure they match verbatim"). The reference
  verifier (`signature_verification_key` → decode, then
  `parts.get("t") != timestamp` → `False`) rejects a mismatch *before*
  computing any HMAC, so this crate surfaces a mismatch as `MalformedHeader`
  rather than `SignatureMismatch`.
- Signed string: `"{timestamp}.{sha256_raw_body_hex}"` — the
  `X-Webhook-Timestamp` value exactly as sent, a literal dot, then the
  **lowercase hex SHA-256 digest of the raw request body**. This is a
  double-hash scheme (body is SHA-256-digested, and *that hex digest* is what
  the HMAC covers), unique among the built-in providers; the docs warn that
  any transform of body or timestamp breaks verification.
- Algorithm: HMAC-SHA256 over the signed string, hex-encoded (bare — no
  prefix).
- Secret/key: the `signature_verification_key` Ripple exposes at subscription
  creation is **base64**-encoded ("This value is a base64-encoded symmetric
  secret"). It is decoded with a single strict standard-base64 decode
  (padding required), matching the reference verifier's
  `base64.b64decode(secret, validate=True)`, and the **decoded** bytes key
  the HMAC. "Secret double-base64 encoded" is the docs' first listed
  signature-mismatch pitfall; an undecodable or empty decoded key fails
  closed with `InvalidSecret`. The secret bytes themselves never enter any
  signed string, logging, or error output.
- Replay protection: `X-Webhook-Timestamp` is epoch **milliseconds**, and the
  reference verifier floors ms values to whole seconds
  (`if ts_int > 1_000_000_000_000: ts_int //= 1000`) before its freshness
  comparison. This crate applies the identical floor to the parsed value
  before the shared symmetric `|now - t| > max_age` (default 300s) check —
  the same ms→s treatment as WorkOS and HubSpot. The docs' example passes
  `max_age_seconds=300`, matching the crate default.
- Header parsing: the signature header is a comma-separated `key=value` list
  split on the literal `,`. The `t` and `v1` keys are matched after trimming
  surrounding whitespace (the `t=..., v1=...` comma-space spelling must not
  drop a recognized key); values are never trimmed — the timestamp is reused
  verbatim and the signature is hex-decoded as sent. Unknown fields
  (including a hypothetical future scheme) are discarded; duplicate `t=` or
  `v1=` elements are rejected as ambiguous (§4.4) since the docs define
  exactly one signature element and no rotation window. Non-hex or
  non-32-byte signatures are `BadEncoding`.
- Replay/verification ordering: the timestamp header is shape-validated
  first (`parse_millis`), then `t` ↔ `X-Webhook-Timestamp` verbatim agreement,
  then the HMAC — so a forged header pair fails closed at the earliest
  distinguishable step.
- Test-vector provenance: no official vector exists (Ripple publishes the
  recipe, the reference verifier, and a docs note that "There is no exact,
  public test signature"). The implementation is validated against locally
  constructed, deterministic vectors over exactly the documented construction
  (a Collections-style `payment.completed` body mirroring the docs' event
  shape), cross-checked with Python's `hashlib`/`hmac` and `openssl`.
  Replace them if Ripple ever publishes fixed vectors.

### Tally (form webhooks)

Source: <https://tally.so/help/webhooks> (Tally's official webhook help page:
"Add a signing secret" describes the `Tally-Signature` header and the base64
HMAC-SHA256 construction, and includes the published example webhook event).

- Header: `Tally-Signature: <base64_hmac>` — the SHA256 hash of the webhook
  payload, base64-encoded (standard alphabet with padding), no `sha256=`
  prefix and no timestamp; same shape as Shopify, Xero, and WooCommerce
- Signed string: the raw request body bytes, unmodified. Tally's own example
  hashes `JSON.stringify(webhookPayload)` after the runtime has parsed the
  body — a re-serialization round-trip that reproduces the received bytes only
  when the parser preserves key order and whitespace. This crate hashes
  `raw_body` verbatim (\`spec.md\` §4), which matches the signer's actual wire
  bytes and avoids the re-encoding failure class; callers must pass the
  untouched request body.
- Algorithm: HMAC-SHA256, base64-encoded. Key: the per-webhook signing secret
  (optional — if no secret is set, Tally sends unsigned requests) as its
  UTF-8 bytes, matching the docs' reference construction
  (`createHmac('sha256', secret).update(payload).digest('base64')`)
- No timestamp in the signature scheme (`max_age` has no effect); Tally signs
  on submission-time and retries deliveries with a back-off schedule, so
  callers dedupe from the payload's own `eventId` field, which is outside this
  crate's scope (payload parsing is a non-goal, §1)
- Test-vector provenance: Tally's docs describe the construction and publish
  an example event but no byte-exact example signature (the signing secret is
  endpoint-specific and shown only once at creation), so the implementation
  is validated against locally constructed, deterministic vectors over the
  documented construction using a body mirroring the published example event,
  cross-checked with Python's `hashlib`/`hmac` and `openssl`. Replace them if
  Tally ever publishes fixed vectors.

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
   scan covers every header the scheme declares — with one exception:
   Contentful's signed-header list (`x-contentful-signed-headers`) is
   **self-describing** and arrives with the request, so the additional
   headers it names at delivery time (e.g. `content-type`,
   `x-contentful-topic`) cannot be known statically and are not
   ambiguity-scanned. Duplicate-conflicting values in those
   dynamically-named headers are folded into the signed string first-match
   and are **not** detected by the adapter — the same carve-out `Custom`
   schemes below get, and the reason the Contentful row (§3) documents it
   (Contentful's signer always emits the list, and an attacker who can forge
   a fresh signature over the first value already controls the request
   stream). For `Custom` providers the scan covers only `signature_header` and
   `timestamp_header` — if the user's `signed_string` closure reads
   additional headers, duplicates in those are **not** detected (see
   `CustomScheme` docs).
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
     `PayPal-Cert-Url` must be validated against the caller's own
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
