# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **New provider: LaunchDarkly** (`Provider::LaunchDarkly`): HMAC-SHA256 over
  the raw body bytes, hex-encoded and delivered bare (no `sha256=` prefix) in
  the `X-LD-Signature` header. The signing secret configured on the
  integration is used verbatim (its UTF-8 bytes) as the HMAC key — LaunchDarkly
  never decodes or re-encodes it. No timestamp is signed, so the shared
  `max_age` replay window has no effect for this provider (LaunchDarkly itself
  recommends reordering deliveries by the payload's own `date` field). Sources:
  <https://launchdarkly.com/docs/home/infrastructure/webhooks> and
  <https://launchdarkly.com/docs/api/webhooks>. LaunchDarkly publishes no
  byte-exact example signature, so the vectors are locally constructed over
  exactly the documented construction, cross-checked with OpenSSL.
- **New provider: Zendesk** (`Provider::Zendesk`): HMAC-SHA256 over
  `{timestamp}{raw_body}` — the `X-Zendesk-Webhook-Signature-Timestamp` header
  value exactly as sent (RFC 3339) concatenated with the raw body bytes, no
  separator — base64-encoded and delivered bare (no `sha256=` prefix) in the
  `X-Zendesk-Webhook-Signature` header. The signing secret is used verbatim as
  the HMAC key (Zendesk's reference code never decodes it); the signed
  timestamp enables the shared symmetric `max_age` replay window. Source:
  <https://developer.zendesk.com/documentation/webhooks/verifying>
  ("Verifying webhook authenticity"), corroborated by
  <https://developer.zendesk.com/documentation/webhooks/anatomy-of-a-webhook-request>.
  Zendesk publishes no byte-exact example signature, so the vectors are locally
  constructed over exactly the documented construction using Zendesk's own
  static test-webhook secret, cross-checked across OpenSSL and Python.
- **New provider: Mux** (`Provider::Mux`): HMAC-SHA256 over `{t}.{raw_body}`,
  hex-encoded, delivered in the `Mux-Signature` header as a comma-separated
  `t=<unix_ts>,v1=<hex_hmac>` list. Multiple `v1=` values are accepted during
  signing-secret rotation (a match on any is accepted), matching Mux's
  official SDKs, and the signed timestamp enables the shared symmetric
  `max_age` replay window (Mux's SDKs use a 300s tolerance). Sources:
  <https://www.mux.com/docs/core/verify-webhook-signatures>, the official
  Elixir verifier
  (<https://github.com/muxinc/mux-elixir/blob/master/lib/mux/webhooks.ex>),
  and the official Node verifier
  (<https://github.com/muxinc/mux-node-sdk/blob/main/src/resources/webhooks/webhooks.ts>);
  the primary test vector is Mux's own published vector from its SDK test
  utilities (<https://hexdocs.pm/mux/Mux.Webhooks.TestUtils.html>).
- **New provider: Adyen** (`Provider::Adyen`): HMAC-SHA256 over the raw body,
  base64-encoded, delivered in the `HmacSignature` header (header lookup is
  case-insensitive, so the docs' lowercase `hmacsignature` also resolves) with
  no timestamp or replay window. The Customer Area HMAC key is a hex string and
  is hex-decoded to raw key bytes, matching Adyen's official Java/Go libraries;
  a non-hex or empty key fails closed. Covers Adyen's header-based scheme
  (Adyen for Platforms / Banking, Management API, classic-platform
  notifications); Standard payments webhooks, whose signature lives inside the
  JSON body, are intentionally not covered. Sources:
  <https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures>
  and
  <https://docs.adyen.com/classic-platforms/configure-notifications/signing-notifications-with-hmac>
  (whose worked example is reproduced byte-for-byte as the test vector).
- **New provider: PagerDuty v3 webhooks** (`Provider::PagerDuty`): HMAC-SHA256
  over the raw body, hex-encoded, delivered in the `X-PagerDuty-Signature`
  header as one or more comma-separated `v1=<hex_hmac>` values (matching
  PagerDuty's key-rotation list format) with no timestamp or replay window.
  Non-`v1` elements are discarded per the official SDK's downgrade protection;
  an empty `v1=` value, non-hex, or wrong-length signature fails closed. Source:
  <https://developer.pagerduty.com/docs/verifying-signatures> and the official
  Go SDK's `webhookv3` package, whose published test vectors
  (<https://github.com/PagerDuty/go-pagerduty/blob/main/webhookv3/webhookv3_test.go>)
  are reproduced byte-for-byte.
- **New provider: Twitch EventSub** (`Provider::Twitch`): HMAC-SHA256 over
  the concatenation of the `Twitch-Eventsub-Message-Id` header, the
  `Twitch-Eventsub-Message-Timestamp` header (RFC 3339, used verbatim), and
  the raw body, hex-encoded, delivered in the
  `Twitch-Eventsub-Message-Signature` header as `sha256=<hex_hmac>`. The
  signed timestamp also enables the shared symmetric `max_age` replay window.
  Source:
  <https://dev.twitch.tv/docs/eventsub/handling-webhook-events/>.
- **New provider: Bitbucket Cloud** (`Provider::Bitbucket`): HMAC-SHA256 over
  the raw body, hex-encoded, delivered in the `X-Hub-Signature` header as
  `sha256=<hex_hmac>` (the WebSub `method=signature` format) with no timestamp
  or replay window. The exact `sha256=` prefix is matched case-sensitively,
  mirroring GitHub; an unknown `method` fails closed instead of being
  mis-verified. Source:
  <https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/>.
- **New provider: Sentry** (`Provider::Sentry`): HMAC-SHA256 over the raw
  body, bare hex-encoded, delivered in the `Sentry-Hook-Signature` header,
  keyed by the integration's Client Secret, with no timestamp or replay
  window. Covers Sentry's Integration Platform webhooks. Source:
  <https://docs.sentry.io/integrations/integration-platform/webhooks>.
- **New provider: Razorpay** (`Provider::Razorpay`): HMAC-SHA256 over the raw
  body, bare hex-encoded, delivered in the `X-Razorpay-Signature` header with
  no timestamp or replay window. Source:
  <https://razorpay.com/docs/webhooks/validate-test/> and maintainer-published
  worked examples in <https://github.com/razorpay/razorpay-node/issues/29>.
- A seed corpus for the `parse_and_verify` fuzz target
  (`fuzz/corpus/parse_and_verify/`): the CI nightly run now starts from the
  crate's own published test vectors (GitHub, Slack, Stripe, Discord, Dropbox,
  Razorpay, Sentry,
  Standard Webhooks, HubSpot, Zoom, Paddle, Cloudflare, Coinbase, Notion,
  Square, Xero, Linear, Shopify, LemonSqueezy, Typeform, Twitch, PagerDuty,
  Adyen) plus an adversarial malformed input, so
  libFuzzer spends
  its 600s budget mutating around known-good delivery shapes instead of
  rediscovering the header/body input layout from an empty input. Seeds are
  repo-local only — the `/fuzz` package is excluded from the crates.io
  tarball.
- **New provider: Typeform** (`Provider::Typeform`): HMAC-SHA256 over the
  raw body, base64-encoded, delivered in the `Typeform-Signature` header as
  `sha256=<base64_hmac>` with no timestamp or replay window. Source:
  <https://developers.typeform.com/developers/webhooks/secure-your-webhooks/>.
- **New provider: Lemon Squeezy** (`Provider::LemonSqueezy`): HMAC-SHA256 over
  the raw body, bare hex-encoded, delivered in the `X-Signature` header with
  no timestamp or replay window. Source:
  <https://docs.lemonsqueezy.com/help/webhooks/signing-requests>.
- [`Secret`](crate::Secret) now derives `PartialEq`, `Eq`, and `Hash`. This
  is the one remaining caller-facing key-material type lacking the equality
  contract that `VerifyError`/`ProviderParseError`/`VerifyingKeyMaterial`
  already expose ("complete the `Eq` contract", see the entry below), so
  rotated secrets can now be compared and deduplicated in
  `HashSet`/`HashMap` bookkeeping without the inner value becoming readable —
  the redacted `Debug`/`Display` behavior, `Default`, and all constructors
  are unchanged. Equality hashes/compares the wrapped key bytes directly and
  is verified by tests to stay in lockstep with `Hash`.
- `VerifyError`, `ProviderParseError`, and `VerifyingKeyMaterial` now derive
  `Hash`, completing the `Eq` contract those types already expose. Callers can
  now derive `Hash` on their own types containing them and use them in
  `HashSet`/`HashMap` contexts (e.g. deduplicating logged failures). `Hash` is
  consistent with each type's `PartialEq` — verified by new tests, including a
  pinning test that the hand-written `CustomScheme::hash` stays in lockstep
  with its declarative `PartialEq` (`signed_string` excluded from both).
- [`HeaderMap`](crate::HeaderMap) is now implemented for borrowed-key maps
  (`BTreeMap<&str, &str>`, and `HashMap<&str, &str>` behind the `std`
  feature), so static header tables built from `&'static str` pairs verify
  directly without allocating owned keys — the map counterpart of the
  existing `Vec<(&str, &str)>`/slice impls. Same case-insensitive lookup and
  same first-match semantics as the owned-key forms, with the same
  inherent-`get` shadowing caveat (call `HeaderMap::get(&map, name)`).
  Spec.md §2's blanket-impl list updated.
- CI now build-checks the `no_std + alloc` guarantee against a genuinely
  std-less target: the `no-std-riscv` job builds `cargo build --no-default-features
  --target riscv32imac-unknown-none-elf` (pure core) and `cargo build
  --no-default-features --features sendgrid --target
  riscv32imac-unknown-none-elf` (core + the one genuinely no_std-compatible
  feature). The previous wasm32 gate ships std and could not prove a std-less
  build; `riscv32imac-unknown-none-elf` is a bare-metal target with no
  standard library, closing the gap between the spec.md §7 claim and CI
  enforcement.
- The Standard Webhooks provider's test module now covers the §5.5
  garbage-value case for the opaque `webhook-id` header: a non-id-shaped
  value is pinned as well-formed (verified against a signature made over it)
  rather than a malformed header, and a signature over the real id cannot be
  swapped in (the id feeds the signed string verbatim).
- The combined `key=value` signature headers (Stripe, Paddle, Coinbase,
  Cloudflare) now tolerate whitespace after the element separator: keys are
  compared after trimming, so the comma-space/semicolon-space spelling real
  integrations emit (`t=..., v1=...`, `ts=...; h1=...`, `time=..., sig1=...`,
  `t=..., v0=...`) parses exactly like the canonical form instead of being
  silently dropped into a misleading "missing `t` field" failure. Values are
  never trimmed — timestamps still ride verbatim into the signed string, so
  verification strength is unchanged (spec §3 rows updated).
- The tower (`VerifyLayer`) and actix (`WebhookConfig`) adapters now reject a
  request whose declared `Content-Length` already exceeds
  `with_max_body_size` with `413 Payload Too Large` *before* any body bytes
  are buffered, closing the "bounds work, not memory" gap for
  content-length-bearing requests. Bodies sent without a length
  (`Transfer-Encoding: chunked`) fall through to the existing post-buffer
  check, which still bounds the signature work.
- The `http` feature is now correctly documented as **std-bounded in practice**:
  the `http` crate itself requires `std` (its own `lib.rs` emits
  `compile_error!("std feature currently required...")` when built without it),
  so a genuinely std-less build cannot include the `http` feature — the same
  class of dependency-forced `std` as `paypal` (issue #23, `spec.md` §3).
  The README, spec §6, and spec §7 `no_std` scope record now reflect this
  honestly; the `no_std + alloc` guarantee is core + `sendgrid` only.
- The `test-nostd` `http` CI run (`cargo test --no-default-features
  --features http`) is now correctly framed: it exercises the crate's own
  `http::HeaderMap` impl with the crate's own `std` feature off (a behavioral
  catch for the crate's own code), but cannot prove a std-less build because
  the `http` crate ships `std` regardless. The wasm32 build gate (issue #25)
  now build-checks both `sendgrid,paypal` and `http` feature sets for
  `--target wasm32-unknown-unknown` (parity with the `test-nostd` matrix);
  the `.github/workflows/ci.yml` hunk shipped in PR #26.
- The `test-nostd` and `doc` CI jobs ship in `.github/workflows/ci.yml`,
  retiring the earlier "CI wiring pending — blocked on the runner token's
  missing `workflows` permission" notes (issues #18/#22): the `no_std`
  behavioral test runs and the `RUSTDOCFLAGS="-D warnings"` doc build are now
  enforced by CI itself, not just the local contributor gates.
- The `cargo-audit` dependency-vulnerability scan ships in
  `.github/workflows/ci.yml` as an informational (non-blocking) job against
  the RustSec advisory database (PR #30). The fuzz target build is now
  covered by the `Fuzz` workflow on every PR and master push (build-only;
  timed runs stay nightly), so the duplicate `fuzz-build` job is retired from
  `ci.yml`.
- HubSpot webhook provider (v3 scheme) — HMAC-SHA256 over
  `{method}{uri}{raw_body}{timestamp}`, base64-encoded,
  `X-HubSpot-Signature-V3` with the `X-HubSpot-Request-Timestamp` header
  carrying unix **epoch milliseconds**, and a replay window (ms → whole
  seconds by integer division, shared symmetric tolerance). Requires the new
  `VerifyOptions::request_method` option alongside `request_url`, since this
  is the only scheme that signs the HTTP method. Backed by an official test
  vector from HubSpot's webhook docs (the worked example reproduces the
  published `base64(HMAC-SHA256(...))` byte-for-byte).
- Coinbase (CDP) webhook provider — HMAC-SHA256 over `{t}.{raw_body}`,
  hex-encoded, `v0` scheme in the combined `X-Hook0-Signature` header
  (`t=`/`v0=` fields, `h=`/`v1=` header-binding fields tolerated but not
  interpreted) with timestamp tolerance. Follows the documented construction
  in Coinbase's Developer Platform webhook docs.
- Notion webhook provider — HMAC-SHA256 over the raw body, hex-encoded,
  `sha256=` prefix in the `X-Notion-Signature` header, keyed by the
  subscription's `verification_token`. Backed by an official test vector from
  Notion's docs (the worked-example token/body reproduce the documented
  sample signature byte-for-byte).
- Paddle webhook provider — HMAC-SHA256 over `{ts}:{raw_body}`, hex-encoded,
  combined `Paddle-Signature` header (`ts=`/`h1=` list, rotation-safe) with
  timestamp tolerance. Backed by Paddle's official Go SDK test vector and
  docs.
- `From<&str>`, `From<String>`, and `From<&String>` for [`Secret`](crate::Secret),
  so signing material can be built with the idiomatic `.into()`/`From`
  conversion as well as the explicit `Secret::new` constructor.
- `Provider` now implements `FromStr` (case-insensitive, canonical display
  names) for config-driven provider selection, with `ProviderParseError`.
- Cloudflare (Stream) webhook provider — HMAC-SHA256 over `time.body`,
  hex-encoded, combined `Webhook-Signature` header with timestamp tolerance.
- Xero webhook provider — HMAC-SHA256, base64, `x-xero-signature`.
- Dudect-style constant-time assertion for the core comparison path
  (spec §5.7). Runs as an informational, non-blocking CI job in release
  mode.
- Optional `max_body_size` on Tower `VerifyLayer` and Actix
  `WebhookConfig` for DoS hardening.
- Fuzz target covering Discord's Ed25519 signature-decode path
  (spec §5.6).
- The shared fuzz target (`fuzz/fuzz_targets/parse_and_verify.rs`) now also
  drives the cross-secret rotation path
  [`verify_any`](crate::verify_any) (spec §5.6): per-provider invocation with
  an empty secret slice (immediate `SignatureMismatch`), a garbage-then-
  well-formed slice (error aggregation must keep trying past `InvalidSecret`
  and reach the well-formed key), and an all-garbage slice (aggregation
  across every unusable key). The multi-secret loop gets the same "no panic,
  no timeout" guarantee the single-secret `verify` path already had.
- `CustomScheme::new()` convenience constructor plus the
  `with_timestamp_header` / `with_prefix` builders, so declarative schemes
  can be configured without a struct literal (spec §2.2).
- docs.rs now annotates feature-gated items (the `paypal`/`sendgrid`
  providers and the `tower`/`actix`/`http` adapters) with the crate feature
  they require, via `doc_auto_cfg` + the `docsrs` rustdoc cfg. Local/stable
  builds are unaffected (the cfg is set only on docs.rs).
- [`Provider`](crate::Provider) `FromStr` now also accepts the
  space-separated human-readable spellings used in the docs for the two
  providers whose `Display` name runs words together: `"lemon squeezy"` and
  `"standard webhooks"` (both case-insensitive, like every name). These match
  the product names operators see in `spec.md`/`README.md`, so a
  config-driven `"Lemon Squeezy".parse::<Provider>()` no longer fails.

### Changed

- **Docs: GitLab discoverability** — GitLab's webhook "signing token" (GitLab
  19.0+) implements the Standard Webhooks specification, so
  `Provider::StandardWebhooks` verifies it with no new code. Documented in the
  README provider table, `spec.md` §3, and the module docs. Source:
  <https://docs.gitlab.com/user/project/integrations/webhooks>.
- The crate-level `missing_docs` lint is `deny` instead of `warn`: an
  undocumented public item is now a hard compile error in every configuration
  (stable/MSRV/beta, clippy, and the `no_std` feature matrix) instead of a
  warning the contributor gates never promoted to failure. Docs on every
  existing public item already satisfy the bar; this only guards future API
  surface against silent doc drift.
- [`Provider`](crate::Provider) `Display` for the `Custom` variant now
  renders the full declarative scheme configuration (signature header, hash
  algorithm, encoding, and any configured prefix/timestamp header) instead
  of only the signature header name. Two custom schemes sharing a header
  name but differing in encoding or hash previously logged identically;
  operators can now tell them apart. The `signed_string` closure has no
  reliable textual form and is intentionally not rendered.

### Fixed

- The `parse_and_verify` fuzz target now drives constant-time-shape attempts
  for the five raw-body single-header providers that previously only ran with
  arbitrary fuzz-input headers — Dropbox, LemonSqueezy, Linear, Shopify, and
  Xero. Each gets a well-formed signature-header value (bare hex or bare
  base64 of the 32-byte gate) so arbitrary body bytes reach the 32-byte
  length gate and HMAC comparison instead of failing earlier on
  malformed/missing headers, matching the coverage Cloudflare/Notion/
  Typeform/Coinbase/Paddle/HubSpot already had (spec §5.6). The
  `IMPLEMENTED`-list comments claimed "a well-formed-shaped attempt below"
  for LemonSqueezy when none existed, and the other four said nothing where
  one now does; the comments now match the code.
- The `parse_and_verify` fuzz target's seed-corpus comment described Paddle's
  signed string as `{ts}.{body}` — the `ts`/`h1` entries are joined with a
  colon, Paddle's documented `hmac(secret, "{ts}:{body}")`. The comment now
  matches `src/providers/paddle.rs` and `spec.md` §3's Paddle row. Comment-only
  change; no behavior, seed bytes, or crate code affected.
- `cargo fuzz build` now also compiles the `paypal`-only feature combination
  (without `sendgrid`): the fuzz target imported `VerifyingKeyMaterial` under
  `#[cfg(feature = "sendgrid")]` alone, so the `not(feature = "sendgrid")`
  fallback arms the target ships for the paypal-only build failed with an
  unresolved import. The import is now gated on `any(sendgrid, paypal)`,
  matching the cfg blocks that use it.
- README `no_std` and security notes: multi-line inline code spans with stray
  two-space indentation rendered mangled — commands gained spurious spaces
  (e.g. `--target  wasm32-unknown-unknown`) and a parenthetical dangled
  mid-sentence. Each span now sits on a single line; the narrative flows as
  one paragraph. Content is unchanged.
- Removed the `probe_ci_write_test.yml` debris file left at the repository root
  by a CI permission-probe commit. It was tracked on `master`, not excluded from
  the package, and would have shipped verbatim in the crates.io tarball.
- Discord: a configured public key that decodes to 32 bytes but is not a valid
  Ed25519 compressed point now fails closed with
  [`VerifyError::InvalidSecret`](crate::VerifyError), matching the module's
  documented contract, instead of surfacing as
  [`VerifyError::SignatureMismatch`](crate::VerifyError). The two are distinct
  failure classes in the adapters: a bad key is operator misconfiguration
  (HTTP 500), while a signature mismatch is treated as a forged request (HTTP
  401). Verification outcome is unchanged — such keys could never have verified
  — only the error classification is corrected. Roughly half of random 32-byte
  values fail point decompression, so this catches a common class of
  copy-paste-corrupted Developer Portal keys.
- The `no_std + alloc` configuration is now behaviorally testable: the full test
  suite compiles and passes with `cargo test --no-default-features --features
  sendgrid,paypal` (tests run on the host, no wasm target needed). Test modules
  pick up the standard-prelude names they assume (`String`, `Vec`,
  `ToString`, `format!`, `vec!`) through a `no_std`-gated re-export in the
  shared test helpers — previously the `cfg(not(feature = "std"))` branches
  (the wall-clock fallback in `VerifyOptions::now()`, the
  `std::error::Error`-less `VerifyError`, and the `no_std` re-exports) were
  only build-checked for `wasm32`, so a behavioral regression in them would
  pass CI.
- The contributor gate now builds the docs with `RUSTDOCFLAGS="-D warnings"`
  (AGENTS.md §6), so a broken intra-doc link is caught at review time instead
  of silently degrading docs.rs output. (docs.rs itself builds with
  `-D warnings`; the `doc` CI job now enforces the same flag.)
- spec.md: corrected CI claims that outran the workflow wiring. The
  `-D warnings` doc build and the `no_std` behavioral test run were
  temporarily marked as local/pre-merge gates (issues #18/#22), and have
  since shipped in `.github/workflows/ci.yml` (see the Added section above).
  The §5.7 constant-time bullet no longer describes its already-shipped
  informational CI job as "tracked separately"; and the §7 PayPal ship date
  typo `(2026-10)` is fixed to `(2026-09)` (PayPal and SendGrid both shipped
  in the initial 2026-09 commit).
- `VerifyOptions::with_form_params` docs: the builder claimed "Order does not
  matter; fields are sorted into signing order during verification." That
  holds for distinct field names, but Twilio's scheme signs same-named fields
  in their received relative order (the sort is stable, `spec.md` §3, Twilio
  row), so passing duplicates reordered broke verification while the docs
  implied any order was safe. The docs now state the duplicate-names
  exception, matching the field documentation and the implementation.
- `CustomScheme` replay-protection caveat: the docs now state that the replay
  window only *binds* when the `timestamp_header` value is copied into the
  bytes `signed_string` returns. The check runs against the header alone, so
  a closure that signs the body only leaves the timestamp
  attacker-rewriteable — replaying a captured request with a freshened header
  still verifies, silently defeating the protection. A test pins both halves
  of the documented limitation (stale header rejected, freshened header
  accepted) so the caveat cannot silently drift from the behavior; the
  built-in timestamped providers are unaffected (their signed strings embed
  the timestamp by construction).
- `VerifyError::TimestampOutOfTolerance` `Display` no longer truncates the
  reported skew to whole seconds: a sub-second skew over a sub-second
  `max_age` window previously read e.g. `0s outside the allowed 100ms
  window`, which misdescribes the rejection. The skew now renders like the
  window does (`Duration`'s `Debug`), e.g. `150ms outside the allowed 100ms
  window` — the same second half of the sub-second-tolerance fix that
  already applied to `max_age`.
- The `no_std + alloc` guarantee now actually holds at the dependency level:
  `base64`, `hex`, and `subtle` were declared with default features, each of
  which turns on that crate's `std` feature (`extern crate std`) — invisible
  to the wasm32 CI gate, which ships std, so a stray `--no-default-features`
  build for a genuinely std-less target (bare-metal, no_std wasm) failed in
  the dependency tree. All three are now declared `default-features = false`
  (base64/hex keep [`alloc`]), matching every other dependency's
  no_std-first posture; the `--no-default-features` core and `sendgrid` build
  now compile for `riscv32imac-unknown-none-elf`.
- spec.md/README/Cargo.toml: the `paypal` feature is now documented as
  std-bounded in practice. The §3 PayPal row and the §7 implementation notes
  previously described the feature as `no_std`-compatible, but its
  certificate path pulls `der-parser` and `nom` (via `x509-parser`) with
  their default features, re-enabling `std` in `num-traits`/`num-bigint`/
  `memchr` — and Cargo's union feature-unification means a
  `default-features = false` edge on this crate's own dependency cannot
  revoke those. A `--no-default-features --features sendgrid,paypal` build
  for a genuinely std-less target fails inside `num-traits` with
  `can't find crate for std` (invisible to the wasm32 CI gate, which ships
  std). The `no_std + alloc` scope is core + `sendgrid`, unchanged; the
  host-based no_std test in §6 still passes because host builds have std.
  See issue #23.
- Square: the signature-header constant and README table used the
  title-cased `X-Square-HmacSha256-Signature`, but Square's own docs, the
  crate's `spec.md` §3, and the provider module docs all spell the header
  `x-square-hmacsha256-signature`. The constant and README now match the
  provider's spelling (lookup is ASCII case-insensitive, so this only
  changes the header name surfaced in `VerifyError` messages on the
  adapter duplicate-scan, aligning operator-facing output with Square's
  documentation).
- Paddle malformed-header test battery: the `ts=not-a-number` case used a
  comma (`ts=not-a-number,h1=…`) where `Paddle-Signature` elements are
  `;`-separated. `parse_header` split the lump into a single `ts` element,
  folding the `h1=` field into the timestamp value, so the test passed
  without ever parsing the signature field it claimed to cover. The header
  now uses the documented `;` separator and genuinely exercises a
  well-formed `h1=` signature coexisting with an unparsable timestamp.
- `CustomScheme` docs: the ambiguity-check caveat referenced
  `signature_header_names` (a crate-private helper, not a public item) and the
  two scheme header names via broken intra-doc links, producing rustdoc
  warnings on every `cargo doc` build (including docs.rs). The links now
  resolve to the `CustomScheme` fields, and docs.rs builds the docs with
  `-D warnings` so broken links cannot regress silently on docs.rs.
- Crate-level docs: the Paddle row in the supported-providers table misstated
  the signed-string construction as `ts.body`; it is `{timestamp}:{raw_body}`
  (literal colon), matching `spec.md` §3 and the implementation.
- Crate-level docs and README: the SendGrid row described the signed message
  as `timestamp.body` (implying a dot separator); it is the raw timestamp
  header immediately concatenated with the raw body, no separator,
  matching `spec.md` §3 and the implementation.
- GitHub: the `sha256=` prefix in `X-Hub-Signature-256` is now matched
  case-sensitively, matching GitHub's reference implementations
  (octokit/Ruby). Uppercase/mixed-case prefixes (`SHA256=…`, `Sha256=…`)
  fail closed with `MalformedHeader` instead of being leniently accepted,
  bringing the code into conformance with the literal `sha256=` prefix
  already documented in the spec.
- Standard Webhooks: empty `webhook-id` header now fails closed with
  `MalformedHeader` instead of silently building a wrong signed string
  that masquerades as `SignatureMismatch` (spec §5.5 consistency).
- `verify_any` doc example now actually runs and verifies (it previously
  showed empty headers/body under `no_run`, which would have failed with
  `MissingHeader` if executed).
- PayPal timestamp parsing: strict RFC 3339 leap-second position
  (spec §3.8).
- Doc consistency nits for Zoom and SendGrid provider entries.
- Broken `HashMap` doc link in `HeaderMap` docs under `no_std` (the link
  resolved only with the `std` feature enabled).
- `verify_any` semantics for asymmetric providers clarified in docs.
- README example code fixed (undefined variables).
- Replay protection now honors sub-second `max_age` tolerances exactly:
  `check_replay` previously compared whole-second skew against
  `max_age.as_secs()`, silently flooring a `Duration::from_millis(500)`
  window to 0s (accepting any timestamp) and a `3500ms` window to 3s.
  `TimestampOutOfTolerance` `Display` likewise no longer truncates the
  window to whole seconds in operator-facing messages.
- `no_std` CI spec drift corrected.
- `verify_any` docs corrected: `TimestampOutOfTolerance` is reachable only
  *after* a signature verifies (every timestamped provider checks the
  replay window after the signature comparison), so a stale request with no
  matching key reports `SignatureMismatch`, not `TimestampOutOfTolerance`.
  A regression test pins the behavior (issue #12).
- `tower` and `actix` features now imply `std`: combining either with
  `default-features = false` previously broke with raw `cannot find crate
  std` errors, even though the `no_std + alloc` guarantee is scoped to the
  core path (`spec.md` §7). The combos now compile (they reintroduce `std`).
- Adapter docs (tower `VerifyLayer`/actix `WebhookConfig` module docs,
  `with_max_body_size` rustdoc, README): the `max_body_size` limit was
  described as preventing the server from *buffering* an arbitrarily large
  payload. Both adapters fully buffer the body before the size check
  (verification requires the exact wire bytes), so the claim overstated the
  guarantee. The docs now say the limit bounds the signature-verification
  CPU work only — a `413` still fires before any signature work, but memory
  buffering of an oversized body is not prevented.
- Crate-level doc example: the GitHub delivery snippet is no longer `no_run`.
  It executes as a doc-test, so a regression in GitHub's verification fails
  `cargo test` through its doctests (mirroring the earlier `verify_any` doc
  example conversion).
- `Provider` enum reordered to match the lib.rs doc table.
- Contributor gate (AGENTS.md): the PR definition-of-done now includes
  `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`, so broken
  intra-doc links (rustdoc warnings) are caught pre-merge. docs.rs builds with
  `-D warnings` by default; the `doc` CI job now enforces the same flag, so
  the local gate and CI fail together.
- README "Releasing" instructions now tag the release `v0.1.0` (matching
  `Cargo.toml`'s version) instead of the template's `v0.2.0`.
- Cloudflare and Coinbase combined-header fields (`time`/`sig1` and `t`/`v0`)
  are now rejected when repeated instead of first-wins: ambiguous signing
  material fails closed (`spec.md` §4.4), matching the existing Stripe and
  Paddle behavior.
- Docs: the HubSpot URI-decoding caveat is now surfaced where operators
  configure it. `VerifyOptions::request_url` and the README provider table
  state that HubSpot URL-decodes certain characters (`spec.md` §3 lists them)
  when computing its signature, so the URI must be passed in the same decoded
  form HubSpot signed. Previously only the provider module docs and the spec
  carried the caveat, and a proxied percent-encoded URI failed with an opaque
  `SignatureMismatch`.
- The `cargo audit` CI job was failing on three RustSec advisories that cannot
  be removed from the lockfile today (issue #41): `rsa` 0.9.10 (RUSTSEC-2023-0071,
  Marvin private-key timing attack — upstream has no patched release, and this
  crate only ever runs `RsaPublicKey::verify`, never a private-key operation),
  `time` 0.3.45 (RUSTSEC-2026-0009, fix >=0.3.47 requires Rust 1.88 > MSRV
  1.85; actix adapter stack only), and `h2` 0.3.27 (RUSTSEC-2026-0258, fix is
  the >=0.4.16 major bump for which actix-http has no 0.3-line patch; actix
  adapter stack only). The three are now documented and individually justified
  in `.cargo/audit.toml`, and the job is **blocking** again — a new advisory
  will fail CI and be triaged, while the three accepted ones carry an audit
  trail and re-evaluation triggers instead of failing every run.

## [0.1.0] - Unreleased

Initial release (in progress). See [Unreleased](#unreleased) for the
full feature set targeting v0.1.
