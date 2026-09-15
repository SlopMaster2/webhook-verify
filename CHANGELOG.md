# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
  the `http` crate ships `std` regardless. The wasm32 `http` feature gate
  (issue #25) is designed to build-check both `sendgrid,paypal` and `http`
  feature sets for `--target wasm32-unknown-unknown` (parity with the
  `test-nostd` matrix); the `.github/workflows/ci.yml` hunk is staged in
  issue #25 and awaits a maintainer apply with `workflows` permission.
- The `test-nostd` and `doc` CI jobs ship in `.github/workflows/ci.yml`,
  retiring the earlier "CI wiring pending — blocked on the runner token's
  missing `workflows` permission" notes (issues #18/#22): the `no_std`
  behavioral test runs and the `RUSTDOCFLAGS="-D warnings"` doc build are now
  enforced by CI itself, not just the local contributor gates.
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
- `CustomScheme::new()` convenience constructor plus the
  `with_timestamp_header` / `with_prefix` builders, so declarative schemes
  can be configured without a struct literal (spec §2.2).
- docs.rs now annotates feature-gated items (the `paypal`/`sendgrid`
  providers and the `tower`/`actix`/`http` adapters) with the crate feature
  they require, via `doc_auto_cfg` + the `docsrs` rustdoc cfg. Local/stable
  builds are unaffected (the cfg is set only on docs.rs).

### Changed

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

## [0.1.0] - Unreleased

Initial release (in progress). See [Unreleased](#unreleased) for the
full feature set targeting v0.1.
