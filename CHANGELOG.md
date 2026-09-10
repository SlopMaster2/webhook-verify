# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Fixed

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
- `no_std` CI spec drift corrected.
- `tower` and `actix` features now imply `std`: combining either with
  `default-features = false` previously broke with raw `cannot find crate
  std` errors, even though the `no_std + alloc` guarantee is scoped to the
  core path (`spec.md` §7). The combos now compile (they reintroduce `std`).

### Changed

- `Provider` enum reordered to match the lib.rs doc table.

## [0.1.0] - Unreleased

Initial release (in progress). See [Unreleased](#unreleased) for the
full feature set targeting v0.1.
