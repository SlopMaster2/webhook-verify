# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- PayPal timestamp parsing: strict RFC 3339 leap-second position
  (spec §3.8).
- Doc consistency nits for Zoom and SendGrid provider entries.
- `verify_any` semantics for asymmetric providers clarified in docs.
- README example code fixed (undefined variables).
- `no_std` CI spec drift corrected.

### Changed

- `Provider` enum reordered to match the lib.rs doc table.

## [0.1.0] - Unreleased

Initial release (in progress). See [Unreleased](#unreleased) for the
full feature set targeting v0.1.
