# AGENTS.md

Instructions for AI coding agents (Claude Code, Copilot, Cursor, etc.)
working in this repository. Human contributors should follow the same
rules — this file is the single source of truth for "how we work here,"
just phrased for an agent's operating loop.

Read [`spec.md`](./spec.md) before touching provider logic. It is the
normative contract; this file is the process for meeting it.

---

## 1. What this repo is, in one paragraph

`webhook-verify` is a security-sensitive, dependency-light crate that
verifies inbound webhook signatures for ~15 providers behind one API. The
entire value of this project is **correctness and auditability**. A fast
but wrong change is worse than no change. When in doubt, prefer the
smaller, more conservative diff, and surface uncertainty explicitly in your
final summary rather than guessing silently.

## 2. Before you write any code

1. Identify which layer you're changing:
   - **Core** (`src/core/*`): the `verify()` entry point, `VerifyError`,
     `Secret`, `HeaderMap` trait. Changes here affect every provider —
     treat as high-risk, and check `spec.md` §2 first.
   - **Provider** (`src/providers/<name>.rs`): one provider's signed-string
     construction and header parsing. Changes here are scoped to that
     provider only. This is where most contributions belong.
   - **Adapter** (`src/tower.rs`, `src/actix.rs`): framework glue. axum is
     served by the tower adapter — axum routers are tower services, so
     `VerifyLayer` drops straight in (no `src/axum.rs` exists). Adapters
     should contain no signing/verification logic of their own — they
     only wire `verify()` into that framework's request lifecycle.
2. If adding or modifying a **provider**, re-read the relevant row in
   `spec.md` §3 first. If the provider isn't in `spec.md` yet, add it there
   *before* writing the implementation, in the same PR — the spec entry and
   the code must not drift apart.
3. If you cannot find an official, linkable source for a provider's signing
   scheme (their docs, their official SDK's source, or their own published
   test vectors), **stop and say so** rather than inferring the scheme from
   a third-party blog post. Copying an undocumented recipe from a random
   tutorial is exactly the failure mode this crate exists to eliminate.

## 3. Non-negotiable rules

These map directly to `spec.md` §4 and are enforced by CI, but do not wait
for CI to catch you — apply them while writing the diff:

- **Never** use `==`, `.eq()`, or any non-constant-time comparison on a
  signature, HMAC digest, or anything derived from the secret. Always
  `subtle::ConstantTimeEq` (already a workspace dependency — do not add a
  second crate for this).
- **Never** call `.unwrap()` or `.expect()` on anything derived from
  `headers`, `raw_body`, or `secret` — those are attacker-controlled or
  operator-controlled inputs. Return a `VerifyError` variant instead.
  `#![deny(clippy::unwrap_used, clippy::expect_used)]` is set in provider
  modules; do not add `#[allow(...)]` to work around it — fix the code
  path instead.
- **Never** put secret material, raw bodies, or computed signatures into a
  `format!`, `println!`, `tracing::*`, `log::*`, `Debug`, or `Display` call,
  including in test failure messages beyond what `assert_eq!` prints by
  default for non-secret values. If a test needs to print a secret for
  debugging, gate it behind `#[cfg(test)]` only, never in a path that could
  compile into a release build.
- **Never** hash or compare against a re-serialized/re-encoded version of
  the body. The function signature takes `raw_body: &[u8]` for a reason —
  pass it through untouched to the hasher.
- **Never** silently widen a `max_age`/timestamp-tolerance default or
  disable a replay check to make a failing test pass. If a test is failing
  because of timestamp tolerance, the fix is almost always a clock-mocking
  problem in the test (use the injectable `Clock`), not a spec change.
- **Do not** add a new runtime dependency for something the crypto
  ecosystem already solves. Check `Cargo.toml` and RustCrypto's crate list
  before reaching for a new dependency. New dependencies of any kind need
  to be called out explicitly in your summary, with justification.

## 4. Workflow for adding a new provider

1. Find the provider's official webhook signing documentation (or their
   official server-side SDK's source, if docs are thin) and their
   published example/test payload if one exists. Link it in your PR
   description and in a code comment above the test vector.
2. Add a row to the table in `spec.md` §3 describing: header name(s),
   signed-string construction, hash algorithm, encoding, and whether replay
   protection applies.
3. Implement `src/providers/<name>.rs`:
   - A private function building the exact signed-string/bytes per the
     spec entry.
   - Reuse the shared `hmac_verify()` / `ed25519_verify()` helpers in
     `src/core/crypto.rs` rather than calling `hmac`/`sha2`/`ed25519-dalek`
     directly — this keeps the constant-time and error-handling guarantees
     in one audited place.
   - Wire it into the `Provider` enum and the `verify()` dispatch.
4. Add tests per `spec.md` §5 (official vector, negative/tamper/replay/
   malformed-header cases). Do not merge a provider without all five test
   categories present, even if some feel repetitive — they cover distinct
   failure modes.
5. Update the provider table in `README.md`.
6. Run `cargo test --all-features`, `cargo clippy --all-features -- -D warnings`,
   `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`, and
   `cargo test --no-default-features --features sendgrid,paypal` (spec §6: the
   `no_std + alloc` paths, e.g. the wall-clock fallback in `VerifyOptions::now`,
   until the `test-nostd` CI job ships — issue #22) locally before proposing
   the change.

## 5. Workflow for fixing a reported verification bug

Treat any "signature that should verify doesn't" or "signature that
shouldn't verify does" report as security-relevant until proven otherwise:

1. Reproduce with a minimal failing test *first*, added to the provider's
   test module, before changing any implementation code.
2. If the fix changes what a *previously passing* test does, stop and
   flag it explicitly — that's a signal you may be about to weaken
   verification rather than fix it. Explain the discrepancy in your summary
   before proceeding.
3. Prefer the fix that makes verification *stricter* (rejects more forged
   input) over one that makes it more permissive, when both would satisfy
   the reported case.

## 6. What "done" looks like for a PR

- [ ] `spec.md` updated if provider behavior changed or was added
- [ ] `README.md` provider table updated if the provider list changed
- [ ] All five test categories present for any new/changed provider
      (official vector, negative, tamper, replay, malformed-header)
- [ ] `cargo test --all-features`, `cargo clippy --all-features -- -D warnings`,
      and `cargo test --no-default-features --features sendgrid,paypal`
      pass locally
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps` passes
      locally (docs.rs builds with `-D warnings`, so a broken intra-doc link is
      a rustdoc warning that would otherwise surface only there, after merge —
      see issue #18)
- [ ] No new dependency added without justification in the PR description
- [ ] No secret/body/signature material appears in any log, error message,
      panic message, or test-failure output beyond what's needed
- [ ] PR description links the official source used for any signing-scheme
      claim

## 7. Things to explicitly avoid doing on your own initiative

- Avoid using `cargo search` since it's too slow. Use `cargo add <crate>`
  which automatically fetches the latest version and updates Cargo.toml
  in one step.
- Do not add speculative providers "while you're in there" without a
  linked, verifiable source for their signing scheme.
- Do not refactor `src/core/*` opportunistically inside a provider-focused
  PR — core changes get their own PR and extra scrutiny per §2.
- Do not add framework adapters for frameworks nobody has asked for yet.
  The adapter surface (`axum`, `actix`, `tower`) is intentionally small;
  proposing a new one should come with a linked issue showing demand.
- Do not "simplify" error handling by collapsing distinct `VerifyError`
  variants into fewer, vaguer ones — the granularity is intentional (see
  `spec.md` §2.1).
- Do not implement PayPal/SendGrid-style certificate-based verification by
  reaching for a synchronous network call inside `verify()` — this
  contradicts the "no network calls" goal. See the open question in
  `spec.md` §7 and raise the design question instead of picking a default
  unilaterally.

## 8. When you're unsure

Say so, in plain terms, in your summary — specifically what's uncertain and
why (e.g., "I could not find an official Square test vector, only a
community re-implementation; I've marked this provider's tests as sourced
from a secondary reference and flagged it for review"). For this crate,
an agent that clearly flags a gap in verification is far more valuable than
one that fills the gap with a plausible-looking guess.
