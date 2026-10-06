//! Shared test helpers: a deterministic clock and options for exercising
//! timestamp-based (replay-protected) providers, plus the text normalizer the
//! documentation-drift guards use.

use alloc::sync::Arc;
use core::hash::Hasher;
use core::time::Duration;

// The `std` prelude is not injected under `#![no_std]`, so while the crate
// itself only needs core+alloc, the test modules were written assuming the
// standard prelude (String, Vec, ToString, format!, vec!). Re-export exactly
// that subset here so a single glob (`use crate::test_helpers::*;`) restores
// it under `no_std` test builds without pulling in core-prelude duplicates.
#[cfg(not(feature = "std"))]
pub use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::core::options::VerifyOptions;

/// A [`Clock`](crate::Clock) pinned to a fixed unix-seconds instant.
///
/// A re-export of the crate's own public `FixedClock` rather than a second
/// private copy: the crate's provider tests and a downstream user's tests then
/// exercise the same type, so this file cannot drift from the public one and
/// the `#[cfg(test)]` copy cannot drift from the tests that depend on it.
pub use crate::core::options::FixedClock;

/// The unix-seconds value `secs` seconds after the Unix epoch.
pub fn epoch(secs: u64) -> u64 {
    secs
}

/// A minimal, `no_std`-friendly [`core::hash::Hasher`] that sums the hashed
/// bytes.
///
/// `std::collections::hash_map::DefaultHasher` requires `std`, so tests that
/// assert `Hash`/`Eq` consistency use this — they run under the `test-nostd`
/// CI combos too. Sum collisions across *unequal* values are possible in
/// principle, so the shared tests only assert the invariant that actually
/// matters and is guaranteed: equal values hash equal.
pub struct SumHasher(pub u64);

impl core::hash::Hasher for SumHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0 = self
            .0
            .wrapping_add(bytes.iter().map(|&b| u64::from(b)).sum());
    }
}

/// Feeds `value` through [`SumHasher`], returning the resulting sum.
pub fn hash_of(value: &impl core::hash::Hash) -> u64 {
    let mut hasher = SumHasher(0);
    value.hash(&mut hasher);
    hasher.finish()
}

/// Options pinning "now" to `secs` for deterministic tests.
pub fn clocked_at(secs: u64, max_age: Option<Duration>) -> VerifyOptions {
    VerifyOptions {
        max_age,
        clock: Some(Arc::new(FixedClock(secs))),
        request_url: None,
        request_method: None,
        form_params: None,
        verifying_material: None,
        webhook_id: None,
    }
}

/// Collapses every whitespace run in `text` to a single space.
///
/// The documentation-drift guards that read a doc comment back out of its own
/// source have to match *prose*, not the exact bytes rustfmt happened to wrap it
/// into: a phrase like "bounds both the verification work and the buffered
/// body" is split across lines by `cargo fmt` at the fill column, so a plain
/// `str::contains` on the raw source silently stops matching the moment the
/// comment is re-wrapped — and a stale-doc guard that stops matching is worse
/// than no guard, because it looks like it is still holding. Normalizing both
/// sides of the comparison keeps those guards about what the doc *says*.
///
/// Gated on an adapter because both of its callers are: the adapter body-limit
/// guards cannot run in a build with neither adapter, and a helper nothing
/// calls would warn in exactly the `no_std` / `sendgrid,paypal` combos where a
/// new warning is easiest to miss (issue #335).
#[cfg(any(feature = "tower", feature = "actix"))]
pub fn flattened(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
