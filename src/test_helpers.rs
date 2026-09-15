//! Shared test helpers: a deterministic clock and options for exercising
//! timestamp-based (replay-protected) providers.

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

use crate::core::options::{Clock, VerifyOptions};

/// A [`Clock`] pinned to a fixed unix-seconds instant.
#[derive(Debug)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

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
