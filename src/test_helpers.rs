//! Shared test helpers: a deterministic clock and options for exercising
//! timestamp-based (replay-protected) providers.

use alloc::sync::Arc;
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
