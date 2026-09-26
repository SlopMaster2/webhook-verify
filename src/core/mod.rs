//! Core verification machinery shared by every provider: the error type, the
//! secret wrapper, the header abstraction, verification options, and the
//! audited crypto helpers.
//!
//! Changes here affect every provider and are treated as high-risk; see
//! `spec.md` §2 for the normative contract.

// Gated on `http` as well as the two adapters: the `spec.md` §4.4 ambiguity
// check is a public entry point under `http` (see
// [`adapter_utils::ambiguous_signature_header`]), so a caller driving
// `verify()` with an `http::HeaderMap` can honor the contract without pulling
// in a framework adapter. The adapter-only helpers inside the module
// (`rejection_status`, `declared_content_length`) carry their own narrower
// `cfg`, so nothing here becomes dead code in the `http`-only configuration.
#[cfg(any(feature = "http", feature = "tower", feature = "actix"))]
pub(crate) mod adapter_utils;
pub(crate) mod crypto;
pub(crate) mod error;
pub(crate) mod headers;
pub(crate) mod options;
pub(crate) mod replay;
pub(crate) mod secret;

pub use error::VerifyError;
pub use headers::HeaderMap;
#[cfg(feature = "std")]
pub use options::SystemClock;
pub use options::{Clock, VerifyOptions, VerifyingKeyMaterial};
pub use secret::Secret;
