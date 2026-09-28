//! Core verification machinery shared by every provider: the error type, the
//! secret wrapper, the header abstraction, verification options, and the
//! audited crypto helpers.
//!
//! Changes here affect every provider and are treated as high-risk; see
//! `spec.md` §2 for the normative contract.

// The `spec.md` §4.4 ambiguity check lives here and is public API in two
// shapes: [`adapter_utils::ambiguous_signature_header`] for an
// `http::HeaderMap` (the `http` feature) and
// [`adapter_utils::ambiguous_signature_header_in`] for a name/value pair
// table (no features at all, since the pair shape needs neither `http` nor
// `std`). Both entry points share the one scan implementation, which is what
// keeps a caller, the `tower` adapter and the `actix` adapter from drifting
// apart on what counts as ambiguous — so the module is unconditional, and the
// adapter-only helpers inside it (`rejection_status`,
// `declared_content_length`, `KeyRing`) carry their own narrower `cfg`.
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
