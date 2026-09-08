//! Core verification machinery shared by every provider: the error type, the
//! secret wrapper, the header abstraction, verification options, and the
//! audited crypto helpers.
//!
//! Changes here affect every provider and are treated as high-risk; see
//! `spec.md` §2 for the normative contract.

#[cfg(any(feature = "tower", feature = "actix"))]
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
