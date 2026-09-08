//! Structured verification errors.
//!
//! Design rules (see `spec.md` §2.1): errors never contain the secret, the raw
//! body, or a computed signature. They may carry header *names*, static reason
//! strings, and numeric skew values.

use core::fmt;
use core::time::Duration;

/// Everything that can go wrong while verifying a webhook signature.
///
/// `MissingHeader` / `MalformedHeader` / `BadEncoding` indicate malformed
/// requests; `SignatureMismatch` indicates an active-attack signal (or an
/// out-of-band misconfiguration). Callers that log differently per class can
/// match on the variants — but both classes are "reject the request"
/// outcomes. Never treat a malformed header as "skip verification".
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// A required signature-related header was absent.
    MissingHeader {
        /// Name of the missing header.
        header: &'static str,
    },
    /// A required header was present but could not be parsed into the shape
    /// the provider's scheme requires (wrong prefix, empty value, ...).
    MalformedHeader {
        /// Name of the malformed header.
        header: &'static str,
        /// Static description of what was wrong with its shape.
        reason: &'static str,
    },
    /// A value that must decode in the provider's encoding (hex, base64)
    /// failed to decode, or decoded to the wrong length.
    BadEncoding {
        /// Static description of the decoding failure.
        reason: &'static str,
    },
    /// The signature did not match. Returned identically regardless of how
    /// close the provided signature was to the expected one.
    SignatureMismatch,
    /// The signed timestamp is further from "now" than [`VerifyOptions::
    /// max_age`] allows; skew is how far outside the window it fell.
    TimestampOutOfTolerance {
        /// How far outside the tolerance window the timestamp was.
        skew: Duration,
        /// The configured maximum age.
        max_age: Duration,
    },
    /// The selected [`crate::Provider`] exists but has no verification
    /// implementation yet (fail-closed stub for providers not shipped).
    UnsupportedProvider,
    /// The provided secret is not usable for this provider's scheme
    /// (e.g. wrong format for a hex- or base64-encoded key).
    InvalidSecret {
        /// Static description of why the secret was rejected.
        reason: &'static str,
    },
    /// Verification for this provider requires caller-supplied request
    /// context (such as Square's notification URL, via
    /// [`crate::VerifyOptions::request_url`]) that was not provided. This is
    /// an operator misconfiguration, not an attack signal — but the request
    /// is still rejected: fail closed.
    MissingContext {
        /// Static description of what context was missing.
        reason: &'static str,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::MissingHeader { header } => write!(f, "missing header `{header}`"),
            VerifyError::MalformedHeader { header, reason } => {
                write!(f, "malformed header `{header}`: {reason}")
            }
            VerifyError::BadEncoding { reason } => write!(f, "bad encoding: {reason}"),
            VerifyError::SignatureMismatch => write!(f, "signature mismatch"),
            VerifyError::TimestampOutOfTolerance { skew, max_age } => write!(
                f,
                "timestamp out of tolerance: {}s outside the allowed {}s window",
                skew.as_secs(),
                max_age.as_secs()
            ),
            VerifyError::UnsupportedProvider => write!(f, "provider not implemented yet"),
            VerifyError::InvalidSecret { reason } => write!(f, "invalid secret: {reason}"),
            VerifyError::MissingContext { reason } => {
                write!(f, "missing verification context: {reason}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}

#[cfg(test)]
mod tests {
    use super::VerifyError;

    #[test]
    fn display_never_contains_secret_or_signature_material() {
        // Header names and static reasons only; nothing attacker- or
        // operator-supplied beyond counts/durations.
        let e = VerifyError::MalformedHeader {
            header: "X-Hub-Signature-256",
            reason: "empty",
        };
        assert_eq!(
            e.to_string(),
            "malformed header `X-Hub-Signature-256`: empty"
        );
    }
}
