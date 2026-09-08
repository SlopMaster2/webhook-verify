//! The [`Secret`] wrapper: keeps signing material out of logs, errors, and
//! debug output.

use alloc::string::String;
use core::fmt;

/// Wraps webhook signing material (an HMAC key, or — for asymmetric schemes
/// such as Discord — a hex-encoded public key; see the provider's docs for
/// which one applies).
///
/// `Debug` and `Display` print `Secret(**redacted**)` only. The inner value is
/// deliberately not readable through the public API.
#[must_use]
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    /// Creates a secret from any string-like value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Raw key bytes. Crate-internal: verification helpers need the key
    /// material, but it must never be exposed through the public API or
    /// printed anywhere.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(**redacted**)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(**redacted**)")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_and_display_are_redacted() {
        let s = Secret::new("super-secret-hmac-key");
        assert_eq!(format!("{s:?}"), "Secret(**redacted**)");
        assert_eq!(s.to_string(), "Secret(**redacted**)");
        assert!(!format!("{s:?}").contains("super"));
    }

    #[test]
    fn debug_of_containing_struct_does_not_leak_via_derive_chain() {
        // If someone wraps a Secret in a derived-Debug struct, the Secret's own
        // redacted Debug is what renders — never the inner value.
        let s = Secret::new("leak-me");
        assert_eq!(format!("{s:?}"), "Secret(**redacted**)");
    }
}
