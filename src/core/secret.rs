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
///
/// Equality and hashing compare the wrapped key bytes directly, so rotated
/// secrets can be compared and deduplicated (`HashSet<Secret>`) without the
/// value ever becoming readable.
#[must_use]
#[derive(Clone, Default, PartialEq, Eq, Hash)]
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

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&String> for Secret {
    fn from(value: &String) -> Self {
        Self::new(value)
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
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;

    #[cfg(feature = "std")]
    use std::collections::HashSet;

    use core::hash::{Hash, Hasher};

    use super::Secret;

    /// Trivial hasher so hash-derived comparisons work without pulling in
    /// `std`'s `SipHasher` (tests also run under `--no-default-features`).
    struct DummyHasher(u64);

    impl Hasher for DummyHasher {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            for (i, byte) in bytes.iter().enumerate() {
                self.0 = self
                    .0
                    .wrapping_mul(31)
                    .wrapping_add(*byte as u64 + i as u64);
            }
        }
    }

    fn hash64(secret: &Secret) -> u64 {
        let mut hasher = DummyHasher(0);
        secret.hash(&mut hasher);
        hasher.finish()
    }

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

    #[test]
    fn from_str_and_string_construct_the_same_secret() {
        // `From<&str>`/`From<String>`/`From<&String>` are the idiomatic
        // counterparts of `Secret::new`; they must produce identical secrets
        // (and identical redacted Debug output).
        let borrowed = Secret::from("shared-secret");
        let owned = Secret::from(String::from("shared-secret"));
        let borrowed_owned = Secret::from(&String::from("shared-secret"));
        for s in [&borrowed, &owned, &borrowed_owned] {
            assert_eq!(format!("{s:?}"), "Secret(**redacted**)");
            assert_eq!(s.as_bytes(), b"shared-secret");
        }
    }

    #[test]
    fn equal_secrets_from_any_constructor_compare_equal_and_hash_equal() {
        let a = Secret::new("rotating-key");
        let b = Secret::from("rotating-key");
        let c = Secret::from(String::from("rotating-key"));
        let d = Secret::from(&String::from("rotating-key"));
        for pair in [(&a, &b), (&a, &c), (&a, &d), (&b, &c), (&b, &d), (&c, &d)] {
            assert_eq!(pair.0, pair.1);
            assert_eq!(hash64(pair.0), hash64(pair.1));
        }
    }

    #[test]
    fn unequal_secrets_compare_unequal() {
        assert_ne!(Secret::new("key-a"), Secret::new("key-b"));
    }

    #[test]
    fn eq_and_hash_stay_in_lockstep() {
        // Derived `Hash` must agree with derived `PartialEq` exactly.
        let secrets = [
            Secret::new(""),
            Secret::new("a"),
            Secret::new("ab"),
            Secret::new("b"),
            Secret::new("rotating-key"),
            Secret::new("rotating-keY"),
        ];
        for left in &secrets {
            for right in &secrets {
                let same = left == right;
                assert_eq!(
                    same,
                    hash64(left) == hash64(right),
                    "eq and hash disagreed for {:?} vs {:?}",
                    *left,
                    *right
                );
            }
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn rotated_secrets_deduplicate_in_a_hash_set() {
        let mut known = HashSet::new();
        assert!(known.insert(Secret::new("current-key")));
        assert!(!known.insert(Secret::new("current-key")));
        assert!(known.insert(Secret::new("old-key")));
        assert_eq!(known.len(), 2);
    }
}
