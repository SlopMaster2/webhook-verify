//! Core verification machinery shared by every provider: the error type, the
//! secret wrapper, the header abstraction, verification options, and the
//! audited crypto helpers.
//!
//! Changes here affect every provider and are treated as high-risk; see
//! `spec.md` §2 for the normative contract.

#![deny(clippy::unwrap_used, clippy::expect_used)]

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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    /// Every module that reads attacker-controlled input carries its own
    /// `deny(clippy::unwrap_used, clippy::expect_used)` inner attribute.
    ///
    /// `spec.md` §4 requirement 5 ("no panics on attacker-controlled input") is
    /// mechanical by design: a `.unwrap()` on a header value, a timestamp, or a
    /// hex/base64 digest is a panic on a request path, so the rule is enforced
    /// by a lint gate rather than left to review. The crate root has carried
    /// that gate since the first commit and still covers the whole tree, so this
    /// is defense in depth, not a hole being closed — what the per-module copy
    /// buys is that the rule is legible in the file a reader actually opens, and
    /// that it survives the module being moved, split out, or compiled on its
    /// own. The gate is also what keeps this crate's own tests honest: because it
    /// applies to `#[cfg(test)]` code too, every test in these modules asserts on
    /// the returned `VerifyError` variant (or returns `Result` and lets `?`
    /// propagate) instead of calling `.unwrap()`, which is how the whole suite
    /// came to contain none.
    ///
    /// It is a real convention rather than decoration. Requirement 5 named "the
    /// provider modules", and 60 of the 61 files in `src/providers/` carried the
    /// gate — but `src/providers/mod.rs`, the dispatch that reads headers and
    /// body bytes for *every* provider, did not, and neither did any of the
    /// seven `src/core/` modules. Those are precisely the files that parse the
    /// most attacker-controlled material: header values (`headers.rs`),
    /// timestamps in five formats (`replay.rs`), hex/base64 digests and
    /// verifying keys (`crypto.rs`, `options.rs`), and the §4.4 ambiguity scan
    /// that compares header values it did not produce (`adapter_utils.rs`). The
    /// set that read as exempt was the set where a panic introduced by a
    /// refactor would land on a request path.
    ///
    /// The directories are walked rather than a hand-written list enumerated, so
    /// a module added later is covered by adding the file instead of by
    /// remembering to edit a list — the same anti-drift reason the sibling
    /// source-scanning guards in `providers::tests` exist for. `src/tower.rs`
    /// and `src/actix.rs` are deliberately outside the walked set: per
    /// `AGENTS.md` §2 the adapters are framework glue carrying no signing or
    /// verification logic of their own, so there is no attacker-controlled
    /// parsing in them to gate. `src/test_helpers.rs` is `#[cfg(test)]`-only
    /// for the same reason.
    #[test]
    fn every_verification_module_denies_unwrap_and_expect() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));

        // The crate root first: it is the lint level that actually applies today,
        // so a future edit that drops it must fail here too, before the
        // per-module copies are credited for coverage they no longer provide.
        let lib = root.join("src/lib.rs");
        let Ok(lib_source) = fs::read_to_string(&lib) else {
            // `src/` is shipped in the crates.io tarball, so this is only a guard
            // against a packaging surprise: a crate-owned file the crate's own
            // tests must not fail on.
            return;
        };
        assert!(
            denies_unwrap_and_expect(&lib_source),
            "{} carries no `deny(clippy::unwrap_used, clippy::expect_used)` inner \
             attribute; that crate-level gate is what enforces `spec.md` §4 \
             requirement 5 for every module at once",
            lib.display(),
        );

        let core_dir = root.join("src/core");
        let providers_dir = root.join("src/providers");
        let core_checked = assert_every_module_denies_unwrap_and_expect(&core_dir);
        let provider_checked = assert_every_module_denies_unwrap_and_expect(&providers_dir);

        // A walk that silently found nothing would make this test pass vacuously
        // (a renamed directory, a manifest-dir surprise), which is the one way a
        // source-scanning guard can report coverage it does not have.
        assert!(
            core_checked > 0,
            "the no-panic gate scan found no modules under {}",
            core_dir.display()
        );
        assert!(
            provider_checked > 0,
            "the no-panic gate scan found no modules under {}",
            providers_dir.display()
        );
    }

    /// Requires the no-panic gate in every `*.rs` file directly under `dir`,
    /// returning how many files were checked.
    ///
    /// Unreadable files and non-Rust files are skipped rather than failing: the
    /// directories are part of the published crate, so a read failure is a
    /// packaging surprise and not a lint regression. The caller then requires a
    /// non-zero count, which is what keeps a skipped-everything walk from
    /// passing silently.
    fn assert_every_module_denies_unwrap_and_expect(dir: &Path) -> usize {
        let Ok(entries) = fs::read_dir(dir) else {
            return 0;
        };

        let mut checked = 0_usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Ok(source) = fs::read_to_string(&path) else {
                continue;
            };
            assert!(
                denies_unwrap_and_expect(&source),
                "{} reads attacker-controlled input (headers, timestamps, digests, \
                 verifying keys, or the raw body) but carries no \
                 `deny(clippy::unwrap_used, clippy::expect_used)` inner attribute. \
                 `spec.md` §4 requirement 5 is enforced by that gate, so a `.unwrap()` \
                 added here later would be a panic on a request path that no other \
                 test in the module would catch",
                path.display(),
            );
            checked += 1;
        }
        checked
    }

    /// Whether `source` denies (or forbids) both no-panic lints at module scope.
    ///
    /// Read per inner attribute rather than as one substring over the whole file,
    /// for two reasons. A whole-file search would be satisfied by the prose in a
    /// doc comment quoting the gate — which would make this guard pass in exactly
    /// the case it exists to catch. And the lints may legitimately be spelled in
    /// either order, or as `forbid` (strictly stronger than `deny`), so only the
    /// individual attribute is inspected: each `#![…]` item is collected up to
    /// its closing bracket, which also covers an attribute split across lines.
    fn denies_unwrap_and_expect(source: &str) -> bool {
        let mut unwrap_denied = false;
        let mut expect_denied = false;
        let mut rest = source;
        while let Some(at) = rest.find("#![") {
            let attr_and_rest = &rest[at..];
            // A `]` cannot appear inside a lint list, so the first one closes
            // this attribute. An unterminated one means the rest of the file is
            // not what this scan is looking for; stop rather than read past it.
            let Some(end) = attr_and_rest.find(']') else {
                break;
            };
            let attr = &attr_and_rest[..end];
            // `allow`/`warn` attributes are skipped deliberately: a file that
            // allows one of the lints somewhere is not covered by this check, and
            // clippy is the thing that reports the resulting hole.
            if attr.contains("deny(") || attr.contains("forbid(") {
                unwrap_denied |= attr.contains("clippy::unwrap_used");
                expect_denied |= attr.contains("clippy::expect_used");
            }
            rest = &attr_and_rest[end + 1..];
        }
        unwrap_denied && expect_denied
    }
}
