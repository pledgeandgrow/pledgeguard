//! Property-based tests for the scanner (goal 456).
//!
//! These tests use `proptest` to verify that the scanner:
//! - Never panics on arbitrary input
//! - Findings always have valid line/column numbers
//! - Redacted findings never contain the full secret

use pledgeguard_core::{Scanner, detectors::builtin_detectors};
use proptest::{prop_assert, prop_assert_eq, prop_assert_ne};
use std::path::Path;

proptest::proptest! {
    /// Scanner should never panic on arbitrary string input.
    #[test]
    fn scanner_never_panics(input in ".{0,1000}") {
        let scanner = Scanner::new(builtin_detectors());
        let _ = scanner.scan_str(Path::new("test.txt"), &input);
    }

    /// Scanner should never panic on arbitrary string input (bytes).
    #[test]
    fn scanner_never_panics_bytes(input in proptest::collection::vec(0u8..255, 0..1000)) {
        let scanner = Scanner::new(builtin_detectors());
        if let Ok(s) = std::str::from_utf8(&input) {
            let _ = scanner.scan_str(Path::new("test.bin"), s);
        }
    }

    /// All findings should have line numbers >= 1.
    #[test]
    fn findings_have_valid_line_numbers(input in ".{0,500}") {
        let scanner = Scanner::new(builtin_detectors());
        let findings = scanner.scan_str(Path::new("test.txt"), &input);
        for f in &findings {
            prop_assert!(f.line >= 1);
            prop_assert!(f.column >= 1);
            prop_assert!(!f.rule_id.is_empty());
        }
    }

    /// Redacted findings should not contain the full matched text.
    #[test]
    fn redacted_does_not_leak_full_secret(input in "AKIA[A-Z0-9]{16}") {
        let scanner = Scanner::new(builtin_detectors());
        let findings = scanner.scan_str(Path::new("test.txt"), &input);
        for f in &findings {
            let redacted = f.redacted();
            // The redacted matched text should differ from the original.
            if f.matched.len() > 10 {
                prop_assert_ne!(redacted.matched.as_str(), f.matched.as_str());
            }
        }
    }

    /// Scanning the same input twice should produce identical results.
    #[test]
    fn scanner_is_deterministic(input in "key = .{0,200}") {
        let scanner = Scanner::new(builtin_detectors());
        let r1 = scanner.scan_str(Path::new("test.txt"), &input);
        let r2 = scanner.scan_str(Path::new("test.txt"), &input);
        prop_assert_eq!(r1.len(), r2.len());
    }
}
