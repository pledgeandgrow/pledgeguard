//! Fuzz target for `Scanner::scan_str` (goal 455).
//!
//! Run with: `cargo fuzz run scan_bytes`

#![no_main]

use libfuzzer_sys::fuzz_target;
use pledgeguard_core::{Scanner, builtin_detectors};
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    let detectors = builtin_detectors();
    let scanner = Scanner::new(detectors);
    let path = PathBuf::from("fuzz.txt");
    // Should never panic regardless of input.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = scanner.scan_str(&path, s);
    }
});
