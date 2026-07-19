//! Fuzz target for `Scanner::scan_str` with line-oriented input (goal 455).
//!
//! Run with: `cargo fuzz run scan_line`

#![no_main]

use libfuzzer_sys::fuzz_target;
use pledgeguard_core::{Scanner, builtin_detectors};
use std::path::PathBuf;

fuzz_target!(|data: &str| {
    let detectors = builtin_detectors();
    let scanner = Scanner::new(detectors);
    let path = PathBuf::from("fuzz.txt");
    // Should never panic regardless of input.
    let _ = scanner.scan_str(&path, data);
});
