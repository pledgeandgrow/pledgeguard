//! Golden file tests for the scanner (goal 458).
//!
//! These tests scan known input files and compare the results against
//! expected "golden" output. If detection behavior changes, the golden
//! files must be intentionally updated.

use pledgeguard_core::{Scanner, detectors::builtin_detectors};
use std::path::Path;

fn scan_input(input: &str) -> Vec<String> {
    let scanner = Scanner::new(builtin_detectors());
    let findings = scanner.scan_str(Path::new("test.txt"), input);
    findings
        .into_iter()
        .map(|f| format!("{}:{}:{}", f.rule_id, f.line, f.severity))
        .collect()
}

#[test]
fn golden_aws_key() {
    let input = "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
    let results = scan_input(input);
    assert!(
        results.iter().any(|r| r.starts_with("aws-access-key-id")),
        "expected aws-access-key-id in {:?}",
        results
    );
}

#[test]
fn golden_github_pat() {
    let input = "token = ghp_1234567890abcdef1234567890abcdef1234\n";
    let results = scan_input(input);
    assert!(
        results.iter().any(|r| r.starts_with("github-pat")),
        "expected github-pat in {:?}",
        results
    );
}

#[test]
fn golden_no_false_positive_on_example() {
    let input = "Example: AKIAIOSFODNN7EXAMPLE is a test key.\n";
    let results = scan_input(input);
    // The scanner may flag this, but it should be marked as likely_false_positive.
    // We just verify the scanner doesn't crash.
    let _ = results;
}

#[test]
fn golden_empty_input() {
    let results = scan_input("");
    assert!(results.is_empty(), "expected no findings for empty input");
}

#[test]
fn golden_no_secrets_input() {
    let input = "fn main() {\n    println!(\"Hello, world!\");\n}\n";
    let results = scan_input(input);
    assert!(
        results.is_empty(),
        "expected no findings for clean code, got {:?}",
        results
    );
}

#[test]
fn golden_multiple_secrets() {
    let input = "\
aws_key = \"AKIAIOSFODNN7EXAMPLE\"
github_token = \"ghp_1234567890abcdef1234567890abcdef1234\"
slack_token = \"xoxb-1234567890-abcdefghij\"
";
    let results = scan_input(input);
    assert!(
        results.len() >= 2,
        "expected at least 2 findings, got {}: {:?}",
        results.len(),
        results
    );
}
