//! Snapshot tests for output formats (goal 457).
//!
//! These tests verify that output formats produce stable, expected output
//! for a known set of findings. If the output format changes, the snapshot
//! must be intentionally updated.

use pledgeguard_core::csv::to_csv;
use pledgeguard_core::output_formats::{to_jsonl, to_xml};
use pledgeguard_core::sarif::to_sarif;
use pledgeguard_core::{Finding, Severity, VerificationStatus};
use std::path::PathBuf;

fn sample_findings() -> Vec<Finding> {
    vec![
        Finding {
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            severity: Severity::Critical,
            path: PathBuf::from("src/config.rs"),
            line: 42,
            column: 15,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "    aws_key = \"AKIAIOSFODNN7EXAMPLE\"".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: Some(VerificationStatus::Active),
        },
        Finding {
            rule_id: "github-pat".to_string(),
            description: "GitHub Personal Access Token".to_string(),
            severity: Severity::High,
            path: PathBuf::from("src/auth.rs"),
            line: 10,
            column: 1,
            matched: "ghp_1234567890abcdef1234567890abcdef1234".to_string(),
            context: "token = ghp_1234567890abcdef1234567890abcdef1234".to_string(),
            commit: Some("abc123".to_string()),
            likely_false_positive: false,
            verification: None,
        },
    ]
}

#[test]
fn snapshot_csv_format() {
    let findings = sample_findings();
    let csv = to_csv(&findings);
    let expected = "rule_id,description,severity,path,line,column,matched,commit,verification\n\
aws-access-key-id,AWS Access Key ID,critical,src/config.rs,42,15,AKIAIOSFODNN7EXAMPLE,,active\n\
github-pat,GitHub Personal Access Token,high,src/auth.rs,10,1,ghp_1234567890abcdef1234567890abcdef1234,abc123,\n";
    assert_eq!(csv, expected);
}

#[test]
fn snapshot_jsonl_format() {
    let findings = sample_findings();
    let jsonl = to_jsonl(&findings);
    let lines: Vec<&str> = jsonl.trim().lines().collect();
    assert_eq!(lines.len(), 2);

    // Verify each line is valid JSON with expected fields.
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["rule_id"], "aws-access-key-id");
    assert_eq!(first["severity"], "critical");
    assert_eq!(first["line"], 42);
}

#[test]
fn snapshot_sarif_format() {
    let findings = sample_findings();
    let sarif = to_sarif(&findings);
    let obj = sarif.as_object().unwrap();
    assert!(obj.contains_key("runs"));
    let runs = obj["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    let results = runs[0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn snapshot_xml_format() {
    let findings = sample_findings();
    let xml = to_xml(&findings);
    assert!(xml.contains("<?xml"));
    assert!(xml.contains("<findings>"));
    assert!(xml.contains("aws-access-key-id"));
    assert!(xml.contains("github-pat"));
}
