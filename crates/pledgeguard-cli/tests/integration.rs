//! End-to-end integration tests that run the actual `pledgeguard` binary
//! against fixture files and verify CLI behavior.

use std::fs;
use std::process::Command;

/// Path to the built pledgeguard binary.
fn pledgeguard() -> String {
    env!("CARGO_BIN_EXE_pledgeguard").to_string()
}

/// Create a temp directory with a fixture file containing a known secret.
fn make_fixture(content: &str, ext: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("test.{}", ext));
    fs::write(&path, content).unwrap();
    dir
}

#[test]
fn test_scan_finds_aws_key() {
    let dir = make_fixture("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "env");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("aws-access-key-id"), "stdout: {stdout}");
}

#[test]
fn test_scan_no_secrets() {
    let dir = make_fixture("just some plain text\n", "txt");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No secrets found"), "stdout: {stdout}");
}

#[test]
fn test_scan_json_output() {
    let dir = make_fixture("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "env");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(parsed.is_array());
    assert!(!parsed.as_array().unwrap().is_empty());
}

#[test]
fn test_scan_sarif_output() {
    let dir = make_fixture("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "env");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap(), "--format", "sarif"])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "PledgeGuard");
}

#[test]
fn test_scan_fail_on_findings_exit_code() {
    let dir = make_fixture("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "env");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap(), "--fail-on-findings"])
        .output()
        .expect("failed to run pledgeguard");

    assert!(
        !output.status.success(),
        "should exit non-zero with findings"
    );
}

#[test]
fn test_scan_no_findings_exit_code() {
    let dir = make_fixture("nothing here\n", "txt");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap(), "--fail-on-findings"])
        .output()
        .expect("failed to run pledgeguard");

    assert!(output.status.success(), "should exit zero with no findings");
}

#[test]
fn test_scan_min_severity_filters() {
    // AWS key is Critical, GitHub PAT is Critical. Use a bearer token (Low)
    // mixed with a critical to verify filtering.
    let dir = make_fixture(
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nbearer some-long-opaque-token-value-here-1234567890\n",
        "env",
    );
    let output = Command::new(pledgeguard())
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--min-severity",
            "critical",
            "--show-all",
        ])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // AWS key is Critical — should appear. Bearer token is Low — should be filtered.
    assert!(
        stdout.contains("aws-access-key-id"),
        "critical finding should appear at critical level; stdout: {stdout}"
    );
    assert!(
        !stdout.contains("generic-bearer-token"),
        "low-severity finding should be filtered at critical level; stdout: {stdout}"
    );
}

#[test]
fn test_scan_redact_by_default() {
    let dir = make_fixture("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "env");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret should be redacted by default; stdout: {stdout}"
    );
}

#[test]
fn test_scan_no_redact_flag() {
    let dir = make_fixture("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "env");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap(), "--no-redact"])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret should be visible with --no-redact; stdout: {stdout}"
    );
}

#[test]
fn test_scan_show_all_reveals_false_positives() {
    // A secret in a comment line should be flagged as likely false positive.
    let dir = make_fixture("// AKIAIOSFODNN7EXAMPLE\n", "js");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hidden") || stdout.contains("No secrets found"),
        "false positive should be hidden by default; stdout: {stdout}"
    );

    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap(), "--show-all"])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("aws-access-key-id"),
        "false positive should be visible with --show-all; stdout: {stdout}"
    );
}

#[test]
fn test_baseline_save_and_filter() {
    let dir = make_fixture("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "env");
    let baseline_path = dir.path().join(".baseline.json");

    // Save baseline.
    Command::new(pledgeguard())
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--save-baseline",
            baseline_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pledgeguard");

    assert!(baseline_path.exists(), "baseline file should be created");

    // Now scan with baseline — should suppress the finding.
    let output = Command::new(pledgeguard())
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--baseline",
            baseline_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("suppressed") || stdout.contains("No secrets found"),
        "finding should be suppressed by baseline; stdout: {stdout}, stderr: {stderr}"
    );
}

#[test]
fn test_install_pre_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    // Init a git repo.
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(path)
        .status()
        .expect("git init failed");

    // Install the hook.
    let output = Command::new(pledgeguard())
        .args(["install-pre-commit", path.to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("installed"), "stdout: {stdout}");

    let hook_path = path.join(".git").join("hooks").join("pre-commit");
    assert!(hook_path.exists(), "pre-commit hook file should exist");

    // Running again without --force should fail.
    let output = Command::new(pledgeguard())
        .args(["install-pre-commit", path.to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    assert!(
        !output.status.success(),
        "should fail without --force when hook exists"
    );

    // Running with --force should succeed.
    let output = Command::new(pledgeguard())
        .args(["install-pre-commit", path.to_str().unwrap(), "--force"])
        .output()
        .expect("failed to run pledgeguard");

    assert!(output.status.success(), "should succeed with --force");
}

#[test]
fn test_scan_github_pat() {
    let dir = make_fixture("token=ghp_1234567890abcdef1234567890abcdef1234\n", "env");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("github-pat"), "stdout: {stdout}");
}

#[test]
fn test_scan_private_key() {
    let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----\n";
    let dir = make_fixture(key, "pem");
    let output = Command::new(pledgeguard())
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run pledgeguard");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("private-key"), "stdout: {stdout}");
}
