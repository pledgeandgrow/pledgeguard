//! GitHub Actions output format.
//!
//! Produces `::error` and `::warning` annotations that GitHub Actions
//! renders inline in the PR diff and in the run summary.

use crate::finding::{Finding, Severity};

/// Convert a slice of findings into GitHub Actions annotation lines.
///
/// Each finding becomes one annotation:
///   `::error file=<path>,line=<line>,col=<col>::<severity> <rule_id>: <description>`
///
/// Critical/High findings use `::error`, Medium/Low use `::warning`.
pub fn to_github_actions(findings: &[Finding]) -> String {
    let mut out = String::new();
    for f in findings {
        let level = match f.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium | Severity::Low => "warning",
        };
        let path = f.path.display();
        let redacted = f.redacted();
        out.push_str(&format!(
            "::{level} file={path},line={},col={}::{} {}: {} (matched: {})\n",
            f.line,
            f.column,
            severity_label(f.severity),
            f.rule_id,
            f.description,
            redacted.matched,
        ));
    }
    out
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::VerificationStatus;
    use std::path::PathBuf;

    fn make_finding(severity: Severity, rule_id: &str, desc: &str, matched: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            description: desc.to_string(),
            severity,
            path: PathBuf::from("src/main.rs"),
            line: 42,
            column: 10,
            matched: matched.to_string(),
            context: format!("api_key = \"{}\"", matched),
            commit: None,
            likely_false_positive: false,
            verification: Some(VerificationStatus::Active),
        }
    }

    #[test]
    fn test_github_actions_critical_is_error() {
        let findings = vec![make_finding(
            Severity::Critical,
            "aws-access-key-id",
            "AWS Access Key ID",
            "AKIAIOSFODNN7EXAMPLE",
        )];
        let output = to_github_actions(&findings);
        assert!(output.starts_with("::error "));
        assert!(output.contains("file=src/main.rs"));
        assert!(output.contains("line=42"));
        assert!(output.contains("col=10"));
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("aws-access-key-id"));
    }

    #[test]
    fn test_github_actions_low_is_warning() {
        let findings = vec![make_finding(
            Severity::Low,
            "generic-api-key",
            "Generic API Key",
            "somekey123",
        )];
        let output = to_github_actions(&findings);
        assert!(output.starts_with("::warning "));
    }

    #[test]
    fn test_github_actions_redacts() {
        let findings = vec![make_finding(
            Severity::High,
            "github-pat",
            "GitHub PAT",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        )];
        let output = to_github_actions(&findings);
        // Should not contain the full token
        assert!(!output.contains("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn test_github_actions_empty() {
        let output = to_github_actions(&[]);
        assert!(output.is_empty());
    }
}
