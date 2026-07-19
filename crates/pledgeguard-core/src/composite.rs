//! Composite/proximity rules.
//!
//! Composite rules match when multiple patterns are found within proximity
//! of each other in the same file. This reduces false positives by requiring
//! corroboration (e.g., an AWS key ID near a secret key, or a "password"
//! label near a high-entropy string).

use crate::finding::Finding;
use std::path::Path;

/// A composite rule definition.
#[derive(Debug, Clone)]
pub struct CompositeRule {
    pub id: String,
    pub description: String,
    pub severity: crate::finding::Severity,
    /// The primary pattern to match (regex).
    pub pattern: regex::Regex,
    /// Patterns that must also match within `proximity` lines of the primary match.
    pub require_patterns: Vec<regex::Regex>,
    /// Maximum number of lines between the primary match and required patterns.
    pub proximity: usize,
}

/// Scan a file's contents for composite rule matches.
/// Returns findings for each primary match where all required patterns
/// are found within the proximity window.
pub fn scan_composite(
    contents: &str,
    path: &Path,
    rules: &[CompositeRule],
) -> Vec<Finding> {
    let lines: Vec<&str> = contents.lines().collect();
    let mut findings = Vec::new();

    for rule in rules {
        for (idx, line) in lines.iter().enumerate() {
            if let Some(m) = rule.pattern.find(line) {
                // Check if all required patterns match within proximity window.
                let start = idx.saturating_sub(rule.proximity);
                let end = (idx + rule.proximity + 1).min(lines.len());
                let window = &lines[start..end];

                let mut all_matched = true;
                for req_pat in &rule.require_patterns {
                    let found = window.iter().any(|w| req_pat.is_match(w));
                    if !found {
                        all_matched = false;
                        break;
                    }
                }

                if all_matched {
                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        description: rule.description.clone(),
                        severity: rule.severity,
                        path: path.to_path_buf(),
                        line: idx + 1,
                        column: m.start() + 1,
                        matched: m.as_str().to_string(),
                        context: line.to_string(),
                        commit: None,
                        likely_false_positive: false,
                        verification: None,
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn test_composite_match_within_proximity() {
        let rule = CompositeRule {
            id: "aws-keypair".to_string(),
            description: "AWS Key Pair".to_string(),
            severity: Severity::Critical,
            pattern: regex::Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
            require_patterns: vec![regex::Regex::new(r"(?i)secret").unwrap()],
            proximity: 3,
        };

        let contents = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG\n";
        let findings = scan_composite(contents, Path::new("test.env"), &[rule]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-keypair");
    }

    #[test]
    fn test_composite_no_match_outside_proximity() {
        let rule = CompositeRule {
            id: "aws-keypair".to_string(),
            description: "AWS Key Pair".to_string(),
            severity: Severity::Critical,
            pattern: regex::Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
            require_patterns: vec![regex::Regex::new(r"(?i)secret").unwrap()],
            proximity: 1,
        };

        // "secret" is on line 10, key is on line 1 — outside proximity of 1.
        let contents = "key = AKIAIOSFODNN7EXAMPLE\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nsecret = abc\n";
        let findings = scan_composite(contents, Path::new("test.env"), &[rule]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_composite_multiple_required_patterns() {
        let rule = CompositeRule {
            id: "multi-require".to_string(),
            description: "Multi Required".to_string(),
            severity: Severity::High,
            pattern: regex::Regex::new(r"TOKEN_[A-Z0-9]+").unwrap(),
            require_patterns: vec![
                regex::Regex::new(r"(?i)password").unwrap(),
                regex::Regex::new(r"(?i)username").unwrap(),
            ],
            proximity: 5,
        };

        let contents = "username = admin\npassword = hunter2\ntoken = TOKEN_ABC123\n";
        let findings = scan_composite(contents, Path::new("test.txt"), &[rule]);
        assert_eq!(findings.len(), 1);
    }
}
