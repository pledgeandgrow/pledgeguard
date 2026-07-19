//! Template output format for scan findings.
//!
//! Uses a simple Go-style template syntax (`{{.Field}}`) to let users
//! customize output format. If no template is provided, a default
//! summary template is used.

use crate::finding::Finding;

/// Render findings using a template string.
/// Supports `{{.RuleId}}`, `{{.Description}}`, `{{.Severity}}`, `{{.Path}}`,
/// `{{.Line}}`, `{{.Column}}`, `{{.Matched}}`, `{{.Commit}}`, `{{.Context}}`.
pub fn to_template(findings: &[Finding], template: Option<&str>) -> String {
    let tmpl = template.unwrap_or(DEFAULT_TEMPLATE);
    let mut out = String::new();
    for f in findings {
        let mut line = tmpl.to_string();
        line = line.replace("{{.RuleId}}", &f.rule_id);
        line = line.replace("{{.Description}}", &f.description);
        line = line.replace("{{.Severity}}", &f.severity.to_string());
        line = line.replace("{{.Path}}", &f.path.to_string_lossy());
        line = line.replace("{{.Line}}", &f.line.to_string());
        line = line.replace("{{.Column}}", &f.column.to_string());
        line = line.replace("{{.Matched}}", &f.matched);
        line = line.replace("{{.Commit}}", f.commit.as_deref().unwrap_or(""));
        line = line.replace("{{.Context}}", &f.context);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

const DEFAULT_TEMPLATE: &str =
    "[{{.Severity}}] {{.RuleId}}: {{.Matched}} at {{.Path}}:{{.Line}}:{{.Column}}";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::path::PathBuf;

    #[test]
    fn test_template_default() {
        let findings = vec![Finding {
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            severity: Severity::High,
            path: PathBuf::from("src/config.rs"),
            line: 42,
            column: 1,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "key = AKIAIOSFODNN7EXAMPLE".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }];
        let out = to_template(&findings, None);
        assert!(out.contains("aws-access-key-id"));
        assert!(out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("src/config.rs"));
        assert!(out.contains("42"));
    }

    #[test]
    fn test_template_custom() {
        let findings = vec![Finding {
            rule_id: "test-rule".to_string(),
            description: "Test".to_string(),
            severity: Severity::Low,
            path: PathBuf::from("a.txt"),
            line: 1,
            column: 1,
            matched: "secret123".to_string(),
            context: "secret123".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }];
        let tmpl = "Rule: {{.RuleId}} | File: {{.Path}} | Match: {{.Matched}}";
        let out = to_template(&findings, Some(tmpl));
        assert!(out.contains("Rule: test-rule"));
        assert!(out.contains("File: a.txt"));
        assert!(out.contains("Match: secret123"));
    }
}
