//! CSV output format for scan findings.

use crate::finding::Finding;

/// Convert findings to a CSV string.
pub fn to_csv(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("rule_id,description,severity,path,line,column,matched,commit,verification\n");
    for f in findings {
        let matched = csv_escape(&f.matched);
        let description = csv_escape(&f.description);
        let path = csv_escape(&f.path.to_string_lossy());
        let commit = csv_escape(f.commit.as_deref().unwrap_or(""));
        let verification = csv_escape(
            &f.verification
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_default(),
        );
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            f.rule_id,
            description,
            f.severity,
            path,
            f.line,
            f.column,
            matched,
            commit,
            verification,
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::path::PathBuf;

    #[test]
    fn test_csv_basic() {
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
        let csv = to_csv(&findings);
        assert!(csv.contains("aws-access-key-id"));
        assert!(csv.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(csv.contains("src/config.rs"));
    }

    #[test]
    fn test_csv_escape_comma() {
        let s = csv_escape("hello,world");
        assert_eq!(s, "\"hello,world\"");
    }

    #[test]
    fn test_csv_escape_quote() {
        let s = csv_escape("hello\"world");
        assert_eq!(s, "\"hello\"\"world\"");
    }
}
