//! JUnit XML output format for scan findings (for CI/CD integration).

use crate::finding::Finding;

/// Convert findings to a JUnit XML string.
pub fn to_junit(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<testsuites>\n");
    out.push_str(&format!(
        "  <testsuite name=\"pledgeguard\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"0\">\n",
        findings.len(),
        findings.len(),
    ));

    for f in findings {
        let classname = xml_escape(&f.path.to_string_lossy());
        let name = xml_escape(&format!("{}:{}", f.rule_id, f.line));
        let message = xml_escape(&format!(
            "{}: {} at {}:{}:{} — {}",
            f.severity,
            f.rule_id,
            f.path.display(),
            f.line,
            f.column,
            f.matched,
        ));
        out.push_str(&format!(
            "    <testcase classname=\"{}\" name=\"{}\">\n",
            classname, name,
        ));
        out.push_str(&format!(
            "      <failure message=\"{}\" type=\"{}\">{}</failure>\n",
            message,
            f.severity,
            message,
        ));
        out.push_str("    </testcase>\n");
    }

    out.push_str("  </testsuite>\n");
    out.push_str("</testsuites>\n");
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::path::PathBuf;

    #[test]
    fn test_junit_basic() {
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
        let xml = to_junit(&findings);
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("testsuites"));
        assert!(xml.contains("aws-access-key-id"));
        assert!(xml.contains("<failure"));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a<b>c&d\"e"), "a&lt;b&gt;c&amp;d&quot;e");
    }
}
