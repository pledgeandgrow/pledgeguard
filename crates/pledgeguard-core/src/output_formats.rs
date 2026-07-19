//! Additional output formats (goals 242-248): HTML, Markdown, SPDX,
//! CycloneDX, Prometheus, JSON Lines, XML.
//!
//! Each function takes a slice of findings and returns a formatted string.

use crate::finding::Finding;

/// Convert findings to a self-contained HTML report with summary stats.
pub fn to_html(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"UTF-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    out.push_str("<title>PledgeGuard Scan Report</title>\n");
    out.push_str("<style>\n");
    out.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; background: #f8f9fa; }\n");
    out.push_str("h1 { color: #1a1a2e; }\n");
    out.push_str(".summary { display: flex; gap: 1rem; margin-bottom: 2rem; }\n");
    out.push_str(".card { background: white; padding: 1rem 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); flex: 1; }\n");
    out.push_str(".card .count { font-size: 2rem; font-weight: bold; }\n");
    out.push_str(".critical { color: #dc3545; }\n");
    out.push_str(".high { color: #fd7e14; }\n");
    out.push_str(".medium { color: #ffc107; }\n");
    out.push_str(".low { color: #28a745; }\n");
    out.push_str("table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }\n");
    out.push_str("th { background: #1a1a2e; color: white; padding: 0.75rem; text-align: left; }\n");
    out.push_str("td { padding: 0.75rem; border-bottom: 1px solid #eee; }\n");
    out.push_str("tr:hover { background: #f5f5f5; }\n");
    out.push_str(".sev-critical { background: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }\n");
    out.push_str(".sev-high { background: #fd7e14; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }\n");
    out.push_str(".sev-medium { background: #ffc107; color: #333; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }\n");
    out.push_str(".sev-low { background: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }\n");
    out.push_str("code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 0.9rem; }\n");
    out.push_str("</style>\n</head>\n<body>\n");

    // Summary
    let critical = findings.iter().filter(|f| f.severity == crate::finding::Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == crate::finding::Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == crate::finding::Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == crate::finding::Severity::Low).count();

    out.push_str("<h1>PledgeGuard Scan Report</h1>\n");
    out.push_str(&format!("<p>Generated: {}</p>\n", current_timestamp()));
    out.push_str("<div class=\"summary\">\n");
    out.push_str(&format!("<div class=\"card\"><div class=\"count critical\">{critical}</div><div>Critical</div></div>\n"));
    out.push_str(&format!("<div class=\"card\"><div class=\"count high\">{high}</div><div>High</div></div>\n"));
    out.push_str(&format!("<div class=\"card\"><div class=\"count medium\">{medium}</div><div>Medium</div></div>\n"));
    out.push_str(&format!("<div class=\"card\"><div class=\"count low\">{low}</div><div>Low</div></div>\n"));
    out.push_str(&format!("<div class=\"card\"><div class=\"count\">{}</div><div>Total</div></div>\n", findings.len()));
    out.push_str("</div>\n");

    // Findings table
    if findings.is_empty() {
        out.push_str("<p>No findings. Your codebase looks clean!</p>\n");
    } else {
        out.push_str("<table>\n<thead>\n<tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Matched</th><th>Context</th></tr>\n</thead>\n<tbody>\n");
        for f in findings {
            let sev_class = match f.severity {
                crate::finding::Severity::Critical => "sev-critical",
                crate::finding::Severity::High => "sev-high",
                crate::finding::Severity::Medium => "sev-medium",
                crate::finding::Severity::Low => "sev-low",
            };
            let sev_label = format!("{:?}", f.severity);
            let context = html_escape(&f.context);
            let matched = html_escape(&f.matched);
            out.push_str(&format!(
                "<tr><td><span class=\"{sev_class}\">{sev_label}</span></td><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{matched}</code></td><td>{context}</td></tr>\n",
                html_escape(&f.rule_id),
                html_escape(&f.path.display().to_string()),
                f.line,
            ));
        }
        out.push_str("</tbody>\n</table>\n");
    }

    out.push_str("</body>\n</html>\n");
    out
}

/// Convert findings to a Markdown report suitable for PR comments.
pub fn to_markdown(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("# PledgeGuard Scan Report\n\n");

    let critical = findings.iter().filter(|f| f.severity == crate::finding::Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == crate::finding::Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == crate::finding::Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == crate::finding::Severity::Low).count();

    out.push_str("## Summary\n\n");
    out.push_str("| Severity | Count |\n|---|---|\n");
    out.push_str(&format!("| Critical | {} |\n", critical));
    out.push_str(&format!("| High | {} |\n", high));
    out.push_str(&format!("| Medium | {} |\n", medium));
    out.push_str(&format!("| Low | {} |\n", low));
    out.push_str(&format!("| **Total** | **{}** |\n\n", findings.len()));

    if findings.is_empty() {
        out.push_str("No findings detected. \n");
    } else {
        out.push_str("## Findings\n\n");
        out.push_str("| Severity | Rule | File | Line | Matched |\n");
        out.push_str("|---|---|---|---|---|\n");
        for f in findings {
            let sev = format!("{:?}", f.severity);
            out.push_str(&format!(
                "| {} | `{}` | `{}` | {} | `{}` |\n",
                sev,
                md_escape(&f.rule_id),
                md_escape(&f.path.display().to_string()),
                f.line,
                md_escape(&f.matched),
            ));
        }
    }

    out
}

/// Convert findings to SPDX-like JSON for SBOM-compatible secret report.
pub fn to_spdx(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"spdxVersion\": \"SPDX-2.3\",\n");
    out.push_str("  \"dataLicense\": \"CC0-1.0\",\n");
    out.push_str("  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n");
    out.push_str("  \"name\": \"PledgeGuard Secret Report\",\n");
    out.push_str("  \"creationInfo\": {\n");
    out.push_str(&format!("    \"created\": \"{}\",\n", current_timestamp()));
    out.push_str("    \"creators\": [\"Tool: PledgeGuard\"]\n");
    out.push_str("  },\n");
    out.push_str("  \"findings\": [\n");
    for (i, f) in findings.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"SPDXID\": \"SPDXRef-finding-{}\",\n", i + 1));
        out.push_str(&format!("      \"ruleId\": \"{}\",\n", json_escape(&f.rule_id)));
        out.push_str(&format!("      \"severity\": \"{}\",\n", format!("{:?}", f.severity).to_lowercase()));
        out.push_str(&format!("      \"filePath\": \"{}\",\n", json_escape(&f.path.display().to_string())));
        out.push_str(&format!("      \"line\": {},\n", f.line));
        out.push_str(&format!("      \"matched\": \"{}\"\n", json_escape(&f.matched)));
        out.push_str("    }");
        if i + 1 < findings.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// Convert findings to CycloneDX JSON for SBOM integration.
pub fn to_cyclonedx(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"bomFormat\": \"CycloneDX\",\n");
    out.push_str("  \"specVersion\": \"1.5\",\n");
    out.push_str(&format!("  \"serialNumber\": \"urn:uuid:{}\",\n", uuid_v4()));
    out.push_str("  \"version\": 1,\n");
    out.push_str("  \"metadata\": {\n");
    out.push_str("    \"tools\": [{\"vendor\": \"PledgeGuard\", \"name\": \"pledgeguard\", \"version\": \"1.0\"}]\n");
    out.push_str("  },\n");
    out.push_str("  \"vulnerabilities\": [\n");
    for (i, f) in findings.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"id\": \"PG-{}\",\n", i + 1));
        out.push_str(&format!("      \"description\": \"{}\",\n", json_escape(&f.description)));
        out.push_str(&format!("      \"ratings\": [{{\"severity\": \"{}\"}}],\n", format!("{:?}", f.severity).to_lowercase()));
        out.push_str(&format!("      \"affects\": [{{\"ref\": \"{}\"}}]\n", json_escape(&f.path.display().to_string())));
        out.push_str("    }");
        if i + 1 < findings.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// Convert findings to Prometheus metrics format.
pub fn to_prometheus(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("# HELP pledgeguard_findings_total Total number of findings by severity\n");
    out.push_str("# TYPE pledgeguard_findings_total gauge\n");

    let critical = findings.iter().filter(|f| f.severity == crate::finding::Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == crate::finding::Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == crate::finding::Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == crate::finding::Severity::Low).count();

    out.push_str(&format!("pledgeguard_findings_total{{severity=\"critical\"}} {critical}\n"));
    out.push_str(&format!("pledgeguard_findings_total{{severity=\"high\"}} {high}\n"));
    out.push_str(&format!("pledgeguard_findings_total{{severity=\"medium\"}} {medium}\n"));
    out.push_str(&format!("pledgeguard_findings_total{{severity=\"low\"}} {low}\n"));
    out.push_str(&format!("pledgeguard_findings_total{{severity=\"all\"}} {}\n", findings.len()));

    // Per-rule counts
    out.push_str("\n# HELP pledgeguard_findings_by_rule Findings count by rule ID\n");
    out.push_str("# TYPE pledgeguard_findings_by_rule gauge\n");
    let mut rule_counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in findings {
        *rule_counts.entry(f.rule_id.as_str()).or_insert(0) += 1;
    }
    for (rule, count) in &rule_counts {
        out.push_str(&format!("pledgeguard_findings_by_rule{{rule=\"{rule}\"}} {count}\n"));
    }

    out
}

/// Convert findings to JSON Lines format (one JSON object per line).
pub fn to_jsonl(findings: &[Finding]) -> String {
    let mut out = String::new();
    for f in findings {
        let json = serde_json::json!({
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": format!("{:?}", f.severity).to_lowercase(),
            "path": f.path.display().to_string(),
            "line": f.line,
            "column": f.column,
            "matched": f.matched,
            "context": f.context,
            "commit": f.commit,
            "likely_false_positive": f.likely_false_positive,
            "verification": f.verification.as_ref().map(|v| format!("{:?}", v)),
        });
        out.push_str(&json.to_string());
        out.push('\n');
    }
    out
}

/// Convert findings to XML format for enterprise/SOAP integrations.
pub fn to_xml(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<pledgeguard>\n");
    out.push_str(&format!("  <summary total=\"{}\" />\n", findings.len()));
    out.push_str("  <findings>\n");
    for f in findings {
        out.push_str("    <finding>\n");
        out.push_str(&format!("      <ruleId>{}</ruleId>\n", xml_escape(&f.rule_id)));
        out.push_str(&format!("      <description>{}</description>\n", xml_escape(&f.description)));
        out.push_str(&format!("      <severity>{}</severity>\n", format!("{:?}", f.severity).to_lowercase()));
        out.push_str(&format!("      <path>{}</path>\n", xml_escape(&f.path.display().to_string())));
        out.push_str(&format!("      <line>{}</line>\n", f.line));
        out.push_str(&format!("      <column>{}</column>\n", f.column));
        out.push_str(&format!("      <matched>{}</matched>\n", xml_escape(&f.matched)));
        out.push_str(&format!("      <context>{}</context>\n", xml_escape(&f.context)));
        out.push_str("    </finding>\n");
    }
    out.push_str("  </findings>\n");
    out.push_str("</pledgeguard>\n");
    out
}

// ── Helpers ────────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('`', "\\`")
        .replace('\n', " ")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn uuid_v4() -> String {
    // Simple UUID v4 generation without external crate
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (now & 0xFFFFFFFF) as u32,
        ((now >> 32) & 0xFFFF) as u16,
        ((now >> 48) & 0xFFF) as u16,
        ((now >> 60) & 0xFFFF) as u16 | 0x8000,
        (now >> 76) & 0xFFFFFFFFFFFF,
    )
}

fn current_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple Unix timestamp to ISO 8601 conversion
    let days = now / 86400;
    let secs = now % 86400;
    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;
    // Calculate date from days since epoch (1970-01-01)
    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let month_lengths = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &ml in &month_lengths {
        if remaining < ml {
            break;
        }
        remaining -= ml;
        month += 1;
    }
    (year, month, remaining + 1)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::path::PathBuf;

    fn test_findings() -> Vec<Finding> {
        vec![
            Finding {
                rule_id: "aws-access-key".to_string(),
                description: "AWS Access Key ID".to_string(),
                severity: Severity::Critical,
                path: PathBuf::from("src/config.rs"),
                line: 42,
                column: 1,
                matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
                context: "aws_key = AKIAIOSFODNN7EXAMPLE".to_string(),
                commit: None,
                likely_false_positive: false,
                verification: None,
            },
            Finding {
                rule_id: "github-token".to_string(),
                description: "GitHub Personal Access Token".to_string(),
                severity: Severity::High,
                path: PathBuf::from(".env"),
                line: 10,
                column: 1,
                matched: "ghp_xxxxxxxxxxxxxxxxxxxx".to_string(),
                context: "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx".to_string(),
                commit: None,
                likely_false_positive: false,
                verification: None,
            },
        ]
    }

    #[test]
    fn test_to_html() {
        let findings = test_findings();
        let html = to_html(&findings);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(html.contains("PledgeGuard"));
    }

    #[test]
    fn test_to_html_empty() {
        let html = to_html(&[]);
        assert!(html.contains("No findings"));
    }

    #[test]
    fn test_to_markdown() {
        let findings = test_findings();
        let md = to_markdown(&findings);
        assert!(md.contains("# PledgeGuard Scan Report"));
        assert!(md.contains("| Critical |"));
        assert!(md.contains("aws-access-key"));
    }

    #[test]
    fn test_to_markdown_empty() {
        let md = to_markdown(&[]);
        assert!(md.contains("No findings"));
    }

    #[test]
    fn test_to_spdx() {
        let findings = test_findings();
        let spdx = to_spdx(&findings);
        assert!(spdx.contains("\"spdxVersion\": \"SPDX-2.3\""));
        assert!(spdx.contains("\"SPDXID\""));
        assert!(spdx.contains("aws-access-key"));
    }

    #[test]
    fn test_to_cyclonedx() {
        let findings = test_findings();
        let cdx = to_cyclonedx(&findings);
        assert!(cdx.contains("\"bomFormat\": \"CycloneDX\""));
        assert!(cdx.contains("\"vulnerabilities\""));
        assert!(cdx.contains("AWS Access Key ID"));
    }

    #[test]
    fn test_to_prometheus() {
        let findings = test_findings();
        let prom = to_prometheus(&findings);
        assert!(prom.contains("pledgeguard_findings_total"));
        assert!(prom.contains("severity=\"critical\""));
        assert!(prom.contains("pledgeguard_findings_by_rule"));
    }

    #[test]
    fn test_to_jsonl() {
        let findings = test_findings();
        let jsonl = to_jsonl(&findings);
        let lines: Vec<&str> = jsonl.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"rule_id\""));
        assert!(lines[0].contains("aws-access-key"));
    }

    #[test]
    fn test_to_xml() {
        let findings = test_findings();
        let xml = to_xml(&findings);
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<pledgeguard>"));
        assert!(xml.contains("<ruleId>aws-access-key</ruleId>"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("\"hello\""), "&quot;hello&quot;");
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn test_md_escape() {
        assert_eq!(md_escape("a|b"), "a\\|b");
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello\"world"), "hello\\\"world");
        assert_eq!(json_escape("line\nbreak"), "line\\nbreak");
    }
}
