//! SARIF 2.1.0 output, for GitHub Code Scanning / other SARIF consumers.
//!
//! Produces a minimal-but-valid SARIF log: one `run`, one `tool.driver`
//! with a deduplicated `rules` array, and one `result` per finding.
//! See <https://docs.oasis-open.org/sarif/sarif/v2.1.0/> for the spec.

use crate::finding::{Finding, Severity};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Converts findings into a SARIF 2.1.0 log document.
///
/// Callers should pass already-filtered/redacted findings (the same set
/// that would otherwise be printed as JSON or a table) — this function
/// does not filter by severity or hide `likely_false_positive` findings.
pub fn to_sarif(findings: &[Finding]) -> Value {
    let mut rules: BTreeMap<&str, &str> = BTreeMap::new();
    for f in findings {
        rules
            .entry(f.rule_id.as_str())
            .or_insert(f.description.as_str());
    }

    let rules: Vec<Value> = rules
        .into_iter()
        .map(|(id, description)| {
            json!({
                "id": id,
                "shortDescription": { "text": description },
            })
        })
        .collect();

    let results: Vec<Value> = findings.iter().map(finding_to_result).collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PledgeGuard",
                        "informationUri": "https://github.com/pledgelabs/pledgeguard",
                        "version": env!("CARGO_PKG_VERSION"),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ]
    })
}

fn finding_to_result(f: &Finding) -> Value {
    let uri = f.path.to_string_lossy().replace('\\', "/");
    let mut message = f.description.clone();
    if let Some(commit) = &f.commit {
        message.push_str(&format!(" (commit {})", &commit[..commit.len().min(8)]));
    }
    if let Some(v) = &f.verification {
        message.push_str(&format!(" [live check: {v}]"));
    }

    json!({
        "ruleId": f.rule_id,
        "level": sarif_level(f.severity),
        "message": { "text": message },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": { "uri": uri },
                    "region": {
                        "startLine": f.line,
                        "startColumn": f.column,
                    }
                }
            }
        ],
        "partialFingerprints": {
            "pledgeguardFingerprint": fingerprint(f),
        }
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// A stable-ish identifier for de-duplicating the same finding across
/// scans (rule + location + commit, not the secret value itself).
fn fingerprint(f: &Finding) -> String {
    format!(
        "{}:{}:{}:{}",
        f.rule_id,
        f.path.display(),
        f.line,
        f.commit.as_deref().unwrap_or("-")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            severity: Severity::Critical,
            path: PathBuf::from("secrets.env"),
            line: 3,
            column: 5,
            matched: "AKIA****************".to_string(),
            context: "AWS_KEY=AKIA****************".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }
    }

    #[test]
    fn test_to_sarif_has_valid_shape() {
        let sarif = to_sarif(&[sample_finding()]);
        assert_eq!(sarif["version"], "2.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "aws-access-key-id");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "secrets.env"
        );

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "aws-access-key-id");
    }

    #[test]
    fn test_to_sarif_dedupes_rules() {
        let sarif = to_sarif(&[sample_finding(), sample_finding()]);
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_severity_to_sarif_level_mapping() {
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Low), "note");
    }
}
