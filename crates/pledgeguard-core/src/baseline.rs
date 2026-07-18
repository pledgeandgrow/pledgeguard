//! Baseline / allowlist mode for suppressing known findings across scans.
//!
//! A baseline is a JSON file containing a list of "fingerprints" — stable
//! identifiers derived from a finding's rule id, file path, and matched text.
//! When `--baseline <path>` is passed, findings whose fingerprint appears in
//! the baseline are removed before reporting, so previously reviewed items
//! don't trigger CI failures or clutter output.
//!
//! Typical workflow:
//! 1. `pledgeguard scan --save-baseline .pledgeguard-baseline.json`
//! 2. Manually edit the baseline file to remove entries for real secrets.
//! 3. Commit the baseline (or add it to `.gitignore` if it contains raw
//!    secret values — the `matched` field stores the unredacted match text).
//! 4. `pledgeguard scan --baseline .pledgeguard-baseline.json` in CI.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Stable fingerprint for a finding, used for baseline matching.
/// Matches on `rule_id + path + matched` (line number is intentionally
/// excluded so the suppression survives reformatting / line shifts).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub path: String,
    pub matched: String,
}

impl From<&Finding> for BaselineEntry {
    fn from(f: &Finding) -> Self {
        Self {
            rule_id: f.rule_id.clone(),
            path: f.path.to_string_lossy().to_string(),
            matched: f.matched.clone(),
        }
    }
}

/// A baseline file containing suppressed findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// List of suppressed finding fingerprints.
    pub entries: Vec<BaselineEntry>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

/// Load a baseline from a JSON file.
pub fn load(path: &Path) -> Result<Baseline, std::io::Error> {
    let contents = std::fs::read_to_string(path)?;
    if contents.trim().is_empty() {
        return Ok(Baseline::default());
    }
    serde_json::from_str(&contents)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Save a baseline to a JSON file.
pub fn save(path: &Path, baseline: &Baseline) -> Result<(), std::io::Error> {
    let json = serde_json::to_string_pretty(baseline)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Build a baseline from a list of findings (all findings become entries).
pub fn from_findings(findings: &[Finding]) -> Baseline {
    Baseline {
        version: 1,
        entries: findings.iter().map(BaselineEntry::from).collect(),
    }
}

/// Removes findings whose fingerprint appears in the baseline.
/// Returns `(remaining, suppressed_count)`.
pub fn filter(findings: Vec<Finding>, baseline: &Baseline) -> (Vec<Finding>, usize) {
    let set: HashSet<&BaselineEntry> = baseline.entries.iter().collect();
    let mut suppressed = 0;
    let remaining: Vec<Finding> = findings
        .into_iter()
        .filter(|f| {
            let entry = BaselineEntry::from(f);
            if set.contains(&entry) {
                suppressed += 1;
                false
            } else {
                true
            }
        })
        .collect();
    (remaining, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::path::PathBuf;

    fn mock_finding(rule: &str, path: &str, matched: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            description: "test".to_string(),
            severity: Severity::High,
            path: PathBuf::from(path),
            line,
            column: 1,
            matched: matched.to_string(),
            context: "ctx".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }
    }

    #[test]
    fn test_filter_removes_baseline_entries() {
        let findings = vec![
            mock_finding("aws-access-key-id", "src/a.rs", "AKIAIOSFODNN7EXAMPLE", 10),
            mock_finding("github-pat", "src/b.rs", "ghp_1234567890abcdef1234567890abcdef1234", 5),
        ];
        let baseline = Baseline {
            version: 1,
            entries: vec![BaselineEntry::from(&findings[0])],
        };
        let (remaining, suppressed) = filter(findings, &baseline);
        assert_eq!(remaining.len(), 1);
        assert_eq!(suppressed, 1);
        assert_eq!(remaining[0].rule_id, "github-pat");
    }

    #[test]
    fn test_filter_line_number_agnostic() {
        // Same rule + path + matched but different line should still be suppressed.
        let findings = vec![mock_finding("aws-access-key-id", "src/a.rs", "AKIAIOSFODNN7EXAMPLE", 99)];
        let baseline = Baseline {
            version: 1,
            entries: vec![BaselineEntry {
                rule_id: "aws-access-key-id".to_string(),
                path: "src/a.rs".to_string(),
                matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            }],
        };
        let (remaining, suppressed) = filter(findings, &baseline);
        assert!(remaining.is_empty());
        assert_eq!(suppressed, 1);
    }

    #[test]
    fn test_filter_no_match_returns_all() {
        let findings = vec![mock_finding("aws-access-key-id", "src/a.rs", "AKIAIOSFODNN7EXAMPLE", 1)];
        let baseline = Baseline::default();
        let (remaining, suppressed) = filter(findings, &baseline);
        assert_eq!(remaining.len(), 1);
        assert_eq!(suppressed, 0);
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let baseline = from_findings(&[mock_finding("aws", "a.rs", "AKIA123", 1)]);
        save(&path, &baseline).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].rule_id, "aws");
    }

    #[test]
    fn test_load_empty_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        let loaded = load(&path).unwrap();
        assert!(loaded.entries.is_empty());
    }
}
