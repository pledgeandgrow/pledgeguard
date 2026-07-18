//! Types describing a detected secret ("finding").

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity of a finding, used for CI gating and sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Result of a live check against the credential's own provider API,
/// confirming whether a matched secret is still active. `None` on a
/// `Finding` means verification was never attempted (the default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// The provider API confirmed the credential is currently valid.
    Active,
    /// The provider API confirmed the credential is invalid/revoked.
    Inactive,
    /// The provider responded, but not with a clear active/inactive signal.
    Unknown,
    /// The verification check could not be completed (network error, etc).
    Error(String),
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationStatus::Active => write!(f, "active"),
            VerificationStatus::Inactive => write!(f, "inactive"),
            VerificationStatus::Unknown => write!(f, "unknown"),
            VerificationStatus::Error(e) => write!(f, "error: {e}"),
        }
    }
}

/// A single detected secret in a scanned file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier of the detector that produced this finding (e.g. "aws-access-key-id").
    pub rule_id: String,
    /// Human-readable description of the rule.
    pub description: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// Path to the file where the secret was found.
    pub path: PathBuf,
    /// 1-indexed line number.
    pub line: usize,
    /// 1-indexed column (byte offset within the line) where the match starts.
    pub column: usize,
    /// The raw matched text (may be redacted before display).
    pub matched: String,
    /// The full line of context the match was found on (may be redacted before display).
    pub context: String,
    /// The commit SHA this finding was found in, when produced by a git
    /// history scan. `None` for working-tree scans.
    pub commit: Option<String>,
    /// Best-effort heuristic flag: `true` if the match appears to be inside
    /// a same-line comment or under a test/fixture/example path. This is a
    /// lexical heuristic (see `context` module), not a real parser, so it
    /// may have false negatives/positives; findings are not dropped, only
    /// flagged so callers can choose to hide them.
    pub likely_false_positive: bool,
    /// Result of an optional live provider check (see `verify` module).
    /// `None` unless verification was explicitly requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationStatus>,
}

impl Finding {
    /// Returns a copy of this finding with the secret value redacted for safe display,
    /// keeping the first and last few characters visible.
    pub fn redacted(&self) -> Finding {
        let mut f = self.clone();
        f.matched = crate::redact::redact(&f.matched);
        f.context = crate::redact::redact_in(&f.context, &self.matched);
        f
    }
}
