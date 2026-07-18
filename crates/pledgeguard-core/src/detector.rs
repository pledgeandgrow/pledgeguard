//! The `Detector` trait and supporting types.
//!
//! A `Detector` inspects a single line of text and returns zero or more
//! matches. Built-in detectors are regex-based; the trait is designed so
//! that future detectors (AST-based, WASM-plugin-based) can implement it
//! without changing the scanner.

use crate::finding::Severity;

/// A single match produced by a [`Detector`] within one line of text.
#[derive(Debug, Clone)]
pub struct DetectorMatch {
    /// 0-indexed byte offset within the line where the match starts.
    pub start: usize,
    /// 0-indexed byte offset within the line where the match ends (exclusive).
    pub end: usize,
    /// The matched text.
    pub text: String,
}

/// Implement this trait to add a new secret detector.
pub trait Detector: Send + Sync {
    /// A stable, unique identifier for this rule (e.g. `"aws-access-key-id"`).
    fn id(&self) -> &str;

    /// Human-readable description shown in findings.
    fn description(&self) -> &str;

    /// Severity assigned to findings from this detector.
    fn severity(&self) -> Severity;

    /// Scan a single line of text and return all matches found.
    fn scan_line(&self, line: &str) -> Vec<DetectorMatch>;
}

/// A regex-backed [`Detector`]. Most built-in detectors are implemented this way.
pub struct RegexDetector {
    id: &'static str,
    description: &'static str,
    severity: Severity,
    pattern: regex::Regex,
}

impl RegexDetector {
    pub fn new(
        id: &'static str,
        description: &'static str,
        severity: Severity,
        pattern: &str,
    ) -> Self {
        let pattern = regex::Regex::new(pattern)
            .unwrap_or_else(|e| panic!("invalid regex for detector {id}: {e}"));
        Self {
            id,
            description,
            severity,
            pattern,
        }
    }
}

impl Detector for RegexDetector {
    fn id(&self) -> &str {
        self.id
    }

    fn description(&self) -> &str {
        self.description
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn scan_line(&self, line: &str) -> Vec<DetectorMatch> {
        self.pattern
            .find_iter(line)
            .map(|m| DetectorMatch {
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
            })
            .collect()
    }
}
