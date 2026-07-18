//! The `Detector` trait and supporting types.
//!
//! A `Detector` inspects a single line of text and returns zero or more
//! matches. Built-in detectors are regex-based; the trait is designed so
//! that future detectors (AST-based, WASM-plugin-based) can implement it
//! without changing the scanner.

use crate::finding::Severity;
use smallvec::SmallVec;

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
    fn scan_line(&self, line: &str) -> SmallVec<[DetectorMatch; 1]>;

    /// Distinctive substrings that must be present in a line for this detector
    /// to possibly match. Used by the scanner's Aho-Corasick prefilter to skip
    /// detectors that cannot match. Return an empty slice to always run.
    fn prefilter_patterns(&self) -> &[&str] {
        &[]
    }
}

/// A regex-backed [`Detector`]. Most built-in detectors are implemented this way.
pub struct RegexDetector {
    id: &'static str,
    description: &'static str,
    severity: Severity,
    pattern: regex::Regex,
    prefilter: &'static [&'static str],
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
            prefilter: &[],
        }
    }

    pub fn with_prefilter(
        id: &'static str,
        description: &'static str,
        severity: Severity,
        pattern: &str,
        prefilter: &'static [&'static str],
    ) -> Self {
        let pattern = regex::Regex::new(pattern)
            .unwrap_or_else(|e| panic!("invalid regex for detector {id}: {e}"));
        Self {
            id,
            description,
            severity,
            pattern,
            prefilter,
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

    fn scan_line(&self, line: &str) -> SmallVec<[DetectorMatch; 1]> {
        self.pattern
            .find_iter(line)
            .map(|m| DetectorMatch {
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
            })
            .collect()
    }

    fn prefilter_patterns(&self) -> &[&str] {
        self.prefilter
    }
}
