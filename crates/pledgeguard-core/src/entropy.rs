//! Shannon-entropy based detector for generic high-entropy strings
//! (catches secrets that don't match a known provider format).

use crate::detector::{Detector, DetectorMatch};
use crate::finding::Severity;
use regex::Regex;

/// Detects generic high-entropy tokens assigned to a variable, e.g.
/// `api_key = "aG9uZXN0bHkgdGhpcyBpcyBhIHNlY3JldA=="`.
pub struct EntropyDetector {
    assignment: Regex,
    min_length: usize,
    min_entropy: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self {
            // key/token/secret/password = "<value>" or similar, quoted or bare.
            assignment: Regex::new(
                r#"(?i)(key|token|secret|passwd|password|api[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9+/_\-\.=]{16,})['"]?"#,
            )
            .expect("static regex is valid"),
            min_length: 20,
            min_entropy: 3.5,
        }
    }
}

impl EntropyDetector {
    /// Shannon entropy in bits per character.
    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let len = s.len() as f64;
        let mut counts = std::collections::HashMap::new();
        for c in s.chars() {
            *counts.entry(c).or_insert(0usize) += 1;
        }
        counts
            .values()
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

impl Detector for EntropyDetector {
    fn id(&self) -> &str {
        "generic-high-entropy"
    }

    fn description(&self) -> &str {
        "Generic high-entropy string assigned to a key/token/secret-like variable"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn scan_line(&self, line: &str) -> Vec<DetectorMatch> {
        let mut out = Vec::new();
        for caps in self.assignment.captures_iter(line) {
            if let Some(value) = caps.get(2) {
                let text = value.as_str();
                if text.len() >= self.min_length && Self::shannon_entropy(text) >= self.min_entropy
                {
                    out.push(DetectorMatch {
                        start: value.start(),
                        end: value.end(),
                        text: text.to_string(),
                    });
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_detects_high_entropy_secret() {
        let d = EntropyDetector::default();
        let line = r#"api_key = "aG9uZXN0bHkgdGhpcyBpcyBhIHNlY3JldA==""#;
        let matches = d.scan_line(line);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_entropy_ignores_low_entropy() {
        let d = EntropyDetector::default();
        let line = r#"password = "aaaaaaaaaaaaaaaaaaaaaaaa""#;
        let matches = d.scan_line(line);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_entropy_ignores_short_values() {
        let d = EntropyDetector::default();
        let line = r#"key = "short""#;
        let matches = d.scan_line(line);
        assert!(matches.is_empty());
    }
}
