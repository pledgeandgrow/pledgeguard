//! Recursive base64/encoding decode scanning.
//!
//! When a detector matches a string that looks like base64-encoded data,
//! this module attempts to decode it and re-scan the decoded content for
//! additional secrets. This catches secrets hidden behind encoding layers.

use crate::detector::Detector;
use crate::finding::Finding;
use smallvec::SmallVec;
use std::path::Path;

/// Attempts to base64-decode a matched string and re-scan it with the given detectors.
/// Returns additional findings found in the decoded content.
pub fn decode_and_scan(
    matched: &str,
    path: &Path,
    line: usize,
    column: usize,
    detectors: &[Box<dyn Detector>],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try standard base64 decode.
    if let Some(decoded) = try_base64_decode(matched) {
        let decoded_str = String::from_utf8_lossy(&decoded);
        let decoded_str: &str = &decoded_str;

        // Only proceed if the decoded content looks like text (not binary).
        if is_printable_text(decoded_str) && decoded_str.len() >= 8 {
            // Scan the decoded content with all detectors.
            for detector in detectors {
                let matches: SmallVec<_> = detector.scan_line(decoded_str);
                for m in matches {
                    findings.push(Finding {
                        rule_id: detector.id().to_string(),
                        description: detector.description().to_string(),
                        severity: detector.severity(),
                        path: path.to_path_buf(),
                        line,
                        column: column + m.start,
                        matched: m.text,
                        context: format!("[base64-decoded] {decoded_str}"),
                        commit: None,
                        likely_false_positive: false,
                        verification: None,
                    });
                }
            }

            // Recursively try to decode again (up to 2 levels deep).
            if findings.is_empty()
                && let Some(decoded2) = try_base64_decode(decoded_str)
            {
                    let decoded2_str = String::from_utf8_lossy(&decoded2);
                    let decoded2_str: &str = &decoded2_str;
                    if is_printable_text(decoded2_str) && decoded2_str.len() >= 8 {
                        for detector in detectors {
                            let matches: SmallVec<_> = detector.scan_line(decoded2_str);
                            for m in matches {
                                findings.push(Finding {
                                    rule_id: detector.id().to_string(),
                                    description: detector.description().to_string(),
                                    severity: detector.severity(),
                                    path: path.to_path_buf(),
                                    line,
                                    column: column + m.start,
                                    matched: m.text,
                                    context: format!("[base64-decoded x2] {decoded2_str}"),
                                    commit: None,
                                    likely_false_positive: false,
                                    verification: None,
                                });
                            }
                        }
                    }
            }
        }
    }

    findings
}

/// Attempt base64 decoding, returning None if the input is not valid base64.
fn try_base64_decode(input: &str) -> Option<Vec<u8>> {
    // Strip whitespace and padding issues.
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    // Must be a reasonable length and contain only base64 characters.
    if cleaned.len() < 8 || !cleaned.len().is_multiple_of(4) {
        return None;
    }

    // Quick check: base64 alphabet only.
    let valid = cleaned
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !valid {
        return None;
    }

    // Reject strings that are just alphanumeric (could be a real key, not encoded).
    // Require at least one non-alphanumeric char or mixed case to look like base64.
    let has_upper = cleaned.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = cleaned.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = cleaned.chars().any(|c| c.is_ascii_digit());
    let has_special = cleaned.chars().any(|c| c == '+' || c == '/' || c == '=');
    if !has_special && !(has_upper && has_lower && has_digit) {
        return None;
    }

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .ok()
}

/// Check if a string looks like printable text (not binary garbage).
fn is_printable_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .count();
    printable as f64 / s.chars().count() as f64 > 0.8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode_valid() {
        let decoded = try_base64_decode("aG9uZXN0bHkgdGhpcyBpcyBhIHNlY3JldA==");
        assert!(decoded.is_some());
        let text = String::from_utf8(decoded.unwrap()).unwrap();
        assert_eq!(text, "honestly this is a secret");
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(try_base64_decode("notbase64").is_none());
        assert!(try_base64_decode("short").is_none());
        // All-same-character strings are rejected (no mixed case/digits/special).
        assert!(try_base64_decode("AAAAAAAA").is_none());
    }

    #[test]
    fn test_is_printable_text() {
        assert!(is_printable_text("hello world"));
        assert!(is_printable_text("key=secret\ntoken=abc"));
        assert!(!is_printable_text("\x00\x01\x02\x03\x04\x05\x06\x07\x08"));
    }
}
