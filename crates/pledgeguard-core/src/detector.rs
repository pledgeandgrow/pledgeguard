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

/// Allowlist for a rule or globally — findings matching any of these
/// patterns are suppressed as false positives.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    /// Regex patterns; if any matches the finding's matched text, it is suppressed.
    pub regexes: Vec<regex::Regex>,
    /// Regex patterns matched against the file path; if any matches, findings in that file are suppressed.
    pub paths: Vec<regex::Regex>,
    /// Literal substrings; if any is found in the matched text, it is suppressed.
    pub stopwords: Vec<String>,
}

impl Allowlist {
    /// Returns `true` if the finding's matched text or file path matches any allowlist entry.
    pub fn matches(&self, matched: &str, path: &std::path::Path) -> bool {
        for re in &self.regexes {
            if re.is_match(matched) {
                return true;
            }
        }
        let path_str = path.to_string_lossy();
        for re in &self.paths {
            if re.is_match(&path_str) {
                return true;
            }
        }
        for sw in &self.stopwords {
            if matched.contains(sw.as_str()) {
                return true;
            }
        }
        false
    }

    /// Returns `true` if the file path alone matches any path allowlist entry.
    pub fn matches_path(&self, path: &std::path::Path) -> bool {
        let path_str = path.to_string_lossy();
        self.paths.iter().any(|re| re.is_match(&path_str))
    }
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

    /// Optional per-rule Shannon entropy threshold. If set, only matches whose
    /// extracted secret (see `secret_group`) has entropy >= this value are reported.
    fn entropy_threshold(&self) -> Option<f64> {
        None
    }

    /// Optional regex capture group index (1-indexed) to extract the secret value
    /// from the match. If set, the extracted group text is used as the finding's
    /// matched text and for entropy calculation. If `None`, the full match is used.
    fn secret_group(&self) -> Option<usize> {
        None
    }

    /// Optional allowlist — findings matching any entry are suppressed.
    fn allowlist(&self) -> Option<&Allowlist> {
        None
    }

    /// Optional regex to filter by file path. If set, this detector only runs on
    /// files whose path matches this regex.
    fn path_filter(&self) -> Option<&regex::Regex> {
        None
    }
}

/// A regex-backed [`Detector`]. Most built-in detectors are implemented this way.
pub struct RegexDetector {
    id: &'static str,
    description: &'static str,
    severity: Severity,
    pattern: regex::Regex,
    prefilter: &'static [&'static str],
    entropy: Option<f64>,
    secret_group: Option<usize>,
    allowlist: Option<Allowlist>,
    path_filter: Option<regex::Regex>,
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
            entropy: None,
            secret_group: None,
            allowlist: None,
            path_filter: None,
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
            entropy: None,
            secret_group: None,
            allowlist: None,
            path_filter: None,
        }
    }

    /// Constructor for custom rules from config files where strings are owned.
    /// Leaks the strings to obtain 'static references (bounded by the number of rules).
    pub fn with_prefilter_owned(
        id: String,
        description: String,
        severity: Severity,
        pattern: regex::Regex,
        prefilter: Vec<String>,
    ) -> Self {
        let id: &'static str = Box::leak(id.into_boxed_str());
        let description: &'static str = Box::leak(description.into_boxed_str());
        let prefilter: &'static [&'static str] = if prefilter.is_empty() {
            &[]
        } else {
            Box::leak(
                prefilter
                    .into_iter()
                    .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        };
        Self {
            id,
            description,
            severity,
            pattern,
            prefilter,
            entropy: None,
            secret_group: None,
            allowlist: None,
            path_filter: None,
        }
    }

    /// Builder method to set entropy threshold.
    pub fn with_entropy(mut self, entropy: f64) -> Self {
        self.entropy = Some(entropy);
        self
    }

    /// Builder method to set secret group (capture group index, 1-indexed).
    pub fn with_secret_group(mut self, group: usize) -> Self {
        self.secret_group = Some(group);
        self
    }

    /// Builder method to set allowlist.
    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = Some(allowlist);
        self
    }

    /// Builder method to set path filter regex.
    pub fn with_path_filter(mut self, path_filter: regex::Regex) -> Self {
        self.path_filter = Some(path_filter);
        self
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
        let mut out: SmallVec<[DetectorMatch; 1]> = SmallVec::new();

        for caps in self.pattern.captures_iter(line) {
            // Extract the secret from the specified capture group, or use the full match.
            let (start, end, text) = if let Some(group) = self.secret_group {
                match caps.get(group) {
                    Some(g) => (g.start(), g.end(), g.as_str().to_string()),
                    None => continue, // Group doesn't exist — skip this match.
                }
            } else {
                let m = caps.get(0).unwrap();
                (m.start(), m.end(), m.as_str().to_string())
            };

            // Check entropy threshold if set.
            if let Some(threshold) = self.entropy {
                let entropy = shannon_entropy(&text);
                if entropy < threshold {
                    continue;
                }
            }

            out.push(DetectorMatch { start, end, text });
        }

        out
    }

    fn prefilter_patterns(&self) -> &[&str] {
        self.prefilter
    }

    fn entropy_threshold(&self) -> Option<f64> {
        self.entropy
    }

    fn secret_group(&self) -> Option<usize> {
        self.secret_group
    }

    fn allowlist(&self) -> Option<&Allowlist> {
        self.allowlist.as_ref()
    }

    fn path_filter(&self) -> Option<&regex::Regex> {
        self.path_filter.as_ref()
    }
}

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
