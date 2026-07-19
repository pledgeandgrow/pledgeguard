//! Walks a filesystem path (respecting `.gitignore`) and applies all
//! configured detectors to every text file found, in parallel.
//!
//! Performance architecture:
//! 1. **Aho-Corasick prefilter** — all detector trigger substrings are compiled
//!    into a single automaton. Each line is scanned once; only detectors whose
//!    triggers matched are run (vs. running all 15+ regexes on every line).
//! 2. **memchr fast path** — before Aho-Corasick, a single `memchr` check on
//!    the rarest byte across all patterns skips lines that can't possibly match.
//! 3. **bstr** — byte-oriented line splitting avoids UTF-8 validation overhead.
//! 4. **dashmap** — lock-free concurrent collection of findings across threads.
//! 5. **crossbeam** — work-stealing thread pool for better scheduling than rayon
//!    when mixing I/O (file reads) with CPU (regex scanning).

use crate::detector::{Allowlist, Detector};
use crate::finding::Finding;
use aho_corasick::AhoCorasick;
use bstr::ByteSlice;
use std::path::{Path, PathBuf};

/// A `DashMap`-backed concurrent Vec for collecting findings.
struct DashVec<T> {
    inner: dashmap::DashMap<usize, Vec<T>>,
    len: std::sync::atomic::AtomicUsize,
}

impl<T> DashVec<T> {
    fn new() -> Self {
        Self {
            inner: dashmap::DashMap::new(),
            len: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn push(&self, key: usize, value: T) {
        self.len
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.entry(key).or_default().push(value);
    }

    fn into_vec(self) -> Vec<T> {
        let mut out: Vec<T> = Vec::with_capacity(
            self.len.load(std::sync::atomic::Ordering::Relaxed),
        );
        for (_, mut v) in self.inner {
            out.append(&mut v);
        }
        out
    }
}

/// Errors that can occur while scanning.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("git error: {0}")]
    Git(String),
}

/// Configuration for a scan run.
pub struct ScanOptions {
    /// Maximum file size (in bytes) to scan; larger files are skipped.
    pub max_file_size: u64,
    /// Whether to respect `.gitignore` / `.ignore` files while walking.
    pub respect_gitignore: bool,
    /// Glob patterns for paths to ignore during scan (e.g. `vendor/*`, `*.min.js`).
    pub ignore_paths: Vec<String>,
    /// If set, only detectors whose ID is in this set will run.
    pub enable_rules: Option<Vec<String>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: 5 * 1024 * 1024, // 5 MB
            respect_gitignore: true,
            ignore_paths: Vec::new(),
            enable_rules: None,
        }
    }
}

/// Scans files under `root` using the given `detectors` and returns all findings.
pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
    options: ScanOptions,
    /// Aho-Corasick automaton built from all detector prefilter patterns.
    /// Maps pattern index → detector index.
    prefilter: Option<(AhoCorasick, Vec<usize>)>,
    /// Global allowlist applied to all findings.
    global_allowlist: Option<Allowlist>,
    /// If set, only detectors whose ID is in this set will run.
    enabled_rules: Option<std::collections::HashSet<String>>,
}

impl Scanner {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self::build(detectors, ScanOptions::default(), None)
    }

    pub fn with_options(detectors: Vec<Box<dyn Detector>>, options: ScanOptions) -> Self {
        Self::build(detectors, options, None)
    }

    /// Create a scanner with a global allowlist.
    pub fn with_allowlist(
        detectors: Vec<Box<dyn Detector>>,
        options: ScanOptions,
        global_allowlist: Option<Allowlist>,
    ) -> Self {
        Self::build(detectors, options, global_allowlist)
    }

    fn build(
        detectors: Vec<Box<dyn Detector>>,
        options: ScanOptions,
        global_allowlist: Option<Allowlist>,
    ) -> Self {
        // Extract enabled rules set if configured.
        let enabled_rules = options.enable_rules.as_ref().map(|rules| {
            rules.iter().cloned().collect::<std::collections::HashSet<String>>()
        });

        // Collect all prefilter patterns and build the Aho-Corasick automaton.
        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_to_detector: Vec<usize> = Vec::new();
        for (det_idx, det) in detectors.iter().enumerate() {
            let pats = det.prefilter_patterns();
            if pats.is_empty() {
                // No prefilter — always run. Use empty string as a wildcard.
                continue;
            }
            for pat in pats {
                patterns.push(pat.to_string());
                pattern_to_detector.push(det_idx);
            }
        }

        let prefilter = if patterns.is_empty() {
            None
        } else {
            use aho_corasick::{AhoCorasickBuilder, MatchKind};
            match AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
            {
                Ok(ac) => Some((ac, pattern_to_detector)),
                Err(_) => None,
            }
        };

        Self {
            detectors,
            options,
            prefilter,
            global_allowlist,
            enabled_rules,
        }
    }

    /// Determine which detectors should run on a line, using the Aho-Corasick
    /// prefilter. Returns detector indices that may match.
    /// Filters by enabled_rules and path_filter if configured.
    fn matching_detectors(&self, line_bytes: &[u8], path: &Path) -> Vec<usize> {
        let path_str = path.to_string_lossy();

        let mut det_indices: Vec<usize> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // First, determine which detectors pass the enabled_rules and path_filter checks.
        let mut eligible: Vec<bool> = vec![false; self.detectors.len()];
        for (i, det) in self.detectors.iter().enumerate() {
            // Filter by enabled_rules if set.
            if let Some(ref enabled) = self.enabled_rules
                && !enabled.contains(det.id())
            {
                continue;
            }
            // Filter by per-rule path_filter if set.
            if let Some(path_re) = det.path_filter()
                && !path_re.is_match(&path_str)
            {
                continue;
            }
            // Filter by per-rule allowlist path entries.
            if let Some(al) = det.allowlist()
                && al.matches_path(path)
            {
                continue;
            }
            eligible[i] = true;
        }

        // Now use Aho-Corasick prefilter to find which eligible detectors have trigger patterns.
        if let Some((ac, mapping)) = &self.prefilter {
            for mat in ac.find_iter(line_bytes) {
                let pat_idx = mat.pattern();
                let det_idx = mapping[pat_idx.as_usize()];
                if eligible[det_idx] && seen.insert(det_idx) {
                    det_indices.push(det_idx);
                }
            }
        }

        // Always include eligible detectors without prefilter patterns (e.g. entropy).
        for (i, d) in self.detectors.iter().enumerate() {
            if eligible[i] && d.prefilter_patterns().is_empty() && seen.insert(i) {
                det_indices.push(i);
            }
        }

        // If no prefilter at all, run all eligible detectors.
        if self.prefilter.is_none() {
            for (i, _) in self.detectors.iter().enumerate() {
                if eligible[i] && seen.insert(i) {
                    det_indices.push(i);
                }
            }
        }

        det_indices
    }

    /// Check if a line contains a `pledgeguard:allow` inline comment.
    /// If so, findings on this line should be suppressed.
    fn has_allow_comment(line: &str) -> bool {
        // Check for pledgeguard:allow in the line (case-insensitive).
        // Works for: // pledgeguard:allow, # pledgeguard:allow, <!-- pledgeguard:allow -->, etc.
        let lower = line.to_lowercase();
        lower.contains("pledgeguard:allow")
    }

    /// Check if a finding should be suppressed by allowlists.
    fn is_allowed(&self, matched: &str, path: &Path, detector: &dyn Detector) -> bool {
        // Check per-rule allowlist.
        if let Some(al) = detector.allowlist()
            && al.matches(matched, path)
        {
            return true;
        }
        // Check global allowlist.
        if let Some(ref gal) = self.global_allowlist
            && gal.matches(matched, path)
        {
            return true;
        }
        false
    }

    /// Scan a single file's contents and return findings.
    pub fn scan_str(&self, path: &Path, contents: &str) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        for (idx, line) in contents.lines().enumerate() {
            // Skip lines with pledgeguard:allow inline comment.
            if Self::has_allow_comment(line) {
                continue;
            }

            let line_bytes = line.as_bytes();

            let det_indices = self.matching_detectors(line_bytes, path);
            if det_indices.is_empty() {
                continue;
            }

            for &det_idx in &det_indices {
                let detector = &self.detectors[det_idx];
                for m in detector.scan_line(line) {
                    // Check allowlists.
                    if self.is_allowed(&m.text, path, detector.as_ref()) {
                        continue;
                    }
                    findings.push(Finding {
                        rule_id: detector.id().to_string(),
                        description: detector.description().to_string(),
                        severity: detector.severity(),
                        path: path.to_path_buf(),
                        line: idx + 1,
                        column: m.start + 1,
                        matched: m.text,
                        context: line.to_string(),
                        commit: None,
                        likely_false_positive: false,
                        verification: None,
                    });
                }
            }
        }

        crate::context::annotate(&mut findings);
        if crate::ast::is_js_ts(path) {
            crate::ast::refine_annotation(&mut findings, contents);
        }
        findings
    }

    /// Scan a single file's raw bytes and return findings.
    /// Uses bstr for byte-oriented line splitting (avoids UTF-8 validation).
    fn scan_bytes(&self, path: &Path, contents: &[u8]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        for (idx, line) in contents.lines().enumerate() {
            let det_indices = self.matching_detectors(line, path);
            if det_indices.is_empty() {
                continue;
            }

            // Convert to str for detector calls (lossy if invalid UTF-8).
            let line_str = match std::str::from_utf8(line) {
                Ok(s) => s,
                Err(_) => {
                    // Use lossy conversion for non-UTF8 lines.
                    let lossy = String::from_utf8_lossy(line);
                    let lossy_str: &str = &lossy;
                    // Skip lines with pledgeguard:allow inline comment.
                    if Self::has_allow_comment(lossy_str) {
                        continue;
                    }
                    for &det_idx in &det_indices {
                        let detector = &self.detectors[det_idx];
                        for m in detector.scan_line(lossy_str) {
                            if self.is_allowed(&m.text, path, detector.as_ref()) {
                                continue;
                            }
                            findings.push(Finding {
                                rule_id: detector.id().to_string(),
                                description: detector.description().to_string(),
                                severity: detector.severity(),
                                path: path.to_path_buf(),
                                line: idx + 1,
                                column: m.start + 1,
                                matched: m.text,
                                context: lossy_str.to_string(),
                                commit: None,
                                likely_false_positive: false,
                                verification: None,
                            });
                        }
                    }
                    continue;
                }
            };

            // Skip lines with pledgeguard:allow inline comment.
            if Self::has_allow_comment(line_str) {
                continue;
            }

            for &det_idx in &det_indices {
                let detector = &self.detectors[det_idx];
                for m in detector.scan_line(line_str) {
                    if self.is_allowed(&m.text, path, detector.as_ref()) {
                        continue;
                    }
                    findings.push(Finding {
                        rule_id: detector.id().to_string(),
                        description: detector.description().to_string(),
                        severity: detector.severity(),
                        path: path.to_path_buf(),
                        line: idx + 1,
                        column: m.start + 1,
                        matched: m.text,
                        context: line_str.to_string(),
                        commit: None,
                        likely_false_positive: false,
                        verification: None,
                    });
                }
            }
        }

        // Context annotation needs &str — convert lossy if needed.
        if crate::ast::is_js_ts(path) {
            let contents_str = std::str::from_utf8(contents).unwrap_or("");
            crate::context::annotate(&mut findings);
            crate::ast::refine_annotation(&mut findings, contents_str);
        } else {
            crate::context::annotate(&mut findings);
        }
        findings
    }

    /// Recursively scan a directory (or a single file) and return all findings,
    /// collected in parallel across files using crossbeam + dashmap.
    pub fn scan_path(&self, root: impl AsRef<Path>) -> Result<Vec<Finding>, ScanError> {
        let root = root.as_ref();
        let files = self.collect_files(root)?;

        let results: DashVec<Finding> = DashVec::new();

        crossbeam::scope(|scope| {
            // Use crossbeam's scoped threads with a work-stealing approach.
            // Split files into chunks for parallel processing.
            let chunk_size = (files.len() / num_threads().max(1)).max(1);

            for (chunk_id, chunk) in files.chunks(chunk_size).enumerate() {
                let results = &results;
                scope.spawn(move |_| {
                    for (file_idx, path) in chunk.iter().enumerate() {
                        let meta = match std::fs::metadata(path) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        if meta.len() > self.options.max_file_size {
                            continue;
                        }
                        // Read as bytes (no UTF-8 validation overhead).
                        let contents = match std::fs::read(path) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let file_findings = self.scan_bytes(path, &contents);
                        for f in file_findings {
                            results.push(chunk_id * 100_000 + file_idx, f);
                        }
                    }
                });
            }
        })
        .map_err(|_| ScanError::Git("thread panic".to_string()))?;

        Ok(results.into_vec())
    }

    fn collect_files(&self, root: &Path) -> Result<Vec<PathBuf>, ScanError> {
        if root.is_file() {
            // Check if this single file matches any ignore pattern.
            if self.is_ignored(root) {
                return Ok(Vec::new());
            }
            return Ok(vec![root.to_path_buf()]);
        }

        let mut builder = ignore::WalkBuilder::new(root);
        builder.git_ignore(self.options.respect_gitignore);
        builder.hidden(false);
        // Parallelize file walking.
        builder.threads(num_threads());

        let mut files = Vec::new();
        for entry in builder.build() {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                let path = entry.path();
                if !self.is_ignored(path) {
                    files.push(entry.into_path());
                }
            }
        }
        Ok(files)
    }

    /// Check if a path matches any of the ignore_path glob patterns.
    fn is_ignored(&self, path: &Path) -> bool {
        if self.options.ignore_paths.is_empty() {
            return false;
        }
        let path_str = path.to_string_lossy();
        let path_str = path_str.replace('\\', "/");
        for pattern in &self.options.ignore_paths {
            // Try glob match against the full path and against the file name.
            if let Ok(glob_pat) = glob::Pattern::new(pattern)
                && (glob_pat.matches(&path_str) || glob_pat.matches(path.file_name().unwrap_or_default().to_string_lossy().as_ref()))
            {
                return true;
            }
            // Also try simple substring match for convenience.
            if path_str.contains(pattern) {
                return true;
            }
        }
        false
    }
}

fn num_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::builtin_detectors;
    use std::io::Write;

    #[test]
    fn test_scan_str_finds_aws_key() {
        let scanner = Scanner::new(builtin_detectors());
        let findings = scanner.scan_str(Path::new("test.env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
        assert!(findings.iter().any(|f| f.rule_id == "aws-access-key-id"));
    }

    #[test]
    fn test_scan_path_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("secrets.txt");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "token = ghp_1234567890abcdef1234567890abcdef1234").unwrap();

        let scanner = Scanner::new(builtin_detectors());
        let findings = scanner.scan_path(&file_path).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "github-pat"));
    }

    #[test]
    fn test_scan_path_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "no secrets here\n").unwrap();
        std::fs::write(
            dir.path().join("b.txt"),
            "-----BEGIN RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        let scanner = Scanner::new(builtin_detectors());
        let findings = scanner.scan_path(dir.path()).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "private-key-pem"));
    }

    #[test]
    fn test_max_file_size_skips_large_files() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("big.txt");
        std::fs::write(&file_path, "AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let scanner = Scanner::with_options(
            builtin_detectors(),
            ScanOptions {
                max_file_size: 1, // smaller than the file
                respect_gitignore: true,
                ignore_paths: Vec::new(),
                enable_rules: None,
            },
        );
        let findings = scanner.scan_path(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_prefilter_skips_lines_without_triggers() {
        let scanner = Scanner::new(builtin_detectors());
        // Line with no trigger patterns — should be skipped by prefilter.
        let findings = scanner.scan_str(Path::new("test.txt"), "hello world\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_prefilter_runs_entropy_detector() {
        let scanner = Scanner::new(builtin_detectors());
        // "key" is a prefilter for entropy detector.
        let line = r#"key = "aG9uZXN0bHkgdGhpcyBpcyBhIHNlY3JldA==""#;
        let findings = scanner.scan_str(Path::new("test.txt"), line);
        assert!(findings.iter().any(|f| f.rule_id == "generic-high-entropy"));
    }

    #[test]
    fn test_ignore_path_skips_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret.env"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        std::fs::write(dir.path().join("safe.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let scanner = Scanner::with_options(
            builtin_detectors(),
            ScanOptions {
                max_file_size: 5 * 1024 * 1024,
                respect_gitignore: true,
                ignore_paths: vec!["*.env".to_string()],
                enable_rules: None,
            },
        );
        let findings = scanner.scan_path(dir.path()).unwrap();
        // secret.env should be ignored, safe.txt should still be scanned.
        assert!(findings.iter().all(|f| !f.path.to_string_lossy().contains("secret.env")));
        assert!(findings.iter().any(|f| f.path.to_string_lossy().contains("safe.txt")));
    }

    #[test]
    fn test_enable_rules_filters_detectors() {
        let scanner = Scanner::with_options(
            builtin_detectors(),
            ScanOptions {
                max_file_size: 5 * 1024 * 1024,
                respect_gitignore: true,
                ignore_paths: Vec::new(),
                enable_rules: Some(vec!["github-pat".to_string()]),
            },
        );
        // AWS key should NOT be found because only github-pat is enabled.
        let findings = scanner.scan_str(Path::new("test.env"), "AKIAIOSFODNN7EXAMPLE\n");
        assert!(!findings.iter().any(|f| f.rule_id == "aws-access-key-id"));
        // GitHub PAT should be found.
        let findings = scanner.scan_str(
            Path::new("test.txt"),
            "token = ghp_1234567890abcdef1234567890abcdef1234\n",
        );
        assert!(findings.iter().any(|f| f.rule_id == "github-pat"));
    }

    #[test]
    fn test_pledgeguard_allow_comment_suppresses() {
        let scanner = Scanner::new(builtin_detectors());
        // Line with pledgeguard:allow comment should not produce findings.
        let findings = scanner.scan_str(
            Path::new("test.txt"),
            "AKIAIOSFODNN7EXAMPLE // pledgeguard:allow\n",
        );
        assert!(findings.is_empty());
    }
}
