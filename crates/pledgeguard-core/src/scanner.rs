//! Walks a filesystem path (respecting `.gitignore`) and applies all
//! configured detectors to every text file found, in parallel.

use crate::detector::Detector;
use crate::finding::Finding;
use rayon::prelude::*;
use std::path::{Path, PathBuf};

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
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: 5 * 1024 * 1024, // 5 MB
            respect_gitignore: true,
        }
    }
}

/// Scans files under `root` using the given `detectors` and returns all findings.
pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
    options: ScanOptions,
}

impl Scanner {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self {
            detectors,
            options: ScanOptions::default(),
        }
    }

    pub fn with_options(detectors: Vec<Box<dyn Detector>>, options: ScanOptions) -> Self {
        Self { detectors, options }
    }

    /// Scan a single file's contents and return findings.
    pub fn scan_str(&self, path: &Path, contents: &str) -> Vec<Finding> {
        let mut findings: Vec<Finding> = contents
            .lines()
            .enumerate()
            .flat_map(|(idx, line)| {
                self.detectors.iter().flat_map(move |detector| {
                    detector.scan_line(line).into_iter().map(move |m| Finding {
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
                    })
                })
            })
            .collect();
        crate::context::annotate(&mut findings);
        if crate::ast::is_js_ts(path) {
            crate::ast::refine_annotation(&mut findings, contents);
        }
        findings
    }

    /// Recursively scan a directory (or a single file) and return all findings,
    /// collected in parallel across files.
    pub fn scan_path(&self, root: impl AsRef<Path>) -> Result<Vec<Finding>, ScanError> {
        let root = root.as_ref();
        let files = self.collect_files(root)?;

        let findings: Vec<Finding> = files
            .par_iter()
            .filter_map(|path| {
                let meta = std::fs::metadata(path).ok()?;
                if meta.len() > self.options.max_file_size {
                    return None;
                }
                let contents = std::fs::read_to_string(path).ok()?;
                Some(self.scan_str(path, &contents))
            })
            .flatten()
            .collect();

        Ok(findings)
    }

    fn collect_files(&self, root: &Path) -> Result<Vec<PathBuf>, ScanError> {
        if root.is_file() {
            return Ok(vec![root.to_path_buf()]);
        }

        let mut builder = ignore::WalkBuilder::new(root);
        builder.git_ignore(self.options.respect_gitignore);
        builder.hidden(false);

        let mut files = Vec::new();
        for entry in builder.build() {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                files.push(entry.into_path());
            }
        }
        Ok(files)
    }
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
            },
        );
        let findings = scanner.scan_path(dir.path()).unwrap();
        assert!(findings.is_empty());
    }
}
