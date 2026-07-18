//! Git commit history scanning.
//!
//! Shells out to the system `git` binary (rather than embedding `libgit2`)
//! to keep the dependency graph light and avoid native build requirements.
//! This means a `git` executable must be on `PATH` and `repo_root` must be
//! inside a git working tree; both are reasonable assumptions for a tool
//! that is scanning a git-managed codebase.
//!
//! Only lines *added* by each commit are scanned (as recorded in the
//! commit's unified diff against its first parent). This mirrors what
//! Gitleaks/TruffleHog report: the commit that introduced a secret, not
//! every commit that happens to still contain it in a merge ancestry.

use crate::context;
use crate::detector::Detector;
use crate::finding::Finding;
use crate::scanner::ScanError;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn hunk_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@").expect("valid regex"))
}

/// Scans every commit reachable from any ref (`git log --all`) for secrets,
/// looking only at added lines in each commit's diff.
pub fn scan_git_history(
    repo_root: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, ScanError> {
    let output = Command::new("git")
        .args([
            "log",
            "--all",
            "-p",
            "--no-color",
            "--unified=0",
            "--pretty=format:commit %H",
        ])
        .current_dir(repo_root)
        .output()
        .map_err(ScanError::Io)?;

    if !output.status.success() {
        return Err(ScanError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    let mut current_commit: Option<String> = None;
    let mut current_path: Option<PathBuf> = None;
    let mut new_line_no: usize = 0;

    for line in text.lines() {
        if let Some(sha) = line.strip_prefix("commit ") {
            current_commit = Some(sha.trim().to_string());
            current_path = None;
            continue;
        }

        if line.starts_with("+++ /dev/null") {
            current_path = None;
            continue;
        }
        if let Some(path) = line.strip_prefix("+++ b/") {
            current_path = Some(PathBuf::from(path));
            continue;
        }
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }

        if let Some(caps) = hunk_header_re().captures(line) {
            new_line_no = caps[1].parse().unwrap_or(1);
            continue;
        }

        if let Some(added) = line.strip_prefix('+') {
            let Some(path) = current_path.clone() else {
                continue;
            };
            let commit = current_commit.clone();
            for detector in detectors {
                for m in detector.scan_line(added) {
                    findings.push(Finding {
                        rule_id: detector.id().to_string(),
                        description: detector.description().to_string(),
                        severity: detector.severity(),
                        path: path.clone(),
                        line: new_line_no,
                        column: m.start + 1,
                        matched: m.text,
                        context: added.to_string(),
                        commit: commit.clone(),
                        likely_false_positive: false,
                        verification: None,
                    });
                }
            }
            new_line_no += 1;
            continue;
        }

        // Removed ('-') and context lines don't advance the new-file line
        // counter under --unified=0 (there are no context lines emitted).
    }

    context::annotate(&mut findings);
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::builtin_detectors;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("git must be on PATH to run this test");
        assert!(status.success(), "git {:?} failed", args);
    }

    fn init_repo(dir: &Path) {
        git(dir, &["init", "-q"]);
        git(dir, &["config", "user.email", "test@example.com"]);
        git(dir, &["config", "user.name", "Test"]);
    }

    #[test]
    fn test_scan_git_history_finds_secret_in_past_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        init_repo(path);

        std::fs::write(path.join("secret.env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-q", "-m", "add secret"]);

        std::fs::write(path.join("secret.env"), "AWS_KEY=removed\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-q", "-m", "remove secret"]);

        let findings = scan_git_history(path, &builtin_detectors()).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "aws-access-key-id"));
        assert!(findings.iter().all(|f| f.commit.is_some()));
    }

    #[test]
    fn test_scan_git_history_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        init_repo(path);

        std::fs::write(path.join("a.txt"), "nothing interesting here\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-q", "-m", "init"]);

        let findings = scan_git_history(path, &builtin_detectors()).unwrap();
        assert!(findings.is_empty());
    }
}
