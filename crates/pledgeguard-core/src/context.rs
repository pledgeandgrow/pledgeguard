//! Lightweight, language-agnostic false-positive heuristics.
//!
//! This is deliberately *not* a real parser/AST. It answers two cheap
//! questions to help reduce false positives without the cost/scope of
//! integrating a full syntax parser per language:
//!
//! 1. Does the match sit after a same-line comment marker for the file's
//!    extension (e.g. `//`, `#`, `--`, `<!--`)? This catches fully-commented
//!    lines and trailing comments, but does **not** track multi-line block
//!    comments or string-literal state, so a comment marker appearing
//!    inside a string earlier on the line (e.g. a URL like `http://...`)
//!    will cause everything after it to be treated as a comment too. This
//!    is a known, accepted limitation of the heuristic.
//! 2. Is the file under a path that looks like tests/fixtures/examples
//!    (`test`, `tests`, `fixture`, `fixtures`, `example`, `examples`,
//!    `mock`, `mocks`, `spec`, `specs`, `testdata`)?
//!
//! Findings are never dropped based on these checks — they are flagged via
//! [`crate::finding::Finding::likely_false_positive`] so callers (e.g. the
//! CLI) can decide whether to hide them.

use crate::finding::Finding;
use std::path::Path;

/// Returns the single-line comment marker used for false-positive detection
/// for a given (lowercase, no leading dot) file extension, if known.
fn line_comment_marker(extension: &str) -> Option<&'static str> {
    match extension {
        "py" | "sh" | "bash" | "zsh" | "rb" | "yaml" | "yml" | "toml" | "pl" | "r"
        | "dockerfile" | "makefile" | "ini" | "cfg" | "conf" | "env" => Some("#"),
        "rs" | "js" | "jsx" | "ts" | "tsx" | "go" | "java" | "c" | "h" | "cpp" | "hpp" | "cc"
        | "cs" | "swift" | "kt" | "kts" | "scala" | "php" | "dart" | "zig" => Some("//"),
        "sql" | "lua" | "hs" | "elm" | "ada" => Some("--"),
        "html" | "htm" | "xml" | "vue" | "svelte" => Some("<!--"),
        _ => None,
    }
}

/// Best-effort check for whether the byte offset in `line` falls at or after
/// a same-line comment marker for the given extension. See module docs for
/// limitations.
pub fn is_in_line_comment(line: &str, offset: usize, extension: Option<&str>) -> bool {
    let Some(ext) = extension else { return false };
    let Some(marker) = line_comment_marker(&ext.to_lowercase()) else {
        return false;
    };
    match line.find(marker) {
        Some(pos) => offset >= pos,
        None => false,
    }
}

const FIXTURE_MARKERS: &[&str] = &[
    "test", "tests", "fixture", "fixtures", "example", "examples", "mock", "mocks", "spec",
    "specs", "testdata",
];

/// Returns `true` if any path component looks like a test/fixture/example
/// directory or file stem (case-insensitive, exact-component match).
pub fn is_test_fixture_path(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy().to_lowercase();
        FIXTURE_MARKERS.contains(&s.as_str())
    })
}

/// Annotates every finding's `likely_false_positive` flag in place, based on
/// same-line comment position and test/fixture path heuristics.
pub fn annotate(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let ext = f
            .path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase());
        let in_comment = is_in_line_comment(&f.context, f.column.saturating_sub(1), ext.as_deref());
        let in_fixture = is_test_fixture_path(&f.path);
        f.likely_false_positive = in_comment || in_fixture;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_line_comment_detected() {
        assert!(is_in_line_comment(
            "// api_key = AKIAIOSFODNN7EXAMPLE",
            15,
            Some("rs")
        ));
    }

    #[test]
    fn test_no_comment_marker_for_unknown_extension() {
        assert!(!is_in_line_comment("# AKIA...", 5, Some("bin")));
    }

    #[test]
    fn test_code_before_comment_not_flagged() {
        // The match occurs before the comment marker.
        assert!(!is_in_line_comment(
            "AKIAIOSFODNN7EXAMPLE // example",
            0,
            Some("rs")
        ));
    }

    #[test]
    fn test_fixture_path_detected() {
        assert!(is_test_fixture_path(Path::new("crates/foo/tests/data.rs")));
        assert!(is_test_fixture_path(Path::new("examples/demo.env")));
        assert!(!is_test_fixture_path(Path::new("src/main.rs")));
    }
}
