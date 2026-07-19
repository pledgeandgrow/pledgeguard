//! AST-like comment detection for Python, Go, Ruby, and Java.
//!
//! Since PledgeGuard only uses `oxc` for JS/TS, this module provides
//! lightweight block-comment span detection for the four most common
//! backend languages. It correctly handles:
//!
//! - **Python**: `#` line comments and `"""`/`'''` docstrings (block comments)
//! - **Go**: `//` line comments and `/* */` block comments
//! - **Ruby**: `#` line comments and `=begin`/`=end` block comments
//! - **Java**: `//` line comments and `/* */` (including `/** */`) block comments
//!
//! Unlike the lexical heuristic in `context.rs`, this module tracks
//! multi-line block comments and string-literal state to avoid
//! false positives from comment markers inside strings.

use crate::context;
use crate::finding::Finding;
use std::path::Path;

/// Returns `true` if the file extension is one of the languages handled
/// by this module.
pub fn is_supported(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase());
    matches!(
        ext.as_deref(),
        Some(
            "py" | "go"
                | "rb"
                | "java"
                | "kt"
                | "kts"
                | "scala"
                | "groovy"
                | "c"
                | "h"
                | "cpp"
                | "hpp"
                | "cc"
                | "cxx"
                | "cs"
                | "php"
                | "phtml"
        )
    )
}

/// Refine `likely_false_positive` flags using accurate comment span detection.
/// Overrides the lexical comment heuristic for supported languages.
///
/// Should be called *after* `context::annotate`.
pub fn refine_annotation(findings: &mut [Finding], source: &str) {
    if findings.is_empty() {
        return;
    }

    let ext = findings[0]
        .path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase());

    let lang = match ext.as_deref() {
        Some("py") => Lang::Python,
        Some("go") => Lang::Go,
        Some("rb") => Lang::Ruby,
        Some("java" | "kt" | "kts" | "scala" | "groovy") => Lang::Java,
        Some("c" | "h" | "cpp" | "hpp" | "cc" | "cxx") => Lang::C,
        Some("cs") => Lang::CSharp,
        Some("php" | "phtml") => Lang::Php,
        _ => return,
    };

    let comment_spans = extract_comment_spans(source, lang);

    for f in findings.iter_mut() {
        let offset = byte_offset(source, f.line, f.column);
        let in_comment = comment_spans
            .iter()
            .any(|(start, end)| offset >= *start && offset < *end);
        let in_fixture = context::is_test_fixture_path(&f.path);
        f.likely_false_positive = in_comment || in_fixture;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    Python,
    Go,
    Ruby,
    Java,
    C,
    CSharp,
    Php,
}

/// Extract all comment spans (byte offsets) from source code.
fn extract_comment_spans(source: &str, lang: Lang) -> Vec<(usize, usize)> {
    match lang {
        Lang::Python => extract_python_comments(source),
        Lang::Go => extract_c_style_comments(source, "//", "/*", "*/"),
        Lang::Ruby => extract_ruby_comments(source),
        Lang::Java => extract_c_style_comments(source, "//", "/*", "*/"),
        Lang::C => extract_c_style_comments(source, "//", "/*", "*/"),
        Lang::CSharp => extract_c_style_comments(source, "//", "/*", "*/"),
        Lang::Php => extract_php_comments(source),
    }
}

/// Extract comment spans from Python source.
/// Handles `#` line comments and `"""`/`'''` docstrings.
fn extract_python_comments(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Check for triple-quoted strings (docstrings) — treat as comments.
        if i + 2 < bytes.len() {
            let triple = &bytes[i..i + 3];
            if triple == b"\"\"\"" || triple == b"'''" {
                let quote = triple[0];
                let start = i;
                i += 3;
                // Find closing triple quote.
                while i + 2 < bytes.len() {
                    if bytes[i] == quote && bytes[i + 1] == quote && bytes[i + 2] == quote {
                        i += 3;
                        break;
                    }
                    i += 1;
                }
                spans.push((start, i.min(bytes.len())));
                continue;
            }
        }

        // Check for `#` line comment.
        if bytes[i] == b'#' {
            let start = i;
            // Skip to end of line.
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            spans.push((start, i));
            continue;
        }

        // Skip string literals to avoid false comment detection.
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 2; // Skip escaped char.
                } else {
                    i += 1;
                }
            }
            if i < bytes.len() {
                i += 1; // Skip closing quote.
            }
            continue;
        }

        i += 1;
    }

    spans
}

/// Extract comment spans for C-style languages (Go, Java, C, etc.).
/// Handles `//` line comments and `/* */` block comments.
fn extract_c_style_comments(
    source: &str,
    line_marker: &str,
    block_start: &str,
    block_end: &str,
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let bytes = source.as_bytes();
    let line_marker_bytes = line_marker.as_bytes();
    let block_start_bytes = block_start.as_bytes();
    let block_end_bytes = block_end.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Check for block comment start.
        if i + block_start_bytes.len() <= bytes.len()
            && &bytes[i..i + block_start_bytes.len()] == block_start_bytes
        {
            let start = i;
            i += block_start_bytes.len();
            // Find block end.
            while i + block_end_bytes.len() <= bytes.len() {
                if &bytes[i..i + block_end_bytes.len()] == block_end_bytes {
                    i += block_end_bytes.len();
                    break;
                }
                i += 1;
            }
            spans.push((start, i.min(bytes.len())));
            continue;
        }

        // Check for line comment.
        if i + line_marker_bytes.len() <= bytes.len()
            && &bytes[i..i + line_marker_bytes.len()] == line_marker_bytes
        {
            let start = i;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            spans.push((start, i));
            continue;
        }

        // Skip string literals.
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }

        // Skip char literals (Java/Go).
        if bytes[i] == b'\'' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                if bytes[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }

        // Skip raw strings (Go: backtick).
        if bytes[i] == b'`' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'`' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }

        i += 1;
    }

    spans
}

/// Extract comment spans from Ruby source.
/// Handles `#` line comments and `=begin`/`=end` block comments.
fn extract_ruby_comments(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut offset = 0usize;

    let mut in_block = false;
    let mut block_start = 0usize;

    for (line_idx, line) in lines.iter().enumerate() {
        let line_start = offset;
        let line_end = offset + line.len();

        if in_block {
            // Check for =end.
            if line.trim_start().starts_with("=end") {
                spans.push((block_start, line_end));
                in_block = false;
            }
            // Still in block, continue.
            offset = line_end + 1; // +1 for newline.
            continue;
        }

        // Check for =begin (must be at start of line).
        if line.trim_start().starts_with("=begin") {
            in_block = true;
            block_start = line_start;
            offset = line_end + 1;
            continue;
        }

        // Check for `#` line comment.
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            // Find the position of `#` in the original line.
            let hash_pos = line.find('#').unwrap_or(0);
            spans.push((line_start + hash_pos, line_end));
        }

        offset = line_end + 1;
        let _ = line_idx; // Suppress unused variable warning.
    }

    // If still in_block at EOF, close it.
    if in_block {
        spans.push((block_start, source.len()));
    }

    spans
}

/// Extract comment spans from PHP source.
/// Handles `#`, `//` line comments and `/* */` block comments.
fn extract_php_comments(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Block comment /* */
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < bytes.len() {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            spans.push((start, i.min(bytes.len())));
            continue;
        }

        // Line comment // or #
        if (i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/') || bytes[i] == b'#' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            spans.push((start, i));
            continue;
        }

        // Skip string literals
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }

        i += 1;
    }

    spans
}

/// Convert 1-indexed line and column to a 0-indexed byte offset in `source`.
fn byte_offset(source: &str, line: usize, column: usize) -> usize {
    if line <= 1 {
        return column.saturating_sub(1);
    }

    let mut line_num = 1;
    for (i, ch) in source.char_indices() {
        if ch == '\n' {
            line_num += 1;
            if line_num == line {
                return i + 1 + column.saturating_sub(1);
            }
        }
    }

    source.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::path::PathBuf;

    fn mock_finding(rule: &str, path: &str, line: usize, column: usize) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            description: "test".to_string(),
            severity: Severity::High,
            path: PathBuf::from(path),
            line,
            column,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: String::new(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }
    }

    #[test]
    fn test_is_supported() {
        assert!(is_supported(Path::new("foo.py")));
        assert!(is_supported(Path::new("foo.go")));
        assert!(is_supported(Path::new("foo.rb")));
        assert!(is_supported(Path::new("foo.java")));
        assert!(is_supported(Path::new("foo.kt")));
        assert!(!is_supported(Path::new("foo.rs")));
        assert!(!is_supported(Path::new("foo.js")));
    }

    // ── Python ────────────────────────────────────────────────────────

    #[test]
    fn test_python_line_comment() {
        let source = "# AKIAIOSFODNN7EXAMPLE\nx = 1\n";
        let mut findings = vec![mock_finding("aws", "test.py", 1, 3)];
        findings[0].likely_false_positive = true;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_python_docstring_block() {
        let source = "\"\"\"\nThis is a docstring\nwith AKIAIOSFODNN7EXAMPLE\n\"\"\"\nx = 1\n";
        let mut findings = vec![mock_finding("aws", "test.py", 3, 6)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_python_string_not_comment() {
        let source = "x = \"not a # comment\"\ny = \"AKIAIOSFODNN7EXAMPLE\"\n";
        let mut findings = vec![mock_finding("aws", "test.py", 2, 7)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(!findings[0].likely_false_positive);
    }

    #[test]
    fn test_python_code_not_comment() {
        let source = "key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        let mut findings = vec![mock_finding("aws", "test.py", 1, 8)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(!findings[0].likely_false_positive);
    }

    // ── Go ────────────────────────────────────────────────────────────

    #[test]
    fn test_go_line_comment() {
        let source = "// AKIAIOSFODNN7EXAMPLE\npackage main\n";
        let mut findings = vec![mock_finding("aws", "test.go", 1, 4)];
        findings[0].likely_false_positive = true;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_go_block_comment() {
        let source = "/*\n * AKIAIOSFODNN7EXAMPLE\n */\npackage main\n";
        let mut findings = vec![mock_finding("aws", "test.go", 2, 5)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_go_raw_string_not_comment() {
        let source = "var x = `not a // comment`\nvar y = \"AKIAIOSFODNN7EXAMPLE\"\n";
        let mut findings = vec![mock_finding("aws", "test.go", 2, 9)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(!findings[0].likely_false_positive);
    }

    // ── Ruby ──────────────────────────────────────────────────────────

    #[test]
    fn test_ruby_line_comment() {
        let source = "# AKIAIOSFODNN7EXAMPLE\nx = 1\n";
        let mut findings = vec![mock_finding("aws", "test.rb", 1, 3)];
        findings[0].likely_false_positive = true;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_ruby_block_comment() {
        let source = "=begin\nAKIAIOSFODNN7EXAMPLE\n=end\nx = 1\n";
        let mut findings = vec![mock_finding("aws", "test.rb", 2, 1)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    // ── Java ──────────────────────────────────────────────────────────

    #[test]
    fn test_java_line_comment() {
        let source = "// AKIAIOSFODNN7EXAMPLE\nclass Foo {}\n";
        let mut findings = vec![mock_finding("aws", "test.java", 1, 4)];
        findings[0].likely_false_positive = true;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_java_block_comment() {
        let source = "/*\n * AKIAIOSFODNN7EXAMPLE\n */\nclass Foo {}\n";
        let mut findings = vec![mock_finding("aws", "test.java", 2, 5)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_java_javadoc_comment() {
        let source = "/**\n * @param key AKIAIOSFODNN7EXAMPLE\n */\nclass Foo {}\n";
        let mut findings = vec![mock_finding("aws", "test.java", 2, 15)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_java_string_not_comment() {
        let source = "String x = \"not // a comment\";\nString y = \"AKIAIOSFODNN7EXAMPLE\";\n";
        let mut findings = vec![mock_finding("aws", "test.java", 2, 12)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(!findings[0].likely_false_positive);
    }

    // ── Fixture path ──────────────────────────────────────────────────

    #[test]
    fn test_preserves_fixture_path_flag() {
        let source = "key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        let mut findings = vec![mock_finding("aws", "tests/data.py", 1, 8)];
        findings[0].likely_false_positive = true;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    // ── Byte offset ───────────────────────────────────────────────────

    #[test]
    fn test_byte_offset() {
        let source = "line1\nline2\nline3\n";
        assert_eq!(byte_offset(source, 1, 1), 0);
        assert_eq!(byte_offset(source, 2, 1), 6);
        assert_eq!(byte_offset(source, 3, 3), 14);
    }
}
