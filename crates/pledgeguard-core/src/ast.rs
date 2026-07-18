//! AST-based false-positive refinement for JavaScript/TypeScript files.
//!
//! Uses the `oxc` parser to correctly identify comment spans (including
//! multi-line block comments) and distinguish them from comment markers
//! appearing inside string literals. This is a more accurate replacement
//! for the lexical comment heuristic in `context.rs` when the file is JS/TS.
//!
//! For non-JS/TS files, the lexical heuristic in `context.rs` is used.
//! For git history scans, only the lexical heuristic is available (since
//! we only have the added line text, not the full file).

use crate::context;
use crate::finding::Finding;
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

/// Returns `true` if the file extension is a JS/TS variant that oxc can parse.
pub fn is_js_ts(path: &std::path::Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase());
    matches!(
        ext.as_deref(),
        Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts")
    )
}

/// Refine `likely_false_positive` flags for JS/TS findings using AST-based
/// comment detection. Overrides the lexical comment heuristic with accurate
/// comment span checking (handles block comments, ignores `//` inside strings).
///
/// Should be called *after* `context::annotate` — it overrides the comment
/// portion of the heuristic while preserving the fixture-path check.
pub fn refine_annotation(findings: &mut [Finding], source: &str) {
    if findings.is_empty() {
        return;
    }

    let source_type = match SourceType::from_path(&findings[0].path) {
        Ok(st) => st,
        Err(_) => return, // Unknown extension — keep lexical heuristic.
    };

    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, source_type).parse();

    if ret.panicked {
        return; // Parser failed — keep lexical heuristic.
    }

    // Collect comment spans (byte offsets in source, including delimiters).
    let comment_spans: Vec<(usize, usize)> = ret
        .program
        .comments
        .iter()
        .map(|c| (c.span.start as usize, c.span.end as usize))
        .collect();

    for f in findings.iter_mut() {
        let offset = byte_offset(source, f.line, f.column);
        let in_comment = comment_spans
            .iter()
            .any(|(start, end)| offset >= *start && offset < *end);
        let in_fixture = context::is_test_fixture_path(&f.path);
        f.likely_false_positive = in_comment || in_fixture;
    }
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

    // Line beyond end of source — return a safe upper bound.
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
    fn test_is_js_ts() {
        assert!(is_js_ts(std::path::Path::new("foo.js")));
        assert!(is_js_ts(std::path::Path::new("foo.tsx")));
        assert!(is_js_ts(std::path::Path::new("foo.mts")));
        assert!(!is_js_ts(std::path::Path::new("foo.rs")));
        assert!(!is_js_ts(std::path::Path::new("foo.py")));
    }

    #[test]
    fn test_refine_flags_comment_findings() {
        let source = "// AKIAIOSFODNN7EXAMPLE\nconst x = 1;\n";
        let mut findings = vec![mock_finding("aws", "test.js", 1, 4)];
        // Simulate context::annotate setting it via lexical heuristic.
        findings[0].likely_false_positive = true;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_refine_unflags_string_with_comment_marker() {
        // The lexical heuristic would flag this because `//` appears before the match.
        // The AST knows the `//` is inside a string, not a comment.
        let source = "const url = \"http://example.com\";\nconst key = \"AKIAIOSFODNN7EXAMPLE\";\n";
        let mut findings = vec![mock_finding("aws", "test.js", 2, 15)];
        // Lexical heuristic would NOT flag this (no comment marker on line 2).
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(!findings[0].likely_false_positive);
    }

    #[test]
    fn test_refine_flags_block_comment() {
        // Multi-line block comment — lexical heuristic can't handle this.
        let source = "/* This is a\n   multi-line comment\n   with AKIAIOSFODNN7EXAMPLE\n*/\n";
        let mut findings = vec![mock_finding("aws", "test.js", 3, 8)];
        findings[0].likely_false_positive = false;
        refine_annotation(&mut findings, source);
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_refine_preserves_fixture_path_flag() {
        let source = "const x = \"AKIAIOSFODNN7EXAMPLE\";\n";
        let mut findings = vec![mock_finding("aws", "tests/data.js", 1, 12)];
        findings[0].likely_false_positive = true; // Set by context::annotate
        refine_annotation(&mut findings, source);
        // Not in a comment, but in a test fixture path — should stay flagged.
        assert!(findings[0].likely_false_positive);
    }

    #[test]
    fn test_byte_offset() {
        let source = "line1\nline2\nline3\n";
        assert_eq!(byte_offset(source, 1, 1), 0);
        assert_eq!(byte_offset(source, 2, 1), 6);
        assert_eq!(byte_offset(source, 3, 3), 14);
    }
}
