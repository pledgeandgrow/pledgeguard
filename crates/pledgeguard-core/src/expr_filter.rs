//! Expr-based finding filtering.
//!
//! Provides a small expression language for filtering findings with
//! boolean logic. This enables fine-grained FP reduction rules that
//! combine multiple conditions, e.g.:
//!
//! ```text
//! severity == "critical" && !likely_false_positive
//! rule_id != "generic-api-key" || path contains "src/"
//! likely_false_positive && !rule_id matches "aws.*"
//! ```
//!
//! ## Grammar
//!
//! ```text
//! expr      := or_expr
//! or_expr   := and_expr ( "||" and_expr )*
//! and_expr  := not_expr ( "&&" not_expr )*
//! not_expr  := "!" not_expr | comparison
//! comparison := primary ( op primary )?
//! op        := "==" | "!=" | "contains" | "matches"
//! primary   := field | string | bool | "(" expr ")"
//! field     := identifier
//! string    := '"' char* '"'
//! bool      := "true" | "false"
//! ```
//!
//! Supported fields: `rule_id`, `severity`, `path`, `line`, `column`,
//! `likely_false_positive`, `verification`, `description`.

use crate::finding::{Finding, Severity, VerificationStatus};

/// Error returned when parsing or evaluating an expression fails.
#[derive(Debug, thiserror::Error)]
pub enum ExprError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("evaluation error: {0}")]
    Eval(String),
}

/// A compiled filter expression that can be applied to findings.
#[derive(Debug, Clone)]
pub struct ExprFilter {
    root: Node,
}

/// AST nodes for the expression language.
#[derive(Debug, Clone)]
enum Node {
    /// Field reference (e.g. `severity`).
    Field(Field),
    /// String literal.
    Str(String),
    /// Boolean literal.
    Bool(bool),
    /// Number literal.
    Num(u64),
    /// Logical NOT.
    Not(Box<Node>),
    /// Logical AND.
    And(Box<Node>, Box<Node>),
    /// Logical OR.
    Or(Box<Node>, Box<Node>),
    /// Equality (==).
    Eq(Box<Node>, Box<Node>),
    /// Inequality (!=).
    Neq(Box<Node>, Box<Node>),
    /// String contains.
    Contains(Box<Node>, Box<Node>),
    /// Regex matches.
    Matches(Box<Node>, Box<Node>),
}

/// Identifiable fields in the expression language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    RuleId,
    Severity,
    Path,
    Line,
    Column,
    LikelyFalsePositive,
    Verification,
    Description,
}

impl ExprFilter {
    /// Parse an expression string into a compiled filter.
    pub fn parse(source: &str) -> Result<Self, ExprError> {
        let mut parser = Parser::new(source);
        let root = parser.parse_expr()?;
        parser.expect_eof()?;
        Ok(Self { root })
    }

    /// Evaluate the filter against a finding. Returns `true` if the
    /// finding passes the filter.
    pub fn matches(&self, finding: &Finding) -> Result<bool, ExprError> {
        eval(&self.root, finding)
    }

    /// Filter a slice of findings, keeping only those that match.
    pub fn filter<'a>(&self, findings: &'a [Finding]) -> Result<Vec<&'a Finding>, ExprError> {
        let mut result = Vec::new();
        for f in findings {
            if self.matches(f)? {
                result.push(f);
            }
        }
        Ok(result)
    }
}

// ── Evaluator ──────────────────────────────────────────────────────────

fn eval(node: &Node, f: &Finding) -> Result<bool, ExprError> {
    match node {
        Node::Bool(b) => Ok(*b),
        Node::Field(field) => eval_field_bool(*field, f),
        Node::Str(_) | Node::Num(_) => Err(ExprError::Eval(
            "expected a boolean expression, got a value".into(),
        )),
        Node::Not(inner) => Ok(!eval(inner, f)?),
        Node::And(a, b) => Ok(eval(a, f)? && eval(b, f)?),
        Node::Or(a, b) => Ok(eval(a, f)? || eval(b, f)?),
        Node::Eq(a, b) => {
            let va = eval_value(a, f)?;
            let vb = eval_value(b, f)?;
            Ok(va == vb)
        }
        Node::Neq(a, b) => {
            let va = eval_value(a, f)?;
            let vb = eval_value(b, f)?;
            Ok(va != vb)
        }
        Node::Contains(a, b) => {
            let va = eval_value(a, f)?;
            let vb = eval_value(b, f)?;
            match (&va, &vb) {
                (Value::Str(s), Value::Str(sub)) => Ok(s.contains(sub.as_str())),
                _ => Err(ExprError::Eval(
                    "`contains` requires string operands".into(),
                )),
            }
        }
        Node::Matches(a, b) => {
            let va = eval_value(a, f)?;
            let vb = eval_value(b, f)?;
            match (&va, &vb) {
                (Value::Str(s), Value::Str(pat)) => {
                    let re = regex::Regex::new(pat)
                        .map_err(|e| ExprError::Eval(format!("invalid regex: {e}")))?;
                    Ok(re.is_match(s))
                }
                _ => Err(ExprError::Eval("`matches` requires string operands".into())),
            }
        }
    }
}

/// Intermediate value type for equality comparisons.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(String),
    Bool(bool),
    Num(u64),
}

fn eval_value(node: &Node, f: &Finding) -> Result<Value, ExprError> {
    match node {
        Node::Str(s) => Ok(Value::Str(s.clone())),
        Node::Bool(b) => Ok(Value::Bool(*b)),
        Node::Num(n) => Ok(Value::Num(*n)),
        Node::Field(field) => eval_field_value(*field, f),
        _ => Err(ExprError::Eval(
            "expected a value, got an expression".into(),
        )),
    }
}

fn eval_field_bool(field: Field, f: &Finding) -> Result<bool, ExprError> {
    match field {
        Field::LikelyFalsePositive => Ok(f.likely_false_positive),
        _ => {
            // Non-boolean fields used as boolean: truthy if non-empty / non-zero.
            let v = eval_field_value(field, f)?;
            Ok(match v {
                Value::Bool(b) => b,
                Value::Str(s) => !s.is_empty(),
                Value::Num(n) => n != 0,
            })
        }
    }
}

fn eval_field_value(field: Field, f: &Finding) -> Result<Value, ExprError> {
    Ok(match field {
        Field::RuleId => Value::Str(f.rule_id.clone()),
        Field::Severity => Value::Str(severity_str(f.severity).to_string()),
        Field::Path => Value::Str(f.path.display().to_string()),
        Field::Line => Value::Num(f.line as u64),
        Field::Column => Value::Num(f.column as u64),
        Field::LikelyFalsePositive => Value::Bool(f.likely_false_positive),
        Field::Verification => Value::Str(
            f.verification
                .as_ref()
                .map(verification_str)
                .unwrap_or("none")
                .to_string(),
        ),
        Field::Description => Value::Str(f.description.clone()),
    })
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn verification_str(s: &VerificationStatus) -> &'static str {
    match s {
        VerificationStatus::Active => "active",
        VerificationStatus::Inactive => "inactive",
        VerificationStatus::Unknown => "unknown",
        VerificationStatus::Error(_) => "error",
    }
}

fn field_from_str(s: &str) -> Option<Field> {
    match s {
        "rule_id" => Some(Field::RuleId),
        "severity" => Some(Field::Severity),
        "path" => Some(Field::Path),
        "line" => Some(Field::Line),
        "column" => Some(Field::Column),
        "likely_false_positive" => Some(Field::LikelyFalsePositive),
        "verification" => Some(Field::Verification),
        "description" => Some(Field::Description),
        _ => None,
    }
}

// ── Parser ─────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    Num(u64),
    Bool(bool),
    Eq,
    Neq,
    And,
    Or,
    Not,
    Contains,
    Matches,
    LParen,
    RParen,
    Eof,
}

impl Parser {
    fn new(source: &str) -> Self {
        let tokens = tokenize(source);
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn next(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn expect_eof(&self) -> Result<(), ExprError> {
        if self.peek() != &Token::Eof {
            return Err(ExprError::Parse(format!(
                "unexpected token after expression: {:?}",
                self.peek()
            )));
        }
        Ok(())
    }

    fn parse_expr(&mut self) -> Result<Node, ExprError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Node, ExprError> {
        let mut left = self.parse_and()?;
        while self.peek() == &Token::Or {
            self.next();
            let right = self.parse_and()?;
            left = Node::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Node, ExprError> {
        let mut left = self.parse_not()?;
        while self.peek() == &Token::And {
            self.next();
            let right = self.parse_not()?;
            left = Node::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Node, ExprError> {
        if self.peek() == &Token::Not {
            self.next();
            let inner = self.parse_not()?;
            return Ok(Node::Not(Box::new(inner)));
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<Node, ExprError> {
        let left = self.parse_primary()?;
        match self.peek() {
            Token::Eq => {
                self.next();
                let right = self.parse_primary()?;
                Ok(Node::Eq(Box::new(left), Box::new(right)))
            }
            Token::Neq => {
                self.next();
                let right = self.parse_primary()?;
                Ok(Node::Neq(Box::new(left), Box::new(right)))
            }
            Token::Contains => {
                self.next();
                let right = self.parse_primary()?;
                Ok(Node::Contains(Box::new(left), Box::new(right)))
            }
            Token::Matches => {
                self.next();
                let right = self.parse_primary()?;
                Ok(Node::Matches(Box::new(left), Box::new(right)))
            }
            _ => Ok(left),
        }
    }

    fn parse_primary(&mut self) -> Result<Node, ExprError> {
        match self.next() {
            Token::Ident(s) => {
                let field = field_from_str(&s)
                    .ok_or_else(|| ExprError::Parse(format!("unknown field: {s}")))?;
                Ok(Node::Field(field))
            }
            Token::Str(s) => Ok(Node::Str(s)),
            Token::Bool(b) => Ok(Node::Bool(b)),
            Token::Num(n) => Ok(Node::Num(n)),
            Token::LParen => {
                let inner = self.parse_expr()?;
                match self.next() {
                    Token::RParen => Ok(inner),
                    t => Err(ExprError::Parse(format!("expected `)`, got {t:?}"))),
                }
            }
            t => Err(ExprError::Parse(format!("unexpected token: {t:?}"))),
        }
    }
}

fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == '"' {
                        chars.next();
                        break;
                    }
                    if ch == '\\' {
                        chars.next();
                        if let Some(&next) = chars.peek() {
                            s.push(next);
                            chars.next();
                        }
                    } else {
                        s.push(ch);
                        chars.next();
                    }
                }
                tokens.push(Token::Str(s));
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Eq);
                }
            }
            '!' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Neq);
                } else {
                    tokens.push(Token::Not);
                }
            }
            '&' => {
                chars.next();
                if chars.peek() == Some(&'&') {
                    chars.next();
                    tokens.push(Token::And);
                }
            }
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    tokens.push(Token::Or);
                }
            }
            _ if c.is_alphabetic() || c == '_' => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                match s.as_str() {
                    "true" => tokens.push(Token::Bool(true)),
                    "false" => tokens.push(Token::Bool(false)),
                    "contains" => tokens.push(Token::Contains),
                    "matches" => tokens.push(Token::Matches),
                    _ => tokens.push(Token::Ident(s)),
                }
            }
            _ if c.is_ascii_digit() => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_digit() {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Num(s.parse().unwrap_or(0)));
            }
            _ => {
                chars.next();
            }
        }
    }

    tokens.push(Token::Eof);
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mock_finding(rule_id: &str, severity: Severity, path: &str, lfp: bool) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            description: "Test finding".to_string(),
            severity,
            path: PathBuf::from(path),
            line: 42,
            column: 10,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "api_key = AKIAIOSFODNN7EXAMPLE".to_string(),
            commit: None,
            likely_false_positive: lfp,
            verification: None,
        }
    }

    #[test]
    fn test_severity_eq() {
        let f = mock_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/main.rs",
            false,
        );
        let filter = ExprFilter::parse(r#"severity == "critical""#).unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_severity_neq() {
        let f = mock_finding("aws-access-key-id", Severity::High, "src/main.rs", false);
        let filter = ExprFilter::parse(r#"severity != "critical""#).unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_likely_false_positive() {
        let f = mock_finding("generic-api-key", Severity::Low, "tests/data.rs", true);
        let filter = ExprFilter::parse("likely_false_positive").unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_not_likely_false_positive() {
        let f = mock_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/main.rs",
            false,
        );
        let filter = ExprFilter::parse("!likely_false_positive").unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_and() {
        let f = mock_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/main.rs",
            false,
        );
        let filter =
            ExprFilter::parse(r#"severity == "critical" && !likely_false_positive"#).unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_or() {
        let f = mock_finding("generic-api-key", Severity::Low, "src/main.rs", false);
        let filter =
            ExprFilter::parse(r#"severity == "critical" || rule_id == "generic-api-key""#).unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_contains() {
        let f = mock_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/main.rs",
            false,
        );
        let filter = ExprFilter::parse(r#"path contains "src/""#).unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_matches() {
        let f = mock_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/main.rs",
            false,
        );
        let filter = ExprFilter::parse(r#"rule_id matches "aws.*""#).unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_parens() {
        let f = mock_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/main.rs",
            false,
        );
        let filter = ExprFilter::parse(
            r#"(severity == "critical" || severity == "high") && !likely_false_positive"#,
        )
        .unwrap();
        assert!(filter.matches(&f).unwrap());
    }

    #[test]
    fn test_filter_vec() {
        let findings = vec![
            mock_finding(
                "aws-access-key-id",
                Severity::Critical,
                "src/main.rs",
                false,
            ),
            mock_finding("generic-api-key", Severity::Low, "tests/data.rs", true),
            mock_finding("github-pat", Severity::High, "src/config.rs", false),
        ];
        let filter = ExprFilter::parse(r#"!likely_false_positive && severity != "low""#).unwrap();
        let filtered = filter.filter(&findings).unwrap();
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_unknown_field_error() {
        let result = ExprFilter::parse(r#"unknown_field == "test""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_complex_expression() {
        let f = mock_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/main.rs",
            false,
        );
        let filter = ExprFilter::parse(
            r#"(severity == "critical" || severity == "high") && !likely_false_positive && path contains "src/""#,
        )
        .unwrap();
        assert!(filter.matches(&f).unwrap());
    }
}
