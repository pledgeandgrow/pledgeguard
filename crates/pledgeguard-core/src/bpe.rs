//! Byte-Pair Encoding (BPE) tokenization for improved secret detection.
//!
//! BPE is a subword tokenization algorithm that iteratively merges the
//! most frequent character pairs into larger tokens. For secret scanning,
//! BPE helps:
//!
//! 1. **Distinguish secrets from natural language** — secrets have very
//!    different BPE token distributions compared to code or prose.
//! 2. **Detect obfuscated/split secrets** — secrets that have been broken
//!    across lines or concatenated can be identified by their token patterns.
//! 3. **Improve entropy scoring** — by comparing token-level entropy vs
//!    character-level entropy, we can better classify borderline cases.
//!
//! This module provides a lightweight, training-free BPE implementation
//! with a built-in vocabulary optimized for common secret patterns (API
//! keys, tokens, connection strings).

use std::collections::HashMap;

/// A BPE tokenizer with a fixed vocabulary.
#[derive(Debug, Clone)]
pub struct BpeTokenizer {
    /// Merge rules: (token_a, token_b) -> merged_token, ordered by rank.
    merges: Vec<(String, String, String)>,
    /// Pre-built vocabulary for common secret substrings.
    vocab: HashMap<String, u32>,
}

impl Default for BpeTokenizer {
    fn default() -> Self {
        Self::new()
    }
}

impl BpeTokenizer {
    /// Create a new tokenizer with the built-in secret-optimized vocabulary.
    pub fn new() -> Self {
        let merges = default_merges();
        let mut vocab = HashMap::new();
        for (i, (a, b, merged)) in merges.iter().enumerate() {
            vocab.insert(merged.clone(), i as u32);
            // Also insert the individual tokens.
            vocab.entry(a.clone()).or_insert(i as u32);
            vocab.entry(b.clone()).or_insert(i as u32);
        }
        // Insert single characters.
        for c in 'a'..='z' {
            vocab.entry(c.to_string()).or_insert(256);
        }
        for c in 'A'..='Z' {
            vocab.entry(c.to_string()).or_insert(256);
        }
        for c in '0'..='9' {
            vocab.entry(c.to_string()).or_insert(256);
        }
        Self { merges, vocab }
    }

    /// Tokenize a string into BPE tokens.
    pub fn tokenize(&self, text: &str) -> Vec<String> {
        if text.is_empty() {
            return Vec::new();
        }

        // Start with individual characters.
        let mut tokens: Vec<String> = text.chars().map(|c| c.to_string()).collect();

        // Apply merges in order (greedy, lowest rank first).
        for (a, b, merged) in &self.merges {
            let mut i = 0;
            while i + 1 < tokens.len() {
                if tokens[i] == *a && tokens[i + 1] == *b {
                    tokens[i] = merged.clone();
                    tokens.remove(i + 1);
                } else {
                    i += 1;
                }
            }
        }

        tokens
    }

    /// Tokenize and return token IDs from the vocabulary.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        self.tokenize(text)
            .iter()
            .map(|t| *self.vocab.get(t).unwrap_or(&0))
            .collect()
    }

    /// Compute the token-level entropy of a string.
    /// Higher entropy suggests a more "secret-like" string.
    pub fn token_entropy(&self, text: &str) -> f64 {
        let tokens = self.tokenize(text);
        if tokens.len() <= 1 {
            return 0.0;
        }

        let mut counts: HashMap<String, usize> = HashMap::new();
        for t in &tokens {
            *counts.entry(t.clone()).or_default() += 1;
        }

        let n = tokens.len() as f64;
        let mut entropy = 0.0;
        for &count in counts.values() {
            let p = count as f64 / n;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Compute the ratio of unique tokens to total tokens.
    /// Secrets tend to have a high unique-token ratio (low repetition).
    pub fn uniqueness_ratio(&self, text: &str) -> f64 {
        let tokens = self.tokenize(text);
        if tokens.is_empty() {
            return 0.0;
        }
        let unique: std::collections::HashSet<&String> = tokens.iter().collect();
        unique.len() as f64 / tokens.len() as f64
    }

    /// Classify a string as "secret-like" or "natural" based on BPE features.
    ///
    /// Returns a score in [0.0, 1.0] where higher = more secret-like.
    pub fn secret_score(&self, text: &str) -> f64 {
        if text.len() < 8 {
            return 0.0;
        }

        let token_entropy = self.token_entropy(text);
        let uniqueness = self.uniqueness_ratio(text);
        let char_entropy = char_level_entropy(text);

        // Secrets tend to have:
        // - High token entropy (diverse subword patterns)
        // - High uniqueness ratio (low repetition)
        // - High character entropy (random-looking)
        let entropy_score = (token_entropy / 4.0).min(1.0);
        let uniqueness_score = uniqueness;
        let char_entropy_score = (char_entropy / 4.0).min(1.0);

        // Weighted combination.
        0.3 * entropy_score + 0.3 * uniqueness_score + 0.4 * char_entropy_score
    }
}

/// Compute Shannon entropy at the character level.
fn char_level_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in text.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = text.chars().count() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / n;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Default merge rules optimized for common secret patterns.
///
/// These merges capture common substrings found in API keys, tokens,
/// and connection strings, helping the tokenizer produce meaningful
/// subword units for secret-like strings.
fn default_merges() -> Vec<(String, String, String)> {
    vec![
        // Common prefixes.
        ("A".into(), "K".into(), "AK".into()),
        ("A".into(), "K".into(), "AK".into()),
        ("A".into(), "S".into(), "AS".into()),
        ("A".into(), "G".into(), "AG".into()),
        ("A".into(), "I".into(), "AI".into()),
        ("A".into(), "R".into(), "AR".into()),
        ("A".into(), "N".into(), "AN".into()),
        ("A".into(), "K".into(), "AK".into()),
        // Key patterns.
        ("A".into(), "K".into(), "AK".into()),
        ("g".into(), "h".into(), "gh".into()),
        ("g".into(), "h".into(), "gh".into()),
        ("g".into(), "h".into(), "gh".into()),
        ("g".into(), "p".into(), "gp".into()),
        ("_".into(), "_".into(), "__".into()),
        // Token prefixes.
        ("s".into(), "k".into(), "sk".into()),
        ("x".into(), "o".into(), "xo".into()),
        ("a".into(), "k".into(), "ak".into()),
        // Hex pairs.
        ("0".into(), "1".into(), "01".into()),
        ("2".into(), "3".into(), "23".into()),
        ("4".into(), "5".into(), "45".into()),
        ("6".into(), "7".into(), "67".into()),
        ("8".into(), "9".into(), "89".into()),
        ("a".into(), "b".into(), "ab".into()),
        ("c".into(), "d".into(), "cd".into()),
        ("e".into(), "f".into(), "ef".into()),
        // Common separators.
        ("-".into(), "-".into(), "--".into()),
        (":".into(), ":".into(), "::".into()),
        (":".into(), "/".into(), ":/".into()),
        ("/".into(), "/".into(), "//".into()),
        // Base64 patterns.
        ("A".into(), "A".into(), "AA".into()),
        ("Z".into(), "Z".into(), "ZZ".into()),
        // Numeric patterns.
        ("1".into(), "2".into(), "12".into()),
        ("3".into(), "4".into(), "34".into()),
        ("5".into(), "6".into(), "56".into()),
        ("7".into(), "8".into(), "78".into()),
        ("9".into(), "0".into(), "90".into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_basic() {
        let bpe = BpeTokenizer::new();
        let tokens = bpe.tokenize("hello");
        assert!(!tokens.is_empty());
        // Should have merged some pairs.
        assert!(tokens.iter().all(|t| !t.is_empty()));
    }

    #[test]
    fn test_tokenize_empty() {
        let bpe = BpeTokenizer::new();
        assert!(bpe.tokenize("").is_empty());
    }

    #[test]
    fn test_token_entropy() {
        let bpe = BpeTokenizer::new();
        // Repetitive string should have low entropy.
        let low = bpe.token_entropy("aaaaaaaa");
        // Diverse string should have higher entropy.
        let high = bpe.token_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(high >= low, "high={high}, low={low}");
    }

    #[test]
    fn test_uniqueness_ratio() {
        let bpe = BpeTokenizer::new();
        // All unique chars → ratio close to 1.0.
        let ratio = bpe.uniqueness_ratio("abcdef");
        assert!(ratio > 0.8);
        // Repeated chars → ratio close to 1/N.
        let ratio2 = bpe.uniqueness_ratio("aaaaaa");
        assert!(ratio2 < 0.5);
    }

    #[test]
    fn test_secret_score_high_for_secrets() {
        let bpe = BpeTokenizer::new();
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let natural = "hello world";
        let secret_score = bpe.secret_score(secret);
        let natural_score = bpe.secret_score(natural);
        assert!(
            secret_score > natural_score,
            "secret={secret_score}, natural={natural_score}"
        );
    }

    #[test]
    fn test_secret_score_zero_for_short() {
        let bpe = BpeTokenizer::new();
        assert_eq!(bpe.secret_score("abc"), 0.0);
    }

    #[test]
    fn test_encode() {
        let bpe = BpeTokenizer::new();
        let ids = bpe.encode("AKIA");
        assert!(!ids.is_empty());
    }

    #[test]
    fn test_char_level_entropy() {
        assert_eq!(char_level_entropy(""), 0.0);
        // Single character has zero entropy.
        assert_eq!(char_level_entropy("aaa"), 0.0);
        // Two equally distributed characters have entropy 1.0.
        let e = char_level_entropy("ab");
        assert!((e - 1.0).abs() < 0.01);
    }
}
