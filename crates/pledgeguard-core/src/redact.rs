//! Helpers to redact secret values before they are printed or persisted.

/// Redacts a matched secret, keeping up to 4 leading characters visible and
/// masking the rest with asterisks. Short secrets (<= 6 chars) are fully masked.
pub fn redact(secret: &str) -> String {
    let len = secret.chars().count();
    if len <= 6 {
        return "*".repeat(len);
    }
    let visible = 4.min(len - 2);
    let head: String = secret.chars().take(visible).collect();
    format!("{}{}", head, "*".repeat(len - visible))
}

/// Replaces every occurrence of `secret` inside `context` with its redacted form.
pub fn redact_in(context: &str, secret: &str) -> String {
    if secret.is_empty() {
        return context.to_string();
    }
    context.replace(secret, &redact(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_short() {
        assert_eq!(redact("abc123"), "******");
    }

    #[test]
    fn test_redact_long() {
        let r = redact("AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("AKIA"));
        assert!(r.contains('*'));
    }

    #[test]
    fn test_redact_in() {
        let ctx = "key = AKIAIOSFODNN7EXAMPLE";
        let r = redact_in(ctx, "AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("key = AKIA"));
    }
}
