//! Built-in detector registry — well-known secret formats from popular providers.

use crate::detector::{Detector, RegexDetector};
use crate::entropy::EntropyDetector;
use crate::finding::Severity;

/// Returns the full set of built-in detectors (provider-specific regexes + generic entropy).
pub fn builtin_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(RegexDetector::with_prefilter(
            "aws-access-key-id",
            "AWS Access Key ID",
            Severity::Critical,
            r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b",
            &["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-secret-access-key",
            "AWS Secret Access Key",
            Severity::Critical,
            r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
            &["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "github-pat",
            "GitHub Personal Access Token",
            Severity::Critical,
            r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
            &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "github-fine-grained-pat",
            "GitHub Fine-Grained Personal Access Token",
            Severity::Critical,
            r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
            &["github_pat_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "slack-token",
            "Slack Token",
            Severity::High,
            r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b",
            &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "slack-webhook",
            "Slack Incoming Webhook URL",
            Severity::High,
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{24,}",
            &["hooks.slack.com"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stripe-secret-key",
            "Stripe Secret Key",
            Severity::Critical,
            r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,247}\b",
            &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "google-api-key",
            "Google API Key",
            Severity::High,
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            &["AIza"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "private-key-pem",
            "PEM-Encoded Private Key",
            Severity::Critical,
            r"-----BEGIN ((RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY-----",
            &["-----BEGIN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "jwt",
            "JSON Web Token",
            Severity::Medium,
            r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b",
            &["eyJ"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "npm-token",
            "npm Access Token",
            Severity::High,
            r"\bnpm_[A-Za-z0-9]{36}\b",
            &["npm_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "postgres-connection-string",
            "PostgreSQL Connection String with Credentials",
            Severity::High,
            r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s/]+",
            &["postgres://", "postgresql://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mysql-connection-string",
            "MySQL Connection String with Credentials",
            Severity::High,
            r"mysql://[^:\s]+:[^@\s]+@[^\s/]+",
            &["mysql://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "generic-bearer-token",
            "Generic Bearer Token",
            Severity::Low,
            r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}",
            &["bearer ", "Bearer "],
        )),
        Box::new(EntropyDetector::default()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_detectors_nonempty() {
        assert!(!builtin_detectors().is_empty());
    }

    #[test]
    fn test_aws_key_detected() {
        let detectors = builtin_detectors();
        let aws = detectors
            .iter()
            .find(|d| d.id() == "aws-access-key-id")
            .unwrap();
        let matches = aws.scan_line("aws_key = AKIAIOSFODNN7EXAMPLE");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].text, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_github_pat_detected() {
        let detectors = builtin_detectors();
        let gh = detectors.iter().find(|d| d.id() == "github-pat").unwrap();
        let matches = gh.scan_line("token: ghp_1234567890abcdef1234567890abcdef1234");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_private_key_detected() {
        let detectors = builtin_detectors();
        let pk = detectors
            .iter()
            .find(|d| d.id() == "private-key-pem")
            .unwrap();
        let matches = pk.scan_line("-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_no_false_positive_on_plain_text() {
        let detectors = builtin_detectors();
        for d in &detectors {
            if d.id() == "generic-high-entropy" {
                continue; // entropy detector needs its own targeted tests
            }
            let matches = d.scan_line("this is just a plain sentence with no secrets in it");
            assert!(
                matches.is_empty(),
                "detector {} produced false positive",
                d.id()
            );
        }
    }
}
