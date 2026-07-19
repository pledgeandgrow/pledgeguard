//! Stream-based scanning sources: syslog streams and Vault token detection
//! in log files.
//!
//! These scanners operate on real-time or near-real-time text streams,
//! scanning each line as it arrives for secret patterns.

use crate::detector::Detector;
use crate::finding::Finding;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Helper: scan a single line with all detectors.
fn scan_line(
    line: &str,
    line_no: usize,
    source: &str,
    detectors: &[Box<dyn Detector>],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let virtual_path = Path::new(source);
    for detector in detectors {
        for m in detector.scan_line(line) {
            findings.push(Finding {
                rule_id: detector.id().to_string(),
                description: detector.description().to_string(),
                severity: detector.severity(),
                path: virtual_path.to_path_buf(),
                line: line_no,
                column: m.start + 1,
                matched: m.text,
                context: line.to_string(),
                commit: None,
                likely_false_positive: false,
                verification: None,
            });
        }
    }
    findings
}

// ── Syslog Stream Scanning ─────────────────────────────────────────────

/// Configuration for a syslog stream scan.
#[derive(Debug, Clone)]
pub struct SyslogScanConfig {
    /// Source identifier (e.g., "syslog:remote" or "syslog:file").
    pub source: String,
    /// Maximum number of lines to scan (0 = unlimited).
    pub max_lines: usize,
    /// Timeout in seconds (0 = no timeout, scan until EOF).
    pub timeout_secs: u64,
}

/// Scan a syslog stream (from a reader) for secrets.
///
/// Reads lines from any `BufRead` source (stdin, TCP socket, file tail, etc.)
/// and scans each line for secret patterns. Returns findings and the number
/// of lines scanned.
pub fn scan_syslog_stream<R: BufRead>(
    reader: R,
    config: &SyslogScanConfig,
    detectors: &[Box<dyn Detector>],
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut lines_scanned = 0usize;

    for (idx, line_result) in reader.lines().enumerate() {
        match line_result {
            Ok(line) => {
                findings.extend(scan_line(&line, idx + 1, &config.source, detectors));
                lines_scanned += 1;
                if config.max_lines > 0 && lines_scanned >= config.max_lines {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    (findings, lines_scanned)
}

/// Scan a syslog file (or any log file) for secrets.
pub fn scan_syslog_file(
    path: &Path,
    config: &SyslogScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<(Vec<Finding>, usize), StreamScanError> {
    let file = std::fs::File::open(path).map_err(StreamScanError::Io)?;
    let reader = BufReader::new(file);
    let source = format!("syslog:{}", path.display());
    let config = SyslogScanConfig {
        source,
        ..config.clone()
    };
    Ok(scan_syslog_stream(reader, &config, detectors))
}

/// Scan syslog from stdin. Reads until EOF or max_lines reached.
pub fn scan_syslog_stdin(
    config: &SyslogScanConfig,
    detectors: &[Box<dyn Detector>],
) -> (Vec<Finding>, usize) {
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let config = SyslogScanConfig {
        source: "syslog:stdin".to_string(),
        ..config.clone()
    };
    scan_syslog_stream(reader, &config, detectors)
}

/// Scan a TCP syslog stream (e.g., from a syslog relay on port 514).
/// Spawns a thread to read from the TCP connection and scans lines as they arrive.
/// Returns a receiver that yields findings as they are found.
pub fn scan_syslog_tcp(
    host: &str,
    port: u16,
    config: &SyslogScanConfig,
    detectors: Vec<Box<dyn Detector>>,
) -> mpsc::Receiver<Vec<Finding>> {
    let (tx, rx) = mpsc::channel();
    let source = format!("syslog:tcp://{}:{}", host, port);
    let max_lines = config.max_lines;
    let timeout_secs = config.timeout_secs;
    let host = host.to_string();

    thread::spawn(move || {
        let addr = format!("{}:{}", host, port);
        let stream = match std::net::TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(vec![Finding {
                    rule_id: "syslog-connection-error".to_string(),
                    description: format!("Failed to connect to syslog TCP: {e}"),
                    severity: crate::finding::Severity::Low,
                    path: std::path::PathBuf::from(&source),
                    line: 0,
                    column: 0,
                    matched: String::new(),
                    context: format!("Connection error: {e}"),
                    commit: None,
                    likely_false_positive: false,
                    verification: None,
                }]);
                return;
            }
        };

        // Set timeout if configured.
        if timeout_secs > 0 {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)));
        }

        let reader = BufReader::new(stream);
        let mut lines_scanned = 0usize;

        for (idx, line_result) in reader.lines().enumerate() {
            match line_result {
                Ok(line) => {
                    let line_findings = scan_line(&line, idx + 1, &source, &detectors);
                    if !line_findings.is_empty() {
                        let _ = tx.send(line_findings);
                    }
                    lines_scanned += 1;
                    if max_lines > 0 && lines_scanned >= max_lines {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    rx
}

// ── Vault Token Detection in Logs ──────────────────────────────────────

/// Scan a log file for HashiCorp Vault tokens.
///
/// Vault tokens (s.xxxxx, h.xxxxx, b.xxxxx) are often accidentally
/// logged in application logs. This scanner specifically looks for
/// Vault token patterns in log files, in addition to running all
/// standard detectors.
pub fn scan_vault_tokens_in_logs(
    log_path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, StreamScanError> {
    let file = std::fs::File::open(log_path).map_err(StreamScanError::Io)?;
    let reader = BufReader::new(file);
    let source = format!("vault-logs:{}", log_path.display());

    let mut findings = Vec::new();
    for (idx, line_result) in reader.lines().enumerate() {
        match line_result {
            Ok(line) => {
                // Run all detectors on the line.
                findings.extend(scan_line(&line, idx + 1, &source, detectors));

                // Additionally, look for Vault token patterns that may not
                // be caught by the standard vault detector.
                // Vault tokens: s.<token>, h.<token>, b.<token>
                if let Some(vault_findings) = detect_vault_tokens(&line, idx + 1, &source) {
                    findings.extend(vault_findings);
                }
            }
            Err(_) => break,
        }
    }

    Ok(findings)
}

/// Detect Vault token patterns in a line of text.
/// Vault tokens have the format: <prefix>.<base62 string>
/// where prefix is s (service), h (root/human), b (batch), or r (recovery).
fn detect_vault_tokens(line: &str, line_no: usize, source: &str) -> Option<Vec<Finding>> {
    let vault_re = regex::Regex::new(r"(?i)\b([shbr])\.([A-Za-z0-9]{20,})\b").unwrap();
    let matches: Vec<_> = vault_re.find_iter(line).collect();
    if matches.is_empty() {
        return None;
    }

    let virtual_path = Path::new(source);
    let mut findings = Vec::new();
    for m in matches {
        findings.push(Finding {
            rule_id: "vault-token-in-log".to_string(),
            description: "HashiCorp Vault token detected in log output".to_string(),
            severity: crate::finding::Severity::High,
            path: virtual_path.to_path_buf(),
            line: line_no,
            column: m.start() + 1,
            matched: m.as_str().to_string(),
            context: line.to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        });
    }
    Some(findings)
}

// ── Error type ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StreamScanError {
    Io(std::io::Error),
}

impl std::fmt::Display for StreamScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamScanError::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for StreamScanError {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_line_finds_secrets() {
        let detectors = crate::detectors::builtin_detectors();
        let findings = scan_line("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", 1, "test://file", &detectors);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_syslog_stream() {
        let detectors = crate::detectors::builtin_detectors();
        let input = "Jan 01 00:00:00 host app[123]: aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n";
        let reader = BufReader::new(input.as_bytes());
        let config = SyslogScanConfig {
            source: "syslog:test".to_string(),
            max_lines: 100,
            timeout_secs: 0,
        };
        let (findings, lines) = scan_syslog_stream(reader, &config, &detectors);
        assert_eq!(lines, 1);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_syslog_stream_max_lines() {
        let detectors = crate::detectors::builtin_detectors();
        let input = "line1\nline2\nline3\nline4\nline5\n";
        let reader = BufReader::new(input.as_bytes());
        let config = SyslogScanConfig {
            source: "syslog:test".to_string(),
            max_lines: 3,
            timeout_secs: 0,
        };
        let (_, lines) = scan_syslog_stream(reader, &config, &detectors);
        assert_eq!(lines, 3);
    }

    #[test]
    fn test_detect_vault_tokens() {
        let line = "2024-01-01 app: Using vault token s.abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = detect_vault_tokens(line, 1, "vault-logs:test");
        assert!(findings.is_some());
        let findings = findings.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "vault-token-in-log");
        assert!(findings[0].matched.starts_with("s."));
    }

    #[test]
    fn test_detect_vault_tokens_no_match() {
        let line = "2024-01-01 app: No tokens here, just normal log output";
        let findings = detect_vault_tokens(line, 1, "vault-logs:test");
        assert!(findings.is_none());
    }

    #[test]
    fn test_detect_vault_tokens_multiple() {
        let line = "tokens: s.abcdefghijklmnopqrstuvwxyz1234567890 and h.abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = detect_vault_tokens(line, 1, "vault-logs:test");
        assert!(findings.is_some());
        let findings = findings.unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_scan_vault_tokens_in_log_file() {
        let detectors = crate::detectors::builtin_detectors();
        let log_content = "2024-01-01 app: Starting with token s.abcdefghijklmnopqrstuvwxyz1234567890\n";
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), log_content).unwrap();
        let findings = scan_vault_tokens_in_logs(temp.path(), &detectors).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule_id == "vault-token-in-log"));
    }

    #[test]
    fn test_stream_scan_error_display() {
        let err = StreamScanError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.to_string().contains("IO error"));
    }
}
