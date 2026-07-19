//! Custom configuration file support (`pledgeguard.toml`).
//!
//! Users can define custom detector rules in a TOML file, extending
//! PledgeGuard beyond the built-in detectors without writing WASM plugins.
//!
//! ## Example `pledgeguard.toml`
//!
//! ```toml
//! [[rules]]
//! id = "custom-api-key"
//! description = "My Custom API Key"
//! severity = "high"
//! pattern = '\bMYKEY_[A-Za-z0-9]{32}\b'
//!
//! [[rules]]
//! id = "internal-token"
//! description = "Internal Service Token"
//! severity = "critical"
//! pattern = '\bINT_[A-Fa-f0-9]{40}\b'
//! prefilter = ["INT_"]
//! ```

use crate::detector::{Detector, RegexDetector};
use crate::finding::Severity;
use std::path::Path;

/// A single custom rule from the config file.
#[derive(Debug, serde::Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    #[serde(default)]
    pub prefilter: Vec<String>,
}

/// The top-level config file structure.
#[derive(Debug, serde::Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub rules: Vec<CustomRule>,
}

/// Errors that can occur while loading a config file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid regex in rule '{rule_id}': {error}")]
    InvalidRegex { rule_id: String, error: String },
    #[error("invalid severity '{severity}' in rule '{rule_id}'; expected low, medium, high, or critical")]
    InvalidSeverity { rule_id: String, severity: String },
}

/// Load a config file from a TOML path and return custom detectors.
pub fn load_config(path: &Path) -> Result<Vec<Box<dyn Detector>>, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    config_to_detectors(&config)
}

/// Convert a parsed [`Config`] into a list of detectors.
pub fn config_to_detectors(config: &Config) -> Result<Vec<Box<dyn Detector>>, ConfigError> {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

    for rule in &config.rules {
        let severity = parse_severity(&rule.severity)
            .ok_or_else(|| ConfigError::InvalidSeverity {
                rule_id: rule.id.clone(),
                severity: rule.severity.clone(),
            })?;

        let regex = regex::Regex::new(&rule.pattern).map_err(|e| ConfigError::InvalidRegex {
            rule_id: rule.id.clone(),
            error: e.to_string(),
        })?;

        detectors.push(Box::new(RegexDetector::with_prefilter_owned(
            rule.id.clone(),
            rule.description.clone(),
            severity,
            regex,
            rule.prefilter.clone(),
        )));
    }

    Ok(detectors)
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config_from_toml() {
        let toml = r#"
[[rules]]
id = "custom-api-key"
description = "My Custom API Key"
severity = "high"
pattern = '\bMYKEY_[A-Za-z0-9]{32}\b'
prefilter = ["MYKEY_"]

[[rules]]
id = "internal-token"
description = "Internal Service Token"
severity = "critical"
pattern = '\bINT_[A-Fa-f0-9]{40}\b'
prefilter = ["INT_"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let detectors = config_to_detectors(&config).unwrap();
        assert_eq!(detectors.len(), 2);

        let m = detectors[0].scan_line("key = MYKEY_abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(m.len(), 1);
        assert_eq!(detectors[0].id(), "custom-api-key");

        let m = detectors[1].scan_line("token = INT_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
        assert_eq!(m.len(), 1);
        assert_eq!(detectors[1].id(), "internal-token");
    }

    #[test]
    fn test_invalid_severity_errors() {
        let toml = r#"
[[rules]]
id = "bad-rule"
description = "Bad"
severity = "extreme"
pattern = 'foo'
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let result = config_to_detectors(&config);
        assert!(matches!(result, Err(ConfigError::InvalidSeverity { .. })));
    }

    #[test]
    fn test_invalid_regex_errors() {
        let toml = r#"
[[rules]]
id = "bad-regex"
description = "Bad Regex"
severity = "low"
pattern = '[invalid('
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let result = config_to_detectors(&config);
        assert!(matches!(result, Err(ConfigError::InvalidRegex { .. })));
    }

    #[test]
    fn test_empty_config() {
        let config = Config::default();
        let detectors = config_to_detectors(&config).unwrap();
        assert!(detectors.is_empty());
    }
}
