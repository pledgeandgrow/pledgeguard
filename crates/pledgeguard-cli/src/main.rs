//! PledgeGuard CLI — scan files/directories for leaked secrets.

mod mcp;

// Use jemalloc on non-Windows platforms for better allocation performance.
#[cfg(not(target_os = "windows"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::{Parser, ValueEnum};
use pledgeguard_core::{
    Allowlist, Detector, Finding, Scanner, Severity, VerificationStatus, baseline,
    detectors::builtin_detectors, load_config, scan_git_history,
    verify_findings, verify_findings_with_options, VerifyOptions,
};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "pledgeguard", version, about = "Rust-native secret scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Scan a file or directory (working tree only) for secrets.
    Scan {
        /// Path to scan (file or directory). Defaults to the current directory.
        /// Use `-` to read from stdin.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,

        /// Minimum severity to report.
        #[arg(long, value_enum, default_value_t = CliSeverity::Low)]
        min_severity: CliSeverity,

        /// Do not redact secret values in output (unsafe — for local debugging only).
        #[arg(long)]
        no_redact: bool,

        /// Exit with a non-zero status if any finding at or above `min-severity` is found.
        /// Intended for use as a CI gate.
        #[arg(long)]
        fail_on_findings: bool,

        /// Directory containing `.wasm` plugin detectors to load in addition
        /// to the built-in detectors. May be given multiple times.
        #[arg(long = "plugin-dir")]
        plugin_dirs: Vec<PathBuf>,

        /// Include findings flagged as likely false positives (same-line
        /// comments or test/fixture/example paths). Hidden by default.
        #[arg(long)]
        show_all: bool,

        /// Call each finding's provider API to check whether the secret is
        /// still active. Best-effort (only some rules support this) and
        /// makes outbound network requests, so it is off by default.
        #[arg(long)]
        verify: bool,

        /// Load a baseline file and suppress findings whose fingerprint
        /// (rule_id + path + matched) appears in it. Useful for suppressing
        /// known false positives across runs.
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Save all current findings as a baseline file for future use with
        /// `--baseline`. The file contains raw matched secret values, so it
        /// should be treated as sensitive.
        #[arg(long)]
        save_baseline: Option<PathBuf>,

        /// Load custom detector rules from a TOML config file (pledgeguard.toml format).
        #[arg(long)]
        config: Option<PathBuf>,

        /// Write output to a file instead of stdout.
        #[arg(long)]
        report_file: Option<PathBuf>,

        /// Verbose output — print scan progress and stats to stderr.
        #[arg(long)]
        verbose: bool,

        /// Paths to ignore during scan (glob patterns). May be given multiple times.
        #[arg(long = "ignore-path")]
        ignore_paths: Vec<String>,

        /// Only run rules with the given IDs. May be given multiple times.
        /// If not set, all rules are enabled.
        #[arg(long = "enable-rule")]
        enable_rules: Vec<String>,

        /// Only show findings that have been verified as Active by a provider.
        /// Implies --verify. Unverified findings (no verifier or verification
        /// returned Inactive/Unknown/Error) are excluded from output.
        #[arg(long)]
        only_verified: bool,

        /// Only verify findings whose rule ID is in this list. May be given
        /// multiple times. If not set, all verifiable rules are checked.
        #[arg(long = "verify-detector")]
        verify_detectors: Vec<String>,

        /// Skip verification for findings whose rule ID is in this list.
        /// Takes precedence over --verify-detectors.
        #[arg(long = "no-verify-detector")]
        no_verify_detectors: Vec<String>,

        /// Enable verification caching to avoid repeated API calls for the
        /// same secret. Recommended for large scans.
        #[arg(long)]
        verify_cache: bool,

        /// Timeout in seconds for the scan. Currently informational (no hard enforcement).
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },

    /// Scan git commit history (all refs) for secrets introduced in past commits.
    History {
        /// Path to the git repository. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,

        /// Minimum severity to report.
        #[arg(long, value_enum, default_value_t = CliSeverity::Low)]
        min_severity: CliSeverity,

        /// Do not redact secret values in output (unsafe — for local debugging only).
        #[arg(long)]
        no_redact: bool,

        /// Exit with a non-zero status if any finding at or above `min-severity` is found.
        #[arg(long)]
        fail_on_findings: bool,

        /// Directory containing `.wasm` plugin detectors to load in addition
        /// to the built-in detectors. May be given multiple times.
        #[arg(long = "plugin-dir")]
        plugin_dirs: Vec<PathBuf>,

        /// Include findings flagged as likely false positives.
        #[arg(long)]
        show_all: bool,

        /// Call each finding's provider API to check whether the secret is
        /// still active. Best-effort and makes outbound network requests,
        /// so it is off by default.
        #[arg(long)]
        verify: bool,

        /// Load a baseline file and suppress findings whose fingerprint
        /// appears in it.
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Save all current findings as a baseline file for future use.
        #[arg(long)]
        save_baseline: Option<PathBuf>,

        /// Load custom detector rules from a TOML config file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Write output to a file instead of stdout.
        #[arg(long)]
        report_file: Option<PathBuf>,

        /// Verbose output — print scan progress and stats to stderr.
        #[arg(long)]
        verbose: bool,

        /// Only run rules with the given IDs. May be given multiple times.
        /// If not set, all rules are enabled.
        #[arg(long = "enable-rule")]
        enable_rules: Vec<String>,

        /// Only show findings that have been verified as Active by a provider.
        /// Implies --verify. Unverified findings are excluded from output.
        #[arg(long)]
        only_verified: bool,

        /// Only verify findings whose rule ID is in this list.
        #[arg(long = "verify-detector")]
        verify_detectors: Vec<String>,

        /// Skip verification for findings whose rule ID is in this list.
        #[arg(long = "no-verify-detector")]
        no_verify_detectors: Vec<String>,

        /// Enable verification caching.
        #[arg(long)]
        verify_cache: bool,

        /// Timeout in seconds for the scan.
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },

    /// Scan a remote source (Confluence, Slack, Jira, S3, GCS, Azure Blob,
    /// CircleCI, Travis CI, Jenkins, DroneCI, etc.) for secrets via API.
    ScanSource {
        /// Source type to scan.
        #[arg(long, value_enum)]
        source: ScanSourceType,

        /// API token or credential for the source.
        #[arg(long)]
        token: String,

        /// Additional configuration (e.g., bucket name, project slug, base URL).
        /// Format varies by source type.
        #[arg(long)]
        target: Option<String>,

        /// Secondary target (e.g., container name for Azure Blob, repo slug for Travis).
        #[arg(long)]
        target2: Option<String>,

        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,

        /// Minimum severity to report.
        #[arg(long, value_enum, default_value_t = CliSeverity::Low)]
        min_severity: CliSeverity,

        /// Do not redact secret values in output.
        #[arg(long)]
        no_redact: bool,

        /// Exit with non-zero status if any finding is found.
        #[arg(long)]
        fail_on_findings: bool,

        /// Verify findings via provider APIs.
        #[arg(long)]
        verify: bool,

        /// Only show verified-active findings.
        #[arg(long)]
        only_verified: bool,

        /// Write output to a file.
        #[arg(long)]
        report_file: Option<PathBuf>,

        /// Verbose output.
        #[arg(long)]
        verbose: bool,
    },

    /// Run a Model Context Protocol (MCP) server over stdio, exposing scan
    /// results as tools for AI agents to call directly.
    Mcp {
        /// Directory containing `.wasm` plugin detectors to load in addition
        /// to the built-in detectors, for every scan/history tool call. May
        /// be given multiple times.
        #[arg(long = "plugin-dir")]
        plugin_dirs: Vec<PathBuf>,
    },

    /// Install a git pre-commit hook that runs `pledgeguard scan --fail-on-findings`.
    InstallPreCommit {
        /// Overwrite an existing pre-commit hook if one exists.
        #[arg(long)]
        force: bool,

        /// Path to the git repository. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Sarif,
    Csv,
    Junit,
    GithubActions,
    Template,
}

#[derive(Copy, Clone, ValueEnum)]
enum CliSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<CliSeverity> for Severity {
    fn from(s: CliSeverity) -> Self {
        match s {
            CliSeverity::Low => Severity::Low,
            CliSeverity::Medium => Severity::Medium,
            CliSeverity::High => Severity::High,
            CliSeverity::Critical => Severity::Critical,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ScanSourceType {
    Confluence,
    Slack,
    Jira,
    Postman,
    Gerrit,
    Buildkite,
    Artifactory,
    AwsSecretsManager,
    S3,
    Gcs,
    AzureBlob,
    AlibabaOss,
    Circleci,
    TravisCi,
    Jenkins,
    Droneci,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            format,
            min_severity,
            no_redact,
            fail_on_findings,
            plugin_dirs,
            show_all,
            verify,
            baseline: baseline_path,
            save_baseline,
            config: config_path,
            report_file,
            verbose,
            ignore_paths,
            enable_rules,
            only_verified,
            verify_detectors,
            no_verify_detectors,
            verify_cache,
            timeout: _,
        } => {
            if verbose {
                eprintln!("pledgeguard: loading detectors...");
            }
            let (detectors, global_allowlist) = load_all_detectors_and_allowlist(&plugin_dirs, config_path.as_deref());

            let scan_opts = pledgeguard_core::ScanOptions {
                max_file_size: 5 * 1024 * 1024,
                respect_gitignore: true,
                ignore_paths,
                enable_rules: if enable_rules.is_empty() { None } else { Some(enable_rules) },
            };
            let scanner = Scanner::with_allowlist(detectors, scan_opts, global_allowlist);

            // Handle stdin scanning.
            let findings = if path == std::path::Path::new("-") {
                if verbose {
                    eprintln!("pledgeguard: reading from stdin");
                }
                let mut input = String::new();
                if let Err(e) = std::io::stdin().read_to_string(&mut input) {
                    eprintln!("error reading stdin: {e}");
                    return ExitCode::FAILURE;
                }
                scanner.scan_str(std::path::Path::new("<stdin>"), &input)
            } else {
                if verbose {
                    eprintln!("pledgeguard: scanning {}", path.display());
                }
                match scanner.scan_path(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("error scanning {}: {}", path.display(), e);
                        return ExitCode::FAILURE;
                    }
                }
            };

            if verbose {
                eprintln!("pledgeguard: {} raw finding(s)", findings.len());
            }

            report(
                findings,
                ReportOptions {
                    format,
                    min_severity: min_severity.into(),
                    no_redact,
                    fail_on_findings,
                    show_all,
                    verify,
                    only_verified,
                    baseline: baseline_path,
                    save_baseline,
                    report_file,
                    verify_detectors,
                    no_verify_detectors,
                    use_verify_cache: verify_cache,
                },
            )
        }
        Command::History {
            path,
            format,
            min_severity,
            no_redact,
            fail_on_findings,
            plugin_dirs,
            show_all,
            verify,
            baseline: baseline_path,
            save_baseline,
            config: config_path,
            report_file,
            verbose,
            enable_rules,
            only_verified,
            verify_detectors,
            no_verify_detectors,
            verify_cache,
            timeout: _,
        } => {
            if verbose {
                eprintln!("pledgeguard: loading detectors...");
            }
            let (detectors, _global_allowlist) = load_all_detectors_and_allowlist(&plugin_dirs, config_path.as_deref());
            // For history scanning, we filter detectors by enable_rules manually.
            let detectors = if enable_rules.is_empty() {
                detectors
            } else {
                let enabled: std::collections::HashSet<&str> = enable_rules.iter().map(|s| s.as_str()).collect();
                detectors.into_iter().filter(|d| enabled.contains(d.id())).collect()
            };
            if verbose {
                eprintln!("pledgeguard: scanning git history at {}", path.display());
            }
            let findings = match scan_git_history(&path, &detectors) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error scanning git history at {}: {}", path.display(), e);
                    return ExitCode::FAILURE;
                }
            };
            if verbose {
                eprintln!("pledgeguard: {} raw finding(s)", findings.len());
            }
            report(
                findings,
                ReportOptions {
                    format,
                    min_severity: min_severity.into(),
                    no_redact,
                    fail_on_findings,
                    show_all,
                    verify,
                    only_verified,
                    baseline: baseline_path,
                    save_baseline,
                    report_file,
                    verify_detectors,
                    no_verify_detectors,
                    use_verify_cache: verify_cache,
                },
            )
        }
        Command::ScanSource {
            source,
            token,
            target,
            target2,
            format,
            min_severity,
            no_redact,
            fail_on_findings,
            verify,
            only_verified,
            report_file,
            verbose,
        } => {
            let detectors = builtin_detectors();
            if verbose {
                eprintln!("pledgeguard: scanning source {:?}", source);
            }

            let findings = match source {
                ScanSourceType::Confluence => {
                    let config = pledgeguard_core::ConfluenceScanConfig {
                        base_url: target.unwrap_or_default(),
                        api_token: token,
                        email: target2.unwrap_or_default(),
                        space_key: None,
                        max_pages: 500,
                    };
                    pledgeguard_core::scan_confluence(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Slack => {
                    let config = pledgeguard_core::SlackScanConfig {
                        token,
                        channel_ids: target.unwrap_or_default().split(',').map(String::from).collect(),
                        max_messages: 1000,
                    };
                    pledgeguard_core::scan_slack(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Jira => {
                    let config = pledgeguard_core::JiraScanConfig {
                        base_url: target.unwrap_or_default(),
                        api_token: token,
                        email: target2.unwrap_or_default(),
                        jql: None,
                        max_issues: 500,
                    };
                    pledgeguard_core::scan_jira(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Postman => {
                    let config = pledgeguard_core::PostmanScanConfig {
                        api_key: token,
                        collection_id: target,
                        max_collections: 100,
                    };
                    pledgeguard_core::scan_postman(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Gerrit => {
                    let config = pledgeguard_core::GerritScanConfig {
                        base_url: target.unwrap_or_default(),
                        credentials: Some(token),
                        project: target2,
                        max_changes: 200,
                    };
                    pledgeguard_core::scan_gerrit(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Buildkite => {
                    let config = pledgeguard_core::BuildkiteScanConfig {
                        api_token: token,
                        org: target.unwrap_or_default(),
                        pipeline: target2,
                        max_builds: 100,
                    };
                    pledgeguard_core::scan_buildkite(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Artifactory => {
                    let config = pledgeguard_core::ArtifactoryScanConfig {
                        base_url: target.unwrap_or_default(),
                        api_key: token,
                        repo: target2,
                        max_files: 500,
                    };
                    pledgeguard_core::scan_artifactory(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::AwsSecretsManager => {
                    let parts: Vec<&str> = target.as_deref().unwrap_or("").split(':').collect();
                    let config = pledgeguard_core::AwsSecretsManagerScanConfig {
                        region: parts.get(1).unwrap_or(&"us-east-1").to_string(),
                        access_key_id: parts.first().unwrap_or(&"").to_string(),
                        secret_access_key: token,
                        name_prefix: target2,
                        max_secrets: 100,
                    };
                    pledgeguard_core::scan_aws_secrets_manager(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::S3 => {
                    let config = pledgeguard_core::S3ScanConfig {
                        bucket: target.unwrap_or_default(),
                        region: target2.unwrap_or_else(|| "us-east-1".to_string()),
                        access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                        secret_access_key: token,
                        prefix: None,
                        max_objects: 1000,
                    };
                    pledgeguard_core::scan_s3_bucket(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Gcs => {
                    let config = pledgeguard_core::GcsScanConfig {
                        bucket: target.unwrap_or_default(),
                        oauth_token: token,
                        prefix: None,
                        max_objects: 1000,
                    };
                    pledgeguard_core::scan_gcs_bucket(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::AzureBlob => {
                    let config = pledgeguard_core::AzureBlobScanConfig {
                        account: target.unwrap_or_default(),
                        container: target2.unwrap_or_default(),
                        sas_token: token,
                        prefix: None,
                        max_blobs: 500,
                    };
                    pledgeguard_core::scan_azure_blob(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::AlibabaOss => {
                    let config = pledgeguard_core::OssScanConfig {
                        bucket: target.unwrap_or_default(),
                        endpoint: target2.unwrap_or_else(|| "oss-cn-hangzhou.aliyuncs.com".to_string()),
                        access_key_id: std::env::var("ALIBABA_ACCESS_KEY_ID").unwrap_or_default(),
                        access_key_secret: token,
                        prefix: None,
                        max_objects: 1000,
                    };
                    pledgeguard_core::scan_alibaba_oss(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Circleci => {
                    let config = pledgeguard_core::CircleCiArtifactsScanConfig {
                        api_token: token,
                        project_slug: target.unwrap_or_default(),
                        max_builds: 30,
                    };
                    pledgeguard_core::scan_circleci_artifacts(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::TravisCi => {
                    let config = pledgeguard_core::TravisCiScanConfig {
                        api_token: token,
                        repo_slug: target.unwrap_or_default(),
                        base_url: None,
                        max_builds: 50,
                    };
                    pledgeguard_core::scan_travis_ci_logs(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Jenkins => {
                    let config = pledgeguard_core::JenkinsScanConfig {
                        base_url: target.unwrap_or_default(),
                        username: target2.unwrap_or_default(),
                        api_token: token,
                        job_name: None,
                        max_builds: 50,
                    };
                    pledgeguard_core::scan_jenkins_logs(&config, &detectors).unwrap_or_default()
                }
                ScanSourceType::Droneci => {
                    let config = pledgeguard_core::DroneCiScanConfig {
                        base_url: target.unwrap_or_default(),
                        api_token: token,
                        repo_slug: target2,
                        max_builds: 50,
                    };
                    pledgeguard_core::scan_droneci_builds(&config, &detectors).unwrap_or_default()
                }
            };

            if verbose {
                eprintln!("pledgeguard: {} raw finding(s)", findings.len());
            }

            report(
                findings,
                ReportOptions {
                    format,
                    min_severity: min_severity.into(),
                    no_redact,
                    fail_on_findings,
                    show_all: false,
                    verify,
                    only_verified,
                    baseline: None,
                    save_baseline: None,
                    report_file,
                    verify_detectors: vec![],
                    no_verify_detectors: vec![],
                    use_verify_cache: false,
                },
            )
        }
        Command::Mcp { plugin_dirs } => {
            mcp::run(&plugin_dirs);
            ExitCode::SUCCESS
        }
        Command::InstallPreCommit { force, path } => install_pre_commit(&path, force),
    }
}

fn load_all_detectors_and_allowlist(
    plugin_dirs: &[PathBuf],
    config_path: Option<&std::path::Path>,
) -> (Vec<Box<dyn Detector>>, Option<Allowlist>) {
    let mut detectors = builtin_detectors();
    for dir in plugin_dirs {
        detectors.extend(pledgeguard_core::load_plugins(dir));
    }
    let mut global_allowlist = None;
    if let Some(cp) = config_path {
        match load_config(cp) {
            Ok(result) => {
                detectors.extend(result.detectors);
                global_allowlist = result.global_allowlist;
            }
            Err(e) => {
                eprintln!("warning: failed to load config from {}: {}", cp.display(), e);
            }
        }
    }
    (detectors, global_allowlist)
}

struct ReportOptions {
    format: OutputFormat,
    min_severity: Severity,
    no_redact: bool,
    fail_on_findings: bool,
    show_all: bool,
    verify: bool,
    only_verified: bool,
    baseline: Option<PathBuf>,
    save_baseline: Option<PathBuf>,
    report_file: Option<PathBuf>,
    verify_detectors: Vec<String>,
    no_verify_detectors: Vec<String>,
    use_verify_cache: bool,
}

fn report(findings: Vec<Finding>, opts: ReportOptions) -> ExitCode {
    let ReportOptions {
        format,
        min_severity,
        no_redact,
        fail_on_findings,
        show_all,
        verify,
        only_verified,
        baseline: baseline_path,
        save_baseline,
        report_file,
        verify_detectors,
        no_verify_detectors,
        use_verify_cache,
    } = opts;
    // Save baseline before any filtering, so it captures everything.
    if let Some(ref bp) = save_baseline {
        let bl = baseline::from_findings(&findings);
        match baseline::save(bp, &bl) {
            Ok(()) => {
                println!(
                    "Baseline saved to {} ({} entries).",
                    bp.display(),
                    bl.entries.len()
                );
            }
            Err(e) => {
                eprintln!("failed to save baseline: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Apply baseline filtering before severity / show_all filtering.
    let mut findings = findings;
    if let Some(ref bp) = baseline_path {
        match baseline::load(bp) {
            Ok(bl) => {
                let (remaining, suppressed) = baseline::filter(findings, &bl);
                if suppressed > 0 {
                    eprintln!(
                        "{suppressed} finding(s) suppressed by baseline ({}).",
                        bp.display()
                    );
                }
                findings = remaining;
            }
            Err(e) => {
                eprintln!("failed to load baseline {}: {}", bp.display(), e);
                return ExitCode::FAILURE;
            }
        }
    }

    let mut findings: Vec<_> = findings
        .into_iter()
        .filter(|f| f.severity >= min_severity)
        .collect();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));

    let hidden_count = findings.iter().filter(|f| f.likely_false_positive).count();
    let mut visible: Vec<_> = if show_all {
        findings.clone()
    } else {
        findings
            .iter()
            .filter(|f| !f.likely_false_positive)
            .cloned()
            .collect()
    };

    let verify = verify || only_verified;
    if verify {
        if verify_detectors.is_empty() && no_verify_detectors.is_empty() && !use_verify_cache {
            verify_findings(&mut visible);
        } else {
            let verify_opts = VerifyOptions {
                verify_detectors,
                no_verify_detectors,
                use_cache: use_verify_cache,
                rate_limit_aware: true,
            };
            verify_findings_with_options(&mut visible, &verify_opts);
        }
    }

    if only_verified {
        visible.retain(|f| {
            matches!(f.verification, Some(VerificationStatus::Active))
        });
    }

    let display: Vec<_> = if no_redact {
        visible.clone()
    } else {
        visible.iter().map(|f| f.redacted()).collect()
    };

    let output = match format {
        OutputFormat::Table => format_table(&display),
        OutputFormat::Json => format_json(&display),
        OutputFormat::Sarif => format_sarif(&display),
        OutputFormat::Csv => pledgeguard_core::to_csv(&display),
        OutputFormat::Junit => pledgeguard_core::to_junit(&display),
        OutputFormat::GithubActions => pledgeguard_core::to_github_actions(&display),
        OutputFormat::Template => pledgeguard_core::to_template(&display, None),
    };

    let mut output = output;
    if !show_all && hidden_count > 0 {
        output.push_str(&format!(
            "\n{} low-confidence finding(s) hidden (in comments or test/fixture paths); use --show-all to include them.\n",
            hidden_count
        ));
    }

    if let Some(ref rf) = report_file {
        if let Err(e) = std::fs::write(rf, &output) {
            eprintln!("failed to write report file {}: {}", rf.display(), e);
            return ExitCode::FAILURE;
        }
        eprintln!("Report written to {} ({} findings).", rf.display(), visible.len());
    } else {
        print!("{output}");
    }

    if fail_on_findings && !visible.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn format_table(findings: &[pledgeguard_core::Finding]) -> String {
    if findings.is_empty() {
        return "No secrets found.\n".to_string();
    }

    let mut out = format!(
        "{:<10} {:<28} {:<40} {:<9} {:<10} FILE:LINE\n",
        "SEVERITY", "RULE", "MATCH", "COMMIT", "VERIFIED",
    );
    for f in findings {
        let commit = f
            .commit
            .as_deref()
            .map(|c| &c[..c.len().min(8)])
            .unwrap_or("-");
        let verified = f
            .verification
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{:<10} {:<28} {:<40} {:<9} {:<10} {}:{}\n",
            f.severity.to_string(),
            f.rule_id,
            f.matched,
            commit,
            verified,
            f.path.display(),
            f.line
        ));
    }
    out.push_str(&format!("\n{} finding(s).\n", findings.len()));
    out
}

fn format_json(findings: &[pledgeguard_core::Finding]) -> String {
    match serde_json::to_string_pretty(findings) {
        Ok(s) => s + "\n",
        Err(e) => format!("failed to serialize findings: {e}\n"),
    }
}

fn format_sarif(findings: &[pledgeguard_core::Finding]) -> String {
    let sarif = pledgeguard_core::to_sarif(findings);
    match serde_json::to_string_pretty(&sarif) {
        Ok(s) => s + "\n",
        Err(e) => format!("failed to serialize SARIF: {e}\n"),
    }
}

const PRE_COMMIT_HOOK: &str = "#!/bin/sh\n# PledgeGuard pre-commit hook — scans for secrets before commit.\n# Installed by `pledgeguard install-pre-commit`.\n# To customize, edit this file or remove it and re-run: pledgeguard install-pre-commit --force\npledgeguard scan --fail-on-findings\n";

fn install_pre_commit(path: &std::path::Path, force: bool) -> ExitCode {
    let output = match std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(path)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("failed to run `git rev-parse --git-dir`: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !output.status.success() {
        eprintln!(
            "not inside a git repository (git rev-parse failed): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return ExitCode::FAILURE;
    }

    let git_dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let hooks_dir = path.join(&git_dir).join("hooks");
    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() && !force {
        eprintln!(
            "pre-commit hook already exists at {}; use --force to overwrite",
            hook_path.display()
        );
        return ExitCode::FAILURE;
    }

    if let Err(e) = std::fs::create_dir_all(&hooks_dir) {
        eprintln!(
            "failed to create hooks directory {}: {e}",
            hooks_dir.display()
        );
        return ExitCode::FAILURE;
    }

    if let Err(e) = std::fs::write(&hook_path, PRE_COMMIT_HOOK) {
        eprintln!("failed to write hook file {}: {e}", hook_path.display());
        return ExitCode::FAILURE;
    }

    // On Windows, also write a pre-commit.bat wrapper that delegates to the
    // shell script. Git for Windows will use the .bat if core.shell is cmd.exe;
    // if it's bash (the default), it uses the shell script directly.
    #[cfg(windows)]
    {
        let bat_path = hooks_dir.join("pre-commit.bat");
        let bat_content = "@echo off\nrem PledgeGuard pre-commit hook (Windows wrapper)\nrem Delegates to the shell script via Git Bash if available.\nwhere bash >nul 2>nul && (\n  bash \"%~dp0pre-commit\"\n  exit /b %errorlevel%\n)\necho PledgeGuard: bash not found on PATH. Install Git for Windows or run pledgeguard manually.\nexit /b 0\n";
        if let Err(e) = std::fs::write(&bat_path, bat_content) {
            eprintln!("warning: failed to write Windows .bat wrapper: {e}");
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&hook_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&hook_path, perms);
        }
    }

    println!("Pre-commit hook installed at {}.", hook_path.display());
    println!("The hook runs `pledgeguard scan --fail-on-findings` before each commit.");
    println!("To customize, edit the hook file or re-run with --force after editing.");
    ExitCode::SUCCESS
}
