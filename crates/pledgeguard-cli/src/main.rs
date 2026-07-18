//! PledgeGuard CLI — scan files/directories for leaked secrets.

mod mcp;

use clap::{Parser, ValueEnum};
use pledgeguard_core::{
    baseline, detectors::builtin_detectors, scan_git_history, verify_findings, Detector, Finding,
    Scanner, Severity,
};
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
        } => {
            let detectors = load_all_detectors(&plugin_dirs);
            let scanner = Scanner::new(detectors);
            let findings = match scanner.scan_path(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error scanning {}: {}", path.display(), e);
                    return ExitCode::FAILURE;
                }
            };
            report(
                findings,
                format,
                min_severity.into(),
                no_redact,
                fail_on_findings,
                show_all,
                verify,
                baseline_path,
                save_baseline,
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
        } => {
            let detectors = load_all_detectors(&plugin_dirs);
            let findings = match scan_git_history(&path, &detectors) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error scanning git history at {}: {}", path.display(), e);
                    return ExitCode::FAILURE;
                }
            };
            report(
                findings,
                format,
                min_severity.into(),
                no_redact,
                fail_on_findings,
                show_all,
                verify,
                baseline_path,
                save_baseline,
            )
        }
        Command::Mcp { plugin_dirs } => {
            mcp::run(&plugin_dirs);
            ExitCode::SUCCESS
        }
        Command::InstallPreCommit { force, path } => {
            install_pre_commit(&path, force)
        }
    }
}

fn load_all_detectors(plugin_dirs: &[PathBuf]) -> Vec<Box<dyn Detector>> {
    let mut detectors = builtin_detectors();
    for dir in plugin_dirs {
        detectors.extend(pledgeguard_core::load_plugins(dir));
    }
    detectors
}

fn report(
    findings: Vec<Finding>,
    format: OutputFormat,
    min_severity: Severity,
    no_redact: bool,
    fail_on_findings: bool,
    show_all: bool,
    verify: bool,
    baseline_path: Option<PathBuf>,
    save_baseline: Option<PathBuf>,
) -> ExitCode {
    // Save baseline before any filtering, so it captures everything.
    if let Some(ref bp) = save_baseline {
        let bl = baseline::from_findings(&findings);
        match baseline::save(bp, &bl) {
            Ok(()) => {
                println!("Baseline saved to {} ({} entries).", bp.display(), bl.entries.len());
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
                    eprintln!("{suppressed} finding(s) suppressed by baseline ({}).", bp.display());
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

    if verify {
        verify_findings(&mut visible);
    }

    let display: Vec<_> = if no_redact {
        visible.clone()
    } else {
        visible.iter().map(|f| f.redacted()).collect()
    };

    match format {
        OutputFormat::Table => print_table(&display),
        OutputFormat::Json => print_json(&display),
        OutputFormat::Sarif => print_sarif(&display),
    }

    if !show_all && hidden_count > 0 {
        println!(
            "\n{} low-confidence finding(s) hidden (in comments or test/fixture paths); use --show-all to include them.",
            hidden_count
        );
    }

    if fail_on_findings && !visible.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_table(findings: &[pledgeguard_core::Finding]) {
    if findings.is_empty() {
        println!("No secrets found.");
        return;
    }

    println!(
        "{:<10} {:<28} {:<40} {:<9} {:<10} {}:{}",
        "SEVERITY", "RULE", "MATCH", "COMMIT", "VERIFIED", "FILE", "LINE"
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
        println!(
            "{:<10} {:<28} {:<40} {:<9} {:<10} {}:{}",
            f.severity.to_string(),
            f.rule_id,
            f.matched,
            commit,
            verified,
            f.path.display(),
            f.line
        );
    }
    println!("\n{} finding(s).", findings.len());
}

fn print_json(findings: &[pledgeguard_core::Finding]) {
    match serde_json::to_string_pretty(findings) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("failed to serialize findings: {e}"),
    }
}

fn print_sarif(findings: &[pledgeguard_core::Finding]) {
    let sarif = pledgeguard_core::to_sarif(findings);
    match serde_json::to_string_pretty(&sarif) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("failed to serialize SARIF: {e}"),
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
        eprintln!("failed to create hooks directory {}: {e}", hooks_dir.display());
        return ExitCode::FAILURE;
    }

    if let Err(e) = std::fs::write(&hook_path, PRE_COMMIT_HOOK) {
        eprintln!("failed to write hook file {}: {e}", hook_path.display());
        return ExitCode::FAILURE;
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
    ExitCode::SUCCESS
}
