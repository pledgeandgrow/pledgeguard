//! Minimal Model Context Protocol (MCP) server over stdio.
//!
//! Exposes two tools — `scan_path` and `scan_git_history` — so an AI agent
//! (or any MCP-compatible client) can run PledgeGuard scans and consume
//! findings directly, without shelling out to the CLI and parsing table
//! output. Implements just enough of the MCP JSON-RPC 2.0 stdio transport
//! (newline-delimited JSON messages) to serve `initialize`, `tools/list`,
//! and `tools/call`; there is no dependency on an external MCP SDK crate,
//! consistent with this project's preference for a light dependency graph.

use pledgeguard_core::{
    detectors::builtin_detectors, scan_git_history, verify_findings, Detector, Finding, Scanner,
    Severity,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Deserialize)]
struct RpcRequest {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

/// Runs the MCP server, reading JSON-RPC requests from stdin and writing
/// responses to stdout (one JSON object per line), until stdin closes.
pub fn run(default_plugin_dirs: &[PathBuf]) {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let request: RpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                respond_error(None, -32700, &format!("parse error: {e}"));
                continue;
            }
        };

        // Notifications (no `id`) never get a response, per JSON-RPC 2.0.
        let is_notification = request.id.is_none();

        match request.method.as_str() {
            "initialize" => {
                if !is_notification {
                    respond(
                        request.id,
                        json!({
                            "protocolVersion": "2024-11-05",
                            "serverInfo": { "name": "pledgeguard", "version": env!("CARGO_PKG_VERSION") },
                            "capabilities": { "tools": {} }
                        }),
                    );
                }
            }
            "notifications/initialized" | "ping" => {
                if !is_notification {
                    respond(request.id, json!({}));
                }
            }
            "tools/list" => {
                if !is_notification {
                    respond(request.id, json!({ "tools": tool_defs() }));
                }
            }
            "tools/call" => {
                if !is_notification {
                    let result = handle_tools_call(&request.params, default_plugin_dirs);
                    respond(request.id, result);
                }
            }
            other => {
                if !is_notification {
                    respond_error(request.id, -32601, &format!("method not found: {other}"));
                }
            }
        }
    }
}

fn tool_defs() -> Value {
    let common_props = json!({
        "path": { "type": "string", "description": "File or directory path to scan (or git repo root for scan_git_history)." },
        "min_severity": { "type": "string", "enum": ["low", "medium", "high", "critical"], "default": "low" },
        "show_all": { "type": "boolean", "description": "Include findings flagged as likely false positives.", "default": false },
        "verify": { "type": "boolean", "description": "Call provider APIs to check whether matched secrets are still active.", "default": false }
    });

    json!([
        {
            "name": "scan_path",
            "description": "Scan a file or directory in the working tree for hardcoded secrets using PledgeGuard's regex + entropy detectors.",
            "inputSchema": {
                "type": "object",
                "properties": common_props,
                "required": ["path"]
            }
        },
        {
            "name": "scan_git_history",
            "description": "Scan a git repository's commit history (all refs, added lines only) for secrets introduced in past commits.",
            "inputSchema": {
                "type": "object",
                "properties": common_props,
                "required": ["path"]
            }
        }
    ])
}

fn handle_tools_call(params: &Value, default_plugin_dirs: &[PathBuf]) -> Value {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    let outcome = match name {
        "scan_path" => run_scan(&args, default_plugin_dirs),
        "scan_git_history" => run_history(&args, default_plugin_dirs),
        other => Err(format!("unknown tool: {other}")),
    };

    match outcome {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
        Err(err) => json!({ "content": [{ "type": "text", "text": err }], "isError": true }),
    }
}

fn run_scan(args: &Value, default_plugin_dirs: &[PathBuf]) -> Result<String, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: path")?;

    let detectors = load_detectors(args, default_plugin_dirs);
    let scanner = Scanner::new(detectors);
    let findings = scanner
        .scan_path(path)
        .map_err(|e| format!("scan failed: {e}"))?;

    finalize(findings, args)
}

fn run_history(args: &Value, default_plugin_dirs: &[PathBuf]) -> Result<String, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: path")?;

    let detectors = load_detectors(args, default_plugin_dirs);
    let findings = scan_git_history(std::path::Path::new(path), &detectors)
        .map_err(|e| format!("git history scan failed: {e}"))?;

    finalize(findings, args)
}

fn load_detectors(args: &Value, default_plugin_dirs: &[PathBuf]) -> Vec<Box<dyn Detector>> {
    let mut detectors = builtin_detectors();
    for dir in default_plugin_dirs {
        detectors.extend(pledgeguard_core::load_plugins(dir));
    }
    if let Some(dirs) = args.get("plugin_dirs").and_then(|v| v.as_array()) {
        for dir in dirs.iter().filter_map(|v| v.as_str()) {
            detectors.extend(pledgeguard_core::load_plugins(std::path::Path::new(dir)));
        }
    }
    detectors
}

fn finalize(findings: Vec<Finding>, args: &Value) -> Result<String, String> {
    let min_severity = args
        .get("min_severity")
        .and_then(|v| v.as_str())
        .map(parse_severity)
        .unwrap_or(Severity::Low);
    let show_all = args
        .get("show_all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let verify = args.get("verify").and_then(|v| v.as_bool()).unwrap_or(false);

    let mut visible: Vec<Finding> = findings
        .into_iter()
        .filter(|f| f.severity >= min_severity)
        .filter(|f| show_all || !f.likely_false_positive)
        .collect();
    visible.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));

    if verify {
        verify_findings(&mut visible);
    }

    let redacted: Vec<Finding> = visible.iter().map(|f| f.redacted()).collect();
    serde_json::to_string_pretty(&redacted).map_err(|e| format!("failed to serialize findings: {e}"))
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn respond(id: Option<Value>, result: Value) {
    write_message(json!({ "jsonrpc": "2.0", "id": id, "result": result }));
}

fn respond_error(id: Option<Value>, code: i64, message: &str) {
    write_message(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }));
}

fn write_message(message: Value) {
    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "{message}");
    let _ = stdout.flush();
}
