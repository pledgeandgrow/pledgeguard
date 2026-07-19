//! Model Context Protocol (MCP) server v2 for PledgeGuard.
//!
//! Exposes tools so an AI agent (or any MCP-compatible client) can run
//! PledgeGuard scans, verify secrets, and list detectors — all without
//! shelling out to the CLI. Implements the MCP JSON-RPC 2.0 protocol
//! over stdio (default) or TCP (remote mode).
//!
//! ## v2 features (goals 325-328)
//!
//! | Goal | Feature |
//! |---|---|
//! | 325 | `scan_source`, `verify_secret`, `list_detectors` tools |
//! | 326 | Streaming progress notifications during scans |
//! | 327 | Token-based authentication for remote connections |
//! | 328 | TCP transport (remote mode) in addition to stdio |

use pledgeguard_core::{
    Detector, Finding, Scanner, Severity, detectors::builtin_detectors, scan_git_history,
    verify_findings, verify_one, VerificationStatus,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Deserialize)]
struct RpcRequest {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

/// MCP server configuration.
#[derive(Clone)]
pub struct McpConfig {
    /// Plugin directories to load WASM detectors from.
    pub plugin_dirs: Vec<PathBuf>,
    /// Optional authentication token. If set, all requests must include
    /// it in the `params.auth` or `params._meta.auth` field (goal 327).
    pub auth_token: Option<String>,
    /// Transport mode: stdio (default) or TCP (remote mode, goal 328).
    pub transport: McpTransport,
}

/// MCP transport mode.
#[derive(Clone)]
pub enum McpTransport {
    /// Read from stdin, write to stdout (default).
    Stdio,
    /// Listen on a TCP port for remote connections (goal 328).
    Tcp {
        /// Address to bind, e.g. "127.0.0.1:9470".
        addr: String,
    },
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            plugin_dirs: Vec::new(),
            auth_token: None,
            transport: McpTransport::Stdio,
        }
    }
}

/// Runs the MCP server with the given configuration.
pub fn run(config: &McpConfig) {
    match &config.transport {
        McpTransport::Stdio => run_stdio(config),
        McpTransport::Tcp { addr } => run_tcp(config, addr),
    }
}

/// Runs the MCP server over stdio.
fn run_stdio(config: &McpConfig) {
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

        if !check_auth(&request, config) {
            respond_error(request.id.clone(), -32001, "authentication required");
            continue;
        }

        let is_notification = request.id.is_none();
        handle_request(&request, is_notification, config);
    }
}

/// Handles a single JSON-RPC request (shared between stdio and TCP).
fn handle_request(request: &RpcRequest, is_notification: bool, config: &McpConfig) {
    match request.method.as_str() {
        "initialize" => {
            if !is_notification {
                respond(
                    request.id.clone(),
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
                respond(request.id.clone(), json!({}));
            }
        }
        "tools/list" => {
            if !is_notification {
                respond(request.id.clone(), json!({ "tools": tool_defs() }));
            }
        }
        "tools/call" => {
            if !is_notification {
                let result = handle_tools_call(&request.params, config);
                respond(request.id.clone(), result);
            }
        }
        other => {
            if !is_notification {
                respond_error(request.id.clone(), -32601, &format!("method not found: {other}"));
            }
        }
    }
}

/// Checks if the request is authenticated (goal 327).
fn check_auth(request: &RpcRequest, config: &McpConfig) -> bool {
    if config.auth_token.is_none() {
        return true;
    }
    let token = request
        .params
        .get("_meta")
        .and_then(|m| m.get("auth"))
        .and_then(|a| a.as_str())
        .or_else(|| request.params.get("auth").and_then(|a| a.as_str()));
    token == config.auth_token.as_deref()
}

fn tool_defs() -> Value {
    let common_props = json!({
        "path": { "type": "string", "description": "File or directory path to scan." },
        "min_severity": { "type": "string", "enum": ["low", "medium", "high", "critical"], "default": "low" },
        "show_all": { "type": "boolean", "description": "Include findings flagged as likely false positives.", "default": false },
        "verify": { "type": "boolean", "description": "Call provider APIs to check whether matched secrets are still active.", "default": false }
    });

    json!([
        {
            "name": "scan_path",
            "description": "Scan a file or directory in the working tree for hardcoded secrets.",
            "inputSchema": {
                "type": "object",
                "properties": common_props,
                "required": ["path"]
            }
        },
        {
            "name": "scan_git_history",
            "description": "Scan a git repository's commit history for secrets introduced in past commits.",
            "inputSchema": {
                "type": "object",
                "properties": common_props,
                "required": ["path"]
            }
        },
        {
            "name": "scan_source",
            "description": "Scan a remote source (Confluence, Slack, Jira, S3, GCS, Azure Blob, Postman) for secrets via API.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_type": { "type": "string", "description": "Source type: confluence, slack, jira, s3, gcs, azure_blob, postman" },
                    "token": { "type": "string", "description": "API token or credential for the source." },
                    "target": { "type": "string", "description": "Additional target info (bucket name, base URL, etc.)." },
                    "min_severity": { "type": "string", "enum": ["low", "medium", "high", "critical"], "default": "low" },
                    "verify": { "type": "boolean", "default": false }
                },
                "required": ["source_type", "token"]
            }
        },
        {
            "name": "verify_secret",
            "description": "Verify a single secret against its provider API to check if it is active, inactive, or unknown.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_id": { "type": "string", "description": "The detector rule ID (e.g. 'github-pat')." },
                    "secret": { "type": "string", "description": "The secret value to verify." }
                },
                "required": ["rule_id", "secret"]
            }
        },
        {
            "name": "list_detectors",
            "description": "List all built-in detector rules with their IDs, descriptions, and severities.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }
    ])
}

fn handle_tools_call(params: &Value, config: &McpConfig) -> Value {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    send_progress(name, "started");

    let outcome = match name {
        "scan_path" => run_scan(&args, config),
        "scan_git_history" => run_history(&args, config),
        "scan_source" => run_scan_source(&args),
        "verify_secret" => run_verify_secret(&args),
        "list_detectors" => run_list_detectors(),
        other => Err(format!("unknown tool: {other}")),
    };

    send_progress(name, if outcome.is_ok() { "completed" } else { "failed" });

    match outcome {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
        Err(err) => json!({ "content": [{ "type": "text", "text": err }], "isError": true }),
    }
}

fn run_scan(args: &Value, config: &McpConfig) -> Result<String, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: path")?;

    let detectors = load_detectors(args, &config.plugin_dirs);
    let scanner = Scanner::new(detectors);
    let findings = scanner
        .scan_path(path)
        .map_err(|e| format!("scan failed: {e}"))?;

    finalize(findings, args)
}

fn run_history(args: &Value, config: &McpConfig) -> Result<String, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: path")?;

    let detectors = load_detectors(args, &config.plugin_dirs);
    let findings = scan_git_history(std::path::Path::new(path), &detectors)
        .map_err(|e| format!("git history scan failed: {e}"))?;

    finalize(findings, args)
}

fn run_scan_source(args: &Value) -> Result<String, String> {
    let source_type = args
        .get("source_type")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: source_type")?;
    let token = args
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: token")?;
    let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");

    let detectors = builtin_detectors();
    let findings = match source_type {
        "confluence" => {
            let cfg = pledgeguard_core::ConfluenceScanConfig {
                base_url: target.to_string(),
                api_token: token.to_string(),
                email: String::new(),
                space_key: None,
                max_pages: 500,
            };
            pledgeguard_core::scan_confluence(&cfg, &detectors).unwrap_or_default()
        }
        "slack" => {
            let cfg = pledgeguard_core::SlackScanConfig {
                token: token.to_string(),
                channel_ids: target.split(',').map(String::from).collect(),
                max_messages: 1000,
            };
            pledgeguard_core::scan_slack(&cfg, &detectors).unwrap_or_default()
        }
        "jira" => {
            let cfg = pledgeguard_core::JiraScanConfig {
                base_url: target.to_string(),
                api_token: token.to_string(),
                email: String::new(),
                jql: None,
                max_issues: 500,
            };
            pledgeguard_core::scan_jira(&cfg, &detectors).unwrap_or_default()
        }
        "s3" => {
            let cfg = pledgeguard_core::S3ScanConfig {
                bucket: target.to_string(),
                region: "us-east-1".to_string(),
                access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                secret_access_key: token.to_string(),
                prefix: None,
                max_objects: 1000,
            };
            pledgeguard_core::scan_s3_bucket(&cfg, &detectors).unwrap_or_default()
        }
        "gcs" => {
            let cfg = pledgeguard_core::GcsScanConfig {
                bucket: target.to_string(),
                oauth_token: token.to_string(),
                prefix: None,
                max_objects: 1000,
            };
            pledgeguard_core::scan_gcs_bucket(&cfg, &detectors).unwrap_or_default()
        }
        "azure_blob" => {
            let parts: Vec<&str> = target.splitn(2, '/').collect();
            let cfg = pledgeguard_core::AzureBlobScanConfig {
                account: parts.first().unwrap_or(&"").to_string(),
                container: parts.get(1).unwrap_or(&"").to_string(),
                sas_token: token.to_string(),
                prefix: None,
                max_blobs: 500,
            };
            pledgeguard_core::scan_azure_blob(&cfg, &detectors).unwrap_or_default()
        }
        "postman" => {
            let cfg = pledgeguard_core::PostmanScanConfig {
                api_key: token.to_string(),
                collection_id: Some(target.to_string()),
                max_collections: 100,
            };
            pledgeguard_core::scan_postman(&cfg, &detectors).unwrap_or_default()
        }
        _ => return Err(format!("unsupported source type: {source_type}")),
    };

    finalize(findings, args)
}

fn run_verify_secret(args: &Value) -> Result<String, String> {
    let rule_id = args
        .get("rule_id")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: rule_id")?;
    let secret = args
        .get("secret")
        .and_then(|v| v.as_str())
        .ok_or("missing required argument: secret")?;

    match verify_one(rule_id, secret) {
        Some(status) => {
            let result = json!({
                "rule_id": rule_id,
                "verification": status.to_string(),
                "verified": matches!(status, VerificationStatus::Active),
            });
            serde_json::to_string_pretty(&result)
                .map_err(|e| format!("serialization error: {e}"))
        }
        None => {
            let result = json!({
                "rule_id": rule_id,
                "verification": "unsupported",
                "verified": false,
                "message": "No verifier available for this rule ID."
            });
            serde_json::to_string_pretty(&result)
                .map_err(|e| format!("serialization error: {e}"))
        }
    }
}

fn run_list_detectors() -> Result<String, String> {
    let detectors = builtin_detectors();
    let list: Vec<Value> = detectors
        .iter()
        .map(|d| {
            json!({
                "id": d.id(),
                "description": d.description(),
                "severity": d.severity().to_string(),
            })
        })
        .collect();
    let result = json!({ "detectors": list, "count": list.len() });
    serde_json::to_string_pretty(&result)
        .map_err(|e| format!("serialization error: {e}"))
}

fn load_detectors(args: &Value, plugin_dirs: &[PathBuf]) -> Vec<Box<dyn Detector>> {
    let mut detectors = builtin_detectors();
    for dir in plugin_dirs {
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
    let verify = args
        .get("verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

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
    serde_json::to_string_pretty(&redacted)
        .map_err(|e| format!("failed to serialize findings: {e}"))
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Sends a progress notification (goal 326). Notifications are JSON-RPC
/// messages without an `id` field, so clients know not to reply.
fn send_progress(tool_name: &str, status: &str) {
    write_message(json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "tool": tool_name,
            "status": status,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
    }));
}

/// Runs the MCP server over TCP (goal 328).
fn run_tcp(config: &McpConfig, addr: &str) {
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("pledgeguard mcp: failed to bind {addr}: {e}");
            return;
        }
    };
    eprintln!("pledgeguard mcp: listening on {addr}");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("pledgeguard mcp: connection error: {e}");
                continue;
            }
        };
        let config = config.clone();
        std::thread::spawn(move || {
            handle_tcp_client(stream, &config);
        });
    }
}

/// Handles a single TCP client connection.
fn handle_tcp_client(stream: std::net::TcpStream, config: &McpConfig) {
    let reader = io::BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;

    for line in reader.lines() {
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
                let msg = json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": format!("parse error: {e}") } });
                let _ = writeln!(writer, "{msg}");
                continue;
            }
        };

        if !check_auth(&request, config) {
            let msg = json!({ "jsonrpc": "2.0", "id": request.id, "error": { "code": -32001, "message": "authentication required" } });
            let _ = writeln!(writer, "{msg}");
            continue;
        }

        let is_notification = request.id.is_none();
        let id = request.id.clone();
        let method = request.method.clone();
        let params = request.params.clone();

        match method.as_str() {
            "initialize" => {
                if !is_notification {
                    let msg = json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": { "name": "pledgeguard", "version": env!("CARGO_PKG_VERSION") },
                        "capabilities": { "tools": {} }
                    }});
                    let _ = writeln!(writer, "{msg}");
                }
            }
            "notifications/initialized" | "ping" => {
                if !is_notification {
                    let _ = writeln!(writer, "{}", json!({ "jsonrpc": "2.0", "id": id, "result": {} }));
                }
            }
            "tools/list" => {
                if !is_notification {
                    let _ = writeln!(writer, "{}", json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": tool_defs() } }));
                }
            }
            "tools/call" => {
                if !is_notification {
                    let result = handle_tools_call(&params, config);
                    let _ = writeln!(writer, "{}", json!({ "jsonrpc": "2.0", "id": id, "result": result }));
                }
            }
            other => {
                if !is_notification {
                    let _ = writeln!(writer, "{}", json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {other}") } }));
                }
            }
        }
    }
}

fn respond(id: Option<Value>, result: Value) {
    write_message(json!({ "jsonrpc": "2.0", "id": id, "result": result }));
}

fn respond_error(id: Option<Value>, code: i64, message: &str) {
    write_message(
        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    );
}

fn write_message(message: Value) {
    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "{message}");
    let _ = stdout.flush();
}
