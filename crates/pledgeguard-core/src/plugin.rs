//! WASM plugin support: load custom [`Detector`] implementations compiled to
//! WebAssembly, without recompiling PledgeGuard.
//!
//! # Plugin ABI
//!
//! A plugin is a `.wasm` module that exports:
//!
//! - `memory` — an exported linear memory the host reads/writes.
//! - `pg_alloc(len: i32) -> i32` — allocate `len` bytes inside the module's
//!   memory and return the pointer; the host writes the input line there.
//! - `pg_metadata() -> i64` — returns a packed `(ptr << 32) | len` pointing
//!   at a UTF-8 JSON object: `{"id": "...", "description": "...", "severity": "low|medium|high|critical"}`.
//! - `pg_scan_line(ptr: i32, len: i32) -> i64` — scans the UTF-8 line
//!   written at `ptr`/`len` and returns a packed `(ptr << 32) | len`
//!   pointing at a UTF-8 JSON array of matches:
//!   `[{"start": 0, "end": 10, "text": "..."}]`. Byte offsets are relative
//!   to the input line.
//!
//! The host does not free memory returned by the plugin; a plugin should
//! reuse/overwrite its own scratch buffer on each call. A single plugin
//! instance is called from at most one thread at a time (serialized behind
//! a mutex), so a plugin does not need to be reentrant.

use crate::detector::{Detector, DetectorMatch};
use crate::finding::Severity;
use serde::Deserialize;
use std::path::Path;
use std::sync::Mutex;
use wasmtime::{Engine, Instance, Memory, Module, Store, TypedFunc};

#[derive(Deserialize)]
struct PluginMetadata {
    id: String,
    description: String,
    severity: String,
}

#[derive(Deserialize)]
struct RawMatch {
    start: usize,
    end: usize,
    text: String,
}

/// Errors that can occur while loading or running a WASM plugin.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("wasm error: {0}")]
    Wasm(#[from] wasmtime::Error),
    #[error("plugin metadata invalid: {0}")]
    Metadata(#[from] serde_json::Error),
    #[error("plugin missing required export: {0}")]
    MissingExport(&'static str),
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn unpack(v: i64) -> (i32, i32) {
    ((v >> 32) as i32, (v & 0xFFFF_FFFF) as i32)
}

struct PluginState {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    scan_line: TypedFunc<(i32, i32), i64>,
}

impl PluginState {
    fn read_memory(&self, ptr: i32, len: i32) -> Vec<u8> {
        if len <= 0 || ptr < 0 {
            return Vec::new();
        }
        let data = self.memory.data(&self.store);
        let start = ptr as usize;
        let end = start.saturating_add(len as usize);
        data.get(start..end).unwrap_or(&[]).to_vec()
    }
}

/// A [`Detector`] backed by a loaded WASM module.
pub struct WasmDetector {
    id: String,
    description: String,
    severity: Severity,
    state: Mutex<PluginState>,
}

impl WasmDetector {
    /// Loads a single `.wasm` plugin module from disk.
    pub fn load(path: &Path) -> Result<Self, PluginError> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path)?;
        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module, &[])?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(PluginError::MissingExport("memory"))?;
        let alloc: TypedFunc<i32, i32> = instance
            .get_typed_func(&mut store, "pg_alloc")
            .map_err(|_| PluginError::MissingExport("pg_alloc"))?;
        let metadata_fn: TypedFunc<(), i64> = instance
            .get_typed_func(&mut store, "pg_metadata")
            .map_err(|_| PluginError::MissingExport("pg_metadata"))?;
        let scan_line: TypedFunc<(i32, i32), i64> = instance
            .get_typed_func(&mut store, "pg_scan_line")
            .map_err(|_| PluginError::MissingExport("pg_scan_line"))?;

        let packed = metadata_fn.call(&mut store, ())?;
        let (ptr, len) = unpack(packed);
        let raw = {
            let data = memory.data(&store);
            let start = ptr.max(0) as usize;
            let end = start.saturating_add(len.max(0) as usize);
            data.get(start..end).unwrap_or(&[]).to_vec()
        };
        let meta: PluginMetadata = serde_json::from_slice(&raw)?;

        Ok(Self {
            id: meta.id,
            description: meta.description,
            severity: parse_severity(&meta.severity),
            state: Mutex::new(PluginState {
                store,
                memory,
                alloc,
                scan_line,
            }),
        })
    }
}

impl Detector for WasmDetector {
    fn id(&self) -> &str {
        &self.id
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn scan_line(&self, line: &str) -> Vec<DetectorMatch> {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let bytes = line.as_bytes();
        let alloc = state.alloc.clone();
        let scan_line = state.scan_line.clone();
        let memory = state.memory;

        let ptr = match alloc.call(&mut state.store, bytes.len() as i32) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        {
            let mem = memory.data_mut(&mut state.store);
            let start = ptr as usize;
            let end = start + bytes.len();
            if end > mem.len() {
                return Vec::new();
            }
            mem[start..end].copy_from_slice(bytes);
        }

        let packed = match scan_line.call(&mut state.store, (ptr, bytes.len() as i32)) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        let (out_ptr, out_len) = unpack(packed);
        if out_len == 0 {
            return Vec::new();
        }
        let raw = state.read_memory(out_ptr, out_len);
        let matches: Vec<RawMatch> = match serde_json::from_slice(&raw) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };

        matches
            .into_iter()
            .map(|m| DetectorMatch {
                start: m.start,
                end: m.end,
                text: m.text,
            })
            .collect()
    }
}

/// Loads every `.wasm` file directly inside `dir` as a plugin detector.
/// Plugins that fail to load are skipped (with a warning printed to
/// stderr) rather than aborting the whole scan.
pub fn load_plugins(dir: &Path) -> Vec<Box<dyn Detector>> {
    let mut detectors = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!("warning: plugin directory not found: {}", dir.display());
        return detectors;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
            continue;
        }
        match WasmDetector::load(&path) {
            Ok(d) => detectors.push(Box::new(d) as Box<dyn Detector>),
            Err(e) => eprintln!("warning: failed to load plugin {}: {}", path.display(), e),
        }
    }
    detectors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_plugins_missing_dir_returns_empty() {
        let detectors = load_plugins(Path::new("/definitely/does/not/exist"));
        assert!(detectors.is_empty());
    }

    #[test]
    fn test_load_plugins_ignores_non_wasm_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a plugin").unwrap();
        let detectors = load_plugins(dir.path());
        assert!(detectors.is_empty());
    }

    #[test]
    fn test_load_plugins_skips_invalid_wasm_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.wasm"), b"not a real wasm module").unwrap();
        let detectors = load_plugins(dir.path());
        assert!(detectors.is_empty());
    }
}
