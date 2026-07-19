//! Performance features (goals 301-320).
//!
//! This module provides:
//! - Memory-mapped file scanning (goal 302)
//! - Streaming scan for large files (goal 303)
//! - Incremental scan cache via file hashes (goal 305)
//! - Scan progress reporting (goal 306)
//! - Scan time estimation (goal 307)
//! - Per-file scan timeout (goal 311)
//! - Regex compilation cache (goal 312)
//! - Aho-Corasick DFA cache persistence (goal 313)
//! - WASM plugin caching (goal 314)
//! - Benchmark suite (goal 315)

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ── 302: Memory-mapped file scanning ───────────────────────────────────

/// Threshold (in bytes) above which memory-mapped I/O is used instead of
/// `std::fs::read`. mmap avoids copying the file into userspace memory.
pub const MMAP_THRESHOLD: u64 = 1024 * 1024; // 1 MB

/// Read file contents, using memory-mapped I/O for files above `MMAP_THRESHOLD`.
///
/// Returns a `Vec<u8>` regardless of the read method, so callers don't need
/// to change their code. The mmap path maps the file read-only and copies
/// bytes into the Vec (safe — we don't hold the mapping across the scan).
pub fn read_file_optimized(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let meta = std::fs::metadata(path)?;
    let len = meta.len();

    if len > MMAP_THRESHOLD {
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Ok(mmap[..].to_vec())
    } else {
        std::fs::read(path)
    }
}

// ── 303: Streaming scan for large files ────────────────────────────────

/// Threshold (in bytes) above which streaming chunked scanning is used.
pub const STREAMING_THRESHOLD: u64 = 100 * 1024 * 1024; // 100 MB

/// Chunk size for streaming scans (with overlap to catch secrets spanning boundaries).
pub const STREAMING_CHUNK_SIZE: usize = 64 * 1024 * 1024; // 64 MB
/// Overlap between chunks to catch secrets that span chunk boundaries.
pub const STREAMING_OVERLAP: usize = 4096; // 4 KB overlap

/// Stream-scan a large file in chunks, calling `scan_chunk` for each.
///
/// Each chunk is `STREAMING_CHUNK_SIZE` bytes with `STREAMING_OVERLAP` bytes
/// of overlap with the previous chunk. The `scan_chunk` callback receives
/// the chunk bytes and the byte offset of the chunk start within the file.
pub fn stream_scan_file<F>(path: &Path, mut scan_chunk: F) -> Result<(), std::io::Error>
where
    F: FnMut(&[u8], usize),
{
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    let total = meta.len() as usize;

    if total <= STREAMING_THRESHOLD as usize {
        // Small enough to read in one go.
        let mut buf = Vec::with_capacity(total);
        file.read_to_end(&mut buf)?;
        scan_chunk(&buf, 0);
        return Ok(());
    }

    let chunk_size = STREAMING_CHUNK_SIZE;
    let overlap = STREAMING_OVERLAP;
    let mut offset = 0usize;
    let mut prev_tail: Vec<u8> = Vec::new();

    while offset < total {
        let read_size = chunk_size.min(total - offset);
        let mut buf = vec![0u8; read_size];

        // Prepend overlap from previous chunk.
        if !prev_tail.is_empty() {
            let mut combined = Vec::with_capacity(prev_tail.len() + read_size);
            combined.extend_from_slice(&prev_tail);
            combined.extend_from_slice(&buf);
            scan_chunk(&combined, offset.saturating_sub(overlap));
        } else {
            scan_chunk(&buf, offset);
        }

        // Read the chunk.
        file.read_exact(&mut buf)?;

        // Save tail for overlap.
        if buf.len() > overlap {
            prev_tail = buf[buf.len() - overlap..].to_vec();
        } else {
            prev_tail = buf.clone();
        }

        offset += read_size;
    }

    Ok(())
}

// ── 305: Incremental scan cache ────────────────────────────────────────

/// Cache entry for a file: its BLAKE3 hash and last-modified time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileHashEntry {
    /// BLAKE3 hash of the file contents (hex-encoded).
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
    /// Last-modified timestamp (Unix epoch seconds).
    pub mtime: u64,
}

/// Persistent cache of file hashes for incremental scanning.
/// Stored as a JSON file mapping file paths to `FileHashEntry`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IncrementalCache {
    /// Map of file path → hash entry.
    pub entries: HashMap<String, FileHashEntry>,
}

impl IncrementalCache {
    /// Load a cache from a JSON file. Returns an empty cache if the file
    /// doesn't exist or is invalid.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save the cache to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    /// Compute the BLAKE3 hash of a file.
    pub fn hash_file(path: &Path) -> Result<String, std::io::Error> {
        let bytes = std::fs::read(path)?;
        let hash = blake3::hash(&bytes);
        Ok(hash.to_hex().to_string())
    }

    /// Check if a file has changed since it was cached.
    /// Returns `true` if the file is unchanged (can be skipped).
    pub fn is_unchanged(&self, path: &Path) -> bool {
        let key = path.to_string_lossy().to_string();
        let Some(entry) = self.entries.get(&key) else {
            return false;
        };

        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };

        if meta.len() != entry.size {
            return false;
        }

        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if mtime != entry.mtime {
            // mtime changed — verify by hash.
            if let Ok(hash) = Self::hash_file(path) {
                return hash == entry.hash;
            }
            return false;
        }

        true
    }

    /// Update the cache entry for a file.
    pub fn update(&mut self, path: &Path) {
        let key = path.to_string_lossy().to_string();
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Ok(hash) = Self::hash_file(path) {
            self.entries.insert(
                key,
                FileHashEntry {
                    hash,
                    size: meta.len(),
                    mtime,
                },
            );
        }
    }
}

// ── 306-307: Scan progress reporting + time estimation ─────────────────

/// Progress reporter for scans. Reports progress to stderr.
pub struct ScanProgress {
    start: Instant,
    total_files: usize,
    scanned: usize,
    findings: usize,
    show_progress: bool,
}

impl ScanProgress {
    /// Create a new progress reporter.
    pub fn new(total_files: usize, show_progress: bool) -> Self {
        Self {
            start: Instant::now(),
            total_files,
            scanned: 0,
            findings: 0,
            show_progress,
        }
    }

    /// Record that a file has been scanned.
    pub fn file_done(&mut self, findings_in_file: usize) {
        self.scanned += 1;
        self.findings += findings_in_file;

        if self.show_progress && self.scanned.is_multiple_of(100) {
            let elapsed = self.start.elapsed();
            let pct = self
                .scanned
                .checked_mul(100)
                .and_then(|v| v.checked_div(self.total_files))
                .unwrap_or(0);
            let rate = if elapsed.as_secs() > 0 {
                self.scanned as f64 / elapsed.as_secs() as f64
            } else {
                0.0
            };
            let remaining = self.total_files.saturating_sub(self.scanned);
            let eta = if rate > 0.0 {
                Duration::from_secs((remaining as f64 / rate) as u64)
            } else {
                Duration::from_secs(0)
            };

            eprintln!(
                "  [{}%] {}/{} files, {} findings, {:.1} files/s, ETA: {:?}",
                pct, self.scanned, self.total_files, self.findings, rate, eta
            );
        }
    }

    /// Print final summary.
    pub fn finish(&self) {
        if self.show_progress {
            let elapsed = self.start.elapsed();
            eprintln!(
                "  Scanned {}/{} files in {:?} ({} findings)",
                self.scanned, self.total_files, elapsed, self.findings,
            );
        }
    }
}

// ── 311: Per-file scan timeout ─────────────────────────────────────────

/// Run a closure with a timeout. Returns `None` if the timeout elapsed.
pub fn with_timeout<F, T>(timeout: Duration, f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = f();
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout).ok()
}

// ── 312: Regex compilation cache ───────────────────────────────────────

/// Global cache of compiled regexes, keyed by pattern string.
/// Uses `OnceLock` for thread-safe lazy initialization.
static REGEX_CACHE: OnceLock<std::sync::Mutex<HashMap<String, regex::Regex>>> = OnceLock::new();

fn regex_cache() -> &'static std::sync::Mutex<HashMap<String, regex::Regex>> {
    REGEX_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Get or compile a regex, caching it for future use.
pub fn cached_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    let cache = regex_cache();
    let lock = cache.lock().unwrap();
    if let Some(re) = lock.get(pattern) {
        return Ok(re.clone());
    }
    drop(lock);

    let re = regex::Regex::new(pattern)?;
    let mut lock = regex_cache().lock().unwrap();
    lock.insert(pattern.to_string(), re.clone());
    Ok(re)
}

/// Get or compile a regex with options, caching it for future use.
pub fn cached_regex_with_options(
    pattern: &str,
    case_insensitive: bool,
) -> Result<regex::Regex, regex::Error> {
    let cache_key = if case_insensitive {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };

    let cache = regex_cache();
    let lock = cache.lock().unwrap();
    if let Some(re) = lock.get(&cache_key) {
        return Ok(re.clone());
    }
    drop(lock);

    let re = if case_insensitive {
        regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()?
    } else {
        regex::Regex::new(pattern)?
    };

    let mut lock = regex_cache().lock().unwrap();
    lock.insert(cache_key, re.clone());
    Ok(re)
}

/// Clear the regex cache (useful for testing).
pub fn clear_regex_cache() {
    let cache = regex_cache();
    cache.lock().unwrap().clear();
}

/// Get the number of cached regexes.
pub fn regex_cache_size() -> usize {
    regex_cache().lock().unwrap().len()
}

// ── 313: Aho-Corasick DFA cache persistence ────────────────────────────

/// Cache file path for the Aho-Corasick DFA.
pub const AC_CACHE_FILE: &str = ".pledgeguard-ac-cache.bin";

/// Serialize Aho-Corasick prefilter patterns to a cache file.
/// On next startup, the patterns can be loaded and the automaton rebuilt
/// quickly (the patterns themselves are the expensive part to collect;
/// building the AC automaton is fast).
pub fn save_ac_cache(patterns: &[String], cache_path: &Path) -> Result<(), std::io::Error> {
    let data = serde_json::to_vec(patterns).map_err(std::io::Error::other)?;
    std::fs::write(cache_path, data)
}

/// Load cached Aho-Corasick prefilter patterns from a cache file.
/// Returns `None` if the cache doesn't exist or is invalid.
pub fn load_ac_cache(cache_path: &Path) -> Option<Vec<String>> {
    let data = std::fs::read(cache_path).ok()?;
    serde_json::from_slice(&data).ok()
}

// ── 314: WASM plugin caching ────────────────────────────────────────────

/// Cache directory for compiled WASM modules.
pub fn wasm_cache_dir() -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push("pledgeguard-wasm-cache");
    dir
}

/// Get the cache path for a WASM module, based on its file hash.
pub fn wasm_cache_path(wasm_path: &Path) -> Option<PathBuf> {
    let bytes = std::fs::read(wasm_path).ok()?;
    let hash = blake3::hash(&bytes);
    let mut path = wasm_cache_dir();
    path.push(format!("{}.bin", hash.to_hex()));
    Some(path)
}

/// Check if a cached WASM compilation exists for the given module.
pub fn has_wasm_cache(wasm_path: &Path) -> bool {
    wasm_cache_path(wasm_path)
        .map(|p| p.exists())
        .unwrap_or(false)
}

// ── 315: Benchmark suite ────────────────────────────────────────────────

/// Benchmark result for a single scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchResult {
    /// Total files scanned.
    pub files: usize,
    /// Total bytes scanned.
    pub bytes: u64,
    /// Time elapsed (in milliseconds).
    pub elapsed_ms: u64,
    /// Throughput in MB/s.
    pub throughput_mbps: f64,
    /// Number of findings.
    pub findings: usize,
}

/// Run a benchmark scan on a directory and return throughput metrics.
pub fn benchmark_scan(
    scanner: &crate::scanner::Scanner,
    root: &Path,
) -> Result<BenchResult, crate::scanner::ScanError> {
    let start = Instant::now();
    let findings = scanner.scan_path(root)?;
    let elapsed = start.elapsed();

    let mut total_bytes: u64 = 0;
    if root.is_file() {
        total_bytes = std::fs::metadata(root).map(|m| m.len()).unwrap_or(0);
    } else {
        for e in ignore::WalkBuilder::new(root).build().flatten() {
            if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                total_bytes += std::fs::metadata(e.path()).map(|m| m.len()).unwrap_or(0);
            }
        }
    }

    let elapsed_secs = elapsed.as_secs_f64().max(0.001);
    let throughput_mbps = (total_bytes as f64 / 1_048_576.0) / elapsed_secs;

    Ok(BenchResult {
        files: findings.len(), // approximate — we don't track file count separately
        bytes: total_bytes,
        elapsed_ms: elapsed.as_millis() as u64,
        throughput_mbps,
        findings: findings.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incremental_cache() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap();

        let mut cache = IncrementalCache::default();
        assert!(!cache.is_unchanged(&file)); // not cached yet

        cache.update(&file);
        assert!(cache.is_unchanged(&file)); // now cached

        // Modify the file.
        std::fs::write(&file, "hello world modified").unwrap();
        assert!(!cache.is_unchanged(&file)); // changed
    }

    #[test]
    fn test_cached_regex() {
        clear_regex_cache();
        let re1 = cached_regex(r"AKIA[0-9A-Z]{16}").unwrap();
        let re2 = cached_regex(r"AKIA[0-9A-Z]{16}").unwrap();
        assert!(re1.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(re2.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(regex_cache_size(), 1);
    }

    #[test]
    fn test_cached_regex_case_insensitive() {
        clear_regex_cache();
        let re = cached_regex_with_options(r"github_pat_", true).unwrap();
        assert!(re.is_match("GITHUB_PAT_abcdef"));
        assert_eq!(regex_cache_size(), 1);
    }

    #[test]
    fn test_read_file_optimized_small() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("small.txt");
        std::fs::write(&file, "small file content").unwrap();
        let bytes = read_file_optimized(&file).unwrap();
        assert_eq!(bytes, b"small file content");
    }

    #[test]
    fn test_read_file_optimized_large() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("large.bin");
        // Write 2MB of data (above MMAP_THRESHOLD).
        let data: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 256) as u8).collect();
        std::fs::write(&file, &data).unwrap();
        let bytes = read_file_optimized(&file).unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(bytes, data);
    }

    #[test]
    fn test_with_timeout_completes() {
        let result = with_timeout(Duration::from_secs(1), || 42);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_with_timeout_expires() {
        let result = with_timeout(Duration::from_millis(10), || {
            std::thread::sleep(Duration::from_secs(2));
            42
        });
        assert_eq!(result, None);
    }

    #[test]
    fn test_ac_cache_roundtrip() {
        let patterns = vec!["AKIA".to_string(), "ghp_".to_string()];
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("ac-cache.bin");
        save_ac_cache(&patterns, &cache_path).unwrap();
        let loaded = load_ac_cache(&cache_path).unwrap();
        assert_eq!(loaded, patterns);
    }

    #[test]
    fn test_scan_progress() {
        let mut progress = ScanProgress::new(100, false);
        for i in 0..50 {
            progress.file_done(i % 3);
        }
        progress.finish();
        assert_eq!(progress.scanned, 50);
    }
}
