//! Minimal example PledgeGuard WASM plugin, used to validate the plugin ABI.
//! Flags any line containing the literal substring `PLUGIN_SECRET`.

use std::sync::Mutex;

static SCRATCH: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn pack(ptr: i32, len: i32) -> i64 {
    ((ptr as i64) << 32) | (len as i64 & 0xFFFF_FFFF)
}

#[no_mangle]
pub extern "C" fn pg_alloc(len: i32) -> i32 {
    let mut buf = SCRATCH.lock().unwrap();
    buf.clear();
    buf.resize(len as usize, 0);
    buf.as_mut_ptr() as i32
}

#[no_mangle]
pub extern "C" fn pg_metadata() -> i64 {
    let mut out = OUT.lock().unwrap();
    *out = br#"{"id":"example-plugin","description":"Example WASM plugin (PLUGIN_SECRET)","severity":"high"}"#.to_vec();
    pack(out.as_ptr() as i32, out.len() as i32)
}

#[no_mangle]
pub extern "C" fn pg_scan_line(ptr: i32, len: i32) -> i64 {
    let line = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    };
    let line = String::from_utf8_lossy(line);

    let mut out = OUT.lock().unwrap();
    out.clear();
    if let Some(pos) = line.find("PLUGIN_SECRET") {
        let end = pos + "PLUGIN_SECRET".len();
        out.extend_from_slice(
            format!(r#"[{{"start":{pos},"end":{end},"text":"PLUGIN_SECRET"}}]"#).as_bytes(),
        );
    } else {
        out.extend_from_slice(b"[]");
    }
    pack(out.as_ptr() as i32, out.len() as i32)
}
