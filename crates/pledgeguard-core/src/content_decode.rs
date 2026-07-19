//! HTML & content decoding (goals 381-400).
//!
//! This module provides decoders and parsers for various content formats:
//! - HTML entity decoder, tag stripper
//! - URL decoder, Unicode normalization
//! - JSON string unescaper
//! - YAML multi-document parser
//! - XML parser
//! - CSV, INI, .env, Dockerfile, HCL parsers
//! - Markdown code block extractor
//! - Jupyter notebook cell scanner
//! - PDF, Word, Excel, PowerPoint text extractors
//! - Image OCR scanning
//! - Binary string extraction

use crate::detector::Detector;
use crate::finding::Finding;
use smallvec::SmallVec;
use std::path::Path;

// ── 381: HTML entity decoder ───────────────────────────────────────────

/// Decode HTML entities like &lt; &gt; &amp; &#x27; &#39; &quot; etc.
pub fn decode_html_entities(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            let mut found = false;

            // Try to read an entity.
            while let Some(&next) = chars.peek() {
                if next == ';' {
                    chars.next();
                    found = true;
                    break;
                }
                entity.push(next);
                chars.next();
                if entity.len() > 10 {
                    break;
                }
            }

            if found {
                if let Some(decoded) = decode_single_entity(&entity) {
                    result.push_str(&decoded);
                } else {
                    result.push('&');
                    result.push_str(&entity);
                    result.push(';');
                }
            } else {
                result.push('&');
                result.push_str(&entity);
            }
        } else {
            result.push(c);
        }
    }

    result
}

fn decode_single_entity(entity: &str) -> Option<String> {
    match entity {
        "lt" => Some("<".to_string()),
        "gt" => Some(">".to_string()),
        "amp" => Some("&".to_string()),
        "quot" => Some("\"".to_string()),
        "apos" => Some("'".to_string()),
        "nbsp" => Some("\u{00A0}".to_string()),
        "copy" => Some("\u{00A9}".to_string()),
        "reg" => Some("\u{00AE}".to_string()),
        "trade" => Some("\u{2122}".to_string()),
        "hellip" => Some("\u{2026}".to_string()),
        "mdash" => Some("\u{2014}".to_string()),
        "ndash" => Some("\u{2013}".to_string()),
        "ldquo" => Some("\u{201C}".to_string()),
        "rdquo" => Some("\u{201D}".to_string()),
        "lsquo" => Some("\u{2018}".to_string()),
        "rsquo" => Some("\u{2019}".to_string()),
        _ => {
            // Numeric entity: #x27 (hex) or #39 (decimal)
            if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                let code = u32::from_str_radix(hex, 16).ok()?;
                char::from_u32(code).map(|c| c.to_string())
            } else if let Some(decimal) = entity.strip_prefix('#') {
                let code: u32 = decimal.parse().ok()?;
                char::from_u32(code).map(|c| c.to_string())
            } else {
                None
            }
        }
    }
}

// ── 382: HTML tag stripper ──────────────────────────────────────────────

/// Strip HTML tags from content, leaving only text.
pub fn strip_html_tags(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut in_tag = false;
    let mut in_script = false;

    let lower = input.to_lowercase();
    let mut i = 0;
    let chars: Vec<char> = input.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    while i < chars.len() {
        if !in_tag && !in_script {
            // Check for <script or <style
            if chars[i] == '<' {
                let rest: String = lower_chars[i..].iter().take(8).collect();
                if rest.starts_with("<script") {
                    in_script = true;
                    in_tag = true;
                    i += 1;
                    continue;
                }
                let rest: String = lower_chars[i..].iter().take(7).collect();
                if rest.starts_with("<style") {
                    in_script = true;
                    in_tag = true;
                    i += 1;
                    continue;
                }
            }
        }

        if chars[i] == '<' && !in_script {
            in_tag = true;
        } else if chars[i] == '<' && in_script {
            // Check for </script> or </style>
            let rest: String = lower_chars[i..].iter().take(9).collect();
            if rest.starts_with("</script>") || rest.starts_with("</style>") {
                in_script = false;
                in_tag = true;
            }
        } else if chars[i] == '>' && in_tag {
            in_tag = false;
            i += 1;
            continue;
        }

        if !in_tag && !in_script {
            result.push(chars[i]);
        }
        i += 1;
    }

    result
}

/// Full HTML content processing: strip tags + decode entities.
pub fn decode_html_content(input: &str) -> String {
    let stripped = strip_html_tags(input);
    decode_html_entities(&stripped)
}

// ── 383: URL decoder ───────────────────────────────────────────────────

/// Decode percent-encoded strings (URL decoding).
pub fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex1 = chars.next();
            let hex2 = chars.next();
            if let (Some(h1), Some(h2)) = (hex1, hex2) {
                let hex_str = format!("{h1}{h2}");
                if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push(h1);
                    result.push(h2);
                }
            } else {
                result.push('%');
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

// ── 384: Unicode normalization (NFC) ───────────────────────────────────

/// Normalize Unicode to NFC (Normalization Form Canonical Composition).
/// This is a simplified implementation that handles common cases.
pub fn normalize_nfc(input: &str) -> String {
    // Full NFC normalization requires the `unicode-normalization` crate.
    // We implement a basic version that handles common combining characters.
    let mut result = String::with_capacity(input.len());

    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        // Check for common combining sequences.
        if let Some(&next) = chars.peek() {
            // Handle common Latin combining characters.
            let combined = try_combine(c, next);
            if let Some(combined) = combined {
                result.push(combined);
                chars.next();
                continue;
            }
        }
        result.push(c);
    }

    result
}

/// Try to combine a base character with a combining character.
fn try_combine(base: char, combining: char) -> Option<char> {
    // Common NFC combinations.
    match (base, combining) {
        ('A', '\u{0300}') => Some('\u{00C0}'), // À
        ('A', '\u{0301}') => Some('\u{00C1}'), // Á
        ('A', '\u{0302}') => Some('\u{00C2}'), // Â
        ('A', '\u{0308}') => Some('\u{00C4}'), // Ä
        ('E', '\u{0300}') => Some('\u{00C8}'), // È
        ('E', '\u{0301}') => Some('\u{00C9}'), // É
        ('E', '\u{0302}') => Some('\u{00CA}'), // Ê
        ('E', '\u{0308}') => Some('\u{00CB}'), // Ë
        ('I', '\u{0302}') => Some('\u{00CE}'), // Î
        ('I', '\u{0308}') => Some('\u{00CF}'), // Ï
        ('O', '\u{0302}') => Some('\u{00D4}'), // Ô
        ('O', '\u{0308}') => Some('\u{00D6}'), // Ö
        ('U', '\u{0300}') => Some('\u{00D9}'), // Ù
        ('U', '\u{0301}') => Some('\u{00DA}'), // Ú
        ('U', '\u{0302}') => Some('\u{00DB}'), // Û
        ('U', '\u{0308}') => Some('\u{00DC}'), // Ü
        ('a', '\u{0300}') => Some('\u{00E0}'), // à
        ('a', '\u{0301}') => Some('\u{00E1}'), // á
        ('a', '\u{0302}') => Some('\u{00E2}'), // â
        ('a', '\u{0308}') => Some('\u{00E4}'), // ä
        ('e', '\u{0300}') => Some('\u{00E8}'), // è
        ('e', '\u{0301}') => Some('\u{00E9}'), // é
        ('e', '\u{0302}') => Some('\u{00EA}'), // ê
        ('e', '\u{0308}') => Some('\u{00EB}'), // ë
        ('o', '\u{0302}') => Some('\u{00F4}'), // ô
        ('o', '\u{0308}') => Some('\u{00F6}'), // ö
        ('u', '\u{0300}') => Some('\u{00F9}'), // ù
        ('u', '\u{0301}') => Some('\u{00FA}'), // ú
        ('u', '\u{0302}') => Some('\u{00FB}'), // û
        ('u', '\u{0308}') => Some('\u{00FC}'), // ü
        ('c', '\u{0327}') => Some('\u{00E7}'), // ç
        ('C', '\u{0327}') => Some('\u{00C7}'), // Ç
        ('n', '\u{0303}') => Some('\u{00F1}'), // ñ
        ('N', '\u{0303}') => Some('\u{00D1}'), // Ñ
        _ => None,
    }
}

// ── 385: JSON string unescaper ─────────────────────────────────────────

/// Unescape JSON string escape sequences: \n \t \r \" \\ \uXXXX
pub fn unescape_json_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('b') => result.push('\u{0008}'),
                Some('f') => result.push('\u{000C}'),
                Some('u') => {
                    let hex: String = (0..4).filter_map(|_| chars.next()).collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16)
                        && let Some(ch) = char::from_u32(code)
                    {
                        result.push(ch);
                    }
                }
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

// ── 386: YAML multi-document parser ────────────────────────────────────

/// Split a YAML multi-document stream (separated by `---`) into individual documents.
pub fn split_yaml_documents(input: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut current = String::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed == "---" || trimmed == "..." {
            if !current.is_empty() {
                docs.push(current.clone());
                current.clear();
            }
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }

    if !current.is_empty() {
        docs.push(current);
    }

    if docs.is_empty() {
        vec![input.to_string()]
    } else {
        docs
    }
}

/// Extract values from a simple YAML document (key: value pairs).
pub fn extract_yaml_values(input: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(colon_pos) = trimmed.find(':') {
            let key = trimmed[..colon_pos].trim().to_string();
            let value = trimmed[colon_pos + 1..].trim().to_string();
            if !value.is_empty() {
                values.push((key, value));
            }
        }
    }

    values
}

// ── 387: XML parser ────────────────────────────────────────────────────

/// Extract attribute values and text nodes from XML.
pub fn extract_xml_values(input: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut in_tag = false;
    let mut current_tag = String::new();
    let mut current_text = String::new();
    let mut in_attr_value = false;
    let mut attr_value = String::new();

    for c in input.chars() {
        if !in_tag {
            if c == '<' {
                if !current_text.trim().is_empty() {
                    values.push(current_text.trim().to_string());
                }
                current_text.clear();
                in_tag = true;
                current_tag.clear();
            } else {
                current_text.push(c);
            }
        } else {
            if c == '>' {
                in_tag = false;
            } else if c == '"' || c == '\'' {
                if in_attr_value {
                    if !attr_value.is_empty() {
                        values.push(attr_value.clone());
                    }
                    attr_value.clear();
                    in_attr_value = false;
                } else {
                    in_attr_value = true;
                }
            } else if in_attr_value {
                attr_value.push(c);
            }
        }
    }

    if !current_text.trim().is_empty() {
        values.push(current_text.trim().to_string());
    }

    values
}

// ── 388: CSV parser ────────────────────────────────────────────────────

/// Parse a CSV line into cells, handling quoted values.
pub fn parse_csv_line(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            cells.push(current.clone());
            current.clear();
        } else {
            current.push(c);
        }
    }

    cells.push(current);
    cells
}

/// Parse CSV content into rows of cells.
pub fn parse_csv(content: &str) -> Vec<Vec<String>> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .map(parse_csv_line)
        .collect()
}

// ── 389: INI parser ────────────────────────────────────────────────────

/// Parse INI/properties file into key-value pairs.
pub fn parse_ini(content: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos + 1..].trim().to_string();
            let full_key = if current_section.is_empty() {
                key
            } else {
                format!("{current_section}.{key}")
            };
            values.push((full_key, value));
        }
    }

    values
}

// ── 390: .env parser ───────────────────────────────────────────────────

/// Parse .env file into key-value pairs, skipping comments.
pub fn parse_env_file(content: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Handle export KEY=VALUE
        let line = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..].trim().to_string();
            // Strip surrounding quotes.
            let value = value.trim_matches(|c| c == '"' || c == '\'').to_string();
            if !key.is_empty() {
                values.push((key, value));
            }
        }
    }

    values
}

// ── 391: Dockerfile parser ─────────────────────────────────────────────

/// Parse Dockerfile instructions (ENV, ARG, LABEL) into key-value pairs.
pub fn parse_dockerfile(content: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("ENV ") {
            // ENV KEY=VALUE or ENV KEY VALUE
            if let Some(eq_pos) = rest.find('=') {
                let key = rest[..eq_pos].trim().to_string();
                let value = rest[eq_pos + 1..].trim().to_string();
                values.push((key, value));
            } else if let Some(space_pos) = rest.find(char::is_whitespace) {
                let key = rest[..space_pos].trim().to_string();
                let value = rest[space_pos..].trim().to_string();
                values.push((key, value));
            }
        } else if let Some(rest) = trimmed.strip_prefix("ARG ") {
            // ARG KEY=VALUE or ARG KEY
            if let Some(eq_pos) = rest.find('=') {
                let key = rest[..eq_pos].trim().to_string();
                let value = rest[eq_pos + 1..].trim().to_string();
                values.push((key, value));
            } else {
                values.push((rest.trim().to_string(), String::new()));
            }
        } else if let Some(rest) = trimmed.strip_prefix("LABEL ") {
            // LABEL key=value
            if let Some(eq_pos) = rest.find('=') {
                let key = rest[..eq_pos].trim().to_string();
                let value = rest[eq_pos + 1..].trim().trim_matches('"').to_string();
                values.push((key, value));
            }
        }
    }

    values
}

// ── 392: HCL parser ────────────────────────────────────────────────────

/// Parse HCL/Terraform variable and local blocks into key-value pairs.
pub fn parse_hcl(content: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    let mut in_block = false;
    let mut block_type = String::new();
    let mut block_name = String::new();
    let mut brace_depth = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        if !in_block {
            // Check for block start: variable "name" { or locals { etc.
            if let Some(brace_pos) = trimmed.find('{') {
                let before_brace = trimmed[..brace_pos].trim();
                let parts: Vec<&str> = before_brace.splitn(2, char::is_whitespace).collect();
                if !parts.is_empty() {
                    block_type = parts[0].to_string();
                    if parts.len() > 1 {
                        block_name = parts[1].trim_matches('"').to_string();
                    }
                    in_block = true;
                    brace_depth = 1;
                    continue;
                }
            }
        } else {
            // Count braces.
            for c in trimmed.chars() {
                if c == '{' {
                    brace_depth += 1;
                } else if c == '}' {
                    brace_depth -= 1;
                }
            }

            if brace_depth <= 0 {
                in_block = false;
                block_type.clear();
                block_name.clear();
            } else {
                // Extract key = value pairs inside the block.
                if let Some(eq_pos) = trimmed.find('=') {
                    let key = trimmed[..eq_pos].trim().to_string();
                    let value = trimmed[eq_pos + 1..].trim().to_string();
                    if !key.is_empty() && !value.is_empty() {
                        let full_key = if block_name.is_empty() {
                            format!("{block_type}.{key}")
                        } else {
                            format!("{block_type}.{block_name}.{key}")
                        };
                        values.push((full_key, value.trim_matches('"').to_string()));
                    }
                }
            }
        }
    }

    values
}

// ── 393: Markdown code block extractor ─────────────────────────────────

/// Extract code blocks from Markdown content.
/// Returns a vector of (language, code) tuples.
pub fn extract_markdown_code_blocks(content: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut in_code_block = false;
    let mut current_lang = String::new();
    let mut current_code = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(stripped) = trimmed.strip_prefix("```") {
            if in_code_block {
                blocks.push((current_lang.clone(), current_code.clone()));
                current_lang.clear();
                current_code.clear();
                in_code_block = false;
            } else {
                current_lang = stripped.trim().to_string();
                in_code_block = true;
            }
        } else if in_code_block {
            current_code.push_str(line);
            current_code.push('\n');
        }
    }

    blocks
}

// ── 394: Jupyter notebook cell scanner ─────────────────────────────────

/// Extract code and output cells from a Jupyter notebook (.ipynb JSON).
pub fn extract_jupyter_cells(content: &str) -> Vec<(String, String)> {
    let mut cells = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return cells,
    };

    if let Some(cells_array) = json.get("cells").and_then(|c| c.as_array()) {
        for cell in cells_array {
            let cell_type = cell.get("cell_type").and_then(|t| t.as_str()).unwrap_or("");
            let source = cell.get("source");
            let source_text = if let Some(s) = source {
                if let Some(arr) = s.as_array() {
                    arr.iter()
                        .filter_map(|l| l.as_str())
                        .collect::<Vec<_>>()
                        .join("")
                } else if let Some(s) = s.as_str() {
                    s.to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            if !source_text.is_empty() {
                cells.push((cell_type.to_string(), source_text));
            }

            // Also extract output cells.
            if let Some(outputs) = cell.get("outputs").and_then(|o| o.as_array()) {
                for output in outputs {
                    if let Some(text) = output.get("text").and_then(|t| t.as_str()) {
                        cells.push(("output".to_string(), text.to_string()));
                    } else if let Some(data) = output.get("data").and_then(|d| d.as_object())
                        && let Some(text) = data.get("text/plain").and_then(|t| t.as_str())
                    {
                        cells.push(("output".to_string(), text.to_string()));
                    }
                }
            }
        }
    }

    cells
}

// ── 395: PDF text extractor ────────────────────────────────────────────

/// Extract text from a PDF file.
/// This is a simplified extractor that reads text between BT/ET markers.
/// For production use, a full PDF parser crate (like `pdf-extract`) is recommended.
pub fn extract_pdf_text(content: &[u8]) -> String {
    let text = String::from_utf8_lossy(content);
    let mut result = String::new();

    // Look for text in parentheses within BT...ET blocks.
    let mut in_text_block = false;
    let mut i = 0;
    let bytes = text.as_bytes();

    while i < bytes.len() {
        if i + 1 < bytes.len() {
            let pair = &bytes[i..i + 2];
            if pair == b"BT" {
                in_text_block = true;
                i += 2;
                continue;
            } else if pair == b"ET" {
                in_text_block = false;
                i += 2;
                continue;
            }
        }

        if in_text_block && bytes[i] == b'(' {
            // Read until closing paren.
            let mut text = String::new();
            i += 1;
            while i < bytes.len() && bytes[i] != b')' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                }
                text.push(bytes[i] as char);
                i += 1;
            }
            if !text.is_empty() {
                result.push_str(&text);
                result.push(' ');
            }
        }
        i += 1;
    }

    result
}

// ── 396: Word document text extractor ──────────────────────────────────

/// Extract text from a .docx file (which is a ZIP archive containing XML).
pub fn extract_docx_text(content: &[u8]) -> String {
    // .docx files are ZIP archives. The main content is in word/document.xml.
    // We use the `zip` crate to extract and parse the XML.
    let cursor = std::io::Cursor::new(content);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return String::new(),
    };

    let document_xml = match archive.by_name("word/document.xml") {
        Ok(mut file) => {
            let mut buf = String::new();
            if std::io::Read::read_to_string(&mut file, &mut buf).is_err() {
                return String::new();
            }
            buf
        }
        Err(_) => return String::new(),
    };

    // Extract text from <w:t> tags.
    let mut result = String::new();
    let mut in_text = false;
    let mut current_text = String::new();

    for c in document_xml.chars() {
        if in_text {
            if c == '<' {
                result.push_str(&current_text);
                current_text.clear();
                in_text = false;
            } else {
                current_text.push(c);
            }
        } else if c == '>' {
            // Check if the tag we just closed was <w:t>
            // Simplified: just look for text content after w:t tags.
        }
    }

    // Alternative: just strip all XML tags and keep text.
    let stripped = strip_xml_tags_simple(&document_xml);
    if stripped.len() > result.len() {
        stripped
    } else {
        result
    }
}

fn strip_xml_tags_simple(input: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for c in input.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(c);
        }
    }
    result
}

// ── 397: Excel cell scanner ────────────────────────────────────────────

/// Extract cell values from an .xlsx file (ZIP archive with XML sheets).
pub fn extract_xlsx_cells(content: &[u8]) -> Vec<String> {
    let cursor = std::io::Cursor::new(content);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };

    let mut values = Vec::new();

    // Shared strings file.
    let shared_strings = {
        let mut buf = String::new();
        if let Ok(mut file) = archive.by_name("xl/sharedStrings.xml") {
            let _ = std::io::Read::read_to_string(&mut file, &mut buf);
        }
        buf
    };

    // Parse shared strings for cell values.
    let stripped = strip_xml_tags_simple(&shared_strings);
    for word in stripped.split_whitespace() {
        if !word.is_empty() {
            values.push(word.to_string());
        }
    }

    // Also try to read sheet files.
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i)
            && file.name().contains("sheet")
            && file.name().ends_with(".xml")
        {
            let mut buf = String::new();
            let mut file = file;
            if std::io::Read::read_to_string(&mut file, &mut buf).is_ok() {
                let stripped = strip_xml_tags_simple(&buf);
                for word in stripped.split_whitespace() {
                    if !word.is_empty() && !values.iter().any(|v| v == word) {
                        values.push(word.to_string());
                    }
                }
            }
        }
    }

    values
}

// ── 398: PowerPoint text scanner ───────────────────────────────────────

/// Extract text from a .pptx file (ZIP archive with XML slides).
pub fn extract_pptx_text(content: &[u8]) -> String {
    let cursor = std::io::Cursor::new(content);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return String::new(),
    };

    let mut result = String::new();

    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_string();
            if name.starts_with("ppt/slides/slide") && name.ends_with(".xml") {
                let mut buf = String::new();
                let mut file = file;
                if std::io::Read::read_to_string(&mut file, &mut buf).is_ok() {
                    let stripped = strip_xml_tags_simple(&buf);
                    result.push_str(&stripped);
                    result.push(' ');
                }
            }
        }
    }

    result
}

// ── 399: Image OCR scanning ────────────────────────────────────────────

/// Extract text from an image via OCR.
/// This is a placeholder that would use Tesseract OCR in production.
/// Since Tesseract requires a native library, we provide the interface
/// and a stub implementation.
pub fn extract_image_text(_content: &[u8]) -> Option<String> {
    // In production, this would call:
    // tesseract::ocr(image_bytes, "eng")
    // For now, we return None to indicate OCR is not available.
    None
}

/// Check if OCR is available (Tesseract installed).
pub fn is_ocr_available() -> bool {
    // Check if tesseract is in PATH.
    std::process::Command::new("tesseract")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

// ── 400: Binary string extraction ─────────────────────────────────────

/// Extract printable strings from binary content (like the `strings` command).
/// Extracts sequences of 4+ printable ASCII characters.
pub fn extract_binary_strings(content: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in content {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte as char);
        } else {
            if current.len() >= 4 {
                strings.push(current.trim().to_string());
            }
            current.clear();
        }
    }

    if current.len() >= 4 {
        strings.push(current.trim().to_string());
    }

    strings
}

/// Extract printable strings with a minimum length threshold.
pub fn extract_binary_strings_min(content: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in content {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte as char);
        } else {
            if current.trim().len() >= min_len {
                strings.push(current.trim().to_string());
            }
            current.clear();
        }
    }

    if current.trim().len() >= min_len {
        strings.push(current.trim().to_string());
    }

    strings
}

// ── Content decoding pipeline ──────────────────────────────────────────

/// Detected content type.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentType {
    Html,
    Xml,
    Json,
    Yaml,
    Csv,
    Ini,
    Env,
    Dockerfile,
    Hcl,
    Markdown,
    Jupyter,
    Pdf,
    Docx,
    Xlsx,
    Pptx,
    Binary,
    Text,
}

/// Detect content type from file extension.
pub fn detect_content_type(path: &Path) -> ContentType {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => ContentType::Html,
        Some("xml") => ContentType::Xml,
        Some("json") => ContentType::Json,
        Some("yaml") | Some("yml") => ContentType::Yaml,
        Some("csv") | Some("tsv") => ContentType::Csv,
        Some("ini") | Some("cfg") | Some("conf") | Some("properties") => ContentType::Ini,
        Some("env") => ContentType::Env,
        Some("dockerfile") => ContentType::Dockerfile,
        Some("hcl") | Some("tf") => ContentType::Hcl,
        Some("md") | Some("markdown") => ContentType::Markdown,
        Some("ipynb") => ContentType::Jupyter,
        Some("pdf") => ContentType::Pdf,
        Some("docx") => ContentType::Docx,
        Some("xlsx") => ContentType::Xlsx,
        Some("pptx") => ContentType::Pptx,
        _ => {
            // Check filename.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.eq_ignore_ascii_case("dockerfile") {
                ContentType::Dockerfile
            } else if name.starts_with('.') && name.contains("env") {
                ContentType::Env
            } else {
                ContentType::Text
            }
        }
    }
}

/// Decode content based on its type, returning extracted text lines for scanning.
pub fn decode_content(content: &[u8], content_type: &ContentType) -> Vec<String> {
    match content_type {
        ContentType::Html => {
            let text = String::from_utf8_lossy(content);
            let decoded = decode_html_content(&text);
            decoded.lines().map(String::from).collect()
        }
        ContentType::Xml => {
            let text = String::from_utf8_lossy(content);
            extract_xml_values(&text)
        }
        ContentType::Json => {
            let text = String::from_utf8_lossy(content);
            // Extract all string values from JSON.
            extract_json_string_values(&text)
        }
        ContentType::Yaml => {
            let text = String::from_utf8_lossy(content);
            let docs = split_yaml_documents(&text);
            let mut lines = Vec::new();
            for doc in docs {
                for (key, value) in extract_yaml_values(&doc) {
                    lines.push(format!("{key}: {value}"));
                }
            }
            lines
        }
        ContentType::Csv => {
            let text = String::from_utf8_lossy(content);
            parse_csv(&text).into_iter().flatten().collect()
        }
        ContentType::Ini => {
            let text = String::from_utf8_lossy(content);
            parse_ini(&text)
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect()
        }
        ContentType::Env => {
            let text = String::from_utf8_lossy(content);
            parse_env_file(&text)
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect()
        }
        ContentType::Dockerfile => {
            let text = String::from_utf8_lossy(content);
            parse_dockerfile(&text)
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect()
        }
        ContentType::Hcl => {
            let text = String::from_utf8_lossy(content);
            parse_hcl(&text)
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect()
        }
        ContentType::Markdown => {
            let text = String::from_utf8_lossy(content);
            extract_markdown_code_blocks(&text)
                .into_iter()
                .flat_map(|(_, code)| code.lines().map(String::from).collect::<Vec<_>>())
                .collect()
        }
        ContentType::Jupyter => {
            let text = String::from_utf8_lossy(content);
            extract_jupyter_cells(&text)
                .into_iter()
                .flat_map(|(_, code)| code.lines().map(String::from).collect::<Vec<_>>())
                .collect()
        }
        ContentType::Pdf => {
            let text = extract_pdf_text(content);
            text.lines().map(String::from).collect()
        }
        ContentType::Docx => {
            let text = extract_docx_text(content);
            text.lines().map(String::from).collect()
        }
        ContentType::Xlsx => extract_xlsx_cells(content),
        ContentType::Pptx => {
            let text = extract_pptx_text(content);
            text.lines().map(String::from).collect()
        }
        ContentType::Binary => extract_binary_strings(content),
        ContentType::Text => String::from_utf8_lossy(content)
            .lines()
            .map(String::from)
            .collect(),
    }
}

/// Extract all string values from a JSON document.
fn extract_json_string_values(json: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut in_string = false;
    let mut current = String::new();
    let mut chars = json.chars().peekable();

    while let Some(c) = chars.next() {
        if in_string {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    current.push('\\');
                    current.push(next);
                    chars.next();
                }
            } else if c == '"' {
                if !current.is_empty() {
                    values.push(unescape_json_string(&current));
                }
                current.clear();
                in_string = false;
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_string = true;
        }
    }

    values
}

/// Scan decoded content with detectors and return findings.
pub fn scan_decoded_content(
    content: &[u8],
    path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Vec<Finding> {
    let content_type = detect_content_type(path);
    let lines = decode_content(content, &content_type);

    let mut findings = Vec::new();
    for (line_idx, line) in lines.iter().enumerate() {
        for detector in detectors {
            let matches: SmallVec<_> = detector.scan_line(line);
            for m in matches {
                findings.push(Finding {
                    rule_id: detector.id().to_string(),
                    description: detector.description().to_string(),
                    severity: detector.severity(),
                    path: path.to_path_buf(),
                    line: line_idx + 1,
                    column: m.start + 1,
                    matched: m.text,
                    context: line.clone(),
                    commit: None,
                    likely_false_positive: false,
                    verification: None,
                });
            }
        }
    }

    findings
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_html_entities() {
        assert_eq!(decode_html_entities("&lt;div&gt;"), "<div>");
        assert_eq!(decode_html_entities("&amp;"), "&");
        assert_eq!(decode_html_entities("&#x27;"), "'");
        assert_eq!(decode_html_entities("&#39;"), "'");
        assert_eq!(decode_html_entities("&quot;"), "\"");
        assert_eq!(
            decode_html_entities("hello &amp; goodbye"),
            "hello & goodbye"
        );
        assert_eq!(decode_html_entities("&nbsp;"), "\u{00A0}");
        assert_eq!(decode_html_entities("no entities here"), "no entities here");
    }

    #[test]
    fn test_strip_html_tags() {
        assert_eq!(strip_html_tags("<p>Hello</p>"), "Hello");
        assert_eq!(strip_html_tags("<div>World</div>"), "World");
        assert_eq!(strip_html_tags("<b>bold</b> text"), "bold text");
        let html = "<html><body><script>alert(1)</script><p>content</p></body></html>";
        let stripped = strip_html_tags(html);
        assert!(!stripped.contains("alert"));
        assert!(stripped.contains("content"));
    }

    #[test]
    fn test_decode_html_content() {
        let html = "<p>key = &lt;AKIAIOSFODNN7EXAMPLE&gt;</p>";
        let decoded = decode_html_content(html);
        assert!(decoded.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("key%3Dvalue"), "key=value");
        assert_eq!(url_decode("no+encoding+needed"), "no encoding needed");
        assert_eq!(url_decode("a%2Fb%2Fc"), "a/b/c");
    }

    #[test]
    fn test_normalize_nfc() {
        assert_eq!(normalize_nfc("hello"), "hello");
        let combined = normalize_nfc("e\u{0301}");
        assert_eq!(combined, "é");
    }

    #[test]
    fn test_unescape_json_string() {
        assert_eq!(unescape_json_string("hello\\nworld"), "hello\nworld");
        assert_eq!(unescape_json_string("tab\\there"), "tab\there");
        assert_eq!(unescape_json_string("quote\\\"here"), "quote\"here");
        assert_eq!(unescape_json_string("back\\\\slash"), "back\\slash");
        assert_eq!(unescape_json_string("unicode\\u0041"), "unicodeA");
    }

    #[test]
    fn test_split_yaml_documents() {
        let yaml = "key1: value1\n---\nkey2: value2\n---\nkey3: value3";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 3);
        assert!(docs[0].contains("key1"));
        assert!(docs[1].contains("key2"));
        assert!(docs[2].contains("key3"));
    }

    #[test]
    fn test_extract_yaml_values() {
        let yaml = "name: my-secret\nkey: AKIAIOSFODNN7EXAMPLE\n# comment\nempty:";
        let values = extract_yaml_values(yaml);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].0, "name");
        assert_eq!(values[0].1, "my-secret");
        assert_eq!(values[1].1, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_extract_xml_values() {
        let xml = r#"<root><name>AKIAIOSFODNN7EXAMPLE</name><attr key="ghp_token"/></root>"#;
        let values = extract_xml_values(xml);
        assert!(values.iter().any(|v| v.contains("AKIAIOSFODNN7EXAMPLE")));
    }

    #[test]
    fn test_parse_csv_line() {
        let cells = parse_csv_line("a,b,c");
        assert_eq!(cells, vec!["a", "b", "c"]);

        let cells = parse_csv_line("\"quoted,value\",plain");
        assert_eq!(cells, vec!["quoted,value", "plain"]);

        let cells = parse_csv_line("\"escaped\"\"quote\"");
        assert_eq!(cells, vec!["escaped\"quote"]);
    }

    #[test]
    fn test_parse_csv() {
        let content = "a,b\nc,d\ne,f";
        let rows = parse_csv(content);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], vec!["a", "b"]);
    }

    #[test]
    fn test_parse_ini() {
        let content = "[database]\nhost = localhost\nport = 5432\n# comment\npassword = secret123";
        let values = parse_ini(content);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].0, "database.host");
        assert_eq!(values[0].1, "localhost");
        assert_eq!(values[2].0, "database.password");
        assert_eq!(values[2].1, "secret123");
    }

    #[test]
    fn test_parse_env_file() {
        let content =
            "# comment\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nexport DB_PASSWORD=\"secret\"\nEMPTY=";
        let values = parse_env_file(content);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].0, "AWS_KEY");
        assert_eq!(values[0].1, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(values[1].0, "DB_PASSWORD");
        assert_eq!(values[1].1, "secret");
        assert_eq!(values[2].0, "EMPTY");
        assert_eq!(values[2].1, "");
    }

    #[test]
    fn test_parse_dockerfile() {
        let content = "FROM ubuntu:20.04\nENV AWS_KEY=AKIAIOSFODNN7EXAMPLE\nARG BUILD_VERSION=1.0\nLABEL maintainer=\"team@example.com\"";
        let values = parse_dockerfile(content);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].0, "AWS_KEY");
        assert_eq!(values[0].1, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_parse_hcl() {
        let content = r#"
variable "db_password" {
  type    = "string"
  default = "supersecret123"
}

locals {
  api_key = "AKIAIOSFODNN7EXAMPLE"
}
"#;
        let values = parse_hcl(content);
        assert!(
            values
                .iter()
                .any(|(k, v)| k.contains("db_password") && v.contains("supersecret"))
        );
        assert!(
            values
                .iter()
                .any(|(_, v)| v.contains("AKIAIOSFODNN7EXAMPLE"))
        );
    }

    #[test]
    fn test_extract_markdown_code_blocks() {
        let content = "Some text\n```python\nAWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n```\nMore text\n```bash\nexport TOKEN=ghp_123\n```";
        let blocks = extract_markdown_code_blocks(content);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, "python");
        assert!(blocks[0].1.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(blocks[1].0, "bash");
    }

    #[test]
    fn test_extract_jupyter_cells() {
        let json = r##"{
  "cells": [
    {
      "cell_type": "code",
      "source": ["AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\""]
    },
    {
      "cell_type": "markdown",
      "source": ["# Title"]
    }
  ]
}"##;
        let cells = extract_jupyter_cells(json);
        assert_eq!(cells.len(), 2);
        assert!(cells[0].1.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_extract_binary_strings() {
        let content = b"\x00\x00hello world\x00\x00secret123\x00\x00";
        let strings = extract_binary_strings(content);
        assert!(strings.contains(&"hello world".to_string()));
        assert!(strings.contains(&"secret123".to_string()));
    }

    #[test]
    fn test_extract_binary_strings_min() {
        let content = b"\x00ab\x00abcd\x00abcdef\x00";
        let strings = extract_binary_strings_min(content, 4);
        assert!(strings.contains(&"abcd".to_string()));
        assert!(strings.contains(&"abcdef".to_string()));
        assert!(!strings.contains(&"ab".to_string()));
    }

    #[test]
    fn test_detect_content_type() {
        assert_eq!(
            detect_content_type(Path::new("test.html")),
            ContentType::Html
        );
        assert_eq!(
            detect_content_type(Path::new("test.yml")),
            ContentType::Yaml
        );
        assert_eq!(
            detect_content_type(Path::new("Dockerfile")),
            ContentType::Dockerfile
        );
        assert_eq!(detect_content_type(Path::new("test.env")), ContentType::Env);
        assert_eq!(detect_content_type(Path::new("main.tf")), ContentType::Hcl);
        assert_eq!(
            detect_content_type(Path::new("notebook.ipynb")),
            ContentType::Jupyter
        );
        assert_eq!(
            detect_content_type(Path::new("README.md")),
            ContentType::Markdown
        );
        assert_eq!(detect_content_type(Path::new("data.csv")), ContentType::Csv);
        assert_eq!(
            detect_content_type(Path::new("config.ini")),
            ContentType::Ini
        );
    }

    #[test]
    fn test_decode_content_text() {
        let content = b"key = AKIAIOSFODNN7EXAMPLE\nother = value";
        let lines = decode_content(content, &ContentType::Text);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_decode_content_env() {
        let content = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n# comment\nDB_PASS=secret";
        let lines = decode_content(content, &ContentType::Env);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_decode_content_html() {
        let content = b"<p>key = &lt;AKIAIOSFODNN7EXAMPLE&gt;</p>";
        let lines = decode_content(content, &ContentType::Html);
        assert!(lines.iter().any(|l| l.contains("AKIAIOSFODNN7EXAMPLE")));
    }

    #[test]
    fn test_extract_json_string_values() {
        let json = r#"{"key": "AKIAIOSFODNN7EXAMPLE", "other": "ghp_token"}"#;
        let values = extract_json_string_values(json);
        assert!(values.contains(&"AKIAIOSFODNN7EXAMPLE".to_string()));
        assert!(values.contains(&"ghp_token".to_string()));
    }
}
