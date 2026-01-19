//! Lexer comparison tool for debugging differences between wasmib and libsmi.
//!
//! Usage:
//!   lexer_cmp <file>              Compare single file, show first divergence
//!   lexer_cmp --corpus <dir>      Compare all files, list those with differences
//!   lexer_cmp --analyze <file>    Deep analysis of a single file's differences
//!   lexer_cmp --diff <file>       Side-by-side token diff around divergences
//!   lexer_cmp --bytes <file>      Byte-level analysis around divergence points
//!
//! This tool provides rich context around divergences:
//! - Source file location (line, column, hex dump)
//! - Tokens before/after the divergence point
//! - Categorization of the difference type
//!
//! For state tracing in libsmi tokenizer, set TRACE_STATES=1 environment variable

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wasmib_core::lexer::{Lexer, TokenKind};

/// A parsed token from either tokenizer.
#[derive(Debug, Clone)]
struct ParsedToken {
    line: u32,
    col: u32,
    kind: String,
    text: String,
}

/// Category of difference between tokenizers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffCategory {
    /// wasmib has more tokens than libsmi
    ExtraWasmibTokens,
    /// libsmi has more tokens than wasmib
    ExtraLibsmiTokens,
    /// Token types differ at the same position
    TypeMismatch,
    /// Only content differs (types match)
    ContentOnly,
    /// Structural tokens identical, only ERROR tokens or line numbers differ
    NonStructuralOnly,
    /// Outputs are identical
    Identical,
}

/// Check if a token kind is structural (affects parsed MIB structure).
/// ERROR tokens and line number differences are non-structural.
fn is_structural_token(kind: &str) -> bool {
    kind != "ERROR"
}

/// Result of comparing two token streams.
#[derive(Debug)]
struct CompareResult {
    category: DiffCategory,
    wasmib_count: usize,
    libsmi_count: usize,
    /// Index of first divergence in wasmib stream
    diverge_wasmib_idx: Option<usize>,
    /// Index of first divergence in libsmi stream
    diverge_libsmi_idx: Option<usize>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} <file>              Compare single file", args[0]);
        eprintln!("  {} --corpus <dir>      Compare all files in directory", args[0]);
        eprintln!("  {} --analyze <file>    Deep analysis of differences", args[0]);
        eprintln!("  {} --diff <file>       Side-by-side token diff", args[0]);
        eprintln!("  {} --bytes <file>      Byte-level analysis around divergences", args[0]);
        eprintln!();
        eprintln!("For libsmi state tracing, set TRACE_STATES=1 environment variable");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "--corpus" => {
            if args.len() < 3 {
                eprintln!("Missing directory argument");
                std::process::exit(1);
            }
            corpus_compare(&args[2]);
        }
        "--analyze" => {
            if args.len() < 3 {
                eprintln!("Missing file argument");
                std::process::exit(1);
            }
            analyze_file(&args[2]);
        }
        "--diff" => {
            if args.len() < 3 {
                eprintln!("Missing file argument");
                std::process::exit(1);
            }
            diff_file(&args[2]);
        }
        "--bytes" => {
            if args.len() < 3 {
                eprintln!("Missing file argument");
                std::process::exit(1);
            }
            bytes_file(&args[2]);
        }
        path => {
            compare_single(path);
        }
    }
}

/// Compare a single file and show brief result.
fn compare_single(path: &str) {
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            std::process::exit(1);
        }
    };

    let wasmib_tokens = tokenize_wasmib(&source);
    let libsmi_tokens = match tokenize_libsmi(path) {
        Ok(tokens) => tokens,
        Err(e) => {
            eprintln!("Error running libsmi tokenizer: {e}");
            std::process::exit(1);
        }
    };

    let result = compare_tokens(&wasmib_tokens, &libsmi_tokens);

    match result.category {
        DiffCategory::Identical => {
            println!("\x1b[32m✓\x1b[0m {path} (identical, {} tokens)", result.wasmib_count);
        }
        DiffCategory::ContentOnly => {
            println!(
                "\x1b[33m~\x1b[0m {path} (content differs, types match, {} tokens)",
                result.wasmib_count
            );
        }
        _ => {
            println!(
                "\x1b[31m✗\x1b[0m {path} ({:?}, wasmib={}, libsmi={})",
                result.category, result.wasmib_count, result.libsmi_count
            );
            // Show brief divergence info
            if let Some(idx) = result.diverge_wasmib_idx {
                show_divergence_brief(&source, &wasmib_tokens, &libsmi_tokens, idx, result.diverge_libsmi_idx.unwrap_or(idx));
            }
        }
    }
}

/// Deep analysis of a single file.
fn analyze_file(path: &str) {
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            std::process::exit(1);
        }
    };

    let wasmib_tokens = tokenize_wasmib(&source);
    let libsmi_tokens = match tokenize_libsmi(path) {
        Ok(tokens) => tokens,
        Err(e) => {
            eprintln!("Error running libsmi tokenizer: {e}");
            std::process::exit(1);
        }
    };

    let result = compare_tokens(&wasmib_tokens, &libsmi_tokens);

    println!("=== Lexer Comparison: {} ===\n", path);
    println!("wasmib tokens: {}", result.wasmib_count);
    println!("libsmi tokens: {}", result.libsmi_count);
    println!("Category: {:?}\n", result.category);

    if result.category == DiffCategory::Identical {
        println!("No differences found.");
        return;
    }

    // Find all divergence points
    let divergences = find_all_divergences(&wasmib_tokens, &libsmi_tokens);

    println!("Found {} divergence point(s):\n", divergences.len());

    for (i, (w_idx, l_idx)) in divergences.iter().enumerate() {
        println!("--- Divergence #{} ---", i + 1);
        show_divergence_detailed(&source, &wasmib_tokens, &libsmi_tokens, *w_idx, *l_idx);
        println!();

        // Limit output for corpus with many differences
        if i >= 4 {
            println!("... and {} more divergences", divergences.len() - 5);
            break;
        }
    }
}

/// Side-by-side diff of tokens with alignment at divergence points.
fn diff_file(path: &str) {
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            std::process::exit(1);
        }
    };

    let wasmib_tokens = tokenize_wasmib(&source);
    let libsmi_tokens = match tokenize_libsmi(path) {
        Ok(tokens) => tokens,
        Err(e) => {
            eprintln!("Error running libsmi tokenizer: {e}");
            std::process::exit(1);
        }
    };

    let result = compare_tokens(&wasmib_tokens, &libsmi_tokens);

    println!("=== Token Diff: {} ===\n", path);
    println!("wasmib: {} tokens", result.wasmib_count);
    println!("libsmi: {} tokens", result.libsmi_count);
    println!("Category: {:?}\n", result.category);

    if result.category == DiffCategory::Identical {
        println!("Tokens are identical.");
        return;
    }

    if result.category == DiffCategory::ContentOnly {
        println!("Token types match. Only line/column or text content differs.");
        show_content_diff(&wasmib_tokens, &libsmi_tokens);
        return;
    }

    // Show aligned diff
    println!("Side-by-side comparison (showing around divergences):\n");
    println!(
        "{:>6} {:>40} | {:>6} {:>40}",
        "IDX", "WASMIB", "IDX", "LIBSMI"
    );
    println!("{}", "-".repeat(100));

    show_aligned_diff(&wasmib_tokens, &libsmi_tokens, 5);

    // Summary of differences
    println!("\n=== Difference Summary ===\n");
    summarize_differences(&wasmib_tokens, &libsmi_tokens);
}

/// Byte-level analysis around divergence points.
fn bytes_file(path: &str) {
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            std::process::exit(1);
        }
    };

    let wasmib_tokens = tokenize_wasmib(&source);
    let libsmi_tokens = match tokenize_libsmi(path) {
        Ok(tokens) => tokens,
        Err(e) => {
            eprintln!("Error running libsmi tokenizer: {e}");
            std::process::exit(1);
        }
    };

    let result = compare_tokens(&wasmib_tokens, &libsmi_tokens);

    println!("=== Byte-Level Analysis: {} ===\n", path);
    println!("wasmib: {} tokens", result.wasmib_count);
    println!("libsmi: {} tokens", result.libsmi_count);
    println!("Category: {:?}\n", result.category);

    if result.category == DiffCategory::Identical {
        println!("Tokens are identical.");
        return;
    }

    // Compute line offsets for source navigation
    let line_offsets = compute_line_offsets(&source);

    // Find divergence points and show byte-level context
    let divergences = find_all_divergences(&wasmib_tokens, &libsmi_tokens);

    println!("Found {} divergence point(s). Showing byte-level context:\n", divergences.len());

    for (i, (w_idx, l_idx)) in divergences.iter().enumerate() {
        if i >= 5 {
            println!("... and {} more divergences", divergences.len() - 5);
            break;
        }

        println!("=== Divergence #{} ===", i + 1);

        let w_token = wasmib_tokens.get(*w_idx);
        let l_token = libsmi_tokens.get(*l_idx);

        // Get source location from wasmib token (it tracks start position)
        if let Some(w) = w_token {
            let line = w.line as usize;
            let col = w.col as usize;

            println!("wasmib[{}]: line {}:{} {} {:?}",
                     w_idx, w.line, w.col, w.kind, truncate(&w.text, 30));

            if let Some(l) = l_token {
                println!("libsmi[{}]: line {}:{} {} {:?}",
                         l_idx, l.line, l.col, l.kind, truncate(&l.text, 30));
            } else {
                println!("libsmi[{}]: (end of stream)", l_idx);
            }

            // Show source lines with byte dump
            println!("\nSource context:");
            let start_line = line.saturating_sub(2);
            let end_line = (line + 2).min(line_offsets.len());

            for ln in start_line..end_line {
                let line_num = ln + 1;
                let line_start = line_offsets.get(ln).copied().unwrap_or(source.len());
                let line_end = line_offsets.get(ln + 1).copied().unwrap_or(source.len());
                let line_bytes = &source[line_start..line_end.min(source.len())];

                let marker = if line_num == line { ">>>" } else { "   " };
                let line_str = String::from_utf8_lossy(line_bytes);
                println!("{} {:4}: {}", marker, line_num, line_str.trim_end());

                // For the divergence line, show byte dump
                if line_num == line {
                    // Show hex dump of the entire line
                    print!("         Bytes: ");
                    for (byte_idx, &b) in line_bytes.iter().enumerate() {
                        let is_col = byte_idx + 1 == col;
                        if is_col {
                            print!("\x1b[1;31m");  // Bold red for divergence point
                        }
                        print!("{:02x}", b);
                        if is_col {
                            print!("\x1b[0m");
                        }
                        print!(" ");
                        if (byte_idx + 1) % 16 == 0 && byte_idx + 1 < line_bytes.len() {
                            print!("\n                ");
                        }
                    }
                    println!();

                    // Show ASCII interpretation
                    print!("         ASCII: ");
                    for (byte_idx, &b) in line_bytes.iter().enumerate() {
                        let is_col = byte_idx + 1 == col;
                        if is_col {
                            print!("\x1b[1;31m");
                        }
                        if b >= 0x20 && b < 0x7f {
                            print!("{} ", b as char);
                        } else {
                            print!(". ");
                        }
                        if is_col {
                            print!("\x1b[0m");
                        }
                        print!(" ");
                        if (byte_idx + 1) % 16 == 0 && byte_idx + 1 < line_bytes.len() {
                            print!("\n                ");
                        }
                    }
                    println!();

                    // Show byte interpretation at column
                    if col > 0 && col <= line_bytes.len() {
                        let byte_at_col = line_bytes[col - 1];
                        println!("\n         At column {}: byte 0x{:02x}", col, byte_at_col);
                        if byte_at_col >= 0x20 && byte_at_col < 0x7f {
                            println!("                       char '{}'", byte_at_col as char);
                        }
                        // Show surrounding bytes
                        let ctx_start = (col - 1).saturating_sub(5);
                        let ctx_end = (col + 10).min(line_bytes.len());
                        print!("         Context: ");
                        for idx in ctx_start..ctx_end {
                            if idx == col - 1 {
                                print!("[{:02x}]", line_bytes[idx]);
                            } else {
                                print!("{:02x} ", line_bytes[idx]);
                            }
                        }
                        println!();
                    }
                }
            }

            // Show what libsmi might be seeing differently
            if let Some(l) = l_token {
                if l.line != w.line || l.col != w.col {
                    println!("\n         Note: libsmi reports different position {}:{}", l.line, l.col);
                    println!("               This often indicates multi-line token handling differences");
                }
            }
        }

        println!();
    }

    // Summary
    println!("=== Analysis Summary ===\n");
    println!("Token count difference: {} (wasmib) vs {} (libsmi) = {} difference",
             wasmib_tokens.len(), libsmi_tokens.len(),
             (wasmib_tokens.len() as i64 - libsmi_tokens.len() as i64).abs());

    // Count extra tokens by type
    let mut extra_types: std::collections::HashMap<&str, i32> = std::collections::HashMap::new();
    for w in &wasmib_tokens {
        *extra_types.entry(&w.kind).or_insert(0) += 1;
    }
    for l in &libsmi_tokens {
        *extra_types.entry(&l.kind).or_insert(0) -= 1;
    }

    let mut diffs: Vec<_> = extra_types.iter().filter(|(_, v)| **v != 0).collect();
    diffs.sort_by(|a, b| b.1.abs().cmp(&a.1.abs()));

    if !diffs.is_empty() {
        println!("\nToken type balance (positive = more in wasmib, negative = more in libsmi):");
        for (kind, count) in diffs.iter().take(10) {
            let sign = if **count > 0 { "+" } else { "" };
            println!("  {}: {}{}", kind, sign, count);
        }
    }

    println!("\nTip: Set TRACE_STATES=1 and run libsmi tokenizer directly to see state transitions:");
    println!("  TRACE_STATES=1 ./tools/libsmi-tokenizer/tokenizer {} 2>&1 | head -100", path);
}

/// Show content differences when types match.
fn show_content_diff(wasmib: &[ParsedToken], libsmi: &[ParsedToken]) {
    let mut diffs = Vec::new();
    for (i, (w, l)) in wasmib.iter().zip(libsmi.iter()).enumerate() {
        if w.line != l.line || w.col != l.col {
            diffs.push((i, "position", format!("{}:{} vs {}:{}", w.line, w.col, l.line, l.col)));
        } else if w.text != l.text {
            diffs.push((i, "text", format!("{:?} vs {:?}", truncate(&w.text, 20), truncate(&l.text, 20))));
        }
    }

    println!("\nFirst 10 content differences:");
    for (i, kind, desc) in diffs.iter().take(10) {
        println!("  [{}] {}: {}", i, kind, desc);
    }
    if diffs.len() > 10 {
        println!("  ... and {} more", diffs.len() - 10);
    }
}

/// Show aligned diff around divergence points.
fn show_aligned_diff(wasmib: &[ParsedToken], libsmi: &[ParsedToken], context: usize) {
    let mut w_idx = 0;
    let mut l_idx = 0;
    let mut shown_ranges: Vec<(usize, usize)> = Vec::new();
    let mut divergence_count = 0;

    while w_idx < wasmib.len() || l_idx < libsmi.len() {
        let w_token = wasmib.get(w_idx);
        let l_token = libsmi.get(l_idx);

        let types_match = match (w_token, l_token) {
            (Some(w), Some(l)) => w.kind == l.kind,
            _ => false,
        };

        if types_match {
            w_idx += 1;
            l_idx += 1;
            continue;
        }

        // Found divergence - show context
        divergence_count += 1;
        if divergence_count > 5 {
            println!("\n... ({} more divergences not shown)",
                find_all_divergences(wasmib, libsmi).len() - 5);
            break;
        }

        let start_w = w_idx.saturating_sub(context);
        let start_l = l_idx.saturating_sub(context);

        // Check if this overlaps with previously shown range
        let overlaps = shown_ranges.iter().any(|(s, e)| start_w < *e && w_idx > *s);
        if !overlaps {
            println!("\n--- Divergence at wasmib[{}] / libsmi[{}] ---", w_idx, l_idx);

            // Show context before
            for i in start_w..w_idx {
                let w = &wasmib[i];
                let l = libsmi.get(start_l + (i - start_w));
                print_diff_line(i, Some(w), start_l + (i - start_w), l, false);
            }

            // Show divergent tokens
            let end_w = (w_idx + context + 1).min(wasmib.len());
            let end_l = (l_idx + context + 1).min(libsmi.len());

            // Try to resync
            let (new_w, new_l) = find_resync_point(wasmib, libsmi, w_idx, l_idx, 10);

            // Show divergent section
            let div_end_w = new_w.min(end_w);
            let div_end_l = new_l.min(end_l);

            for i in 0..(div_end_w - w_idx).max(div_end_l - l_idx) {
                let w = wasmib.get(w_idx + i);
                let l = libsmi.get(l_idx + i);
                print_diff_line(w_idx + i, w, l_idx + i, l, true);
            }

            shown_ranges.push((start_w, div_end_w));
        }

        // Advance past divergence
        let (new_w, new_l) = find_resync_point(wasmib, libsmi, w_idx, l_idx, 10);
        w_idx = new_w;
        l_idx = new_l;
    }
}

/// Find a point where both streams resync.
fn find_resync_point(
    wasmib: &[ParsedToken],
    libsmi: &[ParsedToken],
    w_start: usize,
    l_start: usize,
    max_look: usize,
) -> (usize, usize) {
    for offset in 1..=max_look {
        // Check if wasmib has extra tokens
        if w_start + offset < wasmib.len() && l_start < libsmi.len() {
            if wasmib[w_start + offset].kind == libsmi[l_start].kind {
                return (w_start + offset, l_start);
            }
        }
        // Check if libsmi has extra tokens
        if w_start < wasmib.len() && l_start + offset < libsmi.len() {
            if wasmib[w_start].kind == libsmi[l_start + offset].kind {
                return (w_start, l_start + offset);
            }
        }
        // Check diagonal
        if w_start + offset < wasmib.len() && l_start + offset < libsmi.len() {
            if wasmib[w_start + offset].kind == libsmi[l_start + offset].kind {
                return (w_start + offset, l_start + offset);
            }
        }
    }
    // No resync found, advance both by 1
    (w_start + 1, l_start + 1)
}

/// Print a single diff line.
fn print_diff_line(w_idx: usize, w: Option<&ParsedToken>, l_idx: usize, l: Option<&ParsedToken>, is_diff: bool) {
    let marker = if is_diff { ">>>" } else { "   " };

    let w_str = match w {
        Some(t) => format!("{}:{} {} {:?}", t.line, t.col, t.kind, truncate(&t.text, 15)),
        None => "(end)".to_string(),
    };

    let l_str = match l {
        Some(t) => format!("{}:{} {} {:?}", t.line, t.col, t.kind, truncate(&t.text, 15)),
        None => "(end)".to_string(),
    };

    let match_marker = match (w, l) {
        (Some(wt), Some(lt)) if wt.kind == lt.kind => " ",
        _ => "!",
    };

    println!(
        "{} {:>5} {:>38} {} {:>5} {:>38}",
        marker, w_idx, w_str, match_marker, l_idx, l_str
    );
}

/// Summarize the types of differences found.
fn summarize_differences(wasmib: &[ParsedToken], libsmi: &[ParsedToken]) {
    let mut extra_wasmib_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut extra_libsmi_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut type_mismatches: std::collections::HashMap<(String, String), usize> = std::collections::HashMap::new();

    let mut w_idx = 0;
    let mut l_idx = 0;

    while w_idx < wasmib.len() || l_idx < libsmi.len() {
        let w = wasmib.get(w_idx);
        let l = libsmi.get(l_idx);

        match (w, l) {
            (Some(wt), Some(lt)) if wt.kind == lt.kind => {
                w_idx += 1;
                l_idx += 1;
            }
            (Some(wt), Some(lt)) => {
                // Type mismatch - try to determine if it's extra tokens or true mismatch
                let w_ahead = wasmib.get(w_idx + 1).map(|t| &t.kind);
                let l_ahead = libsmi.get(l_idx + 1).map(|t| &t.kind);

                if w_ahead == Some(&lt.kind) {
                    // wasmib has extra token
                    *extra_wasmib_types.entry(wt.kind.clone()).or_insert(0) += 1;
                    w_idx += 1;
                } else if l_ahead == Some(&wt.kind) {
                    // libsmi has extra token
                    *extra_libsmi_types.entry(lt.kind.clone()).or_insert(0) += 1;
                    l_idx += 1;
                } else {
                    // True type mismatch
                    *type_mismatches.entry((wt.kind.clone(), lt.kind.clone())).or_insert(0) += 1;
                    w_idx += 1;
                    l_idx += 1;
                }
            }
            (Some(wt), None) => {
                *extra_wasmib_types.entry(wt.kind.clone()).or_insert(0) += 1;
                w_idx += 1;
            }
            (None, Some(lt)) => {
                *extra_libsmi_types.entry(lt.kind.clone()).or_insert(0) += 1;
                l_idx += 1;
            }
            (None, None) => break,
        }
    }

    if !extra_wasmib_types.is_empty() {
        println!("Extra tokens in wasmib (not in libsmi):");
        let mut sorted: Vec<_> = extra_wasmib_types.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in sorted.iter().take(10) {
            println!("  {}: {}", kind, count);
        }
    }

    if !extra_libsmi_types.is_empty() {
        println!("\nExtra tokens in libsmi (not in wasmib):");
        let mut sorted: Vec<_> = extra_libsmi_types.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in sorted.iter().take(10) {
            println!("  {}: {}", kind, count);
        }
    }

    if !type_mismatches.is_empty() {
        println!("\nType mismatches (wasmib -> libsmi):");
        let mut sorted: Vec<_> = type_mismatches.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for ((w_kind, l_kind), count) in sorted.iter().take(10) {
            println!("  {} -> {}: {}", w_kind, l_kind, count);
        }
    }
}

/// Compare all files in a directory recursively.
fn corpus_compare(dir: &str) {
    let mut identical = 0;
    let mut content_diff = 0;
    let mut non_structural = 0;
    let mut structural_diff = 0;
    let mut non_structural_files = Vec::new();
    let mut structural_diff_files = Vec::new();
    let mut errors = 0;

    for entry in walkdir(dir) {
        let path = entry.to_string_lossy();

        // Skip very small files (likely not MIBs)
        if let Ok(meta) = fs::metadata(&entry) {
            if meta.len() < 10 {
                continue;
            }
        }

        let source = match fs::read(&entry) {
            Ok(bytes) => bytes,
            Err(_) => {
                errors += 1;
                continue;
            }
        };

        let wasmib_tokens = tokenize_wasmib(&source);
        let libsmi_tokens = match tokenize_libsmi(&path) {
            Ok(tokens) => tokens,
            Err(_) => {
                errors += 1;
                continue;
            }
        };

        let result = compare_tokens(&wasmib_tokens, &libsmi_tokens);

        match result.category {
            DiffCategory::Identical => identical += 1,
            DiffCategory::ContentOnly => content_diff += 1,
            DiffCategory::NonStructuralOnly => {
                non_structural += 1;
                non_structural_files.push((entry.clone(), result));
            }
            _ => {
                structural_diff += 1;
                structural_diff_files.push((entry.clone(), result));
            }
        }
    }

    let total = identical + content_diff + non_structural + structural_diff;
    println!("=== Corpus Comparison: {} ===\n", dir);
    println!("Total files: {}", total);
    println!("\x1b[32mIdentical:\x1b[0m {}", identical);
    println!("\x1b[32mContent differs (structural match):\x1b[0m {}", content_diff);
    println!("\x1b[33mNon-structural only (ERROR tokens/line nums):\x1b[0m {}", non_structural);
    println!("\x1b[31mStructural differences:\x1b[0m {}", structural_diff);
    if errors > 0 {
        println!("Errors: {}", errors);
    }

    if !non_structural_files.is_empty() {
        println!("\nFiles with non-structural differences (OK for parsing):");
        for (path, result) in &non_structural_files {
            println!(
                "  {} (w={}, l={})",
                path.display(),
                result.wasmib_count,
                result.libsmi_count
            );
        }
    }

    if !structural_diff_files.is_empty() {
        println!("\nFiles with STRUCTURAL differences (may affect parsing):");
        for (path, result) in &structural_diff_files {
            println!(
                "  {} ({:?}, w={}, l={})",
                path.display(),
                result.category,
                result.wasmib_count,
                result.libsmi_count
            );
        }
    }
}

/// Recursively walk a directory.
fn walkdir(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walkdir_impl(Path::new(dir), &mut files);
    files
}

fn walkdir_impl(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walkdir_impl(&path, files);
        } else if path.is_file() {
            files.push(path);
        }
    }
}

/// Tokenize using wasmib lexer.
fn tokenize_wasmib(source: &[u8]) -> Vec<ParsedToken> {
    let line_offsets = compute_line_offsets(source);
    let lexer = Lexer::new(source);
    let (tokens, _diagnostics) = lexer.tokenize();

    tokens
        .into_iter()
        .map(|t| {
            let (line, col) = offset_to_line_col(&line_offsets, t.span.start as usize);
            let text = &source[t.span.start as usize..t.span.end as usize];
            ParsedToken {
                line: line as u32,
                col: col as u32,
                kind: token_kind_name(t.kind).to_string(),
                text: escape_bytes(text),
            }
        })
        .collect()
}

/// Tokenize using libsmi tokenizer (via subprocess).
fn tokenize_libsmi(path: &str) -> Result<Vec<ParsedToken>, String> {
    // Find the libsmi tokenizer
    let tokenizer_path = find_libsmi_tokenizer()?;

    let output = Command::new(&tokenizer_path)
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("Failed to run tokenizer: {e}"))?;

    let mut tokens = Vec::new();

    // Split on newlines and handle non-UTF-8 bytes with lossy conversion
    for line_bytes in output.stdout.split(|&b| b == b'\n') {
        if line_bytes.is_empty() {
            continue;
        }

        // Convert to string, replacing invalid UTF-8 with replacement char
        let line = String::from_utf8_lossy(line_bytes);

        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 2 {
            continue;
        }

        // Parse "LINE:COL"
        let pos_parts: Vec<&str> = parts[0].splitn(2, ':').collect();
        if pos_parts.len() != 2 {
            continue;
        }

        let line_num: u32 = pos_parts[0].parse().unwrap_or(0);
        let col_num: u32 = pos_parts[1].parse().unwrap_or(0);
        let kind = parts[1].to_string();
        let text = parts.get(2).unwrap_or(&"").to_string();

        tokens.push(ParsedToken {
            line: line_num,
            col: col_num,
            kind,
            text,
        });
    }

    Ok(tokens)
}

/// Find the libsmi tokenizer binary.
fn find_libsmi_tokenizer() -> Result<PathBuf, String> {
    // Try relative to current exe
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            // crates/wasmib-std/target/release/lexer_cmp -> tools/libsmi-tokenizer/tokenizer
            let candidates = [
                parent.join("../../tools/libsmi-tokenizer/tokenizer"),
                parent.join("../../../tools/libsmi-tokenizer/tokenizer"),
                parent.join("../../../../tools/libsmi-tokenizer/tokenizer"),
            ];
            for candidate in &candidates {
                if candidate.exists() {
                    return Ok(candidate.canonicalize().unwrap_or_else(|_| candidate.clone()));
                }
            }
        }
    }

    // Try relative to CWD
    let cwd_candidate = PathBuf::from("tools/libsmi-tokenizer/tokenizer");
    if cwd_candidate.exists() {
        return Ok(cwd_candidate);
    }

    Err("Could not find libsmi tokenizer. Run: cd tools/libsmi-tokenizer && make".to_string())
}

/// Compare two token streams.
fn compare_tokens(wasmib: &[ParsedToken], libsmi: &[ParsedToken]) -> CompareResult {
    // Filter to structural tokens only (ignore ERROR tokens)
    let wasmib_structural: Vec<&ParsedToken> = wasmib.iter().filter(|t| is_structural_token(&t.kind)).collect();
    let libsmi_structural: Vec<&ParsedToken> = libsmi.iter().filter(|t| is_structural_token(&t.kind)).collect();

    let wasmib_struct_kinds: Vec<&str> = wasmib_structural.iter().map(|t| t.kind.as_str()).collect();
    let libsmi_struct_kinds: Vec<&str> = libsmi_structural.iter().map(|t| t.kind.as_str()).collect();

    // Check if structural tokens are identical (ignoring line numbers)
    if wasmib_struct_kinds == libsmi_struct_kinds {
        // Structural tokens match - check if content matches too
        let wasmib_struct_content: Vec<(&str, &str)> = wasmib_structural.iter().map(|t| (t.kind.as_str(), t.text.as_str())).collect();
        let libsmi_struct_content: Vec<(&str, &str)> = libsmi_structural.iter().map(|t| (t.kind.as_str(), t.text.as_str())).collect();

        // Check full token streams for complete identity
        let wasmib_kinds: Vec<&str> = wasmib.iter().map(|t| t.kind.as_str()).collect();
        let libsmi_kinds: Vec<&str> = libsmi.iter().map(|t| t.kind.as_str()).collect();

        let category = if wasmib_kinds == libsmi_kinds {
            // All tokens identical in kind
            let wasmib_full: Vec<(&str, &str)> = wasmib.iter().map(|t| (t.kind.as_str(), t.text.as_str())).collect();
            let libsmi_full: Vec<(&str, &str)> = libsmi.iter().map(|t| (t.kind.as_str(), t.text.as_str())).collect();
            if wasmib_full == libsmi_full {
                DiffCategory::Identical
            } else {
                DiffCategory::ContentOnly
            }
        } else if wasmib_struct_content == libsmi_struct_content {
            // Structural tokens identical in kind AND content, only ERROR tokens differ
            DiffCategory::NonStructuralOnly
        } else {
            // Structural kinds match but content differs (e.g., different identifier text)
            DiffCategory::ContentOnly
        };

        return CompareResult {
            category,
            wasmib_count: wasmib.len(),
            libsmi_count: libsmi.len(),
            diverge_wasmib_idx: None,
            diverge_libsmi_idx: None,
        };
    }

    // Structural tokens differ - find first divergence in structural stream
    let mut w_idx = 0;
    let mut l_idx = 0;
    while w_idx < wasmib_struct_kinds.len() && l_idx < libsmi_struct_kinds.len() {
        if wasmib_struct_kinds[w_idx] != libsmi_struct_kinds[l_idx] {
            break;
        }
        w_idx += 1;
        l_idx += 1;
    }

    // Map back to original indices for reporting
    let orig_w_idx = if w_idx < wasmib_structural.len() {
        wasmib.iter().position(|t| std::ptr::eq(t, *wasmib_structural.get(w_idx).unwrap_or(&wasmib_structural[0])))
    } else {
        Some(wasmib.len())
    };
    let orig_l_idx = if l_idx < libsmi_structural.len() {
        libsmi.iter().position(|t| std::ptr::eq(t, *libsmi_structural.get(l_idx).unwrap_or(&libsmi_structural[0])))
    } else {
        Some(libsmi.len())
    };

    let category = if wasmib_structural.len() > libsmi_structural.len() {
        DiffCategory::ExtraWasmibTokens
    } else if libsmi_structural.len() > wasmib_structural.len() {
        DiffCategory::ExtraLibsmiTokens
    } else {
        DiffCategory::TypeMismatch
    };

    CompareResult {
        category,
        wasmib_count: wasmib.len(),
        libsmi_count: libsmi.len(),
        diverge_wasmib_idx: orig_w_idx,
        diverge_libsmi_idx: orig_l_idx,
    }
}

/// Find all divergence points.
fn find_all_divergences(wasmib: &[ParsedToken], libsmi: &[ParsedToken]) -> Vec<(usize, usize)> {
    let mut divergences = Vec::new();
    let mut w_idx = 0;
    let mut l_idx = 0;

    while w_idx < wasmib.len() && l_idx < libsmi.len() {
        if wasmib[w_idx].kind != libsmi[l_idx].kind {
            divergences.push((w_idx, l_idx));

            // Try to re-sync by looking ahead
            let mut synced = false;
            for look_ahead in 1..=5 {
                // Check if wasmib has extra tokens
                if w_idx + look_ahead < wasmib.len() && wasmib[w_idx + look_ahead].kind == libsmi[l_idx].kind {
                    w_idx += look_ahead;
                    synced = true;
                    break;
                }
                // Check if libsmi has extra tokens
                if l_idx + look_ahead < libsmi.len() && wasmib[w_idx].kind == libsmi[l_idx + look_ahead].kind {
                    l_idx += look_ahead;
                    synced = true;
                    break;
                }
            }

            if !synced {
                // Can't re-sync, just advance both
                w_idx += 1;
                l_idx += 1;
            }
        } else {
            w_idx += 1;
            l_idx += 1;
        }
    }

    // Handle remaining tokens
    while w_idx < wasmib.len() {
        divergences.push((w_idx, libsmi.len().saturating_sub(1)));
        w_idx += 1;
    }
    while l_idx < libsmi.len() {
        divergences.push((wasmib.len().saturating_sub(1), l_idx));
        l_idx += 1;
    }

    divergences
}

/// Show brief divergence info.
fn show_divergence_brief(
    source: &[u8],
    wasmib: &[ParsedToken],
    libsmi: &[ParsedToken],
    w_idx: usize,
    l_idx: usize,
) {
    let w_token = wasmib.get(w_idx);
    let l_token = libsmi.get(l_idx);

    if let Some(w) = w_token {
        println!("  At line {}:{}", w.line, w.col);

        // Show source context
        let line_offsets = compute_line_offsets(source);
        if let Some(&line_start) = line_offsets.get(w.line.saturating_sub(1) as usize) {
            let line_end = line_offsets
                .get(w.line as usize)
                .copied()
                .unwrap_or(source.len());
            let line_bytes = &source[line_start..line_end.min(source.len())];
            let line_str = String::from_utf8_lossy(line_bytes);
            println!("  Source: {}", line_str.trim_end());

            // Show hex for non-ASCII around the column
            let col_start = (w.col as usize).saturating_sub(1);
            let col_end = (col_start + 10).min(line_bytes.len());
            if col_start < line_bytes.len() {
                let bytes = &line_bytes[col_start..col_end];
                if bytes.iter().any(|&b| b > 127) {
                    print!("  Bytes:  ");
                    for &b in bytes {
                        print!("{:02x} ", b);
                    }
                    println!();
                }
            }
        }
    }

    print!("  wasmib: ");
    if let Some(w) = w_token {
        println!("{} {:?}", w.kind, truncate(&w.text, 40));
    } else {
        println!("(end)");
    }

    print!("  libsmi: ");
    if let Some(l) = l_token {
        println!("{} {:?}", l.kind, truncate(&l.text, 40));
    } else {
        println!("(end)");
    }
}

/// Show detailed divergence info.
fn show_divergence_detailed(
    source: &[u8],
    wasmib: &[ParsedToken],
    libsmi: &[ParsedToken],
    w_idx: usize,
    l_idx: usize,
) {
    let w_token = wasmib.get(w_idx);
    let l_token = libsmi.get(l_idx);

    // Determine source location
    let (line, col) = if let Some(w) = w_token {
        (w.line, w.col)
    } else if let Some(l) = l_token {
        (l.line, l.col)
    } else {
        (0, 0)
    };

    println!("Location: line {}, col {}", line, col);
    println!();

    // Show source context (3 lines before, error line, 2 lines after)
    let line_offsets = compute_line_offsets(source);
    let start_line = line.saturating_sub(3) as usize;
    let end_line = (line as usize + 3).min(line_offsets.len());

    println!("Source context:");
    for ln in start_line..end_line {
        let line_num = ln + 1;
        let line_start = line_offsets.get(ln).copied().unwrap_or(source.len());
        let line_end = line_offsets.get(ln + 1).copied().unwrap_or(source.len());
        let line_bytes = &source[line_start..line_end.min(source.len())];
        let line_str = String::from_utf8_lossy(line_bytes);

        let marker = if line_num == line as usize { ">>>" } else { "   " };
        println!("{} {:4}: {}", marker, line_num, line_str.trim_end());

        // Show hex dump for the error line
        if line_num == line as usize {
            // Find interesting bytes around the column
            let col_idx = (col as usize).saturating_sub(1);
            if col_idx < line_bytes.len() {
                let start = col_idx.saturating_sub(5);
                let end = (col_idx + 15).min(line_bytes.len());
                let bytes = &line_bytes[start..end];

                print!("         Hex: ");
                for (i, &b) in bytes.iter().enumerate() {
                    if i + start == col_idx {
                        print!("[{:02x}]", b);
                    } else {
                        print!("{:02x} ", b);
                    }
                }
                println!();

                // Identify any interesting characters
                for (i, &b) in bytes.iter().enumerate() {
                    if b > 127 {
                        let abs_pos = start + i;
                        // Try to decode as UTF-8
                        let remaining = &line_bytes[start + i..];
                        if let Ok(s) = std::str::from_utf8(&remaining[..remaining.len().min(4)]) {
                            if let Some(c) = s.chars().next() {
                                println!("         Col {}: U+{:04X} '{}'", abs_pos + 1, c as u32, c);
                            }
                        }
                    }
                }
            }
        }
    }
    println!();

    // Show token context
    println!("Token context (wasmib):");
    let start = w_idx.saturating_sub(2);
    let end = (w_idx + 3).min(wasmib.len());
    for i in start..end {
        let marker = if i == w_idx { ">>>" } else { "   " };
        let t = &wasmib[i];
        println!("{} [{}] {}:{} {} {:?}", marker, i, t.line, t.col, t.kind, truncate(&t.text, 30));
    }
    println!();

    println!("Token context (libsmi):");
    let start = l_idx.saturating_sub(2);
    let end = (l_idx + 3).min(libsmi.len());
    for i in start..end {
        let marker = if i == l_idx { ">>>" } else { "   " };
        let t = &libsmi[i];
        println!("{} [{}] {}:{} {} {:?}", marker, i, t.line, t.col, t.kind, truncate(&t.text, 30));
    }
}

/// Compute byte offsets for the start of each line.
fn compute_line_offsets(source: &[u8]) -> Vec<usize> {
    let mut offsets = vec![0];
    for (i, &b) in source.iter().enumerate() {
        if b == b'\n' {
            offsets.push(i + 1);
        }
    }
    offsets
}

/// Convert byte offset to 1-based line and column.
fn offset_to_line_col(line_offsets: &[usize], offset: usize) -> (usize, usize) {
    let line_idx = match line_offsets.binary_search(&offset) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    };
    let line = line_idx + 1;
    let col = offset - line_offsets[line_idx] + 1;
    (line, col)
}

/// Escape bytes for display.
fn escape_bytes(bytes: &[u8]) -> String {
    let text_str = String::from_utf8_lossy(bytes);
    let mut result = String::with_capacity(bytes.len());
    for c in text_str.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

/// Truncate a string for display.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Map token kind to name (matching libsmi output).
fn token_kind_name(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Error => "ERROR",
        TokenKind::Eof => "EOF",
        TokenKind::ForbiddenKeyword => "FORBIDDEN_KEYWORD",
        TokenKind::UppercaseIdent => "UPPERCASE_IDENTIFIER",
        TokenKind::LowercaseIdent => "LOWERCASE_IDENTIFIER",
        TokenKind::Number => "NUMBER",
        TokenKind::NegativeNumber => "NEGATIVENUMBER",
        TokenKind::QuotedString => "QUOTED_STRING",
        TokenKind::HexString => "HEX_STRING",
        TokenKind::BinString => "BIN_STRING",
        TokenKind::LBracket => "LBRACKET",
        TokenKind::RBracket => "RBRACKET",
        TokenKind::LBrace => "LBRACE",
        TokenKind::RBrace => "RBRACE",
        TokenKind::LParen => "LPAREN",
        TokenKind::RParen => "RPAREN",
        TokenKind::Colon => "COLON",
        TokenKind::Semicolon => "SEMICOLON",
        TokenKind::Comma => "COMMA",
        TokenKind::Dot => "DOT",
        TokenKind::Pipe => "PIPE",
        TokenKind::Minus => "MINUS",
        TokenKind::DotDot => "DOT_DOT",
        TokenKind::ColonColonEqual => "COLON_COLON_EQUAL",
        TokenKind::KwDefinitions => "DEFINITIONS",
        TokenKind::KwBegin => "BEGIN",
        TokenKind::KwEnd => "END",
        TokenKind::KwImports => "IMPORTS",
        TokenKind::KwExports => "EXPORTS",
        TokenKind::KwFrom => "FROM",
        TokenKind::KwObject => "OBJECT",
        TokenKind::KwIdentifier => "IDENTIFIER",
        TokenKind::KwSequence => "SEQUENCE",
        TokenKind::KwOf => "OF",
        TokenKind::KwChoice => "CHOICE",
        TokenKind::KwMacro => "MACRO",
        TokenKind::KwSyntax => "SYNTAX",
        TokenKind::KwMaxAccess => "MAX_ACCESS",
        TokenKind::KwMinAccess => "MIN_ACCESS",
        TokenKind::KwAccess => "ACCESS",
        TokenKind::KwStatus => "STATUS",
        TokenKind::KwDescription => "DESCRIPTION",
        TokenKind::KwReference => "REFERENCE",
        TokenKind::KwIndex => "INDEX",
        TokenKind::KwDefval => "DEFVAL",
        TokenKind::KwAugments => "AUGMENTS",
        TokenKind::KwUnits => "UNITS",
        TokenKind::KwDisplayHint => "DISPLAY_HINT",
        TokenKind::KwObjects => "OBJECTS",
        TokenKind::KwNotifications => "NOTIFICATIONS",
        TokenKind::KwModule => "MODULE",
        TokenKind::KwMandatoryGroups => "MANDATORY_GROUPS",
        TokenKind::KwGroup => "GROUP",
        TokenKind::KwWriteSyntax => "WRITE_SYNTAX",
        TokenKind::KwProductRelease => "PRODUCT_RELEASE",
        TokenKind::KwSupports => "SUPPORTS",
        TokenKind::KwIncludes => "INCLUDES",
        TokenKind::KwVariation => "VARIATION",
        TokenKind::KwCreationRequires => "CREATION_REQUIRES",
        TokenKind::KwRevision => "REVISION",
        TokenKind::KwLastUpdated => "LAST_UPDATED",
        TokenKind::KwOrganization => "ORGANIZATION",
        TokenKind::KwContactInfo => "CONTACT_INFO",
        TokenKind::KwImplied => "IMPLIED",
        TokenKind::KwSize => "SIZE",
        TokenKind::KwEnterprise => "ENTERPRISE",
        TokenKind::KwVariables => "VARIABLES",
        TokenKind::KwModuleIdentity => "MODULE_IDENTITY",
        TokenKind::KwModuleCompliance => "MODULE_COMPLIANCE",
        TokenKind::KwObjectGroup => "OBJECT_GROUP",
        TokenKind::KwNotificationGroup => "NOTIFICATION_GROUP",
        TokenKind::KwAgentCapabilities => "AGENT_CAPABILITIES",
        TokenKind::KwObjectType => "OBJECT_TYPE",
        TokenKind::KwObjectIdentity => "OBJECT_IDENTITY",
        TokenKind::KwNotificationType => "NOTIFICATION_TYPE",
        TokenKind::KwTextualConvention => "TEXTUAL_CONVENTION",
        TokenKind::KwTrapType => "TRAP_TYPE",
        TokenKind::KwInteger => "INTEGER",
        TokenKind::KwInteger32 => "INTEGER32",
        TokenKind::KwUnsigned32 => "UNSIGNED32",
        TokenKind::KwCounter32 => "COUNTER32",
        TokenKind::KwCounter64 => "COUNTER64",
        TokenKind::KwGauge32 => "GAUGE32",
        TokenKind::KwIpAddress => "IPADDRESS",
        TokenKind::KwOpaque => "OPAQUE",
        TokenKind::KwTimeTicks => "TIMETICKS",
        TokenKind::KwBits => "BITS",
        TokenKind::KwOctet => "OCTET",
        TokenKind::KwString => "STRING",
        TokenKind::KwCounter => "COUNTER",
        TokenKind::KwGauge => "GAUGE",
        TokenKind::KwNetworkAddress => "NETWORKADDRESS",
        TokenKind::KwApplication => "APPLICATION",
        TokenKind::KwImplicit => "IMPLICIT",
        TokenKind::KwUniversal => "UNIVERSAL",
        TokenKind::KwCurrent => "CURRENT",
        TokenKind::KwDeprecated => "DEPRECATED",
        TokenKind::KwObsolete => "OBSOLETE",
        TokenKind::KwMandatory => "MANDATORY",
        TokenKind::KwOptional => "OPTIONAL",
        TokenKind::KwReadOnly => "READ_ONLY",
        TokenKind::KwReadWrite => "READ_WRITE",
        TokenKind::KwReadCreate => "READ_CREATE",
        TokenKind::KwWriteOnly => "WRITE_ONLY",
        TokenKind::KwNotAccessible => "NOT_ACCESSIBLE",
        TokenKind::KwAccessibleForNotify => "ACCESSIBLE_FOR_NOTIFY",
        TokenKind::KwNotImplemented => "NOT_IMPLEMENTED",
    }
}
