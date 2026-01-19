//! Parser comparison tool for validating wasmib parser against libsmi.
//!
//! Usage:
//!   parser_cmp <file>              Compare single file
//!   parser_cmp --corpus <dir>      Compare all files, summarize differences
//!   parser_cmp --analyze <file>    Detailed analysis of differences
//!   parser_cmp --names <file>      Just list definition names from wasmib
//!
//! This tool compares:
//! - Definition names (exact match)
//! - Definition types (wasmib AST types vs smidump kinds)
//!
//! Note: smidump performs resolution, so some differences (nodekinds, resolved OIDs)
//! are expected until wasmib implements its resolver.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wasmib_core::ast::{Definition, TypeSyntax};
use wasmib_core::lexer::Severity;
use wasmib_core::parser::Parser;

/// A parsed definition from either parser (for comparison).
#[derive(Debug, Clone)]
struct ParsedDef {
    module: String,
    name: String,
    kind: String, // "type", "node", "scalar", "row", "table", "column", etc.
    oid: Option<String>,
}

/// Comparison result for a single file.
#[derive(Debug)]
struct CompareResult {
    module_name: String,
    wasmib_count: usize,
    libsmi_count: usize,
    wasmib_only: Vec<String>,
    libsmi_only: Vec<String>,
    kind_mismatches: Vec<(String, String, String)>, // (name, wasmib_kind, libsmi_kind)
    wasmib_errors: usize,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} <file>              Compare single file", args[0]);
        eprintln!("  {} --corpus <dir>      Compare all files in directory", args[0]);
        eprintln!("  {} --analyze <file>    Detailed analysis of differences", args[0]);
        eprintln!("  {} --names <file>      List definition names from wasmib", args[0]);
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
        "--names" => {
            if args.len() < 3 {
                eprintln!("Missing file argument");
                std::process::exit(1);
            }
            list_names(&args[2]);
        }
        path => {
            compare_single(path);
        }
    }
}

/// Parse a file with wasmib and extract definitions.
fn parse_wasmib(source: &[u8]) -> (String, Vec<ParsedDef>, usize) {
    let parser = Parser::new(source);
    let module = parser.parse_module();
    let module_name = module.name.name.clone();
    let error_count = module.diagnostics.iter().filter(|d| d.severity == Severity::Error).count();

    let mut defs = Vec::new();

    for def in &module.body {
        if let Some(name) = def.name() {
            let kind = wasmib_def_kind(def);
            defs.push(ParsedDef {
                module: module_name.clone(),
                name: name.name.clone(),
                kind,
                oid: None, // No resolution yet
            });
        }
    }

    (module_name, defs, error_count)
}

/// Get the kind string for a wasmib definition.
fn wasmib_def_kind(def: &Definition) -> String {
    match def {
        Definition::ObjectType(d) => {
            // Try to infer nodekind from syntax (table if SEQUENCE OF)
            match &d.syntax.syntax {
                TypeSyntax::SequenceOf { .. } => "table".to_string(),
                TypeSyntax::Sequence { .. } => "row-type".to_string(),
                _ => {
                    // Row if has INDEX or AUGMENTS
                    if d.index.is_some() || d.augments.is_some() {
                        "row".to_string()
                    } else {
                        // Without resolution, we can't tell scalar from column
                        "object".to_string()
                    }
                }
            }
        }
        Definition::ModuleIdentity(_) => "node".to_string(),
        Definition::ObjectIdentity(_) => "node".to_string(),
        Definition::NotificationType(_) => "notification".to_string(),
        Definition::TrapType(_) => "notification".to_string(),
        Definition::TextualConvention(_) => "type".to_string(),
        Definition::TypeAssignment(d) => {
            // SEQUENCE definitions for row types
            if matches!(d.syntax, TypeSyntax::Sequence { .. }) {
                "row-type".to_string()
            } else {
                "type".to_string()
            }
        }
        Definition::ValueAssignment(_) => "node".to_string(),
        Definition::ObjectGroup(_) => "group".to_string(),
        Definition::NotificationGroup(_) => "group".to_string(),
        Definition::ModuleCompliance(_) => "compliance".to_string(),
        Definition::AgentCapabilities(_) => "capabilities".to_string(),
        Definition::MacroDefinition(_) => "macro".to_string(),
        Definition::Error(_) => "error".to_string(),
    }
}

/// Run smidump and parse its output.
fn parse_smidump(path: &str) -> Result<Vec<ParsedDef>, String> {
    let output = Command::new("smidump")
        .args(["-f", "identifiers", path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to run smidump: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // smidump writes errors to stderr but may still produce output
        if output.stdout.is_empty() {
            return Err(format!("smidump failed: {}", stderr));
        }
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut defs = Vec::new();

    for line in stdout.lines() {
        // Skip comments and empty lines
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        // Format: MODULE NAME KIND [OID]
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            defs.push(ParsedDef {
                module: parts[0].to_string(),
                name: parts[1].to_string(),
                kind: parts[2].to_string(),
                oid: parts.get(3).map(|s| s.to_string()),
            });
        }
    }

    Ok(defs)
}

/// Compare a single file.
fn compare_single(path: &str) {
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let (module_name, wasmib_defs, error_count) = parse_wasmib(&source);

    let libsmi_defs = match parse_smidump(path) {
        Ok(defs) => defs,
        Err(e) => {
            eprintln!("Warning: {}", e);
            Vec::new()
        }
    };

    let result = compare_defs(&module_name, &wasmib_defs, &libsmi_defs, error_count);
    print_result(&result, path);
}

/// Compare definition lists.
fn compare_defs(
    module_name: &str,
    wasmib_defs: &[ParsedDef],
    libsmi_defs: &[ParsedDef],
    wasmib_errors: usize,
) -> CompareResult {
    let wasmib_names: HashSet<_> = wasmib_defs.iter().map(|d| d.name.as_str()).collect();
    let libsmi_names: HashSet<_> = libsmi_defs.iter().map(|d| d.name.as_str()).collect();

    let wasmib_only: Vec<_> = wasmib_names
        .difference(&libsmi_names)
        .map(|s| s.to_string())
        .collect();

    let libsmi_only: Vec<_> = libsmi_names
        .difference(&wasmib_names)
        .map(|s| s.to_string())
        .collect();

    // Build maps for kind comparison
    let wasmib_map: HashMap<_, _> = wasmib_defs.iter().map(|d| (d.name.as_str(), &d.kind)).collect();
    let libsmi_map: HashMap<_, _> = libsmi_defs.iter().map(|d| (d.name.as_str(), &d.kind)).collect();

    let mut kind_mismatches = Vec::new();
    for name in wasmib_names.intersection(&libsmi_names) {
        let wasmib_kind = wasmib_map[name];
        let libsmi_kind = libsmi_map[name];

        // Check for significant mismatches (ignoring expected differences)
        if !kinds_compatible(wasmib_kind, libsmi_kind) {
            kind_mismatches.push((
                name.to_string(),
                wasmib_kind.clone(),
                libsmi_kind.clone(),
            ));
        }
    }

    CompareResult {
        module_name: module_name.to_string(),
        wasmib_count: wasmib_defs.len(),
        libsmi_count: libsmi_defs.len(),
        wasmib_only,
        libsmi_only,
        kind_mismatches,
        wasmib_errors,
    }
}

/// Check if two kinds are compatible (accounting for resolution differences).
fn kinds_compatible(wasmib: &str, libsmi: &str) -> bool {
    // Exact match
    if wasmib == libsmi {
        return true;
    }

    // wasmib uses "object" for unresolved OBJECT-TYPEs (could be scalar or column)
    if wasmib == "object" && (libsmi == "scalar" || libsmi == "column") {
        return true;
    }

    // row-type is our name for SEQUENCE type definitions, libsmi doesn't list these
    if wasmib == "row-type" {
        return true;
    }

    // macro definitions are skipped by libsmi
    if wasmib == "macro" {
        return true;
    }

    false
}

/// Print comparison result.
fn print_result(result: &CompareResult, path: &str) {
    let is_perfect = result.wasmib_only.is_empty()
        && result.libsmi_only.is_empty()
        && result.kind_mismatches.is_empty()
        && result.wasmib_errors == 0;

    if is_perfect {
        println!(
            "\x1b[32m✓\x1b[0m {} ({} defs match)",
            path, result.wasmib_count
        );
    } else {
        println!(
            "\x1b[33m!\x1b[0m {} wasmib:{} libsmi:{} errs:{}",
            path, result.wasmib_count, result.libsmi_count, result.wasmib_errors
        );

        if !result.libsmi_only.is_empty() {
            println!("  Missing in wasmib: {:?}", result.libsmi_only);
        }
        if !result.wasmib_only.is_empty() {
            println!("  Extra in wasmib: {:?}", result.wasmib_only);
        }
        if !result.kind_mismatches.is_empty() {
            println!("  Kind mismatches:");
            for (name, wasmib_kind, libsmi_kind) in &result.kind_mismatches {
                println!("    {} - wasmib:{} libsmi:{}", name, wasmib_kind, libsmi_kind);
            }
        }
    }
}

/// List definition names from wasmib (for debugging).
fn list_names(path: &str) {
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let (module_name, defs, error_count) = parse_wasmib(&source);

    println!("Module: {}", module_name);
    println!("Definitions: {}", defs.len());
    println!("Parse errors: {}", error_count);
    println!();

    for def in &defs {
        println!("{:<30} {}", def.name, def.kind);
    }
}

/// Analyze a single file in detail.
fn analyze_file(path: &str) {
    let source = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let (module_name, wasmib_defs, error_count) = parse_wasmib(&source);

    println!("=== wasmib parse ===");
    println!("Module: {}", module_name);
    println!("Definitions: {}", wasmib_defs.len());
    println!("Parse errors: {}", error_count);
    println!();

    let parser = Parser::new(&source);
    let module = parser.parse_module();
    if !module.diagnostics.is_empty() {
        println!("Diagnostics:");
        for diag in &module.diagnostics {
            let line = source[..diag.span.start as usize]
                .iter()
                .filter(|&&b| b == b'\n')
                .count()
                + 1;
            println!("  line {}: {}", line, diag.message);
        }
        println!();
    }

    println!("Definitions by type:");
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for def in &wasmib_defs {
        *type_counts.entry(def.kind.clone()).or_insert(0) += 1;
    }
    let mut types: Vec<_> = type_counts.iter().collect();
    types.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (kind, count) in types {
        println!("  {}: {}", kind, count);
    }
    println!();

    let libsmi_defs = match parse_smidump(path) {
        Ok(defs) => defs,
        Err(e) => {
            eprintln!("Warning: {}", e);
            return;
        }
    };

    println!("=== libsmi parse (smidump) ===");
    println!("Definitions: {}", libsmi_defs.len());
    println!();

    println!("Definitions by type:");
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for def in &libsmi_defs {
        *type_counts.entry(def.kind.clone()).or_insert(0) += 1;
    }
    let mut types: Vec<_> = type_counts.iter().collect();
    types.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (kind, count) in types {
        println!("  {}: {}", kind, count);
    }
    println!();

    let result = compare_defs(&module_name, &wasmib_defs, &libsmi_defs, error_count);

    println!("=== Comparison ===");
    if result.libsmi_only.is_empty() && result.wasmib_only.is_empty() {
        println!("All {} definition names match!", result.wasmib_count);
    } else {
        if !result.libsmi_only.is_empty() {
            println!("Missing in wasmib ({}):", result.libsmi_only.len());
            for name in &result.libsmi_only {
                // Find kind in libsmi
                let libsmi_kind = libsmi_defs
                    .iter()
                    .find(|d| &d.name == name)
                    .map(|d| d.kind.as_str())
                    .unwrap_or("?");
                println!("  {} ({})", name, libsmi_kind);
            }
            println!();
        }
        if !result.wasmib_only.is_empty() {
            println!("Extra in wasmib ({}):", result.wasmib_only.len());
            for name in &result.wasmib_only {
                let wasmib_kind = wasmib_defs
                    .iter()
                    .find(|d| &d.name == name)
                    .map(|d| d.kind.as_str())
                    .unwrap_or("?");
                println!("  {} ({})", name, wasmib_kind);
            }
            println!();
        }
    }

    if !result.kind_mismatches.is_empty() {
        println!("Kind mismatches ({}):", result.kind_mismatches.len());
        for (name, wasmib_kind, libsmi_kind) in &result.kind_mismatches {
            println!("  {} - wasmib:{} libsmi:{}", name, wasmib_kind, libsmi_kind);
        }
    }
}

/// Compare all files in a directory.
fn corpus_compare(dir: &str) {
    let mut files = collect_mib_files(dir);
    files.sort();

    let mut identical = 0;
    let mut with_differences = 0;
    let mut parse_errors = 0;
    let mut smidump_errors = 0;
    let mut total_wasmib_defs = 0;
    let mut total_libsmi_defs = 0;
    let mut total_missing = 0;
    let mut total_extra = 0;

    let total_files = files.len();
    println!("Comparing {} files...\n", total_files);

    for (i, path) in files.iter().enumerate() {
        let path_str = path.to_string_lossy();

        let source = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Error reading {}: {}", path_str, e);
                continue;
            }
        };

        let (module_name, wasmib_defs, error_count) = parse_wasmib(&source);
        total_wasmib_defs += wasmib_defs.len();

        if error_count > 0 {
            parse_errors += 1;
        }

        let libsmi_defs = match parse_smidump(&path_str) {
            Ok(defs) => defs,
            Err(_) => {
                smidump_errors += 1;
                Vec::new()
            }
        };
        total_libsmi_defs += libsmi_defs.len();

        let result = compare_defs(&module_name, &wasmib_defs, &libsmi_defs, error_count);

        total_missing += result.libsmi_only.len();
        total_extra += result.wasmib_only.len();

        let is_perfect = result.wasmib_only.is_empty()
            && result.libsmi_only.is_empty()
            && result.kind_mismatches.is_empty();

        if is_perfect && error_count == 0 {
            identical += 1;
        } else {
            with_differences += 1;
            // Only print files with differences
            if !result.libsmi_only.is_empty() || !result.wasmib_only.is_empty() {
                println!(
                    "\x1b[33m!\x1b[0m {} wasmib:{} libsmi:{} missing:{} extra:{} errs:{}",
                    path_str,
                    result.wasmib_count,
                    result.libsmi_count,
                    result.libsmi_only.len(),
                    result.wasmib_only.len(),
                    error_count
                );
            }
        }

        // Progress indicator every 500 files
        if (i + 1) % 500 == 0 {
            eprintln!("Progress: {}/{} files processed...", i + 1, total_files);
        }
    }

    println!();
    println!("=== Summary ===");
    println!("Total files: {}", total_files);
    println!("Identical: {} ({:.1}%)", identical, 100.0 * identical as f64 / total_files as f64);
    println!("With differences: {}", with_differences);
    println!("Files with parse errors: {}", parse_errors);
    println!("Files smidump couldn't parse: {}", smidump_errors);
    println!();
    println!("Total wasmib definitions: {}", total_wasmib_defs);
    println!("Total libsmi definitions: {}", total_libsmi_defs);
    println!("Total missing (in libsmi but not wasmib): {}", total_missing);
    println!("Total extra (in wasmib but not libsmi): {}", total_extra);
}

/// Collect all potential MIB files from a directory.
fn collect_mib_files(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files_recursive(Path::new(dir), &mut files);
    files
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, files);
            } else if path.is_file() {
                // Accept files without extension or common MIB extensions
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext.is_empty()
                    || ext.eq_ignore_ascii_case("mib")
                    || ext.eq_ignore_ascii_case("txt")
                    || ext.eq_ignore_ascii_case("my")
                {
                    files.push(path);
                }
            }
        }
    }
}
