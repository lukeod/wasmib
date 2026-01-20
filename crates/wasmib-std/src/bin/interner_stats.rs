//! Analyze string interner deduplication effectiveness.
//!
//! Usage: interner_stats --corpus <dir>

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use wasmib_core::hir;
use wasmib_core::model::{Model, StrId};
use wasmib_core::parser::Parser;
use wasmib_core::resolver::Resolver;

fn main() {
    let args: Vec<String> = env::args().collect();

    let corpus_dir = if args.len() > 2 && args[1] == "--corpus" {
        &args[2]
    } else {
        eprintln!("Usage: {} --corpus <dir>", args[0]);
        std::process::exit(1);
    };

    println!("=== String Interner Analysis ===\n");

    // Load corpus
    println!("Loading corpus...");
    let start = Instant::now();
    let model = load_corpus(corpus_dir);
    println!("Loaded in {:?}\n", start.elapsed());

    // Get interner stats
    let interner = model.strings();
    let unique_count = interner.len();
    let data_size = interner.data_size();
    let mem = interner.memory_usage();

    println!("Interner Statistics:");
    println!("  Unique strings: {}", unique_count);
    println!("  Total data size: {} bytes ({:.2} MB)", data_size, data_size as f64 / 1024.0 / 1024.0);
    println!("  Average string length: {:.1} bytes", data_size as f64 / unique_count as f64);
    println!();

    println!("Interner Memory Usage:");
    println!("  Data buffer: {} bytes ({:.2} MB)", mem.data_bytes, mem.data_bytes as f64 / 1024.0 / 1024.0);
    println!("  Offsets vec: {} bytes ({:.2} MB)", mem.offsets_bytes, mem.offsets_bytes as f64 / 1024.0 / 1024.0);
    println!("  Dedup map: {} bytes ({:.2} MB)", mem.dedup_bytes, mem.dedup_bytes as f64 / 1024.0 / 1024.0);
    println!("  Dedup entries: {}", mem.dedup_entry_count);
    println!("  TOTAL: {} bytes ({:.2} MB)", mem.total(), mem.total() as f64 / 1024.0 / 1024.0);
    println!();

    // Analyze string usage patterns by collecting all StrIds used in the model
    println!("Analyzing string usage patterns...");
    let (usage_counts, total_references) = analyze_string_usage(&model);

    println!("  Total string references: {}", total_references);
    println!("  Unique strings referenced: {}", usage_counts.len());
    println!();

    // Calculate deduplication stats
    let mut total_refs_by_length: HashMap<usize, (usize, usize)> = HashMap::new(); // length -> (refs, unique)
    let mut reuse_histogram: HashMap<usize, usize> = HashMap::new(); // reuse_count -> num_strings

    for (&str_id, &count) in &usage_counts {
        let s = model.get_str(str_id);
        let len = s.len();

        let entry = total_refs_by_length.entry(len).or_insert((0, 0));
        entry.0 += count;
        entry.1 += 1;

        *reuse_histogram.entry(count).or_insert(0) += 1;
    }

    // Calculate what size would be without deduplication
    let mut size_without_dedup: usize = 0;
    let mut size_with_dedup: usize = 0;
    let mut short_string_refs: usize = 0;
    let mut short_string_unique: usize = 0;
    let mut long_string_refs: usize = 0;
    let mut long_string_unique: usize = 0;

    for (&str_id, &count) in &usage_counts {
        let s = model.get_str(str_id);
        let len = s.len();

        size_without_dedup += len * count;
        size_with_dedup += len;

        if len < 64 {
            short_string_refs += count;
            short_string_unique += 1;
        } else {
            long_string_refs += count;
            long_string_unique += 1;
        }
    }

    println!("Deduplication Analysis:");
    println!("  Size without dedup: {} bytes ({:.2} MB)", size_without_dedup, size_without_dedup as f64 / 1024.0 / 1024.0);
    println!("  Size with dedup: {} bytes ({:.2} MB)", size_with_dedup, size_with_dedup as f64 / 1024.0 / 1024.0);
    println!("  Space saved: {} bytes ({:.2} MB)", size_without_dedup - size_with_dedup, (size_without_dedup - size_with_dedup) as f64 / 1024.0 / 1024.0);
    println!("  Compression ratio: {:.2}x", size_without_dedup as f64 / size_with_dedup as f64);
    println!();

    println!("Short strings (<64 bytes, deduplicated):");
    println!("  References: {}", short_string_refs);
    println!("  Unique: {}", short_string_unique);
    println!("  Avg reuse: {:.2}x", short_string_refs as f64 / short_string_unique as f64);
    println!();

    println!("Long strings (>=64 bytes, not deduplicated):");
    println!("  References: {}", long_string_refs);
    println!("  Unique: {}", long_string_unique);
    println!("  Avg reuse: {:.2}x", long_string_refs as f64 / long_string_unique.max(1) as f64);
    println!();

    // Show reuse histogram
    println!("String Reuse Distribution:");
    let mut reuse_sorted: Vec<_> = reuse_histogram.iter().collect();
    reuse_sorted.sort_by_key(|(k, _)| *k);

    let mut shown = 0;
    for (reuse_count, num_strings) in &reuse_sorted {
        if shown < 10 || **reuse_count > 100 {
            println!("  Used {}x: {} strings", reuse_count, num_strings);
            shown += 1;
        }
    }
    if reuse_sorted.len() > shown {
        println!("  ... and {} more reuse levels", reuse_sorted.len() - shown);
    }
    println!();

    // Show most reused strings
    let mut by_reuse: Vec<_> = usage_counts.iter().collect();
    by_reuse.sort_by(|a, b| b.1.cmp(a.1));

    println!("Most Reused Strings (top 20):");
    for (str_id, count) in by_reuse.iter().take(20) {
        let s = model.get_str(**str_id);
        let display = if s.len() > 50 {
            format!("{}...", &s[..50])
        } else {
            s.to_string()
        };
        println!("  {:>6}x  {:>3} bytes  {:?}", count, s.len(), display);
    }
    println!();

    // Analyze by string category
    println!("String Categories:");
    let mut keywords = 0usize;
    let mut identifiers = 0usize;
    let mut descriptions = 0usize;
    let mut oid_components = 0usize;
    let mut other = 0usize;

    for &str_id in usage_counts.keys() {
        let s = model.get_str(str_id);
        if s.len() > 100 {
            descriptions += 1;
        } else if s.chars().all(|c| c.is_ascii_digit()) {
            oid_components += 1;
        } else if s.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            identifiers += 1;
        } else if s.len() < 20 && s.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            keywords += 1;
        } else {
            other += 1;
        }
    }

    println!("  Likely descriptions (>100 chars): {}", descriptions);
    println!("  Likely identifiers (uppercase start): {}", identifiers);
    println!("  Likely keywords (short, lowercase): {}", keywords);
    println!("  Numeric (OID components?): {}", oid_components);
    println!("  Other: {}", other);
}

/// Collect all StrId usage from the model
fn analyze_string_usage(model: &Model) -> (HashMap<StrId, usize>, usize) {
    let mut counts: HashMap<StrId, usize> = HashMap::new();
    let mut total = 0usize;

    // Modules
    for module in model.modules() {
        *counts.entry(module.name).or_insert(0) += 1;
        total += 1;
        if let Some(id) = module.last_updated {
            *counts.entry(id).or_insert(0) += 1;
            total += 1;
        }
        if let Some(id) = module.organization {
            *counts.entry(id).or_insert(0) += 1;
            total += 1;
        }
        if let Some(id) = module.contact_info {
            *counts.entry(id).or_insert(0) += 1;
            total += 1;
        }
        if let Some(id) = module.description {
            *counts.entry(id).or_insert(0) += 1;
            total += 1;
        }
        for rev in &module.revisions {
            *counts.entry(rev.date).or_insert(0) += 1;
            total += 1;
            *counts.entry(rev.description).or_insert(0) += 1;
            total += 1;
        }
    }

    // Nodes
    for root_id in model.root_ids() {
        count_node_strings(model, *root_id, &mut counts, &mut total);
    }

    // Types
    for i in 0..model.type_count() {
        if let Some(typ) = model.get_type(wasmib_core::model::TypeId::from_index(i).unwrap()) {
            *counts.entry(typ.name).or_insert(0) += 1;
            total += 1;
            if let Some(id) = typ.hint {
                *counts.entry(id).or_insert(0) += 1;
                total += 1;
            }
            if let Some(id) = typ.description {
                *counts.entry(id).or_insert(0) += 1;
                total += 1;
            }
            if let Some(ref enums) = typ.enum_values {
                for (_, label) in &enums.values {
                    *counts.entry(*label).or_insert(0) += 1;
                    total += 1;
                }
            }
            if let Some(ref bits) = typ.bit_defs {
                for (_, label) in &bits.bits {
                    *counts.entry(*label).or_insert(0) += 1;
                    total += 1;
                }
            }
        }
    }

    // Objects
    for i in 0..model.object_count() {
        if let Some(obj) = model.get_object(wasmib_core::model::ObjectId::from_index(i).unwrap()) {
            *counts.entry(obj.name).or_insert(0) += 1;
            total += 1;
            if let Some(id) = obj.description {
                *counts.entry(id).or_insert(0) += 1;
                total += 1;
            }
            if let Some(id) = obj.units {
                *counts.entry(id).or_insert(0) += 1;
                total += 1;
            }
            if let Some(id) = obj.reference {
                *counts.entry(id).or_insert(0) += 1;
                total += 1;
            }
            if let Some(ref enums) = obj.inline_enum {
                for (_, label) in &enums.values {
                    *counts.entry(*label).or_insert(0) += 1;
                    total += 1;
                }
            }
            if let Some(ref bits) = obj.inline_bits {
                for (_, label) in &bits.bits {
                    *counts.entry(*label).or_insert(0) += 1;
                    total += 1;
                }
            }
        }
    }

    // Notifications
    for i in 0..model.notification_count() {
        if let Some(notif) = model.get_notification(wasmib_core::model::NotificationId::from_index(i).unwrap()) {
            *counts.entry(notif.name).or_insert(0) += 1;
            total += 1;
            if let Some(id) = notif.description {
                *counts.entry(id).or_insert(0) += 1;
                total += 1;
            }
            if let Some(id) = notif.reference {
                *counts.entry(id).or_insert(0) += 1;
                total += 1;
            }
        }
    }

    // Unresolved
    for imp in &model.unresolved().imports {
        *counts.entry(imp.from_module).or_insert(0) += 1;
        total += 1;
        *counts.entry(imp.symbol).or_insert(0) += 1;
        total += 1;
    }
    for typ in &model.unresolved().types {
        *counts.entry(typ.referrer).or_insert(0) += 1;
        total += 1;
        *counts.entry(typ.referenced).or_insert(0) += 1;
        total += 1;
    }
    for oid in &model.unresolved().oids {
        *counts.entry(oid.definition).or_insert(0) += 1;
        total += 1;
        *counts.entry(oid.component).or_insert(0) += 1;
        total += 1;
    }
    for idx in &model.unresolved().indexes {
        *counts.entry(idx.row).or_insert(0) += 1;
        total += 1;
        *counts.entry(idx.index_object).or_insert(0) += 1;
        total += 1;
    }

    (counts, total)
}

fn count_node_strings(
    model: &Model,
    node_id: wasmib_core::model::NodeId,
    counts: &mut HashMap<StrId, usize>,
    total: &mut usize,
) {
    if let Some(node) = model.get_node(node_id) {
        for def in &node.definitions {
            *counts.entry(def.label).or_insert(0) += 1;
            *total += 1;
        }
        for child_id in &node.children {
            count_node_strings(model, *child_id, counts, total);
        }
    }
}

fn load_corpus(dir: &str) -> Model {
    let files = collect_mib_files(dir);
    eprintln!("  Found {} MIB files", files.len());

    let mut hir_modules = Vec::new();

    for path in &files {
        let content = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let parser = Parser::new(&content);
        let ast_module = parser.parse_module();
        let hir_module = hir::lower_module(&ast_module);
        hir_modules.push(hir_module);
    }

    let resolver = Resolver::new();
    resolver.resolve(hir_modules).model
}

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
