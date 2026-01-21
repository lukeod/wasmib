//! wasmib-std: Filesystem loader and CLI utilities
//!
//! This crate provides convenience utilities for native Rust usage,
//! including filesystem-based MIB loading and CLI tools.

use std::fs;
use std::path::{Path, PathBuf};

pub mod cache;

pub use wasmib_core;

/// Recursively collect MIB files from a directory.
///
/// Includes files with no extension, or `.mib`, `.txt`, `.my` extensions.
pub fn collect_mib_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files_recursive(dir, &mut files);
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
