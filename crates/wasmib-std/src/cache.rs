//! Model caching with fingerprint support.
//!
//! Provides serialization of the resolved MIB model for fast startup.
//! Supports two workflows:
//!
//! 1. **Generator → Collector**: Generator resolves MIBs and produces cache;
//!    collectors load cache without verification (no MIB files available).
//!
//! 2. **NMS with local MIBs**: Compute fingerprint from MIB files,
//!    verify cache validity on load, regenerate if needed.
//!
//! # File Format
//!
//! Cache files use the `.wmib` extension by convention and contain
//! protobuf-encoded data (see `wasmib.proto`).
//!
//! # Examples
//!
//! ## Generator → Collector Pipeline
//!
//! ```ignore
//! // Generator: resolve and save cache
//! let model = resolve_mibs(&mib_files)?;
//! save_cache(&model, "mibs.wmib", None)?;
//!
//! // Collector: load cache (no verification)
//! let model = load_cache("mibs.wmib")?;
//! ```
//!
//! ## NMS with Fingerprint Verification
//!
//! ```ignore
//! let model = load_mibs_cached(mib_dir, cache_path)?;
//! // Automatically computes fingerprint, validates cache, regenerates if needed
//! ```

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;
use wasmib_core::model::Model;

// Re-export SCHEMA_VERSION from wasmib-wasm for fingerprint computation
pub use wasmib_wasm::cache::VERSION as SCHEMA_VERSION;

/// Cache error.
#[derive(Debug)]
pub enum CacheError {
    /// Schema version mismatch.
    VersionMismatch {
        /// Expected version.
        expected: u32,
        /// Found version.
        found: u32,
    },
    /// Fingerprint does not match expected value.
    FingerprintMismatch,
    /// Protobuf deserialization failed.
    DeserializationFailed,
    /// IO error.
    Io(io::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionMismatch { expected, found } => {
                write!(f, "version mismatch: expected {expected}, found {found}")
            }
            Self::FingerprintMismatch => write!(f, "fingerprint mismatch"),
            Self::DeserializationFailed => write!(f, "protobuf deserialization failed"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CacheError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<wasmib_wasm::cache::CacheError> for CacheError {
    fn from(e: wasmib_wasm::cache::CacheError) -> Self {
        match e {
            wasmib_wasm::cache::CacheError::VersionMismatch { expected, found } => {
                Self::VersionMismatch { expected, found }
            }
            wasmib_wasm::cache::CacheError::FingerprintMismatch => Self::FingerprintMismatch,
            wasmib_wasm::cache::CacheError::DeserializationFailed => Self::DeserializationFailed,
        }
    }
}

/// Compute a fingerprint from MIB file contents.
///
/// The fingerprint includes the schema version to ensure cache invalidation
/// when the format changes. Files are sorted by name for determinism.
///
/// # Arguments
///
/// * `files` - Pairs of `(filename, content)` for all MIB files
///
/// # Returns
///
/// A 32-byte SHA-256 fingerprint.
pub fn compute_fingerprint<S: AsRef<str>>(files: &[(S, &[u8])]) -> [u8; 32] {
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by_key(|(name, _)| name.as_ref());

    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    for (name, content) in sorted {
        hasher.update(name.as_ref().as_bytes());
        hasher.update(content);
    }

    hasher.finalize().into()
}

/// Serialize a model to cache bytes.
///
/// # Arguments
///
/// * `model` - The resolved model to serialize
/// * `fingerprint` - Optional fingerprint to embed (for later verification)
///
/// # Returns
///
/// Serialized bytes suitable for writing to a cache file.
#[must_use]
pub fn serialize_model(model: &Model, fingerprint: Option<[u8; 32]>) -> Vec<u8> {
    wasmib_wasm::cache::serialize_model(model, fingerprint)
}

/// Deserialize a model from cache bytes.
///
/// # Arguments
///
/// * `bytes` - Cache file contents
/// * `expected_fingerprint` - If `Some`, verify the fingerprint matches; if `None`, skip verification
///
/// # Errors
///
/// Returns an error if:
/// - Schema version doesn't match
/// - Fingerprint doesn't match (when verification requested)
/// - Protobuf deserialization fails
pub fn deserialize_model(
    bytes: &[u8],
    expected_fingerprint: Option<&[u8; 32]>,
) -> Result<Model, CacheError> {
    wasmib_wasm::cache::deserialize_model(bytes, expected_fingerprint).map_err(Into::into)
}

/// Get the fingerprint from cache bytes without fully deserializing.
///
/// Returns `None` if the cache has no embedded fingerprint.
///
/// # Errors
///
/// Returns an error if the header is invalid.
pub fn get_fingerprint(bytes: &[u8]) -> Result<Option<[u8; 32]>, CacheError> {
    wasmib_wasm::cache::get_fingerprint(bytes).map_err(Into::into)
}

// === File-based convenience API ===

/// Save a model to a cache file.
///
/// # Arguments
///
/// * `model` - The resolved model to save
/// * `path` - Path to write the cache file
/// * `fingerprint` - Optional fingerprint to embed
///
/// # Errors
///
/// Returns an IO error if the file cannot be written.
pub fn save_cache<P: AsRef<Path>>(
    model: &Model,
    path: P,
    fingerprint: Option<[u8; 32]>,
) -> io::Result<()> {
    let bytes = serialize_model(model, fingerprint);
    fs::write(path, bytes)
}

/// Load a model from a cache file without fingerprint verification.
///
/// Use this for the generator → collector workflow where collectors
/// don't have MIB files to verify against.
///
/// # Errors
///
/// Returns an error if the file cannot be read or the cache is invalid.
pub fn load_cache<P: AsRef<Path>>(path: P) -> Result<Model, CacheError> {
    let bytes = fs::read(path)?;
    deserialize_model(&bytes, None)
}

/// Load a model from a cache file with fingerprint verification.
///
/// Use this when MIB files are available to verify the cache is still valid.
///
/// # Errors
///
/// Returns an error if the file cannot be read, the cache is invalid,
/// or the fingerprint doesn't match.
pub fn load_cache_verified<P: AsRef<Path>>(
    path: P,
    expected_fingerprint: &[u8; 32],
) -> Result<Model, CacheError> {
    let bytes = fs::read(path)?;
    deserialize_model(&bytes, Some(expected_fingerprint))
}

/// Check if a cache file exists and has a matching fingerprint.
///
/// Returns `true` if the cache exists and its fingerprint matches.
/// Returns `false` if the cache doesn't exist, is invalid, or has
/// a different fingerprint.
pub fn is_cache_valid<P: AsRef<Path>>(path: P, expected_fingerprint: &[u8; 32]) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };

    match get_fingerprint(&bytes) {
        Ok(Some(fp)) => fp == *expected_fingerprint,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let files: &[(&str, &[u8])] = &[("a.mib", b"content a"), ("b.mib", b"content b")];

        let fp1 = compute_fingerprint(files);
        let fp2 = compute_fingerprint(files);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_compute_fingerprint_order_independent() {
        let files1: &[(&str, &[u8])] = &[("a.mib", b"content a"), ("b.mib", b"content b")];
        let files2: &[(&str, &[u8])] = &[("b.mib", b"content b"), ("a.mib", b"content a")];

        let fp1 = compute_fingerprint(files1);
        let fp2 = compute_fingerprint(files2);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_compute_fingerprint_content_sensitive() {
        let files1: &[(&str, &[u8])] = &[("a.mib", b"content a")];
        let files2: &[(&str, &[u8])] = &[("a.mib", b"content b")];

        let fp1 = compute_fingerprint(files1);
        let fp2 = compute_fingerprint(files2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_round_trip_no_fingerprint() {
        let model = Model::new();
        let bytes = serialize_model(&model, None);
        let restored = deserialize_model(&bytes, None).unwrap();
        assert_eq!(restored.node_count(), 0);
        assert_eq!(restored.module_count(), 0);
    }

    #[test]
    fn test_round_trip_with_fingerprint() {
        let model = Model::new();
        let fp = [42u8; 32];
        let bytes = serialize_model(&model, Some(fp));
        let restored = deserialize_model(&bytes, Some(&fp)).unwrap();
        assert_eq!(restored.node_count(), 0);
    }

    #[test]
    fn test_fingerprint_mismatch() {
        let model = Model::new();
        let fp = [42u8; 32];
        let wrong_fp = [0u8; 32];
        let bytes = serialize_model(&model, Some(fp));
        let result = deserialize_model(&bytes, Some(&wrong_fp));
        assert!(matches!(result, Err(CacheError::FingerprintMismatch)));
    }

    #[test]
    fn test_file_round_trip() {
        let model = Model::new();
        let fp = [42u8; 32];

        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_owned();

        save_cache(&model, &path, Some(fp)).unwrap();
        let restored = load_cache_verified(&path, &fp).unwrap();
        assert_eq!(restored.node_count(), 0);
    }

    #[test]
    fn test_is_cache_valid() {
        let model = Model::new();
        let fp = [42u8; 32];
        let wrong_fp = [0u8; 32];

        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_owned();

        save_cache(&model, &path, Some(fp)).unwrap();

        assert!(is_cache_valid(&path, &fp));
        assert!(!is_cache_valid(&path, &wrong_fp));
        assert!(!is_cache_valid("/nonexistent/path.wmib", &fp));
    }
}
