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
//! Cache files use the `.wmib` extension by convention:
//!
//! ```text
//! ┌────────────────────────────────────────┐
//! │ Header (variable, ~13 or ~45 bytes)    │
//! │   magic: [u8; 4]        "WMIB"         │
//! │   version: u32          Schema version │
//! │   has_fingerprint: u8   0 or 1         │
//! │   fingerprint: [u8; 32] (if present)   │
//! ├────────────────────────────────────────┤
//! │ Payload (postcard-encoded ModelParts)  │
//! └────────────────────────────────────────┘
//! ```
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
use wasmib_core::model::{Model, ModelParts};

/// Current schema version. Bump on any breaking change to serialized format.
pub const SCHEMA_VERSION: u32 = 2;

/// Magic bytes identifying a wasmib cache file.
const MAGIC: [u8; 4] = *b"WMIB";

/// Cache error.
#[derive(Debug)]
pub enum CacheError {
    /// File does not start with expected magic bytes.
    InvalidMagic,
    /// Schema version mismatch.
    VersionMismatch {
        /// Expected version.
        expected: u32,
        /// Found version.
        found: u32,
    },
    /// Fingerprint does not match expected value.
    FingerprintMismatch,
    /// Header is truncated.
    TruncatedHeader,
    /// Postcard deserialization failed.
    DeserializationFailed(postcard::Error),
    /// IO error.
    Io(io::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid magic bytes (expected WMIB)"),
            Self::VersionMismatch { expected, found } => {
                write!(f, "version mismatch: expected {expected}, found {found}")
            }
            Self::FingerprintMismatch => write!(f, "fingerprint mismatch"),
            Self::TruncatedHeader => write!(f, "truncated header"),
            Self::DeserializationFailed(e) => write!(f, "postcard deserialization failed: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeserializationFailed(e) => Some(e),
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
pub fn serialize_model(model: &Model, fingerprint: Option<[u8; 32]>) -> Vec<u8> {
    let parts = model.clone().into_parts();

    // Calculate approximate capacity
    let mut bytes = Vec::with_capacity(1024 * 1024); // 1MB initial capacity

    // Write header
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());

    if let Some(fp) = fingerprint {
        bytes.push(1);
        bytes.extend_from_slice(&fp);
    } else {
        bytes.push(0);
    }

    // Write payload
    let payload = postcard::to_allocvec(&parts).expect("serialization should not fail");
    bytes.extend_from_slice(&payload);

    bytes
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
/// - Magic bytes don't match
/// - Schema version doesn't match
/// - Fingerprint doesn't match (when verification requested)
/// - Postcard deserialization fails
pub fn deserialize_model(
    bytes: &[u8],
    expected_fingerprint: Option<&[u8; 32]>,
) -> Result<Model, CacheError> {
    // Minimum header size: magic(4) + version(4) + has_fp(1) = 9 bytes
    if bytes.len() < 9 {
        return Err(CacheError::TruncatedHeader);
    }

    // Check magic
    if bytes[0..4] != MAGIC {
        return Err(CacheError::InvalidMagic);
    }

    // Check version
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != SCHEMA_VERSION {
        return Err(CacheError::VersionMismatch {
            expected: SCHEMA_VERSION,
            found: version,
        });
    }

    // Check fingerprint
    let has_fingerprint = bytes[8] != 0;
    let payload_start = if has_fingerprint {
        if bytes.len() < 9 + 32 {
            return Err(CacheError::TruncatedHeader);
        }

        // Verify fingerprint if expected
        if let Some(expected) = expected_fingerprint {
            let stored = &bytes[9..41];
            if stored != expected {
                return Err(CacheError::FingerprintMismatch);
            }
        }

        9 + 32
    } else {
        // No fingerprint stored, but verification was requested
        if expected_fingerprint.is_some() {
            return Err(CacheError::FingerprintMismatch);
        }
        9
    };

    // Deserialize payload
    let payload = &bytes[payload_start..];
    let parts: ModelParts =
        postcard::from_bytes(payload).map_err(CacheError::DeserializationFailed)?;

    Ok(Model::from_parts(parts))
}

/// Get the fingerprint from cache bytes without fully deserializing.
///
/// Returns `None` if the cache has no embedded fingerprint.
///
/// # Errors
///
/// Returns an error if the header is invalid.
pub fn get_fingerprint(bytes: &[u8]) -> Result<Option<[u8; 32]>, CacheError> {
    if bytes.len() < 9 {
        return Err(CacheError::TruncatedHeader);
    }

    if bytes[0..4] != MAGIC {
        return Err(CacheError::InvalidMagic);
    }

    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != SCHEMA_VERSION {
        return Err(CacheError::VersionMismatch {
            expected: SCHEMA_VERSION,
            found: version,
        });
    }

    let has_fingerprint = bytes[8] != 0;
    if has_fingerprint {
        if bytes.len() < 9 + 32 {
            return Err(CacheError::TruncatedHeader);
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&bytes[9..41]);
        Ok(Some(fp))
    } else {
        Ok(None)
    }
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
