//! Model serialization for caching.
//!
//! Provides serialization of the resolved MIB model for fast startup.
//! Uses protobuf format for compact, cross-platform compatible encoding.
//!
//! # Cache Format
//!
//! Cache files use protobuf-encoded `SerializedModel` messages which include:
//! - Schema version for forward compatibility
//! - Optional fingerprint for cache validation
//! - All model data (strings, modules, nodes, types, objects, notifications)
//!
//! # Usage
//!
//! ```ignore
//! // Serialize with fingerprint
//! let bytes = serialize_model(model, Some(fingerprint));
//!
//! // Deserialize without verification (generator → collector)
//! let model = deserialize_model(&bytes, None)?;
//!
//! // Deserialize with verification (NMS with local MIBs)
//! let model = deserialize_model(&bytes, Some(&expected_fp))?;
//! ```

use alloc::vec::Vec;
use core::fmt;
use wasmib_core::model::Model;

use crate::serialize::{self, SCHEMA_VERSION};

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
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch { expected, found } => {
                write!(f, "version mismatch: expected {expected}, found {found}")
            }
            Self::FingerprintMismatch => write!(f, "fingerprint mismatch"),
            Self::DeserializationFailed => write!(f, "protobuf deserialization failed"),
        }
    }
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
    serialize::to_bytes(model, fingerprint)
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
    // Check version first
    let version = serialize::get_version(bytes).map_err(|_| CacheError::DeserializationFailed)?;
    if version != SCHEMA_VERSION {
        return Err(CacheError::VersionMismatch {
            expected: SCHEMA_VERSION,
            found: version,
        });
    }

    // Check fingerprint if verification requested
    if let Some(expected) = expected_fingerprint {
        let stored =
            serialize::get_fingerprint(bytes).map_err(|_| CacheError::DeserializationFailed)?;
        match stored {
            Some(fp) if fp == *expected => {}
            _ => return Err(CacheError::FingerprintMismatch),
        }
    }

    // Deserialize the model
    serialize::from_bytes(bytes).map_err(|_| CacheError::DeserializationFailed)
}

/// Get the fingerprint from cache bytes without fully deserializing.
///
/// Returns `None` if the cache has no embedded fingerprint.
///
/// # Errors
///
/// Returns an error if the header is invalid.
pub fn get_fingerprint(bytes: &[u8]) -> Result<Option<[u8; 32]>, CacheError> {
    // Check version first
    let version = serialize::get_version(bytes).map_err(|_| CacheError::DeserializationFailed)?;
    if version != SCHEMA_VERSION {
        return Err(CacheError::VersionMismatch {
            expected: SCHEMA_VERSION,
            found: version,
        });
    }

    serialize::get_fingerprint(bytes).map_err(|_| CacheError::DeserializationFailed)
}

/// Re-export `SCHEMA_VERSION` for downstream consumers.
pub use crate::serialize::SCHEMA_VERSION as VERSION;

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_get_fingerprint() {
        let model = Model::new();
        let fp = [42u8; 32];
        let bytes = serialize_model(&model, Some(fp));
        let extracted = get_fingerprint(&bytes).unwrap();
        assert_eq!(extracted, Some(fp));
    }

    #[test]
    fn test_get_fingerprint_none() {
        let model = Model::new();
        let bytes = serialize_model(&model, None);
        let extracted = get_fingerprint(&bytes).unwrap();
        assert_eq!(extracted, None);
    }
}
