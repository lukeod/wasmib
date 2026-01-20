//! Model serialization for caching.
//!
//! Provides serialization of the resolved MIB model for fast startup.
//! Uses postcard format for compact, `no_std` compatible encoding.
//!
//! # Cache Format
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
    DeserializationFailed,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid magic bytes (expected WMIB)"),
            Self::VersionMismatch { expected, found } => {
                write!(f, "version mismatch: expected {expected}, found {found}")
            }
            Self::FingerprintMismatch => write!(f, "fingerprint mismatch"),
            Self::TruncatedHeader => write!(f, "truncated header"),
            Self::DeserializationFailed => write!(f, "postcard deserialization failed"),
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
pub fn serialize_model(model: Model, fingerprint: Option<[u8; 32]>) -> Vec<u8> {
    let parts = model.into_parts();

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
        postcard::from_bytes(payload).map_err(|_| CacheError::DeserializationFailed)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_no_fingerprint() {
        let model = Model::new();
        let bytes = serialize_model(model, None);
        let restored = deserialize_model(&bytes, None).unwrap();
        assert_eq!(restored.node_count(), 0);
        assert_eq!(restored.module_count(), 0);
    }

    #[test]
    fn test_round_trip_with_fingerprint() {
        let model = Model::new();
        let fp = [42u8; 32];
        let bytes = serialize_model(model, Some(fp));
        let restored = deserialize_model(&bytes, Some(&fp)).unwrap();
        assert_eq!(restored.node_count(), 0);
    }

    #[test]
    fn test_fingerprint_mismatch() {
        let model = Model::new();
        let fp = [42u8; 32];
        let wrong_fp = [0u8; 32];
        let bytes = serialize_model(model, Some(fp));
        let result = deserialize_model(&bytes, Some(&wrong_fp));
        assert!(matches!(result, Err(CacheError::FingerprintMismatch)));
    }

    #[test]
    fn test_get_fingerprint() {
        let model = Model::new();
        let fp = [42u8; 32];
        let bytes = serialize_model(model, Some(fp));
        let extracted = get_fingerprint(&bytes).unwrap();
        assert_eq!(extracted, Some(fp));
    }

    #[test]
    fn test_get_fingerprint_none() {
        let model = Model::new();
        let bytes = serialize_model(model, None);
        let extracted = get_fingerprint(&bytes).unwrap();
        assert_eq!(extracted, None);
    }

    #[test]
    fn test_invalid_magic() {
        let bytes = b"BADM\x01\x00\x00\x00\x00";
        let result = deserialize_model(bytes, None);
        assert!(matches!(result, Err(CacheError::InvalidMagic)));
    }

    #[test]
    fn test_version_mismatch() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&999u32.to_le_bytes());
        bytes.push(0);

        let result = deserialize_model(&bytes, None);
        assert!(matches!(
            result,
            Err(CacheError::VersionMismatch {
                expected: SCHEMA_VERSION,
                found: 999
            })
        ));
    }

    #[test]
    fn test_truncated_header() {
        let bytes = b"WMIB";
        let result = deserialize_model(bytes, None);
        assert!(matches!(result, Err(CacheError::TruncatedHeader)));
    }
}
