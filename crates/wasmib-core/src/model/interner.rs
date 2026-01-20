//! String interner for model storage.
//!
//! Provides efficient string storage with deduplication of short strings.

use super::ids::StrId;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Threshold for string deduplication. Strings shorter than this are deduplicated.
const DEDUP_THRESHOLD: usize = 64;

/// String interner with optional deduplication.
///
/// Short strings (<64 bytes) are deduplicated via a lookup table.
/// Long strings (descriptions, etc.) are stored directly without deduplication
/// since they're typically unique.
///
/// # Memory Tradeoff
///
/// Short strings are stored twice: once in `data` (concatenated storage) and once
/// as keys in `dedup` (for O(log n) lookup). This is an intentional tradeoff:
///
/// - **Space cost**: ~2x memory for unique short strings (<64 bytes each)
/// - **Benefit**: O(log n) deduplication checks, crucial for names/types that repeat often
///
/// Alternative designs (offset-based keys, hash maps) were considered but rejected:
/// - Offset-based keys require self-referential structures or unsafe code
/// - Hash-based dedup introduces collision handling complexity
///
/// In practice, short strings are names, type names, and OID labels which have high
/// reuse rates, making the dedup table pay for itself quickly.
#[derive(Clone, Debug)]
pub struct StringInterner {
    /// Concatenated string data.
    data: String,
    /// Offsets into data for each string. offsets[i] is the start of string i.
    offsets: Vec<u32>,
    /// Lookup table for deduplicating short strings.
    ///
    /// Keys are cloned from input strings (not slices into `data`) to avoid
    /// self-referential structures. See struct-level docs for tradeoff rationale.
    dedup: BTreeMap<String, StrId>,
}

impl Default for StringInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl StringInterner {
    /// Create a new string interner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: String::new(),
            offsets: vec![0],
            dedup: BTreeMap::new(),
        }
    }

    /// Intern a string, returning its identifier.
    ///
    /// Short strings are deduplicated; long strings are stored directly.
    pub fn intern(&mut self, s: &str) -> StrId {
        // Check dedup table for short strings
        if s.len() < DEDUP_THRESHOLD {
            if let Some(&id) = self.dedup.get(s) {
                return id;
            }
        }

        // Allocate new string
        self.data.push_str(s);
        self.offsets.push(self.data.len() as u32);

        let id = StrId::from_index(self.offsets.len() - 2).expect("too many strings");

        // Add to dedup table for short strings
        if s.len() < DEDUP_THRESHOLD {
            self.dedup.insert(String::from(s), id);
        }

        id
    }

    /// Get a string by its identifier.
    ///
    /// Returns the interned string, or an empty string if the ID is invalid.
    /// Invalid IDs should not occur in normal operation since all `StrId`s are
    /// created by `intern()`. However, bounds checking is performed to prevent
    /// panics in WASM/no_std environments where panics are unrecoverable.
    ///
    /// # Safety Guarantee
    ///
    /// This method will never panic, even with an invalid `StrId`. In debug
    /// builds, an assertion will fire for invalid IDs to help catch bugs.
    #[must_use]
    pub fn get(&self, id: StrId) -> &str {
        let idx = id.to_index();

        // SAFETY: Bounds checking prevents panics in WASM/no_std environments.
        // In normal operation, all StrIds are created by intern() and are valid.
        // Debug assertion helps catch bugs during development.
        debug_assert!(
            idx + 1 < self.offsets.len(),
            "invalid StrId: index {} out of bounds (offsets len: {})",
            idx,
            self.offsets.len()
        );

        // Use checked indexing with fallback to prevent panics
        let start = self.offsets.get(idx).map_or(0, |&v| v as usize);
        let end = self.offsets.get(idx + 1).map_or(start, |&v| v as usize);

        // Return the slice, or empty string if bounds are invalid
        self.data.get(start..end).unwrap_or("")
    }

    /// Get the total number of interned strings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.offsets.len() - 1
    }

    /// Check if the interner is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the total size of interned string data in bytes.
    #[must_use]
    pub fn data_size(&self) -> usize {
        self.data.len()
    }

    /// Find a string's ID if it exists.
    ///
    /// For short strings (<64 bytes), uses the dedup table for O(log n) lookup.
    /// For long strings, falls back to O(n) scan.
    #[must_use]
    pub fn find(&self, s: &str) -> Option<StrId> {
        // Short strings are in the dedup table - O(log n) lookup
        if s.len() < DEDUP_THRESHOLD {
            return self.dedup.get(s).copied();
        }

        // Long strings require O(n) scan
        for idx in 0..self.len() {
            if let Some(id) = StrId::from_index(idx) {
                if self.get(id) == s {
                    return Some(id);
                }
            }
        }
        None
    }

    /// Decompose the interner into its raw parts for serialization.
    ///
    /// Returns `(data, offsets)` where `data` is the concatenated string buffer
    /// and `offsets[i]` is the start of string `i`.
    #[must_use]
    pub fn into_parts(self) -> (String, Vec<u32>) {
        (self.data, self.offsets)
    }

    /// Reconstruct an interner from raw parts.
    ///
    /// Note: The deduplication table is not rebuilt. This interner can be used
    /// for lookups but will not deduplicate new strings efficiently.
    ///
    /// # Validation
    ///
    /// In debug builds, this function validates that:
    /// - `offsets` is non-empty (contains at least the initial 0)
    /// - `offsets` are monotonically non-decreasing
    /// - All offsets are within bounds of `data.len()`
    ///
    /// Invalid data will trigger a debug assertion. In release builds, invalid
    /// data may cause `get()` to return empty strings for affected indices.
    #[must_use]
    pub fn from_parts(data: String, offsets: Vec<u32>) -> Self {
        // Validate structure in debug builds
        debug_assert!(
            !offsets.is_empty(),
            "offsets must be non-empty (should contain at least initial 0)"
        );
        debug_assert!(
            offsets.first().map_or(true, |&v| v == 0),
            "first offset must be 0, got {:?}",
            offsets.first()
        );
        debug_assert!(
            offsets.windows(2).all(|w| w[0] <= w[1]),
            "offsets must be monotonically non-decreasing"
        );
        debug_assert!(
            offsets.last().map_or(true, |&v| (v as usize) <= data.len()),
            "last offset {} exceeds data length {}",
            offsets.last().unwrap_or(&0),
            data.len()
        );

        Self {
            data,
            offsets,
            dedup: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intern_and_get() {
        let mut interner = StringInterner::new();
        let id = interner.intern("hello");
        assert_eq!(interner.get(id), "hello");
    }

    #[test]
    fn test_multiple_strings() {
        let mut interner = StringInterner::new();
        let id1 = interner.intern("hello");
        let id2 = interner.intern("world");

        assert_eq!(interner.get(id1), "hello");
        assert_eq!(interner.get(id2), "world");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_deduplication() {
        let mut interner = StringInterner::new();
        let id1 = interner.intern("hello");
        let id2 = interner.intern("hello");

        assert_eq!(id1, id2);
        assert_eq!(interner.len(), 1);
    }

    #[test]
    fn test_long_strings_not_deduplicated() {
        let mut interner = StringInterner::new();
        let long = "x".repeat(100);
        let id1 = interner.intern(&long);
        let id2 = interner.intern(&long);

        // Long strings are stored separately (no dedup)
        assert_ne!(id1, id2);
        assert_eq!(interner.len(), 2);
    }

    #[test]
    fn test_empty_string() {
        let mut interner = StringInterner::new();
        let id = interner.intern("");
        assert_eq!(interner.get(id), "");
    }

    #[test]
    fn test_len() {
        let mut interner = StringInterner::new();
        assert!(interner.is_empty());

        interner.intern("a");
        interner.intern("b");
        interner.intern("a"); // deduplicated

        assert_eq!(interner.len(), 2);
    }

    #[test]
    fn test_find_short_string() {
        let mut interner = StringInterner::new();
        let id = interner.intern("hello");

        // Short strings use dedup table for O(log n) lookup
        assert_eq!(interner.find("hello"), Some(id));
        assert_eq!(interner.find("world"), None);
    }

    #[test]
    fn test_find_long_string() {
        let mut interner = StringInterner::new();
        let long = "x".repeat(100);
        let id = interner.intern(&long);

        // Long strings require O(n) scan
        assert_eq!(interner.find(&long), Some(id));
        assert_eq!(interner.find(&"y".repeat(100)), None);
    }

    #[test]
    fn test_into_parts_and_from_parts() {
        let mut interner = StringInterner::new();
        let id1 = interner.intern("hello");
        let id2 = interner.intern("world");

        let (data, offsets) = interner.into_parts();
        let restored = StringInterner::from_parts(data, offsets);

        // IDs should still work after round-trip
        assert_eq!(restored.get(id1), "hello");
        assert_eq!(restored.get(id2), "world");
    }

    // Test that get() returns empty string for invalid IDs instead of panicking.
    // This test only runs in release mode since debug builds will trigger assertions.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_get_invalid_id_returns_empty() {
        let interner = StringInterner::new();

        // Create an invalid StrId (index 999 doesn't exist in empty interner)
        // This tests the bounds checking behavior
        if let Some(invalid_id) = StrId::from_index(999) {
            // Should not panic, should return empty string
            assert_eq!(interner.get(invalid_id), "");
        }
    }

    // Test that get() works correctly at boundaries
    #[test]
    fn test_get_at_boundaries() {
        let mut interner = StringInterner::new();

        // Intern several strings
        let id0 = interner.intern("first");
        let id1 = interner.intern("second");
        let id2 = interner.intern("third");

        // All should be retrievable
        assert_eq!(interner.get(id0), "first");
        assert_eq!(interner.get(id1), "second");
        assert_eq!(interner.get(id2), "third");
    }
}
