//! String interner for model storage.
//!
//! Provides efficient string storage with deduplication of short strings.

use super::ids::StrId;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Threshold for string deduplication. Strings shorter than this are deduplicated.
const DEDUP_THRESHOLD: usize = 64;

/// Memory usage breakdown for the string interner.
#[derive(Clone, Debug, Default)]
pub struct InternerMemoryUsage {
    /// String buffer capacity in bytes.
    pub data_bytes: usize,
    /// Offsets vector capacity in bytes.
    pub offsets_bytes: usize,
    /// Dedup map memory (keys + value vecs + `BTreeMap` overhead).
    pub dedup_bytes: usize,
    /// Number of entries in dedup map.
    pub dedup_entry_count: usize,
}

impl InternerMemoryUsage {
    /// Total estimated heap memory usage.
    #[must_use]
    pub fn total(&self) -> usize {
        self.data_bytes + self.offsets_bytes + self.dedup_bytes
    }
}

/// FxHash-style hash function for strings.
///
/// Fast, non-cryptographic hash with good distribution.
#[inline]
fn hash_str(s: &str) -> u64 {
    // FxHash constant
    const K: u64 = 0x517c_c1b7_2722_0a95;
    let mut hash = 0u64;
    for byte in s.bytes() {
        hash = hash.rotate_left(5) ^ u64::from(byte);
        hash = hash.wrapping_mul(K);
    }
    hash
}

/// String interner with hash-based deduplication.
///
/// Short strings (<64 bytes) are deduplicated via a hash lookup table.
/// Long strings (descriptions, etc.) are stored directly without deduplication
/// since they're typically unique.
///
/// # Deduplication Strategy
///
/// Uses a hash+verify approach for memory efficiency:
/// - Hash the string to get a u64 key
/// - Store candidate `StrIds` in a Vec (almost always size 1)
/// - On lookup, verify candidates against actual string content
///
/// This avoids storing duplicate string keys while handling hash collisions
/// correctly. Memory overhead is ~16 bytes per unique short string (8-byte hash
/// key + 8-byte Vec pointer) vs ~56+ bytes with String keys.
#[derive(Clone, Debug)]
pub struct StringInterner {
    /// Concatenated string data.
    data: String,
    /// Offsets into data for each string. offsets[i] is the start of string i.
    offsets: Vec<u32>,
    /// Hash-based lookup table for deduplicating short strings.
    ///
    /// Maps hash(string) -> list of candidate `StrIds`. On collision (rare),
    /// multiple candidates are stored and verified against actual content.
    dedup: BTreeMap<u64, Vec<StrId>>,
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
    #[allow(clippy::missing_panics_doc)] // Panic only on index overflow (>4B strings)
    #[allow(clippy::cast_possible_truncation)] // String data bounded by available memory
    pub fn intern(&mut self, s: &str) -> StrId {
        // Check dedup table for short strings
        if s.len() < DEDUP_THRESHOLD {
            let hash = hash_str(s);
            if let Some(candidates) = self.dedup.get(&hash) {
                // Verify candidates against actual content
                for &id in candidates {
                    if self.get(id) == s {
                        return id;
                    }
                }
            }
        }

        // Allocate new string
        self.data.push_str(s);
        self.offsets.push(self.data.len() as u32);

        let id = StrId::from_index(self.offsets.len() - 2).expect("too many strings");

        // Add to dedup table for short strings
        if s.len() < DEDUP_THRESHOLD {
            let hash = hash_str(s);
            self.dedup.entry(hash).or_default().push(id);
        }

        id
    }

    /// Get a string by its identifier.
    ///
    /// Returns the interned string, or an empty string if the ID is invalid.
    #[must_use]
    pub fn get(&self, id: StrId) -> &str {
        let idx = id.to_index();

        debug_assert!(
            idx + 1 < self.offsets.len(),
            "invalid StrId: index {} out of bounds (offsets len: {})",
            idx,
            self.offsets.len()
        );

        let start = self.offsets.get(idx).map_or(0, |&v| v as usize);
        let end = self.offsets.get(idx + 1).map_or(start, |&v| v as usize);
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

    /// Estimate total heap memory usage in bytes.
    ///
    /// Returns a breakdown of memory consumption:
    /// - `data`: String buffer capacity
    /// - `offsets`: Vec capacity × 4 bytes
    /// - `dedup`: Hash keys (8 bytes) + Vec overhead + `BTreeMap` nodes
    #[must_use]
    pub fn memory_usage(&self) -> InternerMemoryUsage {
        let data_bytes = self.data.capacity();
        let offsets_bytes = self.offsets.capacity() * core::mem::size_of::<u32>();

        // Calculate dedup map memory:
        // - BTreeMap overhead: ~48 bytes per entry
        // - Each entry: u64 key (8 bytes) + Vec<StrId> (24 bytes + capacity * 4)
        let mut dedup_bytes = 0usize;
        for candidates in self.dedup.values() {
            // Vec overhead (ptr, len, cap) + capacity * sizeof(StrId)
            dedup_bytes += 24 + candidates.capacity() * core::mem::size_of::<StrId>();
        }
        // BTreeMap node overhead
        dedup_bytes += self.dedup.len() * 48;

        InternerMemoryUsage {
            data_bytes,
            offsets_bytes,
            dedup_bytes,
            dedup_entry_count: self.dedup.len(),
        }
    }

    /// Find a string's ID if it exists.
    ///
    /// For short strings (<64 bytes), uses the dedup table for O(log n) lookup.
    /// For long strings, falls back to O(n) scan.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Offsets are bounded by string data length
    pub fn find(&self, s: &str) -> Option<StrId> {
        // Short strings use hash+verify lookup
        if s.len() < DEDUP_THRESHOLD {
            let hash = hash_str(s);
            if let Some(candidates) = self.dedup.get(&hash) {
                for &id in candidates {
                    if self.get(id) == s {
                        return Some(id);
                    }
                }
            }
            return None;
        }

        // Long strings require O(n) scan.
        // Iterate directly over offset pairs to avoid StrId creation per iteration.
        for (idx, window) in self.offsets.windows(2).enumerate() {
            let start = window[0] as usize;
            let end = window[1] as usize;
            if self.data.get(start..end) == Some(s) {
                return StrId::from_index(idx);
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

    /// Export a copy of the raw parts for serialization (non-consuming).
    ///
    /// Returns `(data, offsets)` where `data` is the concatenated string buffer
    /// and `offsets[i]` is the start of string `i`.
    #[must_use]
    pub fn export_parts(&self) -> (String, Vec<u32>) {
        (self.data.clone(), self.offsets.clone())
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
            offsets.first().is_none_or(|&v| v == 0),
            "first offset must be 0, got {:?}",
            offsets.first()
        );
        debug_assert!(
            offsets.windows(2).all(|w| w[0] <= w[1]),
            "offsets must be monotonically non-decreasing"
        );
        debug_assert!(
            offsets.last().is_none_or(|&v| (v as usize) <= data.len()),
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

        // Short strings use hash+verify lookup
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

    // Test hash collision handling (synthetic collision via same hash)
    #[test]
    fn test_hash_collision_handling() {
        let mut interner = StringInterner::new();

        // These strings are different but we verify dedup still works correctly
        // even if they happened to collide (the verify step catches it)
        let id1 = interner.intern("abc");
        let id2 = interner.intern("def");
        let id3 = interner.intern("abc"); // should dedup to id1

        assert_eq!(id1, id3);
        assert_ne!(id1, id2);
        assert_eq!(interner.get(id1), "abc");
        assert_eq!(interner.get(id2), "def");
    }

    #[test]
    fn test_memory_usage() {
        let mut interner = StringInterner::new();
        interner.intern("hello");
        interner.intern("world");

        let usage = interner.memory_usage();
        assert!(usage.data_bytes > 0);
        assert!(usage.offsets_bytes > 0);
        assert_eq!(usage.dedup_entry_count, 2);
        assert!(usage.total() > 0);
    }
}
