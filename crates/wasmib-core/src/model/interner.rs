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
#[derive(Clone, Debug)]
pub struct StringInterner {
    /// Concatenated string data.
    data: String,
    /// Offsets into data for each string. offsets[i] is the start of string i.
    offsets: Vec<u32>,
    /// Lookup table for deduplicating short strings.
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
    #[must_use]
    pub fn get(&self, id: StrId) -> &str {
        let idx = id.to_index();
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        &self.data[start..end]
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

    /// Find a string's ID if it exists. O(n) scan.
    /// For frequent lookups, consider maintaining a reverse index.
    #[must_use]
    pub fn find(&self, s: &str) -> Option<StrId> {
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
    #[must_use]
    pub fn from_parts(data: String, offsets: Vec<u32>) -> Self {
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
}
