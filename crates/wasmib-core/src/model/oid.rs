//! OID (Object Identifier) representation.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A fully-resolved numeric OID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid {
    arcs: Vec<u32>,
}

impl Oid {
    /// Create a new OID from a vector of arcs.
    #[must_use]
    pub fn new(arcs: Vec<u32>) -> Self {
        Self { arcs }
    }

    /// Create an OID from a slice of arcs.
    #[must_use]
    pub fn from_slice(arcs: &[u32]) -> Self {
        Self {
            arcs: arcs.to_vec(),
        }
    }

    /// Parse an OID from dotted notation (e.g., "1.3.6.1.2.1").
    #[must_use]
    pub fn from_dotted(s: &str) -> Option<Self> {
        if s.is_empty() {
            return Some(Self::new(Vec::new()));
        }
        let arcs: Result<Vec<u32>, _> = s.split('.').map(|p| p.parse()).collect();
        arcs.ok().map(Self::new)
    }

    /// Convert to dotted notation string.
    #[must_use]
    pub fn to_dotted(&self) -> String {
        self.arcs
            .iter()
            .map(|n| alloc::string::ToString::to_string(n))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Get the parent OID (all arcs except the last).
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.arcs.len() <= 1 {
            None
        } else {
            Some(Self::new(self.arcs[..self.arcs.len() - 1].to_vec()))
        }
    }

    /// Get the last arc.
    #[must_use]
    pub fn last_arc(&self) -> Option<u32> {
        self.arcs.last().copied()
    }

    /// Check if this OID is a prefix of another.
    #[must_use]
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        other.arcs.starts_with(&self.arcs)
    }

    /// Get the number of arcs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.arcs.len()
    }

    /// Check if the OID is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.arcs.is_empty()
    }

    /// Get the arcs as a slice.
    #[must_use]
    pub fn arcs(&self) -> &[u32] {
        &self.arcs
    }

    /// Create a child OID by appending an arc.
    #[must_use]
    pub fn child(&self, arc: u32) -> Self {
        let mut arcs = self.arcs.clone();
        arcs.push(arc);
        Self::new(arcs)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_dotted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_dotted() {
        let oid = Oid::from_dotted("1.3.6.1").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1]);
    }

    #[test]
    fn test_from_dotted_empty() {
        let oid = Oid::from_dotted("").unwrap();
        assert!(oid.is_empty());
    }

    #[test]
    fn test_from_dotted_invalid() {
        assert!(Oid::from_dotted("1.3.x.1").is_none());
    }

    #[test]
    fn test_to_dotted() {
        let oid = Oid::new(vec![1, 3, 6, 1, 2, 1]);
        assert_eq!(oid.to_dotted(), "1.3.6.1.2.1");
    }

    #[test]
    fn test_parent() {
        let oid = Oid::new(vec![1, 3, 6, 1]);
        let parent = oid.parent().unwrap();
        assert_eq!(parent.arcs(), &[1, 3, 6]);
    }

    #[test]
    fn test_parent_single() {
        let oid = Oid::new(vec![1]);
        assert!(oid.parent().is_none());
    }

    #[test]
    fn test_is_prefix_of() {
        let prefix = Oid::new(vec![1, 3, 6]);
        let full = Oid::new(vec![1, 3, 6, 1, 2, 1]);

        assert!(prefix.is_prefix_of(&full));
        assert!(!full.is_prefix_of(&prefix));
    }

    #[test]
    fn test_child() {
        let oid = Oid::new(vec![1, 3, 6, 1]);
        let child = oid.child(2);
        assert_eq!(child.arcs(), &[1, 3, 6, 1, 2]);
    }

    #[test]
    fn test_display() {
        let oid = Oid::new(vec![1, 3, 6, 1]);
        assert_eq!(format!("{oid}"), "1.3.6.1");
    }
}
