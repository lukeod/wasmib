//! Core HIR types.

use crate::ast::Ident;
use alloc::string::String;
use core::fmt;

/// SMI language version.
///
/// Detected from imports during HIR lowering:
/// - `SMIv2` if imports from SNMPv2-SMI, SNMPv2-TC, or SNMPv2-CONF
/// - `SMIv1` otherwise (default)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SmiLanguage {
    /// Language not yet determined.
    #[default]
    Unknown,
    /// `SMIv1` (RFC 1155, 1212, 1215).
    Smiv1,
    /// `SMIv2` (RFC 2578, 2579, 2580).
    Smiv2,
    /// SPPI Policy Information Base (RFC 3159) - low priority.
    Sppi,
}

impl fmt::Display for SmiLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Smiv1 => write!(f, "SMIv1"),
            Self::Smiv2 => write!(f, "SMIv2"),
            Self::Sppi => write!(f, "SPPI"),
        }
    }
}

/// Symbol identifier.
///
/// Wraps a string name. Later can be replaced with interned strings for efficiency.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Symbol {
    /// The symbol name.
    pub name: String,
}

impl Symbol {
    /// Create a new symbol.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self { name }
    }

    /// Create a symbol from a string slice.
    #[must_use]
    pub fn from_str(name: &str) -> Self {
        Self {
            name: String::from(name),
        }
    }

    /// Check if this is an uppercase symbol (module/type name).
    #[must_use]
    pub fn is_uppercase(&self) -> bool {
        self.name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
    }

    /// Check if this is a lowercase symbol (object/enum name).
    #[must_use]
    pub fn is_lowercase(&self) -> bool {
        self.name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase())
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&str> for Symbol {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl From<String> for Symbol {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<Ident> for Symbol {
    fn from(ident: Ident) -> Self {
        Self::new(ident.name)
    }
}

impl From<&Ident> for Symbol {
    fn from(ident: &Ident) -> Self {
        Self::from_str(&ident.name)
    }
}

/// Normalized access value.
///
/// Unifies `SMIv1` `ACCESS` and `SMIv2` `MAX-ACCESS` into a single representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HirAccess {
    /// Object is read-only.
    ReadOnly,
    /// Object is read-write.
    ReadWrite,
    /// Object is read-create (`SMIv2` only, implies read-write + row creation).
    ReadCreate,
    /// Object is not accessible (internal use, typically index columns).
    NotAccessible,
    /// Object is accessible only for notifications (`SMIv2` only).
    AccessibleForNotify,
    /// Object is write-only (deprecated, but seen in wild).
    WriteOnly,
}

impl fmt::Display for HirAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read-only"),
            Self::ReadWrite => write!(f, "read-write"),
            Self::ReadCreate => write!(f, "read-create"),
            Self::NotAccessible => write!(f, "not-accessible"),
            Self::AccessibleForNotify => write!(f, "accessible-for-notify"),
            Self::WriteOnly => write!(f, "write-only"),
        }
    }
}

/// Normalized status value.
///
/// `SMIv1` status values are mapped to `SMIv2` equivalents:
/// - `mandatory` → `Current`
/// - `optional` → `Deprecated` (with implicit note)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HirStatus {
    /// Object is current and valid.
    #[default]
    Current,
    /// Object is deprecated but still valid.
    Deprecated,
    /// Object is obsolete and should not be used.
    Obsolete,
}

impl fmt::Display for HirStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => write!(f, "current"),
            Self::Deprecated => write!(f, "deprecated"),
            Self::Obsolete => write!(f, "obsolete"),
        }
    }
}
