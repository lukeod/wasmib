//! Type system types for the resolved model.

use super::ids::{ModuleId, StrId, TypeId};
use alloc::vec::Vec;

/// SMI base type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BaseType {
    /// Signed 32-bit integer.
    Integer32,
    /// 32-bit counter (monotonically increasing, wraps).
    Counter32,
    /// 64-bit counter.
    Counter64,
    /// 32-bit gauge (can increase or decrease).
    Gauge32,
    /// Unsigned 32-bit integer.
    Unsigned32,
    /// Time in hundredths of a second.
    TimeTicks,
    /// IPv4 address.
    IpAddress,
    /// Arbitrary ASN.1 data.
    Opaque,
    /// OCTET STRING.
    OctetString,
    /// OBJECT IDENTIFIER.
    ObjectIdentifier,
    /// BITS (bit string with named bits).
    Bits,
    /// SEQUENCE (compound type for table rows).
    Sequence,
}

impl BaseType {
    /// Get a string representation for downstream consumers.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Integer32 => "INTEGER",
            Self::Counter32 => "COUNTER32",
            Self::Counter64 => "COUNTER64",
            Self::Gauge32 => "GAUGE32",
            Self::Unsigned32 => "UNSIGNED32",
            Self::TimeTicks => "TIMETICKS",
            Self::IpAddress => "IPADDRESS",
            Self::Opaque => "OPAQUE",
            Self::OctetString => "OCTETSTR",
            Self::ObjectIdentifier => "OBJID",
            Self::Bits => "BITS",
            Self::Sequence => "SEQUENCE",
        }
    }
}

/// Size constraint for OCTET STRING types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SizeConstraint {
    /// (min, max) pairs for allowed sizes.
    pub ranges: Vec<(u32, u32)>,
}

impl SizeConstraint {
    /// Create a single-value size constraint.
    #[must_use]
    pub fn fixed(size: u32) -> Self {
        Self {
            ranges: vec![(size, size)],
        }
    }

    /// Create a range size constraint.
    #[must_use]
    pub fn range(min: u32, max: u32) -> Self {
        Self {
            ranges: vec![(min, max)],
        }
    }
}

/// Value range constraint for INTEGER types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValueConstraint {
    /// (min, max) pairs for allowed values.
    pub ranges: Vec<(i64, i64)>,
}

impl ValueConstraint {
    /// Create a single-range value constraint.
    #[must_use]
    pub fn range(min: i64, max: i64) -> Self {
        Self {
            ranges: vec![(min, max)],
        }
    }
}

/// Named enumeration values for INTEGER types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EnumValues {
    /// (value, label) pairs.
    pub values: Vec<(i64, StrId)>,
}

impl EnumValues {
    /// Create new enum values.
    #[must_use]
    pub fn new(values: Vec<(i64, StrId)>) -> Self {
        Self { values }
    }

    /// Get the label for a numeric value.
    #[must_use]
    pub fn get_label(&self, value: i64) -> Option<StrId> {
        self.values
            .iter()
            .find(|(v, _)| *v == value)
            .map(|(_, l)| *l)
    }

    /// Get the value for a label.
    #[must_use]
    pub fn get_value(&self, label: StrId) -> Option<i64> {
        self.values
            .iter()
            .find(|(_, l)| *l == label)
            .map(|(v, _)| *v)
    }
}

/// Named bit definitions for BITS types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BitDefinitions {
    /// (bit position, label) pairs.
    pub bits: Vec<(u32, StrId)>,
}

impl BitDefinitions {
    /// Create new bit definitions.
    #[must_use]
    pub fn new(bits: Vec<(u32, StrId)>) -> Self {
        Self { bits }
    }
}

/// Status of a definition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Status {
    /// Currently in use.
    #[default]
    Current,
    /// Being phased out.
    Deprecated,
    /// No longer in use.
    Obsolete,
}

impl Status {
    /// Get a string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Deprecated => "deprecated",
            Self::Obsolete => "obsolete",
        }
    }
}

/// Access level of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Access {
    /// Can only be read.
    ReadOnly,
    /// Can be read and written.
    ReadWrite,
    /// Can be read, written, or used to create rows.
    ReadCreate,
    /// Not accessible via SNMP.
    NotAccessible,
    /// Accessible only for notifications.
    AccessibleForNotify,
    /// Write-only (deprecated but seen in wild).
    WriteOnly,
}

impl Access {
    /// Get a string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::ReadWrite => "read-write",
            Self::ReadCreate => "read-create",
            Self::NotAccessible => "not-accessible",
            Self::AccessibleForNotify => "accessible-for-notify",
            Self::WriteOnly => "write-only",
        }
    }

    /// Check if the object is accessible for GET operations.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite | Self::ReadCreate)
    }
}

/// A resolved type definition.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResolvedType {
    /// Type identifier.
    pub id: TypeId,
    /// Type name.
    pub name: StrId,
    /// Defining module.
    pub module: ModuleId,
    /// Underlying primitive type.
    pub base: BaseType,
    /// Parent type for textual conventions.
    pub parent_type: Option<TypeId>,
    /// Display hint.
    pub hint: Option<StrId>,
    /// Size constraint.
    pub size: Option<SizeConstraint>,
    /// Value range constraint.
    pub value_range: Option<ValueConstraint>,
    /// Enumeration values.
    pub enum_values: Option<EnumValues>,
    /// Bit definitions.
    pub bit_defs: Option<BitDefinitions>,
    /// Description text.
    pub description: Option<StrId>,
    /// Is this a textual convention?
    pub is_textual_convention: bool,
    /// Definition status.
    pub status: Status,
    /// Internal: needs base type resolution from parent.
    /// This is set during initial type creation when the base type couldn't
    /// be determined from syntax alone (e.g., TypeRef to another TC).
    #[cfg_attr(feature = "serde", serde(skip))]
    pub needs_base_resolution: bool,
}

impl ResolvedType {
    /// Create a new resolved type.
    #[must_use]
    pub fn new(id: TypeId, name: StrId, module: ModuleId, base: BaseType) -> Self {
        Self {
            id,
            name,
            module,
            base,
            parent_type: None,
            hint: None,
            size: None,
            value_range: None,
            enum_values: None,
            bit_defs: None,
            description: None,
            is_textual_convention: false,
            status: Status::Current,
            needs_base_resolution: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_type_as_str() {
        assert_eq!(BaseType::Integer32.as_str(), "INTEGER");
        assert_eq!(BaseType::Counter64.as_str(), "COUNTER64");
        assert_eq!(BaseType::OctetString.as_str(), "OCTETSTR");
    }

    #[test]
    fn test_status_as_str() {
        assert_eq!(Status::Current.as_str(), "current");
        assert_eq!(Status::Deprecated.as_str(), "deprecated");
    }

    #[test]
    fn test_access_is_readable() {
        assert!(Access::ReadOnly.is_readable());
        assert!(Access::ReadWrite.is_readable());
        assert!(Access::ReadCreate.is_readable());
        assert!(!Access::NotAccessible.is_readable());
        assert!(!Access::AccessibleForNotify.is_readable());
    }

    #[test]
    fn test_size_constraint() {
        let fixed = SizeConstraint::fixed(6);
        assert_eq!(fixed.ranges, vec![(6, 6)]);

        let range = SizeConstraint::range(0, 255);
        assert_eq!(range.ranges, vec![(0, 255)]);
    }
}
