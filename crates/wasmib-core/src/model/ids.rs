//! Index types for model storage.
//!
//! Using `NonZeroU32` enables `Option<T>` niche optimization (no extra space).

use core::num::NonZeroU32;

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(NonZeroU32);

        impl $name {
            /// Create from a raw index (1-based).
            #[must_use]
            pub const fn from_raw(raw: u32) -> Option<Self> {
                match NonZeroU32::new(raw) {
                    Some(n) => Some(Self(n)),
                    None => None,
                }
            }

            /// Create from a 0-based index.
            #[must_use]
            pub fn from_index(index: usize) -> Option<Self> {
                let raw = (index + 1) as u32;
                Self::from_raw(raw)
            }

            /// Get the raw value (1-based).
            #[must_use]
            pub const fn to_raw(self) -> u32 {
                self.0.get()
            }

            /// Get the 0-based index.
            #[must_use]
            pub const fn to_index(self) -> usize {
                (self.0.get() - 1) as usize
            }
        }
    };
}

define_id!(
    /// Interned string identifier.
    StrId
);

define_id!(
    /// Module identifier.
    ModuleId
);

define_id!(
    /// OID tree node identifier.
    NodeId
);

define_id!(
    /// Type definition identifier.
    TypeId
);

define_id!(
    /// Object definition identifier.
    ObjectId
);

define_id!(
    /// Notification definition identifier.
    NotificationId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_raw_zero() {
        assert!(NodeId::from_raw(0).is_none());
    }

    #[test]
    fn test_from_raw_nonzero() {
        let id = NodeId::from_raw(1).unwrap();
        assert_eq!(id.to_raw(), 1);
        assert_eq!(id.to_index(), 0);
    }

    #[test]
    fn test_from_index() {
        let id = NodeId::from_index(0).unwrap();
        assert_eq!(id.to_raw(), 1);
        assert_eq!(id.to_index(), 0);

        let id = NodeId::from_index(99).unwrap();
        assert_eq!(id.to_raw(), 100);
        assert_eq!(id.to_index(), 99);
    }

    #[test]
    fn test_option_size() {
        // Option<NodeId> should be the same size as NodeId due to niche optimization
        assert_eq!(
            core::mem::size_of::<Option<NodeId>>(),
            core::mem::size_of::<NodeId>()
        );
    }
}
