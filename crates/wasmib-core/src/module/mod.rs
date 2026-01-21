//! Module representation for MIB modules.
//!
//! This module provides a normalized representation of MIB modules, independent of
//! whether the source was `SMIv1` or `SMIv2`. Key transformations:
//!
//! - Language detection from imports
//! - Status normalization (mandatory→Current)
//! - Access normalization (ACCESS→MAX-ACCESS representation)
//! - Unified notification type (TRAP-TYPE and NOTIFICATION-TYPE)
//!
//! # Pipeline Position
//!
//! ```text
//! Source → Lexer → Tokens → Parser → AST → [Lowering] → Module → [Resolver] → Model
//!                                          ^^^^^^^^^^^^^
//!                                          This module
//! ```
//!
//! # What Lowering Does NOT Do
//!
//! These are resolver responsibilities:
//! - OID resolution (keeps OID components as symbols)
//! - Type resolution (keeps type references as symbols)
//! - Nodekind inference (requires resolved OID tree)
//! - Import resolution (just normalize; actual lookup is resolver's job)
//! - Built-in type injection

pub mod base_modules;
mod definition;
mod lower;
mod module;
mod syntax;
mod types;

pub use base_modules::{BaseModule, create_base_modules, is_base_module};
pub use definition::{
    AgentCapabilities, ComplianceGroup, ComplianceModule, ComplianceObject, Definition, IndexItem,
    ModuleCompliance, ModuleIdentity, Notification, NotificationGroup, NotificationVariation,
    ObjectGroup, ObjectIdentity, ObjectType, ObjectVariation, Revision, SupportsModule, TrapInfo,
    TypeDef, ValueAssignment,
};
pub use lower::{LoweringContext, lower_module};
pub use module::{Import, Module};
pub use syntax::{
    Constraint, DefVal, NamedBit, NamedNumber, OidAssignment, OidComponent, Range, RangeValue,
    SequenceField, TypeSyntax,
};
pub use types::{Access, SmiLanguage, Status, Symbol};
