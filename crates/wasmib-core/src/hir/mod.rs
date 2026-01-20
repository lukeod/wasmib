//! High-level Intermediate Representation (HIR) for MIB modules.
//!
//! The HIR provides a normalized representation of MIB modules, independent of
//! whether the source was SMIv1 or SMIv2. Key transformations:
//!
//! - Language detection from imports
//! - Type normalization (Counter→Counter32, Gauge→Gauge32)
//! - Import normalization (RFC1155-SMI→SNMPv2-SMI)
//! - Status normalization (mandatory→Current)
//! - Access normalization (ACCESS→MAX-ACCESS representation)
//! - Unified notification type (TRAP-TYPE and NOTIFICATION-TYPE)
//!
//! # Pipeline Position
//!
//! ```text
//! Source → Lexer → Tokens → Parser → AST → [HIR Lowering] → HIR → [Resolver] → Model
//!                                          ^^^^^^^^^^^^^^^^
//!                                          This module
//! ```
//!
//! # What HIR Does NOT Do
//!
//! These are resolver responsibilities:
//! - OID resolution (HIR keeps OID components as symbols)
//! - Type resolution (HIR keeps type references as symbols)
//! - Nodekind inference (requires resolved OID tree)
//! - Import resolution (just normalize; actual lookup is resolver's job)
//! - Built-in type injection

pub mod base_modules;
mod definition;
mod lower;
mod module;
mod normalize;
mod syntax;
mod types;

pub use base_modules::{create_base_modules, is_base_module, BaseModule};
pub use definition::{
    HirAgentCapabilities, HirComplianceGroup, HirComplianceModule, HirComplianceObject,
    HirDefinition, HirIndexItem, HirModuleCompliance, HirModuleIdentity, HirNotification,
    HirNotificationGroup, HirObjectGroup, HirObjectIdentity, HirObjectType, HirTypeDef,
    HirValueAssignment,
};
pub use lower::{lower_module, LoweringContext};
pub use module::{HirImport, HirModule};
pub use normalize::{normalize_import, normalize_type_name, NormalizedImport};
pub use syntax::{
    HirConstraint, HirDefVal, HirOidAssignment, HirOidComponent, HirRange, HirRangeValue,
    HirTypeSyntax,
};
pub use types::{HirAccess, HirStatus, SmiLanguage, Symbol};
