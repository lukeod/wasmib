//! Abstract Syntax Tree types for parsed MIB modules.
//!
//! The AST captures syntactic structure as-written, preserving source locations
//! for diagnostics. Semantic analysis (resolution, normalization) happens in
//! later phases (HIR lowering and resolver).

mod common;
mod definition;
mod module;
mod oid;
mod syntax;

pub use common::{Ident, NamedNumber, QuotedString};
pub use definition::{
    AgentCapabilitiesDef, Definition, ErrorDef, MacroDefinitionDef, ModuleComplianceDef,
    ModuleIdentityDef, NotificationGroupDef, NotificationTypeDef, ObjectGroupDef,
    ObjectIdentityDef, ObjectTypeDef, TextualConventionDef, TrapTypeDef, TypeAssignmentDef,
    ValueAssignmentDef,
};
pub use module::{DefinitionsKind, ExportsClause, ImportClause, Module};
pub use oid::{OidAssignment, OidComponent};
pub use syntax::{
    AccessClause, AccessKeyword, AccessValue, AugmentsClause, Constraint, DefValClause,
    IndexClause, IndexItem, Range, RangeValue, RevisionClause, SequenceField, StatusClause,
    StatusValue, SyntaxClause, TypeSyntax,
};
