//! Definition types.
//!
//! Each definition type is normalized from its AST counterpart.
//! `SMIv1` and `SMIv2` forms are unified where appropriate.
//!
//! # Optional vs Required Description Fields
//!
//! Per the leniency philosophy, `description` is `Option<String>` for definitions
//! where real-world MIBs commonly omit it:
//!
//! - **`ObjectType`**: Many vendor MIBs omit DESCRIPTION despite RFC 2578 requiring it.
//! - **`Notification`**: `SMIv1` TRAP-TYPE has no DESCRIPTION clause.
//! - **`TypeDef`**: Simple type assignments (non-TC) have no DESCRIPTION clause.
//!
//! `description` is required (`String`) for definitions where the RFC mandates it and
//! real-world compliance is high:
//!
//! - **`ModuleIdentity`**: RFC 2578 requires DESCRIPTION; universally present.
//! - **`ObjectIdentity`**: RFC 2578 requires DESCRIPTION.
//! - **`ObjectGroup`**, **`NotificationGroup`**: RFC 2580 requires DESCRIPTION.
//! - **`ModuleCompliance`**, **`AgentCapabilities`**: RFC 2580 requires DESCRIPTION.
//!
//! This design allows wasmib to parse non-compliant MIBs while preserving required
//! metadata for well-formed definitions.

use super::syntax::{DefVal, OidAssignment, TypeSyntax};
use super::types::{Access, Status, Symbol};
use crate::lexer::Span;
use alloc::string::String;
use alloc::vec::Vec;

/// A definition in a MIB module.
#[derive(Clone, Debug)]
pub enum Definition {
    /// OBJECT-TYPE (both `SMIv1` and `SMIv2`).
    ObjectType(ObjectType),
    /// MODULE-IDENTITY.
    ModuleIdentity(ModuleIdentity),
    /// OBJECT-IDENTITY.
    ObjectIdentity(ObjectIdentity),
    /// NOTIFICATION-TYPE or TRAP-TYPE (unified).
    Notification(Notification),
    /// TEXTUAL-CONVENTION or simple type assignment.
    TypeDef(TypeDef),
    /// Value assignment (OID definition).
    ValueAssignment(ValueAssignment),
    /// OBJECT-GROUP.
    ObjectGroup(ObjectGroup),
    /// NOTIFICATION-GROUP.
    NotificationGroup(NotificationGroup),
    /// MODULE-COMPLIANCE.
    ModuleCompliance(ModuleCompliance),
    /// AGENT-CAPABILITIES.
    AgentCapabilities(AgentCapabilities),
}

impl Definition {
    /// Get the name of this definition.
    #[must_use]
    pub fn name(&self) -> Option<&Symbol> {
        match self {
            Self::ObjectType(d) => Some(&d.name),
            Self::ModuleIdentity(d) => Some(&d.name),
            Self::ObjectIdentity(d) => Some(&d.name),
            Self::Notification(d) => Some(&d.name),
            Self::TypeDef(d) => Some(&d.name),
            Self::ValueAssignment(d) => Some(&d.name),
            Self::ObjectGroup(d) => Some(&d.name),
            Self::NotificationGroup(d) => Some(&d.name),
            Self::ModuleCompliance(d) => Some(&d.name),
            Self::AgentCapabilities(d) => Some(&d.name),
        }
    }

    /// Get the span of this definition.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::ObjectType(d) => d.span,
            Self::ModuleIdentity(d) => d.span,
            Self::ObjectIdentity(d) => d.span,
            Self::Notification(d) => d.span,
            Self::TypeDef(d) => d.span,
            Self::ValueAssignment(d) => d.span,
            Self::ObjectGroup(d) => d.span,
            Self::NotificationGroup(d) => d.span,
            Self::ModuleCompliance(d) => d.span,
            Self::AgentCapabilities(d) => d.span,
        }
    }

    /// Get the OID assignment if this definition has one.
    #[must_use]
    pub fn oid(&self) -> Option<&OidAssignment> {
        match self {
            Self::ObjectType(d) => Some(&d.oid),
            Self::ModuleIdentity(d) => Some(&d.oid),
            Self::ObjectIdentity(d) => Some(&d.oid),
            Self::Notification(d) => d.oid.as_ref(),
            Self::TypeDef(_) => None,
            Self::ValueAssignment(d) => Some(&d.oid),
            Self::ObjectGroup(d) => Some(&d.oid),
            Self::NotificationGroup(d) => Some(&d.oid),
            Self::ModuleCompliance(d) => Some(&d.oid),
            Self::AgentCapabilities(d) => Some(&d.oid),
        }
    }
}

/// OBJECT-TYPE definition.
#[derive(Clone, Debug)]
pub struct ObjectType {
    /// Object name.
    pub name: Symbol,
    /// SYNTAX.
    pub syntax: TypeSyntax,
    /// UNITS clause.
    pub units: Option<String>,
    /// MAX-ACCESS (normalized from ACCESS if `SMIv1`).
    pub access: Access,
    /// STATUS (normalized from `SMIv1` if needed).
    pub status: Status,
    /// DESCRIPTION (optional: many vendor MIBs omit this despite RFC requirement).
    pub description: Option<String>,
    /// REFERENCE.
    pub reference: Option<String>,
    /// INDEX items (object references).
    pub index: Option<Vec<IndexItem>>,
    /// AUGMENTS target.
    pub augments: Option<Symbol>,
    /// DEFVAL clause (default value).
    pub defval: Option<DefVal>,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// An item in an INDEX clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexItem {
    /// Whether this index is IMPLIED.
    pub implied: bool,
    /// Object reference.
    pub object: Symbol,
}

impl IndexItem {
    /// Create a new index item.
    #[must_use]
    pub fn new(object: Symbol, implied: bool) -> Self {
        Self { implied, object }
    }
}

/// MODULE-IDENTITY definition.
#[derive(Clone, Debug)]
pub struct ModuleIdentity {
    /// Identity name.
    pub name: Symbol,
    /// LAST-UPDATED value.
    pub last_updated: String,
    /// ORGANIZATION value.
    pub organization: String,
    /// CONTACT-INFO value.
    pub contact_info: String,
    /// DESCRIPTION value.
    pub description: String,
    /// REVISION clauses.
    pub revisions: Vec<Revision>,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// A REVISION clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    /// Revision date.
    pub date: String,
    /// Revision description.
    pub description: String,
}

/// OBJECT-IDENTITY definition.
#[derive(Clone, Debug)]
pub struct ObjectIdentity {
    /// Identity name.
    pub name: Symbol,
    /// STATUS.
    pub status: Status,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// Unified notification definition.
///
/// Represents both `SMIv1` TRAP-TYPE and `SMIv2` NOTIFICATION-TYPE.
#[derive(Clone, Debug)]
pub struct Notification {
    /// Notification name.
    pub name: Symbol,
    /// OBJECTS/VARIABLES list.
    pub objects: Vec<Symbol>,
    /// STATUS.
    pub status: Status,
    /// DESCRIPTION (optional: `SMIv1` TRAP-TYPE has no DESCRIPTION clause).
    pub description: Option<String>,
    /// REFERENCE.
    pub reference: Option<String>,
    /// For TRAP-TYPE: enterprise reference and trap number.
    /// For NOTIFICATION-TYPE: None.
    pub trap_info: Option<TrapInfo>,
    /// OID assignment (for NOTIFICATION-TYPE).
    /// None for TRAP-TYPE (OID derived from enterprise + trap number).
    pub oid: Option<OidAssignment>,
    /// Source span.
    pub span: Span,
}

/// `SMIv1` TRAP-TYPE specific information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrapInfo {
    /// ENTERPRISE OID reference.
    pub enterprise: Symbol,
    /// Trap number.
    pub trap_number: u32,
}

/// Type definition.
///
/// Represents both TEXTUAL-CONVENTION and simple type assignments.
#[derive(Clone, Debug)]
pub struct TypeDef {
    /// Type name.
    pub name: Symbol,
    /// Base syntax.
    pub syntax: TypeSyntax,
    /// DISPLAY-HINT.
    pub display_hint: Option<String>,
    /// STATUS.
    pub status: Status,
    /// DESCRIPTION (optional: simple type assignments have no DESCRIPTION clause).
    pub description: Option<String>,
    /// REFERENCE.
    pub reference: Option<String>,
    /// True if this was a TEXTUAL-CONVENTION (vs simple type assignment).
    pub is_textual_convention: bool,
    /// Source span.
    pub span: Span,
}

/// Value assignment (OID definition).
#[derive(Clone, Debug)]
pub struct ValueAssignment {
    /// Value name.
    pub name: Symbol,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// OBJECT-GROUP definition.
#[derive(Clone, Debug)]
pub struct ObjectGroup {
    /// Group name.
    pub name: Symbol,
    /// OBJECTS in this group.
    pub objects: Vec<Symbol>,
    /// STATUS.
    pub status: Status,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// NOTIFICATION-GROUP definition.
#[derive(Clone, Debug)]
pub struct NotificationGroup {
    /// Group name.
    pub name: Symbol,
    /// NOTIFICATIONS in this group.
    pub notifications: Vec<Symbol>,
    /// STATUS.
    pub status: Status,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// MODULE-COMPLIANCE definition.
#[derive(Clone, Debug)]
pub struct ModuleCompliance {
    /// Compliance name.
    pub name: Symbol,
    /// STATUS.
    pub status: Status,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// MODULE clauses.
    pub modules: Vec<ComplianceModule>,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// MODULE clause in MODULE-COMPLIANCE.
#[derive(Clone, Debug)]
pub struct ComplianceModule {
    /// Module name (None = current module).
    pub module_name: Option<Symbol>,
    /// MANDATORY-GROUPS.
    pub mandatory_groups: Vec<Symbol>,
    /// GROUP refinements.
    pub groups: Vec<ComplianceGroup>,
    /// OBJECT refinements.
    pub objects: Vec<ComplianceObject>,
}

/// GROUP clause.
#[derive(Clone, Debug)]
pub struct ComplianceGroup {
    /// Group reference.
    pub group: Symbol,
    /// Description.
    pub description: String,
}

/// OBJECT refinement.
#[derive(Clone, Debug)]
pub struct ComplianceObject {
    /// Object reference.
    pub object: Symbol,
    /// SYNTAX restriction.
    pub syntax: Option<TypeSyntax>,
    /// WRITE-SYNTAX restriction.
    pub write_syntax: Option<TypeSyntax>,
    /// MIN-ACCESS restriction.
    pub min_access: Option<Access>,
    /// Description.
    pub description: String,
}

/// AGENT-CAPABILITIES definition.
#[derive(Clone, Debug)]
pub struct AgentCapabilities {
    /// Capabilities name.
    pub name: Symbol,
    /// PRODUCT-RELEASE value.
    pub product_release: String,
    /// STATUS.
    pub status: Status,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// SUPPORTS clauses.
    pub supports: Vec<SupportsModule>,
    /// OID assignment.
    pub oid: OidAssignment,
    /// Source span.
    pub span: Span,
}

/// SUPPORTS clause in AGENT-CAPABILITIES.
#[derive(Clone, Debug)]
pub struct SupportsModule {
    /// Module name.
    pub module_name: Symbol,
    /// INCLUDES list of group references.
    pub includes: Vec<Symbol>,
    /// Object variations.
    pub object_variations: Vec<ObjectVariation>,
    /// Notification variations.
    pub notification_variations: Vec<NotificationVariation>,
}

/// Object VARIATION.
#[derive(Clone, Debug)]
pub struct ObjectVariation {
    /// Object reference.
    pub object: Symbol,
    /// SYNTAX restriction.
    pub syntax: Option<TypeSyntax>,
    /// WRITE-SYNTAX restriction.
    pub write_syntax: Option<TypeSyntax>,
    /// ACCESS restriction.
    pub access: Option<Access>,
    /// CREATION-REQUIRES list.
    pub creation_requires: Option<Vec<Symbol>>,
    /// DEFVAL override.
    pub defval: Option<DefVal>,
    /// Description.
    pub description: String,
}

/// Notification VARIATION.
#[derive(Clone, Debug)]
pub struct NotificationVariation {
    /// Notification reference.
    pub notification: Symbol,
    /// ACCESS restriction (only "not-implemented" is valid per RFC 2580).
    pub access: Option<Access>,
    /// Description.
    pub description: String,
}
