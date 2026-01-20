//! HIR definition types.
//!
//! Each definition type is normalized from its AST counterpart.
//! SMIv1 and SMIv2 forms are unified where appropriate.

use super::syntax::{HirDefVal, HirOidAssignment, HirTypeSyntax};
use super::types::{HirAccess, HirStatus, Symbol};
use crate::lexer::Span;
use alloc::string::String;
use alloc::vec::Vec;

/// A normalized definition in a MIB module.
#[derive(Clone, Debug)]
pub enum HirDefinition {
    /// OBJECT-TYPE (both SMIv1 and SMIv2).
    ObjectType(HirObjectType),
    /// MODULE-IDENTITY.
    ModuleIdentity(HirModuleIdentity),
    /// OBJECT-IDENTITY.
    ObjectIdentity(HirObjectIdentity),
    /// NOTIFICATION-TYPE or TRAP-TYPE (unified).
    Notification(HirNotification),
    /// TEXTUAL-CONVENTION or simple type assignment.
    TypeDef(HirTypeDef),
    /// Value assignment (OID definition).
    ValueAssignment(HirValueAssignment),
    /// OBJECT-GROUP.
    ObjectGroup(HirObjectGroup),
    /// NOTIFICATION-GROUP.
    NotificationGroup(HirNotificationGroup),
    /// MODULE-COMPLIANCE.
    ModuleCompliance(HirModuleCompliance),
    /// AGENT-CAPABILITIES.
    AgentCapabilities(HirAgentCapabilities),
}

impl HirDefinition {
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
    pub fn oid(&self) -> Option<&HirOidAssignment> {
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
pub struct HirObjectType {
    /// Object name.
    pub name: Symbol,
    /// SYNTAX (normalized).
    pub syntax: HirTypeSyntax,
    /// UNITS clause.
    pub units: Option<String>,
    /// MAX-ACCESS (normalized from ACCESS if SMIv1).
    pub access: HirAccess,
    /// STATUS (normalized from SMIv1 if needed).
    pub status: HirStatus,
    /// DESCRIPTION.
    pub description: Option<String>,
    /// REFERENCE.
    pub reference: Option<String>,
    /// INDEX items (object references).
    pub index: Option<Vec<HirIndexItem>>,
    /// AUGMENTS target.
    pub augments: Option<Symbol>,
    /// DEFVAL clause (default value).
    pub defval: Option<HirDefVal>,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
}

/// An item in an INDEX clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirIndexItem {
    /// Whether this index is IMPLIED.
    pub implied: bool,
    /// Object reference.
    pub object: Symbol,
}

impl HirIndexItem {
    /// Create a new index item.
    #[must_use]
    pub fn new(object: Symbol, implied: bool) -> Self {
        Self { implied, object }
    }
}

/// MODULE-IDENTITY definition.
#[derive(Clone, Debug)]
pub struct HirModuleIdentity {
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
    pub revisions: Vec<HirRevision>,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
}

/// A REVISION clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirRevision {
    /// Revision date.
    pub date: String,
    /// Revision description.
    pub description: String,
}

/// OBJECT-IDENTITY definition.
#[derive(Clone, Debug)]
pub struct HirObjectIdentity {
    /// Identity name.
    pub name: Symbol,
    /// STATUS.
    pub status: HirStatus,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
}

/// Unified notification definition.
///
/// Represents both SMIv1 TRAP-TYPE and SMIv2 NOTIFICATION-TYPE.
#[derive(Clone, Debug)]
pub struct HirNotification {
    /// Notification name.
    pub name: Symbol,
    /// OBJECTS/VARIABLES list.
    pub objects: Vec<Symbol>,
    /// STATUS.
    pub status: HirStatus,
    /// DESCRIPTION.
    pub description: Option<String>,
    /// REFERENCE.
    pub reference: Option<String>,
    /// For TRAP-TYPE: enterprise reference and trap number.
    /// For NOTIFICATION-TYPE: None.
    pub trap_info: Option<HirTrapInfo>,
    /// OID assignment (for NOTIFICATION-TYPE).
    /// None for TRAP-TYPE (OID derived from enterprise + trap number).
    pub oid: Option<HirOidAssignment>,
    /// Source span.
    pub span: Span,
}

/// SMIv1 TRAP-TYPE specific information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirTrapInfo {
    /// ENTERPRISE OID reference.
    pub enterprise: Symbol,
    /// Trap number.
    pub trap_number: u32,
}

/// Type definition.
///
/// Represents both TEXTUAL-CONVENTION and simple type assignments.
#[derive(Clone, Debug)]
pub struct HirTypeDef {
    /// Type name.
    pub name: Symbol,
    /// Base syntax.
    pub syntax: HirTypeSyntax,
    /// DISPLAY-HINT.
    pub display_hint: Option<String>,
    /// STATUS.
    pub status: HirStatus,
    /// DESCRIPTION.
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
pub struct HirValueAssignment {
    /// Value name.
    pub name: Symbol,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
}

/// OBJECT-GROUP definition.
#[derive(Clone, Debug)]
pub struct HirObjectGroup {
    /// Group name.
    pub name: Symbol,
    /// OBJECTS in this group.
    pub objects: Vec<Symbol>,
    /// STATUS.
    pub status: HirStatus,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
}

/// NOTIFICATION-GROUP definition.
#[derive(Clone, Debug)]
pub struct HirNotificationGroup {
    /// Group name.
    pub name: Symbol,
    /// NOTIFICATIONS in this group.
    pub notifications: Vec<Symbol>,
    /// STATUS.
    pub status: HirStatus,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
}

/// MODULE-COMPLIANCE definition.
#[derive(Clone, Debug)]
pub struct HirModuleCompliance {
    /// Compliance name.
    pub name: Symbol,
    /// STATUS.
    pub status: HirStatus,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// MODULE clauses.
    pub modules: Vec<HirComplianceModule>,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
}

/// Normalized MODULE clause in MODULE-COMPLIANCE.
#[derive(Clone, Debug)]
pub struct HirComplianceModule {
    /// Module name (None = current module).
    pub module_name: Option<Symbol>,
    /// MANDATORY-GROUPS.
    pub mandatory_groups: Vec<Symbol>,
    /// GROUP refinements.
    pub groups: Vec<HirComplianceGroup>,
    /// OBJECT refinements.
    pub objects: Vec<HirComplianceObject>,
}

/// Normalized GROUP clause.
#[derive(Clone, Debug)]
pub struct HirComplianceGroup {
    /// Group reference.
    pub group: Symbol,
    /// Description.
    pub description: String,
}

/// Normalized OBJECT refinement.
#[derive(Clone, Debug)]
pub struct HirComplianceObject {
    /// Object reference.
    pub object: Symbol,
    /// SYNTAX restriction.
    pub syntax: Option<HirTypeSyntax>,
    /// WRITE-SYNTAX restriction.
    pub write_syntax: Option<HirTypeSyntax>,
    /// MIN-ACCESS restriction.
    pub min_access: Option<HirAccess>,
    /// Description.
    pub description: String,
}

/// AGENT-CAPABILITIES definition.
#[derive(Clone, Debug)]
pub struct HirAgentCapabilities {
    /// Capabilities name.
    pub name: Symbol,
    /// PRODUCT-RELEASE value.
    pub product_release: String,
    /// STATUS.
    pub status: HirStatus,
    /// DESCRIPTION.
    pub description: String,
    /// REFERENCE.
    pub reference: Option<String>,
    /// OID assignment.
    pub oid: HirOidAssignment,
    /// Source span.
    pub span: Span,
    // TODO: SUPPORTS clauses with INCLUDES, VARIATION
}
