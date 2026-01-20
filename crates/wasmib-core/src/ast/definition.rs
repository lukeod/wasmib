//! Definition AST types.
//!
//! Each definition corresponds to a "statement" in a MIB module body.

use super::{
    AccessClause, AugmentsClause, DefValClause, Ident, IndexClause, OidAssignment, QuotedString,
    RevisionClause, StatusClause, SyntaxClause, TypeSyntax,
};
use crate::lexer::Span;
use alloc::vec::Vec;

/// A definition in a MIB module body.
#[derive(Clone, Debug)]
pub enum Definition {
    /// `name OBJECT-TYPE SYNTAX ... ::= { parent subid }`
    ObjectType(ObjectTypeDef),

    /// `name MODULE-IDENTITY ... ::= { parent subid }`
    ModuleIdentity(ModuleIdentityDef),

    /// `name OBJECT-IDENTITY ... ::= { parent subid }`
    ObjectIdentity(ObjectIdentityDef),

    /// `name NOTIFICATION-TYPE ... ::= { parent subid }`
    NotificationType(NotificationTypeDef),

    /// `name TRAP-TYPE ... ::= number` (SMIv1)
    TrapType(TrapTypeDef),

    /// `name TEXTUAL-CONVENTION ... SYNTAX ...`
    TextualConvention(TextualConventionDef),

    /// `name ::= typereference` or `name ::= SEQUENCE { ... }`
    TypeAssignment(TypeAssignmentDef),

    /// `name OBJECT IDENTIFIER ::= { parent subid }` (value assignment)
    ValueAssignment(ValueAssignmentDef),

    /// `name OBJECT-GROUP OBJECTS { ... } ::= { parent subid }`
    ObjectGroup(ObjectGroupDef),

    /// `name NOTIFICATION-GROUP NOTIFICATIONS { ... } ::= { parent subid }`
    NotificationGroup(NotificationGroupDef),

    /// `name MODULE-COMPLIANCE ... ::= { parent subid }`
    ModuleCompliance(ModuleComplianceDef),

    /// `name AGENT-CAPABILITIES ... ::= { parent subid }`
    AgentCapabilities(AgentCapabilitiesDef),

    /// MACRO definitions - content skipped but recorded
    MacroDefinition(MacroDefinitionDef),

    /// Parse error with recovery
    Error(ErrorDef),
}

impl Definition {
    /// Get the name of this definition, if it has one.
    #[must_use]
    pub fn name(&self) -> Option<&Ident> {
        match self {
            Self::ObjectType(d) => Some(&d.name),
            Self::ModuleIdentity(d) => Some(&d.name),
            Self::ObjectIdentity(d) => Some(&d.name),
            Self::NotificationType(d) => Some(&d.name),
            Self::TrapType(d) => Some(&d.name),
            Self::TextualConvention(d) => Some(&d.name),
            Self::TypeAssignment(d) => Some(&d.name),
            Self::ValueAssignment(d) => Some(&d.name),
            Self::ObjectGroup(d) => Some(&d.name),
            Self::NotificationGroup(d) => Some(&d.name),
            Self::ModuleCompliance(d) => Some(&d.name),
            Self::AgentCapabilities(d) => Some(&d.name),
            Self::MacroDefinition(d) => Some(&d.name),
            Self::Error(_) => None,
        }
    }

    /// Get the span of this definition.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::ObjectType(d) => d.span,
            Self::ModuleIdentity(d) => d.span,
            Self::ObjectIdentity(d) => d.span,
            Self::NotificationType(d) => d.span,
            Self::TrapType(d) => d.span,
            Self::TextualConvention(d) => d.span,
            Self::TypeAssignment(d) => d.span,
            Self::ValueAssignment(d) => d.span,
            Self::ObjectGroup(d) => d.span,
            Self::NotificationGroup(d) => d.span,
            Self::ModuleCompliance(d) => d.span,
            Self::AgentCapabilities(d) => d.span,
            Self::MacroDefinition(d) => d.span,
            Self::Error(d) => d.span,
        }
    }
}

/// OBJECT-TYPE definition.
///
/// The most common definition type in MIBs.
///
/// Example:
/// ```text
/// ifIndex OBJECT-TYPE
///     SYNTAX      InterfaceIndex
///     MAX-ACCESS  read-only
///     STATUS      current
///     DESCRIPTION "..."
///     ::= { ifEntry 1 }
/// ```
#[derive(Clone, Debug)]
pub struct ObjectTypeDef {
    /// Object name.
    pub name: Ident,
    /// SYNTAX clause.
    pub syntax: SyntaxClause,
    /// UNITS clause (optional).
    pub units: Option<QuotedString>,
    /// MAX-ACCESS or ACCESS clause.
    pub access: AccessClause,
    /// STATUS clause (optional in some vendor MIBs).
    pub status: Option<StatusClause>,
    /// DESCRIPTION clause.
    pub description: Option<QuotedString>,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// INDEX clause.
    pub index: Option<IndexClause>,
    /// AUGMENTS clause.
    pub augments: Option<AugmentsClause>,
    /// DEFVAL clause.
    pub defval: Option<DefValClause>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// MODULE-IDENTITY definition.
///
/// Provides module-level metadata. Must be the first definition in SMIv2 modules.
#[derive(Clone, Debug)]
pub struct ModuleIdentityDef {
    /// Identity name.
    pub name: Ident,
    /// LAST-UPDATED value.
    pub last_updated: QuotedString,
    /// ORGANIZATION value.
    pub organization: QuotedString,
    /// CONTACT-INFO value.
    pub contact_info: QuotedString,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REVISION clauses.
    pub revisions: Vec<RevisionClause>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// OBJECT-IDENTITY definition.
///
/// Defines an OID without a value, used for documentation and organization.
#[derive(Clone, Debug)]
pub struct ObjectIdentityDef {
    /// Identity name.
    pub name: Ident,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// NOTIFICATION-TYPE definition (SMIv2).
#[derive(Clone, Debug)]
pub struct NotificationTypeDef {
    /// Notification name.
    pub name: Ident,
    /// OBJECTS clause (varbind list).
    pub objects: Vec<Ident>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// TRAP-TYPE definition (SMIv1).
#[derive(Clone, Debug)]
pub struct TrapTypeDef {
    /// Trap name.
    pub name: Ident,
    /// ENTERPRISE OID.
    pub enterprise: Ident,
    /// VARIABLES clause.
    pub variables: Vec<Ident>,
    /// DESCRIPTION value.
    pub description: Option<QuotedString>,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// Trap number (::= number).
    pub trap_number: u32,
    /// Source location.
    pub span: Span,
}

/// TEXTUAL-CONVENTION definition.
#[derive(Clone, Debug)]
pub struct TextualConventionDef {
    /// TC name.
    pub name: Ident,
    /// DISPLAY-HINT value.
    pub display_hint: Option<QuotedString>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// SYNTAX clause.
    pub syntax: SyntaxClause,
    /// Source location.
    pub span: Span,
}

/// Type assignment definition.
///
/// Examples:
/// - `InterfaceIndex ::= Integer32` (simple alias)
/// - `IfEntry ::= SEQUENCE { ifIndex INTEGER, ... }` (row definition)
#[derive(Clone, Debug)]
pub struct TypeAssignmentDef {
    /// Type name.
    pub name: Ident,
    /// Type syntax.
    pub syntax: TypeSyntax,
    /// Source location.
    pub span: Span,
}

/// Value assignment definition (OID definition).
///
/// Example: `internet OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }`
#[derive(Clone, Debug)]
pub struct ValueAssignmentDef {
    /// Value name.
    pub name: Ident,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// OBJECT-GROUP definition.
#[derive(Clone, Debug)]
pub struct ObjectGroupDef {
    /// Group name.
    pub name: Ident,
    /// OBJECTS in this group.
    pub objects: Vec<Ident>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// NOTIFICATION-GROUP definition.
#[derive(Clone, Debug)]
pub struct NotificationGroupDef {
    /// Group name.
    pub name: Ident,
    /// NOTIFICATIONS in this group.
    pub notifications: Vec<Ident>,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// MODULE-COMPLIANCE definition.
#[derive(Clone, Debug)]
pub struct ModuleComplianceDef {
    /// Compliance name.
    pub name: Ident,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// MODULE clauses.
    pub modules: Vec<ComplianceModule>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
}

/// A MODULE clause in MODULE-COMPLIANCE.
#[derive(Clone, Debug)]
pub struct ComplianceModule {
    /// Module name (None = current module).
    pub module_name: Option<Ident>,
    /// Module OID (optional, rare).
    pub module_oid: Option<OidAssignment>,
    /// MANDATORY-GROUPS list.
    pub mandatory_groups: Vec<Ident>,
    /// GROUP and OBJECT refinements.
    pub compliances: Vec<Compliance>,
    /// Source location.
    pub span: Span,
}

/// A compliance item (GROUP or OBJECT refinement).
#[derive(Clone, Debug)]
pub enum Compliance {
    /// GROUP clause - conditionally required group.
    Group(ComplianceGroup),
    /// OBJECT clause - object refinement.
    Object(ComplianceObject),
}

/// GROUP clause in MODULE-COMPLIANCE.
#[derive(Clone, Debug)]
pub struct ComplianceGroup {
    /// Group reference.
    pub group: Ident,
    /// DESCRIPTION.
    pub description: QuotedString,
    /// Source location.
    pub span: Span,
}

/// OBJECT refinement in MODULE-COMPLIANCE.
#[derive(Clone, Debug)]
pub struct ComplianceObject {
    /// Object reference.
    pub object: Ident,
    /// SYNTAX restriction (optional).
    pub syntax: Option<SyntaxClause>,
    /// WRITE-SYNTAX restriction (optional).
    pub write_syntax: Option<SyntaxClause>,
    /// MIN-ACCESS restriction (optional).
    pub min_access: Option<AccessClause>,
    /// DESCRIPTION (required per RFC 2580).
    pub description: QuotedString,
    /// Source location.
    pub span: Span,
}

/// AGENT-CAPABILITIES definition.
#[derive(Clone, Debug)]
pub struct AgentCapabilitiesDef {
    /// Capabilities name.
    pub name: Ident,
    /// PRODUCT-RELEASE value.
    pub product_release: QuotedString,
    /// STATUS clause.
    pub status: StatusClause,
    /// DESCRIPTION value.
    pub description: QuotedString,
    /// REFERENCE clause.
    pub reference: Option<QuotedString>,
    /// OID assignment.
    pub oid_assignment: OidAssignment,
    /// Source location.
    pub span: Span,
    // TODO: SUPPORTS clauses with INCLUDES, VARIATION
}

/// MACRO definition (skipped content).
///
/// MACRO definitions only appear in base SMI modules (SNMPv2-SMI, etc.).
/// We record them but don't parse their content.
#[derive(Clone, Debug)]
pub struct MacroDefinitionDef {
    /// MACRO name (e.g., `OBJECT-TYPE`).
    pub name: Ident,
    /// Source location.
    pub span: Span,
}

/// Parse error with recovery.
///
/// When the parser encounters an error, it records the location and
/// attempts to recover to continue parsing.
#[derive(Clone, Debug)]
pub struct ErrorDef {
    /// Error message.
    pub message: alloc::string::String,
    /// Source location where error occurred.
    pub span: Span,
}
