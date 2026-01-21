//! AST to module lowering.
//!
//! Transforms parsed AST into module representation.
//! This module handles:
//! - Language detection from imports
//! - Unification of SMIv1/SMIv2 forms

use super::definition::{
    AgentCapabilities, ComplianceGroup, ComplianceModule, ComplianceObject, Definition, IndexItem,
    ModuleCompliance, ModuleIdentity, Notification, NotificationGroup, NotificationVariation,
    ObjectGroup, ObjectIdentity, ObjectType, ObjectVariation, Revision, SupportsModule, TrapInfo,
    TypeDef, ValueAssignment,
};
use super::module::{Import, Module};
use super::syntax::{
    Constraint, DefVal, NamedBit, NamedNumber, OidAssignment, OidComponent, Range, RangeValue,
    SequenceField, TypeSyntax,
};
use super::types::{Access, SmiLanguage, Status, Symbol};
use crate::ast::{
    self, AccessValue, DefValClause, DefValContent, IndexClause, RangeValue as AstRangeValue,
    StatusValue,
};
use crate::lexer::Diagnostic;
use alloc::vec::Vec;

/// Context for lowering.
///
/// Tracks state during the lowering process.
#[derive(Debug, Default)]
pub struct LoweringContext {
    /// Diagnostics collected during lowering.
    pub diagnostics: Vec<Diagnostic>,
    /// Detected language (may be updated as imports are processed).
    pub language: SmiLanguage,
}

impl LoweringContext {
    /// Create a new lowering context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a diagnostic.
    pub fn add_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }
}

/// Check if a module name is an `SMIv2` base module.
///
/// These modules indicate the MIB is using `SMIv2` syntax.
fn is_smiv2_base_module(module: &str) -> bool {
    matches!(
        module,
        "SNMPv2-SMI" | "SNMPv2-TC" | "SNMPv2-CONF" | "SNMPv2-MIB"
    )
}

/// Lower an AST module.
///
/// This is the main entry point for lowering. It:
/// 1. Detects the SMI language from imports
/// 2. Lowers imports
/// 3. Lowers each definition
///
/// # Arguments
///
/// * `ast_module` - The parsed AST module
///
/// # Returns
///
/// A module with diagnostics.
#[must_use]
pub fn lower_module(ast_module: &ast::Module) -> Module {
    let mut ctx = LoweringContext::new();

    // Create module
    let mut module = Module::new(Symbol::from(&ast_module.name), ast_module.span);

    // Lower imports and detect language
    module.imports = lower_imports(&ast_module.imports, &mut ctx);
    module.language = ctx.language;

    // Lower definitions
    for def in &ast_module.body {
        if let Some(lowered_def) = lower_definition(def, &ctx) {
            module.definitions.push(lowered_def);
        }
    }

    // Collect diagnostics from AST and lowering
    module.diagnostics.clone_from(&ast_module.diagnostics);
    module.diagnostics.extend(ctx.diagnostics);

    module
}

/// Lower import clauses.
///
/// Also detects SMI language from imports.
fn lower_imports(
    import_clauses: &[ast::ImportClause],
    ctx: &mut LoweringContext,
) -> Vec<Import> {
    let mut imports = Vec::new();

    for clause in import_clauses {
        let from_module = &clause.from_module.name;

        // Detect language from imports
        if is_smiv2_base_module(from_module) {
            ctx.language = SmiLanguage::Smiv2;
        }

        // Flatten each symbol
        for symbol in &clause.symbols {
            imports.push(Import::new(
                Symbol::from_name(from_module),
                Symbol::from(symbol.name.as_str()),
                clause.span,
            ));
        }
    }

    // Default to SMIv1 if no SMIv2 imports detected
    if ctx.language == SmiLanguage::Unknown {
        ctx.language = SmiLanguage::Smiv1;
    }

    imports
}

/// Lower a single definition.
///
/// Returns `None` for definitions that are filtered out (MACRO, Error).
fn lower_definition(def: &ast::Definition, ctx: &LoweringContext) -> Option<Definition> {
    match def {
        ast::Definition::ObjectType(d) => Some(Definition::ObjectType(lower_object_type(d, ctx))),
        ast::Definition::ModuleIdentity(d) => {
            Some(Definition::ModuleIdentity(lower_module_identity(d)))
        }
        ast::Definition::ObjectIdentity(d) => {
            Some(Definition::ObjectIdentity(lower_object_identity(d)))
        }
        ast::Definition::NotificationType(d) => {
            Some(Definition::Notification(lower_notification_type(d)))
        }
        ast::Definition::TrapType(d) => Some(Definition::Notification(lower_trap_type(d))),
        ast::Definition::TextualConvention(d) => {
            Some(Definition::TypeDef(lower_textual_convention(d)))
        }
        ast::Definition::TypeAssignment(d) => Some(Definition::TypeDef(lower_type_assignment(d))),
        ast::Definition::ValueAssignment(d) => {
            Some(Definition::ValueAssignment(lower_value_assignment(d)))
        }
        ast::Definition::ObjectGroup(d) => Some(Definition::ObjectGroup(lower_object_group(d))),
        ast::Definition::NotificationGroup(d) => Some(Definition::NotificationGroup(
            lower_notification_group(d),
        )),
        ast::Definition::ModuleCompliance(d) => {
            Some(Definition::ModuleCompliance(lower_module_compliance(d)))
        }
        ast::Definition::AgentCapabilities(d) => Some(Definition::AgentCapabilities(
            lower_agent_capabilities(d),
        )),
        // Filter out non-semantic definitions
        ast::Definition::MacroDefinition(_) | ast::Definition::Error(_) => None,
    }
}

// === Definition lowering functions ===

fn lower_object_type(def: &ast::ObjectTypeDef, _ctx: &LoweringContext) -> ObjectType {
    ObjectType {
        name: Symbol::from(&def.name),
        syntax: lower_type_syntax(&def.syntax.syntax),
        units: def.units.as_ref().map(|u| u.value.clone()),
        access: lower_access(def.access.value),
        status: def
            .status
            .as_ref()
            .map_or(Status::Current, |s| lower_status(s.value)),
        description: def.description.as_ref().map(|d| d.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        index: lower_index_clause(def.index.as_ref()),
        augments: def.augments.as_ref().map(|a| Symbol::from(&a.target)),
        defval: def.defval.as_ref().map(lower_defval),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

/// Lower a DEFVAL clause from AST.
fn lower_defval(clause: &DefValClause) -> DefVal {
    lower_defval_content(&clause.value)
}

/// Lower `DefValContent` from AST.
fn lower_defval_content(content: &DefValContent) -> DefVal {
    match content {
        DefValContent::Integer(n) => DefVal::Integer(*n),
        DefValContent::Unsigned(n) => DefVal::Unsigned(*n),
        DefValContent::String(qs) => DefVal::String(qs.value.clone()),
        DefValContent::Identifier(ident) => {
            // Could be enum label or OID reference - we can't distinguish
            // until semantic analysis, so treat as Enum (most common case)
            DefVal::Enum(Symbol::from(ident))
        }
        DefValContent::Bits { labels, .. } => {
            DefVal::Bits(labels.iter().map(Symbol::from).collect())
        }
        DefValContent::HexString { content, .. } => DefVal::HexString(content.clone()),
        DefValContent::BinaryString { content, .. } => DefVal::BinaryString(content.clone()),
        DefValContent::ObjectIdentifier { components, .. } => {
            DefVal::OidValue(lower_oid_components(components))
        }
    }
}

/// Lower OID components from AST.
fn lower_oid_components(components: &[ast::OidComponent]) -> Vec<OidComponent> {
    components.iter().map(lower_oid_component).collect()
}

fn lower_module_identity(def: &ast::ModuleIdentityDef) -> ModuleIdentity {
    ModuleIdentity {
        name: Symbol::from(&def.name),
        last_updated: def.last_updated.value.clone(),
        organization: def.organization.value.clone(),
        contact_info: def.contact_info.value.clone(),
        description: def.description.value.clone(),
        revisions: def
            .revisions
            .iter()
            .map(|r| Revision {
                date: r.date.value.clone(),
                description: r.description.value.clone(),
            })
            .collect(),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_object_identity(def: &ast::ObjectIdentityDef) -> ObjectIdentity {
    ObjectIdentity {
        name: Symbol::from(&def.name),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_notification_type(def: &ast::NotificationTypeDef) -> Notification {
    Notification {
        name: Symbol::from(&def.name),
        objects: def.objects.iter().map(Symbol::from).collect(),
        status: lower_status(def.status.value),
        description: Some(def.description.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        trap_info: None,
        oid: Some(lower_oid_assignment(&def.oid_assignment)),
        span: def.span,
    }
}

fn lower_trap_type(def: &ast::TrapTypeDef) -> Notification {
    Notification {
        name: Symbol::from(&def.name),
        objects: def.variables.iter().map(Symbol::from).collect(),
        status: Status::Current, // TRAP-TYPE doesn't have STATUS
        description: def.description.as_ref().map(|d| d.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        trap_info: Some(TrapInfo {
            enterprise: Symbol::from(&def.enterprise),
            trap_number: def.trap_number,
        }),
        oid: None, // TRAP-TYPE OID is derived from enterprise + trap_number
        span: def.span,
    }
}

fn lower_textual_convention(def: &ast::TextualConventionDef) -> TypeDef {
    TypeDef {
        name: Symbol::from(&def.name),
        syntax: lower_type_syntax(&def.syntax.syntax),
        base_type: None, // Derived from syntax during resolution
        display_hint: def.display_hint.as_ref().map(|h| h.value.clone()),
        status: lower_status(def.status.value),
        description: Some(def.description.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        is_textual_convention: true,
        span: def.span,
    }
}

fn lower_type_assignment(def: &ast::TypeAssignmentDef) -> TypeDef {
    TypeDef {
        name: Symbol::from(&def.name),
        syntax: lower_type_syntax(&def.syntax),
        base_type: None, // Derived from syntax during resolution
        display_hint: None,
        status: Status::Current,
        description: None,
        reference: None,
        is_textual_convention: false,
        span: def.span,
    }
}

fn lower_value_assignment(def: &ast::ValueAssignmentDef) -> ValueAssignment {
    ValueAssignment {
        name: Symbol::from(&def.name),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_object_group(def: &ast::ObjectGroupDef) -> ObjectGroup {
    ObjectGroup {
        name: Symbol::from(&def.name),
        objects: def.objects.iter().map(Symbol::from).collect(),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_notification_group(def: &ast::NotificationGroupDef) -> NotificationGroup {
    NotificationGroup {
        name: Symbol::from(&def.name),
        notifications: def.notifications.iter().map(Symbol::from).collect(),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_module_compliance(def: &ast::ModuleComplianceDef) -> ModuleCompliance {
    ModuleCompliance {
        name: Symbol::from(&def.name),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        modules: def.modules.iter().map(lower_compliance_module).collect(),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

/// Lower a compliance MODULE clause.
fn lower_compliance_module(m: &ast::ComplianceModule) -> ComplianceModule {
    ComplianceModule {
        module_name: m.module_name.as_ref().map(Symbol::from),
        mandatory_groups: m.mandatory_groups.iter().map(Symbol::from).collect(),
        groups: m
            .compliances
            .iter()
            .filter_map(|c| match c {
                ast::Compliance::Group(g) => Some(lower_compliance_group(g)),
                ast::Compliance::Object(_) => None,
            })
            .collect(),
        objects: m
            .compliances
            .iter()
            .filter_map(|c| match c {
                ast::Compliance::Object(o) => Some(lower_compliance_object(o)),
                ast::Compliance::Group(_) => None,
            })
            .collect(),
    }
}

/// Lower a compliance GROUP clause.
fn lower_compliance_group(g: &ast::ComplianceGroup) -> ComplianceGroup {
    ComplianceGroup {
        group: Symbol::from(&g.group),
        description: g.description.value.clone(),
    }
}

/// Lower a compliance OBJECT clause.
fn lower_compliance_object(o: &ast::ComplianceObject) -> ComplianceObject {
    ComplianceObject {
        object: Symbol::from(&o.object),
        syntax: o.syntax.as_ref().map(|s| lower_type_syntax(&s.syntax)),
        write_syntax: o
            .write_syntax
            .as_ref()
            .map(|s| lower_type_syntax(&s.syntax)),
        min_access: o.min_access.as_ref().map(|a| lower_access(a.value)),
        description: o.description.value.clone(),
    }
}

fn lower_agent_capabilities(def: &ast::AgentCapabilitiesDef) -> AgentCapabilities {
    AgentCapabilities {
        name: Symbol::from(&def.name),
        product_release: def.product_release.value.clone(),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        supports: def.supports.iter().map(lower_supports_module).collect(),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_supports_module(module: &ast::SupportsModule) -> SupportsModule {
    let mut object_variations = Vec::new();
    let mut notification_variations = Vec::new();

    for variation in &module.variations {
        match variation {
            ast::Variation::Object(v) => {
                object_variations.push(lower_object_variation(v));
            }
            ast::Variation::Notification(v) => {
                notification_variations.push(lower_notification_variation(v));
            }
        }
    }

    SupportsModule {
        module_name: Symbol::from(&module.module_name),
        includes: module.includes.iter().map(Symbol::from).collect(),
        object_variations,
        notification_variations,
    }
}

fn lower_object_variation(v: &ast::ObjectVariation) -> ObjectVariation {
    ObjectVariation {
        object: Symbol::from(&v.object),
        syntax: v.syntax.as_ref().map(|s| lower_type_syntax(&s.syntax)),
        write_syntax: v
            .write_syntax
            .as_ref()
            .map(|s| lower_type_syntax(&s.syntax)),
        access: v.access.as_ref().map(|a| lower_access(a.value)),
        creation_requires: v
            .creation_requires
            .as_ref()
            .map(|objs| objs.iter().map(Symbol::from).collect()),
        defval: v.defval.as_ref().map(lower_defval),
        description: v.description.value.clone(),
    }
}

fn lower_notification_variation(v: &ast::NotificationVariation) -> NotificationVariation {
    NotificationVariation {
        notification: Symbol::from(&v.notification),
        access: v.access.as_ref().map(|a| lower_access(a.value)),
        description: v.description.value.clone(),
    }
}

// === Helper lowering functions ===

/// Lower AST type syntax.
fn lower_type_syntax(syntax: &ast::TypeSyntax) -> TypeSyntax {
    match syntax {
        ast::TypeSyntax::TypeRef(ident) => {
            TypeSyntax::TypeRef(Symbol::from(ident))
        }
        ast::TypeSyntax::IntegerEnum { named_numbers, .. } => TypeSyntax::IntegerEnum(
            named_numbers
                .iter()
                .map(|nn| NamedNumber::new(Symbol::from(&nn.name), nn.value))
                .collect(),
        ),
        ast::TypeSyntax::Bits { named_bits, .. } => TypeSyntax::Bits(
            named_bits
                .iter()
                .map(|nb| {
                    // BITS positions are small non-negative integers (0-127)
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let pos = nb.value as u32;
                    NamedBit::new(Symbol::from(&nb.name), pos)
                })
                .collect(),
        ),
        ast::TypeSyntax::Constrained {
            base, constraint, ..
        } => TypeSyntax::Constrained {
            base: alloc::boxed::Box::new(lower_type_syntax(base)),
            constraint: lower_constraint(constraint),
        },
        ast::TypeSyntax::SequenceOf { entry_type, .. } => {
            TypeSyntax::SequenceOf(Symbol::from(entry_type))
        }
        ast::TypeSyntax::Sequence { fields, .. } => TypeSyntax::Sequence(
            fields
                .iter()
                .map(|f| SequenceField::new(Symbol::from(&f.name), lower_type_syntax(&f.syntax)))
                .collect(),
        ),
        ast::TypeSyntax::OctetString { .. } => TypeSyntax::OctetString,
        ast::TypeSyntax::ObjectIdentifier { .. } => TypeSyntax::ObjectIdentifier,
    }
}

/// Lower AST constraint.
fn lower_constraint(constraint: &ast::Constraint) -> Constraint {
    match constraint {
        ast::Constraint::Size { ranges, .. } => {
            Constraint::Size(ranges.iter().map(lower_range).collect())
        }
        ast::Constraint::Range { ranges, .. } => {
            Constraint::Range(ranges.iter().map(lower_range).collect())
        }
    }
}

/// Lower AST range.
fn lower_range(range: &ast::Range) -> Range {
    Range {
        min: lower_range_value(&range.min),
        max: range.max.as_ref().map(lower_range_value),
    }
}

/// Lower AST range value.
fn lower_range_value(value: &AstRangeValue) -> RangeValue {
    match value {
        AstRangeValue::Signed(n) => RangeValue::Signed(*n),
        AstRangeValue::Unsigned(n) => RangeValue::Unsigned(*n),
        AstRangeValue::Ident(ident) => {
            // Handle MIN/MAX keywords
            match ident.name.as_str() {
                "MIN" => RangeValue::Min,
                "MAX" => RangeValue::Max,
                // Shouldn't happen, but fallback to unsigned 0
                _ => RangeValue::Unsigned(0),
            }
        }
    }
}

/// Lower AST OID assignment.
fn lower_oid_assignment(oid: &ast::OidAssignment) -> OidAssignment {
    OidAssignment {
        components: oid.components.iter().map(lower_oid_component).collect(),
        span: oid.span,
    }
}

/// Lower AST OID component.
fn lower_oid_component(comp: &ast::OidComponent) -> OidComponent {
    match comp {
        ast::OidComponent::Name(ident) => OidComponent::Name(Symbol::from(ident)),
        ast::OidComponent::Number { value, .. } => OidComponent::Number(*value),
        ast::OidComponent::NamedNumber { name, number, .. } => OidComponent::NamedNumber {
            name: Symbol::from(name),
            number: *number,
        },
        ast::OidComponent::QualifiedName { module, name, .. } => OidComponent::QualifiedName {
            module: Symbol::from(module),
            name: Symbol::from(name),
        },
        ast::OidComponent::QualifiedNamedNumber {
            module,
            name,
            number,
            ..
        } => OidComponent::QualifiedNamedNumber {
            module: Symbol::from(module),
            name: Symbol::from(name),
            number: *number,
        },
    }
}

/// Lower AST access value.
fn lower_access(access: AccessValue) -> Access {
    match access {
        AccessValue::ReadOnly | AccessValue::ReportOnly => Access::ReadOnly,
        AccessValue::ReadWrite | AccessValue::Install | AccessValue::InstallNotify => {
            Access::ReadWrite
        }
        AccessValue::ReadCreate => Access::ReadCreate,
        AccessValue::NotAccessible | AccessValue::NotImplemented => Access::NotAccessible,
        AccessValue::AccessibleForNotify => Access::AccessibleForNotify,
        AccessValue::WriteOnly => Access::WriteOnly,
    }
}

/// Lower AST status value.
fn lower_status(status: StatusValue) -> Status {
    match status {
        StatusValue::Current | StatusValue::Mandatory => Status::Current,
        StatusValue::Deprecated | StatusValue::Optional => Status::Deprecated,
        StatusValue::Obsolete => Status::Obsolete,
    }
}

/// Lower AST index clause.
fn lower_index_clause(clause: Option<&IndexClause>) -> Option<Vec<IndexItem>> {
    clause.map(|c| match c {
        IndexClause::Index { indexes, .. } | IndexClause::PibIndex { indexes, .. } => indexes
            .iter()
            .map(|i| IndexItem::new(Symbol::from(&i.object), i.implied))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lower_access() {
        assert_eq!(lower_access(AccessValue::ReadOnly), Access::ReadOnly);
        assert_eq!(lower_access(AccessValue::ReadWrite), Access::ReadWrite);
        assert_eq!(lower_access(AccessValue::ReadCreate), Access::ReadCreate);
    }

    #[test]
    fn test_lower_status() {
        assert_eq!(lower_status(StatusValue::Current), Status::Current);
        assert_eq!(lower_status(StatusValue::Deprecated), Status::Deprecated);
        assert_eq!(lower_status(StatusValue::Obsolete), Status::Obsolete);
        // SMIv1 normalization
        assert_eq!(lower_status(StatusValue::Mandatory), Status::Current);
        assert_eq!(lower_status(StatusValue::Optional), Status::Deprecated);
    }
}
