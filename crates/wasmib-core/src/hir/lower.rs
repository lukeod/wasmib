//! AST to HIR lowering.
//!
//! Transforms parsed AST into normalized HIR representation.
//! This module handles:
//! - Language detection from imports
//! - Import normalization
//! - Type normalization
//! - Status normalization
//! - Unification of SMIv1/SMIv2 forms

use super::definition::{
    HirAgentCapabilities, HirComplianceGroup, HirComplianceModule, HirComplianceObject,
    HirDefinition, HirIndexItem, HirModuleCompliance, HirModuleIdentity, HirNotification,
    HirNotificationGroup, HirNotificationVariation, HirObjectGroup, HirObjectIdentity,
    HirObjectType, HirObjectVariation, HirRevision, HirSupportsModule, HirTrapInfo, HirTypeDef,
    HirValueAssignment,
};
use super::module::{HirImport, HirModule};
use super::normalize::{is_smiv2_base_module, normalize_import, normalize_type_name};
use super::syntax::{
    HirConstraint, HirDefVal, HirOidAssignment, HirOidComponent, HirRange, HirRangeValue,
    HirTypeSyntax, NamedBit, NamedNumber, SequenceField,
};
use super::types::{HirAccess, HirStatus, SmiLanguage, Symbol};
use crate::ast::{
    self, AccessValue, Constraint, DefValClause, DefValContent, Definition, IndexClause, Module,
    OidComponent, RangeValue, StatusValue, TypeSyntax,
};
use crate::lexer::Diagnostic;
use alloc::vec::Vec;

/// Context for HIR lowering.
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

/// Lower an AST module to HIR.
///
/// This is the main entry point for HIR lowering. It:
/// 1. Detects the SMI language from imports
/// 2. Normalizes imports
/// 3. Lowers each definition
///
/// # Arguments
///
/// * `ast_module` - The parsed AST module
///
/// # Returns
///
/// A normalized HIR module with diagnostics.
#[must_use]
pub fn lower_module(ast_module: &Module) -> HirModule {
    let mut ctx = LoweringContext::new();

    // Create HIR module
    let mut hir_module = HirModule::new(Symbol::from(&ast_module.name), ast_module.span);

    // Lower imports and detect language
    hir_module.imports = lower_imports(&ast_module.imports, &mut ctx);
    hir_module.language = ctx.language;

    // Lower definitions
    for def in &ast_module.body {
        if let Some(hir_def) = lower_definition(def, &ctx) {
            hir_module.definitions.push(hir_def);
        }
    }

    // Collect diagnostics from AST and lowering
    hir_module.diagnostics.clone_from(&ast_module.diagnostics);
    hir_module.diagnostics.extend(ctx.diagnostics);

    hir_module
}

/// Lower import clauses to HIR imports.
///
/// Also detects SMI language from imports.
fn lower_imports(
    import_clauses: &[ast::ImportClause],
    ctx: &mut LoweringContext,
) -> Vec<HirImport> {
    let mut imports = Vec::new();

    for clause in import_clauses {
        let from_module = &clause.from_module.name;

        // Detect language from imports
        if is_smiv2_base_module(from_module) {
            ctx.language = SmiLanguage::Smiv2;
        }

        // Flatten and normalize each symbol
        for symbol in &clause.symbols {
            let normalized = normalize_import(from_module, &symbol.name);
            imports.push(HirImport::new(
                normalized.module,
                normalized.symbol,
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

/// Lower a single definition to HIR.
///
/// Returns `None` for definitions that are filtered out (MACRO, Error).
fn lower_definition(def: &Definition, ctx: &LoweringContext) -> Option<HirDefinition> {
    match def {
        Definition::ObjectType(d) => Some(HirDefinition::ObjectType(lower_object_type(d, ctx))),
        Definition::ModuleIdentity(d) => {
            Some(HirDefinition::ModuleIdentity(lower_module_identity(d)))
        }
        Definition::ObjectIdentity(d) => {
            Some(HirDefinition::ObjectIdentity(lower_object_identity(d)))
        }
        Definition::NotificationType(d) => {
            Some(HirDefinition::Notification(lower_notification_type(d)))
        }
        Definition::TrapType(d) => Some(HirDefinition::Notification(lower_trap_type(d))),
        Definition::TextualConvention(d) => {
            Some(HirDefinition::TypeDef(lower_textual_convention(d)))
        }
        Definition::TypeAssignment(d) => Some(HirDefinition::TypeDef(lower_type_assignment(d))),
        Definition::ValueAssignment(d) => {
            Some(HirDefinition::ValueAssignment(lower_value_assignment(d)))
        }
        Definition::ObjectGroup(d) => Some(HirDefinition::ObjectGroup(lower_object_group(d))),
        Definition::NotificationGroup(d) => Some(HirDefinition::NotificationGroup(
            lower_notification_group(d),
        )),
        Definition::ModuleCompliance(d) => {
            Some(HirDefinition::ModuleCompliance(lower_module_compliance(d)))
        }
        Definition::AgentCapabilities(d) => Some(HirDefinition::AgentCapabilities(
            lower_agent_capabilities(d),
        )),
        // Filter out non-semantic definitions
        Definition::MacroDefinition(_) | Definition::Error(_) => None,
    }
}

// === Definition lowering functions ===

fn lower_object_type(def: &ast::ObjectTypeDef, _ctx: &LoweringContext) -> HirObjectType {
    HirObjectType {
        name: Symbol::from(&def.name),
        syntax: lower_type_syntax(&def.syntax.syntax),
        units: def.units.as_ref().map(|u| u.value.clone()),
        access: lower_access(def.access.value),
        status: def
            .status
            .as_ref()
            .map_or(HirStatus::Current, |s| lower_status(s.value)),
        description: def.description.as_ref().map(|d| d.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        index: lower_index_clause(def.index.as_ref()),
        augments: def.augments.as_ref().map(|a| Symbol::from(&a.target)),
        defval: def.defval.as_ref().map(lower_defval),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

/// Lower a DEFVAL clause from AST to HIR.
fn lower_defval(clause: &DefValClause) -> HirDefVal {
    lower_defval_content(&clause.value)
}

/// Lower `DefValContent` from AST to `HirDefVal`.
fn lower_defval_content(content: &DefValContent) -> HirDefVal {
    match content {
        DefValContent::Integer(n) => HirDefVal::Integer(*n),
        DefValContent::Unsigned(n) => HirDefVal::Unsigned(*n),
        DefValContent::String(qs) => HirDefVal::String(qs.value.clone()),
        DefValContent::Identifier(ident) => {
            // Could be enum label or OID reference - we can't distinguish
            // until semantic analysis, so treat as Enum (most common case)
            HirDefVal::Enum(Symbol::from(ident))
        }
        DefValContent::Bits { labels, .. } => {
            HirDefVal::Bits(labels.iter().map(Symbol::from).collect())
        }
        DefValContent::HexString { content, .. } => HirDefVal::HexString(content.clone()),
        DefValContent::BinaryString { content, .. } => HirDefVal::BinaryString(content.clone()),
        DefValContent::ObjectIdentifier { components, .. } => {
            HirDefVal::OidValue(lower_oid_components(components))
        }
    }
}

/// Lower OID components from AST to HIR OID components.
fn lower_oid_components(components: &[OidComponent]) -> Vec<HirOidComponent> {
    components.iter().map(lower_oid_component).collect()
}

fn lower_module_identity(def: &ast::ModuleIdentityDef) -> HirModuleIdentity {
    HirModuleIdentity {
        name: Symbol::from(&def.name),
        last_updated: def.last_updated.value.clone(),
        organization: def.organization.value.clone(),
        contact_info: def.contact_info.value.clone(),
        description: def.description.value.clone(),
        revisions: def
            .revisions
            .iter()
            .map(|r| HirRevision {
                date: r.date.value.clone(),
                description: r.description.value.clone(),
            })
            .collect(),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_object_identity(def: &ast::ObjectIdentityDef) -> HirObjectIdentity {
    HirObjectIdentity {
        name: Symbol::from(&def.name),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_notification_type(def: &ast::NotificationTypeDef) -> HirNotification {
    HirNotification {
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

fn lower_trap_type(def: &ast::TrapTypeDef) -> HirNotification {
    HirNotification {
        name: Symbol::from(&def.name),
        objects: def.variables.iter().map(Symbol::from).collect(),
        status: HirStatus::Current, // TRAP-TYPE doesn't have STATUS
        description: def.description.as_ref().map(|d| d.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        trap_info: Some(HirTrapInfo {
            enterprise: Symbol::from(&def.enterprise),
            trap_number: def.trap_number,
        }),
        oid: None, // TRAP-TYPE OID is derived from enterprise + trap_number
        span: def.span,
    }
}

fn lower_textual_convention(def: &ast::TextualConventionDef) -> HirTypeDef {
    HirTypeDef {
        name: Symbol::from(&def.name),
        syntax: lower_type_syntax(&def.syntax.syntax),
        display_hint: def.display_hint.as_ref().map(|h| h.value.clone()),
        status: lower_status(def.status.value),
        description: Some(def.description.value.clone()),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        is_textual_convention: true,
        span: def.span,
    }
}

fn lower_type_assignment(def: &ast::TypeAssignmentDef) -> HirTypeDef {
    HirTypeDef {
        name: Symbol::from(&def.name),
        syntax: lower_type_syntax(&def.syntax),
        display_hint: None,
        status: HirStatus::Current,
        description: None,
        reference: None,
        is_textual_convention: false,
        span: def.span,
    }
}

fn lower_value_assignment(def: &ast::ValueAssignmentDef) -> HirValueAssignment {
    HirValueAssignment {
        name: Symbol::from(&def.name),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_object_group(def: &ast::ObjectGroupDef) -> HirObjectGroup {
    HirObjectGroup {
        name: Symbol::from(&def.name),
        objects: def.objects.iter().map(Symbol::from).collect(),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_notification_group(def: &ast::NotificationGroupDef) -> HirNotificationGroup {
    HirNotificationGroup {
        name: Symbol::from(&def.name),
        notifications: def.notifications.iter().map(Symbol::from).collect(),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

fn lower_module_compliance(def: &ast::ModuleComplianceDef) -> HirModuleCompliance {
    HirModuleCompliance {
        name: Symbol::from(&def.name),
        status: lower_status(def.status.value),
        description: def.description.value.clone(),
        reference: def.reference.as_ref().map(|r| r.value.clone()),
        modules: def.modules.iter().map(lower_compliance_module).collect(),
        oid: lower_oid_assignment(&def.oid_assignment),
        span: def.span,
    }
}

/// Lower a compliance MODULE clause to HIR.
fn lower_compliance_module(m: &ast::ComplianceModule) -> HirComplianceModule {
    HirComplianceModule {
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

/// Lower a compliance GROUP clause to HIR.
fn lower_compliance_group(g: &ast::ComplianceGroup) -> HirComplianceGroup {
    HirComplianceGroup {
        group: Symbol::from(&g.group),
        description: g.description.value.clone(),
    }
}

/// Lower a compliance OBJECT clause to HIR.
fn lower_compliance_object(o: &ast::ComplianceObject) -> HirComplianceObject {
    HirComplianceObject {
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

fn lower_agent_capabilities(def: &ast::AgentCapabilitiesDef) -> HirAgentCapabilities {
    HirAgentCapabilities {
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

fn lower_supports_module(module: &ast::SupportsModule) -> HirSupportsModule {
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

    HirSupportsModule {
        module_name: Symbol::from(&module.module_name),
        includes: module.includes.iter().map(Symbol::from).collect(),
        object_variations,
        notification_variations,
    }
}

fn lower_object_variation(v: &ast::ObjectVariation) -> HirObjectVariation {
    HirObjectVariation {
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

fn lower_notification_variation(v: &ast::NotificationVariation) -> HirNotificationVariation {
    HirNotificationVariation {
        notification: Symbol::from(&v.notification),
        access: v.access.as_ref().map(|a| lower_access(a.value)),
        description: v.description.value.clone(),
    }
}

// === Helper lowering functions ===

/// Lower AST type syntax to HIR type syntax with normalization.
fn lower_type_syntax(syntax: &TypeSyntax) -> HirTypeSyntax {
    match syntax {
        TypeSyntax::TypeRef(ident) => {
            // Normalize type name (Counter→Counter32, etc.)
            let normalized_name = normalize_type_name(&ident.name);
            HirTypeSyntax::TypeRef(Symbol::from_name(normalized_name))
        }
        TypeSyntax::IntegerEnum { named_numbers, .. } => HirTypeSyntax::IntegerEnum(
            named_numbers
                .iter()
                .map(|nn| NamedNumber::new(Symbol::from(&nn.name), nn.value))
                .collect(),
        ),
        TypeSyntax::Bits { named_bits, .. } => HirTypeSyntax::Bits(
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
        TypeSyntax::Constrained {
            base, constraint, ..
        } => HirTypeSyntax::Constrained {
            base: alloc::boxed::Box::new(lower_type_syntax(base)),
            constraint: lower_constraint(constraint),
        },
        TypeSyntax::SequenceOf { entry_type, .. } => {
            HirTypeSyntax::SequenceOf(Symbol::from(entry_type))
        }
        TypeSyntax::Sequence { fields, .. } => HirTypeSyntax::Sequence(
            fields
                .iter()
                .map(|f| SequenceField::new(Symbol::from(&f.name), lower_type_syntax(&f.syntax)))
                .collect(),
        ),
        TypeSyntax::OctetString { .. } => HirTypeSyntax::OctetString,
        TypeSyntax::ObjectIdentifier { .. } => HirTypeSyntax::ObjectIdentifier,
    }
}

/// Lower AST constraint to HIR constraint.
fn lower_constraint(constraint: &Constraint) -> HirConstraint {
    match constraint {
        Constraint::Size { ranges, .. } => {
            HirConstraint::Size(ranges.iter().map(lower_range).collect())
        }
        Constraint::Range { ranges, .. } => {
            HirConstraint::Range(ranges.iter().map(lower_range).collect())
        }
    }
}

/// Lower AST range to HIR range.
fn lower_range(range: &ast::Range) -> HirRange {
    HirRange {
        min: lower_range_value(&range.min),
        max: range.max.as_ref().map(lower_range_value),
    }
}

/// Lower AST range value to HIR range value.
fn lower_range_value(value: &RangeValue) -> HirRangeValue {
    match value {
        RangeValue::Signed(n) => HirRangeValue::Signed(*n),
        RangeValue::Unsigned(n) => HirRangeValue::Unsigned(*n),
        RangeValue::Ident(ident) => {
            // Handle MIN/MAX keywords
            match ident.name.as_str() {
                "MIN" => HirRangeValue::Min,
                "MAX" => HirRangeValue::Max,
                // Shouldn't happen, but fallback to unsigned 0
                _ => HirRangeValue::Unsigned(0),
            }
        }
    }
}

/// Lower AST OID assignment to HIR OID assignment.
fn lower_oid_assignment(oid: &ast::OidAssignment) -> HirOidAssignment {
    HirOidAssignment {
        components: oid.components.iter().map(lower_oid_component).collect(),
        span: oid.span,
    }
}

/// Lower AST OID component to HIR OID component.
fn lower_oid_component(comp: &OidComponent) -> HirOidComponent {
    match comp {
        OidComponent::Name(ident) => HirOidComponent::Name(Symbol::from(ident)),
        OidComponent::Number { value, .. } => HirOidComponent::Number(*value),
        OidComponent::NamedNumber { name, number, .. } => HirOidComponent::NamedNumber {
            name: Symbol::from(name),
            number: *number,
        },
        OidComponent::QualifiedName { module, name, .. } => HirOidComponent::QualifiedName {
            module: Symbol::from(module),
            name: Symbol::from(name),
        },
        OidComponent::QualifiedNamedNumber {
            module,
            name,
            number,
            ..
        } => HirOidComponent::QualifiedNamedNumber {
            module: Symbol::from(module),
            name: Symbol::from(name),
            number: *number,
        },
    }
}

/// Lower AST access value to HIR access.
fn lower_access(access: AccessValue) -> HirAccess {
    match access {
        AccessValue::ReadOnly | AccessValue::ReportOnly => HirAccess::ReadOnly,
        AccessValue::ReadWrite | AccessValue::Install | AccessValue::InstallNotify => {
            HirAccess::ReadWrite
        }
        AccessValue::ReadCreate => HirAccess::ReadCreate,
        AccessValue::NotAccessible | AccessValue::NotImplemented => HirAccess::NotAccessible,
        AccessValue::AccessibleForNotify => HirAccess::AccessibleForNotify,
        AccessValue::WriteOnly => HirAccess::WriteOnly,
    }
}

/// Lower AST status value to HIR status with normalization.
fn lower_status(status: StatusValue) -> HirStatus {
    match status {
        StatusValue::Current | StatusValue::Mandatory => HirStatus::Current,
        StatusValue::Deprecated | StatusValue::Optional => HirStatus::Deprecated,
        StatusValue::Obsolete => HirStatus::Obsolete,
    }
}

/// Lower AST index clause to HIR index items.
fn lower_index_clause(clause: Option<&IndexClause>) -> Option<Vec<HirIndexItem>> {
    clause.map(|c| match c {
        IndexClause::Index { indexes, .. } | IndexClause::PibIndex { indexes, .. } => indexes
            .iter()
            .map(|i| HirIndexItem::new(Symbol::from(&i.object), i.implied))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lower_access() {
        assert_eq!(lower_access(AccessValue::ReadOnly), HirAccess::ReadOnly);
        assert_eq!(lower_access(AccessValue::ReadWrite), HirAccess::ReadWrite);
        assert_eq!(lower_access(AccessValue::ReadCreate), HirAccess::ReadCreate);
    }

    #[test]
    fn test_lower_status() {
        assert_eq!(lower_status(StatusValue::Current), HirStatus::Current);
        assert_eq!(lower_status(StatusValue::Deprecated), HirStatus::Deprecated);
        assert_eq!(lower_status(StatusValue::Obsolete), HirStatus::Obsolete);
        // SMIv1 normalization
        assert_eq!(lower_status(StatusValue::Mandatory), HirStatus::Current);
        assert_eq!(lower_status(StatusValue::Optional), HirStatus::Deprecated);
    }
}
