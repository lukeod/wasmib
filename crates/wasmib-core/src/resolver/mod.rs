//! Symbol resolution for MIB modules.
//!
//! The resolver transforms HIR modules (with unresolved symbol references) into
//! a fully resolved Model. It handles:
//!
//! - Import resolution (from built-ins and user modules)
//! - Type resolution (building inheritance chains)
//! - OID tree construction
//! - Table/index semantics
//!
//! # Pipeline
//!
//! ```text
//! HIR Modules → Resolver → Model
//! ```
//!
//! # Built-in Definitions
//!
//! The resolver is pre-seeded with built-in definitions from SMI base modules:
//!
//! - **Types**: Integer32, Counter32, etc. from SNMPv2-SMI
//! - **Textual Conventions**: DisplayString, TruthValue, etc. from SNMPv2-TC
//! - **OID Roots**: iso, internet, enterprises, etc.
//! - **MACROs**: OBJECT-TYPE, MODULE-IDENTITY, etc.
//!
//! These resolve automatically without requiring user-provided base module files.
//!
//! # Usage
//!
//! ```ignore
//! use wasmib_core::resolver::builtins::resolve_builtin_symbol;
//!
//! // Check if a symbol from a base module import resolves
//! if let Some(sym) = resolve_builtin_symbol("SNMPv2-SMI", "Counter32") {
//!     // sym is a BuiltinSymbol::BaseType
//! }
//! ```

pub mod builtins;

pub use builtins::{
    is_base_module, resolve_builtin_symbol, BaseModule, BuiltinBaseType, BuiltinMacro,
    BuiltinOidNode, BuiltinSymbol, BuiltinTextualConvention, TcBaseSyntax, TcConstraint,
    TcSizeConstraint, BUILTIN_OID_NODES, BUILTIN_TEXTUAL_CONVENTIONS,
};
