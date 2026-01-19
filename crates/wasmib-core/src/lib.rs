//! wasmib-core: Pure MIB parser library
//!
//! This crate provides the core parsing functionality for SNMP MIB files.
//! It is designed to be `no_std` compatible and IO-free for WASM portability.
//!
//! # Pipeline
//!
//! ```text
//! Source → Lexer → Tokens → Parser → AST → HIR Lowering → HIR → Resolver → Model
//!          ^^^^^            ^^^^^^         ^^^^^^^^^^^^^        ^^^^^^^^    ^^^^^
//!          lexer            parser         hir                  resolver    model
//! ```
//!
//! - **Lexer** (`lexer`): Tokenizes MIB source text
//! - **Parser** (`parser`): Builds AST from tokens
//! - **HIR** (`hir`): Normalized intermediate representation with SMIv1/v2 unification
//! - **Resolver** (`resolver`): Symbol resolution, OID tree building
//! - **Model** (`model`): Final resolved representation

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod ast;
pub mod hir;
pub mod lexer;
pub mod model;
pub mod parser;
pub mod resolver;
