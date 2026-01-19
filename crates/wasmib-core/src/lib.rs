//! wasmib-core: Pure MIB parser library
//!
//! This crate provides the core parsing functionality for SNMP MIB files.
//! It is designed to be `no_std` compatible and IO-free for WASM portability.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod ast;
pub mod lexer;
pub mod parser;
