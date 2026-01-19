//! wasmib-wasm: WASM FFI boundary
//!
//! This crate provides the WebAssembly interface for wasmib,
//! including memory management and serialization.

#![no_std]

extern crate alloc;

// SAFETY: The runtime environment must be single-threaded WASM.
#[cfg(target_arch = "wasm32")]
#[global_allocator]
#[allow(unsafe_code)]
static ALLOCATOR: talc::TalckWasm = unsafe { talc::TalckWasm::new_global() };

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use wasmib_core;
