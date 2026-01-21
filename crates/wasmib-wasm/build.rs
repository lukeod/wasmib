//! Build script for generating protobuf code from wasmib.proto

use micropb_gen::{EncodeDecode, Generator};
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto_dir = Path::new(&manifest_dir).join("../../proto");
    let proto_path = proto_dir.join("wasmib.proto");
    let proto_path = proto_path
        .canonicalize()
        .expect("Failed to canonicalize proto path");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_file = Path::new(&out_dir).join("wasmib.rs");

    println!("cargo:rerun-if-changed={}", proto_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    // Change to proto directory so protoc can find the file
    std::env::set_current_dir(proto_path.parent().unwrap())
        .expect("Failed to change to proto directory");

    let mut generator = Generator::new();

    // Use alloc types (Vec, String) instead of heapless containers
    generator.use_container_alloc();

    // Generate both encode and decode code for cache round-trips
    generator.encode_decode(EncodeDecode::Both);

    generator
        .compile_protos(&["wasmib.proto"], out_file)
        .expect("Failed to compile proto files");
}
