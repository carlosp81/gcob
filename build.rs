fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "proto/api/v1";

    tonic_prost_build::configure()
        .type_attribute(".", "#[allow(clippy::len_without_is_empty)]")
        .build_server(false)
        .build_client(true)
        .compile_protos(&["cln/node.proto"], &[proto_dir])?;

    tonic_prost_build::configure()
        .type_attribute(".", "#[allow(clippy::len_without_is_empty)]")
        .compile_protos(&["cln/services.proto", "cln/events.proto"], &[proto_dir])?;

    println!("cargo:rerun-if-changed=proto/api/v1/cln/node.proto");
    println!("cargo:rerun-if-changed=proto/api/v1/cln/services.proto");
    println!("cargo:rerun-if-changed=proto/api/v1/cln/events.proto");
    println!("cargo:rerun-if-changed=proto/api/v1/primitives.proto");
    Ok(())
}
