use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_file = "cipher312.h";

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_include_guard("CIPHER312_H")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(output_file);

    println!("cargo:rerun-if-changed=src/");
}
