use std::env;

#[allow(unused_imports)]
use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    if env::var_os("SP1_SKIP_PROGRAM_BUILD").is_some() {
        println!("cargo:warning=skipping SP1 program build because SP1_SKIP_PROGRAM_BUILD is set");
        return;
    }

    build_program_with_args(
        "../program",
        BuildArgs {
            // docker: true,
            // tag: "v5.1.0".to_string(),
            output_directory: Some("../elf".to_string()),
            ..Default::default()
        },
    );
}
