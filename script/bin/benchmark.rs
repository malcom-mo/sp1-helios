use clap::Parser;
use sp1_helios_script::benchmark::{BenchmarkArgs, parse_mode, run};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(about = "Run the synthetic SP1 Helios update benchmark.")]
struct Args {
    #[arg(default_value = "minimal")]
    spec: String,

    #[arg(default_value = "strict")]
    mode: String,

    #[arg(default_value_t = 8)]
    update_count: usize,

    #[arg(default_value_t = 0)]
    initial_slot: u64,

    #[arg(default_value_t = 22)]
    signers_per_update: usize,

    #[arg(default_value_t = 5)]
    runs: usize,

    #[arg(default_value = "target/sp1-synthetic-update-results.csv")]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    run(&BenchmarkArgs {
        spec_name: &args.spec,
        mode: parse_mode(&args.mode),
        update_count: args.update_count,
        initial_slot: args.initial_slot,
        signers_per_update: args.signers_per_update,
        runs: args.runs,
        output: &args.output,
    })
}
