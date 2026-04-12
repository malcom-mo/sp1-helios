use std::{
    fs::{OpenOptions, create_dir_all, metadata, read},
    io::Write,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use alloy_primitives::B256;
use helios_consensus_core::{
    benchmark::{
        BenchmarkFixture, BenchmarkMode, BenchmarkRun, SimplifiedMainnetConsensusSpec,
        SimplifiedMinimalConsensusSpec, SyntheticFixtureConfig, benchmark_committee_size,
        benchmark_signers_per_update, default_benchmark_forks, generate_fixture,
        run_update_benchmark,
    },
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec, MinimalConsensusSpec},
};
use sp1_helios_primitives::types::{
    MainnetSyntheticBenchmarkFixture, MainnetSyntheticBenchmarkStep,
    MinimalSyntheticBenchmarkFixture, MinimalSyntheticBenchmarkStep,
    SimplifiedMainnetSyntheticBenchmarkFixture, SimplifiedMainnetSyntheticBenchmarkStep,
    SimplifiedMinimalSyntheticBenchmarkFixture, SimplifiedMinimalSyntheticBenchmarkStep,
    SyntheticBenchmarkMode, SyntheticBenchmarkSpec, SyntheticProofInputs, SyntheticProofOutputs,
};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey,
    SP1ProofWithPublicValues, SP1Stdin,
};
use tree_hash::TreeHash;

#[derive(Debug, Clone)]
pub struct BenchmarkArgs<'a> {
    pub spec_name: &'a str,
    pub mode: BenchmarkMode,
    pub committee_transitions: usize,
    pub initial_slot: u64,
    pub signers_per_update: usize,
    pub runs: usize,
    pub output: &'a Path,
}

pub async fn run(args: &BenchmarkArgs<'_>) -> Result<()> {
    match (args.spec_name, args.mode) {
        ("minimal", BenchmarkMode::Strict) => {
            run_for_spec::<MinimalConsensusSpec>(args).await
        }
        ("minimal", BenchmarkMode::Simplified) => {
            run_for_spec::<SimplifiedMinimalConsensusSpec>(args).await
        }
        ("mainnet", BenchmarkMode::Strict) => {
            run_for_spec::<MainnetConsensusSpec>(args).await
        }
        ("mainnet", BenchmarkMode::Simplified) => {
            run_for_spec::<SimplifiedMainnetConsensusSpec>(args).await
        }
        _ => anyhow::bail!("spec must be one of: minimal, mainnet"),
    }
}

async fn run_for_spec<S: BenchmarkSpecBinding>(args: &BenchmarkArgs<'_>) -> Result<()> {
    let effective_signers =
        benchmark_signers_per_update(args.mode, args.spec_name, args.signers_per_update);

    let fixture_started = Instant::now();
    let fixture = generate_fixture::<S>(&SyntheticFixtureConfig {
        mode: args.mode,
        initial_slot: args.initial_slot,
        committee_transitions: args.committee_transitions,
        signers_per_update: effective_signers,
        genesis_root: B256::repeat_byte(7),
        forks: default_benchmark_forks(),
    })
    .map_err(|err| anyhow::anyhow!("failed to generate synthetic fixture: {err}"))?;
    let fixture_elapsed = fixture_started.elapsed();

    let native_run = run_update_benchmark(&fixture)
        .map_err(|err| anyhow::anyhow!("native benchmark run failed: {err}"))?;
    let expected_outputs = expected_outputs(S::nominal_spec(), args.mode, &fixture, &native_run);

    let encoded_inputs = serde_cbor::to_vec(&S::wrap_input(fixture.clone()))
        .context("failed to encode synthetic proof inputs")?;

    let client = ProverClient::from_env().await;
    let elf = load_synthetic_update_elf()?;

    let setup_started = Instant::now();
    let pk = client
        .setup(Elf::from(elf))
        .await
        .context("failed to set up synthetic benchmark program")?;
    let setup_elapsed = setup_started.elapsed();
    let proof_mode = selected_proof_mode();

    let mut prove_times = Vec::with_capacity(args.runs);
    let mut last_proof = None;

    for _ in 0..args.runs {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&encoded_inputs);

        let prove_started = Instant::now();
        let proof = prove_synthetic_update(&client, &pk, stdin, proof_mode)
            .await
            .context("synthetic update proof failed")?;
        prove_times.push(prove_started.elapsed().as_micros());
        last_proof = Some(proof);
    }

    let proof = last_proof.expect("runs must be greater than zero");
    let public_values = decode_public_values(&proof)?;
    ensure!(
        public_values == expected_outputs,
        "proof outputs diverged from native benchmark run"
    );

    let mut verify_times = Vec::with_capacity(args.runs);
    if proof_mode.requires_verification() {
        for _ in 0..args.runs {
            let verify_started = Instant::now();
            client
                .verify(&proof, pk.verifying_key(), None)
                .context("synthetic update proof verification failed")?;
            verify_times.push(verify_started.elapsed().as_micros());
        }
    } else {
        verify_times.resize(args.runs, 0);
    }

    append_csv(
        args.output,
        args.spec_name,
        args.mode,
        benchmark_committee_size(args.mode, args.spec_name),
        args.initial_slot,
        args.committee_transitions,
        effective_signers,
        args.runs,
        fixture_elapsed.as_micros(),
        setup_elapsed.as_micros(),
        stats(&prove_times),
        stats(&verify_times),
        &public_values,
        pk.verifying_key().bytes32(),
    )?;

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyntheticProofMode {
    Core,
    Plonk,
}

impl SyntheticProofMode {
    fn requires_verification(self) -> bool {
        matches!(self, Self::Plonk)
    }
}

fn selected_proof_mode() -> SyntheticProofMode {
    match std::env::var("SP1_PROVER").ok().as_deref() {
        Some("mock" | "light") => SyntheticProofMode::Core,
        _ => SyntheticProofMode::Plonk,
    }
}

async fn prove_synthetic_update<P: Prover>(
    client: &P,
    pk: &P::ProvingKey,
    stdin: SP1Stdin,
    proof_mode: SyntheticProofMode,
) -> Result<SP1ProofWithPublicValues, P::Error> {
    match proof_mode {
        SyntheticProofMode::Core => client.prove(pk, stdin).core().await,
        SyntheticProofMode::Plonk => client.prove(pk, stdin).plonk().await,
    }
}

fn expected_outputs<S: ConsensusSpec>(
    spec: SyntheticBenchmarkSpec,
    mode: BenchmarkMode,
    fixture: &BenchmarkFixture<S>,
    run: &BenchmarkRun<S>,
) -> SyntheticProofOutputs {
    SyntheticProofOutputs {
        mode: convert_mode(mode),
        spec,
        updates_processed: run.metrics.updates_processed,
        prev_header: fixture.store.finalized_header.beacon().tree_hash_root(),
        prev_head: fixture.store.finalized_header.beacon().slot,
        prev_sync_committee_hash: fixture.store.current_sync_committee.tree_hash_root(),
        new_header: run.store.finalized_header.beacon().tree_hash_root(),
        new_head: run.store.finalized_header.beacon().slot,
        sync_committee_hash: run.store.current_sync_committee.tree_hash_root(),
        next_sync_committee_hash: run
            .store
            .next_sync_committee
            .as_ref()
            .map(|committee| committee.tree_hash_root())
            .unwrap_or(B256::ZERO),
    }
}

fn decode_public_values(proof: &SP1ProofWithPublicValues) -> Result<SyntheticProofOutputs> {
    serde_cbor::from_slice(proof.public_values.as_slice())
        .context("failed to decode synthetic proof public values")
}

fn append_csv(
    path: &Path,
    spec_name: &str,
    mode: BenchmarkMode,
    committee_size: usize,
    initial_slot: u64,
    committee_transitions: usize,
    signers_per_update: usize,
    runs: usize,
    fixture_us: u128,
    setup_us: u128,
    prove_stats: (u128, u128, f64),
    verify_stats: (u128, u128, f64),
    public_values: &SyntheticProofOutputs,
    vkey: String,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let has_rows = metadata(path).map(|m| m.len() > 0).unwrap_or(false);
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    if !has_rows {
        writeln!(
            file,
            "timestamp,spec,mode,committee_size,initial_slot,effective_signers_per_update,committee_transitions,runs,fixture_us,setup_us,prove_min_us,prove_max_us,prove_avg_us,verify_min_us,verify_max_us,verify_avg_us,prev_head,new_head,updates_processed,vkey"
        )?;
    }

    writeln!(
        file,
        "{},{},{},{},{},{},{},{},{},{},{},{},{:.2},{},{},{:.2},{},{},{},{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        spec_name,
        mode_label(mode),
        committee_size,
        initial_slot,
        signers_per_update,
        committee_transitions,
        runs,
        fixture_us,
        setup_us,
        prove_stats.0,
        prove_stats.1,
        prove_stats.2,
        verify_stats.0,
        verify_stats.1,
        verify_stats.2,
        public_values.prev_head,
        public_values.new_head,
        public_values.updates_processed,
        vkey,
    )?;

    Ok(())
}

fn load_synthetic_update_elf() -> Result<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("elf")
        .join("synthetic_update");
    read(&path).with_context(|| format!("failed to read synthetic benchmark ELF at {}", path.display()))
}

fn stats(values: &[u128]) -> (u128, u128, f64) {
    let min = *values.iter().min().unwrap_or(&0);
    let max = *values.iter().max().unwrap_or(&0);
    let avg = if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<u128>() as f64 / values.len() as f64
    };
    (min, max, avg)
}

pub fn parse_mode(mode: &str) -> BenchmarkMode {
    match mode {
        "strict" => BenchmarkMode::Strict,
        "simplified" => BenchmarkMode::Simplified,
        _ => panic!("mode must be one of: strict, simplified"),
    }
}

fn mode_label(mode: BenchmarkMode) -> &'static str {
    match mode {
        BenchmarkMode::Strict => "strict",
        BenchmarkMode::Simplified => "simplified",
    }
}

fn convert_mode(mode: BenchmarkMode) -> SyntheticBenchmarkMode {
    match mode {
        BenchmarkMode::Strict => SyntheticBenchmarkMode::Strict,
        BenchmarkMode::Simplified => SyntheticBenchmarkMode::Simplified,
    }
}

trait BenchmarkSpecBinding: ConsensusSpec {
    fn nominal_spec() -> SyntheticBenchmarkSpec;
    fn wrap_input(fixture: BenchmarkFixture<Self>) -> SyntheticProofInputs;
}

impl BenchmarkSpecBinding for MinimalConsensusSpec {
    fn nominal_spec() -> SyntheticBenchmarkSpec {
        SyntheticBenchmarkSpec::Minimal
    }

    fn wrap_input(fixture: BenchmarkFixture<Self>) -> SyntheticProofInputs {
        SyntheticProofInputs::MinimalStrict(MinimalSyntheticBenchmarkFixture {
            mode: convert_mode(fixture.mode),
            genesis_root: fixture.genesis_root,
            forks: fixture.forks,
            store: fixture.store,
            steps: fixture
                .steps
                .into_iter()
                .map(|step| MinimalSyntheticBenchmarkStep {
                    current_slot: step.current_slot,
                    update: step.update,
                })
                .collect(),
        })
    }
}

impl BenchmarkSpecBinding for MainnetConsensusSpec {
    fn nominal_spec() -> SyntheticBenchmarkSpec {
        SyntheticBenchmarkSpec::Mainnet
    }

    fn wrap_input(fixture: BenchmarkFixture<Self>) -> SyntheticProofInputs {
        SyntheticProofInputs::MainnetStrict(MainnetSyntheticBenchmarkFixture {
            mode: convert_mode(fixture.mode),
            genesis_root: fixture.genesis_root,
            forks: fixture.forks,
            store: fixture.store,
            steps: fixture
                .steps
                .into_iter()
                .map(|step| MainnetSyntheticBenchmarkStep {
                    current_slot: step.current_slot,
                    update: step.update,
                })
                .collect(),
        })
    }
}

impl BenchmarkSpecBinding for SimplifiedMinimalConsensusSpec {
    fn nominal_spec() -> SyntheticBenchmarkSpec {
        SyntheticBenchmarkSpec::Minimal
    }

    fn wrap_input(fixture: BenchmarkFixture<Self>) -> SyntheticProofInputs {
        SyntheticProofInputs::MinimalSimplified(SimplifiedMinimalSyntheticBenchmarkFixture {
            mode: convert_mode(fixture.mode),
            genesis_root: fixture.genesis_root,
            forks: fixture.forks,
            store: fixture.store,
            steps: fixture
                .steps
                .into_iter()
                .map(|step| SimplifiedMinimalSyntheticBenchmarkStep {
                    current_slot: step.current_slot,
                    update: step.update,
                })
                .collect(),
        })
    }
}

impl BenchmarkSpecBinding for SimplifiedMainnetConsensusSpec {
    fn nominal_spec() -> SyntheticBenchmarkSpec {
        SyntheticBenchmarkSpec::Mainnet
    }

    fn wrap_input(fixture: BenchmarkFixture<Self>) -> SyntheticProofInputs {
        SyntheticProofInputs::MainnetSimplified(SimplifiedMainnetSyntheticBenchmarkFixture {
            mode: convert_mode(fixture.mode),
            genesis_root: fixture.genesis_root,
            forks: fixture.forks,
            store: fixture.store,
            steps: fixture
                .steps
                .into_iter()
                .map(|step| SimplifiedMainnetSyntheticBenchmarkStep {
                    current_slot: step.current_slot,
                    update: step.update,
                })
                .collect(),
        })
    }
}
