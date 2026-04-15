use std::{
    fs::{OpenOptions, create_dir_all, metadata, read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
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
    Elf, ProveRequest, Prover, ProverClient, ProvingKey,
    SP1ProofWithPublicValues, SP1Stdin,
};
use tree_hash::TreeHash;
use tracing::span;
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    fmt::format::FmtSpan,
    layer::{Context as LayerContext, SubscriberExt},
    registry::LookupSpan,
    util::SubscriberInitExt,
};

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
    let prove_span_times = init_tracing_once();

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
        .setup(Elf::from(elf.clone()))
        .await
        .context("failed to set up synthetic benchmark program")?;
    let setup_elapsed = setup_started.elapsed();
    let proof_mode = selected_proof_mode();

    // Deterministic execution metrics via execute() — no proof generation, fast.
    // Placed outside the prove timing loop so it never contaminates wall-clock measurements.
    let execute_started = Instant::now();
    let mut exec_stdin = SP1Stdin::new();
    exec_stdin.write_slice(&encoded_inputs);
    let (_exec_pv, exec_report) = client
        .execute(Elf::from(elf.clone()), exec_stdin)
        .await
        .context("execute() for metrics collection failed")?;
    let execute_elapsed = execute_started.elapsed();
    let total_instructions = exec_report.total_instruction_count();
    let gas = exec_report.gas().unwrap_or(0);

    let mut prove_times = Vec::with_capacity(args.runs);
    let mut last_proof = None;

    // Clear any span timings that may have accumulated before the timed loop.
    prove_span_times.lock().unwrap().clear();

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

    let sp1_span_vec: Vec<u128> = prove_span_times.lock().unwrap().clone();
    let sp1_prove_span_avg_us = avg(&sp1_span_vec);

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

    // .bytes() is only valid for Plonk/Groth16 proofs; Core (mock) proofs have no onchain encoding.
    let proof_bytes = if proof_mode.requires_verification() {
        proof.bytes().len()
    } else {
        0
    };

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
        avg(&prove_times),
        avg(&verify_times),
        &public_values,
        proof_bytes,
        total_instructions,
        gas,
        execute_elapsed.as_micros(),
        sp1_prove_span_avg_us,
    )?;

    Ok(())
}

// ── SP1 prove-span capture ────────────────────────────────────────────────────

/// Marker stored in span extensions to record the wall-clock start time.
struct SpanStart(Instant);

/// Tracing layer that records the wall-clock duration of SP1's internal `prove`
/// span into a shared Vec. One entry is pushed per `prove()` call.
struct ProveSpanCapture {
    times: Arc<Mutex<Vec<u128>>>,
}

impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> Layer<S> for ProveSpanCapture {
    fn on_new_span(
        &self,
        _attrs: &span::Attributes<'_>,
        id: &span::Id,
        ctx: LayerContext<'_, S>,
    ) {
        if let Some(s) = ctx.span(id) {
            if s.name() == "prove" {
                s.extensions_mut().insert(SpanStart(Instant::now()));
            }
        }
    }

    fn on_close(&self, id: span::Id, ctx: LayerContext<'_, S>) {
        if let Some(s) = ctx.span(&id) {
            if s.name() == "prove" {
                if let Some(start) = s.extensions().get::<SpanStart>() {
                    self.times
                        .lock()
                        .unwrap()
                        .push(start.0.elapsed().as_micros());
                }
            }
        }
    }
}

/// Initialise the global tracing subscriber exactly once and return a handle to
/// the shared prove-span timing buffer. Thread-safe; safe to call repeatedly
/// (subsequent calls return the same Arc without re-initialising).
fn init_tracing_once() -> Arc<Mutex<Vec<u128>>> {
    static PROVE_TIMES: OnceLock<Arc<Mutex<Vec<u128>>>> = OnceLock::new();
    PROVE_TIMES
        .get_or_init(|| {
            let times: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::new()));
            let capture = ProveSpanCapture { times: Arc::clone(&times) };

            let filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"));

            let _ = Registry::default()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .compact()
                        .with_span_events(FmtSpan::CLOSE),
                )
                .with(capture)
                .try_init();

            times
        })
        .clone()
}

// ── Proof mode ────────────────────────────────────────────────────────────────

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

// ── Output helpers ────────────────────────────────────────────────────────────

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

#[allow(clippy::too_many_arguments)]
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
    prove_avg_us: f64,
    verify_avg_us: f64,
    public_values: &SyntheticProofOutputs,
    proof_bytes: usize,
    total_instructions: u64,
    gas: u64,
    execute_us: u128,
    sp1_prove_span_avg_us: f64,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let has_rows = metadata(path).map(|m| m.len() > 0).unwrap_or(false);
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(file);

    if !has_rows {
        wtr.write_record(&[
            "timestamp", "spec", "mode", "committee_size", "initial_slot",
            "effective_signers_per_update", "committee_transitions", "runs",
            "fixture_us", "setup_us", "prove_avg_us", "verify_avg_us",
            "prev_head", "new_head", "updates_processed", "proof_bytes",
            "total_instructions", "gas", "execute_us", "sp1_prove_span_avg_us",
        ])?;
    }

    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    wtr.write_record(&[
        ts.to_string(),
        spec_name.to_string(),
        mode_label(mode).to_string(),
        committee_size.to_string(),
        initial_slot.to_string(),
        signers_per_update.to_string(),
        committee_transitions.to_string(),
        runs.to_string(),
        fixture_us.to_string(),
        setup_us.to_string(),
        format!("{prove_avg_us:.2}"),
        format!("{verify_avg_us:.2}"),
        public_values.prev_head.to_string(),
        public_values.new_head.to_string(),
        public_values.updates_processed.to_string(),
        proof_bytes.to_string(),
        total_instructions.to_string(),
        gas.to_string(),
        execute_us.to_string(),
        format!("{sp1_prove_span_avg_us:.2}"),
    ])?;
    wtr.flush()?;

    Ok(())
}

fn load_synthetic_update_elf() -> Result<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("elf")
        .join("synthetic_update");
    read(&path).with_context(|| format!("failed to read synthetic benchmark ELF at {}", path.display()))
}

fn avg(values: &[u128]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<u128>() as f64 / values.len() as f64
    }
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
