#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use helios_consensus_core::{
    benchmark::{BenchmarkFixture, BenchmarkMode, BenchmarkStep, run_update_benchmark},
    consensus_spec::ConsensusSpec,
};
use sp1_helios_primitives::types::{
    MainnetSyntheticBenchmarkFixture, MinimalSyntheticBenchmarkFixture,
    SimplifiedMainnetSyntheticBenchmarkFixture, SimplifiedMinimalSyntheticBenchmarkFixture,
    SyntheticBenchmarkMode, SyntheticBenchmarkSpec, SyntheticProofInputs, SyntheticProofOutputs,
};
use tree_hash::TreeHash;

pub fn main() {
    let encoded_inputs = sp1_zkvm::io::read_vec();
    let inputs: SyntheticProofInputs = serde_cbor::from_slice(&encoded_inputs).unwrap();

    let proof_outputs = match inputs {
        SyntheticProofInputs::MinimalStrict(fixture) => {
            run_minimal_fixture(SyntheticBenchmarkSpec::Minimal, fixture)
        }
        SyntheticProofInputs::MainnetStrict(fixture) => {
            run_mainnet_fixture(SyntheticBenchmarkSpec::Mainnet, fixture)
        }
        SyntheticProofInputs::MinimalSimplified(fixture) => {
            run_simplified_minimal_fixture(SyntheticBenchmarkSpec::Minimal, fixture)
        }
        SyntheticProofInputs::MainnetSimplified(fixture) => {
            run_simplified_mainnet_fixture(SyntheticBenchmarkSpec::Mainnet, fixture)
        }
    };

    let encoded_outputs = serde_cbor::to_vec(&proof_outputs).unwrap();
    sp1_zkvm::io::commit_slice(&encoded_outputs);
}

fn run_minimal_fixture(
    spec: SyntheticBenchmarkSpec,
    fixture: MinimalSyntheticBenchmarkFixture,
) -> SyntheticProofOutputs {
    run_fixture_inner::<helios_consensus_core::consensus_spec::MinimalConsensusSpec>(
        spec,
        fixture.mode,
        fixture.genesis_root,
        fixture.forks,
        fixture.store,
        fixture
            .steps
            .into_iter()
            .map(|step| BenchmarkStep {
                current_slot: step.current_slot,
                update: step.update,
            })
            .collect(),
    )
}

fn run_mainnet_fixture(
    spec: SyntheticBenchmarkSpec,
    fixture: MainnetSyntheticBenchmarkFixture,
) -> SyntheticProofOutputs {
    run_fixture_inner::<helios_consensus_core::consensus_spec::MainnetConsensusSpec>(
        spec,
        fixture.mode,
        fixture.genesis_root,
        fixture.forks,
        fixture.store,
        fixture
            .steps
            .into_iter()
            .map(|step| BenchmarkStep {
                current_slot: step.current_slot,
                update: step.update,
            })
            .collect(),
    )
}

fn run_simplified_minimal_fixture(
    spec: SyntheticBenchmarkSpec,
    fixture: SimplifiedMinimalSyntheticBenchmarkFixture,
) -> SyntheticProofOutputs {
    run_fixture_inner::<helios_consensus_core::benchmark::SimplifiedMinimalConsensusSpec>(
        spec,
        fixture.mode,
        fixture.genesis_root,
        fixture.forks,
        fixture.store,
        fixture
            .steps
            .into_iter()
            .map(|step| BenchmarkStep {
                current_slot: step.current_slot,
                update: step.update,
            })
            .collect(),
    )
}

fn run_simplified_mainnet_fixture(
    spec: SyntheticBenchmarkSpec,
    fixture: SimplifiedMainnetSyntheticBenchmarkFixture,
) -> SyntheticProofOutputs {
    run_fixture_inner::<helios_consensus_core::benchmark::SimplifiedMainnetConsensusSpec>(
        spec,
        fixture.mode,
        fixture.genesis_root,
        fixture.forks,
        fixture.store,
        fixture
            .steps
            .into_iter()
            .map(|step| BenchmarkStep {
                current_slot: step.current_slot,
                update: step.update,
            })
            .collect(),
    )
}

fn run_fixture_inner<S: ConsensusSpec>(
    spec: SyntheticBenchmarkSpec,
    mode: SyntheticBenchmarkMode,
    genesis_root: B256,
    forks: helios_consensus_core::types::Forks,
    store: helios_consensus_core::types::LightClientStore<S>,
    steps: Vec<BenchmarkStep<S>>,
) -> SyntheticProofOutputs {
    let prev_sync_committee_hash = store.current_sync_committee.tree_hash_root();
    let prev_header: B256 = store.finalized_header.beacon().tree_hash_root();
    let prev_head = store.finalized_header.beacon().slot;

    let benchmark_fixture = BenchmarkFixture {
        mode: convert_mode(mode),
        genesis_root,
        forks,
        store,
        steps,
    };

    let run = run_update_benchmark(&benchmark_fixture).expect("synthetic benchmark run failed");
    let store = run.store;

    SyntheticProofOutputs {
        mode,
        spec,
        updates_processed: run.metrics.updates_processed,
        prev_header,
        prev_head,
        prev_sync_committee_hash,
        new_header: store.finalized_header.beacon().tree_hash_root(),
        new_head: store.finalized_header.beacon().slot,
        sync_committee_hash: store.current_sync_committee.tree_hash_root(),
        next_sync_committee_hash: store
            .next_sync_committee
            .map(|committee| committee.tree_hash_root())
            .unwrap_or(B256::ZERO),
    }
}

fn convert_mode(mode: SyntheticBenchmarkMode) -> BenchmarkMode {
    match mode {
        SyntheticBenchmarkMode::Strict => BenchmarkMode::Strict,
        SyntheticBenchmarkMode::Simplified => BenchmarkMode::Simplified,
    }
}
