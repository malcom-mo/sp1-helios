# SP1 Helios

## Overview

SP1 Helios verifies the consensus of a source chain in the execution environment of a destination chain. For example, you can run an SP1 Helios light client on Polygon that verifies Ethereum Mainnet's consensus.

[Docs](https://succinctlabs.github.io/sp1-helios/)

## Benchmarking

The `benchmark` branch contains a synthetic benchmark that measures SP1 proving and verification cost for the Ethereum light-client update path, without any live RPC or execution-layer dependency.

### Prerequisites

1. **SP1 toolchain** — install once per machine:
   ```
   curl -L https://sp1.succinct.xyz | bash && sp1up
   ```
2. **protoc** — required by `sp1-prover-types`:
   ```
   # Debian/Ubuntu
   apt install protobuf-compiler
   # macOS
   brew install protobuf
   ```
3. **Guest ELF** — build the synthetic benchmark zkVM program:
   ```
   cd program
   cargo prove build --output-directory ../elf
   ```

### Smoke test

Validates the full prove/verify path using the mock prover (fast, no real proofs):

```
./script/benchmark_smoke.sh [output-dir]
```

Runs three configurations (minimal spec — committee size 32, mock mode) and writes CSVs to `output-dir` (default `/tmp/sp1-helios-smoke`).
