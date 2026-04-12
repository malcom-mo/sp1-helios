#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-/tmp/sp1-helios-smoke}"
BIN_PATH="$ROOT_DIR/target/release/benchmark"

export PATH="$HOME/.sp1/bin:$PATH"
export SP1_PROVER="${SP1_PROVER:-mock}"
export SP1_SKIP_PROGRAM_BUILD=1

if [[ ! -f "$ROOT_DIR/elf/synthetic_update" ]]; then
  echo "missing elf/synthetic_update; run 'cd program && cargo prove build --output-directory ../elf' first" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

cargo build --release -p sp1-helios-script --bin benchmark --manifest-path "$ROOT_DIR/Cargo.toml"

"$BIN_PATH" minimal strict 1 0 22 1 "$OUT_DIR/minimal-strict.csv"
"$BIN_PATH" minimal simplified 1 0 999 1 "$OUT_DIR/minimal-simplified.csv"
"$BIN_PATH" minimal strict 4 61 22 1 "$OUT_DIR/minimal-strict-rotate.csv"

echo "wrote smoke benchmark outputs to $OUT_DIR"
