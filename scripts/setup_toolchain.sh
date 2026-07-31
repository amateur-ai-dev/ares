#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="$HOME/.ares/datasets"
model_dir="$HOME/.ares/models"
hayabusa_dir="$repo_dir/tools/hayabusa"
hayabusa_binary="$hayabusa_dir/hayabusa-3.10.0-mac-aarch64"
lock_file="$repo_dir/datasets.lock"

lock_sha() {
  local name="$1"
  awk -v name="$name" '$1 == name { print $2; exit }' "$lock_file"
}

verify_file() {
  local file="$1" checksum_name="$2" expected_sha
  expected_sha="$(lock_sha "$checksum_name")"
  [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'Missing or invalid checksum for %s in %s\n' "$checksum_name" "$lock_file" >&2
    exit 1
  }
  [[ -f "$file" ]] && printf '%s  %s\n' "$expected_sha" "$file" | shasum -a 256 -c - >/dev/null
}

if ! command -v ollama >/dev/null 2>&1; then
  printf 'Ollama is required. Install it from https://ollama.com/download, then rerun this script.\n' >&2
  exit 1
fi
if ! command -v uv >/dev/null 2>&1; then
  printf 'uv is required. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh\nThen rerun this script.\n' >&2
  exit 1
fi

mkdir -p "$data_dir/attack" "$data_dir/evtx" "$model_dir"

if [[ ! -f "$hayabusa_binary" || ! -x "$hayabusa_binary" ]]; then
  stage_dir="$(mktemp -d)"
  trap 'rm -rf "$stage_dir"' EXIT
  curl --fail --location --output "$stage_dir/hayabusa.zip" "https://github.com/Yamato-Security/hayabusa/releases/download/v3.10.0/hayabusa-3.10.0-mac-aarch64.zip"
  mkdir -p "$hayabusa_dir"
  unzip -q "$stage_dir/hayabusa.zip" -d "$hayabusa_dir"
fi

foundation_gguf="$model_dir/foundation-sec-8b-q4km.gguf"
if ! verify_file "$foundation_gguf" 'models/foundation-sec-8b-q4km.gguf'; then
  curl --fail --location --continue-at - --output "$foundation_gguf" "https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/resolve/main/foundation-sec-8b-reasoning-q4_k_m.gguf"
  verify_file "$foundation_gguf" 'models/foundation-sec-8b-q4km.gguf' || {
    printf 'Foundation-Sec-8B GGUF checksum verification failed.\n' >&2
    exit 1
  }
fi

if ! ollama list | awk 'NR > 1 {print $1}' | grep -Fxq nomic-embed-text; then
  ollama pull nomic-embed-text
fi

if ! ollama list | awk 'NR > 1 {print $1}' | grep -Fxq foundation-sec-8b; then
  modelfile="$model_dir/Modelfile"
  printf 'FROM %s\n' "$foundation_gguf" > "$modelfile"
  ollama create foundation-sec-8b -f "$modelfile"
fi

if ! grep -Fq 'mitreattack-python' "$repo_dir/pyproject.toml"; then
  (cd "$repo_dir" && uv add mitreattack-python)
fi

# ATT&CK STIX is reference data, not a frozen evaluation control, so this mutable upstream URL is intentional.
if [[ ! -s "$data_dir/attack/enterprise-attack.json" ]]; then
  curl --fail --location --output "$data_dir/attack/enterprise-attack.json" "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
fi
sample_evtx="$data_dir/evtx/sample.evtx"
if ! verify_file "$sample_evtx" 'evtx/sample.evtx'; then
  curl --fail --location --output "$data_dir/evtx/sample.evtx" "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/CA_sysmon_hashdump_cmd_meterpreter.evtx"
  verify_file "$sample_evtx" 'evtx/sample.evtx' || {
    printf 'EVTX smoke-control checksum verification failed.\n' >&2
    exit 1
  }
fi

"$hayabusa_binary" csv-timeline -f "$sample_evtx" -o "$data_dir/evtx/timeline.csv" -w -q
