#!/usr/bin/env bash
set -euo pipefail

data_dir="${1:-$HOME/.ares/datasets}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="$repo_dir/datasets.lock"

lock_sha() {
  local name="$1"
  awk -v name="$name" '$1 == name { print $2; exit }' "$lock_file"
}

commit="$(awk -F= '/^OTRF_SECURITY_DATASETS_COMMIT=/{ print $2; exit }' "$lock_file")"
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Missing or invalid OTRF_SECURITY_DATASETS_COMMIT in %s\n' "$lock_file" >&2
  exit 1
fi
base_url="https://github.com/OTRF/Security-Datasets/raw/$commit/datasets/compound/apt29"

mkdir -p "$data_dir"
stage_dir="$(mktemp -d "$data_dir/.apt29-stage.XXXXXX")"
trap 'rm -rf "$stage_dir"' EXIT

fetch_archive() {
  local day="$1" archive="$2" legacy_archive="$3"
  local expected_sha destination legacy_destination
  expected_sha="$(lock_sha "$archive")"
  if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'Missing or invalid checksum for %s in %s\n' "$archive" "$lock_file" >&2
    exit 1
  fi
  destination="$data_dir/$archive"
  legacy_destination="$data_dir/$legacy_archive"

  if [[ -f "$destination" ]] && printf '%s  %s\n' "$expected_sha" "$destination" | shasum -a 256 -c - >/dev/null; then
    printf 'Using verified %s\n' "$destination"
    ARCHIVE_PATH="$destination"
  elif [[ -f "$legacy_destination" ]] && printf '%s  %s\n' "$expected_sha" "$legacy_destination" | shasum -a 256 -c - >/dev/null; then
    printf 'Using verified legacy archive %s\n' "$legacy_destination"
    ARCHIVE_PATH="$legacy_destination"
  else
    curl --fail --location --output "$stage_dir/$archive" "$base_url/$day/$archive"
    printf '%s  %s\n' "$expected_sha" "$stage_dir/$archive" | shasum -a 256 -c -
    ARCHIVE_PATH="$stage_dir/$archive"
  fi
}

fetch_archive day1 apt29_evals_day1_manual.zip apt29d1.zip
day1_archive="$ARCHIVE_PATH"
fetch_archive day2 apt29_evals_day2_manual.zip apt29d2.zip
day2_archive="$ARCHIVE_PATH"

if [[ -f "$data_dir/apt29/day1/apt29_evals_day1_manual_2020-05-01225525.json" && -f "$data_dir/apt29/day2/apt29_evals_day2_manual_2020-05-02035409.json" ]]; then
  printf 'Verified dataset already extracted at %s/apt29\n' "$data_dir"
  exit 0
fi

mkdir -p "$stage_dir/apt29/day1" "$stage_dir/apt29/day2"
unzip -q "$day1_archive" -d "$stage_dir/apt29/day1"
unzip -q "$day2_archive" -d "$stage_dir/apt29/day2"

if [[ -e "$data_dir/apt29" ]]; then
  backup_dir="$data_dir/.apt29-previous"
  rm -rf "$backup_dir"
  mv "$data_dir/apt29" "$backup_dir"
  trap 'if [[ -e "$backup_dir" && ! -e "$data_dir/apt29" ]]; then mv "$backup_dir" "$data_dir/apt29"; fi; rm -rf "$stage_dir"' EXIT
fi
mv "$stage_dir/apt29" "$data_dir/apt29"
if [[ -f "$stage_dir/apt29_evals_day1_manual.zip" ]]; then
  mv "$stage_dir/apt29_evals_day1_manual.zip" "$data_dir/apt29_evals_day1_manual.zip"
fi
if [[ -f "$stage_dir/apt29_evals_day2_manual.zip" ]]; then
  mv "$stage_dir/apt29_evals_day2_manual.zip" "$data_dir/apt29_evals_day2_manual.zip"
fi
if [[ -n "${backup_dir:-}" ]]; then
  rm -rf "$backup_dir"
fi
printf 'Fetched and verified frozen OTRF APT29 files into %s/apt29\n' "$data_dir"
