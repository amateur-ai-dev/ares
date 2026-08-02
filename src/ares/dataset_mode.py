"""Dataset identity helpers shared by the run and scoring boundaries."""

from pathlib import Path


MODES = frozenset({"demo", "eval"})


def mode_from_log(log_path):
    """Infer dataset identity from the physically separate corpus location."""
    if "demo" in Path(log_path).parts:
        return "demo"
    return "eval"


def mode_from_key(key_path, key):
    """Prefer a frozen key declaration; legacy evaluation keys remain evaluation."""
    mode = key.get("dataset_mode")
    if mode is None:
        return "demo" if "demo" in Path(key_path).name else "eval"
    if mode not in MODES:
        raise ValueError(f"unknown dataset mode in key: {mode!r}")
    return mode


def require_mode(mode):
    if mode not in MODES:
        raise ValueError(f"dataset mode must be one of {sorted(MODES)}, got {mode!r}")
    return mode
