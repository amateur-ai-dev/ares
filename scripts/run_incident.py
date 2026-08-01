#!/usr/bin/env python3
"""Run and score one Phase 1 ARES incident arm."""

import argparse
import sqlite3
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.pipeline import run_incident
from ares.scoring import score_run
from ares.store import initialize


LOGS = {
    "day1": Path("/Users/nithingowda/.ares/datasets/apt29/day1/apt29_evals_day1_manual_2020-05-01225525.json"),
    "day2": Path("/Users/nithingowda/.ares/datasets/apt29/day2/apt29_evals_day2_manual_2020-05-02035409.json"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incident", choices=LOGS, required=True)
    parser.add_argument("--arm", choices=("local", "frontier"), required=True)
    parser.add_argument("--db", type=Path, default=Path("data/ares.db"))
    parser.add_argument("--limit-chunks", type=int)
    parser.add_argument("--key", type=Path, required=True)
    # Which local model proposes. MASTER_PLAN section 5 names Foundation-Sec-8B;
    # revision-8 deviation notes why the default differs. Kept a flag so a
    # different local model is a re-run, not an edit.
    parser.add_argument("--model", help="override the local proposing model")
    args = parser.parse_args()

    args.db.parent.mkdir(parents=True, exist_ok=True)
    run_incident_id = f"{args.incident}:{args.arm}:{uuid.uuid4().hex}"
    connection = sqlite3.connect(args.db)
    try:
        initialize(connection)
        counts = run_incident(
            connection,
            incident_id=run_incident_id,
            log_path=LOGS[args.incident],
            arm=args.arm,
            limit_chunks=args.limit_chunks,
            model=args.model,
        )
        metrics = score_run(connection, args.key, run_incident_id)
    finally:
        connection.close()

    print(f"Incident: {args.incident} ({args.arm} arm, run {run_incident_id.rsplit(':', 1)[1]})")
    print(
        "Run counts: "
        f"proposals={counts.proposals_made}, badged={counts.badged}, "
        f"refuted={counts.refuted}, aporias={counts.aporias}, "
        f"discarded-as-malformed={counts.discarded_as_malformed}"
    )
    denominator = metrics["observable_true_edge_count"]
    print(
        f"Proposal recall: {metrics['proposal_recall']:.1%} "
        f"({metrics['proposed_true_edge_count']}/{denominator})"
    )
    print(
        f"Verification precision: {metrics['verification_precision']:.1%} "
        f"({metrics['correct_badged_edge_count']}/{metrics['badged_edge_count']})"
    )
    print(
        f"Verified-edge recall: {metrics['verified_edge_recall']:.1%} "
        f"({metrics['correct_badged_edge_count']}/{denominator})"
    )
    print(f"Key edges out of scope (SAME_SESSION/WROTE_PATH_BEFORE_EXECUTION): {metrics['out_of_scope_for_build_count']}")
    print(
        f"Badges the key cannot speak to: {metrics['out_of_universe_badge_count']} "
        f"(both events absent from the key — real relations, outside the attack narrative)"
    )
    print(
        f"  wrong badges caught in-universe: {metrics['in_universe_wrong_badge_count']}, "
        f"on hand-listed confounder pairs: {metrics['confounder_badge_count']}"
    )
    # Do not let a clean precision figure be read as a hard-won result.
    print(
        "\nHow to read verification precision: SPAWNED and PROCESS_OPENED_CONNECTION are\n"
        "deterministic joins, so on well-formed logs they are correct by construction and\n"
        "this figure is expected to sit at 100%. It is a floor, not an achievement — any\n"
        "dip means a real defect. The genuine test of precision is the confounded-negative\n"
        "fixture suite, which found 8 false-VERIFIED paths a clean incident run never hits."
    )


if __name__ == "__main__":
    main()
