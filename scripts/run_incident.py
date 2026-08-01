#!/usr/bin/env python3
"""Run and score one Phase 1 ARES incident arm."""

import argparse
import sqlite3
import sys
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
    args = parser.parse_args()

    args.db.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(args.db)
    try:
        initialize(connection)
        counts = run_incident(
            connection,
            incident_id=args.incident,
            log_path=LOGS[args.incident],
            arm=args.arm,
            limit_chunks=args.limit_chunks,
        )
        metrics = score_run(connection, args.key, args.incident)
    finally:
        connection.close()

    print(f"Incident: {args.incident} ({args.arm} arm)")
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


if __name__ == "__main__":
    main()
