#!/usr/bin/env python3
"""Bring runs from before the `runs` table existed into the dashboard.

Fourteen databases were produced during the experiments and each holds one run's
claims and verifier executions, but none has the `runs`, `run_metrics` or
`model_selections` tables the dashboard reads. They are invisible to it.

This imports them, and the interesting part is what it refuses to invent.

**Selections are not recoverable.** `model_selections` did not exist when these
ran, so the model's picks were never written down. They were made - these runs
have published recall figures - but they are gone. Every imported run is marked
`selections_recorded = 0`, and the report then shows selection recall as "not
recorded" rather than as 0%. Importing them with a zero would have manufactured
fourteen failed runs out of missing data.

**Nothing is recomputed.** Claims and verifier executions are copied byte for
byte. Ids are remapped because they are per-database autoincrements, and the
badge firewall re-checks every copied claim on insert - a claim whose execution
did not come across correctly is rejected by the trigger, not silently badged.

Idempotent: a run already present is skipped, so this can be re-run safely.
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.store import initialize

VERIFIER_COLUMNS = (
    "incident_id", "predicate_id", "predicate_version", "input_event_ids",
    "evaluated_fields", "result", "log_provenance", "run_id", "executed_at",
)
CLAIM_COLUMNS = (
    "incident_id", "claim_type", "predicate_type", "source_event_id",
    "target_event_id", "source_hostname", "target_hostname", "claim_text", "badge",
)
GAP_COLUMNS = (
    "incident_id", "claim_text", "relation_type", "source_event_id",
    "target_event_id", "status", "verification_failure_code",
    "verification_failure_detail", "verifier_execution_json", "created_at",
)


def normalise_incident_id(incident_id, run_id):
    """`day1` alone routes to the wrong answer key; `day1:` prefixed does not.

    report._key_for selects the key by prefix, so a bare `day1` falls through to
    the demo key and the run then fails its own dataset-mode check. One smoke
    database predates the convention.
    """
    if incident_id in ("day1", "day2"):
        return f"{incident_id}:legacy:{run_id}"
    return incident_id


def import_database(source_path, target, dry_run=False):
    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "verifier_executions" not in tables or "claims" not in tables:
            return None

        run_rows = source.execute(
            "SELECT run_id, MIN(executed_at) FROM verifier_executions GROUP BY run_id"
        ).fetchall()
        if len(run_rows) != 1:
            return None
        run_id, created_at = run_rows[0]

        if target.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone():
            return {"run_id": run_id, "skipped": "already imported"}

        incident_id = source.execute(
            "SELECT incident_id FROM claims LIMIT 1").fetchone()[0]
        incident_id = normalise_incident_id(incident_id, run_id)

        if dry_run:
            claims = source.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
            return {"run_id": run_id, "incident_id": incident_id,
                    "claims": claims, "created_at": created_at, "dry_run": True}

        # verifier_executions first: the badge firewall checks that a claim's
        # execution already exists, matches its incident and predicate, and
        # returned true. Copying claims first would be rejected by the trigger.
        execution_map = {}
        for row in source.execute(
            f"SELECT id, {', '.join(VERIFIER_COLUMNS)} FROM verifier_executions"
        ):
            old_id, values = row[0], list(row[1:])
            values[0] = incident_id
            cursor = target.execute(
                f"INSERT INTO verifier_executions ({', '.join(VERIFIER_COLUMNS)}) "
                f"VALUES ({', '.join('?' for _ in VERIFIER_COLUMNS)})",
                values,
            )
            execution_map[old_id] = cursor.lastrowid

        claim_map = {}
        for row in source.execute(
            f"SELECT id, verifier_execution_id, {', '.join(CLAIM_COLUMNS)} FROM claims"
        ):
            old_id, old_execution, values = row[0], row[1], list(row[2:])
            values[0] = incident_id
            cursor = target.execute(
                f"INSERT INTO claims (verifier_execution_id, {', '.join(CLAIM_COLUMNS)}) "
                f"VALUES ({', '.join('?' for _ in range(len(CLAIM_COLUMNS) + 1))})",
                [execution_map.get(old_execution)] + values,
            )
            claim_map[old_id] = cursor.lastrowid

        gaps = 0
        if "causal_gaps" in tables:
            for row in source.execute(
                f"SELECT claim_id, {', '.join(GAP_COLUMNS)} FROM causal_gaps"
            ):
                old_claim, values = row[0], list(row[1:])
                values[0] = incident_id
                # The execution id is also embedded in this JSON blob, and the
                # report joins on it. Remap it there too or the aporias vanish.
                payload = json.loads(values[8])
                if "verifier_execution_id" in payload:
                    payload["verifier_execution_id"] = execution_map.get(
                        payload["verifier_execution_id"], payload["verifier_execution_id"])
                    values[8] = json.dumps(payload)
                target.execute(
                    f"INSERT INTO causal_gaps (claim_id, {', '.join(GAP_COLUMNS)}) "
                    f"VALUES ({', '.join('?' for _ in range(len(GAP_COLUMNS) + 1))})",
                    [claim_map.get(old_claim)] + values,
                )
                gaps += 1

        badged = target.execute(
            "SELECT COUNT(*) FROM claims c JOIN verifier_executions v "
            "ON c.verifier_execution_id = v.id "
            "WHERE v.run_id = ? AND c.badge NOT IN ('unverifiable','refuted')",
            (run_id,),
        ).fetchone()[0]
        enumerated = len(claim_map)

        target.execute(
            "INSERT INTO runs (run_id, incident_id, dataset_mode, created_at) "
            "VALUES (?, ?, 'eval', ?)",
            (run_id, incident_id, created_at),
        )
        target.execute(
            "INSERT INTO run_metrics (run_id, events_parsed, events_in_scope,"
            " edges_enumerated, edges_verified, verified_edges_shown, selections_made,"
            " refuted, aporias, discarded_as_malformed, selections_recorded)"
            " VALUES (?, 0, 0, ?, ?, 0, 0, ?, ?, 0, 0)",
            (run_id, enumerated, badged, enumerated - badged - gaps, gaps),
        )
        target.commit()
        return {"run_id": run_id, "incident_id": incident_id,
                "claims": enumerated, "badged": badged, "aporias": gaps,
                "created_at": created_at}
    finally:
        source.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=Path("data/eval/ares.db"))
    parser.add_argument("--sources", type=Path, default=Path("data"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    args.target.parent.mkdir(parents=True, exist_ok=True)
    target = sqlite3.connect(args.target)
    initialize(target)

    imported = skipped = 0
    try:
        for path in sorted(args.sources.glob("ares-*.db")):
            result = import_database(path, target, args.dry_run)
            if result is None:
                print(f"  skip     {path.name}: no single run to import")
                continue
            if result.get("skipped"):
                print(f"  present  {path.name}: {result['run_id'][:20]}")
                skipped += 1
                continue
            imported += 1
            detail = (f"{result['claims']} claims" if args.dry_run
                      else f"{result['badged']}/{result['claims']} badged, "
                           f"{result['aporias']} aporias")
            print(f"  imported {path.name:30} {result['created_at']}  {detail}")
    finally:
        target.close()

    verb = "would import" if args.dry_run else "imported"
    print(f"\n{verb} {imported}, already present {skipped}")
    if not args.dry_run and imported:
        print(
            "\nSelections were not recorded for these runs - model_selections did not\n"
            "exist when they ran. They are marked as such, and the report shows\n"
            "selection recall as 'not recorded' rather than as 0%."
        )


if __name__ == "__main__":
    main()
