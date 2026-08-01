import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.predicates import (
    PROCESS_OPENED_CONNECTION,
    SPAWNED,
    process_opened_connection,
    spawned,
)
from ares import store
from ares.scoring import score_claims
from ares.store import (
    assign_verified_badge,
    create_claim,
    initialize,
    persist_predicate_result,
    record_verifier_execution,
)


SYSMON = "Microsoft-Windows-Sysmon/Operational"


def process_event(guid, host="host.example", parent=None):
    event = {"Channel": SYSMON, "EventID": 1, "Hostname": host, "ProcessGuid": guid}
    if parent is not None:
        event["ParentProcessGuid"] = parent
    return event


def connection_event(guid, host="host.example"):
    return {
        "Channel": SYSMON,
        "EventID": 3,
        "Hostname": host,
        "ProcessGuid": guid,
        "SourceIp": "10.0.0.1",
        "DestinationIp": "10.0.0.2",
        "DestinationPort": "443",
    }


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        initialize(self.connection)

    def claim(self, predicate_type=SPAWNED, source="parent", target="child"):
        return create_claim(
            self.connection,
            incident_id="incident-1",
            predicate_type=predicate_type,
            source_event_id=source,
            target_event_id=target,
            source_hostname="host.example",
            target_hostname="host.example",
            claim_text="relation proposed",
        )

    def true_execution(self, source="parent", target="child", predicate_id=SPAWNED):
        result = spawned(process_event(source), process_event(target, parent=source), source, target)
        if predicate_id != SPAWNED:
            result = result.with_predicate(predicate_id)
        return record_verifier_execution(self.connection, "incident-1", result, "run-1")

    def test_raw_sql_cannot_bypass_the_badge_firewall(self):
        claim_id = self.claim()

        with self.assertRaisesRegex(sqlite3.IntegrityError, "badge firewall"):
            self.connection.execute(
                "UPDATE claims SET badge = ?, verifier_execution_id = NULL WHERE id = ?",
                (SPAWNED, claim_id),
            )

    def test_firewall_rejects_execution_for_a_different_ordered_event_pair(self):
        claim_id = self.claim()
        execution_id = self.true_execution(source="other-parent", target="other-child")

        with self.assertRaisesRegex(sqlite3.IntegrityError, "badge firewall"):
            self.connection.execute(
                "UPDATE claims SET badge = ?, verifier_execution_id = ? WHERE id = ?",
                (SPAWNED, execution_id, claim_id),
            )

    def test_firewall_rejects_execution_with_a_different_predicate_id(self):
        claim_id = self.claim()
        execution_id = self.true_execution(predicate_id=PROCESS_OPENED_CONNECTION)

        with self.assertRaisesRegex(sqlite3.IntegrityError, "badge firewall"):
            self.connection.execute(
                "UPDATE claims SET badge = ?, verifier_execution_id = ? WHERE id = ?",
                (SPAWNED, execution_id, claim_id),
            )

    def test_badge_function_assigns_a_matching_successful_execution(self):
        claim_id = self.claim()
        execution_id = self.true_execution()

        assign_verified_badge(self.connection, claim_id, execution_id)

        self.assertEqual(
            self.connection.execute(
                "SELECT badge, verifier_execution_id FROM claims WHERE id = ?", (claim_id,)
            ).fetchone(),
            (SPAWNED, execution_id),
        )


class PredicateTests(unittest.TestCase):
    def test_spawned_refuses_self_parenting(self):
        result = spawned(process_event("same"), process_event("same", parent="same"), "parent", "child")

        self.assertEqual(result.outcome, "false")
        self.assertFalse(result.result)

    def test_process_opened_connection_does_not_join_across_hosts(self):
        result = process_opened_connection(
            process_event("process", host="host-a"),
            connection_event("process", host="host-b"),
            "process-event",
            "connection-event",
        )

        self.assertEqual(result.outcome, "false")
        self.assertFalse(result.result)

    def test_missing_process_create_becomes_an_aporia_not_a_badge(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        initialize(connection)
        claim_id = create_claim(
            connection,
            incident_id="incident-1",
            predicate_type=PROCESS_OPENED_CONNECTION,
            source_event_id="missing-process-create",
            target_event_id="connection-event",
            source_hostname="host.example",
            target_hostname="host.example",
            claim_text="process opened connection",
        )
        result = process_opened_connection(
            None,
            connection_event("process"),
            "missing-process-create",
            "connection-event",
        )

        persist_predicate_result(connection, claim_id, result, "run-1")

        self.assertEqual(result.outcome, "unevaluable")
        self.assertEqual(
            connection.execute("SELECT badge FROM claims WHERE id = ?", (claim_id,)).fetchone()[0],
            "unverifiable",
        )
        self.assertEqual(
            connection.execute(
                "SELECT verification_failure_code FROM causal_gaps WHERE claim_id = ?", (claim_id,)
            ).fetchone()[0],
            "missing_process_create",
        )


class ScoringTests(unittest.TestCase):
    def test_score_claims_counts_an_acceptable_equivalence_once(self):
        key = {
            "true_edges": [
                {
                    "id": "one",
                    "relation_type": SPAWNED,
                    "source": {"line": 1, "Hostname": "a"},
                    "target": {"line": 2, "Hostname": "a"},
                    "acceptable_equivalences": [
                        {"source": {"line": 101, "Hostname": "a"}, "target": {"line": 102, "Hostname": "a"}}
                    ],
                }
            ],
        }
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "key.yaml"
        path.write_text(yaml.safe_dump(key))

        result = score_claims(path, [{
            "predicate_type": SPAWNED,
            "badge": SPAWNED,
            "source_event_id": "101",
            "target_event_id": "102",
            "source_hostname": "a",
            "target_hostname": "a",
        }])

        self.assertEqual(result["observable_true_edge_count"], 1)
        self.assertEqual(result["proposal_recall"], 1.0)
        self.assertEqual(result["verified_edge_recall"], 1.0)

    def test_score_claims_deduplicates_and_reports_cut_predicates(self):
        key = {
            "true_edges": [
                {"id": "one", "relation_type": SPAWNED, "source": {"line": 1, "Hostname": "a"}, "target": {"line": 2, "Hostname": "a"}, "acceptable_equivalences": []},
                {"id": "two", "relation_type": PROCESS_OPENED_CONNECTION, "source": {"line": 3, "Hostname": "a"}, "target": {"line": 4, "Hostname": "a"}, "acceptable_equivalences": []},
                {"id": "cut", "relation_type": "SAME_SESSION", "source": {"line": 5, "Hostname": "a"}, "target": {"line": 6, "Hostname": "a"}, "acceptable_equivalences": []},
            ],
            "telemetry_unobservable": [],
            "negative_confounder_pairs": [
                {"id": "negative", "source": {"line": 7, "Hostname": "a"}, "target": {"line": 8, "Hostname": "a"}},
            ],
            "unscored_composites": [],
        }
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "key.yaml"
        path.write_text(yaml.safe_dump(key))
        claims = [
            {"predicate_type": SPAWNED, "badge": SPAWNED, "source_event_id": "1", "target_event_id": "2", "source_hostname": "a", "target_hostname": "a"},
            {"predicate_type": SPAWNED, "badge": SPAWNED, "source_event_id": "1", "target_event_id": "2", "source_hostname": "a", "target_hostname": "a"},
            {"predicate_type": PROCESS_OPENED_CONNECTION, "badge": "unverifiable", "source_event_id": "3", "target_event_id": "4", "source_hostname": "a", "target_hostname": "a"},
            {"predicate_type": SPAWNED, "badge": SPAWNED, "source_event_id": "7", "target_event_id": "8", "source_hostname": "a", "target_hostname": "a"},
        ]

        result = score_claims(path, claims)

        self.assertEqual(result["observable_true_edge_count"], 2)
        self.assertEqual(result["out_of_scope_for_build_count"], 1)
        self.assertEqual(result["proposal_recall"], 1.0)
        self.assertEqual(result["verified_edge_recall"], 0.5)
        self.assertEqual(result["verification_precision"], 0.5)
        self.assertFalse(result["verification_precision_passed"])


if __name__ == "__main__":
    unittest.main()


class BadgedClaimImmutabilityTests(unittest.TestCase):
    """A badge is a statement about specific bytes; the claim must not drift after it."""

    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        store.initialize(self.connection)
        self.execution_id = self.connection.execute(
            """
            INSERT INTO verifier_executions (
                incident_id, predicate_id, predicate_version, input_event_ids,
                evaluated_fields, result, log_provenance, run_id
            ) VALUES ('i', 'SPAWNED', 'v1', '["1","2"]', '{}', 1, '["log"]', 'r')
            """
        ).lastrowid
        self.connection.execute(
            """
            INSERT INTO claims (
                id, incident_id, predicate_type, source_event_id, target_event_id,
                source_hostname, target_hostname, claim_text, badge, verifier_execution_id
            ) VALUES (99, 'i', 'SPAWNED', '1', '2', 'HOST-A', 'HOST-A', 'legit', 'SPAWNED', ?)
            """,
            (self.execution_id,),
        )

    def test_hostnames_of_a_badged_claim_cannot_be_rewritten(self):
        # Every predicate join in 2.1 is host-scoped, so swapping the hosts makes the
        # badge describe an assertion nobody verified.
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE claims SET source_hostname = 'HOST-X' WHERE id = 99")

    def test_claim_text_of_a_badged_claim_cannot_be_rewritten(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE claims SET claim_text = 'forged' WHERE id = 99")

    def test_an_unbadged_claim_stays_editable(self):
        self.connection.execute(
            """
            INSERT INTO claims (
                id, incident_id, predicate_type, source_event_id, target_event_id,
                source_hostname, target_hostname, claim_text
            ) VALUES (100, 'i', 'SPAWNED', '5', '6', 'h', 'h', 'draft')
            """
        )
        self.connection.execute("UPDATE claims SET claim_text = 'revised' WHERE id = 100")
        text = self.connection.execute("SELECT claim_text FROM claims WHERE id = 100").fetchone()[0]
        self.assertEqual(text, "revised")
