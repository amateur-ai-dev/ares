import json
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
from ares.proposer import parse_proposals
from ares.pipeline import enumerate_candidate_edges, load_events, run_incident
from ares.scoring import score_claims, score_run
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
    def _write_key(self, directory, mode):
        key = Path(directory) / f"{mode}.edges.yaml"
        key.write_text(yaml.safe_dump({
            "schema_version": 1,
            "dataset_mode": mode,
            "true_edges": [],
        }), encoding="utf-8")
        return key

    def test_score_claims_rejects_a_mode_the_key_disagrees_with(self):
        """score_run is not the only door into scoring.

        A dashboard or exporter holding claims in memory can call score_claims
        directly, and that path must not be the one where a demo number acquires
        an evaluation label.
        """
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        eval_key = self._write_key(directory.name, "eval")
        demo_key = self._write_key(directory.name, "demo")

        with self.assertRaises(ValueError):
            score_claims(eval_key, [], dataset_mode="demo")
        with self.assertRaises(ValueError):
            score_claims(demo_key, [], dataset_mode="eval")

    def test_score_claims_without_a_mode_still_scores_corpus_free_fixtures(self):
        """The fixture suite scores hand-built claims that belong to no corpus."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        demo_key = self._write_key(directory.name, "demo")

        metrics = score_claims(demo_key, [])
        self.assertEqual(metrics["dataset_mode"], "demo")

    def test_score_run_rejects_a_demo_run_against_an_eval_key(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        demo_log = Path(directory.name) / "data" / "demo" / "demo.json"
        demo_log.parent.mkdir(parents=True)
        demo_log.write_text("\n".join([
            json.dumps(process_event("demo.example", "parent")),
            json.dumps(process_event("demo.example", "child", parent="parent")),
        ]) + "\n")
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        counts = run_incident(connection, "demo-run", demo_log, "local", limit_chunks=0)

        with self.assertRaisesRegex(ValueError, "dataset mode mismatch"):
            score_run(
                connection,
                Path(__file__).parents[1] / "eval" / "ground_truth" / "apt29-day1.edges.yaml",
                "demo-run",
                selected_edge_ids=counts.selected_edge_ids,
            )

    def test_requested_mode_cannot_override_the_log_location(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        log_path = Path(directory.name) / "data" / "demo" / "demo.json"
        log_path.parent.mkdir(parents=True)
        log_path.write_text(json.dumps(process_event("demo.example", "parent")) + "\n")
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)

        with self.assertRaisesRegex(ValueError, "dataset mode mismatch"):
            run_incident(
                connection,
                "demo-run",
                log_path,
                "local",
                limit_chunks=0,
                dataset_mode="eval",
            )

    def test_score_run_returns_the_persisted_dataset_mode(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        log_path = Path(directory.name) / "data" / "demo" / "demo.json"
        log_path.parent.mkdir(parents=True)
        log_path.write_text("\n".join([
            json.dumps(process_event("demo.example", "parent")),
            json.dumps(process_event("demo.example", "child", parent="parent")),
        ]) + "\n")
        key_path = Path(directory.name) / "demo.edges.yaml"
        key_path.write_text(yaml.safe_dump({
            "dataset_mode": "demo",
            "true_edges": [{
                "id": "edge",
                "relation_type": SPAWNED,
                "source": {"line": 1, "Hostname": "demo.example"},
                "target": {"line": 2, "Hostname": "demo.example"},
                "acceptable_equivalences": [],
            }],
        }))
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        counts = run_incident(connection, "demo-run", log_path, "local", limit_chunks=0)

        metrics = score_run(connection, key_path, "demo-run", selected_edge_ids=counts.selected_edge_ids)

        self.assertEqual(counts.dataset_mode, "demo")
        self.assertEqual(metrics["dataset_mode"], "demo")


class DemoCorpusTests(unittest.TestCase):
    def test_demo_log_has_the_declared_event_count_and_orphan_connection(self):
        log_path = Path(__file__).parents[1] / "data" / "demo" / "demo-incident.json"

        events = load_events(log_path)

        self.assertEqual(len(events), 200)
        self.assertEqual(sum(event.event["EventID"] == 1 for event in events), 178)
        self.assertEqual(sum(event.event["EventID"] == 3 for event in events), 2)
        orphan = events[84].event
        self.assertEqual(orphan["DestinationIp"], "203.0.113.99")
        self.assertNotIn(orphan["ProcessGuid"], {
            event.event.get("ProcessGuid")
            for event in events
            if event.event["EventID"] == 1
        })

    def test_demo_key_edges_are_enumerated_by_the_real_pipeline(self):
        root = Path(__file__).parents[1]
        log_path = root / "data" / "demo" / "demo-incident.json"
        key_path = root / "eval" / "ground_truth" / "demo.edges.yaml"
        key = yaml.safe_load(key_path.read_text())

        actual = {
            (edge.relation_type, edge.source_event_id, edge.target_event_id)
            for edge in enumerate_candidate_edges(load_events(log_path))
        }
        expected = {
            (edge["relation_type"], str(edge["source"]["line"]), str(edge["target"]["line"]))
            for edge in key["true_edges"]
        }

        self.assertSetEqual(actual & expected, expected)

    def test_demo_run_records_the_deliberate_orphan_as_an_aporia(self):
        root = Path(__file__).parents[1]
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)

        counts = run_incident(
            connection,
            "demo-aporia",
            root / "data" / "demo" / "demo-incident.json",
            "local",
            limit_chunks=0,
        )

        self.assertEqual(counts.aporias, 1)
        self.assertEqual(
            connection.execute("SELECT badge FROM claims WHERE badge = 'unverifiable'").fetchone(),
            ("unverifiable",),
        )
    def test_score_claims_uses_transient_selection_for_selection_metrics(self):
        key = {
            "true_edges": [
                {"id": "one", "relation_type": SPAWNED, "source": {"line": 1, "Hostname": "a"}, "target": {"line": 2, "Hostname": "a"}, "acceptable_equivalences": []},
                {"id": "two", "relation_type": SPAWNED, "source": {"line": 3, "Hostname": "a"}, "target": {"line": 4, "Hostname": "a"}, "acceptable_equivalences": []},
            ],
        }
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "key.yaml"
        path.write_text(yaml.safe_dump(key))
        claims = [
            {"predicate_type": SPAWNED, "badge": SPAWNED, "source_event_id": "1", "target_event_id": "2", "source_hostname": "a", "target_hostname": "a"},
            {"predicate_type": SPAWNED, "badge": SPAWNED, "source_event_id": "3", "target_event_id": "4", "source_hostname": "a", "target_hostname": "a"},
        ]

        result = score_claims(
            path,
            claims,
            selected_edge_ids={"SPAWNED:1:2"},
            enumerated_edge_count=7,
            verified_edge_count=6,
            verified_edges_shown=5,
        )

        self.assertEqual(result["selection_recall"], 0.5)
        self.assertEqual(result["verified_edge_recall"], 0.5)
        self.assertEqual(result["selected_true_edge_count"], 1)
        self.assertEqual(result["enumerated_edge_count"], 7)
        self.assertEqual(result["verified_edge_count"], 6)
        self.assertEqual(result["verified_edges_shown"], 5)

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


class TruncatedResponseSalvageTests(unittest.TestCase):
    """A cut-off response must not cost the proposals it already finished writing."""

    ALLOWED = {"373", "650", "622"}

    def test_completed_entries_survive_a_truncated_array(self):
        raw = (
            '{"edges": [\n'
            '{"source_event_id":"373","target_event_id":"650","relation_type":"SPAWNED","rationale":"guid match"},\n'
            '{"source_event_id":"622","target_event_id":"650","relation_type":"SPAWNED","rationale":"second"},\n'
            '{"source_event_id":"999","target_event_id":"'
        )
        proposals, discarded = parse_proposals(raw, self.ALLOWED)
        self.assertEqual([(p.source_event_id, p.target_event_id) for p in proposals],
                         [("373", "650"), ("622", "650")])
        self.assertEqual(discarded, 0)

    def test_salvage_still_rejects_hallucinated_event_ids(self):
        raw = '{"edges":[{"source_event_id":"11111","target_event_id":"650","relation_type":"SPAWNED","rationale":"x"}'
        proposals, discarded = parse_proposals(raw, self.ALLOWED)
        self.assertEqual(proposals, [])
        self.assertEqual(discarded, 1)

    def test_unparseable_text_is_still_discarded(self):
        proposals, discarded = parse_proposals("the model declined", self.ALLOWED)
        self.assertEqual(proposals, [])
        self.assertEqual(discarded, 1)
