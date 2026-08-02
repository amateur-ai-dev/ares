import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.pipeline import (
    CandidateEvent,
    CandidateEdge,
    chunk_candidates,
    enumerate_candidate_edges,
    record_proposal,
    run_incident,
    verify_candidate_edges,
)
from ares.predicates import PROCESS_OPENED_CONNECTION, SPAWNED
from ares.prioritise import prioritise_edges
from ares.proposer import ProposedEdge, SelectedEdge, parse_proposals, parse_selections
from ares.store import initialize


SYSMON = "Microsoft-Windows-Sysmon/Operational"


def process_event(host, guid, parent=None, event_time="2020-05-01 00:00:00"):
    event = {
        "Channel": SYSMON,
        "EventID": 1,
        "Hostname": host,
        "ProcessGuid": guid,
        "EventTime": event_time,
        "Image": "C:\\Windows\\System32\\cmd.exe",
    }
    if parent is not None:
        event["ParentProcessGuid"] = parent
    return event


def connection_event(host, guid, port="443", event_time="2020-05-01 00:00:01"):
    return {
        "Channel": SYSMON,
        "EventID": 3,
        "Hostname": host,
        "ProcessGuid": guid,
        "DestinationIp": "198.51.100.10",
        "DestinationPort": port,
        "EventTime": event_time,
    }


class ProposerParsingTests(unittest.TestCase):
    def test_discards_malformed_json(self):
        proposals, discarded = parse_proposals("[not valid JSON]", {"10", "11"})

        self.assertEqual(proposals, [])
        self.assertEqual(discarded, 1)

    def test_discards_malformed_json_entries(self):
        raw = json.dumps([
            {
                "source_event_id": "10",
                "target_event_id": "11",
                "relation_type": SPAWNED,
                "rationale": "parent GUID matches",
            },
            {
                "source_event_id": "10",
                "target_event_id": "11",
                "relation_type": "INVENTED",
                "rationale": "not a supported predicate",
            },
        ])

        proposals, discarded = parse_proposals(raw, {"10", "11"})

        self.assertEqual(len(proposals), 1)
        self.assertEqual(discarded, 1)

    def test_discards_hallucinated_line_numbers(self):
        raw = json.dumps([{
            "source_event_id": "10",
            "target_event_id": "999",
            "relation_type": SPAWNED,
            "rationale": "invented line",
        }])

        proposals, discarded = parse_proposals(raw, {"10", "11"})

        self.assertEqual(proposals, [])
        self.assertEqual(discarded, 1)

    def test_discards_out_of_batch_selection_ids(self):
        raw = json.dumps([{
            "edge_id": "SPAWNED:10:999",
            "rationale": "invented edge",
            "attack_technique_id": "T1059",
        }])

        selections, discarded = parse_selections(raw, {"SPAWNED:10:11"})

        self.assertEqual(selections, [])
        self.assertEqual(discarded, 1)


class CandidateSelectionTests(unittest.TestCase):
    def test_chunking_keeps_hosts_separate(self):
        candidates = [
            CandidateEvent("1", process_event("host-a", "a1", event_time="2020-05-01 00:00:03")),
            CandidateEvent("2", process_event("host-b", "b1", event_time="2020-05-01 00:00:01")),
            CandidateEvent("3", process_event("host-a", "a2", parent="a1", event_time="2020-05-01 00:00:02")),
            CandidateEvent("4", process_event("host-b", "b2", parent="b1", event_time="2020-05-01 00:00:02")),
        ]

        chunks = list(chunk_candidates(candidates, chunk_size=2, overlap=1))

        self.assertEqual([event.line_number for event in chunks[0]], ["3", "1"])
        self.assertEqual([event.line_number for event in chunks[1]], ["2", "4"])
        self.assertTrue(all(len({event.event["Hostname"] for event in chunk}) == 1 for chunk in chunks))


class CandidateEnumerationTests(unittest.TestCase):
    def test_enumerates_host_scoped_spawn_and_connection_edges(self):
        candidates = [
            CandidateEvent("1", process_event("host-a", "parent")),
            CandidateEvent("2", process_event("host-a", "child", parent="parent")),
            CandidateEvent("3", connection_event("host-a", "child")),
            CandidateEvent("4", process_event("host-b", "parent")),
            CandidateEvent("5", process_event("host-b", "other", parent="parent")),
        ]

        edges = enumerate_candidate_edges(candidates)

        self.assertEqual(
            [(edge.relation_type, edge.source_event_id, edge.target_event_id) for edge in edges],
            [
                (SPAWNED, "1", "2"),
                (PROCESS_OPENED_CONNECTION, "2", "3"),
                (SPAWNED, "4", "5"),
            ],
        )

    def test_spawned_enumeration_keeps_existing_cycle_and_ambiguity_guards(self):
        cases = {
            "self parent": [CandidateEvent("1", process_event("host", "same", parent="same"))],
            "mutual cycle": [
                CandidateEvent("1", process_event("host", "a", parent="b")),
                CandidateEvent("2", process_event("host", "b", parent="a")),
            ],
            "longer cycle": [
                CandidateEvent("1", process_event("host", "a", parent="c")),
                CandidateEvent("2", process_event("host", "b", parent="a")),
                CandidateEvent("3", process_event("host", "c", parent="b")),
            ],
            "ambiguous parent guid": [
                CandidateEvent("1", process_event("host", "parent")),
                CandidateEvent("2", process_event("host", "parent")),
                CandidateEvent("3", process_event("host", "child", parent="parent")),
            ],
        }

        for name, candidates in cases.items():
            with self.subTest(name=name):
                self.assertEqual(enumerate_candidate_edges(candidates), [])

    def test_enumerated_edges_are_persisted_through_the_badge_firewall(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        initialize(connection)
        edges = enumerate_candidate_edges([
            CandidateEvent("1", process_event("host", "parent")),
            CandidateEvent("2", process_event("host", "child", parent="parent")),
        ])

        verified = verify_candidate_edges(connection, "incident", edges, "run")

        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0].outcome, "true")
        self.assertEqual(
            connection.execute("SELECT badge FROM claims").fetchone()[0],
            SPAWNED,
        )


class PrioritisationTests(unittest.TestCase):
    def test_prioritisation_orders_without_removing_or_badging_edges(self):
        low_source = CandidateEvent("1", process_event("host", "parent"))
        low_target = CandidateEvent("2", process_event("host", "child", parent="parent"))
        high_source = CandidateEvent(
            "3",
            process_event("host", "powershell", event_time="2020-05-01 00:00:02"),
        )
        high_source.event["Image"] = "C:\\Users\\alice\\AppData\\Roaming\\powershell.exe"
        high_source.event["CommandLine"] = "powershell -enc ZABlAG0AbwA="
        high_target = CandidateEvent(
            "4",
            process_event("host", "script", parent="powershell", event_time="2020-05-01 00:00:03"),
        )
        edges = [
            CandidateEdge(SPAWNED, low_source, low_target),
            CandidateEdge(SPAWNED, high_source, high_target),
        ]

        prioritised = prioritise_edges(edges, [low_source, low_target, high_source, high_target])

        self.assertEqual([item.edge.edge_id for item in prioritised], [edges[1].edge_id, edges[0].edge_id])
        self.assertEqual({item.edge.edge_id for item in prioritised}, {edge.edge_id for edge in edges})


class PipelineAporiaTests(unittest.TestCase):
    def test_pipeline_discards_out_of_batch_edge_returned_by_selection_backend(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        log_path = Path(directory.name) / "events.jsonl"
        log_path.write_text("\n".join([
            json.dumps(process_event("host", "parent")),
            json.dumps(process_event("host", "child", parent="parent")),
        ]) + "\n")
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)

        counts = run_incident(
            connection,
            "incident",
            log_path,
            "local",
            select_batch=lambda arm, prompt, allowed, seed: (
                [SelectedEdge("SPAWNED:999:1000", "invented", "T1059")],
                0,
            ),
        )

        self.assertEqual(counts.edges_enumerated, 1)
        self.assertEqual(counts.edges_verified, 1)
        self.assertEqual(counts.selections_made, 0)
        self.assertEqual(counts.discarded_as_malformed, 1)

    def test_cross_host_proposal_becomes_an_aporia(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        initialize(connection)

        outcome = record_proposal(
            connection,
            incident_id="test-incident",
            proposal=ProposedEdge("1", "2", SPAWNED, "claimed across hosts"),
            events_by_line={
                "1": CandidateEvent("1", process_event("host-a", "parent")),
                "2": CandidateEvent("2", process_event("host-b", "child", parent="parent")),
            },
            run_id="test-run",
        )

        self.assertEqual(outcome, "unevaluable")
        self.assertEqual(
            connection.execute("SELECT verification_failure_code FROM causal_gaps").fetchone()[0],
            "cross_host",
        )


if __name__ == "__main__":
    unittest.main()
