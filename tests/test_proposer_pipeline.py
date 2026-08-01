import json
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.pipeline import CandidateEvent, chunk_candidates, record_proposal
from ares.predicates import SPAWNED
from ares.proposer import ProposedEdge, parse_proposals
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


class ProposerParsingTests(unittest.TestCase):
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


class PipelineAporiaTests(unittest.TestCase):
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
