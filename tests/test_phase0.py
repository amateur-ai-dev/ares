import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.phase0 import badge_first_spawned, parse_events, summarize_sysmon


class Phase0Tests(unittest.TestCase):
    def write_events(self, events):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "events.jsonl"
        path.write_text("\n".join(events) + "\n")
        return path

    def test_summarize_sysmon_counts_events_and_hosts(self):
        path = self.write_events([
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "a.dmevals.local", "ProcessGuid": "parent"}',
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "a.dmevals.local", "ProcessGuid": "child", "ParentProcessGuid": "parent"}',
            '{"EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "b.dmevals.local"}',
            '{"EventID": 7, "Channel": "Other", "Hostname": "b.dmevals.local"}',
        ])

        self.assertEqual(summarize_sysmon(parse_events(path)), {"total_events": 4, "sysmon_event_ids": {1: 2, 3: 1}, "hosts": {"a.dmevals.local", "b.dmevals.local"}})

    def test_badges_spawned_only_when_parent_is_on_same_hostname(self):
        path = self.write_events([
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "a.dmevals.local", "ProcessGuid": "parent-a"}',
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "b.dmevals.local", "ProcessGuid": "parent-b"}',
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "a.dmevals.local", "ProcessGuid": "child", "ParentProcessGuid": "parent-a"}',
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "a.dmevals.local", "ProcessGuid": "cross-host", "ParentProcessGuid": "parent-b"}',
        ])

        self.assertEqual(badge_first_spawned(parse_events(path)), {"badge": "SPAWNED", "child_process_guid": "child", "parent_process_guid": "parent-a", "hostname": "a.dmevals.local"})

    def test_badge_first_spawned_returns_none_when_no_parent_resolves(self):
        path = self.write_events([
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "a.dmevals.local", "ProcessGuid": "child", "ParentProcessGuid": "missing-parent"}',
        ])

        self.assertEqual(badge_first_spawned(parse_events(path)), None)

    def test_badge_first_spawned_refuses_a_record_that_is_its_own_parent(self):
        """A self-join proves no relationship — badging it is a false VERIFIED."""
        path = self.write_events([
            '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "a.dmevals.local", "ProcessGuid": "g", "ParentProcessGuid": "g"}',
        ])

        self.assertEqual(badge_first_spawned(parse_events(path)), None)

    def test_badge_first_spawned_ignores_non_sysmon_event_id_1_records(self):
        path = self.write_events([
            '{"EventID": 1, "Channel": "Other", "Hostname": "a.dmevals.local", "ProcessGuid": "parent"}',
            '{"EventID": 1, "Channel": "Other", "Hostname": "a.dmevals.local", "ProcessGuid": "child", "ParentProcessGuid": "parent"}',
        ])

        self.assertEqual(badge_first_spawned(parse_events(path)), None)
