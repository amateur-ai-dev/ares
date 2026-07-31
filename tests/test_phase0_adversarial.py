"""Independent, contract-derived adversarial tests for Phase 0.

These tests intentionally exercise malformed and internally inconsistent input.
For SPAWNED, abstention is always preferable to a relationship that cannot be
proved from two distinct, unambiguous Sysmon ProcessCreate records.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ares.phase0 import (
    SYSMON_CHANNEL,
    badge_first_spawned,
    parse_events,
    summarize_sysmon,
)


def process_create(host="host.example", guid="{child}", parent="{parent}", **extra):
    event = {
        "Channel": SYSMON_CHANNEL,
        "EventID": 1,
        "Hostname": host,
        "ProcessGuid": guid,
        "ParentProcessGuid": parent,
    }
    event.update(extra)
    return event


class ParseEventsAdversarialTests(unittest.TestCase):
    def jsonl(self, content):
        temporary = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        temporary.write(content)
        temporary.close()
        return Path(temporary.name)

    def test_ignores_blank_lines_and_accepts_trailing_whitespace(self):
        path = self.jsonl('\n  \t\n{"event": 1}   \n\n{"event": 2}\t\n')

        self.assertEqual(list(parse_events(path)), [{"event": 1}, {"event": 2}])

    def test_preserves_unicode_and_deeply_nested_json(self):
        event = {"Hostname": "münchen-東京.example", "nested": {"a": {"b": {"c": 1}}}}
        path = self.jsonl(json.dumps(event, ensure_ascii=False) + "\n")

        self.assertEqual(list(parse_events(path)), [event])

    def test_rejects_malformed_nonblank_json(self):
        path = self.jsonl('{"event": 1}\nnot json\n')

        with self.assertRaises(json.JSONDecodeError):
            list(parse_events(path))


class SummarizeSysmonAdversarialTests(unittest.TestCase):
    def test_counts_every_record_but_only_exact_sysmon_channel_event_ids_and_hosts(self):
        events = [
            {"Channel": SYSMON_CHANNEL, "EventID": 1, "Hostname": "α.example"},
            {"Channel": SYSMON_CHANNEL, "EventID": 3, "Hostname": "β.example"},
            {"Channel": "microsoft-windows-sysmon/operational", "EventID": 1, "Hostname": "wrong-case"},
            {"Channel": SYSMON_CHANNEL + " ", "EventID": 1, "Hostname": "trailing-space"},
            {"EventID": 1, "Hostname": "no-channel"},
        ]

        self.assertEqual(
            summarize_sysmon(events),
            {"total_events": 5, "sysmon_event_ids": {1: 1, 3: 1}, "hosts": {"α.example", "β.example"}},
        )

    def test_does_not_collect_hosts_seen_only_on_non_sysmon_channels(self):
        summary = summarize_sysmon([
            {"Channel": "Security", "EventID": 4624, "Hostname": "security-only"},
            {"Channel": SYSMON_CHANNEL, "EventID": 1},
        ])

        self.assertEqual(summary["hosts"], set())

    def test_counts_string_event_id_as_its_observed_value(self):
        summary = summarize_sysmon([{"Channel": SYSMON_CHANNEL, "EventID": "1", "Hostname": "host"}])

        self.assertEqual(summary, {"total_events": 1, "sysmon_event_ids": {"1": 1}, "hosts": {"host"}})

    def test_ignores_sysmon_records_without_an_event_id(self):
        """An event with no EventID cannot belong in an EventID count."""
        summary = summarize_sysmon([
            {"Channel": SYSMON_CHANNEL, "Hostname": "missing-id"},
            {"Channel": SYSMON_CHANNEL, "EventID": 1, "Hostname": "valid"},
        ])

        self.assertEqual(summary, {"total_events": 2, "sysmon_event_ids": {1: 1}, "hosts": {"missing-id", "valid"}})


class SpawnedBadgeAdversarialTests(unittest.TestCase):
    def test_badges_a_well_formed_same_host_parent_child_pair(self):
        badge = badge_first_spawned([
            process_create(guid="{parent}", parent=None),
            process_create(guid="{child}", parent="{parent}"),
        ])

        self.assertEqual(
            badge,
            {
                "badge": "SPAWNED",
                "child_process_guid": "{child}",
                "parent_process_guid": "{parent}",
                "hostname": "host.example",
            },
        )

    def test_abstains_when_a_record_names_itself_as_parent(self):
        self.assertIsNone(badge_first_spawned([process_create(guid="{same}", parent="{same}")]))

    def test_abstains_from_mutual_parent_cycle(self):
        events = [
            process_create(guid="{a}", parent="{b}"),
            process_create(guid="{b}", parent="{a}"),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_abstains_from_longer_parent_cycle(self):
        events = [
            process_create(guid="{a}", parent="{c}"),
            process_create(guid="{b}", parent="{a}"),
            process_create(guid="{c}", parent="{b}"),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_abstains_when_matching_guid_exists_only_on_another_host(self):
        events = [
            process_create(host="host-a", guid="{parent}", parent=None),
            process_create(host="host-b", guid="{child}", parent="{parent}"),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_abstains_when_event_id_is_string_not_integer_one(self):
        events = [
            process_create(guid="{parent}", parent=None),
            process_create(guid="{child}", parent="{parent}", EventID="1"),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_abstains_for_channel_case_whitespace_and_near_misses(self):
        invalid_channels = [
            "microsoft-windows-sysmon/operational",
            SYSMON_CHANNEL + " ",
            "Microsoft-Windows-Sysmon/Operation",
            "Microsoft-Windows-Sysmon/Operational/",
        ]
        for channel in invalid_channels:
            with self.subTest(channel=channel):
                self.assertIsNone(badge_first_spawned([
                    process_create(guid="{parent}", parent=None),
                    process_create(guid="{child}", parent="{parent}", Channel=channel),
                ]))

    def test_abstains_when_required_identity_fields_are_none_empty_or_whitespace(self):
        cases = [
            process_create(host=None),
            process_create(host=""),
            process_create(host="   "),
            process_create(guid=""),
            process_create(guid="   "),
            process_create(parent=""),
            process_create(parent="   "),
        ]
        for invalid_child in cases:
            with self.subTest(invalid_child=invalid_child):
                self.assertIsNone(badge_first_spawned([
                    process_create(guid="{parent}", parent=None),
                    invalid_child,
                ]))

    def test_abstains_when_event_id_is_boolean(self):
        events = [
            process_create(guid="{parent}", parent=None),
            process_create(guid="{child}", parent="{parent}", EventID=True),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_abstains_when_process_guids_use_non_string_values_that_compare_equal(self):
        events = [
            process_create(guid=True, parent=None),
            process_create(guid="{child}", parent=1),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_abstains_when_hostname_is_not_a_string(self):
        events = [
            process_create(host=7, guid="{parent}", parent=None),
            process_create(host=7, guid="{child}", parent="{parent}"),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_abstains_when_parent_guid_is_ambiguous_on_the_same_host(self):
        events = [
            process_create(guid="{parent}", parent=None, Image="first-parent.exe"),
            process_create(guid="{parent}", parent=None, Image="second-parent.exe"),
            process_create(guid="{child}", parent="{parent}"),
        ]

        self.assertIsNone(badge_first_spawned(events))

    def test_accepts_long_unicode_guid_values_when_the_records_are_unambiguous(self):
        parent = "{親}" + "p" * 4096
        child = "{子}" + "c" * 4096
        badge = badge_first_spawned([
            process_create(host="東京.example", guid=parent, parent=None),
            process_create(host="東京.example", guid=child, parent=parent),
        ])

        self.assertEqual(badge["child_process_guid"], child)
        self.assertEqual(badge["parent_process_guid"], parent)
        self.assertEqual(badge["hostname"], "東京.example")


if __name__ == "__main__":
    unittest.main()
