#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.phase0 import badge_first_spawned, parse_events, summarize_sysmon


# The full histogram is frozen, not a chosen subset: a subset lets every other
# event id drift so long as the total holds. The badge payload is frozen too —
# "some SPAWNED badge exists" still passes if the badged relationship changes.
EXPECTED = {
    "apt29_evals_day1_manual_2020-05-01225525.json": {
        "total_events": 196081,
        "sysmon_event_ids": {1: 447, 2: 209, 3: 1229, 4: 1, 5: 401, 7: 20259, 8: 95, 9: 652, 10: 39283, 11: 1649, 12: 61151, 13: 17541, 15: 18, 17: 84, 18: 362, 22: 81, 23: 422},
        "spawned_badge": {
            "badge": "SPAWNED",
            "child_process_guid": "{47ab858c-e144-5eac-aa03-000000000400}",
            "parent_process_guid": "{47ab858c-e13c-5eac-a903-000000000400}",
            "hostname": "SCRANTON.dmevals.local",
        },
    },
    "apt29_evals_day2_manual_2020-05-02035409.json": {
        "total_events": 587286,
        "sysmon_event_ids": {1: 581, 2: 360, 3: 2186, 4: 1, 5: 607, 7: 32012, 8: 103, 9: 973, 10: 99218, 11: 5479, 12: 162894, 13: 101230, 15: 18, 17: 66, 18: 360, 19: 1, 20: 1, 21: 1, 22: 145, 23: 1027, 255: 2},
        "spawned_badge": {
            "badge": "SPAWNED",
            "child_process_guid": "{8320f18b-2724-5ead-7205-000000000400}",
            "parent_process_guid": "{8320f18b-2724-5ead-7105-000000000400}",
            "hostname": "UTICA.dmevals.local",
        },
    },
}
EXPECTED_HOSTS = {"NASHUA.dmevals.local", "NEWYORK.dmevals.local", "SCRANTON.dmevals.local", "UTICA.dmevals.local"}


parser = argparse.ArgumentParser(description="Confirm the frozen OTRF APT29 Phase 0 dataset.")
parser.add_argument("data_dir", type=Path, nargs="?", default=Path.home() / ".ares" / "datasets" / "apt29")
args = parser.parse_args()

for filename, expected in EXPECTED.items():
    incident = args.data_dir / ("day1" if "day1" in filename else "day2") / filename
    summary = summarize_sysmon(parse_events(incident))
    badge = badge_first_spawned(parse_events(incident))
    observed = {**summary, "hosts": sorted(summary["hosts"]), "spawned_badge": badge}
    print(json.dumps({"incident": str(incident), **observed}, indent=2, sort_keys=True))

    if summary["total_events"] != expected["total_events"]:
        raise SystemExit(f"{incident}: unexpected total_events")
    if summary["sysmon_event_ids"] != expected["sysmon_event_ids"]:
        raise SystemExit(f"{incident}: unexpected Sysmon event counts")
    if summary["hosts"] != EXPECTED_HOSTS:
        raise SystemExit(f"{incident}: unexpected hosts")
    if not all(host.endswith(".dmevals.local") for host in summary["hosts"]):
        raise SystemExit(f"{incident}: host is outside dmevals.local")
    if badge != expected["spawned_badge"]:
        raise SystemExit(f"{incident}: SPAWNED badge changed identity")
