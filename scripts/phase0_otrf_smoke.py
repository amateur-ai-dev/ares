#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ares.phase0 import badge_first_spawned, parse_events, summarize_sysmon


EXPECTED = {
    "apt29_evals_day1_manual_2020-05-01225525.json": {"total_events": 196081, "sysmon_event_ids": {1: 447, 3: 1229, 7: 20259, 11: 1649}},
    "apt29_evals_day2_manual_2020-05-02035409.json": {"total_events": 587286, "sysmon_event_ids": {1: 581, 3: 2186, 7: 32012, 11: 5479}},
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
    observed_event_ids = {event_id: summary["sysmon_event_ids"].get(event_id, 0) for event_id in expected["sysmon_event_ids"]}
    if observed_event_ids != expected["sysmon_event_ids"]:
        raise SystemExit(f"{incident}: unexpected Sysmon event counts")
    if summary["hosts"] != EXPECTED_HOSTS:
        raise SystemExit(f"{incident}: unexpected hosts")
    if not all(host.endswith(".dmevals.local") for host in summary["hosts"]):
        raise SystemExit(f"{incident}: host is outside dmevals.local")
    if badge is None:
        raise SystemExit(f"{incident}: no SPAWNED badge found")
