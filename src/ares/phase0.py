"""Small, deliberately standalone Phase 0 checks for OTRF JSONL incidents."""

import json
from collections import Counter
from pathlib import Path


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def parse_events(path: Path):
    """Yield records from OTRF's newline-delimited JSON export."""
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                yield json.loads(line)


def summarize_sysmon(events):
    total_events = 0
    event_ids = Counter()
    hosts = set()
    for event in events:
        total_events += 1
        if event.get("Channel") == SYSMON_CHANNEL:
            event_ids[event["EventID"]] += 1
            if hostname := event.get("Hostname"):
                hosts.add(hostname)
    return {"total_events": total_events, "sysmon_event_ids": dict(event_ids), "hosts": hosts}


def badge_first_spawned(events):
    """Return one host-scoped Sysmon EID 1 SPAWNED badge, if present."""
    process_creates = [
        event for event in events
        if event.get("Channel") == SYSMON_CHANNEL and event.get("EventID") == 1 and event.get("ProcessGuid") and event.get("Hostname")
    ]
    by_host_and_guid = {(event["Hostname"], event["ProcessGuid"]): event for event in process_creates}
    for child in process_creates:
        parent_guid = child.get("ParentProcessGuid")
        # A record whose ParentProcessGuid equals its own ProcessGuid joins to
        # itself and proves no parent-child relationship. Badging it would be a
        # false SPAWNED — the one failure this project must never produce.
        if parent_guid == child["ProcessGuid"]:
            continue
        if parent_guid and (child["Hostname"], parent_guid) in by_host_and_guid:
            return {
                "badge": "SPAWNED",
                "child_process_guid": child["ProcessGuid"],
                "parent_process_guid": parent_guid,
                "hostname": child["Hostname"],
            }
    return None
