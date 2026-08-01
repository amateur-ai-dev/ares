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
            if (event_id := event.get("EventID")) is not None:
                event_ids[event_id] += 1
            if hostname := event.get("Hostname"):
                hosts.add(hostname)
    return {"total_events": total_events, "sysmon_event_ids": dict(event_ids), "hosts": hosts}


def badge_first_spawned(events):
    """Return one host-scoped Sysmon EID 1 SPAWNED badge, if present."""

    def identity(value):
        return isinstance(value, str) and bool(value.strip())

    process_creates = [
        event for event in events
        if event.get("Channel") == SYSMON_CHANNEL
        and type(event.get("EventID")) is int
        and event["EventID"] == 1
        and identity(event.get("ProcessGuid"))
        and identity(event.get("Hostname"))
    ]
    by_host_and_guid = {}
    for event in process_creates:
        key = (event["Hostname"], event["ProcessGuid"])
        by_host_and_guid.setdefault(key, []).append(event)

    def forms_cycle(child, parent):
        seen = {child["ProcessGuid"]}
        current = parent
        while True:
            current_guid = current["ProcessGuid"]
            if current_guid in seen:
                return True
            seen.add(current_guid)
            ancestor_guid = current.get("ParentProcessGuid")
            if not identity(ancestor_guid):
                return False
            ancestors = by_host_and_guid.get((current["Hostname"], ancestor_guid), [])
            if len(ancestors) != 1:
                return False
            current = ancestors[0]

    for child in process_creates:
        parent_guid = child.get("ParentProcessGuid")
        # A record whose ParentProcessGuid equals its own ProcessGuid joins to
        # itself and proves no parent-child relationship. Badging it would be a
        # false SPAWNED — the one failure this project must never produce.
        if not identity(parent_guid) or parent_guid == child["ProcessGuid"]:
            continue
        parents = by_host_and_guid.get((child["Hostname"], parent_guid), [])
        if len(parents) == 1 and not forms_cycle(child, parents[0]):
            return {
                "badge": "SPAWNED",
                "child_process_guid": child["ProcessGuid"],
                "parent_process_guid": parent_guid,
                "hostname": child["Hostname"],
            }
    return None
