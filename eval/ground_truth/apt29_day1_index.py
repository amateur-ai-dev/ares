#!/usr/bin/env python3
"""Stream-index APT29 Day 1 Sysmon events for ground-truth authoring.

The source JSON is newline-delimited and too large to load as a list. This
tool stores only predicate-eligible Sysmon EIDs (1, 3, 7, 11) in SQLite, with
the original line number as a stable record identity, then exposes compact
queries useful when binding emulation-plan commands to events.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

LOG = Path("/Users/nithingowda/.ares/datasets/apt29/day1/apt29_evals_day1_manual_2020-05-01225525.json")
DB = Path("/private/tmp/apt29-day1-ground-truth.sqlite")
ELIGIBLE = {1, 3, 7, 11}


def value(event: dict, key: str) -> str | None:
    item = event.get(key)
    return None if item is None else str(item)


def build() -> None:
    if DB.exists():
        DB.unlink()
    con = sqlite3.connect(DB)
    con.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE events (
          line_no INTEGER PRIMARY KEY, event_time TEXT, timestamp TEXT,
          hostname TEXT, event_id INTEGER, process_guid TEXT,
          parent_process_guid TEXT, logon_id TEXT, image TEXT,
          command_line TEXT, target_filename TEXT, image_loaded TEXT,
          source_ip TEXT, destination_ip TEXT, destination_port TEXT,
          user TEXT, raw TEXT NOT NULL
        );
        CREATE INDEX event_lookup ON events(event_id, hostname, event_time);
        CREATE INDEX process_lookup ON events(process_guid, hostname);
        CREATE INDEX parent_lookup ON events(parent_process_guid, hostname);
        CREATE INDEX image_lookup ON events(image);
        CREATE INDEX target_lookup ON events(target_filename);
        CREATE INDEX command_lookup ON events(command_line);
    """)
    batch = []
    with LOG.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            event = json.loads(line)
            if event.get("Channel") != "Microsoft-Windows-Sysmon/Operational":
                continue
            event_id = event.get("EventID")
            if event_id not in ELIGIBLE:
                continue
            batch.append((
                line_no, value(event, "EventTime"), value(event, "@timestamp"),
                value(event, "Hostname"), event_id, value(event, "ProcessGuid"),
                value(event, "ParentProcessGuid"), value(event, "LogonId"),
                value(event, "Image"), value(event, "CommandLine"),
                value(event, "TargetFilename"), value(event, "ImageLoaded"),
                value(event, "SourceIp"), value(event, "DestinationIp"),
                value(event, "DestinationPort"), value(event, "User"), line,
            ))
            if len(batch) >= 2000:
                con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                batch.clear()
    if batch:
        con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
    con.commit()
    print(DB)
    for row in con.execute("SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY event_id"):
        print(*row, sep="\t")
    con.close()


def search(needle: str) -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    like = f"%{needle.lower()}%"
    rows = con.execute("""
      SELECT line_no,event_time,hostname,event_id,process_guid,parent_process_guid,
             logon_id,image,command_line,target_filename,image_loaded,
             source_ip,destination_ip,destination_port,user
      FROM events
      WHERE lower(coalesce(image,'')) LIKE ? OR lower(coalesce(command_line,'')) LIKE ?
         OR lower(coalesce(target_filename,'')) LIKE ? OR lower(coalesce(image_loaded,'')) LIKE ?
      ORDER BY event_time, line_no
    """, (like, like, like, like)).fetchall()
    for row in rows:
        print(json.dumps(dict(row), sort_keys=True))
    print(f"rows={len(rows)}")


def sql(query: str) -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    for row in con.execute(query):
        print(json.dumps(dict(row), sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "search", "sql"))
    parser.add_argument("value", nargs="?")
    args = parser.parse_args()
    if args.action == "build":
        build()
    elif args.action == "search":
        search(args.value)
    else:
        sql(args.value)
