#!/usr/bin/env python3
"""Render an owner-checkable audit sample from a frozen ground-truth key.

The first version of this rendering failed an audit for a rendering reason, not
a data reason: it printed both events in full, so verifying a SPAWNED edge meant
spotting that the target's *ParentProcessGuid* equals the source's *ProcessGuid*
while each record also displayed its own other GUID as a decoy. Eight correct
edges got marked wrong. The values that must match now appear alone, adjacent,
under plain-English labels, and nothing else is shown next to them.
"""

import argparse
import json
import random
from pathlib import Path

import yaml

# For each predicate: which field on each side actually has to match, and how to
# say that without jargon.
COMPARISONS = {
    "SPAWNED": {
        "a_field": "ProcessGuid",
        "a_label": "its own ID",
        "b_field": "ParentProcessGuid",
        "b_label": "the ID of whatever started it",
        "means": "{a} started {b}",
    },
    "PROCESS_OPENED_CONNECTION": {
        "a_field": "ProcessGuid",
        "a_label": "its own ID",
        "b_field": "ProcessGuid",
        "b_label": "the ID of the process that opened the connection",
        "means": "{a} is what opened this network connection",
    },
    "SAME_SESSION": {
        "a_field": "LogonId",
        "a_label": "its logon session",
        "b_field": "LogonId",
        "b_label": "its logon session",
        "means": "{a} and {b} ran in the same logged-in session",
    },
    "WROTE_PATH_BEFORE_EXECUTION": {
        "a_field": "TargetFilename",
        "a_label": "the file it wrote",
        "b_field": "Image",
        "b_label": "the file that was then run",
        "means": "{a} wrote the file that {b} later ran",
    },
}

VERDICT = (
    "**Your verdict:**\n\n"
    "- [ ] MATCH — the two values are identical\n"
    "- [ ] NO MATCH — they differ\n"
    "- [ ] unsure\n"
)


def load_lines(log_path, wanted):
    """Pull specific one-based lines out of the JSONL log in a single pass."""
    found = {}
    with open(log_path, encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if number in wanted:
                found[number] = json.loads(line)
                if len(found) == len(wanted):
                    break
    return found


def short_name(event):
    """A human-sized name for a process: the executable, without its path."""
    image = event.get("Image") or event.get("TargetFilename") or "?"
    return image.rsplit("\\", 1)[-1]


def render(edge, events):
    rule = COMPARISONS.get(edge["relation_type"])
    source = events[edge["source"]["line"]]
    target = events[edge["target"]["line"]]
    a_name, b_name = short_name(source), short_name(target)

    out = [f"## {edge['id']} — {rule['means'].format(a=a_name, b=b_name)}", ""]
    out.append(f"From attack step `{', '.join(edge.get('plan_steps') or ['—'])}`. "
               f"Relation claimed: `{edge['relation_type']}`.")
    out += ["", "### Compare these two values", "", "```text"]
    out.append(f"A.  {a_name}   (log line {edge['source']['line']})")
    out.append(f"    {rule['a_label']}:")
    out.append(f"    {source.get(rule['a_field'], '<missing>')}")
    out.append("")
    out.append(f"B.  {b_name}   (log line {edge['target']['line']})")
    out.append(f"    {rule['b_label']}:")
    out.append(f"    {target.get(rule['b_field'], '<missing>')}")
    out += ["```", ""]
    out.append(f"**Are A and B identical?** If yes, {rule['means'].format(a=a_name, b=b_name)} "
               f"— the edge is right. Ignore every other value in the log; this one "
               f"comparison is the whole check.")
    out += ["", "<details><summary>More context, only if you want it</summary>", ""]
    out.append("```text")
    for label, event, side in (("A", source, "source"), ("B", target, "target")):
        out.append(f"{label}: {event.get('EventTime', '?')}  {event.get('Hostname', '?')}")
        out.append(f"   {event.get('Image', '?')}")
        if event.get("CommandLine"):
            out.append(f"   {event['CommandLine'][:120]}")
    out.append("```")
    if edge.get("note"):
        out += ["", edge["note"]]
    out += ["", "</details>", "", VERDICT]
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("key", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260731)
    args = parser.parse_args()

    key = yaml.safe_load(args.key.read_text())
    edges = [edge for edge in key["true_edges"] if edge["relation_type"] in COMPARISONS]
    chosen = random.Random(args.seed).sample(edges, min(args.sample, len(edges)))

    wanted = {edge[side]["line"] for edge in chosen for side in ("source", "target")}
    events = load_lines(args.log, wanted)

    day = "1" if "day1" in args.key.name else "2"
    header = [
        f"# Day {day} — check {len(chosen)} entries from the answer key",
        "",
        "> Each entry below shows **two values, A and B**. Your only job is to say",
        "> whether they are identical. Nothing else on the page needs checking, and",
        "> no security knowledge is required — it is string comparison.",
        ">",
        "> Tick one box per entry by putting an `x` in the brackets: `- [x]`.",
        ">",
        "> These values are read straight out of the raw log at the line numbers shown,",
        "> so they are what the log actually says, not a summary of it.",
        "",
        f"Sample: {len(chosen)} of {len(edges)} scoreable edges, "
        f"`random.Random({args.seed})`, seed fixed so this is reproducible.",
        "",
        "---",
        "",
    ]
    args.out.write_text("\n".join(header) + "\n\n---\n\n".join(render(e, events) for e in chosen) + "\n")
    print(f"wrote {args.out} — {len(chosen)} entries")


if __name__ == "__main__":
    main()
