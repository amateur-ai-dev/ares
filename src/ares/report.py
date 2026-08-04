"""Structured, database-backed reports for the dashboard and offline export."""

from dataclasses import dataclass
from html import escape
from pathlib import Path

from .rendering import build_environment
from .scoring import score_run
from .store import PREDICATE_BADGES, edge_facts, run_metrics


@dataclass(frozen=True)
class VerifiedEdge:
    badge: str
    source_event_id: str
    target_event_id: str
    claim_text: str


@dataclass(frozen=True)
class ModelSelection:
    edge_id: str
    rationale: str
    attack_technique_id: str | None


@dataclass(frozen=True)
class Aporia:
    claim_text: str
    failure_code: str
    failure_detail: str


@dataclass(frozen=True)
class FunnelStage:
    """One narrowing step, with the share of the previous stage it kept."""

    key: str
    label: str
    value: int
    note: str
    share_of_previous: float
    share_of_widest: float
    bar_width: float


@dataclass(frozen=True)
class TimelineEntry:
    edge_id: str
    relation_type: str
    occurred_at: str | None
    source_label: str
    target_label: str
    attack_relevant: bool
    offset: float


@dataclass(frozen=True)
class RunReport:
    run_id: str
    incident_id: str
    dataset_mode: str
    counts: dict
    verified_edges: tuple[VerifiedEdge, ...]
    selections: tuple[ModelSelection, ...]
    aporias: tuple[Aporia, ...]
    precision_line: str | None
    coverage_line: str | None
    demo_notice: str | None
    metrics: dict
    funnel: tuple[FunnelStage, ...]
    timeline: tuple[TimelineEntry, ...]
    executive: dict
    duration_seconds: float | None


def _key_for(incident_id):
    root = Path(__file__).resolve().parents[2]
    if incident_id.startswith("day1:"):
        return root / "eval" / "ground_truth" / "apt29-day1.edges.yaml"
    if incident_id.startswith("day2:"):
        return root / "eval" / "ground_truth" / "apt29-day2.edges.yaml"
    return root / "eval" / "ground_truth" / "demo.edges.yaml"


def _build_funnel(metrics, aporia_count):
    """The narrowing from raw log to attack-relevant, with each drop visible.

    Aporia is deliberately NOT a stage in the funnel. It is not a narrower subset
    of the previous stage - it is the set of relations the verifier refused to
    decide, which sits beside the chain rather than inside it. Drawing it as a
    fifth bar would imply it survived the first four.
    """
    stages = [
        ("events", "Events read", metrics.get("events_parsed", 0),
         "every line in the log"),
        ("in_scope", "In scope", metrics.get("events_in_scope", 0),
         "process-create and network-connect only"),
        ("relations", "Relations found", metrics.get("edges_enumerated", 0),
         "candidate links, enumerated by code"),
        ("verified", "Verified", metrics.get("edges_verified", 0),
         "proven by deterministic join"),
        ("attack", "Attack-relevant", metrics.get("selections_made", 0),
         "selected by the model, from proven links only"),
    ]
    widest = max((value for _, _, value, _ in stages), default=0) or 1
    built = []
    previous = None
    for key, label, value, note in stages:
        share = value / widest
        built.append(FunnelStage(
            key=key, label=label, value=value, note=note,
            share_of_previous=(value / previous) if previous else 1.0,
            share_of_widest=share,
            # Square root, and the page says so. At linear scale a run that goes
            # 400 events -> 5 attack-relevant draws a final bar 1.2% wide, which
            # is invisible; the choice is between distorting silently and
            # distorting openly. Order is preserved, and the exact counts sit
            # next to every bar, so the numbers are never the thing being read
            # off the picture.
            bar_width=max(share ** 0.5 * 100, 1.5),
        ))
        previous = value or None
    return tuple(built)


def _build_timeline(connection, run_id, selected_edge_ids):
    """Verified edges in time order, with the model's picks marked.

    Position is computed here rather than in the template because the template
    cannot run script - the page has no JavaScript at all - so every coordinate
    has to arrive already resolved.
    """
    facts = edge_facts(connection, run_id)
    stamped = [fact for fact in facts if fact["occurred_at"]]
    earliest = min((fact["occurred_at"] for fact in stamped), default=None)
    latest = max((fact["occurred_at"] for fact in stamped), default=None)
    entries = []
    for index, fact in enumerate(facts):
        occurred = fact["occurred_at"]
        if occurred and earliest and latest and latest != earliest:
            # Rank rather than true elapsed time: Sysmon UtcTime is a string, and
            # an attack's interesting events often cluster inside one second.
            # Spacing by order keeps them individually visible.
            position = sorted(fact["occurred_at"] for fact in stamped).index(occurred)
            offset = position / max(len(stamped) - 1, 1)
        else:
            offset = index / max(len(facts) - 1, 1)
        entries.append(TimelineEntry(
            edge_id=fact["edge_id"],
            relation_type=fact["relation_type"],
            occurred_at=occurred,
            source_label=fact["source_label"],
            target_label=fact["target_label"],
            attack_relevant=fact["edge_id"] in selected_edge_ids,
            offset=round(offset * 100, 2),
        ))
    return tuple(entries)


def _executive_strip(dataset_mode, scored, metrics, issued_badges, duration):
    """The four numbers a reviewer reads first, or an honest refusal to give them.

    Demo runs return no figures at all. The corpus and its answer key were both
    authored in this repository, so a precision number here would be self-graded;
    and a number on a screen travels further than the caveat beside it. Refusing
    is the only version of that caveat that cannot be cropped out.

    Precision and adjudication coverage are produced as a PAIR and neither is
    emitted alone. Precision over 33 adjudicated of 794 issued badges is not
    "precision", and quoting it without its denominator is the exact failure this
    project exists to remove.
    """
    duration_text = f"{duration:.1f}s" if duration else "—"
    if dataset_mode == "demo" or not scored:
        return {
            "scored": False,
            "reason": "Demo corpus — self-graded figures are withheld, not merely unavailable.",
            "cells": [
                {"key": "PRECISION", "tone": "none", "value": "—", "note": "not scored in demo mode"},
                {"key": "SELECTION RECALL", "tone": "none", "value": "—", "note": "not scored in demo mode"},
                {"key": "ADJUDICATION COVERAGE", "tone": "none", "value": "—", "note": "no independent key"},
                {"key": "RUN DURATION", "tone": "none", "value": duration_text, "note": "wall clock"},
            ],
        }
    adjudicated = scored["badged_edge_count"]
    correct = scored["correct_badged_edge_count"]
    observable = scored["observable_true_edge_count"]
    coverage = (adjudicated / issued_badges) if issued_badges else 0
    return {
        "scored": True,
        "reason": None,
        "cells": [
            {"key": "PRECISION", "tone": "ok",
             "value": f"{scored['verification_precision']:.0%}" if adjudicated else "—",
             "note": f"{correct}/{adjudicated} adjudicated — read with coverage"},
            {"key": "SELECTION RECALL", "tone": "acc",
             "value": f"{scored['selection_recall']:.1%}",
             "note": f"{scored['selected_true_edge_count']}/{observable} findable links"},
            {"key": "ADJUDICATION COVERAGE", "tone": "ap",
             "value": f"{coverage:.1%}",
             "note": f"{adjudicated} of {issued_badges} badges — the key is silent on the rest"},
            {"key": "RUN DURATION", "tone": "none", "value": duration_text, "note": "wall clock"},
        ],
    }


def _run_duration(connection, run_id):
    row = connection.execute(
        "SELECT duration_ms FROM jobs WHERE run_id = ? ORDER BY rowid DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    return (row[0] / 1000) if row and row[0] else None


def build_report(connection, run_id):
    """Load a run once into the format-neutral report model."""
    run = connection.execute(
        "SELECT run_id, incident_id, dataset_mode FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if run is None:
        raise ValueError(f"run {run_id!r} does not exist")
    run_id, incident_id, dataset_mode = run
    verified_rows = connection.execute(
        """
        SELECT badge, source_event_id, target_event_id, claim_text
        FROM claims JOIN verifier_executions ON verifier_execution_id = verifier_executions.id
        WHERE verifier_executions.run_id = ? AND badge IN ({})
        ORDER BY claims.id
        """.format(", ".join("?" for _ in PREDICATE_BADGES)),
        (run_id, *PREDICATE_BADGES),
    ).fetchall()
    aporia_rows = connection.execute(
        """
        SELECT causal_gaps.claim_text, verification_failure_code, verification_failure_detail
        FROM causal_gaps JOIN verifier_executions
          ON json_extract(causal_gaps.verifier_execution_json, '$.verifier_execution_id') = verifier_executions.id
        WHERE verifier_executions.run_id = ? ORDER BY causal_gaps.id
        """,
        (run_id,),
    ).fetchall()
    selections = tuple(ModelSelection(*row) for row in connection.execute(
        """
        SELECT edge_id, rationale, attack_technique_id FROM model_selections
        WHERE run_id = ? ORDER BY id
        """, (run_id,)
    ))
    counts = {
        "verified_edges": len(verified_rows),
        "model_selections": len(selections),
        "aporias": len(aporia_rows),
    }
    precision_line = coverage_line = demo_notice = None
    scored = None
    if dataset_mode == "demo":
        demo_notice = "Demo mode: no accuracy figures are produced because this repository authored both the corpus and its answer key."
    else:
        scored = score_run(connection, _key_for(incident_id), incident_id)
        adjudicated = scored["badged_edge_count"]
        issued = len(verified_rows)
        precision_line = (
            "Precision on adjudicated key edges: "
            f"{scored['correct_badged_edge_count']}/{adjudicated}"
        )
        coverage_line = (
            f"Adjudication coverage: {adjudicated} of {issued} badges issued — "
            f"{issued - adjudicated} unadjudicated"
        )
    metrics = run_metrics(connection, run_id) or {
        "events_parsed": 0, "events_in_scope": 0,
        "edges_enumerated": len(verified_rows), "edges_verified": len(verified_rows),
        "verified_edges_shown": 0, "selections_made": len(selections),
        "refuted": 0, "aporias": len(aporia_rows), "discarded_as_malformed": 0,
    }
    duration = _run_duration(connection, run_id)
    executive = _executive_strip(dataset_mode, scored, metrics, len(verified_rows), duration)
    return RunReport(
        run_id, incident_id, dataset_mode, counts,
        tuple(VerifiedEdge(*row) for row in verified_rows), selections,
        tuple(Aporia(*row) for row in aporia_rows), precision_line, coverage_line, demo_notice,
        metrics,
        _build_funnel(metrics, len(aporia_rows)),
        _build_timeline(connection, run_id, {item.edge_id for item in selections}),
        executive,
        duration,
    )


def render_markdown(report):
    """Render the model as text while escaping HTML-capable untrusted values."""
    q = lambda value: escape(str(value), quote=True)
    lines = ["# ARES report", f"Dataset mode: {q(report.dataset_mode)}", "", "## Run counts"]
    lines.extend(f"- {q(name)}: {value}" for name, value in report.counts.items())
    if report.demo_notice:
        lines.extend(["", report.demo_notice])
    if report.precision_line:
        lines.extend(["", report.precision_line, report.coverage_line])
    lines.extend(["", "## Verified edges"])
    lines.extend(f"- [{q(edge.badge)}] {q(edge.source_event_id)} → {q(edge.target_event_id)}: {q(edge.claim_text)}" for edge in report.verified_edges)
    lines.extend(["", "## Model selections"])
    lines.extend(f"- {q(item.edge_id)}: {q(item.rationale)} (ATT&CK: {q(item.attack_technique_id or 'not supplied')})" for item in report.selections)
    lines.extend(["", "## Aporias — I cannot prove this"])
    lines.extend(f"- {q(item.claim_text)}: {q(item.failure_code)} — {q(item.failure_detail)}" for item in report.aporias)
    return "\n".join(lines) + "\n"


_HTML = """<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"{{ content_security_policy }}\">{{ CSP_META_TAG }}<title>ARES report</title><style>body{font-family:system-ui;margin:2rem;max-width:72rem}.banner,.aporia{padding:1rem;border:3px solid #7a1f1f;background:#fff0f0}.banner{border-color:#5b3c00;background:#fff6d5}.badge{font-weight:bold}</style></head><body><div class=\"banner\">Dataset mode: {{ report.dataset_mode }}{% if report.demo_notice %}. {{ report.demo_notice }}{% endif %}</div><h1>ARES report</h1><h2>Run counts</h2><ul>{% for name, value in report.counts.items() %}<li>{{ name }}: {{ value }}</li>{% endfor %}</ul>{% if report.precision_line %}<p>{{ report.precision_line }}</p><p>{{ report.coverage_line }}</p>{% endif %}<h2>Verified edges</h2><ul>{% for edge in report.verified_edges %}<li><span class=\"badge\">{{ edge.badge }}</span> {{ edge.source_event_id }} → {{ edge.target_event_id }}: {{ edge.claim_text }}</li>{% endfor %}</ul><h2>Model selections</h2><ul>{% for item in report.selections %}<li>{{ item.edge_id }}: {{ item.rationale }} (ATT&amp;CK: {{ item.attack_technique_id or 'not supplied' }})</li>{% endfor %}</ul><section class=\"aporia\"><h2>Aporias — I cannot prove this</h2><ul>{% for item in report.aporias %}<li>{{ item.claim_text }}: {{ item.failure_code }} — {{ item.failure_detail }}</li>{% endfor %}</ul></section></body></html>"""


def render_html(report):
    return build_environment().from_string(_HTML).render(report=report)
