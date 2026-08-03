"""Structured, database-backed reports for the dashboard and offline export."""

from dataclasses import dataclass
from html import escape
from pathlib import Path

from .rendering import build_environment
from .scoring import score_run
from .store import PREDICATE_BADGES


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


def _key_for(incident_id):
    root = Path(__file__).resolve().parents[2]
    if incident_id.startswith("day1:"):
        return root / "eval" / "ground_truth" / "apt29-day1.edges.yaml"
    if incident_id.startswith("day2:"):
        return root / "eval" / "ground_truth" / "apt29-day2.edges.yaml"
    return root / "eval" / "ground_truth" / "demo.edges.yaml"


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
    if dataset_mode == "demo":
        demo_notice = "Demo mode: no accuracy figures are produced because this repository authored both the corpus and its answer key."
    else:
        metrics = score_run(connection, _key_for(incident_id), incident_id)
        adjudicated = metrics["badged_edge_count"]
        issued = len(verified_rows)
        precision_line = (
            "Precision on adjudicated key edges: "
            f"{metrics['correct_badged_edge_count']}/{adjudicated}"
        )
        coverage_line = (
            f"Adjudication coverage: {adjudicated} of {issued} badges issued — "
            f"{issued - adjudicated} unadjudicated"
        )
    return RunReport(
        run_id, incident_id, dataset_mode, counts,
        tuple(VerifiedEdge(*row) for row in verified_rows), selections,
        tuple(Aporia(*row) for row in aporia_rows), precision_line, coverage_line, demo_notice,
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
