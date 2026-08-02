"""Candidate selection and deterministic verification for Phase 1."""

import json
import ntpath
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from .predicates import (
    PROCESS_OPENED_CONNECTION,
    SPAWNED,
    PredicateResult,
    process_opened_connection,
    spawned,
)
from .phase0 import badge_first_spawned
from .prioritise import prioritise_edges
from .proposer import ProposedEdge, render_prompt, select_with_counts
from .store import create_claim, initialize, persist_predicate_result


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFAULT_CHUNK_SIZE = 80
DEFAULT_CHUNK_OVERLAP = 8


@dataclass(frozen=True)
class CandidateEvent:
    line_number: str
    event: dict


@dataclass(frozen=True)
class CandidateEdge:
    """A deterministic relation candidate, before its stored verification."""

    relation_type: str
    source: CandidateEvent
    target: CandidateEvent

    @property
    def source_event_id(self):
        return self.source.line_number

    @property
    def target_event_id(self):
        return self.target.line_number

    @property
    def edge_id(self):
        return f"{self.relation_type}:{self.source_event_id}:{self.target_event_id}"


@dataclass(frozen=True)
class VerifiedEdge:
    """A candidate whose predicate result was persisted through the badge firewall."""

    edge: CandidateEdge
    claim_id: int
    outcome: str


@dataclass(frozen=True)
class RunCounts:
    edges_enumerated: int = 0
    edges_verified: int = 0
    verified_edges_shown: int = 0
    selections_made: int = 0
    selected_edge_ids: frozenset[str] = frozenset()
    refuted: int = 0
    aporias: int = 0
    discarded_as_malformed: int = 0


def stream_events(log_path):
    """Read an OTRF JSONL log once while preserving its stable line identifiers."""
    with Path(log_path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            yield CandidateEvent(str(line_number), json.loads(line))


def stream_candidates(log_path):
    """Read only the Sysmon events relevant to the two Phase 1 predicates."""
    for candidate in stream_events(log_path):
        event = candidate.event
        if (
            event.get("Channel") == SYSMON_CHANNEL
            and type(event.get("EventID")) is int
            and event["EventID"] in (1, 3)
        ):
            yield candidate


def load_candidates(log_path):
    return list(stream_candidates(log_path))


def load_events(log_path):
    return list(stream_events(log_path))


def chunk_candidates(candidates, chunk_size=DEFAULT_CHUNK_SIZE, overlap=DEFAULT_CHUNK_OVERLAP):
    """Yield timestamp-ordered, host-scoped candidate chunks with overlap."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be non-negative and smaller than chunk_size")
    by_host = {}
    for candidate in candidates:
        hostname = candidate.event.get("Hostname")
        if not isinstance(hostname, str) or not hostname.strip():
            continue
        by_host.setdefault(hostname, []).append(candidate)
    step = chunk_size - overlap
    for hostname in sorted(by_host):
        ordered = sorted(
            by_host[hostname],
            key=lambda candidate: (str(candidate.event.get("EventTime", "")), int(candidate.line_number)),
        )
        for start in range(0, len(ordered), step):
            chunk = ordered[start:start + chunk_size]
            if chunk:
                yield chunk
            if start + chunk_size >= len(ordered):
                break


def render_candidate(candidate):
    event = candidate.event
    image = ntpath.basename(str(event.get("Image", "-"))) or "-"
    shared = (
        f"line={candidate.line_number} time={event.get('EventTime', '-')} "
        f"eid={event.get('EventID', '-')} image={image}"
    )
    if event.get("EventID") == 1:
        return (
            f"{shared} ProcessGuid={event.get('ProcessGuid', '-')} "
            f"ParentProcessGuid={event.get('ParentProcessGuid', '-')}"
        )
    return (
        f"{shared} ProcessGuid={event.get('ProcessGuid', '-')} "
        f"DestinationIp={event.get('DestinationIp', '-')} "
        f"DestinationPort={event.get('DestinationPort', '-')}"
    )


def _identity(value):
    return isinstance(value, str) and bool(value.strip())


def _is_process_create(candidate):
    event = candidate.event
    return (
        event.get("Channel") == SYSMON_CHANNEL
        and type(event.get("EventID")) is int
        and event["EventID"] == 1
        and _identity(event.get("ProcessGuid"))
        and _identity(event.get("Hostname"))
    )


def _passes_spawned_guards(process_creates, parent, child):
    """Ask the Phase 0 guard oracle whether this exact SPAWNED pair is admissible.

    `badge_first_spawned` already owns self-parent, cycle, and duplicate-GUID
    refusal.  Reordering only makes the pair under evaluation its first lookup;
    the complete process set remains available for its ambiguity and cycle checks.
    """
    guarded = badge_first_spawned(
        candidate.event
        for candidate in [child, *(candidate for candidate in process_creates if candidate is not child)]
    )
    return guarded == {
        "badge": SPAWNED,
        "child_process_guid": child.event["ProcessGuid"],
        "parent_process_guid": parent.event["ProcessGuid"],
        "hostname": child.event["Hostname"],
    }


def enumerate_candidate_edges(events):
    """Return every host-scoped Phase 1 edge whose existing predicate holds.

    SPAWNED additionally delegates all malformed-graph refusal to the existing
    Phase 0 guard logic.  This function creates no claims and assigns no badges.
    """
    process_creates = [candidate for candidate in events if _is_process_create(candidate)]
    by_host_and_guid = {}
    for candidate in process_creates:
        event = candidate.event
        by_host_and_guid.setdefault((event["Hostname"], event["ProcessGuid"]), []).append(candidate)

    edges = []
    for child in process_creates:
        parent_guid = child.event.get("ParentProcessGuid")
        if not _identity(parent_guid):
            continue
        for parent in by_host_and_guid.get((child.event["Hostname"], parent_guid), []):
            result = spawned(parent.event, child.event, parent.line_number, child.line_number)
            if result.outcome == "true" and _passes_spawned_guards(process_creates, parent, child):
                edges.append(CandidateEdge(SPAWNED, parent, child))

    for connection in events:
        event = connection.event
        if (
            event.get("Channel") != SYSMON_CHANNEL
            or type(event.get("EventID")) is not int
            or event["EventID"] != 3
            or not _identity(event.get("ProcessGuid"))
            or not _identity(event.get("Hostname"))
        ):
            continue
        for process_create in by_host_and_guid.get((event["Hostname"], event["ProcessGuid"]), []):
            result = process_opened_connection(
                process_create.event,
                event,
                process_create.line_number,
                connection.line_number,
            )
            if result.outcome == "true":
                edges.append(CandidateEdge(PROCESS_OPENED_CONNECTION, process_create, connection))

    return sorted(
        edges,
        key=lambda edge: (int(edge.target_event_id), int(edge.source_event_id), edge.relation_type),
    )


def render_verified_edge(edge):
    """Render one already-verified edge as model-readable evidence, not a task."""
    def endpoint(candidate):
        event = candidate.event
        image = ntpath.basename(str(event.get("Image", "-"))) or "-"
        command_line = str(event.get("CommandLine", "-"))
        return f"image={image!r} command_line={command_line!r}"

    host = edge.source.event.get("Hostname", "-")
    source_time = edge.source.event.get("EventTime", "-")
    target_time = edge.target.event.get("EventTime", "-")
    return (
        f"edge_id={edge.edge_id} relation={edge.relation_type} host={host!r} "
        f"time={source_time!r}->{target_time!r} source[{endpoint(edge.source)}] "
        f"target[{endpoint(edge.target)}]"
    )


def _evaluate(proposal, source, target):
    if proposal.relation_type == SPAWNED:
        return spawned(source, target, proposal.source_event_id, proposal.target_event_id)
    if proposal.relation_type == PROCESS_OPENED_CONNECTION:
        return process_opened_connection(source, target, proposal.source_event_id, proposal.target_event_id)
    provenance = tuple(event_id for event_id, event in ((proposal.source_event_id, source), (proposal.target_event_id, target)) if event is not None)
    return PredicateResult(
        proposal.relation_type,
        "1.0",
        (proposal.source_event_id, proposal.target_event_id),
        {},
        None,
        "unevaluable",
        provenance or (proposal.source_event_id,),
        "unsupported_relation",
        "the proposed relation is not implemented in Phase 1",
    )


def _aporia(result, code, detail):
    return replace(result, result=None, outcome="unevaluable", failure_code=code, failure_detail=detail)


def _record_proposal(connection, incident_id, proposal, events_by_line, run_id):
    source_candidate = events_by_line.get(proposal.source_event_id)
    target_candidate = events_by_line.get(proposal.target_event_id)
    source = None if source_candidate is None else source_candidate.event
    target = None if target_candidate is None else target_candidate.event
    source_host = source.get("Hostname") if source else "<missing>"
    target_host = target.get("Hostname") if target else "<missing>"
    claim_id = create_claim(
        connection,
        incident_id,
        proposal.relation_type,
        proposal.source_event_id,
        proposal.target_event_id,
        source_host or "<missing>",
        target_host or "<missing>",
        f"{proposal.relation_type}: {proposal.rationale}",
    )
    result = _evaluate(proposal, source, target)
    if source is None or target is None:
        missing = []
        if source is None:
            missing.append("source")
        if target is None:
            missing.append("target")
        result = _aporia(result, "event_not_found", f"{', '.join(missing)} event id was not found in the incident log")
    elif source_host != target_host:
        result = _aporia(result, "cross_host", "predicate joins are host-scoped; proposed endpoints have different Hostname values")
    persist_predicate_result(connection, claim_id, result, run_id)
    return claim_id, result.outcome


def record_proposal(connection, incident_id, proposal, events_by_line, run_id):
    """Compatibility wrapper for tests of untrusted, model-originated proposals."""
    _, outcome = _record_proposal(connection, incident_id, proposal, events_by_line, run_id)
    return outcome


def verify_candidate_edges(connection, incident_id, edges, run_id):
    """Persist every enumerated edge through the existing predicate/store route."""
    verified = []
    for edge in edges:
        proposal = ProposedEdge(
            edge.source_event_id,
            edge.target_event_id,
            edge.relation_type,
            "deterministically enumerated candidate edge",
        )
        claim_id, outcome = _record_proposal(
            connection,
            incident_id,
            proposal,
            {edge.source_event_id: edge.source, edge.target_event_id: edge.target},
            run_id,
        )
        verified.append(VerifiedEdge(edge, claim_id, outcome))
    return verified


def run_incident(
    connection,
    incident_id,
    log_path,
    arm,
    key_path=None,
    chunk_size=DEFAULT_CHUNK_SIZE,
    overlap=DEFAULT_CHUNK_OVERLAP,
    limit_chunks=None,
    seed=0,
    run_id=None,
    select_batch=None,
    model=None,
    top_n=300,
):
    """Enumerate/verify facts, then ask one model batch to select attack edges."""
    del key_path
    del chunk_size, overlap
    if top_n < 1:
        raise ValueError("top_n must be positive")
    initialize(connection)
    all_events = load_events(log_path)
    events = [
        candidate
        for candidate in all_events
        if candidate.event.get("Channel") == SYSMON_CHANNEL
        and type(candidate.event.get("EventID")) is int
        and candidate.event["EventID"] in (1, 3)
    ]
    run_id = run_id or f"{arm}-{uuid.uuid4().hex}"
    enumerated = enumerate_candidate_edges(events)
    persisted = verify_candidate_edges(connection, incident_id, enumerated, run_id)
    verified = [item.edge for item in persisted if item.outcome == "true"]
    counts = RunCounts(
        edges_enumerated=len(enumerated),
        edges_verified=len(verified),
        refuted=sum(item.outcome == "false" for item in persisted),
        aporias=sum(item.outcome == "unevaluable" for item in persisted),
    )
    # Verification is committed before the potentially slow model call, so a
    # failed selection backend cannot lose independently-derived facts.
    connection.commit()

    if not verified or limit_chunks == 0:
        return counts
    shown = prioritise_edges(verified, all_events)[:top_n]
    allowed_edge_ids = {item.edge.edge_id for item in shown}
    prompt = render_prompt([render_verified_edge(item.edge) for item in shown])
    if select_batch is None:
        response = select_with_counts(arm, prompt, allowed_edge_ids, seed, model)
        selections = response.selections
        discarded = response.discarded_as_malformed
    else:
        selections, discarded = select_batch(arm, prompt, allowed_edge_ids, seed)
    accepted_selections = []
    for selection in selections:
        if selection.edge_id not in allowed_edge_ids:
            discarded += 1
            continue
        accepted_selections.append(selection)
    selected_edge_ids = frozenset(selection.edge_id for selection in accepted_selections)
    counts = replace(
        counts,
        verified_edges_shown=len(shown),
        selections_made=len(accepted_selections),
        selected_edge_ids=selected_edge_ids,
        discarded_as_malformed=discarded,
    )
    return counts
