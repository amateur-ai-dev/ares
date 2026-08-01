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
from .proposer import propose_with_counts, render_prompt
from .store import create_claim, initialize, persist_predicate_result


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFAULT_CHUNK_SIZE = 80
DEFAULT_CHUNK_OVERLAP = 8


@dataclass(frozen=True)
class CandidateEvent:
    line_number: str
    event: dict


@dataclass(frozen=True)
class RunCounts:
    proposals_made: int = 0
    badged: int = 0
    refuted: int = 0
    aporias: int = 0
    discarded_as_malformed: int = 0


def stream_candidates(log_path):
    """Read an OTRF JSONL log once, retaining only predicate-relevant events."""
    with Path(log_path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            if (
                event.get("Channel") == SYSMON_CHANNEL
                and type(event.get("EventID")) is int
                and event["EventID"] in (1, 3)
            ):
                yield CandidateEvent(str(line_number), event)


def load_candidates(log_path):
    return list(stream_candidates(log_path))


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


def record_proposal(connection, incident_id, proposal, events_by_line, run_id):
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
    return result.outcome


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
    propose_chunk=None,
    model=None,
):
    """Run one proposing arm over an incident and return its terminal proposal counts."""
    del key_path
    initialize(connection)
    events = load_candidates(log_path)
    events_by_line = {candidate.line_number: candidate for candidate in events}
    run_id = run_id or f"{arm}-{uuid.uuid4().hex}"
    counts = RunCounts()
    for chunk_index, chunk in enumerate(chunk_candidates(events, chunk_size, overlap)):
        if limit_chunks is not None and chunk_index >= limit_chunks:
            break
        allowed_event_ids = {candidate.line_number for candidate in chunk}
        prompt = render_prompt([render_candidate(candidate) for candidate in chunk])
        if propose_chunk is None:
            response = propose_with_counts(arm, prompt, allowed_event_ids, seed, model)
            proposals = response.proposals
            discarded = response.discarded_as_malformed
        else:
            proposals, discarded = propose_chunk(arm, prompt, allowed_event_ids, seed)
        counts = replace(counts, discarded_as_malformed=counts.discarded_as_malformed + discarded)
        for proposal in proposals:
            if (
                proposal.source_event_id not in allowed_event_ids
                or proposal.target_event_id not in allowed_event_ids
                or proposal.relation_type not in {SPAWNED, PROCESS_OPENED_CONNECTION}
            ):
                counts = replace(counts, discarded_as_malformed=counts.discarded_as_malformed + 1)
                continue
            outcome = record_proposal(connection, incident_id, proposal, events_by_line, run_id)
            counts = replace(counts, proposals_made=counts.proposals_made + 1)
            if outcome == "true":
                counts = replace(counts, badged=counts.badged + 1)
            elif outcome == "false":
                counts = replace(counts, refuted=counts.refuted + 1)
            else:
                counts = replace(counts, aporias=counts.aporias + 1)
        # Commit per chunk, not once at the end. A run is tens of minutes of model
        # calls; committing only on success means any interruption discards all of
        # it, and the frontier arm is hours long. Each chunk is independent, so a
        # partial run is still usable evidence.
        connection.commit()
        print(f"  chunk {chunk_index + 1}: {counts.proposals_made} proposals, "
              f"{counts.badged} badged, {counts.aporias} aporias", flush=True)
    connection.commit()
    return counts
