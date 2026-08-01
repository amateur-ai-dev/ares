"""The two Phase 1 relational predicates."""

from dataclasses import dataclass, replace


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SPAWNED = "SPAWNED"
PROCESS_OPENED_CONNECTION = "PROCESS_OPENED_CONNECTION"
PREDICATE_VERSION = "1.0"


@dataclass(frozen=True)
class PredicateResult:
    predicate_id: str
    predicate_version: str
    input_event_ids: tuple[str, str]
    evaluated_fields: dict
    result: bool | None
    outcome: str
    log_provenance: tuple[str, ...]
    failure_code: str = ""
    failure_detail: str = ""

    def with_predicate(self, predicate_id):
        return replace(self, predicate_id=predicate_id)


def _fields(parent, child, names):
    return {
        f"{prefix}.{name}": None if event is None else event.get(name)
        for prefix, event in (("source", parent), ("target", child))
        for name in names
    }


def _result(predicate_id, source_event_id, target_event_id, fields, result, outcome, provenance, code="", detail=""):
    return PredicateResult(
        predicate_id=predicate_id,
        predicate_version=PREDICATE_VERSION,
        input_event_ids=(str(source_event_id), str(target_event_id)),
        evaluated_fields=fields,
        result=result,
        outcome=outcome,
        log_provenance=tuple(str(event_id) for event_id in provenance),
        failure_code=code,
        failure_detail=detail,
    )


def _is_sysmon(event, event_id):
    return event is not None and event.get("Channel") == SYSMON_CHANNEL and event.get("EventID") == event_id


def spawned(parent, child, source_event_id, target_event_id):
    fields = _fields(parent, child, ("ProcessGuid", "ParentProcessGuid", "Hostname"))
    provenance = [event_id for event, event_id in ((parent, source_event_id), (child, target_event_id)) if event is not None]
    if not _is_sysmon(parent, 1) or not _is_sysmon(child, 1):
        return _result(SPAWNED, source_event_id, target_event_id, fields, None, "unevaluable", provenance, "missing_process_create", "both endpoints must be Sysmon EID 1 records")
    parent_guid = parent.get("ProcessGuid")
    child_guid = child.get("ProcessGuid")
    parent_reference = child.get("ParentProcessGuid")
    parent_host = parent.get("Hostname")
    child_host = child.get("Hostname")
    if not all(isinstance(value, str) and value.strip() for value in (parent_guid, child_guid, parent_reference, parent_host, child_host)):
        return _result(SPAWNED, source_event_id, target_event_id, fields, None, "unevaluable", provenance, "missing_join_field", "SPAWNED requires process GUIDs and hostnames")
    if parent_reference == child_guid:
        return _result(SPAWNED, source_event_id, target_event_id, fields, False, "false", provenance, "self_parent", "a process cannot prove that it spawned itself")
    matched = parent_reference == parent_guid and parent_host == child_host
    return _result(SPAWNED, source_event_id, target_event_id, fields, matched, "true" if matched else "false", provenance, "conflicting_fields" if not matched else "", "parent GUID or hostname does not match" if not matched else "")


def process_opened_connection(process_create, network_connect, source_event_id, target_event_id):
    fields = _fields(
        process_create,
        network_connect,
        ("ProcessGuid", "Hostname", "SourceIp", "DestinationIp", "DestinationPort"),
    )
    provenance = [event_id for event, event_id in ((process_create, source_event_id), (network_connect, target_event_id)) if event is not None]
    if process_create is None:
        return _result(PROCESS_OPENED_CONNECTION, source_event_id, target_event_id, fields, None, "unevaluable", provenance, "missing_process_create", "the matching Sysmon EID 1 record is absent from the capture")
    if not _is_sysmon(process_create, 1) or not _is_sysmon(network_connect, 3):
        return _result(PROCESS_OPENED_CONNECTION, source_event_id, target_event_id, fields, None, "unevaluable", provenance, "missing_join_field", "requires Sysmon EID 1 and EID 3 records")
    process_guid = process_create.get("ProcessGuid")
    connection_guid = network_connect.get("ProcessGuid")
    process_host = process_create.get("Hostname")
    connection_host = network_connect.get("Hostname")
    if not all(isinstance(value, str) and value.strip() for value in (process_guid, connection_guid, process_host, connection_host)):
        return _result(PROCESS_OPENED_CONNECTION, source_event_id, target_event_id, fields, None, "unevaluable", provenance, "missing_join_field", "PROCESS_OPENED_CONNECTION requires process GUIDs and hostnames")
    matched = process_guid == connection_guid and process_host == connection_host
    return _result(PROCESS_OPENED_CONNECTION, source_event_id, target_event_id, fields, matched, "true" if matched else "false", provenance, "conflicting_fields" if not matched else "", "process GUID or hostname does not match" if not matched else "")
