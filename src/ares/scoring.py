"""Score Phase 1 claims against a frozen edge-level ground-truth key."""

from pathlib import Path

import yaml

from .dataset_mode import mode_from_key, require_mode
from .store import PREDICATE_BADGES, run_mode


CUT_PREDICATES = {"SAME_SESSION", "WROTE_PATH_BEFORE_EXECUTION"}


def _endpoint(endpoint):
    return str(endpoint["line"]), endpoint["Hostname"]


def _edge_keys(edge):
    relation_type = edge["relation_type"]
    variants = [(edge["source"], edge["target"], relation_type)]
    for equivalent in edge.get("acceptable_equivalences", []):
        if "source" in equivalent and "target" in equivalent:
            variants.append((equivalent["source"], equivalent["target"], equivalent.get("relation_type", relation_type)))
        elif "source_line" in equivalent and "target_line" in equivalent:
            variants.append((
                {"line": equivalent["source_line"], "Hostname": equivalent.get("source_hostname", edge["source"]["Hostname"])},
                {"line": equivalent["target_line"], "Hostname": equivalent.get("target_hostname", edge["target"]["Hostname"])},
                equivalent.get("relation_type", relation_type),
            ))
    return {(_endpoint(source), _endpoint(target), kind) for source, target, kind in variants}


def _claim_key(claim, relation_type):
    source_host = claim.get("source_hostname")
    target_host = claim.get("target_hostname")
    if not source_host or not target_host:
        return None
    return (
        (str(claim["source_event_id"]), source_host),
        (str(claim["target_event_id"]), target_host),
        relation_type,
    )


def _edge_id(relation_type, claim):
    return f"{relation_type}:{claim['source_event_id']}:{claim['target_event_id']}"


def score_claims(
    key_path: Path,
    claims,
    selected_edge_ids=None,
    enumerated_edge_count=0,
    verified_edge_count=0,
    verified_edges_shown=0,
    dataset_mode=None,
):
    """Score verified facts and transient model selections against the frozen key.

    Selection is interpretation, deliberately kept out of the claims table.  A
    ``None`` selection set preserves the legacy all-claims behaviour for direct
    callers; production runs always pass the model's verified-edge IDs.

    ``dataset_mode`` is the caller's belief about which corpus these claims came
    from.  ``score_run`` enforces the same agreement against the mode recorded in
    the database, but it is not the only way in: a dashboard or exporter holding
    claims in memory can reach this function directly, and that path must not be
    the one where a demo number acquires an evaluation label.  Passing ``None``
    asserts nothing and is left available for the fixture suite, which scores
    hand-built claim lists that belong to no corpus at all.
    """
    with Path(key_path).open(encoding="utf-8") as source:
        key = yaml.safe_load(source)
    key_mode = mode_from_key(key_path, key)
    if dataset_mode is not None and require_mode(dataset_mode) != key_mode:
        raise ValueError(
            f"dataset mode mismatch: claims are {dataset_mode!r}, key is {key_mode!r}"
        )

    observable = [edge for edge in key.get("true_edges", []) if edge["relation_type"] not in CUT_PREDICATES]
    out_of_scope = [edge for edge in key.get("true_edges", []) if edge["relation_type"] in CUT_PREDICATES]
    true_key_to_id = {
        edge_key: edge["id"]
        for edge in observable
        for edge_key in _edge_keys(edge)
    }
    negative_pairs = {
        (_endpoint(edge["source"]), _endpoint(edge["target"]))
        for edge in key.get("negative_confounder_pairs", [])
    }

    # The key enumerates the attack narrative, not every true relation in the log.
    # A badge on two events the key never mentions is therefore usually a real
    # background process spawn, not an error — but it must be counted and shown,
    # not silently dropped, or the reader cannot tell how much of the output the
    # key was even able to speak to.
    key_endpoints = {
        endpoint[0]
        for edge in observable
        for endpoint in (_endpoint(edge["source"]), _endpoint(edge["target"]))
    }

    proposed = set()
    badged = set()
    verified_and_selected = set()
    negative_badges = set()
    in_universe_not_in_key = set()
    out_of_universe_badges = set()
    selected_edge_ids = None if selected_edge_ids is None else {str(edge_id) for edge_id in selected_edge_ids}
    for claim in claims:
        relation_type = claim.get("predicate_type")
        if relation_type not in PREDICATE_BADGES or relation_type in CUT_PREDICATES:
            continue
        edge_key = _claim_key(claim, relation_type)
        if edge_key is None:
            continue
        selected = selected_edge_ids is None or _edge_id(relation_type, claim) in selected_edge_ids
        if edge_key in true_key_to_id and selected:
            proposed.add(true_key_to_id[edge_key])
        if claim.get("badge") in PREDICATE_BADGES:
            badge_key = _claim_key(claim, claim["badge"])
            if badge_key in true_key_to_id:
                badged.add(true_key_to_id[badge_key])
                badge_selected = (
                    selected_edge_ids is None
                    or _edge_id(claim["badge"], claim) in selected_edge_ids
                )
                if selected and badge_selected:
                    verified_and_selected.add(true_key_to_id[badge_key])
            elif badge_key is not None and badge_key[:2] in negative_pairs:
                negative_badges.add(badge_key)
            elif badge_key is not None:
                # Absence from the key is NOT evidence of falsehood. The key
                # enumerates the attack narrative, not every true relation in the
                # log, so a badge between two key-mentioned events can still be a
                # perfectly real background spawn. An earlier version counted these
                # against precision and flagged two badges whose ProcessGuids match
                # exactly on the same host — correct badges, called wrong by the
                # metric. Only the key's explicit negative pairs can falsify a badge
                # here; the exhaustive test of precision is the fixture suite.
                if badge_key[0][0] in key_endpoints and badge_key[1][0] in key_endpoints:
                    in_universe_not_in_key.add(badge_key)
                else:
                    out_of_universe_badges.add(badge_key)

    denominator = len(observable)
    correct_badges = len(badged)
    false_badges = len(negative_badges)
    total_badges = correct_badges + false_badges
    precision = correct_badges / total_badges if total_badges else 0.0
    return {
        "dataset_mode": key_mode,
        "out_of_universe_badge_count": len(out_of_universe_badges),
        "in_universe_wrong_badge_count": len(in_universe_not_in_key),
        "confounder_badge_count": len(negative_badges),
        "observable_true_edge_count": denominator,
        "out_of_scope_for_build_count": len(out_of_scope),
        "selection_recall": len(proposed) / denominator if denominator else 0.0,
        # Kept for existing callers while naming the metric honestly in all new
        # reporting and code paths.
        "proposal_recall": len(proposed) / denominator if denominator else 0.0,
        "verification_precision": precision,
        "verification_precision_passed": total_badges > 0 and false_badges == 0,
        "verified_edge_recall": len(verified_and_selected) / denominator if denominator else 0.0,
        "enumerated_edge_count": enumerated_edge_count,
        "verified_edge_count": verified_edge_count,
        "verified_edges_shown": verified_edges_shown,
        "selected_true_edge_count": len(proposed),
        "verified_selected_true_edge_count": len(verified_and_selected),
        "proposed_true_edge_count": len(proposed),
        "correct_badged_edge_count": correct_badges,
        "false_badged_edge_count": false_badges,
        "badged_edge_count": total_badges,
    }


def score_run(
    connection,
    key_path: Path,
    incident_id,
    selected_edge_ids=None,
    enumerated_edge_count=0,
    verified_edge_count=0,
    verified_edges_shown=0,
):
    """Score all stored claims for one incident against a frozen YAML key."""
    with Path(key_path).open(encoding="utf-8") as source:
        key = yaml.safe_load(source)
    recorded_mode = run_mode(connection, incident_id)
    key_mode = mode_from_key(key_path, key)
    if recorded_mode != key_mode:
        raise ValueError(
            f"dataset mode mismatch: run is {recorded_mode!r}, key is {key_mode!r}"
        )
    cursor = connection.execute(
        """
        SELECT predicate_type, badge, source_event_id, target_event_id,
               source_hostname, target_hostname
        FROM claims WHERE incident_id = ?
        """,
        (incident_id,),
    )
    columns = [column[0] for column in cursor.description]
    claims = [dict(zip(columns, row)) for row in cursor]
    return score_claims(
        key_path,
        claims,
        selected_edge_ids=selected_edge_ids,
        enumerated_edge_count=enumerated_edge_count,
        verified_edge_count=verified_edge_count,
        verified_edges_shown=verified_edges_shown,
        dataset_mode=recorded_mode,
    )
