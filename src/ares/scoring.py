"""Score Phase 1 claims against a frozen edge-level ground-truth key."""

from pathlib import Path

import yaml

from .store import PREDICATE_BADGES


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


def score_claims(key_path: Path, claims):
    """Return deterministic metrics for iterable claim mappings or sqlite Rows."""
    with Path(key_path).open(encoding="utf-8") as source:
        key = yaml.safe_load(source)

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

    proposed = set()
    badged = set()
    negative_badges = set()
    for claim in claims:
        relation_type = claim.get("predicate_type")
        if relation_type not in PREDICATE_BADGES or relation_type in CUT_PREDICATES:
            continue
        edge_key = _claim_key(claim, relation_type)
        if edge_key is None:
            continue
        if edge_key in true_key_to_id:
            proposed.add(true_key_to_id[edge_key])
        if claim.get("badge") in PREDICATE_BADGES:
            badge_key = _claim_key(claim, claim["badge"])
            if badge_key in true_key_to_id:
                badged.add(true_key_to_id[badge_key])
            elif badge_key is not None and badge_key[:2] in negative_pairs:
                negative_badges.add(badge_key)

    denominator = len(observable)
    correct_badges = len(badged)
    false_badges = len(negative_badges)
    total_badges = correct_badges + false_badges
    precision = correct_badges / total_badges if total_badges else 0.0
    return {
        "observable_true_edge_count": denominator,
        "out_of_scope_for_build_count": len(out_of_scope),
        "proposal_recall": len(proposed) / denominator if denominator else 0.0,
        "verification_precision": precision,
        "verification_precision_passed": total_badges > 0 and false_badges == 0,
        "verified_edge_recall": correct_badges / denominator if denominator else 0.0,
        "proposed_true_edge_count": len(proposed),
        "correct_badged_edge_count": correct_badges,
        "false_badged_edge_count": false_badges,
        "badged_edge_count": total_badges,
    }


def score_run(connection, key_path: Path, incident_id):
    """Score all stored claims for one incident against a frozen YAML key."""
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
    return score_claims(key_path, claims)
