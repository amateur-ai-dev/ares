"""SQLite storage for Phase 1 claims and deterministic verification evidence."""

import json


PREDICATE_BADGES = (
    "SPAWNED",
    "SAME_SESSION",
    "WROTE_PATH_BEFORE_EXECUTION",
    "PROCESS_OPENED_CONNECTION",
)


def initialize(connection):
    connection.execute("PRAGMA foreign_keys = ON")
    predicate_badges = ", ".join(repr(badge) for badge in PREDICATE_BADGES)
    connection.executescript(f"""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            dataset_mode TEXT NOT NULL CHECK (dataset_mode IN ('demo', 'eval')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY,
            incident_id TEXT NOT NULL,
            claim_type TEXT NOT NULL DEFAULT 'relational_predicate',
            predicate_type TEXT,
            source_event_id TEXT NOT NULL,
            target_event_id TEXT NOT NULL,
            source_hostname TEXT NOT NULL,
            target_hostname TEXT NOT NULL,
            claim_text TEXT NOT NULL,
            badge TEXT NOT NULL DEFAULT 'unverifiable',
            verifier_execution_id INTEGER REFERENCES verifier_executions(id),
            CHECK (badge IN ('unverifiable', 'refuted', {predicate_badges})),
            CHECK (
                badge NOT IN ({predicate_badges})
                OR (claim_type = 'relational_predicate' AND predicate_type = badge)
            )
        );

        CREATE TABLE IF NOT EXISTS verifier_executions (
            id INTEGER PRIMARY KEY,
            incident_id TEXT NOT NULL,
            predicate_id TEXT NOT NULL,
            predicate_version TEXT NOT NULL CHECK (trim(predicate_version) <> ''),
            input_event_ids TEXT NOT NULL CHECK (
                json_valid(input_event_ids)
                AND json_type(input_event_ids) = 'array'
                AND json_array_length(input_event_ids) = 2
            ),
            evaluated_fields TEXT NOT NULL CHECK (json_valid(evaluated_fields)),
            result INTEGER CHECK (result IN (0, 1) OR result IS NULL),
            log_provenance TEXT NOT NULL CHECK (
                json_valid(log_provenance)
                AND json_type(log_provenance) = 'array'
                AND json_array_length(log_provenance) > 0
            ),
            run_id TEXT NOT NULL,
            executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS causal_gaps (
            id INTEGER PRIMARY KEY,
            incident_id TEXT NOT NULL,
            claim_id INTEGER NOT NULL REFERENCES claims(id),
            claim_text TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            target_event_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            verification_failure_code TEXT NOT NULL,
            verification_failure_detail TEXT NOT NULL,
            verifier_execution_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS model_selections (
            id INTEGER PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            edge_id TEXT NOT NULL,
            rationale TEXT NOT NULL,
            attack_technique_id TEXT,
            UNIQUE (run_id, edge_id)
        );

        CREATE TABLE IF NOT EXISTS run_metrics (
            run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
            events_parsed INTEGER NOT NULL,
            events_in_scope INTEGER NOT NULL,
            edges_enumerated INTEGER NOT NULL,
            edges_verified INTEGER NOT NULL,
            verified_edges_shown INTEGER NOT NULL,
            selections_made INTEGER NOT NULL,
            refuted INTEGER NOT NULL,
            aporias INTEGER NOT NULL,
            discarded_as_malformed INTEGER NOT NULL
        );

        -- What a verified edge was ABOUT, kept for display only. Deliberately a
        -- separate table from claims: claims are badge-bearing evidence behind an
        -- immutability trigger, and nothing that exists to draw a picture belongs
        -- on that path. Nothing here can widen or contradict a badge.
        CREATE TABLE IF NOT EXISTS edge_facts (
            id INTEGER PRIMARY KEY,
            -- No foreign key on run_id, matching verifier_executions. Making a
            -- display table stricter than the evidence table it illustrates
            -- would mean verification could succeed while drawing its picture
            -- failed, which is the wrong way round.
            run_id TEXT NOT NULL,
            edge_id TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            occurred_at TEXT,
            source_label TEXT NOT NULL,
            target_label TEXT NOT NULL,
            UNIQUE (run_id, edge_id)
        );

        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            source_name TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            source_bytes INTEGER NOT NULL,
            arm TEXT NOT NULL,
            model TEXT,
            top_n INTEGER NOT NULL,
            batch_size INTEGER,
            dataset_mode TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            run_id TEXT,
            metrics_json TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            finished_at TEXT,
            duration_ms INTEGER
        );

        CREATE TRIGGER IF NOT EXISTS verifier_executions_immutable_update
        BEFORE UPDATE ON verifier_executions
        BEGIN
            SELECT RAISE(ABORT, 'verifier_executions are immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS verifier_executions_immutable_delete
        BEFORE DELETE ON verifier_executions
        BEGIN
            SELECT RAISE(ABORT, 'verifier_executions are immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS claims_badge_firewall_insert
        BEFORE INSERT ON claims
        WHEN NEW.badge IN ({predicate_badges})
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM verifier_executions AS execution
                WHERE execution.id = NEW.verifier_execution_id
                  AND execution.incident_id = NEW.incident_id
                  AND execution.predicate_id = NEW.predicate_type
                  AND execution.predicate_version <> ''
                  AND execution.result = 1
                  AND json_extract(execution.input_event_ids, '$[0]') = NEW.source_event_id
                  AND json_extract(execution.input_event_ids, '$[1]') = NEW.target_event_id
                  AND json_array_length(execution.input_event_ids) = 2
                  AND json_array_length(execution.log_provenance) > 0
            ) THEN RAISE(ABORT, 'badge firewall: no matching verifier execution') END;
        END;

        -- The firewall above only guards the badge-bearing columns. Without this,
        -- a legitimately badged claim can be rewritten afterwards -- including its
        -- hostnames, which every predicate join in 2.1 is host-scoped on -- while
        -- keeping a stamp earned by a different assertion. Verification is a
        -- statement about specific bytes, so once a claim carries a badge its
        -- meaning is frozen, exactly as verifier_executions are.
        CREATE TRIGGER IF NOT EXISTS claims_badged_are_immutable
        BEFORE UPDATE OF claim_text, source_hostname, target_hostname, claim_type
                       ON claims
        WHEN OLD.badge IN ({predicate_badges})
        BEGIN
            SELECT RAISE(ABORT, 'badge firewall: a badged claim is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS claims_badge_firewall_update
        BEFORE UPDATE OF badge, verifier_execution_id, predicate_type, source_event_id,
                         target_event_id, incident_id ON claims
        WHEN NEW.badge IN ({predicate_badges})
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM verifier_executions AS execution
                WHERE execution.id = NEW.verifier_execution_id
                  AND execution.incident_id = NEW.incident_id
                  AND execution.predicate_id = NEW.predicate_type
                  AND execution.predicate_version <> ''
                  AND execution.result = 1
                  AND json_extract(execution.input_event_ids, '$[0]') = NEW.source_event_id
                  AND json_extract(execution.input_event_ids, '$[1]') = NEW.target_event_id
                  AND json_array_length(execution.input_event_ids) = 2
                  AND json_array_length(execution.log_provenance) > 0
            ) THEN RAISE(ABORT, 'badge firewall: no matching verifier execution') END;
        END;
    """)


def record_run(connection, run_id, incident_id, dataset_mode):
    """Persist the identity that every later metric must carry."""
    connection.execute(
        "INSERT INTO runs (run_id, incident_id, dataset_mode) VALUES (?, ?, ?)",
        (run_id, incident_id, dataset_mode),
    )


def record_model_selection(connection, run_id, edge_id, rationale, attack_technique_id):
    """Persist the model's interpretation separately from verified evidence."""
    connection.execute(
        """
        INSERT OR REPLACE INTO model_selections (
            run_id, edge_id, rationale, attack_technique_id
        ) VALUES (?, ?, ?, ?)
        """,
        (run_id, edge_id, rationale, attack_technique_id),
    )


def run_mode(connection, incident_id):
    row = connection.execute(
        "SELECT dataset_mode FROM runs WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
        (incident_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"no recorded run for incident {incident_id!r}")
    return row[0]


def create_claim(
    connection,
    incident_id,
    predicate_type,
    source_event_id,
    target_event_id,
    source_hostname,
    target_hostname,
    claim_text,
):
    cursor = connection.execute(
        """
        INSERT INTO claims (
            incident_id, predicate_type, source_event_id, target_event_id,
            source_hostname, target_hostname, claim_text
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            predicate_type,
            str(source_event_id),
            str(target_event_id),
            source_hostname,
            target_hostname,
            claim_text,
        ),
    )
    return cursor.lastrowid


def record_verifier_execution(connection, incident_id, predicate_result, run_id):
    cursor = connection.execute(
        """
        INSERT INTO verifier_executions (
            incident_id, predicate_id, predicate_version, input_event_ids,
            evaluated_fields, result, log_provenance, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            predicate_result.predicate_id,
            predicate_result.predicate_version,
            json.dumps(list(predicate_result.input_event_ids)),
            json.dumps(predicate_result.evaluated_fields, sort_keys=True),
            None if predicate_result.result is None else int(predicate_result.result),
            json.dumps(list(predicate_result.log_provenance)),
            run_id,
        ),
    )
    return cursor.lastrowid


def assign_verified_badge(connection, claim_id, verifier_execution_id):
    """The sanctioned application path for assigning a predicate badge."""
    cursor = connection.execute(
        """
        UPDATE claims
        SET badge = predicate_type, verifier_execution_id = ?
        WHERE id = ?
        """,
        (verifier_execution_id, claim_id),
    )
    if cursor.rowcount != 1:
        raise ValueError(f"claim {claim_id} does not exist")


def persist_predicate_result(connection, claim_id, predicate_result, run_id):
    claim = connection.execute(
        """
        SELECT incident_id, predicate_type, source_event_id, target_event_id, claim_text
        FROM claims WHERE id = ?
        """,
        (claim_id,),
    ).fetchone()
    if claim is None:
        raise ValueError(f"claim {claim_id} does not exist")
    incident_id, predicate_type, source_event_id, target_event_id, claim_text = claim
    if predicate_type != predicate_result.predicate_id:
        raise ValueError("predicate result does not match the claim predicate")
    if tuple(predicate_result.input_event_ids) != (source_event_id, target_event_id):
        raise ValueError("predicate result does not match the claim event pair")

    execution_id = record_verifier_execution(connection, incident_id, predicate_result, run_id)
    if predicate_result.outcome == "true":
        assign_verified_badge(connection, claim_id, execution_id)
    elif predicate_result.outcome == "false":
        connection.execute("UPDATE claims SET badge = 'refuted' WHERE id = ?", (claim_id,))
    else:
        connection.execute("UPDATE claims SET badge = 'unverifiable' WHERE id = ?", (claim_id,))
        connection.execute(
            """
            INSERT INTO causal_gaps (
                incident_id, claim_id, claim_text, relation_type, source_event_id,
                target_event_id, verification_failure_code,
                verification_failure_detail, verifier_execution_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                claim_id,
                claim_text,
                predicate_result.predicate_id,
                source_event_id,
                target_event_id,
                predicate_result.failure_code,
                predicate_result.failure_detail,
                json.dumps({"verifier_execution_id": execution_id}),
            ),
        )
    return execution_id


def record_run_metrics(connection, run_id, counts):
    """Persist the funnel numbers on the run itself.

    They already exist on a dashboard job, but a run started from the CLI has no
    job - and the run detail page should not render a different, poorer view
    depending on which door the run came through.
    """
    connection.execute(
        """
        INSERT OR REPLACE INTO run_metrics (
            run_id, events_parsed, events_in_scope, edges_enumerated,
            edges_verified, verified_edges_shown, selections_made,
            refuted, aporias, discarded_as_malformed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, counts.events_parsed, counts.events_in_scope,
         counts.edges_enumerated, counts.edges_verified,
         counts.verified_edges_shown, counts.selections_made,
         counts.refuted, counts.aporias, counts.discarded_as_malformed),
    )


def record_edge_fact(connection, run_id, edge_id, relation_type,
                     occurred_at, source_label, target_label):
    """Record what a verified edge was about, for display only."""
    connection.execute(
        """
        INSERT OR IGNORE INTO edge_facts (
            run_id, edge_id, relation_type, occurred_at, source_label, target_label
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (run_id, edge_id, relation_type, occurred_at, source_label, target_label),
    )


def run_metrics(connection, run_id):
    columns = ("events_parsed", "events_in_scope", "edges_enumerated",
               "edges_verified", "verified_edges_shown", "selections_made",
               "refuted", "aporias", "discarded_as_malformed")
    row = connection.execute(
        f"SELECT {', '.join(columns)} FROM run_metrics WHERE run_id = ?", (run_id,)
    ).fetchone()
    return dict(zip(columns, row)) if row else None


def edge_facts(connection, run_id):
    """Verified edges in the order they happened, unknown timestamps last."""
    rows = connection.execute(
        """
        SELECT edge_id, relation_type, occurred_at, source_label, target_label
        FROM edge_facts WHERE run_id = ?
        ORDER BY occurred_at IS NULL, occurred_at, id
        """,
        (run_id,),
    ).fetchall()
    columns = ("edge_id", "relation_type", "occurred_at", "source_label", "target_label")
    return [dict(zip(columns, row)) for row in rows]
