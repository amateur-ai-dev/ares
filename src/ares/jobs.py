"""Analysis jobs: an uploaded log, the run it produced, and what that run cost.

The CLI already runs an incident end to end. This module exists because the
dashboard needs three things the CLI never had to provide: somewhere durable to
put a file a stranger just handed us, a way to run the pipeline without blocking
the HTTP thread, and a per-run record of what actually happened - how many events
were parsed, how many survived scoping, how long it took.

The metrics are stored on the job rather than recomputed from the run, because
several of them (wall-clock duration, throughput, the arm and window the operator
chose) are properties of the *execution* and are simply not recoverable from the
claims table afterwards.

Uploaded files are treated as hostile. They are never executed, never named by
anything the uploader controls, and never parsed until they have been size-capped
and shown to be the format we claim to accept.
"""

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .pipeline import run_incident


# A Sysmon day is tens of megabytes; APT29 day 2 is ~590k events. The cap is set
# above any realistic single-machine day and well below anything that would fill
# a laptop disk from one POST. It is enforced while reading, not after, so an
# oversized body is abandoned rather than buffered.
MAX_UPLOAD_BYTES = 192 * 1024 * 1024

# A malformed line is normal in real telemetry, so the check is "does this look
# like the format at all", not "is every line valid". Reading a bounded prefix
# keeps a 190MB file from being fully parsed twice.
FORMAT_PROBE_LINES = 50

# A source archive is much smaller than a telemetry dump, and the extraction
# limits in `codereview` are tighter still. Refusing early keeps a 190MB "zip"
# from ever reaching the unpacker.
MAX_ARCHIVE_UPLOAD_BYTES = 32 * 1024 * 1024

JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_COMPLETE = "complete"
JOB_FAILED = "failed"


class UploadRejected(Exception):
    """The submitted file is not something ARES will accept."""


def sha256_of(payload):
    return hashlib.sha256(payload).hexdigest()


def looks_like_event_log(payload):
    """Return True if the prefix parses as the JSON-lines shape the pipeline reads.

    This is a format check, not a trust decision. Passing it means the parser
    will not immediately die; it says nothing about the contents, which stay
    untrusted through verification and rendering alike.
    """
    seen = 0
    for line in payload.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        if not isinstance(record, dict):
            return False
        seen += 1
        if seen >= FORMAT_PROBE_LINES:
            break
    return seen > 0


def store_upload(uploads_directory, filename, payload):
    """Write an uploaded log to disk under a name ARES chose, and return its path.

    The uploader's filename is recorded as a label and never reaches the
    filesystem: the stored name is a fresh UUID. That removes path traversal,
    absolute paths, control characters, reserved Windows device names and
    case-collision overwrites as a class, rather than filtering for them.
    """
    if not payload:
        raise UploadRejected("The uploaded file was empty.")
    if len(payload) > MAX_UPLOAD_BYTES:
        raise UploadRejected(
            f"File is larger than the {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit."
        )
    if not looks_like_event_log(payload):
        raise UploadRejected(
            "That does not read as a JSON-lines event log. ARES expects one JSON "
            "object per line, as exported by Sysmon/OTRF tooling."
        )
    directory = Path(uploads_directory)
    directory.mkdir(parents=True, exist_ok=True)
    stored = directory / f"{uuid.uuid4().hex}.jsonl"
    stored.write_bytes(payload)
    return stored


def store_review_upload(directory, payload):
    """Write an uploaded archive to disk, under a name ARES chose.

    The magic-number check is a fail-fast courtesy, not a security control - the
    real constraints on a hostile archive are in `codereview.safe_extract`, which
    assumes the contents are adversarial regardless of what the header claims.
    """
    if not payload:
        raise UploadRejected("The uploaded archive was empty.")
    if len(payload) > MAX_ARCHIVE_UPLOAD_BYTES:
        raise UploadRejected(
            f"Archive is larger than the {MAX_ARCHIVE_UPLOAD_BYTES // (1024 * 1024)}MB limit."
        )
    if not payload.startswith(b"PK"):
        raise UploadRejected("That is not a .zip archive.")
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    stored = target / f"{uuid.uuid4().hex}.zip"
    stored.write_bytes(payload)
    return stored


def execute_review_job(db_path, job_id, archive_path, workdir):
    """Extract and statically scan one uploaded archive.

    Runs on a worker thread for the same reason an incident does: a full scan of
    a source tree takes longer than a browser will wait, and holding the HTTP
    thread open for it would make the dashboard unresponsive.
    """
    from .codereview import findings_as_dicts, review_archive

    started = time.monotonic()
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "UPDATE jobs SET status = ?, started_at = CURRENT_TIMESTAMP WHERE job_id = ?",
            (JOB_RUNNING, job_id),
        )
        connection.commit()
        findings, skipped = review_archive(archive_path, workdir)
        severities = [finding.severity for finding in findings]
        _finish(connection, job_id, JOB_COMPLETE, started, metrics={
            "findings": findings_as_dicts(findings),
            "skipped": skipped,
            "finding_count": len(findings),
            "error_count": severities.count("ERROR"),
            "warning_count": severities.count("WARNING"),
        })
    except Exception as failure:  # noqa: BLE001 - a rejected archive is a result
        _finish(connection, job_id, JOB_FAILED, started,
                error=f"{type(failure).__name__}: {failure}"[:600])
    finally:
        connection.close()


def start_review_job(db_path, job_id, archive_path, workdir):
    thread = threading.Thread(
        target=execute_review_job,
        args=(db_path, job_id, archive_path, workdir),
        daemon=True,
    )
    thread.start()
    return thread


def safe_label(filename):
    """Keep a display-only version of the uploader's filename.

    Rendering is already escaped, so this is not an injection defence - it stops
    a 4KB filename or an embedded newline from wrecking the layout.
    """
    cleaned = "".join(
        character for character in (filename or "") if character.isprintable()
    ).strip()
    return cleaned[:120] or "uploaded log"


def create_job(connection, *, label, source_name, source_sha256, source_bytes,
               arm, model, top_n, batch_size, dataset_mode, kind="incident"):
    job_id = uuid.uuid4().hex
    connection.execute(
        """
        INSERT INTO jobs (
            job_id, kind, label, source_name, source_sha256, source_bytes,
            arm, model, top_n, batch_size, dataset_mode, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (job_id, kind, label, source_name, source_sha256, source_bytes,
         arm, model, top_n, batch_size, dataset_mode, JOB_QUEUED),
    )
    connection.commit()
    return job_id


def _finish(connection, job_id, status, started, *, run_id=None, metrics=None, error=None):
    connection.execute(
        """
        UPDATE jobs SET status = ?, run_id = ?, metrics_json = ?, error = ?,
                        finished_at = CURRENT_TIMESTAMP, duration_ms = ?
        WHERE job_id = ?
        """,
        (status, run_id, json.dumps(metrics) if metrics else None, error,
         int((time.monotonic() - started) * 1000), job_id),
    )
    connection.commit()


def execute_job(db_path, job_id, log_path, incident_id):
    """Run one job to completion against its own connection.

    Runs on a worker thread, so it opens its own SQLite connection: connections
    are not shareable across threads, and the HTTP handler must not be holding
    one open for the minutes a selection call can take.
    """
    started = time.monotonic()
    connection = sqlite3.connect(db_path)
    try:
        job = connection.execute(
            "SELECT arm, model, top_n, batch_size, dataset_mode FROM jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if job is None:
            return
        arm, model, top_n, batch_size, dataset_mode = job
        connection.execute(
            "UPDATE jobs SET status = ?, started_at = CURRENT_TIMESTAMP WHERE job_id = ?",
            (JOB_RUNNING, job_id),
        )
        connection.commit()
        counts = run_incident(
            connection,
            incident_id=incident_id,
            log_path=log_path,
            arm=arm,
            model=model,
            top_n=top_n,
            batch_size=batch_size,
            dataset_mode=dataset_mode,
        )
        metrics = {
            "events_parsed": counts.events_parsed,
            "events_in_scope": counts.events_in_scope,
            "edges_enumerated": counts.edges_enumerated,
            "edges_verified": counts.edges_verified,
            "verified_edges_shown": counts.verified_edges_shown,
            "selections_made": counts.selections_made,
            "refuted": counts.refuted,
            "aporias": counts.aporias,
            "discarded_as_malformed": counts.discarded_as_malformed,
        }
        _finish(connection, job_id, JOB_COMPLETE, started,
                run_id=counts.run_id, metrics=metrics)
    except Exception as failure:  # noqa: BLE001 - a failed job is a result, not a crash
        # The message is rendered back to the operator, and it can quote a
        # malformed record from an untrusted file. It is escaped at render time
        # like every other untrusted value; truncation here is about the layout.
        _finish(connection, job_id, JOB_FAILED, started,
                error=f"{type(failure).__name__}: {failure}"[:600])
    finally:
        connection.close()


def start_job(db_path, job_id, log_path, incident_id):
    """Hand the job to a daemon thread so the HTTP response can return now."""
    thread = threading.Thread(
        target=execute_job,
        args=(db_path, job_id, log_path, incident_id),
        daemon=True,
    )
    thread.start()
    return thread


JOB_FIELDS = (
    "job_id", "kind", "label", "source_name", "source_sha256", "source_bytes",
    "arm", "model", "top_n", "batch_size", "dataset_mode", "status", "error",
    "run_id", "metrics_json", "created_at", "started_at", "finished_at", "duration_ms",
)


METRIC_DEFAULTS = {
    "events_parsed": 0, "events_in_scope": 0, "edges_enumerated": 0,
    "edges_verified": 0, "verified_edges_shown": 0, "selections_made": 0,
    "refuted": 0, "aporias": 0, "discarded_as_malformed": 0,
    "findings": [], "skipped": [], "finding_count": 0,
    "error_count": 0, "warning_count": 0,
}


def _as_job(row):
    job = dict(zip(JOB_FIELDS, row))
    # Templates render with StrictUndefined, so a queued job with no metrics yet
    # would raise rather than show zeros. Defaults are filled here, once, instead
    # of every template guarding every field.
    job["metrics"] = {**METRIC_DEFAULTS, **json.loads(job.pop("metrics_json") or "{}")}
    job["duration_seconds"] = (job["duration_ms"] or 0) / 1000
    parsed = job["metrics"].get("events_parsed") or 0
    seconds = job["duration_seconds"]
    job["events_per_second"] = int(parsed / seconds) if seconds > 0 and parsed else 0
    job["source_kb"] = round(job["source_bytes"] / 1024)
    return job


def list_jobs(connection, limit=50):
    rows = connection.execute(
        f"SELECT {', '.join(JOB_FIELDS)} FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_as_job(row) for row in rows]


def get_job(connection, job_id):
    row = connection.execute(
        f"SELECT {', '.join(JOB_FIELDS)} FROM jobs WHERE job_id = ?", (job_id,)
    ).fetchone()
    return _as_job(row) if row else None
