"""Loopback dashboard: browse finished runs, and start new ones.

This used to be strictly read-only, which made its security story short - there
was no way to reach the database through it except SELECT. Adding "upload a log"
and "run analysis" ends that, so the guards are stated here rather than left
implied:

* **Loopback binding is not access control.** Any page in the operator's browser
  can POST to 127.0.0.1. Binding to localhost stops the *network* reaching the
  server, not other *origins* in the same browser. Both state-changing routes
  therefore check the Origin/Referer header AND a per-process CSRF token that a
  cross-origin page cannot read.
* **The uploader names nothing on disk.** Stored files get a UUID; the submitted
  filename is a display label only (`jobs.store_upload`).
* **Uploads are size-capped while being read**, so an oversized body is abandoned
  rather than buffered into memory first.
* **Nothing uploaded is ever executed** - logs are parsed, archives are scanned.
  See `codereview` for the extraction and subprocess constraints.

The Content-Security-Policy is relaxed by exactly one directive relative to the
exported reports (`form-action 'self'`, so the page can submit to itself).
Script remains forbidden outright, which is why the running-job view refreshes
with a meta tag instead of polling in JavaScript.
"""

import hmac
import re
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .codereview import ArchiveRejected
from .dashboard_style import STYLE
from .local_models import local_status
from .jobs import (
    MAX_UPLOAD_BYTES,
    UploadRejected,
    create_job,
    get_job,
    list_jobs,
    safe_label,
    sha256_of,
    start_job,
    start_review_job,
    store_review_upload,
    store_upload,
)
from .rendering import DASHBOARD_CONTENT_SECURITY_POLICY, build_environment
from .report import build_report, render_html, render_markdown


def _page(title, body, refresh=False):
    """Assemble one dashboard page. Plain Python concatenation, not a template.

    The stylesheet is trusted content that must reach the browser as markup, and
    `|safe` is disabled in the template environment on purpose. Joining the
    trusted shell here and letting Jinja render only the untrusted body keeps
    that restriction intact instead of carving an exception into it.
    """
    meta_refresh = '<meta http-equiv="refresh" content="4">' if refresh else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "{{ DASHBOARD_CSP_META_TAG }}" + meta_refresh +
        f"<title>{title}</title><style>{STYLE}</style></head>" + body + "</html>"
    )


_BAR = (
    '<body><div class="bar"><div class="in">'
    '<a class="brand" href="/" style="color:var(--fg)">A<em>R</em>ES</a>'
    '<span class="tagline">Local incident analysis &middot; nothing leaves this machine</span>'
    '<span class="dot"><i></i>LOCALHOST</span></div></div><main>'
)

_FOOT = (
    '<p class="foot">The model decides what is interesting. It never decides what is '
    "true &mdash; selections are stored apart from proven facts and can never carry a "
    "badge.</p></main></body>"
)

_ERROR = '{% if error %}<div class="err">{{ error }}</div>{% endif %}'

# Sentinel, compared by identity: a CSRF failure is answered with bare text, not
# with the form page, because the form page carries the token.
_CSRF_REFUSED = "This form was not issued by this server. Reload the dashboard and retry."

# Two forms, both multipart, both carrying the CSRF token. There is no JavaScript
# anywhere on this page: the CSP forbids script entirely, so every interaction is
# a plain form POST and a redirect.
_ACTIONS = """<p class="lab">START WORK</p><div class="act">
<div class="panel"><div class="ph"><h2>Analyse a log</h2><span class="note">Sysmon JSON lines</span></div>
<div class="pb"><form class="card" method="post" action="/analyze" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{{ csrf }}">
<div><label for="logfile">UPLOAD LOG FILE</label>
<input id="logfile" type="file" name="logfile" accept=".json,.jsonl,.log,.txt" required></div>
<div class="two">
<div><label for="arm">SELECTOR ARM</label><select id="arm" name="arm">
<option value="local">local &mdash; on this machine</option>
<option value="frontier">frontier &mdash; test arm, leaves the machine</option>
</select></div>
<div><label for="mode">DATASET MODE</label><select id="mode" name="mode">
<option value="demo">demo &mdash; no scoring</option><option value="eval">eval</option>
</select></div></div>
<div><label for="model">LOCAL MODEL{% if not local.reachable %} &mdash; UNAVAILABLE{% endif %}</label>
<select id="model" name="model"{% if not local.reachable %} disabled{% endif %}>
{% for name in local.models %}<option value="{{ name }}">{{ name }}{% if name == local.preferred %} &nbsp;&middot; measured in the paper{% endif %}</option>
{% else %}<option value="">no local model available</option>{% endfor %}
</select>
{% if local.reachable %}<p class="hint">Applies to the local arm only. The frontier arm ignores it.
{% if not local.preferred_present %}<br><b>{{ local.preferred }}</b> is not pulled &mdash; the published
local result was measured with it. <code>ollama pull {{ local.preferred }}</code>{% endif %}</p>
{% else %}<p class="hint">{{ local.error }}<br>Start it with <code>ollama serve</code>, then reload this page.
The frontier arm still works.</p>{% endif %}</div>
<div class="two">
<div><label for="top_n">EDGES SHOWN</label>
<input id="top_n" type="number" name="top_n" value="300" min="1" max="20000"></div>
<div><label for="batch_size">BATCH SIZE</label>
<input id="batch_size" type="number" name="batch_size" placeholder="one call" min="1" max="5000"></div></div>
<button type="submit">RUN ANALYSIS</button>
<p class="hint">Stays on this machine. Max {{ max_mb }}MB. The file is parsed, never executed.</p>
</form></div></div>
<div class="panel"><div class="ph"><h2>Review code</h2><span class="note">static scan only</span></div>
<div class="pb"><form class="card" method="post" action="/review" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{{ csrf }}">
<div><label for="archive">UPLOAD SOURCE ARCHIVE</label>
<input id="archive" type="file" name="archive" accept=".zip" required></div>
<button class="ghost" type="submit">RUN CODE REVIEW</button>
<p class="hint">Semgrep, gitleaks and osv-scanner read the files. Nothing in the archive is
installed, built, imported or run &mdash; and archives that try to write outside the
extraction directory are rejected whole.</p>
</form></div></div></div>"""

_JOBS = """<p class="lab">JOBS</p><div class="panel"><ul class="runs">
{% for job in jobs %}<li><a class="row" href="/job/{{ job.job_id|url }}">
<span class="st {{ job.status }}">{{ job.status|upper }}</span>
<span><b>{{ job.label }}</b><div class="id">{{ job.kind }} &middot; {{ job.source_kb }} KB &middot;
{% if job.duration_ms %}{{ "%.1f"|format(job.duration_seconds) }}s{% else %}&mdash;{% endif %}
&middot; {{ job.created_at }}</div></span>
<span class="arrow">&rarr;</span></a></li>
{% else %}<li style="padding:1.1rem" class="empty">No jobs yet. Upload a log above.</li>{% endfor %}
</ul></div>"""

_INDEX = _page("ARES", _BAR + _ERROR + _ACTIONS + _JOBS + """<p class="lab">WHAT THE BADGES MEAN</p><div class="panel"><div class="thesis"><div class="th"><span class="k v"><i></i>VERIFIED</span><p>Deterministic code checked it. No model involved. Same answer every time.</p></div><div class="th"><span class="k r"><i></i>REFUTED</span><p>Checked, and the evidence contradicts it.</p></div><div class="th"><span class="k a"><i></i>APORIA</span><p>Cannot be determined from this evidence. The tool says so instead of guessing.</p></div></div></div><p class="lab">RUNS</p><div class="panel"><ul class="runs">{% for run in runs %}<li><a class="row" href="/run/{{ run.run_id|url }}"><span class="chip {{ run.dataset_mode }}">{{ run.dataset_mode|upper }}</span><span><b>{{ run.incident_id }}</b><div class="id">{{ run.run_id }}</div></span><span class="arrow">&rarr;</span></a></li>{% else %}<li style="padding:1.1rem" class="empty">No runs yet.</li>{% endfor %}</ul></div><p class="lab">REPORTS</p><div class="panel"><div class="pb"><div class="dl-grid">{% for run in runs %}<a class="dl" href="/run/{{ run.run_id|url }}/report.md"><span class="ext">MD</span><span><b>{{ run.incident_id }}</b><span>markdown &middot; {{ run.dataset_mode }}</span></span></a><a class="dl" href="/run/{{ run.run_id|url }}/report.html"><span class="ext">HTML</span><span><b>{{ run.incident_id }}</b><span>html &middot; {{ run.dataset_mode }}</span></span></a>{% else %}<p class="empty">No reports yet.</p>{% endfor %}</div></div></div>""" + _FOOT)


_METRIC_ROWS = """<div class="panel"><div class="ph"><h2>Run metrics</h2>
<span class="note">measured for this job, not estimated</span></div><div class="mgrid">
<div class="m"><span class="v">{{ job.metrics.events_parsed or 0 }}</span><span class="k">EVENTS PARSED</span></div>
<div class="m"><span class="v">{{ job.metrics.events_in_scope or 0 }}</span><span class="k">IN SCOPE (EID 1,3)</span></div>
<div class="m"><span class="v">{{ job.metrics.edges_enumerated or 0 }}</span><span class="k">EDGES ENUMERATED</span></div>
<div class="m"><span class="v">{{ job.metrics.edges_verified or 0 }}</span><span class="k">VERIFIED</span></div>
<div class="m"><span class="v">{{ job.metrics.refuted or 0 }}</span><span class="k">REFUTED</span></div>
<div class="m"><span class="v">{{ job.metrics.aporias or 0 }}</span><span class="k">APORIA</span></div>
<div class="m"><span class="v">{{ job.metrics.verified_edges_shown or 0 }}</span><span class="k">SHOWN TO MODEL</span></div>
<div class="m"><span class="v">{{ job.metrics.selections_made or 0 }}</span><span class="k">SELECTED</span></div>
<div class="m"><span class="v">{{ job.metrics.discarded_as_malformed or 0 }}</span><span class="k">DISCARDED MALFORMED</span></div>
<div class="m"><span class="v">{{ "%.1f"|format(job.duration_seconds) }}s</span><span class="k">WALL CLOCK</span></div>
<div class="m"><span class="v">{{ job.events_per_second }}</span><span class="k">EVENTS / SEC</span></div>
<div class="m"><span class="v">{{ job.top_n }}</span><span class="k">WINDOW (TOP-N)</span></div>
</div></div>"""

_JOB_BODY = (_BAR + """
<h1>{{ job.label }}</h1><p class="sub">{{ job.kind }} &middot; {{ job.job_id }}</p>
<div class="panel"><div class="ph"><h2>Provenance</h2>
<span class="note">what was submitted, and how it was run</span></div><ul class="rows">
<li><span>Submitted filename<div class="meta">{{ job.source_name }}</div></span></li>
<li><span>SHA-256 of the uploaded bytes<div class="meta">{{ job.source_sha256 }}</div></span></li>
<li><span>Size<div class="meta">{{ job.source_kb }} KB</div></span></li>
<li><span>Selector arm<div class="meta">{{ job.arm }}{% if job.model %} &middot; {{ job.model }}{% endif %}</div></span></li>
<li><span>Dataset mode<div class="meta">{{ job.dataset_mode }}</div></span></li>
<li><span>Batch size<div class="meta">{% if job.batch_size %}{{ job.batch_size }}{% else %}single call{% endif %}</div></span></li>
<li><span>Status<div class="meta">{{ job.status }}{% if job.finished_at %} &middot; finished {{ job.finished_at }}{% endif %}</div></span></li>
</ul></div>
{% if job.status == 'running' or job.status == 'queued' %}
<div class="mode demo"><div><b>WORKING</b>This page refreshes itself every 4 seconds. Selection can take
minutes on a local model &mdash; the run continues even if you close this tab.</div></div>
{% endif %}
{% if job.error %}<div class="err"><b>Job failed.</b><br>{{ job.error }}</div>{% endif %}
{% if job.status == 'complete' and job.kind == 'incident' %}""" + _METRIC_ROWS + """
<div class="panel"><div class="pb"><div class="dl-grid">
<a class="dl" href="/run/{{ job.run_id|url }}"><span class="ext">&rarr;</span><span><b>Open the findings</b><span>badges, aporias, selections</span></span></a>
<a class="dl" href="/run/{{ job.run_id|url }}/report.md"><span class="ext">MD</span><span><b>Markdown report</b><span>diffable</span></span></a>
<a class="dl" href="/run/{{ job.run_id|url }}/report.html"><span class="ext">HTML</span><span><b>HTML report</b><span>self-contained</span></span></a>
</div></div></div>{% endif %}
{% if job.kind == 'review' and job.status == 'complete' %}
<div class="panel"><div class="ph"><h2>Static findings</h2>
<span class="note">read and scanned &middot; never executed</span></div>
<ul class="fnd">{% for finding in job.metrics.findings %}
<li><span class="sev {{ finding.severity }}">{{ finding.severity }}</span>
<span><span class="cwe">{{ finding.cwe }}</span>{{ finding.message }}
<div class="meta">{{ finding.path }}:{{ finding.line }} &middot; {{ finding.tool }} &middot; {{ finding.rule_id }}</div></span></li>
{% else %}<li class="empty">No findings from the scanners that ran.</li>{% endfor %}</ul></div>
{% if job.metrics.skipped %}<div class="panel aporia"><div class="ph"><h2>Scanners that did not run</h2>
<span class="note">a clean result would be misleading without this</span></div>
<ul class="rows">{% for note in job.metrics.skipped %}<li><span>{{ note }}</span></li>{% endfor %}</ul></div>{% endif %}
{% endif %}""" + _FOOT)
_JOB = _page("ARES job", _JOB_BODY)
# A finished job must stop reloading itself; a running one has nothing else to
# report progress with, because the CSP forbids the script a poller would need.
_JOB_RUNNING = _page("ARES job", _JOB_BODY, refresh=True)


_DETAIL = _page("ARES run", '<body><div class="bar"><div class="in"><span class="brand">A<em>R</em>ES</span><span class="tagline">Local incident analysis &middot; nothing leaves this machine</span><span class="dot"><i></i>LOCALHOST</span></div></div><main><p class="lab">DOWNLOADS</p><div class="panel"><div class="pb"><div class="dl-grid"><a class="dl" href="/run/{{ report.run_id|url }}/report.md"><span class="ext">MD</span><span><b>Markdown report</b><span>plain text &middot; diffable</span></span></a><a class="dl" href="/run/{{ report.run_id|url }}/report.html"><span class="ext">HTML</span><span><b>HTML report</b><span>self-contained &middot; offline</span></span></a><a class="dl" href="/"><span class="ext">&larr;</span><span><b>All runs</b><span>back to index</span></span></a></div></div></div><div class="mode {{ report.dataset_mode }}"><div><b>{{ report.dataset_mode }} DATASET</b>{% if report.demo_notice %}{{ report.demo_notice }}{% else %}Accuracy is measured against the frozen answer key for this corpus.{% endif %}</div></div><h1>{{ report.incident_id }}</h1><p class="sub">{{ report.run_id }}</p><div class="panel"><div class="stats"><div class="stat v1"><span class="v">{{ report.verified_edges|length }}</span><span class="k">VERIFIED</span></div><div class="stat v2"><span class="v">{{ report.selections|length }}</span><span class="k">SELECTED BY MODEL</span></div><div class="stat v3"><span class="v">{{ report.aporias|length }}</span><span class="k">APORIA</span></div></div></div>{% if report.precision_line %}<div class="panel"><div class="ph"><h2>Scored</h2></div><div class="prec"><p class="p1">{{ report.precision_line }}</p><p class="p2">{{ report.coverage_line }}</p></div></div>{% endif %}<div class="panel aporia"><div class="ph"><h2>Aporia &mdash; cannot be proven</h2><span class="note">shown, never hidden</span></div><p class="lead" style="padding-top:1rem">The evidence does not support a conclusion here. The tool refuses to guess.</p><ul class="rows">{% for item in report.aporias %}<li><span>{{ item.claim_text }}<div class="meta">{{ item.failure_code }}{% if item.failure_detail %} &middot; {{ item.failure_detail }}{% endif %}</div></span></li>{% else %}<li class="empty">None in this run.</li>{% endfor %}</ul></div><div class="panel"><div class="ph"><h2>Model selections</h2><span class="note">interpretation &middot; never badged</span></div><ul class="rows">{% for item in report.selections %}<li><span class="tag s">PICK</span><span>{{ item.rationale }}<div class="meta">{{ item.edge_id }} &middot; ATT&amp;CK {{ item.attack_technique_id or "not supplied" }}</div></span></li>{% else %}<li class="empty">The model selected nothing in this run.</li>{% endfor %}</ul></div><div class="panel"><div class="ph"><h2>Proven by code</h2><span class="note">independent of the model</span></div><ul class="rows">{% for edge in report.verified_edges %}<li><span class="tag v">{{ edge.badge }}</span><span>{{ edge.claim_text }}</span></li>{% else %}<li class="empty">No verified edges.</li>{% endfor %}</ul></div></main></body></html>')


def allowed_host(host, port):
    return host in {f"localhost:{port}", f"127.0.0.1:{port}"}


def allowed_origin(origin, port):
    """Accept only an Origin/Referer that is this server itself.

    A missing Origin is accepted because a same-origin form POST from a browser
    that omits it is legitimate; the CSRF token is what carries the weight in
    that case, and an attacker page cannot read it. A *present but foreign*
    Origin is refused outright - that is unambiguous.
    """
    if not origin:
        return True
    parsed = urlsplit(origin)
    return parsed.netloc in {f"localhost:{port}", f"127.0.0.1:{port}"}


def non_get_status(method):
    return 200 if method in ("GET", "POST") else 405


_DISPOSITION = re.compile(r'name="([^"]*)"(?:;\s*filename="([^"]*)")?')


def parse_multipart(body, boundary):
    """Minimal multipart/form-data reader.

    Written out rather than pulled from `cgi`, which is deprecated and removed in
    3.13, and rather than adding a web framework for two forms. It returns text
    fields and file parts separately so a caller cannot confuse one for the other.
    """
    fields, files = {}, {}
    for chunk in body.split(b"--" + boundary):
        # A part is delimited by exactly one CRLF before the next boundary. That
        # CRLF belongs to the framing, so it is removed - but only that one. A
        # blanket strip would silently eat the final newline of an uploaded file,
        # which changes the bytes we hash and store.
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        if not chunk or chunk.startswith(b"--") or b"\r\n\r\n" not in chunk:
            continue
        head, data = chunk.split(b"\r\n\r\n", 1)
        match = _DISPOSITION.search(head.decode("utf-8", "replace"))
        if not match:
            continue
        name, filename = match.group(1), match.group(2)
        if filename is not None:
            files[name] = (filename, data)
        else:
            fields[name] = data.decode("utf-8", "replace").strip()
    return fields, files


def _positive_int(raw, default=None, maximum=20000):
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if 0 < value <= maximum else default


def render_run_detail(report):
    return build_environment().from_string(_DETAIL).render(report=report)


def make_handler(db_path, workdir=None, csrf_token=None):
    # One token per server process. There are no accounts and no sessions here,
    # so this is not authentication - it is proof that the request came from a
    # page this server rendered, which is the whole of what CSRF protection needs
    # to establish for a single-operator local tool.
    token = csrf_token or secrets.token_urlsafe(32)
    work_root = Path(workdir) if workdir else Path(db_path).parent / "work"

    class Handler(BaseHTTPRequestHandler):
        server_version = "ares"
        sys_version = ""

        def _headers(self, status, content_type, extra=()):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Security-Policy", DASHBOARD_CONTENT_SECURITY_POLICY)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in extra:
                self.send_header(key, value)
            self.end_headers()

        def _allowed_host(self):
            return allowed_host(self.headers.get("Host"), self.server.server_port)

        def _respond(self, status, body, content_type="text/html; charset=utf-8"):
            self._headers(status, content_type)
            self.wfile.write(body.encode("utf-8"))

        def _redirect(self, location):
            self._headers(303, "text/plain; charset=utf-8", (("Location", location),))
            self.wfile.write(b"")

        def _render_index(self, connection, status=200, error=None):
            runs = [
                dict(zip(("run_id", "incident_id", "dataset_mode"), row))
                for row in connection.execute(
                    "SELECT run_id, incident_id, dataset_mode FROM runs ORDER BY created_at DESC"
                )
            ]
            # Probed on every render rather than cached at startup: the operator
            # starts and stops Ollama independently of this process, so a cached
            # answer would be confidently wrong exactly when it matters.
            self._respond(status, build_environment().from_string(_INDEX).render(
                runs=runs, jobs=list_jobs(connection), csrf=token, error=error,
                max_mb=MAX_UPLOAD_BYTES // (1024 * 1024), local=local_status(),
            ))

        def do_GET(self):
            if not self._allowed_host():
                self._respond(403, "Forbidden", "text/plain; charset=utf-8")
                return
            path = urlsplit(self.path).path
            with sqlite3.connect(db_path) as connection:
                if path == "/":
                    self._render_index(connection)
                    return
                parts = path.split("/")
                if len(parts) == 3 and parts[1] == "job" and _is_id(parts[2]):
                    job = get_job(connection, parts[2])
                    if job is None:
                        self._respond(404, "Not found", "text/plain; charset=utf-8")
                        return
                    template = _JOB_RUNNING if job["status"] in ("queued", "running") else _JOB
                    self._respond(200, build_environment().from_string(template).render(job=job))
                    return
                if len(parts) in (3, 4) and parts[1] == "run" and _is_id(parts[2]):
                    try:
                        report = build_report(connection, parts[2])
                    except ValueError:
                        self._respond(404, "Not found", "text/plain; charset=utf-8")
                        return
                    if len(parts) == 3:
                        self._respond(200, render_run_detail(report))
                    elif parts[3] == "report.md":
                        self._respond(200, render_markdown(report), "text/markdown; charset=utf-8")
                    elif parts[3] == "report.html":
                        self._respond(200, render_html(report))
                    else:
                        self._respond(404, "Not found", "text/plain; charset=utf-8")
                    return
            self._respond(404, "Not found", "text/plain; charset=utf-8")

        def _read_upload(self):
            """Read a bounded request body and split it into fields and files."""
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type or "boundary=" not in content_type:
                return None, None, "Expected a multipart form submission."
            length = _positive_int(self.headers.get("Content-Length"), 0, MAX_UPLOAD_BYTES + 4096)
            if not length:
                return None, None, (
                    f"Upload is empty or larger than the "
                    f"{MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit."
                )
            boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode()
            fields, files = parse_multipart(self.rfile.read(length), boundary)
            if not hmac.compare_digest(fields.get("csrf", ""), token):
                # Deliberately NOT the rendered index: that page embeds the valid
                # token, so re-rendering it would hand the correct token back to a
                # caller who just demonstrated they did not have one. Same-origin
                # policy would usually stop them reading it, but "usually" is not
                # the standard for handing out the credential itself.
                return None, None, _CSRF_REFUSED
            return fields, files, None

        def do_POST(self):
            if not self._allowed_host():
                self._respond(403, "Forbidden", "text/plain; charset=utf-8")
                return
            port = self.server.server_port
            if not allowed_origin(self.headers.get("Origin") or self.headers.get("Referer"), port):
                self._respond(403, "Cross-origin request refused", "text/plain; charset=utf-8")
                return
            path = urlsplit(self.path).path
            if path not in ("/analyze", "/review"):
                self._respond(404, "Not found", "text/plain; charset=utf-8")
                return
            fields, files, error = self._read_upload()
            if error is _CSRF_REFUSED:
                self._respond(403, _CSRF_REFUSED, "text/plain; charset=utf-8")
                return
            with sqlite3.connect(db_path) as connection:
                if error:
                    self._render_index(connection, 400, error)
                    return
                try:
                    if path == "/analyze":
                        location = self._start_incident(connection, fields, files)
                    else:
                        location = self._start_review(connection, files)
                except (UploadRejected, ArchiveRejected) as rejection:
                    self._render_index(connection, 400, str(rejection))
                    return
            self._redirect(location)

        def _start_incident(self, connection, fields, files):
            filename, payload = files.get("logfile", ("", b""))
            mode = fields.get("mode") if fields.get("mode") in ("demo", "eval") else "demo"
            # The pipeline derives the mode a second time, from the corpus path,
            # and aborts if the two disagree. That double-derivation is the guard
            # keeping demo output from ever being scored as evaluation, so the
            # upload directory is chosen to state the mode rather than the check
            # being loosened to accept an unlabelled path.
            stored = store_upload(work_root / "uploads" / mode, filename, payload)
            arm = fields.get("arm") if fields.get("arm") in ("local", "frontier") else "local"
            # Validated against what Ollama actually reports rather than trusted
            # from the form: the field is a request, and an unknown value would
            # otherwise surface as a model call failing minutes into the run.
            model = fields.get("model") or None
            if arm != "local" or model not in local_status()["models"]:
                model = None
            job_id = create_job(
                connection,
                label=safe_label(filename),
                source_name=safe_label(filename),
                source_sha256=sha256_of(payload),
                source_bytes=len(payload),
                arm=arm,
                model=model,
                top_n=_positive_int(fields.get("top_n"), 300),
                batch_size=_positive_int(fields.get("batch_size"), None, 5000),
                dataset_mode=mode,
            )
            start_job(db_path, job_id, stored, f"upload:{job_id}")
            return f"/job/{job_id}"

        def _start_review(self, connection, files):
            filename, payload = files.get("archive", ("", b""))
            stored = store_review_upload(work_root / "archives", payload)
            job_id = create_job(
                connection,
                kind="review",
                label=safe_label(filename),
                source_name=safe_label(filename),
                source_sha256=sha256_of(payload),
                source_bytes=len(payload),
                arm="static-analysis",
                model=None,
                top_n=0,
                batch_size=None,
                dataset_mode="demo",
            )
            start_review_job(db_path, job_id, stored, work_root / "review" / job_id)
            return f"/job/{job_id}"

        def do_PUT(self): self._method_not_allowed()
        def do_DELETE(self): self._method_not_allowed()
        def do_PATCH(self): self._method_not_allowed()
        def do_HEAD(self): self._method_not_allowed()

        def _method_not_allowed(self):
            self._respond(405, "Method not allowed", "text/plain; charset=utf-8")

        def send_error(self, code, message=None, explain=None):
            # BaseHTTPRequestHandler emits 501 for any verb without a do_* method.
            # Only GET and POST are served, so every other verb is 405.
            if code == 501:
                code, message = 405, "Method not allowed"
            self._respond(code, message or "Request failed", "text/plain; charset=utf-8")

        def log_message(self, *_args): pass

    Handler.csrf_token = token
    return Handler


def _is_id(value):
    return bool(value) and all(character.isalnum() or character in ":_-" for character in value)


def make_server(db_path, port=8420, workdir=None):
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(db_path, workdir))


def serve(db_path, port=8420, workdir=None):
    server = make_server(db_path, port, workdir)
    server.serve_forever()
