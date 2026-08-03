"""Read-only loopback dashboard for persisted ARES runs."""

import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .rendering import CONTENT_SECURITY_POLICY, build_environment
from .report import build_report, render_html, render_markdown


_INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{{ CSP_META_TAG }}<title>ARES</title><style>
:root{--void:#24262b;--panel:#2c2f35;--panel2:#33373e;--line:#3b4047;--line2:#4b515a;
--fg:#eae7e1;--fg2:#aca79e;--fg3:#827d75;
--ok:#84b394;--ap:#d3a463;--no:#d08a80;--acc:#93b2ca;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--void);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background-image:radial-gradient(circle at 12% -12%,rgba(147,178,202,.06),transparent 48%),
radial-gradient(circle at 94% 2%,rgba(211,164,99,.05),transparent 42%)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.bar{border-bottom:1px solid var(--line);background:rgba(36,38,43,.92);padding:.85rem 0}
.in{max-width:1080px;margin:0 auto;padding:0 1.5rem}
.bar .in{display:flex;align-items:center;gap:.9rem;flex-wrap:wrap}
.brand{font:700 1.05rem/1 var(--mono);letter-spacing:.22em}
.brand em{color:var(--acc);font-style:normal}
.tagline{color:var(--fg3);font-size:.8rem;border-left:1px solid var(--line2);padding-left:.9rem}
.dot{margin-left:auto;display:flex;align-items:center;gap:.45rem;font:600 .68rem/1 var(--mono);
letter-spacing:.14em;color:var(--ok)}
.dot i{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(132,179,148,.16)}
main{max-width:1080px;margin:0 auto;padding:2rem 1.5rem 5rem}
.lab{font:700 .68rem/1 var(--mono);letter-spacing:.18em;color:var(--fg3);margin:0 0 .7rem}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:1.6rem;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.18)}
.ph{display:flex;align-items:center;gap:.7rem;padding:.75rem 1.1rem;border-bottom:1px solid var(--line);
background:var(--panel2)}
.ph h2{margin:0;font:700 .78rem/1 var(--mono);letter-spacing:.14em;text-transform:uppercase}
.ph .note{margin-left:auto;color:var(--fg3);font-size:.75rem}
.pb{padding:1.1rem}
.dl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.7rem}
.dl{display:flex;align-items:center;gap:.8rem;padding:.85rem 1rem;border:1px solid var(--line2);
border-radius:8px;background:var(--panel2);color:var(--fg)}
.dl:hover{border-color:var(--acc);text-decoration:none;background:#3a3f47}
.dl .ext{font:700 .68rem/1 var(--mono);letter-spacing:.06em;padding:.42rem .5rem;border-radius:5px;
background:rgba(147,178,202,.14);color:var(--acc);flex:none}
.dl b{display:block;font-size:.9rem;font-weight:600}
.dl span{color:var(--fg3);font-size:.74rem;font-family:var(--mono)}
.thesis{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0}
.th{padding:1.1rem;border-right:1px solid var(--line)}
.th:last-child{border-right:0}
.th .k{display:inline-flex;align-items:center;gap:.45rem;font:700 .7rem/1 var(--mono);letter-spacing:.12em;margin-bottom:.5rem}
.th .k i{width:8px;height:8px;border-radius:2px}
.th p{margin:0;color:var(--fg2);font-size:.85rem;line-height:1.5}
.k.v{color:var(--ok)} .k.v i{background:var(--ok)}
.k.r{color:var(--no)} .k.r i{background:var(--no)}
.k.a{color:var(--ap)} .k.a i{background:var(--ap)}
.runs{list-style:none;margin:0;padding:0}
.runs li{border-bottom:1px solid var(--line)}
.runs li:last-child{border-bottom:0}
.runs a.row{display:flex;align-items:center;gap:1rem;padding:.95rem 1.1rem;color:var(--fg)}
.runs a.row:hover{background:var(--panel2);text-decoration:none}
.chip{font:700 .64rem/1 var(--mono);letter-spacing:.12em;padding:.38rem .55rem;border-radius:5px;flex:none;border:1px solid}
.chip.demo{color:var(--ap);border-color:rgba(211,164,99,.38);background:rgba(211,164,99,.12)}
.chip.eval{color:var(--acc);border-color:rgba(147,178,202,.38);background:rgba(147,178,202,.12)}
.runs b{font-size:.94rem;font-weight:600}
.runs .id{color:var(--fg3);font:.72rem var(--mono);margin-top:.15rem}
.arrow{margin-left:auto;color:var(--fg3);font-family:var(--mono)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0}
.stat{padding:1.1rem;border-right:1px solid var(--line)}
.stat:last-child{border-right:0}
.stat .v{display:block;font:700 2rem/1 var(--mono);font-variant-numeric:tabular-nums}
.stat .k{font:700 .66rem/1 var(--mono);letter-spacing:.14em;color:var(--fg3);margin-top:.45rem;display:block}
.stat.v1 .v{color:var(--ok)} .stat.v2 .v{color:var(--ap)} .stat.v3 .v{color:var(--no)}
.mode{display:flex;gap:.9rem;padding:1rem 1.1rem;border-radius:10px;margin-bottom:1.6rem;border:1px solid;font-size:.88rem}
.mode.demo{border-color:rgba(211,164,99,.42);background:rgba(211,164,99,.09);color:#e2bc86}
.mode.eval{border-color:rgba(147,178,202,.4);background:rgba(147,178,202,.08);color:#b7cede}
.mode b{display:block;font:700 .68rem/1 var(--mono);letter-spacing:.16em;margin-bottom:.35rem}
h1{font-size:1.7rem;margin:.2rem 0 .25rem;letter-spacing:-.01em}
.sub{color:var(--fg3);font:.78rem var(--mono);margin:0 0 1.6rem}
.rows{list-style:none;margin:0;padding:0}
.rows li{padding:.8rem 1.1rem;border-bottom:1px solid var(--line);font-size:.9rem;display:flex;gap:.8rem;align-items:flex-start}
.rows li:last-child{border-bottom:0}
.tag{font:700 .62rem/1 var(--mono);letter-spacing:.1em;padding:.35rem .5rem;border-radius:4px;flex:none;margin-top:.1rem}
.tag.v{background:rgba(132,179,148,.15);color:var(--ok)}
.tag.s{background:rgba(211,164,99,.15);color:var(--ap)}
.meta{color:var(--fg3);font:.72rem var(--mono);margin-top:.25rem}
.panel.aporia{border-color:rgba(208,138,128,.45)}
.panel.aporia .ph{background:rgba(208,138,128,.1);border-bottom-color:rgba(208,138,128,.28)}
.panel.aporia .ph h2{color:var(--no)}
.lead{color:var(--fg2);font-size:.88rem;margin:0 0 .9rem;padding:0 1.1rem}
.empty{color:var(--fg3);font-style:italic}
.prec{padding:1.1rem}
.prec .p1{margin:0 0 .4rem;font:700 1rem/1.4 var(--mono);color:var(--ok)}
.prec .p2{margin:0;color:var(--fg2);font-size:.84rem}
.foot{color:var(--fg3);font-size:.78rem;border-top:1px solid var(--line);padding-top:1.2rem;margin-top:2.5rem}
</style></head><body><div class="bar"><div class="in"><span class="brand">A<em>R</em>ES</span><span class="tagline">Local incident analysis &middot; nothing leaves this machine</span><span class="dot"><i></i>LOCALHOST</span></div></div><main><p class="lab">DOWNLOADS</p><div class="panel"><div class="ph"><h2>Reports</h2><span class="note">Generated from stored evidence &middot; open offline</span></div><div class="pb"><div class="dl-grid">{% for run in runs %}<a class="dl" href="/run/{{ run.run_id|url }}/report.md"><span class="ext">MD</span><span><b>{{ run.incident_id }}</b><span>markdown &middot; {{ run.dataset_mode }}</span></span></a><a class="dl" href="/run/{{ run.run_id|url }}/report.html"><span class="ext">HTML</span><span><b>{{ run.incident_id }}</b><span>html &middot; {{ run.dataset_mode }}</span></span></a>{% else %}<p class="empty">No reports yet &mdash; run an incident first.</p>{% endfor %}</div></div></div><p class="lab">WHAT THE BADGES MEAN</p><div class="panel"><div class="thesis"><div class="th"><span class="k v"><i></i>VERIFIED</span><p>Deterministic code checked it. No model involved. Same answer every time.</p></div><div class="th"><span class="k r"><i></i>REFUTED</span><p>Checked, and the evidence contradicts it.</p></div><div class="th"><span class="k a"><i></i>APORIA</span><p>Cannot be determined from this evidence. The tool says so instead of guessing.</p></div></div></div><p class="lab">RUNS</p><div class="panel"><ul class="runs">{% for run in runs %}<li><a class="row" href="/run/{{ run.run_id|url }}"><span class="chip {{ run.dataset_mode }}">{{ run.dataset_mode|upper }}</span><span><b>{{ run.incident_id }}</b><div class="id">{{ run.run_id }}</div></span><span class="arrow">&rarr;</span></a></li>{% else %}<li style="padding:1.1rem" class="empty">No runs yet. Run scripts/run_incident.py first.</li>{% endfor %}</ul></div><p class="foot">The model decides what is interesting. It never decides what is true &mdash; selections are stored apart from proven facts and can never carry a badge.</p></main></body></html>"""

_DETAIL = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{{ CSP_META_TAG }}<title>ARES &mdash; {{ report.incident_id }}</title><style>
:root{--void:#24262b;--panel:#2c2f35;--panel2:#33373e;--line:#3b4047;--line2:#4b515a;
--fg:#eae7e1;--fg2:#aca79e;--fg3:#827d75;
--ok:#84b394;--ap:#d3a463;--no:#d08a80;--acc:#93b2ca;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--void);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background-image:radial-gradient(circle at 12% -12%,rgba(147,178,202,.06),transparent 48%),
radial-gradient(circle at 94% 2%,rgba(211,164,99,.05),transparent 42%)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.bar{border-bottom:1px solid var(--line);background:rgba(36,38,43,.92);padding:.85rem 0}
.in{max-width:1080px;margin:0 auto;padding:0 1.5rem}
.bar .in{display:flex;align-items:center;gap:.9rem;flex-wrap:wrap}
.brand{font:700 1.05rem/1 var(--mono);letter-spacing:.22em}
.brand em{color:var(--acc);font-style:normal}
.tagline{color:var(--fg3);font-size:.8rem;border-left:1px solid var(--line2);padding-left:.9rem}
.dot{margin-left:auto;display:flex;align-items:center;gap:.45rem;font:600 .68rem/1 var(--mono);
letter-spacing:.14em;color:var(--ok)}
.dot i{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(132,179,148,.16)}
main{max-width:1080px;margin:0 auto;padding:2rem 1.5rem 5rem}
.lab{font:700 .68rem/1 var(--mono);letter-spacing:.18em;color:var(--fg3);margin:0 0 .7rem}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:1.6rem;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.18)}
.ph{display:flex;align-items:center;gap:.7rem;padding:.75rem 1.1rem;border-bottom:1px solid var(--line);
background:var(--panel2)}
.ph h2{margin:0;font:700 .78rem/1 var(--mono);letter-spacing:.14em;text-transform:uppercase}
.ph .note{margin-left:auto;color:var(--fg3);font-size:.75rem}
.pb{padding:1.1rem}
.dl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.7rem}
.dl{display:flex;align-items:center;gap:.8rem;padding:.85rem 1rem;border:1px solid var(--line2);
border-radius:8px;background:var(--panel2);color:var(--fg)}
.dl:hover{border-color:var(--acc);text-decoration:none;background:#3a3f47}
.dl .ext{font:700 .68rem/1 var(--mono);letter-spacing:.06em;padding:.42rem .5rem;border-radius:5px;
background:rgba(147,178,202,.14);color:var(--acc);flex:none}
.dl b{display:block;font-size:.9rem;font-weight:600}
.dl span{color:var(--fg3);font-size:.74rem;font-family:var(--mono)}
.thesis{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0}
.th{padding:1.1rem;border-right:1px solid var(--line)}
.th:last-child{border-right:0}
.th .k{display:inline-flex;align-items:center;gap:.45rem;font:700 .7rem/1 var(--mono);letter-spacing:.12em;margin-bottom:.5rem}
.th .k i{width:8px;height:8px;border-radius:2px}
.th p{margin:0;color:var(--fg2);font-size:.85rem;line-height:1.5}
.k.v{color:var(--ok)} .k.v i{background:var(--ok)}
.k.r{color:var(--no)} .k.r i{background:var(--no)}
.k.a{color:var(--ap)} .k.a i{background:var(--ap)}
.runs{list-style:none;margin:0;padding:0}
.runs li{border-bottom:1px solid var(--line)}
.runs li:last-child{border-bottom:0}
.runs a.row{display:flex;align-items:center;gap:1rem;padding:.95rem 1.1rem;color:var(--fg)}
.runs a.row:hover{background:var(--panel2);text-decoration:none}
.chip{font:700 .64rem/1 var(--mono);letter-spacing:.12em;padding:.38rem .55rem;border-radius:5px;flex:none;border:1px solid}
.chip.demo{color:var(--ap);border-color:rgba(211,164,99,.38);background:rgba(211,164,99,.12)}
.chip.eval{color:var(--acc);border-color:rgba(147,178,202,.38);background:rgba(147,178,202,.12)}
.runs b{font-size:.94rem;font-weight:600}
.runs .id{color:var(--fg3);font:.72rem var(--mono);margin-top:.15rem}
.arrow{margin-left:auto;color:var(--fg3);font-family:var(--mono)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0}
.stat{padding:1.1rem;border-right:1px solid var(--line)}
.stat:last-child{border-right:0}
.stat .v{display:block;font:700 2rem/1 var(--mono);font-variant-numeric:tabular-nums}
.stat .k{font:700 .66rem/1 var(--mono);letter-spacing:.14em;color:var(--fg3);margin-top:.45rem;display:block}
.stat.v1 .v{color:var(--ok)} .stat.v2 .v{color:var(--ap)} .stat.v3 .v{color:var(--no)}
.mode{display:flex;gap:.9rem;padding:1rem 1.1rem;border-radius:10px;margin-bottom:1.6rem;border:1px solid;font-size:.88rem}
.mode.demo{border-color:rgba(211,164,99,.42);background:rgba(211,164,99,.09);color:#e2bc86}
.mode.eval{border-color:rgba(147,178,202,.4);background:rgba(147,178,202,.08);color:#b7cede}
.mode b{display:block;font:700 .68rem/1 var(--mono);letter-spacing:.16em;margin-bottom:.35rem}
h1{font-size:1.7rem;margin:.2rem 0 .25rem;letter-spacing:-.01em}
.sub{color:var(--fg3);font:.78rem var(--mono);margin:0 0 1.6rem}
.rows{list-style:none;margin:0;padding:0}
.rows li{padding:.8rem 1.1rem;border-bottom:1px solid var(--line);font-size:.9rem;display:flex;gap:.8rem;align-items:flex-start}
.rows li:last-child{border-bottom:0}
.tag{font:700 .62rem/1 var(--mono);letter-spacing:.1em;padding:.35rem .5rem;border-radius:4px;flex:none;margin-top:.1rem}
.tag.v{background:rgba(132,179,148,.15);color:var(--ok)}
.tag.s{background:rgba(211,164,99,.15);color:var(--ap)}
.meta{color:var(--fg3);font:.72rem var(--mono);margin-top:.25rem}
.panel.aporia{border-color:rgba(208,138,128,.45)}
.panel.aporia .ph{background:rgba(208,138,128,.1);border-bottom-color:rgba(208,138,128,.28)}
.panel.aporia .ph h2{color:var(--no)}
.lead{color:var(--fg2);font-size:.88rem;margin:0 0 .9rem;padding:0 1.1rem}
.empty{color:var(--fg3);font-style:italic}
.prec{padding:1.1rem}
.prec .p1{margin:0 0 .4rem;font:700 1rem/1.4 var(--mono);color:var(--ok)}
.prec .p2{margin:0;color:var(--fg2);font-size:.84rem}
.foot{color:var(--fg3);font-size:.78rem;border-top:1px solid var(--line);padding-top:1.2rem;margin-top:2.5rem}
</style></head><body><div class="bar"><div class="in"><span class="brand">A<em>R</em>ES</span><span class="tagline">Local incident analysis &middot; nothing leaves this machine</span><span class="dot"><i></i>LOCALHOST</span></div></div><main><p class="lab">DOWNLOADS</p><div class="panel"><div class="pb"><div class="dl-grid"><a class="dl" href="/run/{{ report.run_id|url }}/report.md"><span class="ext">MD</span><span><b>Markdown report</b><span>plain text &middot; diffable</span></span></a><a class="dl" href="/run/{{ report.run_id|url }}/report.html"><span class="ext">HTML</span><span><b>HTML report</b><span>self-contained &middot; offline</span></span></a><a class="dl" href="/"><span class="ext">&larr;</span><span><b>All runs</b><span>back to index</span></span></a></div></div></div><div class="mode {{ report.dataset_mode }}"><div><b>{{ report.dataset_mode }} DATASET</b>{% if report.demo_notice %}{{ report.demo_notice }}{% else %}Accuracy is measured against the frozen answer key for this corpus.{% endif %}</div></div><h1>{{ report.incident_id }}</h1><p class="sub">{{ report.run_id }}</p><div class="panel"><div class="stats"><div class="stat v1"><span class="v">{{ report.verified_edges|length }}</span><span class="k">VERIFIED</span></div><div class="stat v2"><span class="v">{{ report.selections|length }}</span><span class="k">SELECTED BY MODEL</span></div><div class="stat v3"><span class="v">{{ report.aporias|length }}</span><span class="k">APORIA</span></div></div></div>{% if report.precision_line %}<div class="panel"><div class="ph"><h2>Scored</h2></div><div class="prec"><p class="p1">{{ report.precision_line }}</p><p class="p2">{{ report.coverage_line }}</p></div></div>{% endif %}<div class="panel aporia"><div class="ph"><h2>Aporia &mdash; cannot be proven</h2><span class="note">shown, never hidden</span></div><p class="lead" style="padding-top:1rem">The evidence does not support a conclusion here. The tool refuses to guess.</p><ul class="rows">{% for item in report.aporias %}<li><span>{{ item.claim_text }}<div class="meta">{{ item.failure_code }}{% if item.failure_detail %} &middot; {{ item.failure_detail }}{% endif %}</div></span></li>{% else %}<li class="empty">None in this run.</li>{% endfor %}</ul></div><div class="panel"><div class="ph"><h2>Model selections</h2><span class="note">interpretation &middot; never badged</span></div><ul class="rows">{% for item in report.selections %}<li><span class="tag s">PICK</span><span>{{ item.rationale }}<div class="meta">{{ item.edge_id }} &middot; ATT&amp;CK {{ item.attack_technique_id or "not supplied" }}</div></span></li>{% else %}<li class="empty">The model selected nothing in this run.</li>{% endfor %}</ul></div><div class="panel"><div class="ph"><h2>Proven by code</h2><span class="note">independent of the model</span></div><ul class="rows">{% for edge in report.verified_edges %}<li><span class="tag v">{{ edge.badge }}</span><span>{{ edge.claim_text }}</span></li>{% else %}<li class="empty">No verified edges.</li>{% endfor %}</ul></div></main></body></html>"""




def allowed_host(host, port):
    return host in {f"localhost:{port}", f"127.0.0.1:{port}"}


def non_get_status(method):
    return 200 if method == "GET" else 405


def render_run_detail(report):
    return build_environment().from_string(_DETAIL).render(report=report)


def make_handler(db_path):
    class Handler(BaseHTTPRequestHandler):
        def _headers(self, status, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()

        def _allowed_host(self):
            return allowed_host(self.headers.get("Host"), self.server.server_port)

        def _respond(self, status, body, content_type="text/html; charset=utf-8"):
            self._headers(status, content_type)
            self.wfile.write(body.encode("utf-8"))

        def do_GET(self):
            if not self._allowed_host():
                self._respond(403, "Forbidden", "text/plain; charset=utf-8")
                return
            path = urlsplit(self.path).path
            with sqlite3.connect(db_path) as connection:
                if path == "/":
                    rows = connection.execute("SELECT run_id, incident_id, dataset_mode FROM runs ORDER BY created_at DESC").fetchall()
                    runs = [dict(zip(("run_id", "incident_id", "dataset_mode"), row)) for row in rows]
                    self._respond(200, build_environment().from_string(_INDEX).render(runs=runs))
                    return
                parts = path.split("/")
                if len(parts) in (3, 4) and parts[1] == "run" and parts[2] and all(character.isalnum() or character in ":_-" for character in parts[2]):
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

        def do_POST(self): self._method_not_allowed()
        def do_PUT(self): self._method_not_allowed()
        def do_DELETE(self): self._method_not_allowed()
        def do_PATCH(self): self._method_not_allowed()
        def do_HEAD(self): self._method_not_allowed()
        def _method_not_allowed(self):
            self._respond(405, "Method not allowed", "text/plain; charset=utf-8")
        def send_error(self, code, message=None, explain=None):
            # BaseHTTPRequestHandler emits 501 for any verb without a do_* method.
            # This service is deliberately read-only, so every such verb is 405.
            if code == 501:
                code, message = 405, "Method not allowed"
            self._respond(code, message or "Request failed", "text/plain; charset=utf-8")
        def log_message(self, *_args): pass

    return Handler


def make_server(db_path, port=8420):
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(db_path))


def serve(db_path, port=8420):
    server = make_server(db_path, port)
    server.serve_forever()
