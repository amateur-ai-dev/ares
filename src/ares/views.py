"""The run view, written once and rendered by both the dashboard and the export.

The downloaded HTML report used to be a separate, much poorer template: no
executive strip, no funnel, no timeline, different wording. Two templates
describing the same run is two chances to disagree about it, and the one people
forward to other people was the worse of the pair.

So the body of a run view lives here as fragments, and both surfaces compose the
same ones. The differences between them are deliberate and small:

* the dashboard wraps this in its top bar and download links, and declares the
  dashboard CSP (`form-action 'self'`, because that page has forms);
* the export declares the stricter CSP (`form-action 'none'`) and carries no
  links back to a server that will not be running when the file is opened.

Everything a reader looks at - the numbers, the bars, the ordering, the
refusals - is the same object in both.
"""

# --- the four headline numbers ------------------------------------------------
EXEC_STRIP = """<div class="exec">{% for cell in report.executive.cells %}<div class="c {{ cell.tone }}">
<span class="k">{{ cell.key }}</span><span class="v">{{ cell.value }}</span><span class="n">{{ cell.note }}</span>
</div>{% endfor %}</div>
{% if not report.executive.scored %}<p class="withheld"><b>WITHHELD</b>{{ report.executive.reason }}</p>{% endif %}"""

# --- mode banner and title ----------------------------------------------------
MODE_BANNER = """<div class="mode {{ report.dataset_mode }}"><div><b>{{ report.dataset_mode }} DATASET</b>
{% if report.demo_notice %}{{ report.demo_notice }}{% else %}Accuracy is measured against the frozen
answer key for this corpus.{% endif %}</div></div>"""

HEADING = """<h1>SESSION {{ report.session_number }}</h1>
<p class="sub">{{ report.created_at }}<br><span style="opacity:.72">{{ report.incident_id }}
&middot; {{ report.run_id }}</span></p>"""

STATS = """<div class="panel"><div class="stats">
<div class="stat v1"><span class="v">{{ report.verified_edges|length }}</span><span class="k">VERIFIED</span></div>
<div class="stat v2"><span class="v">{{ report.selections|length }}</span><span class="k">SELECTED BY MODEL</span></div>
<div class="stat v3"><span class="v">{{ report.aporias|length }}</span><span class="k">APORIA</span></div>
</div></div>"""

SCORED = """{% if report.precision_line %}<div class="panel"><div class="ph"><h2>Scored</h2></div>
<div class="prec"><p class="p1">{{ report.precision_line }}</p>
<p class="p2">{{ report.coverage_line }}</p></div></div>{% endif %}"""

# --- how the log narrowed -----------------------------------------------------
FUNNEL = """<p class="lab">HOW THE LOG NARROWED</p><div class="panel"><div class="ph"><h2>Funnel</h2>
<span class="note">bar length is square-root scaled &middot; the counts are exact</span></div>
<div class="funnel">{% for stage in report.funnel %}<div class="fr s-{{ stage.key }}">
<span class="fl">{{ stage.label }}</span>
<span class="fb"><i style="width:{{ stage.bar_width|round(2) }}%"></i></span>
<span class="fv">{{ stage.value }}</span>
<p class="fn">{{ stage.note }}</p>
{% if not loop.first %}<p class="drop">&darr; kept {{ (stage.share_of_previous * 100)|round(1) }}% of the stage above</p>{% endif %}
</div>{% endfor %}</div>
<div class="beside"><span class="bv">{{ report.aporias|length }}</span>
<span class="bt"><b>Aporia sits beside this funnel, not inside it.</b> These are relations the
verifier refused to decide &mdash; they did not survive the stages above, they were never
eligible for them. Drawing them as a sixth bar would imply otherwise.</span></div></div>"""

# --- when it happened ---------------------------------------------------------
TIMELINE = """<p class="lab">WHEN IT HAPPENED</p><div class="panel"><div class="ph"><h2>Timeline</h2>
<span class="note">{{ report.timeline|length }} verified relations &middot; ordered by event time</span></div>
{% if report.timeline %}<div class="tl"><div class="tlrail">
{% for entry in report.timeline %}<span class="pt{% if entry.attack_relevant %} hit{% endif %}{% if entry.relation_type == 'PROCESS_OPENED_CONNECTION' %} conn{% endif %}" style="left:{{ entry.offset }}%"></span>{% endfor %}
</div><div class="tlends"><span>{{ report.timeline[0].occurred_at or 'start of log' }}</span>
<span>{{ report.timeline[-1].occurred_at or 'end of log' }}</span></div></div>
<div class="tllegend"><span><i></i>verified relation</span><span><i class="conn"></i>network connection</span>
<span><i class="hit"></i>selected as attack-relevant</span></div>
<ul class="tlist">{% for entry in report.timeline %}<li{% if entry.attack_relevant %} class="hit"{% endif %}>
<span class="ts">{{ entry.occurred_at or 'no timestamp' }}</span><span class="mk"></span>
<span><span class="fl2">{{ entry.source_label }}</span><span class="arrow2">&rarr;</span>{{ entry.target_label }}
{% if entry.attack_relevant %}<b class="pick">ATTACK-RELEVANT</b>{% endif %}
<div class="meta">{{ entry.relation_type }}</div></span></li>{% endfor %}</ul>
{% else %}<p class="lead" style="padding:1.1rem">No verified relations carried timing information for this run.</p>{% endif %}
</div>"""

# --- the three evidence panels ------------------------------------------------
# Aporia comes FIRST, before the model's picks and before the proven edges. What
# the tool could not establish is the least likely thing to be read and the most
# likely to matter, so it is not put at the bottom where a reader stops.
APORIA = """<div class="panel aporia"><div class="ph"><h2>Aporia &mdash; cannot be proven</h2>
<span class="note">shown, never hidden</span></div>
<p class="lead" style="padding-top:1rem">The evidence does not support a conclusion here.
The tool refuses to guess.</p>
<ul class="rows">{% for item in report.aporias %}<li><span>{{ item.claim_text }}
<div class="meta">{{ item.failure_code }}{% if item.failure_detail %} &middot; {{ item.failure_detail }}{% endif %}</div>
</span></li>{% else %}<li class="empty">None in this run.</li>{% endfor %}</ul></div>"""

SELECTIONS = """<div class="panel"><div class="ph"><h2>Model selections</h2>
<span class="note">interpretation &middot; never badged</span></div>
<ul class="rows">{% for item in report.selections %}<li><span class="tag s">PICK</span>
<span>{{ item.rationale }}<div class="meta">{{ item.edge_id }} &middot; ATT&amp;CK
{{ item.attack_technique_id or "not supplied" }}</div></span></li>
{% else %}<li class="empty">The model selected nothing in this run.</li>{% endfor %}</ul></div>"""

VERIFIED = """<div class="panel"><div class="ph"><h2>Proven by code</h2>
<span class="note">independent of the model</span></div>
<ul class="rows">{% for edge in report.verified_edges %}<li><span class="tag v">{{ edge.badge }}</span>
<span>{{ edge.claim_text }}</span></li>
{% else %}<li class="empty">No verified edges.</li>{% endfor %}</ul></div>"""

FOOTER = """<p class="foot">The model decides what is interesting. It never decides what is true
&mdash; selections are stored apart from proven facts and can never carry a badge.</p>"""

# The whole run view, in reading order. Both surfaces use exactly this.
RUN_BODY = (
    MODE_BANNER + HEADING + EXEC_STRIP + STATS + SCORED
    + FUNNEL + TIMELINE + APORIA + SELECTIONS + VERIFIED
)
