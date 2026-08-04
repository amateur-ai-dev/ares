"""The single hardened template environment for every HTML surface ARES emits.

Everything ARES renders is untrusted. Model rationales are model output, log
fields are third-party attacker-influenced data, and scanner findings quote
whatever was in the file being scanned. A stored payload in any of them becomes
script the moment a judge opens the dashboard or a downloaded report.

Two things follow, and both are enforced here rather than left to the discipline
of whoever writes the next template:

1. Jinja does NOT autoescape by default - a bare ``Environment`` escapes nothing.
   The default is opt-in and it is the wrong default for this project, so there is
   exactly one environment constructor and it is always configured.
2. ``|safe`` and ``Markup`` are the documented ways to switch escaping back off
   for a value. This module removes them from the environment entirely, so a
   template that tries to use one fails to render instead of silently emitting an
   injection point.

Reports are downloaded and opened from disk, so they cannot rely on a server
header for their Content-Security-Policy; the meta tag is emitted into the
document itself.
"""

from urllib.parse import urlsplit

from jinja2 import Environment, StrictUndefined, select_autoescape
from markupsafe import Markup


# No external origins at all: no CDN, no fonts, no analytics. Everything ARES
# ships is inlined, so 'self' plus inline styles is the whole legitimate surface
# and script has no legitimate source whatsoever. A CSP that forbids script
# outright is the strongest possible statement for a page whose entire content is
# untrusted text, and it costs nothing because these pages do not need script.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)

CSP_META_TAG = f'<meta http-equiv="Content-Security-Policy" content="{CONTENT_SECURITY_POLICY}">'


# The dashboard grew forms - upload a log, start an analysis, submit an archive
# for review - and `form-action 'none'` blocks a page from submitting its own.
# It is relaxed to 'self' for the dashboard ONLY, and nothing else moves: script
# is still forbidden outright, so this permits the dashboard to post to itself
# and permits no new way to run code. Exported reports keep the stricter policy,
# because a downloaded file that can POST anywhere is a worse object to hand
# someone than one that cannot.
DASHBOARD_CONTENT_SECURITY_POLICY = CONTENT_SECURITY_POLICY.replace(
    "form-action 'none'", "form-action 'self'"
)

DASHBOARD_CSP_META_TAG = (
    '<meta http-equiv="Content-Security-Policy" '
    f'content="{DASHBOARD_CONTENT_SECURITY_POLICY}">'
)


# Autoescaping is a defence for TEXT context and nothing else. A value placed in
# an href or src is still a live URL after escaping, so `javascript:alert(1)`
# survives it intact - the regression suite caught exactly that. Any template
# emitting a link must route the value through `url` below.
SAFE_URL_SCHEMES = frozenset({"http", "https", "mailto"})
NEUTRALISED_URL = "#"


def safe_url(value):
    """Return `value` only if it is a scheme ARES is willing to link to.

    Relative URLs are permitted (no scheme). Everything else - `javascript:`,
    `data:`, `vbscript:`, and any scheme invented later - collapses to a dead
    anchor rather than being rendered as a working link.
    """
    if not isinstance(value, str):
        return NEUTRALISED_URL
    candidate = value.strip()
    if not candidate:
        return NEUTRALISED_URL
    # Control characters are how `java\tscript:` style bypasses are smuggled past
    # a naive scheme check; strip them before parsing rather than after.
    candidate = "".join(character for character in candidate if ord(character) > 0x20)
    scheme = urlsplit(candidate).scheme.lower()
    if not scheme:
        return candidate
    return candidate if scheme in SAFE_URL_SCHEMES else NEUTRALISED_URL


class UnsafeTemplateConstruct(Exception):
    """Raised when a template reaches for a documented escape-hatch filter."""


def _refuse(name):
    def refused(*_args, **_kwargs):
        raise UnsafeTemplateConstruct(
            f"{name!r} is disabled in ARES templates: every value rendered here is "
            "untrusted (model output, third-party log fields, scanner findings). "
            "If markup is genuinely needed, build it as structured data the "
            "template walks, never as a pre-rendered string."
        )
    return refused


def build_environment(loader=None):
    """Return the only template environment ARES is permitted to render with.

    ``select_autoescape`` with both defaults set to True escapes every template,
    including ones loaded from a string, rather than only those whose filename
    happens to end in .html.
    """
    environment = Environment(
        loader=loader,
        autoescape=select_autoescape(
            enabled_extensions=("html", "htm", "xml"),
            default_for_string=True,
            default=True,
        ),
        undefined=StrictUndefined,
        auto_reload=False,
    )
    # Removing these is the difference between "we intend not to use |safe" and
    # "a template using |safe does not render".
    for name in ("safe", "Markup", "escape_silent"):
        environment.filters[name] = _refuse(name)
    environment.filters["url"] = safe_url
    # The one value that must reach the page as markup rather than as text.
    # Marking it here - a constant defined in this module, never touched by log
    # data or model output - is what lets the `|safe` filter stay disabled for
    # everything a template could point at. Escaped, it rendered the policy as
    # visible gibberish AND left the page with no CSP at all.
    environment.globals["CSP_META_TAG"] = Markup(CSP_META_TAG)
    environment.globals["DASHBOARD_CSP_META_TAG"] = Markup(DASHBOARD_CSP_META_TAG)
    environment.globals["content_security_policy"] = CONTENT_SECURITY_POLICY
    return environment


def render_string(source, **context):
    """Render a template held in memory, with the same guarantees as a file."""
    return build_environment().from_string(source).render(**context)
