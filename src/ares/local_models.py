"""What the local Ollama instance actually has, asked at the moment it matters.

The dashboard offers a model chooser, and the honest version of that chooser
lists the models this machine can really run rather than a hardcoded menu that
may not match what is installed. A menu that offers a model Ollama does not have
produces a job that fails several minutes later, which is a worse experience than
saying so up front.

Reachability is reported as a value, never raised. Ollama being down is a normal
condition on a laptop - the daemon is not running yet, or is still starting - and
the dashboard needs to render a page that says exactly that.
"""

import json
import os
import urllib.error
import urllib.request

OLLAMA_HOST = os.environ.get("ARES_OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_TAGS_URL = f"{OLLAMA_HOST}/api/tags"

# The model the published local-arm result was measured with. It leads the list
# so the default matches the number in the paper rather than whatever happens to
# sort first.
PREFERRED_LOCAL_MODEL = "qwen2.5:7b-instruct"

# Embedding and support models are not selectors; offering them would produce a
# run that fails inside the model call rather than at the point of choosing.
NON_SELECTOR_MODELS = ("nomic-embed-text",)

PROBE_TIMEOUT_SECONDS = 2


def installed_models(url=OLLAMA_TAGS_URL, timeout=PROBE_TIMEOUT_SECONDS):
    """Return (models, error). `models` is empty whenever `error` is set.

    The timeout is short on purpose: this runs while rendering a page, and a
    dashboard that hangs for thirty seconds because a daemon is down is worse
    than one that reports the daemon is down.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as failure:
        return [], f"Ollama is not reachable at {url} ({failure.reason})."
    except (TimeoutError, OSError) as failure:
        return [], f"Ollama did not respond at {url} ({failure})."
    except json.JSONDecodeError:
        return [], f"Ollama responded at {url} but not with JSON."

    names = [
        str(entry.get("name", ""))
        for entry in payload.get("models", [])
        if entry.get("name")
    ]
    selectors = [name for name in names if not name.startswith(NON_SELECTOR_MODELS)]
    if not selectors:
        # Reachable but empty. Reported through `reachable=True` in local_status
        # so the page can give the right instruction: a fresh container needs a
        # model pulled, not a daemon started.
        return [], None
    # Preferred first, then everything else alphabetically, so the default is
    # deterministic rather than dependent on Ollama's ordering.
    preferred = [name for name in selectors if name == PREFERRED_LOCAL_MODEL]
    rest = sorted(name for name in selectors if name != PREFERRED_LOCAL_MODEL)
    return preferred + rest, None


def local_status(url=OLLAMA_TAGS_URL, timeout=PROBE_TIMEOUT_SECONDS):
    """Everything a template needs to render the local-model chooser.

    `reachable` and `has_models` are separate because the remedies are
    different - start the daemon, versus pull a model - and a page that tells
    you to run `ollama serve` when it is already running sends you the wrong way.
    """
    models, error = installed_models(url, timeout)
    return {
        "reachable": error is None,
        "has_models": bool(models),
        "models": models,
        "error": error,
        "default": models[0] if models else None,
        "preferred_present": PREFERRED_LOCAL_MODEL in models,
        "preferred": PREFERRED_LOCAL_MODEL,
    }


def frontier_status():
    """Whether the frontier arm can actually run here.

    Reported the same way the local model is: as a value the page can render,
    not as an exception thrown after the operator has already submitted a job.
    """
    import shutil

    from .proposer import CODEX_COMPANION_ENV, FRONTIER_MODEL, find_codex_companion

    companion = find_codex_companion()
    node = shutil.which("node")
    if companion and node:
        return {"available": True, "model": FRONTIER_MODEL, "reason": None}
    missing = "Node.js" if companion else "the Codex companion script"
    return {
        "available": False,
        "model": FRONTIER_MODEL,
        "reason": (
            f"Unavailable here: {missing} was not found. "
            f"Set {CODEX_COMPANION_ENV} if it is installed elsewhere. "
            "This is expected inside the container."
        ),
    }
