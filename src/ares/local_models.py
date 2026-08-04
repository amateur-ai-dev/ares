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
import urllib.error
import urllib.request

OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"

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
        return [], "Ollama is running but has no usable model pulled."
    # Preferred first, then everything else alphabetically, so the default is
    # deterministic rather than dependent on Ollama's ordering.
    preferred = [name for name in selectors if name == PREFERRED_LOCAL_MODEL]
    rest = sorted(name for name in selectors if name != PREFERRED_LOCAL_MODEL)
    return preferred + rest, None


def local_status(url=OLLAMA_TAGS_URL, timeout=PROBE_TIMEOUT_SECONDS):
    """Everything a template needs to render the local-model chooser."""
    models, error = installed_models(url, timeout)
    return {
        "reachable": error is None,
        "models": models,
        "error": error,
        "default": models[0] if models else None,
        "preferred_present": PREFERRED_LOCAL_MODEL in models,
        "preferred": PREFERRED_LOCAL_MODEL,
    }
