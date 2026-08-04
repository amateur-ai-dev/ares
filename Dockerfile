# ARES in a container.
#
# The image ships the scanners the code-review add-on needs, because a container
# whose review feature silently reports "gitleaks: not installed" is a container
# that quietly does less than the tool it claims to be.
#
# Every downloaded binary is checksum-verified before it is put on PATH. That is
# the same rule the bare-metal installer follows for Hayabusa, and a Dockerfile
# is exactly the place it usually gets skipped: `curl | tar` inside a build is
# still executing an unverified download, it is just doing it somewhere less
# visible.
FROM python:3.12-slim AS base

# Pinned per architecture, with digests taken from the published release assets.
# Both are needed: an amd64 binary passes its checksum happily on an arm64 host
# and then dies with a Go runtime panic the moment it runs, which looks like a
# broken download rather than the wrong file.
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.28.0
ARG GITLEAKS_SHA256_amd64=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
ARG GITLEAKS_SHA256_arm64=eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356
ARG OSV_SCANNER_VERSION=2.0.2
ARG OSV_SCANNER_SHA256_amd64=3abcfd7126c453a00421487e721b296e0cb68085bd431d6cef60872774170fc8
ARG OSV_SCANNER_SHA256_arm64=5da413cb77ddb99bd115961e25ddf02490f6e1415abea1e15c9557057a457c08

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:/usr/local/bin:$PATH

RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates curl tar \
 && rm -rf /var/lib/apt/lists/*

# --- scanners, each verified before it is trusted -----------------------------
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) asset="x64";   digest="${GITLEAKS_SHA256_amd64}" ;; \
      arm64) asset="arm64"; digest="${GITLEAKS_SHA256_arm64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${asset}.tar.gz"; \
    echo "${digest}  /tmp/gitleaks.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tar.gz; \
    gitleaks version

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) digest="${OSV_SCANNER_SHA256_amd64}" ;; \
      arm64) digest="${OSV_SCANNER_SHA256_arm64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}"; \
    echo "${digest}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/osv-scanner; \
    osv-scanner --version

COPY --from=ghcr.io/astral-sh/uv:0.9.5 /uv /usr/local/bin/uv

WORKDIR /app

# Dependencies before source, so editing a template does not reinstall the world.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# Semgrep is a scanner, not a library the app imports, so it is installed beside
# the app rather than added to its dependency graph.
RUN uv pip install --python /opt/venv "semgrep==1.145.0"

COPY src/ ./src/
COPY scripts/ ./scripts/
COPY rules/ ./rules/
COPY eval/ ./eval/
COPY samples/ ./samples/

# Nothing here needs privilege. The data directory is the only writable path,
# and it is a volume, so the image itself can stay read-only at runtime.
RUN useradd --create-home --uid 10001 ares \
 && mkdir -p /data \
 && chown -R ares:ares /data /app
USER ares

# Scanners are handed a scrubbed environment (PATH/HOME/LANG only), and semgrep
# insists on writing a settings file under HOME. Pointing HOME at a tmpfs is what
# lets the rest of the filesystem stay read-only at runtime, rather than
# widening the scanner environment to carry a semgrep-specific variable.
ENV HOME=/tmp/ares-home \
    ARES_BIND=0.0.0.0 \
    ARES_OLLAMA_HOST=http://ollama:11434

EXPOSE 8420
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8420/',timeout=4)" || exit 1

ENTRYPOINT ["python", "scripts/serve_dashboard.py"]
CMD ["--db", "/data/ares.db", "--workdir", "/data/work", "--port", "8420"]
