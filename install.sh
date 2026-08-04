#!/bin/sh
# ARES installer.
#
#   curl -fsSLO https://github.com/amateur-ai-dev/ares/releases/download/v0.1.0/install.sh
#   shasum -a 256 install.sh    # compare against the value in INSTALL.md
#   sh install.sh
#
# Piping a script from the internet into a shell is a bad habit, and saying so is
# more useful than pretending otherwise. What makes this specific one defensible
# is what it refuses to do:
#
#   * It pins a TAG, never a branch. `main` is mutable - a force-push, or an hour
#     of compromised write access, changes what a branch-pinned installer runs.
#     A tag is checked out and then its commit is compared against the hash
#     recorded below, so moving the tag is not enough either.
#   * It refuses to run as root. Nothing here needs privilege, and an installer
#     that quietly accepts root is an installer that can quietly own the machine.
#   * It never pipes anything else into a shell, and it never runs a downloaded
#     binary. The toolchain step downloads Hayabusa and checks it against
#     datasets.lock before extracting it.
#   * It touches exactly one directory and tells you which one first.
#
# The published copy is a RELEASE ASSET, not this file. A commit cannot contain
# its own hash, so scripts/release.sh stamps PINNED_COMMIT into the asset after
# the tag exists. This in-tree copy is the source; the asset is what to curl.
#
set -eu

REPO_URL="https://github.com/amateur-ai-dev/ares.git"
PINNED_TAG="v0.1.0"
# Stamped by scripts/release.sh into the published asset. Empty here on purpose:
# an unstamped copy warns loudly rather than silently degrading to "whatever the
# tag points at today".
PINNED_COMMIT=""
INSTALL_DIR="${ARES_HOME:-$HOME/ares}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    die "refusing to run as root. ARES needs no privilege; re-run as your own user."
fi

for tool in git curl python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required but not installed."
done

say "ARES installer"
say "  repository: $REPO_URL"
say "  pinned tag: $PINNED_TAG"
say "  install to: $INSTALL_DIR"
say ""

if [ -e "$INSTALL_DIR" ]; then
    die "$INSTALL_DIR already exists. Move it aside, or set ARES_HOME to another path."
fi

# --branch with a tag gives a detached checkout of exactly that tag. HTTPS only:
# no git:// and no ssh fallback, so the transport is authenticated.
git clone --quiet --depth 1 --branch "$PINNED_TAG" "$REPO_URL" "$INSTALL_DIR" \
    || die "clone failed. If the repository is private, authenticate first (gh auth login) and re-run."

cd "$INSTALL_DIR"
ACTUAL_COMMIT="$(git rev-parse HEAD)"

if [ -n "$PINNED_COMMIT" ]; then
    if [ "$ACTUAL_COMMIT" != "$PINNED_COMMIT" ]; then
        cd /
        rm -rf "$INSTALL_DIR"
        die "commit mismatch: tag $PINNED_TAG points at $ACTUAL_COMMIT, expected $PINNED_COMMIT.
     The tag has been moved since this installer was published. Nothing was installed."
    fi
    say "commit verified: $ACTUAL_COMMIT"
else
    say "WARNING: this installer carries no pinned commit, so a moved tag would not"
    say "         be detected. Checked out $ACTUAL_COMMIT."
fi

say ""
say "Source is in place. Next, the toolchain (Hayabusa, Python dependencies):"
say ""
say "    cd $INSTALL_DIR"
say "    ./scripts/setup_toolchain.sh"
say ""
say "Then start the dashboard:"
say ""
say "    uv run python scripts/serve_dashboard.py"
say "    open http://127.0.0.1:8420/"
say ""
# The toolchain step is deliberately NOT run automatically. It downloads a
# release binary and installs dependencies; a person who piped this script into a
# shell should get to see that command before it runs, not after.
say "Nothing was downloaded beyond the source tree. No network calls are made at"
say "analysis time - ARES runs entirely on this machine."
