#!/bin/sh
# Cut a release tag and produce the stamped installer that pins it.
#
# A tag can be moved, so the installer verifies the commit the tag resolves to.
# That pin cannot live in the tagged commit itself - a commit cannot contain its
# own hash - so the installer is published as a RELEASE ASSET generated after the
# tag exists, and the in-tree install.sh stays unstamped.
#
# Result: the file a user curls names both the tag and the exact commit, and a
# moved tag makes it abort.
set -eu

TAG="${1:?usage: scripts/release.sh vX.Y.Z}"
cd "$(dirname "$0")/.."

[ -z "$(git status --porcelain)" ] || { echo "working tree is dirty" >&2; exit 1; }

git tag -a "$TAG" -m "ARES $TAG"
COMMIT="$(git rev-parse "$TAG^{commit}")"

mkdir -p dist
sed "s|^PINNED_COMMIT=.*|PINNED_COMMIT=\"$COMMIT\"|; s|^PINNED_TAG=.*|PINNED_TAG=\"$TAG\"|" \
    install.sh > dist/install.sh
chmod +x dist/install.sh
sh -n dist/install.sh

DIGEST="$(shasum -a 256 dist/install.sh | cut -d' ' -f1)"
cat <<SUMMARY

tagged   $TAG -> $COMMIT
asset    dist/install.sh
sha256   $DIGEST

Publish, then put that sha256 in INSTALL.md:

    git push origin main --follow-tags
    gh release create $TAG dist/install.sh --title "ARES $TAG" --notes-file INSTALL.md

Install command for the README:

    curl -fsSLO https://github.com/amateur-ai-dev/ares/releases/download/$TAG/install.sh
    shasum -a 256 install.sh   # expect $DIGEST
    sh install.sh
SUMMARY
