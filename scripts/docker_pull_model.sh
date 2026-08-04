#!/bin/sh
# Pull the local selection model into the compose Ollama volume.
#
# Separate from `docker compose up` on purpose: it is a multi-gigabyte download,
# and a compose file that silently pulls gigabytes on first start is a compose
# file people stop trusting.
set -eu
model="${1:-qwen2.5:7b-instruct}"
printf 'Pulling %s into the ares-ollama container...\n' "$model"
docker compose exec ollama ollama pull "$model"
printf 'Done. Reload http://127.0.0.1:8420/ and it will appear in the model list.\n'
