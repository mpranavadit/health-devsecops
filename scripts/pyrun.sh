#!/usr/bin/env bash
# Run a shell command inside a throw-away python container as the CURRENT user
# (so files written to the Jenkins workspace are not owned by root).
# Usage: bash scripts/pyrun.sh "pip install --user -q bandit && python -m bandit -r src"
set -euo pipefail
exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
  -v "$PWD:/src" -w /src \
  python:3.11-slim sh -c "$*"
