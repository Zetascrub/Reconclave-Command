#!/usr/bin/env bash
# Build (if needed) and launch the Reconclave desktop coordinator.
#
# Usage: ./start-desktop.sh [extra desktop_app.py args]
# Example: ./start-desktop.sh --enable-network-scan --evidence-dir ./evidence
#
# RECONCLAVE_EXECUTION_KEY / RECONCLAVE_EVIDENCE_KEY in the environment are
# picked up by desktop_app.py itself -- see tools/desktop-node/README.md.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$ROOT_DIR"
WEB_DIR="$DESKTOP_DIR/web"
VENV_DIR="$ROOT_DIR/.venv-desktop-node"

if [ ! -x "$VENV_DIR/bin/python" ]; then
    echo "==> Creating desktop-node virtualenv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -r "$DESKTOP_DIR/requirements.txt"
fi

if [ ! -d "$WEB_DIR/node_modules" ]; then
    echo "==> Installing web dependencies"
    (cd "$WEB_DIR" && npm ci)
fi

# Rebuild the web UI only when it's missing or source is newer than the last build,
# so a normal launch doesn't pay the build cost every time.
if [ ! -d "$WEB_DIR/dist" ] || [ -n "$(find "$WEB_DIR/src" "$WEB_DIR/package.json" -newer "$WEB_DIR/dist" -print -quit 2>/dev/null)" ]; then
    echo "==> Building web UI"
    (cd "$WEB_DIR" && npm run build)
fi

echo "==> Starting desktop coordinator (http://127.0.0.1:8767)"
cd "$DESKTOP_DIR"
exec "$VENV_DIR/bin/python" desktop_app.py --mode both "$@"
