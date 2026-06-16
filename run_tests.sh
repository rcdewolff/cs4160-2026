#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    ACTIVATE_PATH="$SCRIPT_DIR/.venv/bin/activate"
elif [ -f "$SCRIPT_DIR/.venv/Scripts/activate" ]; then
    ACTIVATE_PATH="$SCRIPT_DIR/.venv/Scripts/activate"
else
    echo "ERROR: Could not find .venv activation path"
    exit 1
fi

source "$ACTIVATE_PATH"

cleanup() {
    echo "Cleaning up temp directories..."
    find "$SCRIPT_DIR" -type d -name "*_temp_*" -exec rm -rf {} + 2>/dev/null || true
}
trap cleanup EXIT

if [ $# == 1 ]; then
    python -m unittest $1
else
    python -m unittest discover -s tests -p "*_tests.py"
fi
