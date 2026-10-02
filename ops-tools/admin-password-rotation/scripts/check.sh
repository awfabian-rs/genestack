#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

PYTHON="$VENV_DIR/bin/python"

if [ ! -x "$PYTHON" ]; then
    echo "error: project virtualenv not found or unusable: $VENV_DIR" >&2
    exit 1
fi

cd "$(dirname "$0")/.."
$PYTHON -m pyright
$PYTHON -m pytest -q
$PYTHON -m admin_password_rotation validate-contract --contract config/credential-contract.yaml
$PYTHON -m admin_password_rotation validate-contract --contract config/credential-contract.prod.yaml
$PYTHON -m admin_password_rotation plan --contract config/credential-contract.yaml --snapshot tests/fixtures/dfw-dev-stable.json --format json >/dev/null
$PYTHON -m admin_password_rotation plan --contract config/credential-contract.prod.yaml --snapshot tests/fixtures/prod-stable.json --format json >/dev/null
