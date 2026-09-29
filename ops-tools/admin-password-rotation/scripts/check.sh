#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python -m pyright
python -m pytest -q
python -m admin_password_rotation validate-contract --contract config/credential-contract.yaml
python -m admin_password_rotation validate-contract --contract config/credential-contract.prod.yaml
python -m admin_password_rotation plan --contract config/credential-contract.yaml --snapshot tests/fixtures/dfw-dev-stable.json --format json >/dev/null
python -m admin_password_rotation plan --contract config/credential-contract.prod.yaml --snapshot tests/fixtures/prod-stable.json --format json >/dev/null
