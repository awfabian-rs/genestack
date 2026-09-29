# Bootstrap validation record

Date: September 29, 2026. Environment: Linux, CPython 3.13.5.

## Executed

| Check | Result |
| --- | --- |
| `python -m pytest -q` with coverage | **119 passed** |
| pytest-cov statement/branch summary | **94%** reported combined coverage |
| `python -m compileall -q src tests` | Passed |
| Supplied DFW-DEV contract validation | 24 locations |
| Derived production contract validation | 22 locations |
| DFW-DEV synthetic topology | 24 resolved locations, 8 potential dependencies, no findings |
| Production synthetic topology | 22 resolved locations, 8 potential dependencies, no findings |
| Both clean synthetic reports | `rotation_ready: false`; zero planned/executed mutations |
| Wrong profile against synthetic inventory | Nonzero findings/exit 3; no silent optionality |
| Editable package install | Passed using existing offline dependencies |
| Installed console command from outside source directory | Passed, including production fixture plan |
| Non-editable wheel build | Passed |
| Original contract preservation | Byte-for-byte equal to supplied file |

The module entry point and stdin mode are tested in a child process; that execution
is not included in the parent pytest coverage measurement. The coverage percentage
is not an assurance of operational readiness or absence of defects.

Tested dependency versions: PyYAML 6.0.3, pytest 9.0.2, pytest-cov 7.0.0,
setuptools 82.0.1. The package metadata uses bounded version ranges, not a fully
resolved dependency lock. A fresh online dependency installation remains to be
checked by the next engineer/CI.

## Not executed

**Pyright strict was not run.** Pyright is not installed in this execution
environment. Attempts to obtain missing packages failed because network/DNS
access was unavailable. No passing type-check claim is made. The next required
local check is:

```sh
python -m pip install -e '.[dev]'
python -m pyright
```

No live Kubernetes, PasswordSafe or Keystone endpoint was accessed. The live
adapter's command construction, errors, timeout handling and namespace/context
checks were exercised with fakes/mocks. There has been no actual Kubernetes RBAC,
TLS, authentication-plugin or kubectl-version compatibility test.

Python 3.11/3.12 and macOS/BSD execution have not been tested. The declared minimum
is Python 3.11, and Pyright targets 3.11, but that configuration is not proof of
execution on those platforms.

## Test scope

Tests cover strict configuration, profile differences, named representation lookup,
identity/role validation, required restart declarations, malformed base64/JSON,
duplicate keys, namespace mismatch, incomplete pagination, synthetic fields/INI/
YAML/embedded YAML, literal interpolation characters, explicit rather than inherited
INI options, unknown/unverified credentials, causal dependency deduplication,
undeclared copies in the same Secret/document, escaped YAML, captured-error
sanitization, CLI exit status, stdin mode and explicit live opt-in.

The limited broad audit is tested as limited: an unknown credential in an arbitrary
unrecognized format may not be discovered, and even a clean report remains not
rotation-ready. Source inventory coverage and workload runtime behavior still need
lab validation and the later authoritative-planning slice.

## Reproduce locally

```sh
python -m pip install -e '.[dev]'
python -m pyright
python -m pytest --cov=admin_password_rotation --cov-report=term-missing -q
./scripts/check.sh
```

For the offline bootstrap install, an isolated venv was supplied a `.pth` reference
to already installed dependencies; pip used `--no-build-isolation --no-deps`.
That workaround is not part of the shipped source or normal install instructions.

Original contract SHA-256:

```
a8f618862fd49d79ed4bc274e0117a4bbcfcb9bb1d3b05ffffd187a759a3e2c3
```
