# Genestack Keystone admin password rotation

Staged implementation of the Genestack Keystone administrative
password-rotation tool. Slices 1-3 and Slice 4A are complete. The CLI remains focused on
topology inspection and planning, while bounded library workflows can establish
or reconcile breakglass and move the canonical admin credential through
A0 -> A1 -> A2 -> A3. There is no complete end-to-end rotation command yet.

```
contract YAML -> validated immutable types -> Secret inventory
             -> structural credential reads -> reference-relative classification
             -> undeclared-copy audit -> credential-free topology report
```

Slices 1, 2A, 2B, 2C, 3A, 3B, 3C, 3D, 3E, and 4A are implemented. PREPARE_B is a real
library workflow: it may update only the breakglass credential in PasswordSafe
and Keystone, with durable intent, ownership checks, fresh observation, and
postcondition verification. Slice 3C observes and reconciles A state without
mutation. Slice 3D uses that observation to start only from A0, validates fresh
breakglass authority, suppresses admin lockout, and conditionally stages A-new in
the canonical breeder with transaction provenance. It succeeds only after fresh
observation establishes A1, leaving lockout suppressed and restoration required.
Slice 3E recovers the exact staged A-new from the breeder, resets the recorded
Keystone admin user from A1, requires fresh A2, updates and reads back the exact
PasswordSafe admin record, and requires fresh A3. It does not generate or stage a
credential, and it leaves lockout suppressed with restoration still required.

The implemented canonical `ROTATE_A` write order is breeder -> Keystone ->
PasswordSafe, with forward recovery across A0/A1/A2/A3. These library workflows
are not exposed as an end-to-end CLI runner. Runtime `SWITCH_TO_B` and `VERIFY_B`
remain required before production execution may enter `ROTATE_A`; the ability to
invoke its bounded primitives independently does not weaken that gate.

Slice 4A adds a library primitive that safely mutates one validated contracted
`role: propagated` location to an explicitly supplied allowed admin or breakglass
credential. It structurally updates fields, INI, direct YAML, or nested YAML;
requires a recognized caller-permitted observed state; revalidates current
execution ownership; uses Secret UID/resourceVersion preconditions; and rereads,
reparses, and verifies the exact target. Candidate no-ops also revalidate
ownership and freshly verify the same Secret UID and target credential before
returning `UNCHANGED`. The caller must supply a target credential already proven
authoritative by its higher-level reconciliation. Results distinguish changed
from no-op and retain configured restart metadata without executing it. Conflicts, unsafe
observations, Kubernetes failures, ambiguous writes, and verification failures
are typed, credential-free errors.

There is still no propagation-wave or phase runner. Grouping per-Secret writes,
persisting propagation/action obligations, restart execution, rollout waiting,
runtime/service verification, restoration of all consumers to admin,
`SWITCH_TO_B`, `VERIFY_B`, `SWITCH_TO_A`, `VERIFY_A`, lockout restoration, and
final transaction completion remain unimplemented. Lockout suppression needed by
`ROTATE_A` is implemented, but the current Slice 3 path leaves it suppressed with
restoration still required.

The Slice 2 boundaries use the Kubernetes Python API directly, while the external
clients use `httpx`. The separate Slice 1 live planning adapter runs only `kubectl
get secrets -o json` in an explicitly named context. Offline fixture mode does
not invoke kubectl.

Slice 3A PasswordSafe support is limited to Rackspace Identity token acquisition,
current-credential JSON reads and password-only JSON updates. Historical
PasswordSafe retrieval is not implemented. Exact old-A history remains a deferred
exceptional recovery capability from the implementation brief; Slice 3C
demonstrates that A0-A3 reconciliation does not require it, and no current client
exposes `get_exact_history_version()`.

The Lease defaults are a 120-second duration, 20-second renewal interval and
60-second renewal deadline. This is cooperative ownership, not hard fencing:
expiry or takeover does not prove that an old process cannot reach an external
service, so mutation workflow code must still reobserve and apply recovery gates.

## Install and run locally

The project targets Python 3.12. Create and use the project-local virtual
environment; project validation does not fall back to system Python.

```sh
cd ops-tools/admin-password-rotation
python3.12 -m venv .venv
./.venv/bin/python -m pip install -e '.[dev]'

./.venv/bin/python -m pyright
./.venv/bin/python -m pytest -q
./scripts/check.sh
./.venv/bin/python -m admin_password_rotation --help
```

The installed console command `admin-password-rotation` is equivalent to
`./.venv/bin/python -m admin_password_rotation`. No root-level Genestack files
need changing. `./scripts/check.sh` is the complete local check entry point and
runs the current Pyright, pytest, contract-validation, and planning smoke checks.

## Start without a cluster

Both committed snapshots contain **invented synthetic credentials and metadata**.
They are examples of SecretList API shape, not redacted production exports.

```sh
./.venv/bin/admin-password-rotation validate-contract \
  --contract config/credential-contract.yaml

./.venv/bin/admin-password-rotation plan \
  --contract config/credential-contract.yaml \
  --snapshot tests/fixtures/dfw-dev-stable.json

./.venv/bin/admin-password-rotation plan \
  --contract config/credential-contract.prod.yaml \
  --snapshot tests/fixtures/prod-stable.json --format json
```

The DFW-DEV fixture resolves 24 locations; the production fixture resolves 22.
Each also includes one unrelated Secret to exercise namespace-wide inspection.
A clean fixture derives eight **potential** workload restart dependencies, without
planning or performing any restart. Each dependency retains its causing locations.

Every report says:

```json
{
  "scope": "topology_only",
  "comparison_basis": "unverified_canonical_breeder",
  "authoritative_state_verified": false,
  "rotation_ready": false,
  "planned_mutations": [],
  "executed_actions": []
}
```

A successful topology check means only that the checks implemented here passed.
It does not mean that the password works, PasswordSafe agrees, breakglass is ready,
a previous transaction is absent, or the affected services are healthy.

## Read a lab cluster

Review the configuration first, use a trusted kubeconfig, and use a credential
limited to listing Secrets in `openstack` where practical. Listing Secrets exposes
sensitive data to this process; read-only is not the same as low privilege.

```sh
kubectl config get-contexts -o name

# Replace LAB_CONTEXT with the context you deliberately selected.
./.venv/bin/admin-password-rotation plan \
  --contract config/credential-contract.yaml \
  --live --context LAB_CONTEXT --timeout 60 --format json
```

`--live` and `--context` are both required. There is no implicit use of the current
context. An optional `--kubeconfig /path/to/config` selects a specific file. No
TLS bypass flags are added. The adapter captures raw subprocess output and does
not echo it on failure. Kubeconfig authentication plugins can themselves execute
local code or refresh credentials: the planning command's no-mutation claim does
not cover all behavior of an external authentication plugin.

The live adapter uses **kubectl rather than the Python Kubernetes SDK** for this
read-only planning path. This is a bounded Slice 1 implementation choice, not the
state-persistence architecture: `KubernetesReader` returns immutable snapshots,
while Slice 2B transaction-state persistence uses the Kubernetes Python API client.

A snapshot may also be piped through stdin, avoiding a persistent raw export:

```sh
set -o pipefail  # bash/zsh; do not ignore a failed upstream kubectl command
kubectl --context LAB_CONTEXT -n openstack get secrets -o json |
  ./.venv/bin/admin-password-rotation plan \
    --contract config/credential-contract.yaml --snapshot - --format json
```

Do not enable shell tracing, commit a real SecretList, or upload one to a coding
agent. The `.gitignore` excludes `local/` and `*.local.json` as a convenience, not
a security control. The tool does not persist live snapshots, passwords or tokens.

## Pick the expected contract explicitly

| File | Meaning |
| --- | --- |
| `config/credential-contract.yaml` | Supplied current contract, preserved unchanged. Includes Freezer and Trove: 24 locations. |
| `config/credential-contract.prod.yaml` | Derived example removing only the Freezer/Trove blocks: 22 locations. |

Comments such as "Currently dfw-dev only" do not make entries optional. Every entry
in the selected file is required. Production and lab inventories may change: review
the chosen file against the intended environment. There is no auto-detection or
"skip missing" fallback. A profile mismatch produces blocking findings.

The inherited os-metrics `MISSING INFO` comment is deliberately preserved even
though the supplied entry names a Deployment. Workload existence/ownership is not
validated here. The later `openstack-admin-client` pod recreation action is also
not represented by this slice's `restart` schema; see `docs/HANDOFF.md`.

## Output and exit status

| Exit | Meaning |
| --- | --- |
| `0` | Contract validation or implemented topology checks passed. **Not rotation readiness.** |
| `3` | Topology/credential findings require review. No automatic repairs. |
| `2` | Invalid configuration/input or failed read. |
| `1` | Unexpected error or broken output pipe; sensitive diagnostic content withheld. |
| `130` | Interrupted by the operator. |

`matches_admin_reference` means the declared credential components match the
breeder comparison value. The breeder is not authenticated in this slice.
`unverified_breakglass` means a location names breakglass but no independent B
reference is available. It is a finding, not evidence that B is correct.

The broad audit scans decoded Secret data for the known breeder password outside
accepted password selectors. It also notices uncontracted `OS_USERNAME` fields
naming admin/breakglass. It does **not** claim to discover every unknown, historical,
compressed or alternatively encoded administrative credential. Full transaction
planning must close or explicitly account for these gaps.

## Repository orientation

`src/admin_password_rotation/` contains the typed application and
supporting libraries. `tests/` contains the executable behavior
contract. Start coding-agent work with `AGENTS.md` and
`docs/HANDOFF.md`. `docs/DESIGN.md` describes the architecture currently
implemented, while `docs/reference/README.md` explains the authority and
status of the retained design references.
