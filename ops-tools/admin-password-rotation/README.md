# Genestack Keystone admin password rotation

First draft of the first implementation slice for Genestack. Intended location:
`ops-tools/admin-password-rotation/`. This is a working topology inspector with
synthetic tests, **not a password rotator and not a production approval gate**.

```
contract YAML -> validated immutable types -> Secret inventory
             -> structural credential reads -> reference-relative classification
             -> undeclared-copy audit -> credential-free topology report
```

There are no rotation commands, restart operations or workflow-driven credential
writes. Slice 2B provides conditional transaction-state persistence, Slice 2C
provides cooperative execution ownership, and Slice 3A provides typed direct-HTTP
Keystone, Rackspace Identity and PasswordSafe client primitives. None is wired to
the CLI. The Slice 2 boundaries use the Kubernetes Python API directly; Slice 3A
uses `httpx`. The separate Slice 1 live planning adapter runs only `kubectl get
secrets -o json` in an explicitly named context. Offline fixture mode does not
invoke kubectl.

Slice 3A PasswordSafe support is limited to Rackspace Identity token acquisition,
current-credential JSON reads and password-only JSON updates. Historical
PasswordSafe retrieval is not implemented in Slice 3A. Exact old-A history remains
a deferred exceptional recovery capability from the implementation brief and will
be implemented only if and when the later A-recovery slice requires it.

The Lease defaults are a 120-second duration, 20-second renewal interval and
60-second renewal deadline. This is cooperative ownership, not hard fencing:
expiry or takeover does not prove that an old process cannot reach an external
service, so later workflow code must still reobserve and apply recovery gates.

## Install and run locally

Use Python 3.11 or newer. The validation environment used Python 3.13.5;
compatibility with other interpreter versions still needs a local/CI run.

```sh
cd ops-tools/admin-password-rotation
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'

python -m pytest -q
python -m pyright
python -m admin_password_rotation --help
```

The installed console command `admin-password-rotation` is equivalent to
`python -m admin_password_rotation`. No root-level Genestack files need changing.
The complete local check entry point is `./scripts/check.sh`.

**Validation status:** pytest and installation/CLI smoke tests were executed.
Pyright strict is configured but was **not executed** in the bootstrap environment:
Pyright was unavailable and network/package downloads were blocked. Run it locally
before treating this as type-checked. See `docs/VALIDATION.md` for exact results.

## Start without a cluster

Both committed snapshots contain **invented synthetic credentials and metadata**.
They are examples of SecretList API shape, not redacted production exports.

```sh
admin-password-rotation validate-contract \
  --contract config/credential-contract.yaml

admin-password-rotation plan \
  --contract config/credential-contract.yaml \
  --snapshot tests/fixtures/dfw-dev-stable.json

admin-password-rotation plan \
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
admin-password-rotation plan \
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
  admin-password-rotation plan \
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

`src/admin_password_rotation/` contains the small typed application. `tests/`
contains the executable behavior contract. Start the next coding-agent session
with `AGENTS.md` and `docs/HANDOFF.md`. `docs/DESIGN.md` records bootstrap choices
and limitations; `docs/SOURCE-NOTES.md` separates source requirements from those
choices. `docs/VALIDATION.md` records what was actually tested.
