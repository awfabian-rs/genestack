# Genestack Keystone admin password rotation

Staged implementation of the Genestack Keystone administrative
password-rotation tool. Slices 1-3 and Slices 4A-4F are complete. The CLI remains focused on
topology inspection and planning, while bounded library workflows can establish
or reconcile breakglass, move the canonical admin credential through
A0 -> A1 -> A2 -> A3, compose the ``SWITCH_TO_B`` cutover, and verify the B
safety bridge before ``ROTATE_A``. There is no complete
end-to-end rotation command yet.

```
contract YAML -> validated immutable types -> Secret inventory
             -> structural credential reads -> reference-relative classification
             -> undeclared-copy audit -> credential-free topology report
```

Slices 1, 2A, 2B, 2C, 3A, 3B, 3C, 3D, 3E, 4A, 4B, 4C, 4D, 4E, and 4F are implemented. PREPARE_B is a real
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
are implemented library gates before production execution may enter `ROTATE_A`;
the ability to invoke its bounded primitives independently does not weaken that
gate.

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

Slice 4B adds pure complete-set propagation-wave planning and reconciliation.
For a requested admin or breakglass target it derives every applicable propagated
contract location, deterministically groups logical locations that share a Secret,
records their original classified state and potential restart dependencies, and
can persist that credential-free intent in the existing transaction state under
the existing ownership boundary. Resume retains the immutable stored intent and
reconciles it against fresh Secret reality; progress is only a hint. Contract
drift, missing or replaced Secrets, unparseable or unknown credentials, and
unexplained state changes fail closed. Already-converged locations remain in the
complete obligation and require no planned mutation.

Slice 4C adds grouped Secret-level propagation execution and crash/recovery.
It consumes the durable Slice 4B wave intent, performs a safe pre-reconciliation
pass over every Secret group (fresh GET, per-location classification, UID
continuity check), and then re-observes each group freshly immediately before it
is processed so the no-op-versus-mutation decision and the CAS precondition both
come from a fresh snapshot rather than the earlier precheck. It composes the
required transformations on an evolving in-memory Secret (reusing Slice 4A's
structural machinery) and issues at most one CAS-protected JSON Patch per Secret
group; multiple logical locations sharing one Secret data key are all mutated
together in deterministic order. After each write it freshly rereads the Secret
and verifies every logical location in the group against the target credential.
It records which logical locations actually changed (distinguishing changed from
already-converged), reasserts execution ownership before each durable progress
write, persists that progress after each successfully processed group through the
existing transaction state, and retains the resulting restart
dependencies for the later restart-debt slice without executing any restart.
An originally-non-target location observed at target during recovery but with no
applied marker is conservatively treated as a transition that occurred during the
wave lifetime, retaining its restart debt. Unknown, malformed, replaced, or
regressed state fails closed with no write. The Kubernetes Secret is the mutation
unit; the logical credential location is the verification/accounting unit; the
propagation wave is the transaction unit.

Slice 4D adds the restart/action executor and restart-debt recovery layer. It
consumes Slice 4C's durable changed-location accounting, validates the current
contract's digest against the wave intent, derives and deduplicates the
workload restart actions owed by the changed locations, and executes each one
through the Kubernetes API (a strategic-merge patch on the target Deployment or
DaemonSet's Pod template, setting `spec.template.metadata.annotations` with the
`kubectl.kubernetes.io/restartedAt` marker). It observes each resulting rollout
to completion with a bounded poll, requiring generation convergence
(`observedGeneration >= metadata.generation`) and a matching restart marker. It
persists per-action progress (PENDING/RUNNING/COMPLETE) in the wave's durable
state; the RUNNING write fences ownership, and ownership is reasserted
immediately before the Kubernetes dispatch. A durable COMPLETE is a discharged
obligation: it was written only after a successful rollout observation and is
not re-observed or re-dispatched by a subsequent execution. On resume, PENDING
and RUNNING actions re-observe the workload rather than trusting the last
attempted action: an already-restarted, complete rollout is confirmed without
re-dispatch, and an unverifiable restart is conservatively re-dispatched. The
restart marker is a compact SHA-256 digest of the wave's immutable intent
tuple, derived deterministically. Unexpected durable runtime action IDs fail
closed with `STALE_RUNTIME_ACTIONS`. It performs no credential mutation and
advances no runtime phase.

Slice 4E adds the transaction-level `SWITCH_TO_B` orchestration. It composes the
Slice 4B propagation-wave planning/reconciliation, the Slice 4C grouped
Secret-level propagation execution, and the Slice 4D restart/action executor into
a single re-entrant phase runner. Starting from a transaction whose `PREPARE_B`
has completed (phase `SWITCH_TO_B`, breakglass generation established), it
recovers the authoritative B credential freshly from PasswordSafe and validates
it by fresh breakglass authentication, then plans-or-reconciles and durably
persists the immutable to-B propagation obligation, executes the grouped
propagation wave so every contracted `identity: active` location converges to the
breakglass credential, executes and recovers the resulting restart debt, and
finally advances the durable phase to `VERIFY_B`. Fixed `identity: admin`
locations and the canonical `keystone-admin` breeder are never switched to B.
`SWITCH_TO_B` is interruption-safe: re-entry observes the durable wave intent,
applied-location progress, and runtime-action state and continues without replaying
completed Secret writes or workload restarts. It performs no `VERIFY_B`
service/authentication health verification and does not enter `ROTATE_A`.

Slice 4F adds the transaction-level `VERIFY_B` gate: `run_verify_b()` in
`verify_b.py`. It freshly establishes, from current observed state only, that
the B safety bridge created by `SWITCH_TO_B` is real and sufficient to permit
`ROTATE_A` to begin. It is observational: it never writes a propagated Secret,
never dispatches or re-runs a workload restart, and never mutates the `admin`
credential. The only durable write is the single ownership-fenced phase
advance to `ROTATE_A` after every required check succeeds.

The verification is:

1. fresh breakglass observation (current PasswordSafe B record, generation
   must match the transaction's B generation) plus a fresh, correctly-scoped
   breakglass Keystone authentication — stale evidence from earlier phases is
   explicitly rejected;
2. fresh structural classification of every participating `identity: active`
   propagated location (the complete applicable contract membership, not the
   changed-location progress): each must parse through its declared
   representation and structurally equal the verified breakglass credential —
   missing Secrets, malformed representations, unknown credentials, locations
   still on `admin`, or a different breakglass password all fail the gate.
   Fixed `identity: admin` locations do not participate in the B identity
   transition: they are required to match the verified admin reference and
   fail closed on any other state (including a breakglass credential — a
   password-only fixed-admin consumer interprets the stored password as
   belonging to `admin` — a missing Secret, a malformed representation, or a
   wrong admin password). The `keystone-admin` breeder is re-read and required
   to still anchor the durable `stable-a` receipt;
3. every restart action derived from the B wave's durable changed-location
   accounting (the same derivation `SWITCH_TO_B` executed, with contract-digest
   and stale-action validation) must be durably `COMPLETE`;
4. every affected Deployment/DaemonSet must be freshly observed rolled out and
   ready (generation convergence, replica counters, and the deterministic
   restart marker for this wave in the Pod template), reusing the Slice 4D
   workload abstraction and completion predicate.

Durable progress flags are never accepted as proof: a record claiming
propagation/restart completion while fresh Secret or workload state disagrees
fails closed, and the transaction remains in `VERIFY_B` for re-observation.
A failed verification persists nothing except the credential-free execution
bookkeeping re-stamp performed on resume; it never writes a
`verify-b-complete` receipt and never advances the phase. Re-entry is
deterministic: only genuine successor phases (`ROTATE_A`, `SWITCH_TO_A`,
`VERIFY_A`) are reported `ALREADY_ADVANCED` without re-running checks or
regressing the phase; predecessor phases (`STABLE_A`, `PREPARE_B`,
`SWITCH_TO_B`) are rejected as `UNSUPPORTED_PHASE`; and a crash after the
checks but before the phase advance simply re-runs them. Fixed
`identity: admin` locations and the canonical breeder are never switched to B
or required to hold B. It performs no `ROTATE_A`, no A credential mutation,
no `SWITCH_TO_A` / `VERIFY_A`, no lockout restoration, no final transaction
completion, and no packaging.

The Slice 2 boundaries use the Kubernetes Python API directly, while the external
clients use `httpx`. The separate Slice 1 live planning adapter runs only `kubectl
get secrets -o json` in an explicitly named context. Offline fixture mode does
not invoke kubectl.

Lockout suppression needed by `ROTATE_A` is implemented, but the current
Slice 3 path leaves it suppressed with restoration still required; restoration
remains later work.

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
