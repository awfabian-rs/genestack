# Handoff to the next engineer or coding agent

## Current project state

This directory contains a staged implementation of the Genestack/OpenStack Keystone administrative password-rotation tool.

The project is no longer a read-only bootstrap.

Implemented work currently includes:

```text
Slice 1
    typed configuration and credential-location contract
    structural credential readers
    namespace discovery
    credential classification
    bounded extra-copy audit
    dependency derivation
    read-only planning and reporting

Slice 2A
    strict schema-v2 durable transaction-state model

Slice 2B
    Kubernetes API-backed persistence of state.json
    UID/resourceVersion conditional writes
    read-after-write verification

Slice 2C
    cooperative Kubernetes Lease ownership
    execution-specific holder identity
    renewal watchdog
    sticky ownership loss/uncertainty
    clock-skew-safe foreign-owner takeover observation
    conditional release

Slice 3A
    secret-safe direct HTTP transport
    Keystone v3 password authentication
    Keystone exact-user password mutation
    Keystone lockout-option observation/mutation
    Rackspace Identity Internal v2 authentication
    PasswordSafe current-credential JSON retrieval
    PasswordSafe password-only mutation
    secure administrative-password generation
    behavioral Keystone and PasswordSafe fakes
```

The CLI remains primarily read-only/planning-oriented. The existence of lower-level mutation-capable clients does not mean the rotation workflow is implemented.

No production workflow currently performs PREPARE_B or ROTATE_A.

## Read these first

Before changing this package, read:

```text
AGENTS.md
docs/DESIGN.md
docs/reference/README.md
docs/reference/keystone-admin-rotation-implementation-brief.md
```

Consult the older implementation specification only for detail that has not been superseded.

Where design sources conflict, follow the authority order documented in `AGENTS.md` and `docs/reference/README.md`.

Do not infer current implementation requirements from old bootstrap prose.

## Current implementation boundary

The code intentionally separates:

```text
external observation
    ->
validation / typed representation
    ->
classification
    ->
workflow decision
    ->
persist intent
    ->
assert ownership
    ->
perform effect
    ->
read back / verify actual state
    ->
record progress
```

Do not collapse these layers merely to reduce code.

In particular:

- transport/client adapters do not advance rotation phases;
- durable transaction state is memory, not authority over external reality;
- progress may lag a successfully completed external effect;
- mutation ambiguity must be resolved by reobservation;
- Lease ownership is cooperative exclusion, not hard external fencing;
- stale plans or state snapshots are never authority to overwrite current external state.

## Important invariants

Preserve these unless a later explicit design amendment changes them.

### Administrative identities

```text
A = admin
B = breakglass
```

`admin` is the canonical deployment identity.

`breakglass` is a durable alternate administrative account used as the temporary safety path during rotation.

Successful rotation returns managed consumers to `admin`.

### Breeder

```text
Secret/openstack/keystone-admin
data.password
```

always semantically represents the password for `admin`.

It must never temporarily contain the breakglass password.

### Stable admin authority

In stable state:

```text
PasswordSafe(admin)
    ==
Secret/openstack/keystone-admin.data.password
    ==
credential that freshly authenticates as admin
```

Unexplained disagreement is an error.

Do not choose one source arbitrarily and overwrite the others.

### Mutation discipline

For consequential external effects:

```text
persist intent
    ->
assert current ownership
    ->
perform effect
    ->
observe actual state
    ->
record progress
```

Do not infer non-application merely from an unexpected mutation response.

External mutation results such as:

```text
transport interruption
HTTP 5xx
unexpected 2xx
untrustworthy success representation
```

may be `MUTATION_AMBIGUOUS` and require reobservation.

### Secret handling

Passwords, tokens, raw Kubernetes Secret values and secret-bearing HTTP bodies must not appear in:

```text
logs
exception messages
repr/str output
plans
transaction records
Kubernetes events
diagnostic reports
```

## External client behavior already established

### Keystone

Password authentication has three distinct outcomes:

```text
SUCCESS
CREDENTIAL_REJECTED
INDETERMINATE
```

Do not collapse transport, server, policy, MFA/auth-receipt or malformed-response failures into credential rejection.

Successful authentication returns observed identity/scope metadata so workflow code can validate:

```text
user
domain
project
roles
expiry
```

Administrative user mutations use:

```text
PATCH /v3/users/{user_id}
```

and expect:

```text
HTTP 200
+
matching response user.id
```

Password change uses the administrative user-update path, not the self-service original-password endpoint.

Lockout mutation changes only:

```text
ignore_lockout_failure_attempts
```

### PasswordSafe

Authentication is:

```text
AD service-account credential
    ->
Rackspace Identity Internal v2
    ->
Identity token
    ->
PasswordSafe X-Auth-Token
```

Current credential retrieval uses:

```text
GET /projects/{project_id}/credentials/{credential_id}
Accept: application/json
```

Password mutation uses a password-only JSON PATCH.

A successful HTTP 204 is acceptance of the mutation request, not proof that PasswordSafe now contains the intended value. Later workflow must GET and verify.

Historical PasswordSafe retrieval is intentionally **not implemented yet**. Exact old-A historical retrieval remains a deferred exceptional recovery capability and should be added only if the later A-recovery implementation demonstrates the concrete need.

## Durable transaction and Lease behavior

Transaction schema version 2 is implemented.

Generated replacement credential identifiers use:

```text
sha256:<64 lowercase hex>
```

over the exact UTF-8 password bytes.

Do not reintroduce the superseded HMAC/fingerprint-key design.

The transaction record does not contain clear-text credentials.

The Kubernetes Lease identifies an execution, not a transaction.

Default ownership timings are currently:

```text
Lease duration:       120s
renew interval:        20s
renew deadline:        60s
API call timeout:      30s
```

Foreign-owner takeover eligibility does not use another host's wall-clock timestamps. A contender must observe the same foreign Lease record unchanged for the Lease duration according to its own monotonic clock.

Successful takeover grants cooperative ownership and requires later recovery/reconciliation. It does not prove the previous process is physically unable to continue writing to external systems.

## Behavioral fakes

Prefer the existing behavioral fake clients for workflow tests rather than constructing every test from HTTP mocks.

The Keystone fake can model ambiguous password or lockout mutation in both realities:

```text
MUTATION_AMBIGUOUS + effect applied
MUTATION_AMBIGUOUS + effect not applied
```

The PasswordSafe fake provides equivalent ambiguous mutation behavior.

Later recovery tests should use normal observation methods to discover which reality occurred.

## Next implementation increment

The next intended implementation increment is **Slice 3B**:

```text
stable-A preflight
+
PREPARE_B
+
B0 / B1 / B2 recovery
```

Slice 3B should build on the Slice 3A client boundaries rather than modifying them casually.

The intended PREPARE_B behavior from the current implementation brief is approximately:

```text
verify stable A and normal lockout
    ->
perform safe capability checks
    ->
read current PasswordSafe B
    ->
generate B-new
    ->
persist B-new generation identifier
    ->
PATCH PasswordSafe B
    ->
GET and verify B-new
    ->
using authenticated A, reset Keystone B to B-new
    ->
freshly authenticate B-new
    ->
verify expected identity/project/admin authorization
```

The observed recovery states are:

```text
B0
    PasswordSafe B still pre-rotation
    Keystone B not reset by this transaction

B1
    PasswordSafe B contains intended B-new
    Keystone B reset absent or not yet verified

B2
    PasswordSafe B contains intended B-new
    B-new freshly authenticates with required authorization
```

Once B-new has been durably staged in PasswordSafe, recovery must retain that generation rather than generate another one casually.

A candidate lost before any durable staging may be regenerated only after observation establishes that no prior ambiguous staging operation can still take effect.

## Slice 3B scope boundary

Slice 3B should not implement later consumer propagation.

Keep out of Slice 3B unless an explicit task says otherwise:

```text
SWITCH_TO_B Secret propagation
runtime workload actions
VERIFY_B service/runtime probes

A0/A1/A2/A3 recovery classification
breeder A-new staging
Keystone admin password rotation
PasswordSafe admin convergence

SWITCH_TO_A
VERIFY_A
final lockout restoration
transaction completion cleanup

Job/RBAC packaging
```

The next slice should establish a freshly prepared, authorized breakglass safety credential while leaving normal managed consumers on A.

## Later rotation direction

The intended high-level transaction remains:

```text
STABLE_A
    ->
PREPARE_B
    ->
SWITCH_TO_B
    ->
VERIFY_B
    ->
ROTATE_A
    ->
SWITCH_TO_A
    ->
VERIFY_A
    ->
STABLE_A
```

The current A rotation ordering remains:

```text
stage A-new in breeder with provenance
    ->
change Keystone admin to A-new using B
    ->
freshly authenticate A-new
    ->
PATCH PasswordSafe admin to A-new
    ->
GET and verify PasswordSafe
```

Recognized A states remain:

```text
A0
    PasswordSafe old
    breeder old
    Keystone old

A1
    PasswordSafe old
    breeder new with valid transaction provenance
    Keystone old

A2
    PasswordSafe old
    breeder new with valid provenance
    Keystone new

A3
    PasswordSafe new
    breeder new
    Keystone new
```

These are observed credential states, not program counters.

Forward recovery is preferred over routine password rollback.

## Code-change discipline

Make the smallest coherent change required by the current task.

Do not:

```text
rewrite unrelated completed slices
weaken strict validation to make tests pass
add generic workflow-engine abstractions
add automatic retries for ambiguous mutations
introduce broad Helm redeployment
replace structural credential mutation with global search/replace
delete unrelated untracked/operator-owned files
create commits or push unless explicitly requested
```

If existing design or implementation behavior appears inconsistent with the current task, report the conflict rather than silently inventing a new project-wide rule.

## Validation

From `ops-tools/admin-password-rotation`, run:

```bash
python -m pyright
python -m pytest -q
./scripts/check.sh
git diff --check
```

All should pass before reporting completion unless an environmental limitation is explicitly identified.

Also inspect the final diff for:

```text
unrelated refactors
secret-bearing diagnostics
production subprocess use added to external mutation paths
automatic retries of ambiguous writes
accidental implementation of later slices
generated or temporary files
```

## Current operational caveat

`docs/DESIGN.md` contains the authoritative description of behavior already implemented in code.

Some older documents in this repository originated during the initial read-only bootstrap. If a statement in an older handoff, validation record or historical specification conflicts with current code plus the current implementation brief/amendments, do not resurrect the stale bootstrap behavior.

Use historical files as provenance, not as an instruction to undo completed slices.

## Suggested next-agent task

A suitable next task is:

> Implement Slice 3B only: stable-A preflight and PREPARE_B/B0-B2 recovery using the existing Slice 2 transaction/ownership infrastructure and Slice 3A external clients. Preserve the current external-client contracts. Establish durable intent before consequential credential effects, reobserve ambiguous mutations rather than retrying blindly, keep all managed consumers on A throughout PREPARE_B, and stop after B is freshly authenticated and authorized. Do not implement SWITCH_TO_B, A0-A3 rotation, propagation/actions/probes, or Job/RBAC packaging. Run Pyright, pytest, `./scripts/check.sh`, and `git diff --check`, and report exact results.
