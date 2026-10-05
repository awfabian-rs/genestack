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

Slice 3B
    fresh stable-A reconciliation and lockout preflight
    schema-v2 transaction creation/resumption
    observed B0/B1/B2 classification and recovery
    PasswordSafe B staging and exact-user Keystone B reset
    ambiguity reconciliation without blind mutation retry

Slice 3C
    read-only PasswordSafe A and breeder observation
    intended-generation and stable-old generation matching
    fresh expected-admin Keystone authentication
    typed A0/A1/A2/A3 classification
    typed invalid and indeterminate reconciliation outcomes
    secret-free observation/result records
```

The CLI remains primarily read-only/planning-oriented. PREPARE_B is available as
a library workflow, and A-state reconciliation is available as a read-only library
boundary; the end-to-end rotation command is not implemented.

No production workflow currently performs SWITCH_TO_B, any A mutation, or any
later phase.

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

Historical PasswordSafe retrieval is intentionally **not implemented**. Slice 3C
uses current PasswordSafe A plus the recorded stable-A generation and does not need
history. Exact old-A historical retrieval remains a deferred exceptional recovery
capability that requires a future concrete need.

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

## Implemented PREPARE_B boundary

`prepare_b.py` implements fresh stable-A validation, transaction creation/resume,
and B0/B1/B2 recovery. B-new's clear text is never persisted: B0 records its
SHA-256 generation and intent before staging it, while B1/B2 recover the value
from current PasswordSafe B. Exact-user Keystone reset uses fresh validated A
authorization. B2 requires a fresh, correctly-scoped breakglass token with the
recorded admin role. PasswordSafe B staging is the first PasswordSafe mutation;
PREPARE_B does not mutate PasswordSafe A or the admin lockout option.

`dispatch_unresolved` distinguishes an intent that may have reached an external
service from one persisted before dispatch. Recovery reobserves first. A matching
PasswordSafe value or successful B authentication discovers an applied ambiguous
write; an unresolved old value blocks without a second generation or blind retry.
An expired-owner Lease takeover follows the same observation gates.

On success, PREPARE_B records phase `SWITCH_TO_B` and stops. It does not execute
that phase. Re-entry for the same already-advanced request returns existing
progress without another B rotation.

## Implemented read-only A-state boundary

`a_state.py` observes current PasswordSafe A, breeder A and bounded fresh Keystone
password-authentication results, then classifies A0/A1/A2/A3 or returns a typed
invalid/indeterminate result. Exact credential bytes are reduced to generation
identifiers; the observation and result types contain no cleartext credential.
The transaction's intended A-new generation is the only accepted new generation,
and the earlier successful `stable-a` verification identifies old A once rotation
has an intended new generation.

Transaction mutation progress is not authoritative. For example, already-staged
breeder reality can classify A1 despite pending progress, fresh A-new rejection
overrides a recorded Keystone-reset success, and matching intended values plus
fresh valid A-new authentication classify A3 despite unresolved PasswordSafe
progress. Wrong identity/scope/authorization, unknown generations, both candidates
authenticating, malformed authority data and indeterminate authentication all
block with specific safe reason codes.

This boundary does not suppress lockout, generate A-new, write the breeder, reset
Keystone admin, update PasswordSafe A, write transaction progress, propagate a
credential or run workload actions. Lockout remains a separate typed transaction
fact and is not part of the A0-A3 enum.

## Next implementation increment

The next workflow increment begins with **SWITCH_TO_B**. It must remain separate
from PREPARE_B and derive mutations/actions from fresh observations and the
configured credential-location contract.

Later ROTATE_A mutation work must require the real admin lockout-suppression
operation to be observed active before any A-new breeder staging or admin
password reset. It must consume, not replace, the Slice 3C observed-state
classifier.

Keep out unless an explicit task authorizes the corresponding later slice:

```text
SWITCH_TO_B Secret propagation
runtime workload actions
VERIFY_B service/runtime probes

breeder A-new staging
Keystone admin password rotation
PasswordSafe admin convergence

SWITCH_TO_A
VERIFY_A
final lockout restoration
transaction completion cleanup

Job/RBAC packaging
```

The next slice should propagate the already-prepared breakglass credential
to the configured switchable consumer locations while leaving A itself
unchanged.

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
./.venv/bin/python -m pyright
./.venv/bin/python -m pytest -q
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

> Implement the SWITCH_TO_B slice only, using the existing typed locations,
> transaction state and ownership boundary. Reobserve external state, persist
> exact intents before effects, apply structural consumer changes and required
> runtime actions, and stop before VERIFY_B. Do not begin A rotation.
