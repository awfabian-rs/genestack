# Handoff to the next engineer or coding agent

## Current project state

This directory contains a staged implementation of the Genestack/OpenStack Keystone administrative password-rotation tool. Slices 1-3 are complete through Slice 3E, and Slices 4A-4F are complete.

The project now includes mutation-capable library behavior.

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

Slice 3D
    fresh A0 starting-state gate through Slice 3C
    fresh exact breakglass administrative validation
    durable lockout-restoration intent and real suppression mutation
    positive suppression read-back and ambiguity reconciliation
    secure A-new generation with pre-/post-dispatch recovery semantics
    conditional canonical breeder staging with transaction provenance
    fresh observed A1 completion while lockout remains suppressed

Slice 3E
    exact staged A-new recovery from the canonical breeder
    fresh breakglass and lockout-prerequisite validation
    exact-user Keystone admin reset with ambiguity reconciliation
    fresh observed A2 gate before PasswordSafe mutation
    password-only PasswordSafe admin update and read-after-write verification
    fresh observed A3 completion with forward-only interruption recovery
    immutable A-new generation and no breeder staging

Slice 4A
    typed classified propagated-location and redacted desired-credential inputs
    structural fields, INI, direct YAML, and nested-YAML mutation
    source and fixed-identity protection plus caller-permitted observed-state gate
    current-ownership assertion immediately before mutation
    UID/resourceVersion-conditional Secret JSON Patch
    fresh read-after-write parse and exact-target verification
    typed changed/no-op results with retained, unexecuted restart metadata
    typed secret-safe conflict, unsafe-state, ambiguity, and verification failures

Slice 4B
    complete contract-derived propagation-wave membership
    deterministic logical-location grouping by namespace and Secret name
    immutable credential-free intent in the existing transaction state
    original classification, Secret-instance, generation, and restart metadata
    fresh-state resume reconciliation with progress treated only as a hint
    explicit already-converged, requires-mutation, and unsafe dispositions
    exact contract-drift and changed-membership detection
    ownership-fenced intent persistence without credential or workload mutation

Slice 4C
    safe pre-reconciliation pass over every Secret group before any write
    grouped Secret-level mutation: at most one CAS-protected JSON Patch per group
    same-data-key composition with explicit conflict rejection
    fresh per-location post-write verification
    actual changed-location accounting (changed vs already-converged)
    durable progress persistence through the existing transaction state
    crash/recovery: no duplicate write on resume, regression fails closed
    retained restart metadata for the later restart-debt slice, no restarts

Slice 4D
    restart action derivation from durable changed-location accounting
    deduplication of identical workload targets across locations
    contract-digest validation against wave intent (CONTRACT_DRIFT fail-closed)
    stale durable runtime action ID validation (STALE_RUNTIME_ACTIONS fail-closed)
    direct Kubernetes Deployment/DaemonSet restart via strategic-merge patch on
    the Pod template (spec.template.metadata.annotations)
    generation-aware bounded rollout observation and completion verification
    durable per-action progress (PENDING/RUNNING/COMPLETE) in the wave
    COMPLETE is a discharged obligation (not re-observed/re-dispatched)
    ownership: RUNNING write fences ownership, then reasserted immediately
    before the Kubernetes dispatch
    crash/recovery: re-observe before dispatch, confirm without re-dispatch,
    conservative repeated restart over unverified completion
    deterministic restart-request marker (SHA-256 of wave intent tuple)

Slice 4E
    transaction-level SWITCH_TO_B orchestration composing the Slice 4B/4C
    propagation machinery and the Slice 4D restart executor
    entry conditions: current transaction in SWITCH_TO_B, PREPARE_B complete,
    breakglass generation established, Lease owned, fresh external observation
    authoritative B credential recovered freshly from PasswordSafe and validated
    by fresh, correctly-scoped breakglass Keystone authentication
    canonical admin breeder re-read and required to match the stable-A generation
    immutable to-B propagation obligation planned/reconciled and persisted once
    grouped propagation wave executed (4C): every identity:active location
    reconciled to the transaction's breakglass generation; fixed identity:admin
    locations and keystone-admin are never switched
    restart debt derived from actual changed locations and executed (4D)
    reobserve gate: wave safely reconciled + every runtime action COMPLETE
    phase advanced to VERIFY_B with a credential-free completion receipt
    interruption-safe re-entry across every boundary without replaying completed
    Secret writes or workload restarts
    no VERIFY_B service/authentication/health verification performed

Slice 4F
    transaction-level VERIFY_B gate (run_verify_b in verify_b.py),
    observational and fail-closed: no Secret writes, no restart dispatch,
    no admin credential mutation
    entry conditions: current transaction in VERIFY_B, phase-qualified
    switch-to-b-complete receipt, durable PREPARE_B stable-a/breakglass-b2
    evidence, environment/Keystone/PasswordSafe identity, Lease owned
    fresh breakglass bridge: PasswordSafe B re-derived at the recorded
    generation + fresh, correctly-scoped breakglass Keystone authentication
    (stale PREPARE_B/SWITCH_TO_B evidence explicitly rejected)
    canonical admin breeder re-read, required to still anchor the stable-a
    receipt (old-A generation + breeder UID)
    participating location verification: every identity:active propagated
    location (complete applicable contract membership, not the changed set)
    freshly structurally classified and required to equal the verified
    breakglass credential; fixed identity:admin locations are required to
    match the verified admin reference only -- a breakglass credential there
    is an invalid state and fails closed (not an early convergence), as do
    missing/malformed/unexplained fixed-admin locations
    restart verification: actions derived from durable changed-location
    accounting (contract digest + stale action ID validated); every derived
    action durably COMPLETE
    workload verification: every affected Deployment/DaemonSet freshly
    observed rolled out and ready with the deterministic restart marker
    (Slice 4D abstraction and completion predicate reused, read-only)
    observed state wins over durable progress flags; contradictory or
    unexplained state fails closed
    phase advanced to ROTATE_A with a credential-free verify-b-complete
    receipt (B generation only); ownership asserted immediately before the
    advance; a failed verification persists only the credential-free
    execution bookkeeping re-stamp -- never a receipt or a phase advance --
    and remains resumable in VERIFY_B
    deterministic re-entry: only successor phases (ROTATE_A, SWITCH_TO_A,
    VERIFY_A) report ALREADY_ADVANCED without re-running checks; predecessor
    phases (STABLE_A, PREPARE_B, SWITCH_TO_B) are UNSUPPORTED_PHASE; crash
    before the advance re-runs the checks
    no ROTATE_A, no SWITCH_TO_A/VERIFY_A, no lockout restoration, no final
    completion, no packaging
```

The next intended work is Slice `ROTATE_A` runtime integration: compose the
existing bounded `ROTATE_A` libraries (Slice 3D staging and Slice 3E
convergence) into the `ROTATE_A` runtime phase gated by the now-implemented
`VERIFY_B` completion evidence. `SWITCH_TO_A`, `VERIFY_A`, lockout
restoration, final transaction completion, and packaging remain later work.

The deployment has not yet been verified as safely cut over between A and B.
Slice 4E advances the transaction from a completed `PREPARE_B` to `VERIFY_B`;
Slice 4F advances a verified transaction to `ROTATE_A`, but it performs no A
credential mutation and production execution must still complete the bounded
`ROTATE_A` path (breeder -> Keystone -> PasswordSafe) with the B safety bridge
freshly verified by Slice 4F before any admin credential change. Slice 3's
independently invocable/testable primitives do not bypass or weaken that gate.
Slice 3D changes only the admin lockout option and canonical breeder Secret,
then stops at observed A1. Slice 3E converges the core A credential to
observed A3. Slice 4A can mutate one already classified propagated location.
Slice 4B can durably describe and freshly reconcile a complete propagation
obligation. Slice 4C can safely execute that wave with grouped per-Secret
writes and changed-location accounting, but it does not execute restarts or
advance runtime phases. Slice 4D can execute and recover the workload restart
debt caused by those changes, observing each rollout to completion, but it does
not compose that into a runtime phase. Slice 4E composes 4B/4C/4D into
`SWITCH_TO_B` and advances to `VERIFY_B`. Slice 4F verifies the B safety bridge
and advances to `ROTATE_A`, but it does not mutate the admin credential,
execute `SWITCH_TO_A` / `VERIFY_A`, restore lockout policy, or complete the
transaction.

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
mark DISPATCH_UNRESOLVED
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
persist pre-dispatch intent
    ->
assert current ownership
    ->
record DISPATCH_UNRESOLVED
    ->
perform effect
    ->
reobserve actual state
    ->
record progress
```

Record `DISPATCH_UNRESOLVED` only after ownership is established and immediately
before crossing the external dispatch boundary. It means the request may have
reached the external service. A failure proven to occur before that boundary is
not an ambiguous mutation; a credential candidate whose cleartext was never
externalized may be abandoned and regenerated. After an unresolved dispatch where
application cannot be ruled out, its generation is sticky.

Definite atomic conditional rejection (`CONDITIONAL_REJECTED`) is a separate
recovery class. When the API authoritatively proves the mutation did not apply,
reobserve and return to a pre-dispatch/retryable state rather than leaving
`DISPATCH_UNRESOLVED`; a later execution may replace a lost in-memory candidate.
For `OUTCOME_AMBIGUOUS`, retain `DISPATCH_UNRESOLVED` and the sticky intended
generation. Do not infer definite non-application from a transport or server
response that lacks that guarantee.

Do not add separate same-value capability probes. The first real required
PasswordSafe mutation plus verified read-back establishes PasswordSafe write
capability. Slice 3D establishes lockout capability through the actual
lockout-suppression mutation and positively observes suppression before staging
A-new.

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

A successful HTTP 204 is acceptance of the mutation request, not proof that
PasswordSafe now contains the intended value. Workflow code must GET and verify;
PREPARE_B does so after staging B.

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

Recovery tests should use normal observation methods to discover which reality occurred.

## Implemented PREPARE_B boundary

`prepare_b.py` implements fresh stable-A validation, transaction creation/resume,
and B0/B1/B2 recovery. B-new's clear text is never persisted: B0 records its
SHA-256 generation and intent before staging it, while B1/B2 recover the value
from current PasswordSafe B. Exact-user Keystone reset uses fresh validated A
authorization. B2 requires a fresh, correctly-scoped breakglass token with the
recorded admin role. PasswordSafe B staging is the first PasswordSafe mutation;
PREPARE_B does not mutate PasswordSafe A or the admin lockout option.

`DISPATCH_UNRESOLVED` is recorded after an immediate ownership assertion and just
before external dispatch. It distinguishes an intent that may have reached an
external service from pre-dispatch intent. Recovery reobserves first. A matching
PasswordSafe value or successful B authentication discovers an applied ambiguous
write; an unresolved old value blocks without a second generation or blind retry.
A proven pre-dispatch failure may use a new candidate only when the earlier
cleartext was never externalized. Once dispatch is unresolved, or PasswordSafe is
observed to contain the intended generation, that generation is sticky and the
exact PasswordSafe value must be recovered and reused. An expired-owner Lease
takeover follows the same observation gates.

On success, PREPARE_B records phase `SWITCH_TO_B` and stops. It does not execute
that phase. Re-entry for the same already-advanced request returns existing
progress without another B rotation.

## Implemented read-only A-state boundary

`a_state.py` observes current PasswordSafe A, breeder A and bounded fresh Keystone
password-authentication results, then classifies A0/A1/A2/A3 or returns a typed
invalid/indeterminate result. Exact credential bytes are reduced to generation
identifiers; the observation and result types contain no cleartext credential.
The transaction's intended A-new generation is the only accepted new generation,
and the earlier successful `stable-a` verification identifies old A and anchors
the breeder Secret UID. A current breeder with a different UID is invalid before
topology evaluation or authentication, even when its credential bytes match an
otherwise expected generation; the typed reason is `BREEDER_IDENTITY_CHANGED`.

Transaction mutation progress is not authoritative. For example, already-staged
breeder reality can classify A1 despite pending progress, fresh A-new rejection
overrides a recorded Keystone-reset success, and matching intended values plus
fresh valid A-new authentication classify A3 despite unresolved PasswordSafe
progress. Wrong identity/scope/authorization, unknown generations, both candidates
authenticating, malformed authority data and indeterminate authentication all
block with specific safe reason codes. A2 specifically requires correctly scoped
A-new success plus a determinate old-A rejection; indeterminate old-A
authentication blocks A2.

This boundary does not suppress lockout, generate A-new, write the breeder, reset
Keystone admin, update PasswordSafe A, write transaction progress, propagate a
credential or run workload actions. Lockout remains a separate typed transaction
fact and is not part of the A0-A3 enum.

## Implemented Slice 3D boundary

Slice 3D is implemented as a bounded `ROTATE_A` library capability. Implementation
order remains distinct from runtime execution order: no end-to-end runner may call
it without the still-required `SWITCH_TO_B` and `VERIFY_B` gates.

It consumes Slice 3C, starts new staging only from A0, freshly verifies exact
breakglass administrative authority, durably records restoration intent before the
real lockout suppression mutation, and positively reads suppression back. It then
generates and durably identifies A-new, conditionally stages only the canonical
breeder password plus transaction provenance, and succeeds only after fresh A1
classification. It leaves lockout suppressed and restoration required.

## Implemented Slice 3E boundary

Slice 3E is implemented as bounded `run_rotate_a_converge` recovery. It accepts
only fresh A1/A2/A3 reality from Slice 3C, revalidates breeder UID, exact intended
generation, and transaction provenance, and uses the breeder as the sole cleartext
A-new source. It never generates or stages a replacement credential.

A1 freshly validates exact breakglass authorization and the lockout invariant,
then performs `RESET_A_KEYSTONE` in intent, ownership, unresolved-dispatch,
exact-user mutation, and fresh-observation order. Fresh A2 is mandatory before
`UPDATE_A_PASSWORDSAFE`, which follows the same ordering and adds exact-record GET
verification before fresh A3. Ambiguous dispatches advance only when observed
reality proves the intended effect. Definite non-application remains distinct,
and unresolved old reality is not blindly retried.

Starting at A2 skips the Keystone reset. Starting at A3 performs neither A
mutation. Success records fresh A3 but does not complete the transaction: phase
remains `ROTATE_A`, lockout remains suppressed, and restoration remains required.

Keep all of the following out of Slices 3D/3E:

```text
SWITCH_TO_B Secret propagation
runtime workload actions
VERIFY_B service/runtime probes

SWITCH_TO_A
VERIFY_A
final lockout restoration
transaction completion cleanup

Job/RBAC packaging
```

## Later rotation direction

The logical runtime transaction remains:

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

That runtime order is unchanged by building the bounded Slice 3D/3E libraries
before the propagation and verification libraries. `SWITCH_TO_B` is implemented and advances to `VERIFY_B`; `VERIFY_B` is
implemented and advances to `ROTATE_A`. The `ROTATE_A` runtime integration,
`SWITCH_TO_A`, `VERIFY_A`, lockout restoration, and final transaction
completion remain later work.

The current A rotation ordering remains:

```text
authenticate verified breakglass authorization
    ->
enable and positively verify admin lockout suppression
    ->
stage A-new in breeder with provenance
    ->
change Keystone admin to A-new using B
    ->
freshly authenticate A-new and determinately reject old A
    ->
PATCH PasswordSafe admin to A-new
    ->
GET and verify PasswordSafe
```

In compact form, the implemented write order and states are:

```text
breeder -> Keystone -> PasswordSafe

                    PasswordSafe / breeder / Keystone
A0                              old / old / old
A1                              old / new / old
A2                              old / new / new
A3                              new / new / new
```

Recognized A states remain:

```text
A0
    PasswordSafe and breeder contain established old A
    old A freshly authenticates as the expected admin identity/scope/authorization

A1
    PasswordSafe contains established old A
    breeder contains intended A-new
    old A succeeds as expected admin and A-new is determinately rejected

A2
    PasswordSafe contains established old A
    breeder contains intended A-new
    A-new succeeds as expected admin and old A is determinately rejected

A3
    PasswordSafe and breeder contain intended A-new
    A-new freshly authenticates as the expected admin identity/scope/authorization
```

All four states require continuity with the breeder Secret UID recorded by the
successful `stable-a` verification. A recreated breeder is invalid even when its
credential matches an expected generation. These are observed credential states,
not program counters; mutation progress never overrides external reality. In
particular, A-new success plus old-A indeterminacy is not A2.

Forward recovery is preferred over routine password rollback.

## Implemented Slice 4A

The credential propagation mutation engine's unit of work is one
validated `CredentialLocation` whose `role` is `LocationRole.PROPAGATED`. Given an
explicitly requested allowed identity/credential, it must structurally mutate the
location's declared selectors, validate identity and observed state, use Secret
UID/resourceVersion optimistic concurrency, read the Secret back, verify the
exact declared credential, and report changed, no-op, or failure.

Keep execution authorization distinct from object concurrency:

```text
Lease/current execution ownership
    -> authorizes this execution to perform rotation mutation

Secret UID/resourceVersion tests
    -> prove the object and observed state still match the mutation decision
```

The mutating caller must hold valid current rotation execution ownership and
revalidate it through the existing `LeaseOwnership.assert_owned()` boundary
immediately before the correctness-sensitive Secret write. UID/resourceVersion
tests are additionally mandatory and do not replace Lease ownership. Acquiring,
renewing, and releasing the Lease—and orchestrating the overall A -> B -> A state
machine—remain outside the one-location Slice 4A primitive.
Candidate no-ops are also correctness-sensitive: revalidate ownership, freshly
read the Secret, require the expected UID, and reparse and compare the exact
target before returning `UNCHANGED`.

The mutation may alter only the username/password components selected by the
location's representation. All unrelated configuration must remain semantically
unchanged, especially within `octavia.conf`, `blazar.conf`, `clouds.yaml`, and
embedded generated `clouds.yaml`. Do not use textual search-and-replace or treat
the whole document as disposable. Harmless serialization formatting changes are
acceptable where byte preservation is not guaranteed, but unrelated semantic
configuration changes are not.

After mutation, freshly reread the Secret and require all of the following:

- it is still the intended object;
- its UID equals the expected UID;
- the declared representation resolves successfully;
- the resolved credential exactly equals the intended target credential.

A successful write response alone is insufficient. Matching content from a
deleted and recreated same-name Secret does not verify the original mutation.

Fail closed on credential state. Difference from the target does not by itself
authorize an overwrite. Mutation is allowed only from an observed state permitted
by the current higher-level transition and caller-provided validated intent;
unknown or unexplained state is failure. If a permitted location is already at
the target, its classified snapshot is only a no-op candidate. Report no-op
without writing only after a fresh read proves the same Secret UID still has the
exact target credential. That invocation contributes no restart consequence.
Only a location reported changed may contribute its configured restart
dependencies to a later runtime subslice.

`DesiredCredential` does not establish that an arbitrary password belongs to its
identity label. The higher-level transition is responsible for proving through
its existing reconciliation/authentication path that the supplied value is the
current authoritative admin or breakglass credential. There is no existing
single source type that proves this cross-system fact, so Slice 4A documents the
caller precondition instead of introducing another credential framework.

Reuse the checked-in representation and contract model rather than introducing a
parallel schema:

- `config.py` produces the validated `CredentialContract` and
  `CredentialLocation` values.
- `model.py` already defines `IdentityBinding`, `LocationRole`,
  `FieldsRepresentation`, `IniRepresentation`, `YamlRepresentation`,
  `SecretSnapshot`, `ObservedCredential`, and the existing transaction types
  `KubernetesMutationTarget`, `CredentialMutationIntent`, and `PropagationWave`.
- `representations.py` and `syntax.py` contain the current exact fields/INI/YAML
  and `document_path` parsing and validation semantics; mutation and read-back
  must agree with `read_credential()`.
- `kubernetes_api.py` is the shared direct Kubernetes-client construction
  boundary. `breeder.py` demonstrates the required Secret UID/resourceVersion
  JSON Patch discipline and read-after-write safety, but its breeder-specific
  client and provenance must remain source-only rather than being generalized by
  accident.

The Kubernetes client exposes status, reason, headers, and body for API errors,
but no stable structured field distinguishes a JSON Patch `test` failure from
other HTTP 422 validation failures. Slice 4A therefore treats 409/412 as
conditional rejection and 422 as generic Kubernetes failure; it does not parse
human-readable server messages to claim a concurrency conflict.

Slice 4A supports `fields`, `ini`, `yaml`, and nested YAML/`document_path`.
It must not execute any `CredentialLocation.restart` dependency, restart or wait
for a workload, execute `SWITCH_TO_B`, `VERIFY_B`, `SWITCH_TO_A`, or `VERIFY_A`,
restore lockout policy, or finalize the transaction. Phase orchestration and
runtime actions belong to later Slice 4 subslices.

## Implemented Slice 4B

`propagation_wave.py` plans the complete applicable `role: propagated` set from
the validated contract and reconciled inventory. Breakglass intent includes all
switchable active locations and excludes sources and fixed-admin locations. Admin
intent includes active and fixed-admin propagated locations. Already-target
locations remain members even though fresh reconciliation does not require a
write for them.

Logical locations are grouped by `(namespace, Secret name)`, never by UID, with
stable Secret-group and location ordering. Each durable group retains its original
UID/resourceVersion so resume can distinguish the intended object from a
same-name replacement. The immutable intent also retains the exact contract
digest, stable location identifiers, expected starting classifications, target
identity/generation, and potential restart metadata. It contains no plaintext
credential and lives inside the existing `PropagationWave` transaction record.

On resume, do not regenerate or replace existing intent. Reconcile it with fresh
contract and Secret state. Recorded progress is not authority: fresh target state
can satisfy an incomplete hint, and fresh non-target state invalidates a complete
hint. Missing/replaced Secrets, unknown credentials, parse failures, unexpected
identity changes, target regression, target-generation mismatch, and contract
drift are explicit unsafe outcomes. Material contract drift includes changed
membership, identity/role, Secret placement, representation, or restart metadata;
never auto-expand or shrink an in-progress wave.

Planning and reconciliation are read-only. Persisting new intent is a transaction
mutation and therefore uses the existing ownership assertion plus conditional
state store. Restart dependencies remain potential: no runtime action or restart
debt is created until Slice 4C observes an actual changed result. Slice 4B never
calls `mutate_credential_location()`, writes propagated Secrets, restarts a
workload, waits for rollout, advances cutover phases, or completes a transaction.

## Implemented Slice 4C

`propagation.py` now contains `execute_grouped_propagation_wave()`, which
safely executes the durable Slice 4B wave. The mutation unit is the Kubernetes
Secret; the logical credential location is the verification/accounting unit; the
wave is the transaction unit. For one Secret holding several participating
logical locations, it performs one coherent Secret mutation when mutation is
required. It does not naively invoke the Slice 4A one-location API repeatedly
against the same Secret.

Before any write, every Secret group is freshly observed: GET, UID continuity
check against the durable observed UID, and per-location parse/classification
against the known credential references. A group may safely contain a mixture of
admin/breakglass/target states so long as every state is recognized and allowed
by the persisted intent; only the non-target locations require transformation.
Unknown credentials, unparseable representations, replaced Secrets, a
recorded-complete location that is no longer at target, and a current identity
that contradicts durable intent fail the whole wave closed with no Secret write.
This all-wave safety pass is a coarse early gate; each group is then
**re-observed freshly immediately before it is processed** so the
no-op-versus-mutation decision and the CAS precondition both come from a fresh
snapshot rather than the earlier precheck, preventing a stale precheck from
accepting a group that another actor changed between precheck and execution.

Per-location structural transformations reuse Slice 4A's
`mutate_credential_fields()` and are composed by `compose_group_replacements()`
on an evolving in-memory Secret. Each location's transformation is derived and
applied to the running document in deterministic group order, so several logical
locations that share one Secret data key (for example distinct INI options in
one file) are all mutated together: every transformation operates on the
already-updated document, so no change is discarded. One final replacement is
emitted per data key that actually changed relative to the original Secret.
Merely sharing a data key is not a conflict; only a genuinely incompatible
declaration that composition cannot give deterministic safe semantics to is
rejected.

Each group that needs mutation issues a single JSON Patch guarded by atomic UID
and resourceVersion tests, using the freshly observed Secret as the CAS
precondition (never the planning-time resourceVersion). A definite conditional
rejection is a `CONFLICT` (no blind retry); an ambiguous outcome is a
`WRITE_AMBIGUOUS` resolved by fresh reobservation on resume. After each write the
Secret is freshly reread and every logical location is reparsed and required to
exactly equal the target credential.

Slice 4C distinguishes `ALREADY_CONVERGED` from `CHANGED_BY_THIS_PROPAGATION`
per logical location. Durable progress (`applied_location_ids`) advances for
locations that actually changed plus locations that were already recorded-complete
and remain at target. Because a location's durable intent records
`expected_target` (whether it was already at target when the wave was
established), an originally-non-target location (`expected_target == False`)
freshly observed at target during recovery but with no applied marker is
conservatively treated as a transition that occurred during the wave lifetime —
our write succeeded immediately before a crash, or another actor converged the
Secret while the wave was active. Its restart debt is retained in either case.
A location already target at wave creation (`expected_target == True`) is not
restart debt merely because it remains target. Verified progress is persisted
after each successfully processed group, not only at the end of the wave, so
changed/restart-debt accounting survives a crash between a write and wave
completion. Execution ownership is reasserted immediately before each durable
progress write: the state-store update is itself a mutation that must obey the
same Lease/ownership discipline as Secret writes. If ownership is lost, the
executor raises `OWNERSHIP_LOST` and does not update transaction state.

Crash/recovery follows the existing "fresh state is authoritative, progress is a
hint" model: a crash before the write resumes to the mutation; a crash after the
write but before progress persistence resumes to an already-converged observation
with no duplicate write, retaining the originally-non-target location's restart
debt; and progress claiming completion while fresh state regressed is treated as
unsafe. The wave is credential-converged when fresh observation establishes every
intended location at the target — this does not mean runtime consumers are using
the new credential; that requires the later restart/action slice. Slice 4C does
not execute workload restarts, wait for rollouts, discharge restart debt, perform
`SWITCH_TO_B`/`VERIFY_B`/`SWITCH_TO_A`/`VERIFY_A`, restore lockout, or complete
the transaction.

## Implemented Slice 4E

`switch_to_b.py` adds `run_switch_to_b()`, the transaction-level `SWITCH_TO_B`
phase runner. It composes the already-implemented Slice 4B/4C propagation
machinery and the Slice 4D restart executor; it does not create a second
propagation or restart framework. It moves a transaction whose `PREPARE_B` has
completed (phase `SWITCH_TO_B`, breakglass generation established, Lease owned)
through the temporary cutover of every contracted `identity: active` credential
location to the verified/staged breakglass credential, executes the runtime
restart actions caused by the locations that actually changed, and advances the
durable phase to `VERIFY_B`.

Entry conditions are re-observed, not trusted from a stale `PREPARE_B` result.
Phase plus the B generation are intent/history, not proof that `PREPARE_B`
actually succeeded, so the entry validation also requires the durable `PREPARE_B`
completion evidence to be present and consistent. Each receipt is matched on both
`check_id` and `phase`, so a same-named receipt from another phase is treated as
missing: a single `SUCCESS` `stable-a` receipt at phase `PREPARE_B` (old-A
generation + breeder UID) and a single `SUCCESS` `breakglass-b2` receipt at phase
`PREPARE_B` whose generation equals `new_b_sha256`. A missing or wrong-phase,
non-`SUCCESS`, malformed/ambiguous, or generation-inconsistent receipt fails closed
(`PREPARE_B_PREREQUISITE_MISSING` / `PREPARE_B_PREREQUISITE_INVALID`) before any
observation, mutation, or phase work — the evidence is validated, never
synthesized from the current breeder. The authoritative B credential is then
recovered freshly from PasswordSafe (the same "current PasswordSafe value plus the
recorded generation" discipline `PREPARE_B` uses for `B1`) and validated by a
fresh, correctly-scoped breakglass Keystone authentication; the canonical admin
breeder is re-read and required to agree with the durable `stable-a` receipt (both
the old-A generation and the breeder Secret UID), else it fails closed
(`ADMIN_REFERENCE_INVALID`). Fixed `identity: admin` locations and `keystone-admin`
are never switched to B; the work set is derived from the contract and the generic
propagation machinery, not a bespoke Secret list.

`transaction.execution` records the execution currently operating/resuming the
transaction. It is credential-free bookkeeping, **not** the fencing mechanism:
current Lease ownership (`OwnershipGuard.assert_owned`) is the authoritative source
of mutation permission, distinct from `transaction.execution` (which execution is
operating the transaction) and `transaction_id` (which durable transaction). A
durable update to transaction state — including the credential-free
`transaction.execution` field — is itself a mutation, so current Lease ownership is
asserted **before** the re-stamp. On every resume `run_switch_to_b` re-stamps
`transaction.execution` to the request's execution (a legitimate takeover by `E2`
updates the durable field to `E2`) via a CAS-protected write performed only after
the ownership assertion; a stale execution that has lost the Lease cannot modify
the durable transaction at all, even the bookkeeping field. This is a
**transaction-wide invariant**, not a `PREPARE_B`- or `SWITCH_TO_B`-specific
convention. Bounded technical debt: the older `ROTATE_A` Slice 3D/3E entry points
(`RotateAStageInputs`) do not carry an `execution` field and do not uniformly
maintain `transaction.execution`; normalize when orchestration reaches that
boundary, not in this pass.

Transaction progress uses only existing schema concepts: the immutable wave
`intent` (4B), `applied_location_ids` (4C changed-location accounting), and
`runtime_actions` (4D `PENDING`/`RUNNING`/`COMPLETE`). `SWITCH_TO_B` is complete
when fresh observation establishes every intended location at the target, the
wave is safely reconciled, and every derived runtime action is `COMPLETE`. At
that point the phase advances to `VERIFY_B` (ownership-fenced) and a
credential-free `switch-to-b-complete` verification receipt (carrying only the B
generation) is recorded.

Re-entry is interruption-safe across every boundary: no intent yet, intent
persisted but no propagation, partial propagation, propagation complete with
restart debt pending, some runtime actions `RUNNING`, and all actions `COMPLETE`
but phase not yet advanced. It continues the existing transaction by observing
durable propagation/action state; it does not replay completed Secret writes,
blindly restart workloads, generate or stage a new B credential, or create a new
transaction. Stale, unknown, contradictory, concurrent, or contract-drift state
reported by the existing machinery fails closed with the established typed
semantics.

Slice 4E performs no `VERIFY_B` (no service/authentication/health verification of
the B safety bridge), no `ROTATE_A`, no `SWITCH_TO_A` / `VERIFY_A`, no lockout
restoration, no final transaction completion, and no Kubernetes Job/CronJob
packaging or RBAC. It stops at the `VERIFY_B` boundary.

## Implemented Slice 4F

`verify_b.py` adds `run_verify_b()`, the transaction-level `VERIFY_B` gate. It
is observational: it reads and re-observes external state and its only durable
write is the ownership-fenced phase advance to `ROTATE_A`. It does not write a
propagated Secret, does not dispatch or re-run a restart, and does not mutate
the admin credential or lockout policy.

Entry conditions are re-observed, not trusted from a stale `SWITCH_TO_B`
result. A transaction in `VERIFY_B` must carry the phase-qualified durable
`switch-to-b-complete` receipt (at phase `SWITCH_TO_B`, generation equal to
`new_b_sha256`) plus the PREPARE_B `stable-a` / `breakglass-b2` evidence; a
transaction already past `VERIFY_B` is reported `ALREADY_ADVANCED`
deterministically without re-running the checks, and a transaction still in
`SWITCH_TO_B` is rejected. The authoritative B value is then re-derived freshly
from PasswordSafe at the recorded generation and re-validated by a fresh,
correctly-scoped breakglass Keystone authentication — historical success from
`PREPARE_B` or `SWITCH_TO_B` is explicitly not current verification. The
canonical breeder is re-read and required to still anchor the `stable-a`
receipt (old-A generation and breeder UID).

The participating set is the complete applicable `identity: active`
propagated membership of the current contract (the same membership the
immutable wave intent was derived from), not the durable changed set:
`applied_location_ids` is a progress hint and never proof that a location
converged. Every active location is freshly read, structurally parsed, and
required to equal the verified breakglass credential per its exact declared
fields. Missing Secrets, malformed representations, unknown credentials,
locations still on `admin`, or a different breakglass password all fail closed
(`LOCATION_UNVERIFIED`); nothing is overwritten. Fixed `identity: admin`
propagated locations do not participate in the B identity transition: they are
required to match the verified admin reference and fail closed on any other
state, including a breakglass credential (not an "early convergence"), a
missing Secret, a malformed representation, or a wrong admin password. The
`keystone-admin` source is checked separately as the canonical breeder anchor.

Restart obligations are derived exactly as Slice 4D derives them (contract
digest validated against the intent; stale durable action IDs fail closed),
and every derived action must be durably `COMPLETE`. Every affected workload
is then freshly observed through the Slice 4D workload abstraction and its
generation-aware completion predicate (matching restart marker, converged
replicas); a durable `COMPLETE` flag is not laundered — the fresh observation
decides.

On success the phase advances to `ROTATE_A` with a credential-free
`verify-b-complete` receipt (B generation only), ownership asserted
immediately before the write. On any failure or ambiguity the
`verify-b-complete` receipt is never written and the phase is never
advanced; the only durable write a failed invocation may perform is the
credential-free execution bookkeeping re-stamp on resume, so the transaction
remains in `VERIFY_B` (or, for a predecessor phase, exactly where it was
found) and the same invocation re-observes on retry. Re-entry is
deterministic by phase class: only successor phases (`ROTATE_A`,
`SWITCH_TO_A`, `VERIFY_A`) report `ALREADY_ADVANCED` without re-running the
checks or regressing the phase; predecessor phases (`STABLE_A`, `PREPARE_B`,
`SWITCH_TO_B`) are rejected with `UNSUPPORTED_PHASE`. `VERIFY_B` performs no
`ROTATE_A`, no A credential generation/staging/mutation, no `SWITCH_TO_A` /
`VERIFY_A`, no lockout restoration or lockout-state read, no final completion,
and no packaging.

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

## Current boundary

```text
Slice 4F:
    VERIFY_B gate complete

Next:
    ROTATE_A runtime integration
```

Slice 4F is implemented and advances a `SWITCH_TO_B`-completed transaction to
`ROTATE_A` only after the B safety bridge is freshly verified (breakglass
authentication, participating location state, restart completion, and workload
health). The next slice is the beginning of `ROTATE_A` runtime integration:
compose the existing bounded Slice 3D/3E `ROTATE_A` libraries into the
`ROTATE_A` runtime phase gated by the `verify-b-complete` evidence, starting
with lockout-suppression recovery and A-new staging. `SWITCH_TO_A`, `VERIFY_A`,
lockout restoration, final transaction completion, and packaging remain later
work. The complete A -> B -> A rotation is not yet implemented.

## Suggested next-agent task

Build the `ROTATE_A` runtime integration — the phase that, behind the now
implemented `VERIFY_B` gate, establishes/recoveries admin lockout
suppression, stages A-new in the canonical breeder, resets the Keystone admin
user to A-new using the verified breakglass credential, and converges
PasswordSafe A, in the established breeder -> Keystone -> PasswordSafe write
order with forward-only A0-A3 recovery. It reuses the bounded Slice 3D/3E
libraries; it must not perform `SWITCH_TO_A`, `VERIFY_A`, lockout
restoration, final transaction completion, or packaging.
