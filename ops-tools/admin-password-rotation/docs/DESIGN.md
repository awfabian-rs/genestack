# Design

Status: Slices 1-3 (through Slice 3E) and Slices 4A-4C are complete.

- PREPARE_B is implemented as a library workflow and may invoke its narrowly
  scoped B credential mutations.
- Read-only A0/A1/A2/A3 credential-state observation and classification is
  implemented as a library boundary.
- Slice 3D implements admin lockout suppression and canonical A-new breeder
  staging, stopping only after fresh observation establishes A1.
- Slice 3E implements forward-only core A convergence from A1/A2/A3, stopping
  only after fresh observation establishes A3.
- Slice 4A implements safe one-location mutation for contracted
  `role: propagated` credentials.
- Slice 4B implements complete propagation-wave planning, durable immutable
  intent, same-Secret grouping, and fresh-state resume reconciliation.
- Slice 4C implements grouped Secret-level propagation execution and
  crash/recovery: a safe pre-reconciliation pass, one CAS-protected write per
  Secret group, fresh per-location verification, and actual changed-location
  accounting. It does not execute restarts or advance runtime phases.
- Restart execution, rollout waiting, runtime/service verification, SWITCH_TO_B,
  VERIFY_B, SWITCH_TO_A, VERIFY_A, lockout restoration, and all later
  orchestration remain unimplemented.
- No complete end-to-end rotation workflow is implemented.

## Boundaries

| Module | Responsibility |
| --- | --- |
| `model.py` | Immutable typed configuration, observations, findings and plan data. |
| `config.py` | Validate and normalize the supplied contract; resolve named representations. |
| `syntax.py` | Bounded YAML structure reader with tags and source spans; no constructors. |
| `representations.py` | Read and structurally mutate direct fields, explicit INI options, and direct/embedded YAML paths. |
| `kubernetes.py` | Validate SecretList JSON; read live data through a constrained kubectl adapter. |
| `discovery.py` | Compare against supplied reference values and audit undeclared known-password copies. |
| `planning.py` | Pure function over contract and inventory; derive findings and potential dependencies. |
| `reporting.py` | Explicit allow-listed projection into credential-free text/JSON. |
| `state.py` | Strict schema-v2 JSON boundary for durable transaction memory. |
| `state_store.py` | Conditional Kubernetes API Secret persistence and read-after-write validation for `state.json`. |
| `kubernetes_api.py` | Shared narrow construction boundary for generated Kubernetes API clients. |
| `lease.py` | Validated Lease observation, conditional ownership operations and sticky local renewal guard. |
| `external_http.py` | Bounded, secret-safe direct HTTP transport shared by external credential adapters. |
| `keystone.py` | Typed Keystone v3 authentication, exact-user password update and user-option operations. |
| `passwordsafe.py` | Rackspace Identity authentication and PasswordSafe current-credential read/update operations. |
| `passwords.py` | Cryptographically secure administrative-password generation. |
| `prepare_b.py` | Stable-A reconciliation and observed-state PREPARE_B/B0-B2 orchestration. |
| `a_state.py` | Read-only authoritative A-credential observation and A0-A3 reconciliation. |
| `breeder.py` | Direct canonical-breeder reads and UID/resourceVersion-conditional password/provenance patches. |
| `rotate_a.py` | Bounded Slice 3D A0-to-A1 staging and Slice 3E A1-to-A3 core-credential convergence. |
| `propagation.py` | Classify and conditionally mutate one propagated credential location, then read back and verify it; execute a grouped Secret-level propagation wave with crash/recovery and changed-location accounting. |
| `propagation_wave.py` | Plan complete propagated-location obligations, group them by Secret, and reconcile durable intent against fresh state. |
| `wave_digest.py` | Shared credential-free wave planning primitives (contract digest and membership) used by both planning and grouped execution. |
| `cli.py` | Select input mode, enforce opt-in, report errors and return exit status. |

Configuration validates before any live read. Namespace is fixed to `openstack`
for this slice. The sole source must be fixed-admin `keystone-admin/password`
with no restart dependency. Source is validated; no downstream location can become
its authority. All locations require explicit identity, role, representation and
restart properties. Unknown fields are rejected rather than silently ignored.

Named representations are normalized at load time. Multiple disjoint credential
locations can share a Secret or a document. Overlapping username/password selectors,
mixed formats for one data field, and different embedded document roots within
one field are rejected. These are conservative Slice 1 planning constraints, not
claims that the general design prohibits every such future extension.

## Actual identity versus identity binding

`Identity` contains only `admin` and `breakglass`. `IdentityBinding.ACTIVE` is a
contract directive. It is not an actual account and never appears as an observed
username. This avoids the earlier illustrative model's conflation of the two.

The CLI obtains only an **unverified comparison reference** from the breeder.
It cannot assert PasswordSafe equality, successful Keystone authentication or
breakglass authorization. Consequently:

- Equal copies classify as `matches_admin_reference`, never "verified admin".
- A breakglass username without an independent B reference becomes
  `unverified_breakglass`, which blocks a clean topology check.
- Unknown credentials are findings, not overwrite candidates.
- Missing objects and representation failures are findings, not credential states
  that authorize repair. The output observation labels distinguish these errors.

`classify()` also accepts a B reference for unit testing and a future read-only
integration, but supplying a reference still does not prove authentication. The
planning CLI does not accept a password flag, credential file or environment
variable as an alternative authority.

## Parsing decisions

Secret `.data` is strict-base64 decoded exactly once at the API/fixture boundary.
Declared credential strings must be nonempty, single-line UTF-8 without NUL.
Direct field bytes are otherwise not trimmed or normalized. INI syntax whitespace
is handled by the parser; values containing interpolation characters remain literal.

YAML preserves the distinction between a string and an integer/boolean/null.
A non-string password is rejected, not coerced. `document_path` identifies a
string inside the outer YAML that is parsed again; a dotted key is one literal
path component. The supported YAML subset rejects duplicates, aliases, merges,
complex keys and custom tags. Anchored-but-unused values are not rejected merely
for having an anchor; aliases are rejected on reuse. Documents are limited to
1 MiB, 20,000 composed nodes and depth 64. These are conservative initial limits.
PyYAML composes the node tree before node/depth checks; the byte limit applies
before composition, but this is not a hostile-input sandbox or memory quota.

INI uses ConfigParser with interpolation disabled, strict duplicate checking and
case-preserved options. Credentials must be explicit options in the declared
section, not silently inherited from DEFAULT, and must be single-line. Blazar's
explicit DEFAULT options are supported. A small lexical span finder verifies the
selected value against ConfigParser so the audit masks only that option. Repeated
options elsewhere in an oslo.config file may be valid to that service but are
rejected by the Slice 1 parser: test real sanitized shapes before expanding
compatibility. Mutation reuses these exact source spans and reparses its output;
it does not round-trip an entire INI document through ConfigParser.

## Bounded extra-copy audit

Every decoded data field in the namespace inventory is scanned. A declared
location is not permission to ignore an entire Secret or an entire configuration
file. Only a password selector whose complete declared credential matches the
comparison reference is exempted from the known-password audit.

For INI, lexical spans exclude only accepted password values; an extra option or
even a comment containing the same password remains a finding. For declared YAML,
both raw lexical text and decoded scalar values are inspected. This catches an
escaped extra copy in the same parsed document. For embedded YAML, masking the
outer scalar does not hide the inner document: its remaining text/scalars are
audited separately. Multiple disjoint declarations in one document are accounted
for together. Audit views are ephemeral scanner inputs, **never candidate writes**.

An uncontracted `OS_USERNAME` naming admin/breakglass is another candidate even
with a different password. This is not comprehensive schema discovery: unknown
or historical values in arbitrary files, a differently named identity field,
uncontracted escaped YAML, Helm's compressed release data, encrypted content and
other encodings may escape this slice's audit. No full-deployment safety claim is
made. `rotation_ready` remains false on all outputs, including clean fixtures.

## Plans and dependency edges

The planner does not generate replacement passwords or compute a mutation payload.
It lists potential dependencies for a hypothetical active-identity cutover, using
only currently readable matching active/propagated locations. Each workload retains
all causal locations. Source and fixed-identity locations do not drive that cutover
list. Empty restart lists remain meaningful.

These are not actual restarts, nor a single deduplicated list for an
entire A->B->A transaction. A later Slice 4 runtime subslice must derive actions
from actual changes and distinguish the B and A transitions. The Slice 1 planner
itself has no resumed-action receipts, action tokens, ownership protocol or
transaction journal; those concerns belong to the transaction and runtime layers
described below.

Secret UID and resourceVersion are retained as opaque observations. They are not
ordered or incremented. The inventory is a finite observation, not a lock across
Kubernetes, PasswordSafe and Keystone. Any mutating workflow must acquire
ownership and reread relevant state; a saved report cannot be applied.

## Durable transaction state

Schema version 2 defines the contents of
`Secret/openstack/keystone-admin-rotation-state` at `data/state.json`. Slice 2B
stores that document in a precreated infrastructure Secret; it does not create
the Secret or perform rotation work. Lease ownership is a separate Slice 2C library
boundary. The planning CLI remains read-only and invokes neither boundary.

The state is durable transaction memory, not authority over external reality.
Recorded progress may lag an effect that completed before the next state update.
For that reason the model keeps one explicit current credential-mutation intent,
its observed-effect state, both propagation waves, lockout intent/observations and
bounded latest verification results. Consequential mutation workflows follow:

```
persist pre-dispatch intent
    -> assert current ownership
    -> record DISPATCH_UNRESOLVED
    -> perform effect
    -> reobserve actual state
    -> record progress
```

`DISPATCH_UNRESOLVED` is written only after ownership has been established and
immediately before crossing the external dispatch boundary. It means that the
request may have reached the external service. A failure proven to occur before
that boundary is not ambiguous and permits an unexternalized credential candidate
to be abandoned and regenerated. An authoritative atomic conditional rejection
likewise proves non-application; after reobservation, recovery returns to a
pre-dispatch/retryable state and may replace a candidate whose clear text was
lost. If a dispatched outcome may have applied, its generation remains sticky.

Each credential-mutation intent names one exact consequential effect rather than a
broad rotation phase. Runtime-action progress is keyed by the normalized configured
action ID, including actions such as Pod recreation that are not expressible as a
Deployment or DaemonSet reference. This accommodates both `rollout_restart` and
`recreate_pod` obligations without copying action definitions into state. The
configuration digest binds those IDs to the same effective action definitions on
resume. Lockout booleans explicitly represent Keystone's
`ignore_lockout_failure_attempts` option; the normal stable value is `false`, while
observed abnormal and transitional values remain representable.

The state retains resolved Keystone object IDs so recovery does not silently adopt
same-name replacements. Generated credential generations are represented only as
`sha256:<64 lowercase hex>` over their exact UTF-8 bytes. Credential values, old
credential fingerprints, tokens, raw API responses and free-form diagnostics are
not fields in the schema. Last errors and verification detail use safe identifier
codes. Completed-request entries are compact and bounded rather than full historical
transactions. Retention policy belongs to a later slice.

The persistence observation keeps the Secret namespace, name, UID and
`resourceVersion` outside the serialized transaction model. UID identifies the
specific Kubernetes object rather than merely its reusable name. Every update is
derived from one such observation. `KubernetesStateStore` uses a narrow direct
Kubernetes Python API transport to issue atomic JSON Patch tests for both UID and
`resourceVersion` before replacing only `data/state.json`. A stale update fails;
future runner logic must discard its stale decision, reobserve, and revalidate
rather than retry the same document blindly. Unrelated Secret data and metadata are
not included in the patch. Explicit kubeconfig context/path selection is supported;
otherwise client construction tries in-cluster credentials before the current
kubeconfig context.

After an accepted patch, the store performs a fresh GET, validates the document
through the normal schema-v2 boundary, checks that the UID is unchanged and that
the typed state equals the intended state, and returns the new `resourceVersion`.
An unobservable or contradictory result fails closed. State persistence and Lease
ownership remain separate concerns.

## Cooperative execution ownership

`Lease/openstack/keystone-admin-rotation` provides temporary cooperative ownership
to one execution UUID. It is precreated infrastructure: the ownership code neither
creates nor deletes it and adds no Job owner reference. The Lease UID identifies
the object, while `resourceVersion` is an optimistic-concurrency precondition.
Acquisition, renewal and release use atomic JSON Patch tests for both values and
change only Lease ownership fields. Lease observations and revisions are transient
and are never serialized into schema-v2 `state.json`.

The defaults are a 120-second Lease duration, 20-second renewal interval,
60-second renewal deadline and 30-second API-call timeout. A dedicated watchdog
renews independently of future workflow code. Holder or UID changes, ambiguous
renewals, malformed observations and renewal-deadline expiry make local ownership
loss/uncertainty sticky for that execution. `assert_owned()` then fails before
future consequential effects. A lost execution stops renewal and never issues a
stale cleanup write. Normal release requires locally fresh ownership, then
reobserves it and uses the same conditional patch discipline.

Lease UTC timestamps are parsed and retained but are not assumed to be synchronized
with another execution's clock. Foreign-owner takeover eligibility instead requires
the same UID, holder identity and `resourceVersion` to remain unchanged for the
observed `leaseDurationSeconds` according to a local monotonic clock. Any record
change resets that local observation window. This contender-side timer is separate
from the owner-side monotonic renewal-freshness timer used by `assert_owned()`.

Fresh acquisition, continued same-execution ownership and expired-Lease takeover
are distinct results. An expired takeover makes the new execution the current
cooperative owner, but it is explicitly marked as requiring a subsequent recovery gate.
Lease expiry is not proof that the previous process is dead or unable to call
Keystone, PasswordSafe or Kubernetes. The Lease is not hard fencing. Mutation
workflows must combine current ownership with fresh external observations,
object-level concurrency and transaction recovery checks.

## External credential-system boundaries

Slice 3A provides direct HTTP client boundaries without connecting them to the
planning CLI or embedding workflow decisions in the adapters. Slice 3B connects
the required clients to durable transaction state and Lease ownership for
PREPARE_B, while Slice 3C consumes their read/authentication behavior for A-state
reconciliation. HTTP calls use bounded 5-second connect and 30-second request
timeouts with configurable trusted CA input. Mutating requests have no automatic
retry. A transport interruption during a mutation is reported as ambiguous so
workflow orchestration must reobserve external state before deciding whether to
act again.

For external mutations, a non-success or malformed response does not by itself
prove that the server did not apply the change. Transport failures, 5xx responses,
unexpected 2xx responses, and untrustworthy success responses are reported as
ambiguous when application cannot be ruled out. Workflow code must reobserve the
actual external state before deciding whether another mutation is permitted.

Keystone v3 password authentication has three typed outcomes: success, definite
credential rejection, and indeterminate. Only an unambiguous authentication 401
is credential rejection. Transport, server, policy and malformed-response failures
remain indeterminate. Success includes the observed user, domain, project, roles
and expiry so workflow policy can validate identity and scope rather than treating
token issuance alone as sufficient. Administrative password updates address the
recorded user ID, and lockout-option updates patch only
`ignore_lockout_failure_attempts`. Both operations use `PATCH /v3/users/{user_id}`
and require HTTP 200 with a response `user.id` matching the requested ID. The
returned representation proves only that Keystone identified the intended resource;
fresh authentication is still required to observe whether an intended password works.

Rackspace Identity Internal v2 exchanges the configured AD service-account
credential for a redacted token used as PasswordSafe `X-Auth-Token`. Normal
PasswordSafe reads use JSON. Password updates PATCH only the password, and HTTP
204 is merely acceptance of the request, not proof of durable completion.
Mutation workflows must use a separate GET to verify the observed credential and
version; PREPARE_B does so for B staging and Slice 3E does so for the admin A
update.
Historical PasswordSafe retrieval is not implemented. Exact old-A history remains
a deferred exceptional recovery capability from the implementation brief; Slice 3C
instead uses current PasswordSafe A and the successful stable-A verification.

Replacement administrative passwords are exactly 32 characters from ASCII
letters, digits and underscore, selected with Python's cryptographic `secrets`
source. Passwords and tokens use the existing redacted `SecretValue`; request
headers/bodies and response content are excluded from representations, and adapter
errors expose fixed diagnostics rather than raw HTTP content. No password or token
is persisted by these clients.

## PREPARE_B workflow

Slice 3B adds the first mutation-capable workflow boundary, without wiring it to
the planning CLI. Before any mutation it rebuilds the topology plan from a fresh
inventory, structurally reads the breeder, requires PasswordSafe A equality,
freshly authenticates A, validates the exact user/domain/project/role/expiry, and
requires the admin user's `ignore_lockout_failure_attempts` value to be `false`.
Disagreement blocks; it is never resolved by choosing one credential source and
overwriting another.

After stable A is established, PREPARE_B classifies B from external observations:

```text
B0  PasswordSafe B does not contain this transaction's intended generation
B1  PasswordSafe B contains it, but fresh authorized B authentication is absent
B2  PasswordSafe B contains it and fresh B authentication proves the recorded
    breakglass identity, domain, project, required role and valid expiry
```

The intended B generation is a SHA-256 identifier only. B-new clear text remains
in memory until it is read back from PasswordSafe. B0 persists the generation and
`STAGE_B_PASSWORDSAFE` pre-dispatch intent, asserts ownership, records
`DISPATCH_UNRESOLVED`, and issues a password-only PATCH. B1 recovers the exact
current PasswordSafe value, persists `RESET_B_KEYSTONE`, obtains fresh validated A
authorization, asserts ownership, records `DISPATCH_UNRESOLVED`, and updates only
the recorded breakglass user ID. B2 performs no B password write.
No old-B fingerprint, PasswordSafe history, rollback, user creation or grant repair
is involved.

Schema-v2 intent state includes `dispatch_unresolved` to distinguish a durable
pre-dispatch intent from an operation that may have reached an external service.
A generated credential becomes sticky at that external dispatch boundary, not
merely when its SHA-256 generation identifier is persisted. Before the boundary,
a candidate proven never to have been dispatched may be abandoned and regenerated
when its clear text is no longer available. Once dispatch is unresolved, or
PasswordSafe contains the intended generation, replacement is forbidden.
After an ambiguous PasswordSafe B write, a matching read-back advances to B1; an
old or unobservable value blocks without retrying or inventing B-newer. After an
ambiguous Keystone reset, fresh successful B authentication advances to B2;
rejection or indeterminacy blocks and preserves the same staged generation. Resume
and Lease takeover always repeat fresh stable-A and B observations. The Lease's
recovery-gate marker does not authorize blind replay.

Every PREPARE_B mutation follows durable pre-dispatch intent, an immediate
ownership assertion, durable dispatch-unresolved recording, one non-retried
external write, and postcondition verification. PasswordSafe B staging is
PREPARE_B's first PasswordSafe mutation;
its verified read-back establishes PasswordSafe mutation capability. PREPARE_B
does not mutate PasswordSafe A or the admin lockout option. Slice 3D's real
lockout-suppression mutation establishes that capability before mutating A.
Verification results retain bounded timestamps and generation identifiers, never
credential values.

Completion revalidates stable A, PasswordSafe B and authorized B authentication,
then records the next phase as `SWITCH_TO_B` and stops. It does not mutate any
managed consumer, begin propagation, suppress lockout, rotate A, or execute any
later phase. Re-entering Slice 3B for an already advanced transaction is a no-op.

## Read-only A credential reconciliation

Slice 3C adds a read-only `a_state.py` library boundary. It freshly reads the
configured PasswordSafe A record and breeder Secret, hashes each exact UTF-8
credential as `sha256:<64 lowercase hex>`, and compares only those identifiers
with the transaction's intended A-new generation. A changed value that does not
match that generation is unknown; difference from old A is never enough to call
it A-new. The successful `stable-a` verification recorded before rotation
establishes both old-A generation identity and the breeder Secret UID. The current
breeder must retain that UID before any credential topology or authentication is
accepted; credential equality cannot legitimize a deleted and recreated object.
No old-A plaintext journal is introduced.

The credential topology and fresh Keystone password authentication produce these
observed states:

```text
A0  PasswordSafe and breeder contain established old A; old A authenticates as
    the expected admin identity, scope and authorization.
A1  PasswordSafe contains established old A, breeder contains intended A-new;
    A-new is definitely rejected and old A authenticates as expected admin.
A2  PasswordSafe contains established old A, breeder contains intended A-new;
    A-new authenticates as expected admin and old A is definitely rejected.
A3  PasswordSafe and breeder contain the identical intended A-new; A-new
    authenticates as expected admin.
```

Successful authentication is accepted only for the recorded admin user ID,
username, user domain, project ID/name/domain, required role ID and unexpired
token. Credential rejection and indeterminate transport/policy/malformed outcomes
remain distinct. Both old and new authenticating, wrong identity or scope,
unknown credential generations, reversed/partial authority topologies, malformed
representations, breeder UID replacement (`BREEDER_IDENTITY_CHANGED`) and lack of
any working admin candidate return typed invalid or indeterminate reconciliation
results rather than being forced into A0-A3. An indeterminate old-A authentication
prevents A2 even when A-new authentication succeeds.

Mutation intent and `DISPATCH_UNRESOLVED` progress are deliberately ignored as
authority: they may explain why recovery is occurring, but observed external
reality determines the credential state. Slice 3C performs no PasswordSafe,
Keystone, breeder, transaction-progress, propagation or runtime write. Lockout
state remains a separate typed transaction fact; this classifier neither reads a
fresh lockout value nor uses lockout suppression to define A0-A3.

## Runtime order and implemented boundaries

The logical runtime transaction remains:

```text
STABLE_A -> PREPARE_B -> SWITCH_TO_B -> VERIFY_B -> ROTATE_A
    -> SWITCH_TO_A -> VERIFY_A -> STABLE_A
```

Implementation slices need not be built in that execution order. Slice 3D is the
bounded `run_rotate_a_stage_breeder` capability and Slice 3E is the bounded
`run_rotate_a_converge` capability. Their existence does not authorize an
end-to-end runner to invoke `ROTATE_A` before the still-required `SWITCH_TO_B` and
`VERIFY_B` runtime gates.

Slice 3D consumes the Slice 3C classifier and begins new staging only from freshly
observed A0. It freshly retrieves and authenticates the authoritative breakglass
credential, persists restoration intent, conditionally suppresses admin lockout by
exact user ID, and requires a positive user read-back before generating A-new.
Only A-new's SHA-256 generation identifier is durable. A candidate lost before
breeder dispatch may be replaced; after `STAGE_A_BREEDER` reaches
`DISPATCH_UNRESOLVED`, its generation is sticky.

The canonical `Secret/openstack/keystone-admin` write uses a direct Kubernetes
JSON Patch with UID and resourceVersion tests, replaces only `data.password`, and
atomically adds transaction ID, A-new generation and `pending-keystone` provenance.
Read-back verifies identity, generation and provenance. Success requires fresh
Slice 3C observation of A1. Lockout remains suppressed, restoration remains
required, and the transaction remains in `ROTATE_A`; no Keystone admin password or
PasswordSafe A mutation is performed.

A failed UID/resourceVersion JSON Patch test (`CONDITIONAL_REJECTED`) is a definite
atomic rejection, not an ambiguous external effect. Slice 3D re-reads the breeder
and, when it is still the stable-UID old-A object without rotation provenance,
returns staging to the pre-dispatch `UNKNOWN` intent state and reports a retryable
conflict. A later
invocation may generate a replacement candidate if the prior cleartext was lost.
`DISPATCH_UNRESOLVED` remains reserved for `OUTCOME_AMBIGUOUS` results such as
timeouts, 429s and 5xx responses where the patch may actually have applied; those
generations stay sticky.

Slice 3E consumes only fresh Slice 3C reality. It revalidates the stable breeder
UID, transaction provenance, and intended generation and recovers the exact
cleartext A-new from the breeder; it never generates A-newer. It also freshly
validates breakglass authorization and requires the admin lockout option to remain
suppressed with durable restoration required.

From A1 it persists `RESET_A_KEYSTONE` intent, asserts ownership, records
`DISPATCH_UNRESOLVED`, resets the recorded admin user ID to exact staged A-new,
and requires fresh A2. From fresh A2 it similarly persists
`UPDATE_A_PASSWORDSAFE`, asserts ownership, records unresolved dispatch, PATCHes
only the admin password, reads the exact record back, and requires fresh A3.
Ambiguous mutations are resolved only by observation; old/unsettled reality stays
unresolved without blind replay, while definite rejection returns to pre-dispatch
retryable progress. Starting at A2 skips the Keystone write and starting at A3
performs no A credential mutation.

Successful Slice 3E means only that the core A credential is converged across the
breeder, Keystone, and PasswordSafe at fresh A3. The transaction remains in
`ROTATE_A`; lockout remains suppressed and restoration remains required. Consumer
propagation, runtime actions, `SWITCH_TO_A`, `VERIFY_A`, lockout restoration,
final transaction completion, and deployment packaging remain separate later
work.

The canonical `ROTATE_A` write order is fixed:

```text
breeder -> Keystone -> PasswordSafe
```

The A0/A1/A2/A3 columns are PasswordSafe / breeder / Keystone:

```text
A0 = old / old / old
A1 = old / new / old
A2 = old / new / new
A3 = new / new / new
```

Completing Slice 3 does not complete the A -> B -> A transaction. In particular,
no implemented orchestration path propagates a complete wave of admin or
breakglass credentials, executes restart dependencies, waits for workload
rollouts, performs service/runtime verification after cutover, restores all
consumers to admin, or performs final `VERIFY_A` and transaction completion.
The one-location Slice 4A primitive does not relax those gates. `VERIFY_B` must
succeed before a production runner enters `ROTATE_A`; independent development and
testing of the bounded `ROTATE_A` machinery does not relax that entry condition.

### Implemented Slice 4A — credential propagation mutation engine

Slice 4A safely mutates one validated
contracted `role: propagated` credential location to an explicitly requested
allowed identity and credential. It covers the existing `FieldsRepresentation`,
`IniRepresentation`, and `YamlRepresentation`, including nested YAML selected by
`document_path`, and requires:

```text
structural mutation
identity and observed-state validation
UID/resourceVersion optimistic concurrency
fresh read-after-write verification
changed / no-op / failure reporting
```

Rotation execution ownership and Kubernetes object concurrency are separate
requirements. The Lease/current execution determines whether this execution is
authorized to perform a rotation mutation. The Secret UID and `resourceVersion`
tests determine whether the named object is still the exact object and observed
state on which the mutation decision was based. A mutating caller must already
hold valid current ownership and must revalidate it with the existing ownership
assertion immediately before the correctness-sensitive write; optimistic
concurrency does not replace that assertion. Slice 4A does not acquire, renew, or
release the Lease and does not own the overall A -> B -> A state machine.
The no-op decision is also correctness-sensitive: a candidate no-op revalidates
ownership before freshly reading and verifying current Secret reality.

Structural mutation may change only the declared username/password selectors
required for the requested target credential. All unrelated configuration must
remain semantically invariant, including other content in `octavia.conf`,
`blazar.conf`, `clouds.yaml`, and embedded generated `clouds.yaml` documents. This
is not arbitrary document rewriting or textual search-and-replace. Serialization
may make harmless formatting changes where byte-preserving output is not
guaranteed; it must not change unrelated configuration semantics.

After a write, Slice 4A must freshly reread the Secret, require the expected UID,
resolve the declared representation successfully, and verify the exact intended
target credential. A successful Kubernetes write response is not verification,
and matching content in a deleted and recreated same-name Secret is not success.

Observed state is an authorization input, not merely a comparison with the
target. A location may be mutated only from a state permitted by the current
higher-level transition and its validated caller intent. An unknown or unexplained
credential must fail closed rather than being treated as "needs update." If the
same intended credential is already present in a permitted state, the result is a
no-op only after ownership revalidation and a fresh read proves the same Secret
UID still contains the exact intended credential. A stale classified snapshot is
never sufficient proof of convergence. No mutation occurred and that invocation
contributes no restart dependency. Only an actually changed location may
contribute its configured restart edges to a later runtime subslice.

`classify_credential_location()` converts a successfully parsed exact admin or
breakglass match into `ClassifiedCredentialLocation`; unknown, unverified, or
unresolvable state never becomes a mutation input. `DesiredCredential` carries a
redacted target value and identity, but construction does not prove that pairing
is authoritative. The higher-level transition must first reconcile/authenticate
the relevant admin or breakglass source and then supply that proven current
credential. No existing source type alone proves that cross-system fact, so Slice
4A deliberately keeps this as an explicit caller precondition rather than adding
a misleading credential wrapper. `mutate_credential_location()` additionally
requires the caller's explicitly permitted observed identities, rejects source
locations and identity-binding violations, and calls the supplied ownership guard
before either a no-op verification read or a write.

`KubernetesApiCredentialSecretClient` replaces only changed Secret data entries
with one JSON Patch guarded by atomic UID and resourceVersion tests. It never
retries a rejected or ambiguous write. HTTP 409 and 412 responses are classified
as conditional rejection; HTTP 422 remains a generic Kubernetes failure because
the available exception fields do not robustly distinguish a failed JSON Patch
`test` from unrelated validation errors without parsing fragile message text.
`CredentialMutationResult` reports
`CHANGED` or `UNCHANGED`, target identity, location, and configured restart
dependencies; `required_restart_dependencies` is empty for no-op results. Stable
`CredentialMutationErrorCode` values distinguish unsafe state, conflicts,
ambiguous writes, Kubernetes failure, and post-write verification failure without
including credential material.

Slice 4A does not execute restart dependencies, orchestrate `SWITCH_TO_B` or
`SWITCH_TO_A`, run `VERIFY_B` or `VERIFY_A`, wait for rollouts, or finalize the
transaction. Those are later Slice 4 subslices. The contract-driven restart edges
remain the model for those later runtime actions.

### Implemented Slice 4B — propagation-wave planning and durable intent

Slice 4B raises propagation planning from one location to the complete applicable
contract set without performing any propagated-Secret mutation. A breakglass wave
contains every `identity: active`, `role: propagated` location. An admin wave
contains every active or fixed-admin propagated location. Source locations never
participate, and fixed-admin locations never switch to breakglass. A location
already at the target remains part of the obligation and is distinguished from a
location that still requires mutation.

The candidate plan groups logical locations by stable `(namespace, Secret name)`;
Secret groups and their member location IDs are sorted deterministically. The
group also retains the observed UID and resourceVersion. Those observations do
not define grouping: UID is an observed-instance safety fact, so a same-name
replacement is reported separately during resume. Each location retains only its
stable ID, expected starting identity/target status, and potential restart
dependencies. The wave contains no cleartext credential. Its target generation
uses the existing SHA-256 generation reference.

The immutable `PropagationWaveIntent` is embedded in the existing schema-v2
`PropagationWave` for `to_b` or `to_a`; no second state store exists. It records:

```text
target identity and generation reference
exact contract-semantics digest
ordered Secret groups and logical location membership
original Secret instance observations
original classified identity/target state
potential restart metadata
```

Read-only candidate construction and reconciliation require no Lease. Persisting
new intent uses the existing conditionally updated transaction record and requires
the current execution ownership assertion. Once intent exists it is reused
exactly; a resume never replaces it by replanning. The planner compares the full
current contract digest and exact applicable membership with durable intent, so
added/removed locations, changed identity or role, moved Secrets, representation
changes, and restart-metadata changes produce typed contract drift rather than an
automatically expanded or reduced wave.

`applied_location_ids` is intentionally only a progress hint. Fresh parsed and
classified Secret state determines reconciliation: an incomplete location already
at target is `ALREADY_CONVERGED`, while a recorded-complete location that is no
longer at target is unsafe. Missing or replaced Secrets, unparseable
representations, unknown credentials, and changes that contradict the original
observation fail closed. Safe output distinguishes confirmed convergence,
already-converged work, and work that still requires mutation.

Restart edges carried by the plan are potential dependencies only. Slice 4B does
not populate runtime actions or infer restart debt merely from membership. Slice
4C must use actual changed mutation results, preserve the explicit same-Secret
relationship during writes, and then record confirmed progress. Slice 4B does not
call `mutate_credential_location()`, restart workloads, wait for rollouts, advance
runtime phases, or complete the transaction.

### Implemented Slice 4C — grouped Secret-level propagation execution

Slice 4C raises propagation from one-location mutation to executing a complete
durable wave. The mutation unit is the Kubernetes Secret; the logical credential
location is the verification and accounting unit; the propagation wave is the
transaction unit. For a group of logical locations sharing one Secret, Slice 4C
performs at most one coherent Secret mutation when mutation is required, rather
than invoking the Slice 4A one-location API repeatedly against the same Secret.

`execute_grouped_propagation_wave()` consumes the durable Slice 4B wave intent
(`PropagationWave` plus its `intent`), a fresh credential reference for the
target, and current transaction ownership, then:

```text
safe pre-reconciliation pass over every Secret group
    ->
compose required per-location transformations in memory
    ->
one CAS-protected Secret write per group that needs it
    ->
fresh reread + per-location verification
    ->
persist changed-location progress
```

**Safe pre-reconciliation pass.** Before any write, every group is freshly
observed: the Secret is GET, its UID is checked against the durable observed UID
(a same-name replacement fails closed), and every participating logical location
is parsed and classified against the known credential references. This all-wave
safety pass is a coarse early gate: an unknown, malformed, replaced, or regressed
location in one group fails the whole wave with no Secret write. Crucially, each
group is **re-observed freshly immediately before it is processed** — the
no-op-versus-mutation decision and the CAS precondition both come from that fresh
snapshot, never from the earlier precheck. This prevents a stale precheck from
accepting a group that another actor changed between the precheck and execution.

**Changed-location accounting.** For each logical location Slice 4C distinguishes
`ALREADY_CONVERGED` (freshly at target, no write this run) from
`CHANGED_BY_THIS_PROPAGATION` (required and performed a mutation). Durable
progress (`applied_location_ids`) advances only for locations that actually
changed plus locations that were already recorded-complete and remain at target.
Because a location's durable intent records `expected_target` (whether it was
already at target when the wave was established), an originally-non-target
location (`expected_target == False`) that is freshly observed at target during
recovery but has no applied marker is conservatively treated as a transition that
occurred during the wave lifetime — our write succeeded immediately before a
crash, or another actor converged the Secret while the wave was active. Its
restart debt is retained in either case, because a runtime consumer may still
require restart. A location that was already target at wave creation
(`expected_target == True`) is not restart debt merely because it remains target.

**Per-group progress persistence.** Verified propagation progress is persisted
after each successfully processed Secret group, not only once at the end of the
full wave. This shrinks the window in which a successful write is not yet backed
by durable accounting. The unavoidable crash between a successful write and the
subsequent progress persistence is still handled by the recovery rule above: on
resume the Secret is already target and the originally-non-target location's
restart debt is reconstructed from the durable intent.

**One conditional write per group.** Each group that requires mutation issues a
single JSON Patch guarded by atomic UID and resourceVersion tests, using the
freshly observed Secret as the CAS precondition (never the planning-time
resourceVersion). The patch replaces only the data keys that actually change.
A definite conditional rejection is a `CONFLICT` (no blind retry); an ambiguous
outcome is a `WRITE_AMBIGUOUS` and is resolved by fresh reobservation on resume,
not by re-issuing the write.

**Fresh verification.** A successful write response is not verification. After
each group write the Secret is freshly reread, its UID is required to match, and
every logical location in the group is reparsed and required to exactly equal the
target credential. Any deviation is `POST_WRITE_VERIFICATION_FAILED`.

**Changed-location accounting.** For each logical location Slice 4C distinguishes
`ALREADY_CONVERGED` (freshly at target, no write this run) from
`CHANGED_BY_THIS_PROPAGATION` (required and performed a mutation). Durable
progress (`applied_location_ids`) advances only for locations that actually
changed plus locations that were already recorded-complete and remain at target.
Restart dependencies are retained from the locations that actually changed and
are passed to the later restart-debt slice; Slice 4C performs no restart.

**Crash/recovery.** Because fresh state is authoritative and progress is a hint:
a crash before the Secret write resumes to the mutation; a crash after the write
but before progress persistence resumes to an already-converged observation with
no duplicate write; a crash after progress persistence resumes to a confirmed
converged state; and progress claiming completion while fresh state regressed is
treated as unsafe. The wave is credential-converged when fresh observation
establishes every intended location at the target and durable progress has been
reconciled — this means only credential propagation is complete, not that runtime
consumers are using the new credential.

Slice 4C does not execute workload restarts, wait for rollouts, discharge restart
debt, perform `SWITCH_TO_B`/`VERIFY_B`/`SWITCH_TO_A`/`VERIFY_A`, restore lockout,
or complete the transaction. Those are later slices.

## Security and deployment limits

A live list reads all Secrets in the namespace, not only the contract's objects.
That read privilege and the process's memory are sensitive. Use trusted kubeconfig
files/executables, protect the host, and do not persist/export real snapshots.
The subprocess output is captured, time-limited, and withheld on errors. The final
inventory byte limit is 128 MiB; subprocess capture itself is not a streaming memory
limit. Pagination is aggregated by kubectl; a still-present continuation token is
rejected at the JSON boundary.

Secret-bearing dataclasses suppress repr, and reporting uses an explicit projection.
Do not assume repr suppression is encryption, memory zeroization, or protection
against debugger/core dumps. No credential hashes are emitted. Safe errors do not
include raw parser/subprocess messages. Metadata names and configured location IDs
remain visible in reports and are operationally sensitive.

Slice 1 planning still uses its constrained, read-only kubectl adapter. Slice 2B
state persistence and Slice 2C Lease ownership instead depend on the Kubernetes
Python client and never invoke kubectl. Their narrow API transports are tested
independently from behavioral fakes that exercise persistence and ownership
semantics.
