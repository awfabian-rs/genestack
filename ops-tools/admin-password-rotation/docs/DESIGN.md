# Design

Status: Slices 1-3 (through Slice 3E) and Slices 4A-4H are complete.

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
- Slice 4D implements the restart/action executor and restart-debt recovery
  layer: it consumes Slice 4C's durable changed-location accounting, derives
  deduplicated workload restart actions, dispatches the Kubernetes restart
  through direct APIs, observes the resulting rollout, persists per-action
  progress, and recovers outstanding debt after interruption. It does not
  advance runtime phases.
- Slice 4E implements the transaction-level `SWITCH_TO_B` orchestration:
  it composes the Slice 4B/4C propagation machinery and the Slice 4D restart
  executor into a re-entrant phase runner that moves a completed `PREPARE_B`
  transaction through the temporary cutover of every contracted
  `identity: active` location to the breakglass credential, executes the
  resulting restart debt, and advances the durable phase to `VERIFY_B`.
  It does not perform `VERIFY_B` or any later phase.
- Slice 4F implements the transaction-level `VERIFY_B` gate: an
  observational, fail-closed verification of the B safety bridge from fresh
  external state that advances a verified `VERIFY_B` transaction to
  `ROTATE_A`. It does not perform `ROTATE_A` or any later phase.
- Slice 4G implements the transaction-level `ROTATE_A` runtime integration:
  it composes the bounded Slice 3D staging and Slice 3E convergence
  libraries into the `ROTATE_A` runtime phase, gated by the durable
  `verify-b-complete` receipt and the `PREPARE_B` `stable-a` /
  `breakglass-b2` evidence. It advances a converged transaction to
  `SWITCH_TO_A` with the credential-free `rotate-a-complete` receipt.
  It does not perform `SWITCH_TO_A` or any later phase.
- Slice 4H implements the transaction-level `SWITCH_TO_A` runtime
  integration: it composes the Slice 4B/4C propagation machinery (with the
  admin target) and the Slice 4D restart executor into the `SWITCH_TO_A`
  runtime phase, gated by the durable `rotate-a-complete` receipt and the
  `PREPARE_B` `stable-a` / `breakglass-b2` evidence. It freshly reconciles
  the authoritative A boundary at A3 (the propagation source), propagates the
  new admin credential back to every contracted `identity: active` location,
  executes the resulting restart debt, and advances the transaction to
  `VERIFY_A` with the credential-free `switch-to-a-complete` receipt.
  It does not perform `VERIFY_A` or any later phase.
- `VERIFY_A`, lockout restoration, and all later orchestration remain
  unimplemented.
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
| `runtime_rotate_a.py` | The re-entrant `ROTATE_A` runtime integration that composes the bounded Slice 3D staging and Slice 3E convergence libraries into the `ROTATE_A` phase, gated by the durable `verify-b-complete` receipt and `PREPARE_B` evidence, and advances a converged transaction to `SWITCH_TO_A`. |
| `switch_to_a.py` | The re-entrant `SWITCH_TO_A` runtime integration that composes the Slice 4B/4C propagation machinery (admin target) and the Slice 4D restart executor into the `SWITCH_TO_A` phase, gated by the durable `rotate-a-complete` receipt and `PREPARE_B` evidence, fresh-authoritative-A reconciliation at A3, and advances a converged transaction to `VERIFY_A`. |
| `propagation.py` | Classify and conditionally mutate one propagated credential location, then read back and verify it; execute a grouped Secret-level propagation wave with crash/recovery and changed-location accounting. |
| `propagation_wave.py` | Plan complete propagated-location obligations, group them by Secret, and reconcile durable intent against fresh state. |
| `restart.py` | Derive restart actions from durable changed-location accounting, dispatch the Kubernetes workload restart through direct APIs, observe the rollout to completion, persist per-action progress, and recover outstanding debt after interruption. |
| `switch_to_b.py` | Compose the Slice 4B/4C propagation machinery and the Slice 4D restart executor into the re-entrant `SWITCH_TO_B` phase runner that advances a completed `PREPARE_B` transaction to `VERIFY_B`. |
| `verify_b.py` | The re-entrant, observational `VERIFY_B` gate that freshly verifies the B safety bridge (breakglass authentication, participating location state, restart completion, workload health) and advances a verified transaction to `ROTATE_A`. |
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
no implemented orchestration path performs final `VERIFY_A` and transaction
completion. The one-location Slice 4A primitive does not relax
those gates. `VERIFY_B` (Slice 4F) is the implemented gate before a production
runner enters `ROTATE_A`; `SWITCH_TO_A` (Slice 4H) is the implemented phase that
propagates the new admin credential back to the participating `identity: active`
locations and executes its restart debt, returning the consumers to A. Only
`VERIFY_A` (the observational final verification, transaction completion, and
breeder provenance cleanup) remains unimplemented.

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
restart debt is reconstructed from the durable intent. Execution ownership is
reasserted immediately before each durable progress write: the state-store
update is itself a mutation and must obey the same Lease/ownership discipline as
Secret writes. If ownership is lost, the executor raises `OWNERSHIP_LOST` and
does not update transaction state; recovery is left to the next valid executor.
When there is no state change to write, no ownership assertion is performed.

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

### Implemented Slice 4D — restart/action executor and restart-debt recovery

Slice 4D executes and recovers the restart/action debt caused by Slice 4C's
confirmed credential propagation. It consumes the wave's durable
`applied_location_ids` (the changed-location accounting) and the contract's
restart edges; it does not recompute this distinction from current Secret
contents. The unit of work is one deduplicated workload restart action:

```text
derive restart actions from durable changed-location accounting
    (validating the contract digest against the wave intent)
    ->
validate durable runtime action IDs against the derived action set
    ->
persist any missing action records (batch, ownership-fenced)
    ->
for each outstanding action:
    re-observe the workload (fresh reality, not progress)
    ->
    if the restart marker matches and the rollout is complete: confirm
    ->
    else: persist RUNNING (ownership-fenced), reassert ownership,
          dispatch the restart
    ->
    observe the rollout to completion (bounded poll)
    ->
    persist COMPLETE (ownership-fenced)
```

**Restart action derivation.** For each location in the wave's durable changed
set (`applied_location_ids`), its `restart` list contributes one or more
workload actions. The contributed targets are unioned and deduplicated, so
multiple changed locations naming the same workload yield exactly one action.
An empty `restart` list produces no action. The action ID is a stable,
schema-valid identifier derived from the workload (`<kind>_<name>`), and the
action retains its causal location IDs for tests and reporting. No credential
values are involved.

**Restart request identity.** The restart marker written to the workload Pod
template is derived deterministically from the wave's immutable intent
(`restart_request_for`), not from an opaque caller-supplied string. It is a
compact SHA-256 digest of the full identifying tuple (target identity, target
generation, contract digest), prefixed with `genestack-`. Every declared input
contributes to the final marker. It is stable across recovery of the same
restart wave (the intent is immutable), different between logically separate
to-B and to-A restart waves, safe to place in a Kubernetes annotation, and
contains no credential material.

**Direct Kubernetes restart.** The restart is dispatched through the Kubernetes
Python API (AppsV1), not by shelling out to `kubectl`. The executor sets the
`kubectl.kubernetes.io/restartedAt` annotation on the target Deployment or
DaemonSet's Pod template (`spec.template.metadata.annotations`) via a
strategic-merge patch, then re-reads the workload. A successful patch response
alone is not completion. The marker is written to and read from the same
Pod-template location; a top-level workload metadata annotation does not
trigger a rollout and is not considered the restart marker.

**Rollout observation.** After dispatch the executor polls the workload with a
small, explicit poll interval and deadline. Rollout completion is
generation-aware: the workload's `metadata.generation` must have been observed
by the controller (`status.observedGeneration >= metadata.generation`) before
the rollout is considered complete, and the observed Pod-template restart
annotation must equal the expected restart request. A Deployment completes
when, in addition, every desired replica is updated and ready with none
unavailable; a DaemonSet completes when every scheduled node has an updated,
ready replica. A rollout that reports `Failed` (or a
`ProgressDeadlineExceeded` condition on a Deployment) raises `ROLLOUT_FAILED`;
a rollout that does not complete within the deadline raises `ROLLOUT_TIMEOUT`.
The executor considers the action complete only after the required
rollout/replacement has been observed successfully.

**Durable progress and ownership.** Each action's progress is persisted in the
existing schema-v2 `PropagationWave.runtime_actions` (PENDING → RUNNING →
COMPLETE). The ownership sequence around dispatch is:

1. Persist RUNNING (the state-store write fences ownership internally).
2. Reassert ownership immediately before the external Kubernetes mutation.
3. Dispatch the restart.
4. Observe the rollout to completion.
5. Persist COMPLETE (the state-store write fences ownership internally).

This ensures that a loss of ownership between the RUNNING write and the dispatch
is detected: the immediately-pre-dispatch assertion fails and no Kubernetes
mutation occurs. The persisted RUNNING state is acceptable and recoverable.

Before deriving restart actions, the executor validates that the current
contract's canonical digest matches the wave intent's `contract_digest`. A
contract that retains the same location IDs while changing restart edges
produces a different digest and fails closed with `CONTRACT_DRIFT`. The executor
also validates that every durable runtime action ID belongs to the derived
action set; an unexpected durable action ID fails closed with
`STALE_RUNTIME_ACTIONS` rather than remaining unreachable debt.

**Crash/recovery.** On resume the executor re-observes the workload rather than
trusting the last attempted action:

- a crash before dispatch resumes to the dispatch (the action record is PENDING
  and the workload has no matching restart annotation);
- a crash after dispatch but before the completion write resumes to an
  already-restarted, complete workload: the executor confirms completion
  without re-dispatching (the restart annotation matches and the rollout is
  complete);
- a crash after the rollout is observed complete but before the durable
  completion write likewise confirms from fresh observation.

**COMPLETE is a discharged obligation.** A durable `RuntimeActionState.COMPLETE`
record means this transaction's restart obligation was previously observed
complete (written only after a successful rollout observation with matching
restart marker and generation convergence). A subsequent execution does not
re-observe or re-dispatch a COMPLETE action: unrelated workload changes after
the restart should not resurrect old restart debt. Only PENDING and RUNNING
actions are re-observed and conservatively re-dispatched if the workload can no
longer be observed as restarted-and-complete.

The executor never issues credential mutations; restart debt that was not yet
dispatched remains durable and recoverable. The wave's restart debt is not lost
merely because the credential locations are already at their target values.

Slice 4D does not perform `SWITCH_TO_B`/`VERIFY_B`/`SWITCH_TO_A`/`VERIFY_A`,
restore lockout, complete the transaction, or compose propagation and actions
into a runtime phase. Those are later slices.

### Implemented Slice 4E — SWITCH_TO_B orchestration

Slice 4E composes the already-implemented Slice 4B/4C propagation machinery and
the Slice 4D restart executor into the `SWITCH_TO_B` runtime phase. It does not
introduce a second propagation or restart framework; it orchestrates the
existing typed boundaries:

```text
validate transaction / phase / identity / environment / config
    (fresh PasswordSafe B + fresh breakglass auth + fresh admin breeder)
require the phase-qualified durable PREPARE_B completion evidence
    (a single SUCCESS stable-a receipt AND a single SUCCESS breakglass-b2
    receipt, both explicitly at phase PREPARE_B)
    ->
assert current Lease ownership
    ->
re-stamp the durable transaction's current execution on resume
    ->
plan or reconcile the immutable to-B propagation intent   (4B)
    ->
persist the intent durably when newly created (ownership-fenced) (4B)
    ->
execute the grouped propagation wave (4C)
    ->
execute and recover the derived restart debt (4D)
    ->
reobserve: require the wave to be safely reconciled and no debt outstanding
    ->
advance the durable phase to VERIFY_B (ownership-fenced) and stop
```

**Entry conditions.** `run_switch_to_b` proceeds only when a current transaction
exists, its phase is `SWITCH_TO_B`, the environment and Keystone/PasswordSafe
identity match the request, and the transaction's breakglass generation is
established. Phase plus generation are *intent and history*, not proof that
`PREPARE_B` actually succeeded, so the entry validation additionally requires the
durable `PREPARE_B` completion evidence to be present and internally consistent.
Each required receipt is matched on **both** `check_id` and `phase`, so a
same-named receipt originating from another phase is treated as missing:

- a single, `SUCCESS` `stable-a` verification receipt explicitly at phase
  `PREPARE_B`, carrying the old-A `credential_generation` and the breeder
  `target_uid` that `PREPARE_B` verified; and
- a single, `SUCCESS` `breakglass-b2` verification receipt explicitly at phase
  `PREPARE_B`, whose `credential_generation` equals the transaction's
  `new_b_sha256`.

A missing or wrong-phase receipt (`PREPARE_B_PREREQUISITE_MISSING`), a
non-`SUCCESS` or malformed/ambiguous (zero or multiple matching) receipt
(`PREPARE_B_PREREQUISITE_INVALID`), a missing required generation/UID, or a
`breakglass-b2` generation that disagrees with `new_b_sha256` fails closed before
any observation, mutation, or phase work. The evidence is *validated*, not
synthesized: the runner does not fabricate a missing `stable-a` record from the
current breeder.

It does not trust a stale `PREPARE_B` result: the authoritative B credential is
recovered freshly from PasswordSafe (the same
"current PasswordSafe value plus the recorded generation" discipline `PREPARE_B`
uses for `B1`) and its identity is re-validated by a fresh, correctly-scoped
breakglass Keystone authentication. The canonical admin breeder is re-read and
required to agree with the durable `stable-a` receipt — both the recorded old-A
generation and the breeder Secret UID; a changed or regenerated breeder fails
closed (`ADMIN_REFERENCE_INVALID`) because the propagation reference would then be
wrong. Unknown or contradictory state fails closed before any Secret mutation.

**Execution identity.** `transaction.execution` records the execution currently
operating/resuming the transaction. It is credential-free bookkeeping, **not**
the fencing mechanism: current Lease ownership (via `OwnershipGuard.assert_owned`)
is the authoritative source of mutation permission. The three identifiers are
distinct and must not be conflated:

```text
Lease                      = who is allowed to mutate now
transaction.execution      = which execution is currently operating the transaction
transaction_id             = which durable transaction this is
```

A durable update to transaction state — including the credential-free
`transaction.execution` field — is itself a mutation, so current Lease ownership is
asserted **before** the re-stamp. On every resume `run_switch_to_b` re-stamps
`transaction.execution` to the request's execution (a legitimate takeover by
execution `E2` updates the durable field to `E2`), via a CAS-protected
state-store write that is performed only after the ownership assertion; when the
durable execution already matches the resuming one it is a no-op. A stale
execution that has lost the Lease cannot modify the durable transaction at all —
even the bookkeeping field — because the ownership assertion precedes the write.
This is intended as a **transaction-wide invariant**, not a `PREPARE_B`- or
`SWITCH_TO_B`-specific convention. Bounded technical debt: the older `ROTATE_A`
Slice 3D/3E entry points (`RotateAStageInputs`) do not carry an `execution` field
and so do not uniformly maintain `transaction.execution`; that should be
normalized when orchestration reaches that boundary, and is deliberately out of
scope for this corrective pass.

**Propagation target.** For this phase the target identity for every contracted
`identity: active` propagated location is `breakglass`, using the transaction's
established B generation. Fixed-identity `identity: admin` locations, and in
particular the canonical `Secret/openstack/keystone-admin` breeder, are never
switched to B. The work set is derived from the credential-location contract and
the generic propagation machinery, not a bespoke list of Secret names.

**Transaction progress.** No new schema object is added. The existing
`PropagationWave` fields already distinguish every required recovery state: the
immutable `intent` (created by 4B), `applied_location_ids` (changed-location
accounting from 4C), and `runtime_actions` (`PENDING`/`RUNNING`/`COMPLETE` from
4D). `SWITCH_TO_B` is complete when fresh observation establishes every intended
location at the target, the wave is safely reconciled, and every derived runtime
action is `COMPLETE`. At that point the phase advances to `VERIFY_B` and a
credential-free `switch-to-b-complete` verification receipt (carrying only the
B generation) is recorded. The phase advance is ownership-fenced.

**Recovery and re-entry.** Every interruption boundary is recovered by observing
the durable state and continuing the existing transaction:

- no intent yet: the to-B obligation is planned and persisted once;
- intent persisted but no propagation: the grouped wave executes from fresh
  observation, with already-converged locations reported as no-ops;
- partial propagation: 4C's crash/recovery model resumes without replaying
  completed Secret writes and retains originally-non-target restart debt;
- propagation complete, restart debt pending: 4D derives and executes the
  actions from the durable changed-location accounting;
- some runtime actions `RUNNING`: 4D re-observes each workload and confirms a
  matching complete rollout without re-dispatch, otherwise conservatively
  re-dispatches;
- all actions `COMPLETE` but phase not yet advanced: the reobserve gate passes
  and the phase advances without any needless redispatch.

It does not blindly replay every Secret write, restart every workload, generate
or stage a new B credential, or create a new transaction on re-entry. Stale,
unknown, contradictory, concurrent, or contract-drift state reported by the
existing machinery fails closed with the established typed semantics.

**Exclusions.** Slice 4E performs no `VERIFY_B` (no service/authentication/health
verification of the B safety bridge), no `ROTATE_A`, no `SWITCH_TO_A` /
`VERIFY_A`, no lockout restoration, no final transaction completion or
cleanup, and no Kubernetes Job/CronJob packaging or RBAC. It stops at the
`VERIFY_B` boundary.

### Implemented Slice 4F — VERIFY_B gate

Slice 4F implements the transaction-level `VERIFY_B` gate: the hard,
fail-closed, resumable verification that the B safety bridge created by
`SWITCH_TO_B` is real and sufficient to permit `ROTATE_A` to begin. It is
**observational**: it never writes a propagated Secret, never dispatches or
re-runs a workload restart, never mutates the `admin` credential or lockout
policy, and generates no new credential. Aside from ownership-fenced
execution bookkeeping re-stamping on resume/takeover, its only semantic
transaction write is the successful `VERIFY_B` -> `ROTATE_A` phase advance
plus a credential-free `verify-b-complete` verification receipt (carrying
only the B generation) recorded at phase `VERIFY_B`. A verification failure
never advances the phase and never writes the receipt; if a re-stamp was
required it may have persisted only that execution bookkeeping.

```text
validate transaction / phase / identity / environment / config
    (a transaction already past VERIFY_B returns ALREADY_ADVANCED
     without re-running the checks or regressing the phase; a
     transaction still in SWITCH_TO_B is rejected)
require the phase-qualified durable completion evidence:
    a single SUCCESS switch-to-b-complete receipt at SWITCH_TO_B whose
    generation equals the transaction's B generation, plus the PREPARE_B
    stable-a/breakglass-b2 receipts that anchor the admin reference
    ->
re-stamp the durable transaction's current execution on resume
    (ownership-fenced bookkeeping, no-op when already current)
    ->
fresh breakglass B observation (PasswordSafe) + generation match
    ->
fresh breakglass Keystone authentication (identity-validated)
    ->
fresh admin breeder observation (must still match the stable-a receipt)
    ->
fresh per-location structural classification of every participating
    identity: active location (all must be the verified B credential)
    ->
every derived restart action durably COMPLETE
    ->
fresh observation that every affected workload is complete with the
    deterministic restart marker
    ->
advance the durable phase to ROTATE_A (ownership-fenced) and stop
```

**Fresh breakglass bridge.** A successful earlier authentication (PREPARE_B
`B2`, the `SWITCH_TO_B` entry check) is stale evidence. The authoritative B
value is re-derived from PasswordSafe — the current record must carry the
transaction's recorded B generation — and its identity is re-validated by a
fresh, correctly-scoped breakglass Keystone authentication (recorded user,
domain, project, role, expiry). Rejection, generation drift, or indeterminacy
fails closed.

**Participating location verification.** The verification set is the complete
applicable membership of the B transition: every `role: propagated`,
`identity: active` location in the current contract — the same membership the
immutable wave intent was derived from. Durable progress flags
(`applied_location_ids`) are not proof: a location that was already at target
when the wave was planned is absent from the changed set yet still required to
hold B now. Every active location is freshly read through the supplied Secret
client, structurally parsed with its declared representation, and required to
equal the verified breakglass credential (username `breakglass`, exact B
password, per the location's exact fields). Any of: missing Secret, unparseable
representation, unknown credential, still on `admin`, a different breakglass
password, or any other unrecognized state fails the gate
(`LOCATION_UNVERIFIED`). Fixed `identity: admin` propagated locations do not
participate in the `admin -> breakglass -> admin` identity transition: the
contract defines them as remaining associated with `admin`, so they are
required to match the verified admin reference and fail closed on any other
state — including a breakglass credential (a password-only fixed-admin
consumer semantically interprets the stored password as belonging to
`admin`, so a breakglass password there is not a valid B transition), a
missing Secret, a malformed representation, or a wrong admin password. The
canonical `keystone-admin` breeder is re-read and required to still anchor the
durable `stable-a` receipt (old-A generation and breeder UID) — a changed or
regenerated breeder fails closed because a location "still matching admin"
would then be matching a wrong reference.

**Restart and workload verification.** Restart actions are derived exactly as
the Slice 4D executor derives them (`derive_restart_actions` from the wave's
durable changed-location accounting, validating the contract digest against
the immutable intent); stale durable action IDs and contract drift fail closed
(`CONTRACT_DRIFT`). Every derived action must be durably `COMPLETE`, and every
affected workload must be freshly observed complete for this wave — generation
convergence, converged replica counters, and the deterministic
`restart_request_for` marker present in the Pod template — reusing the Slice
4D workload abstraction and completion predicate. The gate observes; it does
not re-dispatch a restart, even for a durable PENDING/RUNNING action: the
executor owns that reconciliation, and a not-yet-complete obligation is
simply a failed gate that re-observes on retry.

**Transaction progress.** No new schema object is added. The phase advance to
`ROTATE_A` plus the credential-free `verify-b-complete` receipt (B generation
only) is the entire durable record of success, and the `verify-b-complete`
receipt is written only on success. A failed verification persists nothing
except the credential-free execution bookkeeping re-stamp performed on resume
(the same discipline as every other phase); it never writes a
`verify-b-complete` receipt and never advances the phase, so the transaction
remains in `VERIFY_B` and the phase itself is the resumable marker. Current
Lease ownership is asserted immediately before the phase advance (and before
the execution re-stamp when it writes); a lost owner cannot advance the
transaction.

**Recovery and re-entry.** Re-invocation is deterministic and idempotent: only
genuine successor phases (`ROTATE_A`, `SWITCH_TO_A`, `VERIFY_A`) report
`ALREADY_ADVANCED` without re-running the checks or regressing the phase;
predecessor phases (`STABLE_A`, `PREPARE_B`, `SWITCH_TO_B`) are rejected with
`UNSUPPORTED_PHASE` because the B bridge has not durably been established by
this transaction; a crash after all checks but before the phase advance simply
causes the checks to run again; and a failed verification (recoverable or
invalid/contradictory) leaves the transaction exactly as found for
re-observation. The result vocabulary distinguishes
`VERIFIED` (bridge freshly observed and sufficient), `NOT_VERIFIED`
(bridge does not currently hold: location/restart/workload), and
`UNABLE_TO_VERIFY` (invalid/contradictory evidence or unavailable external
dependency); none of them advance a transaction that does not currently hold
the bridge.

**Exclusions.** Slice 4F performs no `ROTATE_A`, no A credential generation,
staging, or mutation, no Keystone admin password or PasswordSafe admin
mutation, no `SWITCH_TO_A` / `VERIFY_A`, no lockout restoration (lockout state
is not read or verified in this gate), no final transaction completion, and no
Kubernetes Job/CronJob packaging or RBAC. It stops at the `ROTATE_A` boundary
with the admin credential untouched.

### Implemented Slice 4G — ROTATE_A runtime integration

Slice 4G implements the transaction-level `ROTATE_A` runtime integration: the
phase that, behind the now-implemented `VERIFY_B` gate, composes the bounded
Slice 3D staging and Slice 3E convergence libraries into the `ROTATE_A`
runtime phase and advances a converged transaction to `SWITCH_TO_A`.

```text
validate transaction / phase / identity / environment / config
    (a transaction already past ROTATE_A returns ALREADY_ADVANCED
     without re-running the machinery; a predecessor phase is rejected)
require the phase-qualified durable completion evidence:
    a single SUCCESS verify-b-complete receipt at VERIFY_B whose
    generation equals the transaction's B generation, plus the PREPARE_B
    stable-a/breakglass-b2 receipts that anchor the old-A reference
    ->
re-stamp the durable transaction's current execution on resume
    (ownership-fenced bookkeeping, no-op when already current)
    ->
run or resume Slice 3D staging (run_rotate_a_stage_breeder):
    fresh A0 -> lockout suppression + A-new generation + breeder staging;
    A1/A2/A3 -> resume without re-staging
    ->
run or resume Slice 3E convergence (run_rotate_a_converge):
    A1 -> Keystone reset -> A2 -> PasswordSafe update -> fresh A3;
    A2 -> PasswordSafe update -> fresh A3;
    A3 -> no A mutation
    ->
fresh final A3 re-verification through the Slice 3C observation machinery
    (fresh breeder read, fresh PasswordSafe A read, fresh admin Keystone
    authentication); requires a valid A3 classification
    ->
advance the durable phase to SWITCH_TO_A (ownership-fenced) with the
    credential-free rotate-a-complete receipt (A generation only) and stop
```

**Entry conditions.** `run_rotate_a` proceeds only when a current transaction
exists, its phase is `ROTATE_A`, the environment and Keystone/PasswordSafe
identity match the request, and the transaction's B generation is
established. The phase-qualified `verify-b-complete` receipt (at phase
`VERIFY_B`, generation equal to `new_b_sha256`) proves the B safety bridge
durably passed the gate; the `PREPARE_B` `stable-a` / `breakglass-b2`
receipts anchor the old-A generation and breeder UID that the A0-A3
machinery validates against. Missing, wrong-phase, non-success, malformed, or
generation-inconsistent evidence fails closed before any observation,
mutation, or phase work. The evidence is *validated*, never synthesized.

**Composition.** The runtime slice adds no new credential-mutation logic. It
composes the bounded Slice 3D and Slice 3E libraries, which own every
correctness-sensitive mechanism: password generation, breeder staging with
transaction provenance, Keystone/PasswordSafe mutation, ambiguous-dispatch
recovery, A-state classification, and read-after-write verification. The
runtime's own durable writes are limited to the ownership-fenced execution
re-stamp and the phase advance with the credential-free `rotate-a-complete`
receipt. A bounded-library failure is re-raised unchanged (the operator sees
the library's own typed error category) and leaves the transaction blocked in
`ROTATE_A` for re-observation.

**Recovery and re-entry.** Re-entry is safe across every interruption
boundary:

- fresh A0: Slice 3D establishes lockout suppression, generates and durably
  identifies A-new, and stages the canonical breeder with transaction
  provenance; Slice 3E then converges from A1;
- fresh A1: Slice 3D resumes without re-staging (the breeder already holds
  the intended A-new with transaction provenance); Slice 3E resets Keystone
  and converges PasswordSafe;
- fresh A2: Slice 3D reports ahead-of-slice; Slice 3E updates PasswordSafe
  and converges to A3;
- fresh A3: both libraries skip their mutation work; the runtime performs a
  fresh final A3 re-observation and advances the phase.

The staged A-new generation is immutable once durably established: recovery
from A1, A2, or A3 never generates a replacement credential. Durable progress
flags are never authority: the A0-A3 classifier and the bounded libraries
classify from observed external state, and contradictory progress is either
reconciled from observation or fails closed.

**Fresh final A3 verification.** Before the phase advances, the runtime
re-observes the authoritative A boundary directly through the Slice 3C
machinery: a fresh breeder read, a fresh PasswordSafe A read, and a fresh
admin Keystone authentication. The result must be a valid A3 classification
at the transaction's A generation. Any invalid, indeterminate, or non-A3
classification fails closed before the phase advances. This verification is
of `ROTATE_A`'s authoritative boundary only; it does not inspect propagated
credential locations (that is `SWITCH_TO_A` / `VERIFY_A` work).

**Completion receipt.** The phase advance to `SWITCH_TO_A` is accompanied by
a credential-free `rotate-a-complete` verification receipt (at phase
`ROTATE_A`, carrying the A generation only). The receipt is written only on
success; a failed invocation never writes it and never advances the phase.
The receipt and phase advance are a single ownership-fenced CAS-protected
state-store write.

**Exclusions.** Slice 4G performs no `SWITCH_TO_A` (no propagated-location
mutation, no workload restart), no `VERIFY_A`, no lockout restoration (lockout
remains suppressed, restoration remains required), no breeder provenance
cleanup (the transaction provenance remains on the canonical breeder), no
final transaction completion, and no Kubernetes Job/CronJob packaging or
RBAC. It stops at the `SWITCH_TO_A` boundary with the temporary breakglass
propagation still in place.

### Implemented Slice 4H — SWITCH_TO_A runtime integration

Slice 4H implements the transaction-level `SWITCH_TO_A` runtime integration:
the phase that, behind the now-implemented `ROTATE_A` gate, propagates the
newly rotated `admin` credential back to every contracted `identity: active`
credential location (reusing the Slice 4B/4C propagation machinery with the
admin target) and executes the resulting restart debt (Slice 4D), then
advances the durable phase to `VERIFY_A`.

```text
validate transaction / phase / identity / environment / config
    (a transaction already past SWITCH_TO_A returns ALREADY_ADVANCED
     without re-running the machinery; a predecessor phase is rejected)
require the phase-qualified durable completion evidence:
    a single SUCCESS rotate-a-complete receipt at ROTATE_A whose
    generation equals the transaction's A generation, plus the
    PREPARE_B stable-a / breakglass-b2 receipts that anchor the old-A
    reference and breeder UID
    ->
re-stamp the durable transaction's current execution on resume
    (ownership-fenced bookkeeping, no-op when already current)
    ->
fresh authoritative-A reconciliation (Slice 3C): fresh breeder read,
    fresh PasswordSafe A read, fresh admin Keystone authentication;
    require a valid A3 at the transaction's A generation; the breeder
    value is the propagation source
    ->
fresh breakglass B reference (PasswordSafe + breakglass auth) for the
    known-credential classification set
    ->
plan or reconcile the immutable to-A propagation intent   (4B)
    ->
persist the intent durably when newly created (ownership-fenced) (4B)
    ->
execute the grouped propagation wave (4C) with the fresh A reference:
    every identity: active location converges from breakglass/B to
    admin/new-A; fixed-admin locations are no-ops
    ->
execute and recover the derived restart debt (4D)
    ->
reobserve: require the wave to be safely reconciled and no debt outstanding
    ->
advance the durable phase to VERIFY_A (ownership-fenced) with the
    credential-free switch-to-a-complete receipt (A generation) and stop
```

**Entry conditions.** `run_switch_to_a` proceeds only when a current
transaction exists, its phase is `SWITCH_TO_A`, the environment and
Keystone/PasswordSafe identity match the request, the transaction's A
generation is established, and the phase-qualified `rotate-a-complete`
receipt (at phase `ROTATE_A`, generation equal to `new_a_sha256`) plus the
`PREPARE_B` `stable-a` / `breakglass-b2` evidence are present and internally
consistent. A transaction already past `SWITCH_TO_A` (`VERIFY_A`) reports
`ALREADY_ADVANCED` deterministically without re-running the machinery; a
predecessor phase is rejected as `UNSUPPORTED_PHASE`. Each receipt is matched
on both `check_id` and `phase`, so a same-named receipt from another phase is
treated as missing. Missing, wrong-phase, non-success, malformed, or
generation-inconsistent evidence fails closed before any observation,
mutation, or phase work. The evidence is *validated*, never synthesized.

**Fresh authoritative-A reconciliation.** The propagation source is not
trusted from any single location in isolation. Before propagating, the phase
re-derives the A3 reality through the Slice 3C observation machinery (fresh
breeder read, fresh PasswordSafe A read, fresh admin Keystone authentication)
and requires the result to classify as a valid A3 at the transaction's A
generation. The breeder is the canonical Kubernetes breeder for `admin`; its
transaction provenance does not make its password semantically less
authoritative. At A3 the breeder and PasswordSafe A hold the identical value,
and because `ROTATE_A` writes `breeder -> Keystone -> PasswordSafe` the breeder
is the freshest A source; its exact value is the propagation source. Any
invalid, indeterminate, or non-A3 classification fails closed, and a breeder
generation that does not match `new_a_sha256` is a contradiction that also
fails closed. No new password is generated.

**Propagation target.** For this phase the target identity is `admin`, using
the transaction's established A generation. Under the contract semantics the
admin wave's applicable membership is every `role: propagated` location whose
identity is `active` **or** fixed `admin`: the `identity: active` locations
converge from `breakglass`/B to `admin`/new-A, while fixed-`identity: admin`
propagated locations (which were never switched to B) are already at the new-A
reference and are no-ops. The canonical `keystone-admin` source is never a
propagation target. The breakglass (B) credential is recovered freshly from
PasswordSafe at the recorded B generation and validated by a fresh breakglass
Keystone authentication; it is supplied only as the known-credential reference
that lets the machinery recognize a participating `identity: active` location
currently holding B, and is never propagated.

**Restart debt.** Restart debt derives from the durable changed-location
accounting exactly as the Slice 4D executor derives it (validating the
contract digest against the wave intent). Only locations that actually
changed (i.e. the `identity: active` ones that required a B -> A mutation)
contribute restart edges; a fixed-admin no-op contributes none. Restart
targets are deduplicated, and only the restart debt produced by this wave is
executed. The phase does not restart consumers merely because they appear in
the contract.

**Recovery and re-entry.** Every interruption boundary is recovered by
observing the durable state and continuing the existing transaction:

- no intent yet: the to-A obligation is planned and persisted once;
- intent persisted but no propagation: the grouped wave executes from fresh
  observation, with already-converged locations reported as no-ops;
- partial propagation: 4C's crash/recovery model resumes without replaying
  completed Secret writes and retains originally-non-target restart debt;
- propagation complete, restart debt pending: 4D derives and executes the
  actions from the durable changed-location accounting;
- some runtime actions `RUNNING`: 4D re-observes each workload and confirms a
  matching complete rollout without re-dispatch, otherwise conservatively
  re-dispatches;
- all actions `COMPLETE` but phase not yet advanced: the reobserve gate passes
  and the phase advances without any needless redispatch.

It does not blindly replay every Secret write, restart every workload,
generate or stage a new A credential, or create a new transaction on re-entry.
Stale, unknown, contradictory, concurrent, or contract-drift state reported by
the existing machinery fails closed with the established typed semantics.

**Exclusions.** Slice 4H performs no `VERIFY_A` (no observational final
verification of the whole system, no service-health gate beyond what restart
completion requires, no STABLE_A declaration), no Keystone/PasswordSafe admin
mutation, no new password generation, no lockout restoration (lockout remains
suppressed, restoration remains required), no breeder provenance cleanup (the
transaction provenance remains on the canonical breeder), no transaction
completion, and no Kubernetes Job/CronJob packaging or RBAC. It stops at the
`VERIFY_A` boundary with the participating consumers returned to A.

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
