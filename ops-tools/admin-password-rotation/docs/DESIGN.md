# Design

Status: Slices 1, 2A, 2B, 2C, 3A, 3B, and 3C are implemented.

- PREPARE_B is implemented as a library workflow and may invoke its narrowly
  scoped B credential mutations.
- Read-only A0/A1/A2/A3 credential-state observation and classification is
  implemented as a library boundary.
- SWITCH_TO_B, A mutation, and all later orchestration remain unimplemented.

## Boundaries

| Module | Responsibility |
| --- | --- |
| `model.py` | Immutable typed configuration, observations, findings and plan data. |
| `config.py` | Validate and normalize the supplied contract; resolve named representations. |
| `syntax.py` | Bounded YAML structure reader with tags and source spans; no constructors or writers. |
| `representations.py` | Read direct fields, explicit INI options, direct/embedded YAML paths. |
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
| `cli.py` | Select input mode, enforce opt-in, report errors and return exit status. |

Configuration validates before any live read. Namespace is fixed to `openstack`
for this slice. The sole source must be fixed-admin `keystone-admin/password`
with no restart dependency. Source is validated; no downstream location can become
its authority. All locations require explicit identity, role, representation and
restart properties. Unknown fields are rejected rather than silently ignored.

Named representations are normalized at load time. Multiple disjoint credential
locations can share a Secret or a document. Overlapping username/password selectors,
mixed formats for one data field, and different embedded document roots within
one field are rejected. These are conservative bootstrap constraints, not claims
that the general design prohibits every such future extension.

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
integration, but supplying a reference still does not prove authentication. This
bootstrap's CLI does not accept a password flag, credential file or environment
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
rejected by this bootstrap parser: test real sanitized shapes before expanding
compatibility. No serializer or mutation method is included.

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
entire A->B->A transaction. The future executor must derive actions from
actual changes and distinguish the B and A transitions. The Slice 1
planner has no resumed-action receipts, action tokens, ownership
protocol or transaction journal; those concerns belong to later
implementation layers described below.

Secret UID and resourceVersion are retained as opaque observations. They are not
ordered or incremented. The inventory is a finite observation, not a lock across
Kubernetes, PasswordSafe and Keystone. Any future mutating command must acquire
ownership and reread relevant state; a saved report cannot be applied.

## Durable transaction state

Schema version 2 defines the future contents of
`Secret/openstack/keystone-admin-rotation-state` at `data/state.json`. This slice
stores that document in a precreated infrastructure Secret; it does not create the
Secret or perform rotation work. Lease ownership is a separate Slice 2C library
boundary. The planning CLI remains read-only and invokes neither boundary.

The state is durable transaction memory, not authority over external reality.
Recorded progress may lag an effect that completed before the next state update.
For that reason the model keeps one explicit current credential-mutation intent,
its observed-effect state, both propagation waves, lockout intent/observations and
bounded latest verification results. Future executors must follow:

```
persist intent -> perform effect -> read/verify actual state -> record progress
```

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
cooperative owner, but it is explicitly marked as requiring a later recovery gate.
Lease expiry is not proof that the previous process is dead or unable to call
Keystone, PasswordSafe or Kubernetes. The Lease is not hard fencing. Future
mutation code must combine current ownership with fresh external observations,
object-level concurrency and transaction recovery checks.

## External credential-system boundaries

Slice 3A provides direct HTTP client boundaries without connecting them to the
CLI, transaction state, Lease acquisition or workflow decisions. HTTP calls use
bounded 5-second connect and 30-second request timeouts with configurable trusted
CA input. Mutating requests have no automatic retry. A transport interruption
during a mutation is reported as ambiguous so future orchestration must reobserve
external state before deciding whether to act again.

For external mutations, a non-success or malformed response does not by itself
prove that the server did not apply the change. Transport failures, 5xx responses,
unexpected 2xx responses, and untrustworthy success responses are reported as
ambiguous when application cannot be ruled out. Later workflow must reobserve the
actual external state before deciding whether another mutation is permitted.

Keystone v3 password authentication has three typed outcomes: success, definite
credential rejection, and indeterminate. Only an unambiguous authentication 401
is credential rejection. Transport, server, policy and malformed-response failures
remain indeterminate. Success includes the observed user, domain, project, roles
and expiry so future policy can validate identity and scope rather than treating
token issuance alone as sufficient. Administrative password updates address the
recorded user ID, and lockout-option updates patch only
`ignore_lockout_failure_attempts`. Both operations use `PATCH /v3/users/{user_id}`
and require HTTP 200 with a response `user.id` matching the requested ID. The
returned representation proves only that Keystone identified the intended resource;
fresh authentication is still required to observe whether an intended password works.

Rackspace Identity Internal v2 exchanges the configured AD service-account
credential for a redacted token used as PasswordSafe `X-Auth-Token`. Normal
PasswordSafe reads use JSON. Password updates PATCH only the password, and HTTP
204 is merely acceptance of the request, not proof of durable completion. Future
workflow must use a separate GET to verify the observed credential and version.
Historical PasswordSafe retrieval is not implemented in Slice 3A. Exact old-A
history remains a deferred exceptional recovery capability from the implementation
brief. Slice 3C does not require it: current PasswordSafe A and the recorded
stable-A generation provide the bounded old-A evidence used by classification.

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
does not mutate PasswordSafe A or the admin lockout option. The later real
lockout-suppression mutation establishes that capability before A rotation.
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
it A-new. Once an intended generation exists, the successful `stable-a`
verification generation recorded before rotation establishes old-A identity.
No old-A plaintext journal or PasswordSafe history retrieval is introduced.

The credential topology and fresh Keystone password authentication produce these
observed states:

```text
A0  PasswordSafe and breeder contain established old A; old A authenticates as
    the expected admin identity, scope and authorization.
A1  PasswordSafe contains established old A, breeder contains intended A-new;
    A-new is definitely rejected and old A authenticates as expected admin.
A2  PasswordSafe contains established old A, breeder contains intended A-new;
    A-new authenticates as expected admin.
A3  PasswordSafe and breeder contain the identical intended A-new; A-new
    authenticates as expected admin.
```

Successful authentication is accepted only for the recorded admin user ID,
username, user domain, project ID/name/domain, required role ID and unexpired
token. Credential rejection and indeterminate transport/policy/malformed outcomes
remain distinct. Both old and new authenticating, wrong identity or scope,
unknown credential generations, reversed/partial authority topologies, malformed
representations and lack of any working admin candidate return typed invalid or
indeterminate reconciliation results rather than being forced into A0-A3.

Mutation intent and `DISPATCH_UNRESOLVED` progress are deliberately ignored as
authority: they may explain why recovery is occurring, but observed external
reality determines the credential state. Slice 3C performs no PasswordSafe,
Keystone, breeder, transaction-progress, propagation or runtime write. Lockout
state remains a separate typed transaction fact; this classifier neither reads a
fresh lockout value nor uses lockout suppression to define A0-A3.

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
