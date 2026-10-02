# Automated Keystone Administrative Password Rotation
## Minimal one-shot implementation specification

**Version:** 0.1 - implementation and review baseline  
**Date:** 2026-09-25  
**Project:** Genestack / OSPC-2361  
**Executable:** `keystone-admin-rotate`  
**Normative companion:** `transaction.schema.json`  
**Configuration companions:** `environment.example.yaml`, `credential-contract.baseline.yaml`

The words MUST, MUST NOT, SHOULD, and MAY express implementation requirements. Examples containing `REQUIRED_...` are deliberately incomplete environment configuration, not operational discoveries. No implementation or production rotation was executed in preparing this specification.

## 1. Scope and authority

Implement a finite Python program that plans, executes, resumes, verifies, and reports one administrative password rotation in one Kubernetes/OpenStack environment. Run mutating invocations as Kubernetes Jobs. The transaction survives the process; the process does not remain running between invocations.

The current design authority is the retrieved `synopsis(1).md`, supplemented by the current credential-location contract, superseding A/B state machine, ROTATE_A write-ordering decision, persistent-transaction decision, concurrency decision, established PasswordSafe behavior, and the explicit admin-client and lockout requirements supplied for this specification. Section 20 identifies the sources. Older symmetric A/B, permanent-service, and broad chart-reinstallation explorations are not implementation requirements. [S1-S9]

The implementation rotates **admin**, using an already provisioned, independently verified **breakglass** account. It does not create users, change grants, rotate breakglass, retrieve password history, repair arbitrary drift, or automatically roll back passwords. Breakglass credential lifecycle remains a separate operational responsibility. PREPARE_B means preparation for use, not an additional credential-rotation transaction.

Non-goals are a Kubernetes operator, HTTP API, permanent controller, generic workflow engine, multi-cluster coordinator, Helm redeployment, host-file mutation, continuous drift correction, and removal of existing service dependencies on admin. A later CronJob may schedule this executable without changing its transaction semantics.

## 2. Terminology and invariants

### 2.1 Identities and generations

| Term | Meaning |
|---|---|
| A | Keystone user `admin` in domain `default`; canonical deployment identity. |
| B | Keystone user `breakglass` in domain `default`; durable alternate identity. |
| `admin_old` | A credential verified at transaction creation. |
| `admin_new` | Replacement A credential; authoritative generation is fixed once durably staged. |
| `breakglass` generation | B credential retrieved from its configured PasswordSafe record and verified before use. |
| breeder | `Secret/openstack/keystone-admin`, field `data.password`. |
| location | One declared structural credential representation, not necessarily an entire Secret. |
| action | Runtime reconciliation required because a location actually changed. |
| wave | `to_b` or `to_a`; a propagation barrier followed by its runtime actions. |
| transaction T | Durable rotation intent and recovery context. |
| execution E | One program invocation with its own UUID and ownership epoch. |

Resolve user, domain, project, and required role names to IDs; record those IDs in T. Authenticate and mutate by those IDs thereafter. Domain names are not assumed to equal domain IDs. The normal project and project domain are `admin` and `default`. Configuration supplies the management-token scope actually authorized by the deployment.

### 2.2 Stable invariants

A successful transaction establishes all of the following from fresh observations:

1. PasswordSafe(admin), breeder, and the credential that freshly authenticates as the recorded admin user are equal to `admin_new`.
2. Every active propagated location represents admin; every fixed-admin propagated location contains `admin_new`; no managed active location remains on B.
3. All actions caused by actual mutations have completed and their required runtime and functional checks pass.
4. `openstack-admin-client` exists, is Ready, and freshly authenticates as the recorded admin user in the expected project.
5. Admin's `ignore_lockout_failure_attempts` is explicitly false after restoration, or a documented server representation normalizes false to absence. No successful transaction leaves it true.
6. The transaction has a verified terminal receipt and no active staging/mutation annotations remain on managed Secrets.

The breeder always semantically represents **admin**. Its value may be a pending new admin password in recognized A1 state. It must never contain B. [S1, S3, S4]

### 2.3 Transitional invariants

Only the current fenced execution may attempt mutations. Intent precedes every consequential credential, runtime or provenance-cleanup write. Lease acquisition/renewal and writes of the journal itself are directly conditional state operations, not recursively journaled effects. Object identity and optimistic concurrency are checked. Unknown credentials, unexplained authoritative disagreement, unrecognized topology, and conflicting provenance stop mutation.

Before A is invalidated, every participating runtime consumer must have a verified B credential path. Lockout suppression is not a substitute for this protection. A fixed-admin location may remain old only where discovery establishes that no active or spontaneously starting consumer will use that value during the vulnerable interval.

A0/A1/A2/A3 are **observed credential states**, not program counters. A progress flag can lag reality; it cannot authorize overwriting contradictory reality. Old A need only remain recoverable through the period when PasswordSafe still contains it. After A3, fingerprints are sufficient to identify known old downstream copies; password history is unnecessary.

## 3. Program architecture and dependencies

Use Python 3.12 as the initial language target, with Pyright strict over production code and tests. Pin tested dependency versions and the image digest in the release lockfile; do not resolve floating versions at Job startup.

A small package is sufficient:

```text
rotation/
  cli.py                # arguments, result serialization, exit codes
  models.py             # validated models and finite enums
  config.py             # configuration and manifest validation
  representations.py    # fields / INI / YAML read and structural mutation
  clients.py            # typed Kubernetes, Keystone, PasswordSafe adapters
  state.py              # record persistence, fingerprints, ownership
  actions.py            # two runtime handlers and probe execution
  runner.py             # explicit phase functions and recovery classifier
```

Use standard-library `dataclasses`, `enum`, `secrets`, `hashlib`, `hmac`, `uuid`, and logging. Use Pydantic v2 strict models with `extra='forbid'` for configuration and persistent records, `ruamel.yaml` safe/round-trip parsing for YAML, the Kubernetes Python client behind a narrow typed adapter, and `httpx` for direct HTTP. External JSON is runtime-validated before entering the typed core. Handwritten adapter stubs or narrowly scoped casts may contain untyped third-party boundaries; `Any`, unchecked casts, and ignored errors must not spread into planning or state-machine code.

The runner performs consequential effects sequentially. A small renewal/watchdog thread maintains ownership and a sticky stop flag. There is no service scheduler or parallel mutation executor. Transports have bounded calls; ownership loss prevents subsequent effects even when the main runner resumes from a delayed call.

Example internal distinctions:

```python
@dataclass(frozen=True)
class Credential:
    identity: Identity
    password: SecretValue  # repr and str are redacted; explicit reveal at adapters

@dataclass(frozen=True)
class ClassifiedLocation:
    location_id: str
    generation: Generation
    fingerprint: Fingerprint
    object_uid: str
    resource_version: str

@dataclass(frozen=True)
class MutationResult:
    operation_id: UUID
    changed_location_ids: tuple[str, ...]
    observed_uid: str
    observed_resource_version: str

Action = RolloutRestart | RecreatePod
AuthResult = AuthenticatedIdentity | AuthenticationRejected | DependencyUnavailable
```

`UnknownCredential` is a classification error, not a credential that can be passed to a mutation adapter. Secret-bearing objects must not use generic `asdict()`/model dumping for logs or records.

```toml
[tool.pyright]
pythonVersion = "3.12"
typeCheckingMode = "strict"
include = ["rotation", "tests"]
```

### 3.1 OpenStack boundary

Use direct Keystone v3 HTTP in the rotation process. The required operations are few, and explicit requests make token freshness, password write ordering, error classification, and secret redaction visible. Do not use cached SDK authentication as proof that a password currently works.

The one deliberate OpenStack CLI boundary is a command executed **inside the existing admin-client Pod** through Kubernetes exec. That tests the client's own delivered environment rather than merely repeating authentication from the Job. No local shell or `kubectl` subprocess is required. Other probes are configured read-only commands or HTTP checks, not service-specific phase code.

## 4. Configuration contract

Load exactly one environment YAML file and one credential-contract YAML file. Paths resolve relative to the environment file unless absolute. All mounted configuration and manifests are read-only. Reject duplicate keys, unknown fields, unresolved placeholders, unsupported schema versions, invalid quantities, or inconsistent references before contacting external APIs.

`environment.example.yaml` is the normative example. Its fields have these meanings:

| Section | Required content and validation |
|---|---|
| `schema_version` | Integer 1. |
| `environment_id` | Stable nonsecret identifier, matching the initialized state record. |
| `namespace` | Exactly `openstack` in v1. |
| `contract` | Path to the complete environment contract. No implicit baseline merge. |
| `keystone` | HTTPS v3 base URL, trusted CA path, region, fixed names, configured management scope and required roles. |
| `passwordsafe` | HTTPS base and Identity token URLs; Rackspace Identity domain; projected AD username/password files; separate positive integer project/credential IDs for A and B. |
| `state` | Precreated state Secret and Lease names; expected fingerprint-key Secret UID/key ID and SHA-256 content pin; projected 32-byte raw key file. |
| `execution` | Immutable release image digest and Downward API Pod/Job identity. Mutating outside a Kubernetes Pod is unsupported in v1. |
| `ownership` | Lease timings; mutation settlement policy and evidence reference. |
| `timeouts` | Bounded per-operation, polling, action, and probe deadlines. |
| `safety` | Reviewed discovery coverage and non-runtime exception evidence; a maintenance/change-exclusion reference. |
| `probes` | Explicit credential-effect and functional checks with action coverage. |

Canonical public-object JSON uses UTF-8, sorted mapping keys, no insignificant whitespace, `ensure_ascii=False` and `allow_nan=False`. The compiled configuration digest is SHA-256 over canonical JSON of the validated environment and **fully expanded** contract, plus the content digests of referenced manifests and probe programs. The evidence files referenced by configuration are included by digest where they are local files; an external evidence reference is recorded as the exact reviewed reference, not assumed to have been fetched. Exclude ephemeral execution identity, request ID, credentials, timestamps, and result paths. Include endpoints, scopes, record IDs, topology, actions, timeout/safety policies, and release image digest. Store `sha256:<64 lowercase hex>` in T. Resume requires an identical digest. Changing contract semantics mid-transaction is an operator recovery exercise, not `--force` behavior.

Credentials are never literal configuration. Read projected files exactly; do not strip password whitespace, expand shell expressions, or interpolate arbitrary environment variables. Resolve explicit secret-file references only at the client boundary. Keep the B credential in memory and recover it from PasswordSafe on resume; do not introduce a second breeder.

### 4.1 Credential-location schema

```yaml
schema_version: 1
namespace: openstack
representations:
  keystone-admin-env:
    type: fields
    username: OS_USERNAME
    password: OS_PASSWORD
locations:
  keystone-keystone-admin:
    secret: keystone-keystone-admin
    identity: active
    role: propagated
    representation: keystone-admin-env
    actions: [admin-client]
actions:
  admin-client:
    type: recreate_pod
    pod: openstack-admin-client
    container: openstack-admin-client
    manifest: /etc/rotation/manifests/utils-openstack-client-admin.yaml
    required_before_start: false
    required_after: true
```

Each location has exactly `secret`, `identity`, `role`, `representation`, and `actions`. IDs are unique map keys. `identity` is `active`, `admin`, or `breakglass`; `role` is `source` or `propagated`. Every representation exposes a password; active locations also expose a username. The only source supported in v1 is the fixed-admin breeder, with an empty action list. Fixed-breakglass propagated locations, if explicitly configured, remain B and do not participate in A rotation; they cannot be an undisclosed alternate runtime state.

A representation is either a named reference or one of these strict objects:

```yaml
# Direct Secret data values, after one Kubernetes base64 decoding.
type: fields
username: OS_USERNAME       # optional only for fixed identities
password: OS_PASSWORD
```

```yaml
# One INI document stored in a Secret data value.
type: ini
key: octavia.conf
section: service_auth
username: username         # optional only for fixed identities
password: password
```

```yaml
# One YAML document; optionally one embedded YAML string document.
type: yaml
key: generated-clouds-yaml
document_path: [clouds.yaml]  # optional, one embedded document boundary
username_path: [clouds, default, auth, username]
password_path: [clouds, default, auth, password]
```

Paths are nonempty lists of literal string map keys in v1, not JSONPath or expressions. Omit `username_path` only for a fixed identity. `document_path` must resolve to a string; parse that string before resolving credential paths.

Require all configured Secrets and paths to exist. There is no `required: false`, wildcard Secret mutation, optional location, or auto-discovered mutation target. Environment differences are expressed by different complete contracts. Absence of an unconfigured location is acceptable; presence of an unmanaged administrative credential is not.

Reject overlapping writable leaves across locations. Multiple nonoverlapping locations in one Secret are allowed and are changed together in one object mutation. `actions: []` means no immediate runtime action; it does not prove absence of consumers or satisfy the fixed-A safety exception by itself.

### 4.2 Structural parsing and mutation

Decode Kubernetes `data` strictly; credentials must be nonempty UTF-8 strings. Credential equality is exact. Do not trim, normalize, decode a second time, infer usernames from a Secret name, or replace arbitrary matching substrings.

For INI, implement an adapter using a parser configured without interpolation and with case preserved. Treat `DEFAULT` explicitly. A declared non-default section must contain its credential options explicitly, not inherit them from defaults. Reject duplicate sections or duplicate credential options and unsupported syntax rather than guessing. Preserve the complete noncredential semantic document. A parser round-trip that changes unrelated semantics is a hard error. Representative deployed configuration fixtures are required tests before release.

For YAML, reject duplicate mapping keys, unsafe tags, and aliases/merge constructs whose mutation would also alter undeclared leaves. Resolve the exact paths, replace only the declared scalar credentials, serialize inner then outer documents, reparse, and assert semantic equality after masking the declared writable leaves. Preserve unrelated Secret fields byte-for-byte. Comments and serialization formatting are not credential authority, but round-trip preservation should minimize changes.

A no-op is determined by credential components, not serializer output. Do not rewrite an unchanged document merely to normalize formatting.

### 4.3 Runtime action schema

Action IDs reference one of two tagged objects:

```yaml
type: rollout_restart
kind: Deployment             # Deployment or DaemonSet only in v1
name: octavia-api
timeout_seconds: 600         # optional; environment default otherwise
```

```yaml
type: recreate_pod
pod: openstack-admin-client
container: openstack-admin-client
manifest: /etc/rotation/manifests/utils-openstack-client-admin.yaml
required_before_start: false
required_after: true
timeout_seconds: 300         # optional
```

Namespace is inherited as `openstack`. Normalize the deduplication key to `(type, namespace, kind, name)`. Reject duplicate targets with different definitions, including conflicting manifest paths or container names. Adding a future action class requires one schema variant and one handler implementing `observe/execute/verify`; it must not require editing service-specific phase branches.

For each wave, derive action instances **only from observed actual credential mutations**, including mutations recovered from durable receipts. The same target runs at most once for a satisfied wave token. Distinct B and A waves intentionally have distinct tokens.

## 5. Baseline managed topology

The baseline contract contains 23 credential locations: 21 active, one fixed-admin source, and one fixed-admin propagated location. Its 15 standard-template Secrets were established in DFW-DEV, not asserted to be the exact inventory of every production environment. The supplied contract must be reviewed for the target environment. [S2, S10]

All entries below are in namespace `openstack` and kind Secret. `F` means the named `keystone-admin-env` fields representation. Every non-source row is `role: propagated`.

| Location ID / Secret | Identity / representation | Runtime action |
|---|---|---|
| `keystone-admin` | admin/source; `fields.password=password` | None. |
| `barbican-keystone-admin` | active / F | None. |
| `cinder-keystone-admin` | active / F | None. |
| `glance-keystone-admin` | active / F | None. |
| `gnocchi-keystone-admin` | active / F | None. |
| `heat-keystone-admin` | active / F | None. |
| `magnum-keystone-admin` | active / F | None. |
| `placement-keystone-admin` | active / F | None. |
| `skyline-keystone-admin` | active / F | None. |
| `zaqar-keystone-admin` | active / F | None. |
| `nova-keystone-admin` | active / F | None. |
| `octavia-keystone-admin` | active / F | None; worker/health-manager get-port init dependency. |
| `blazar-keystone-admin` | active / F | None. |
| `keystone-keystone-admin` | active / F | Recreate required Pod `openstack-admin-client`. |
| `neutron-keystone-admin` | active / F | Restart DaemonSet `neutron-netns-cleanup-cron-default`. |
| `ceilometer-keystone-admin` | active / F | None. |
| `ceilometer-keystone-admin-password` | admin; `fields.password=password` | None; fixed-A usage must pass the safety gate below. |
| `octavia-service-auth-etc` / `octavia-etc` | active; `octavia.conf`, `[service_auth]`, `username/password` | Restart Deployments `octavia-api`, `octavia-housekeeping`. |
| `octavia-service-auth-worker` / `octavia-worker-default` | active; same INI selectors | Restart DaemonSet `octavia-worker-default`. |
| `octavia-service-auth-health-manager` / `octavia-health-manager-default` | active; same INI selectors | Restart DaemonSet `octavia-health-manager-default`. |
| `blazar-admin-config` / `blazar-etc` | active; `blazar.conf`, `[DEFAULT]`, `os_admin_username/os_admin_password` | Restart Deployments `blazar-api`, `blazar-manager`. |
| `openstack-config-admin` / `openstack-config` | active; `clouds.yaml`, `clouds.default.auth.username/password` | Restart Deployment `os-metrics-prometheus-openstack-exporter`. |
| `generated-clouds-yaml-admin` / `clouds-yaml-secret` | active; `generated-clouds-yaml`, embedded `[clouds.yaml]`, then the same auth paths | None. |

For a healthy complete baseline wave, the deduplicated runtime set is eight rollout restarts and one Pod recreation. The initial B wave changes 21 active locations. The return wave changes those 21 plus the fixed-admin propagated copy; breeder staging is a separate preceding mutation. These counts are consequences of this baseline, not hard-coded workflow constants.

Preserve the startup/runtime distinction: `octavia-keystone-admin` itself has no restart edge. Runtime `[service_auth]` mutations cause worker and health-manager restarts, whose newly created init containers also consume the already updated standard Secret. All Secret changes in a wave complete before its first runtime action. Generated clouds YAML is still propagated state; its name does not make it a credential authority. [S1, S2]

### 5.1 Required fixed-A and external-consumer safety gate

Before production enablement, discovery must establish the usage of `ceilometer-keystone-admin-password` and direct breeder consumers. The existing empty restart lists do not establish that those values are safe to invalidate or stage ahead of Keystone.

Configuration must identify these locations in `safety.fixed_admin_nonruntime_locations`, with a discovery evidence reference, and assert that their consumers cannot execute during A1/A2 or before return propagation. Preflight additionally scans live Pod specifications and controller templates for direct Secret references and checks the configured evidence against the observed topology. An unexplained active reference blocks rotation. Do not automatically pause CronJobs or scale consumers as an invented workaround; update the reviewed contract/design when such a dependency is found.

The broader environment must exclude concurrent Helm/deployment writers, credential sync controllers, manual password changes, and out-of-namespace administrative consumers not covered by the reviewed inventory. Namespace-scoped scanning cannot prove the absence of host files, external systems, or opaque encoded credentials. These limits must be explicit in the production readiness evidence, not silently treated as successful discovery.

## 6. Persistent state and credential fingerprints

### 6.1 Storage

Precreate these objects in `openstack` during installation, not during rotation:

```text
Secret/keystone-admin-rotation-state       data["state.json"]
Secret/keystone-admin-rotation-fingerprint-key
Lease/keystone-admin-rotation
```

The state Secret is `type: Opaque`, has no Job owner reference, and contains UTF-8 JSON conforming to the supplied Draft 2020-12 `transaction.schema.json`. Using Secret rather than ConfigMap limits casual access to sensitive topology and fingerprints; it does not imply the JSON contains passwords or that Kubernetes storage is inherently encrypted.

The state envelope has exactly:

```text
schema_version: 1
environment_id: string
cluster:
  kube_system_namespace_uid: string
  openstack_namespace_uid: string
lease_uid: string
revision: nonnegative integer
current: Transaction | null
completed: list[Receipt]   # maximum 12
```

The installer initializes this envelope with `current: null`, `completed: []`, `revision: 0` and the observed cluster/Lease UIDs. The runtime never initializes a missing record. Record namespace UIDs to reject accidental execution against another cluster or a recreated namespace. The configured Lease must retain its UID. Missing or recreated state, Lease, or key objects during an unfinished transaction are not repaired automatically.

All state changes use GET followed by resourceVersion-conditional PATCH and read-back. `revision` increments on every application state write; it is not substituted for Kubernetes resourceVersion. The renewal thread writes only the Lease; only the main runner writes transaction state.

Keep decoded `state.json` below 512 KiB, including history. Check projected record size before accepting another operation. Never truncate an unfinished journal to make a write fit. Compact completed verification observations by check/wave, retaining the latest evidence; retain every consequential operation and execution needed to explain active provenance.

### 6.2 Exact transaction representation

The JSON Schema is normative for required fields, types, enum values, nullability, limits, tagged operation payloads, and rejection of additional properties. All fields defined on an object are required unless its schema explicitly says otherwise; optional observations use null rather than omitted keys.

| Transaction field | Meaning |
|---|---|
| `transaction_id`, `request_id` | Independently generated UUIDs; request ID provides bounded duplicate-delivery protection. |
| `status` | `active`, `blocked`, or `completed`; blocked remains unfinished. |
| `phase` | One of the seven named state-machine phases. |
| `created_at`, `updated_at` | UTC RFC 3339 timestamps. |
| `config_sha256`, `program_image_digest` | Frozen compiled configuration and executing release. |
| `fingerprint_key_id`, `fingerprint_key_secret_uid` | Identity of the retained fingerprint key. |
| `identities` | Resolved A/B user and domain IDs, project/domain ID, required role IDs. |
| `generations` | Old-A and B fingerprints; nullable new-A fingerprint; stage-attempt counter; observed staging flag. |
| `executions` | Ownership epochs and their Pod/Job identity, release and settlement evidence; maximum 128. |
| `owner_execution_id`, `owner_epoch` | Current owner, matching the acquired Lease. |
| `objects` | Managed credential Secret/action-target UID, last observed resourceVersion, and protected semantic digest. The state Secret, key and Lease are excluded from this map to avoid recursive self-digests. |
| `locations` | Per-location initial/observed generation, fingerprint, operation attribution, observation time. |
| `actions` | Per-wave action receipts and causes; map key is `<wave>.<action-id>`. |
| `operations` | Ordered write-ahead journal, maximum 512 entries, with tagged payloads and observations. |
| `lockout` | Initial normal state, suppression/restoration intent, observations, and outstanding restoration obligation. |
| `passwordsafe_admin`, `passwordsafe_breakglass` | Record IDs, last observed version/fingerprint/time; no password. |
| `verifications` | Safe check results bound to execution, wave, target UIDs and timestamp. |
| `completion` | Separate password, authority, runtime, lockout, final-audit, and cleanup results. |
| `last_error` | Bounded allowlisted diagnostic, retryability, and operator requirement. |

Operation payload variants are `patch_secret`, `patch_keystone_password`, `patch_lockout`, `patch_passwordsafe`, `rollout_restart`, `delete_pod`, `create_pod`, and `cleanup_annotations`. Every journal entry has a UUID, strictly increasing sequence, phase, execution/epoch, intent time, payload, observation (`pending`, `applied`, `not_applied`, or `conflict`), and nullable observed identifiers/request ID/error.

`pending` means the request may be unsent, in flight, failed with an unknown outcome, or completed without recorded observation. It NEVER means that a write is known not to have happened. There may be at most one unresolved consequential operation. Observed `not_applied` closes an attempt; a retry creates a new journal entry under the current execution, retaining the same staged generation or action token. An applied operation is not resent merely because execution changed.

Additional semantic validators MUST enforce constraints not expressible conveniently in JSON Schema: map keys match configured IDs; object kinds match payload kinds; source changes are breeder-only; only one pending operation exists; owners and operation epochs reference retained executions; recorded fingerprints use the retained key; action causes refer to actual applied credential changes in the same wave; timestamps do not confer authority; and completed state satisfies all completion flags. In particular, `status=completed` requires `phase=STABLE_A`, nonnull new generation/completion time, no pending operation, `lockout.state=restored`, `restore_required=false`, cleanup done and no outstanding error. Never persist active STABLE_A as a shortcut around those gates.

### 6.3 Fingerprint definition

Install a cryptographically random, 32-byte HMAC key separately from administrative credentials. It is an identification key, not a second password store. Pin its ID, Secret UID and `state.fingerprint_key_sha256`; check the raw key bytes against that SHA-256 content pin before use. Changing bytes under the same identity is a hard error. Retain the key while an active or retained completed record depends on it.

For a credential, construct canonical JSON with no whitespace:

```python
[
  "genestack-admin-rotation/credential/v1",
  environment_id,
  kube_system_namespace_uid,
  openstack_namespace_uid,
  domain_id,
  user_id,
  username,
  password,
]
```

Encode with `json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")`. Calculate HMAC-SHA-256 using the retained key. Encode all 32 digest bytes as unpadded URL-safe Base64:

```text
hmac-sha256:v1:<key-id>:<43-character-base64url-digest>
```

Never persist the canonical input. Compare fingerprints and credential bytes with `hmac.compare_digest` where applicable. No truncated fingerprints are used for recovery. Result logs use generation names, not password digests.

Use the same keyed construction with distinct domain separators for protected object/user/annotation semantic digests. Canonicalize map keys in sorted order before hashing. Such objects can contain unrelated credentials; an unkeyed digest is not automatically safe merely because the rotated password was masked. Public configuration/manifest digests use unkeyed SHA-256.

### 6.4 Local mutation provenance

Use annotation prefix `rotation.genestack.org/`. Breeder staging changes the password and all the following annotations in **one conditional Secret PATCH**:

```yaml
rotation.genestack.org/transaction-id: "<T>"
rotation.genestack.org/operation-id: "<operation UUID>"
rotation.genestack.org/execution-id: "<E>"
rotation.genestack.org/epoch: "<decimal epoch>"
rotation.genestack.org/stage: pending-keystone
rotation.genestack.org/new-admin-fingerprint: "<full HMAC fingerprint>"
```

Global intent already contains the new fingerprint before this PATCH. The read-back must match T, operation, E/epoch, fingerprint, and actual password. An earlier epoch's marker is valid provenance when its recorded operation belongs to T; it need not be rewritten just because ownership changed.

The `stage` marker MAY lag live state. Keep the original staging marker through the transaction rather than performing extra cosmetic stage updates. Successful new-A authentication and PasswordSafe equality establish A2/A3, even while the annotation still says `pending-keystone`. The field describes the staging operation, not a current-state assertion.

Each propagated Secret mutation also atomically writes one compact JSON annotation, `rotation.genestack.org/mutation`, containing exactly:

```json
{
  "version": 1,
  "transaction_id": "<T>",
  "operation_id": "<operation UUID>",
  "execution_id": "<E>",
  "epoch": 1,
  "wave": "to_b",
  "locations": {"<location-id>": "<target credential fingerprint>"}
}
```

The annotation and credential changes are atomic at the Secret boundary. This closes the crash gap between changing a location and recording its required runtime actions. A new owner can prove that the mutation occurred and recover its action obligations. No-op reads add no receipt and cause no action. Remove transaction-owned Secret annotations during final cleanup; never remove another transaction's metadata.

### 6.5 Retention and completion cleanup

Keep the full current transaction, including a completed one, until a subsequent request begins. On the next valid new request, atomically move a compact completed receipt into `completed` and install the new current transaction. Retain at most 12 receipts and no receipts older than 90 days, subject to not deleting evidence referenced by remaining local provenance. There is no age-based expiration of unfinished state.

Cleanup runs only after final A verification and verified lockout restoration. Persist `completion.cleanup_state=intent`, remove this transaction's Secret annotations with conditional writes and read-back, then repeat the final stable audit. Mark cleanup done and transaction completed together in the state record. A crash during cleanup resumes cleanup; missing annotations are allowed only when attributable to recorded cleanup intent/operations and freshly converged state.

Cleanup failure does not mean that the password is invalid. It does mean that this transaction is not yet declared complete. Report the distinction and resume without another rotation. Successful rollout/pod reconciliation-token annotations may remain as generation receipts; they are not active credential staging markers and contain no password.

## 7. Ownership, takeover, and optimistic concurrency

### 7.1 Lease protocol

Use `coordination.k8s.io/v1 Lease/openstack/keystone-admin-rotation`, precreated with an empty holder. Default timings:

```text
leaseDurationSeconds = 120
renew every           = 20 seconds
renewal stop deadline = 60 seconds since last successful renewal
acquisition polling   = 5 seconds
expiry observation    = 120 seconds unchanged + 15 seconds safety margin
```

Assign E a fresh UUID at every invocation; T is not a Lease holder. Store `holderIdentity=E` and annotations for monotonically increasing `rotation.genestack.org/epoch`, Pod name/UID, Job UID, and current transaction ID when known. Acquisition is a resourceVersion-conditional update; increment the epoch in that same update. Set `spec.acquireTime`, `spec.renewTime` and `spec.leaseDurationSeconds`; renew by conditionally advancing `renewTime` while preserving holder and epoch. `spec.leaseTransitions`, if populated, is diagnostic only; the recorded epoch is the application ownership generation. Never interpret resourceVersion as an integer or use it as a timestamp.

Before starting a new T, the owner must also check the retained predecessor execution for unresolved dispatch or missing quiescence, even when that predecessor never reached transaction creation. Lease acquisition metadata supplies its Pod identity.

A contender measures unchanged holder/renewal state with its own monotonic clock for the full expiry observation interval. A first observation of an old-looking wall-clock timestamp does not immediately authorize takeover. UTC Lease timestamps remain useful diagnostics. Any observed renewal restarts the observation interval. An unexpired foreign holder yields `OWNERSHIP_BUSY` without transaction or credential mutation. Without `--wait-for-lease`, an occupied Lease returns busy rather than performing the full expiry observation; use `resume --wait-for-lease` for an interrupted owner.

After acquiring, GET the Lease again, validate its UID/holder/epoch, reread state, and register E through a conditional state update. A crash between Lease acquisition and state registration is recoverable ownership setup, not permission for credential mutation. Compare the predecessor recorded in the Lease with the prior execution list; unexplained identity/epoch conflicts block execution.

### 7.2 Mutation guard and loss of ownership

Immediately before each journal/state write and each consequential external request, require:

```text
sticky_stop_flag is false
Lease UID matches initialized lease_uid
Lease holder and epoch match E
state owner matches E and epoch (except registration or atomic creation of a new T)
last successful renewal is less than 40 seconds old
transaction ID/configuration/generation still match the intended operation
specific target preconditions have just been revalidated
```

A guard failure stops effects. Once ownership is lost or renewal exceeds 60 seconds, E permanently loses mutation capability; it must not reacquire and continue within the same process. Cancel waits and exit. A watchdog must also terminate a locally stuck mutator; it must not keep renewing indefinitely while the mutator cannot honor stop/deadline checks.

The guard is checked before both intent recording and dispatch. After an uncertain call, do not start another write until its outcome has been reconciled. A stale execution may emit a safe local failure report, but may not update transaction state or restore lockout after losing ownership.

### 7.3 Actual fencing boundary

Lease ownership plus client-side epoch checks is **cooperative fencing**, not a server-enforced transaction token for Keystone or PasswordSafe. A paused former owner can pass a check and be delayed before sending; an already sent request can outlive a client timeout. Kubernetes leader-election documentation explicitly warns that leader election alone does not guarantee fencing. [E2]

Accordingly, expiry permits a new owner to acquire and **observe**, but consequential takeover mutations require both:

1. **Former executor quiescence:** recorded clean release with no live mutator, or the previous Job Pod's containers observed terminated under `restartPolicy: Never`, or explicit operator evidence that the process/node has been fenced. A missing/force-deleted Pod or an expired Lease alone is not proof. The Kubernetes force-delete contract explicitly does not wait for process termination. [E7]
2. **Outstanding request settlement:** no potentially delayed consequential request from that executor remains capable of taking effect.

A clean release establishes both only when all dispatched requests are conclusively completed and the executor has permanently disabled further writes before release. For a crash, a `pending` operation is settled only by conclusive commit evidence, a qualified completion bound, or operator evidence. A matching value alone is not universally conclusive.

Conclusive commit evidence may settle a single dispatched operation without waiting for a bound: an exact atomic Kubernetes operation receipt/token under its recorded UID/resourceVersion; a uniquely staged new password now freshly authenticating after the recorded old-to-new change; or PS now containing that unique new generation after its recorded old-to-new PATCH. This is permitted only with one pending request, automatic write retries disabled, verified exclusion of other writers, and qualified API semantics in which that request cannot perform another later credential write after the observed commit. An already expired UID/resourceVersion precondition can also fence a delayed Kubernetes request once that precondition cannot become valid again. Do not extend this inference to a same-value capability PATCH: observing the same old value does not prove it was dispatched or completed. A PS version change attributable exclusively to that capability operation can be evidence; otherwise settlement remains unresolved.

For operations without conclusive commit/precondition-fencing evidence, configure either a **verified deployment bound** for server-side mutation completion, or operator-assisted settlement. With a verified bound, wait that entire bound after confirmed former-process termination, then observe again before writing. The bound must include ingress queues, request execution and backend commit; it is not derived from the client's 30-second timeout. The example leaves this bound unset. Without such conclusive evidence or a qualified bound, an interrupted potentially in-flight write requires an operator settlement attestation before automatic mutation resumes.

An attestation is a read-only mounted YAML file supplied using `resume --settlement-evidence PATH`, with exact fields `schema_version: 1`, `transaction_id`, `predecessor_execution_id`, `predecessor_epoch`, `predecessor_pod_uid`, `process_fenced: true`, `outstanding_requests_settled: true`, `operation_ids` (the unresolved operation UUIDs), `approved_by`, `approved_at`, and `evidence_reference`. Validate every identity against recorded predecessor state. Store its reference and SHA-256 digest, not arbitrary text, in the execution receipt. This is an explicit operational assertion, not a claim that the program can independently verify physical fencing. No generic force-takeover switch exists.

Apply this settlement rule to delayed Kubernetes mutations as well: resourceVersion tests help but do not, by themselves, prove that a paused old client cannot still submit an otherwise applicable write. The conservative gate avoids introducing a fencing service or distributed coordinator.

### 7.4 Per-object concurrency

For Secrets, Lease, state, and workload templates, use JSON Patch with tests on `/metadata/uid` and `/metadata/resourceVersion`, plus narrow modifications. Escape JSON Pointer keys correctly. Do not force server-side apply, overwrite a whole stale object, or update Kubernetes-managed fields. A delete uses UID and resourceVersion preconditions. Kubernetes conditional updates reject stale object state rather than silently accepting lost updates. [E3]

Protect all noncredential Secret content and relevant workload specification with a keyed semantic digest. Exclude server-managed metadata and this tool's own annotations. On conflict, reread. If only irrelevant metadata/status changed, explicitly revalidate the original semantic decision, record the newly observed resourceVersion, and retry at most three times. Any credential, protected specification, UID, unknown annotation, or concurrent ownership change is a conflict requiring a stop. A newer object cannot be blindly adopted because its credential happens to look familiar.

For reproducible protected digests, include resource kind/name/namespace/UID, Secret type/immutable flag, labels, non-tool annotations, ownerReferences, and all relevant data/specification. Exclude resourceVersion, generation, timestamps, managedFields and status; mask this tool's annotation prefix. For managed Secret fields, use each representation's parsed semantic tree and replace only declared credential leaves with typed markers containing location ID and component name. Decode a declared embedded YAML document to a separately tagged inner semantic tree. Preserve unrelated binary data as Base64 strings. For controller specifications, mask only this tool's template annotations. For users, protect identity/name/domain/enabled/default-project and unrelated options; exclude the managed lockout option and server-generated password-expiry timestamps. Serialize these projected trees canonically and HMAC with the appropriate domain separator. The same projection must be used before mutation, on read-back and on resume.

PasswordSafe has no established compare-and-swap facility in the corpus. Do not invent an `If-Match` or version precondition. Its version is observed evidence, not a lock. Require the operational exclusion of other writers, perform just-in-time GET/compare/PATCH/GET, and fail on unexpected version/value changes. Keystone password and option writes similarly rely on exclusive cooperating ownership plus the environmental writer-exclusion requirement, not a fabricated cross-system atomic transaction. [S8]

## 8. External API semantics

### 8.1 Keystone

For a new transaction's initial identity resolution, authenticate with the configured user name and domain name and project name/domain; validate returned names and obtain the IDs from the fresh token. Authenticate B the same way and require matching expected domain/project IDs. Then verify the user resources using B's configured management scope and freeze those IDs. On resume, use only the recorded IDs; do not resolve a newly created same-name user as a replacement. This avoids requiring an unauthenticated directory lookup before the first token.

Obtain a **fresh password-authenticated token** using `POST <v3-base>/auth/tokens` with `methods: [password]`, recorded user ID/password, and the expected project scope. Validate the returned token user ID, domain ID, project ID, role IDs, and future expiration. Treat the response's subject token as secret. A cached or previously issued token is not password verification. [E1]

The normal ID-based password request body is:

```json
{"auth":{"identity":{"methods":["password"],"password":{"user":{"id":"<user-id>","password":"<in-memory-password>"}}},"scope":{"project":{"id":"<project-id>"}}}}
```

For management system scope, replace only scope with `{"system":{"all":true}}`. Require management tokens to have at least 60 seconds of remaining validity before a write, refreshing as needed. Never serialize a token into transaction state.

Obtain management authorization separately using B and the configured project or system scope. B must have the required project permissions for consumers and the management permissions needed to read/update A. Do not assume that a role named admin implies every policy permission.

Read users through `GET <v3-base>/users/{user_id}`. Admin password mutation is:

```http
PATCH <v3-base>/users/{admin_user_id}
X-Auth-Token: <B management token>
Content-Type: application/json

{"user":{"password":"<staged new admin password>"}}
```

Use the administrative user-update API, not the self-service original-password API. The backend must support the operation. Afterward, authenticate with the new password; a successful PATCH is insufficient. [E1]

Lockout-option writes use the same user endpoint with only:

```json
{"user":{"options":{"ignore_lockout_failure_attempts":true}}}
```

or false for normal behavior. A missing boolean option has false semantics in documented Keystone behavior; malformed values are errors. Read back the option and ensure other user options and invariant user fields were preserved. Do not change `enabled`, clear lock counters, change global Keystone configuration, or alter B's lockout policy. Validate the deployed backend's partial-option update behavior during qualification. [E4]

### 8.2 PasswordSafe

The configured AD service account authenticates to Rackspace Identity Internal v2:

```http
POST https://identity-internal.api.rackspacecloud.com/v2.0/tokens
Content-Type: application/json

{
  "auth": {
    "passwordCredentials": {
      "username": "<projected service-account username>",
      "password": "<projected service-account password>"
    },
    "RAX-AUTH:domain": {"name": "Rackspace"}
  }
}
```

Validate and retain `access.token.id` and its expiry in memory. Send that token as `X-Auth-Token` to the configured PasswordSafe HTTPS base. Never send AD credentials directly to PasswordSafe. Refresh the Identity token before expiry and once after an authenticated request receives 401; a 403 is not an expiry-retry instruction. [S8]

Read current credentials only with:

```http
GET /projects/{project_id}/credentials/{credential_id}
Accept: application/json
X-Auth-Token: <Identity token>
```

Validate credential ID, project ID, exact expected username, nonempty password, and integer version. Do not discover records by description or reuse example experiment IDs.

Write only:

```http
PATCH /projects/{project_id}/credentials/{credential_id}
Accept: application/json
Content-Type: application/json
X-Auth-Token: <Identity token>

{"credential":{"password":"<intended password>"}}
```

A demonstrated 204 is an acknowledgement, not completion. Immediately perform JSON GET and compare the returned password with the intended credential. Validate record identity and that the observed version did not regress; do not require an exact `+1` increment as a concurrency mechanism. A new-A value is written only after new-A Keystone authentication has succeeded. Never request HTML or historical credential versions in these commands. [S8, S9]

### 8.3 Proving write access before danger

A read cannot prove update authorization. In PREPARE_B, under ownership and a journaled `patch_passwordsafe` capability operation, PATCH the **currently verified old-A password back to the same admin record**, then GET and confirm it remains unchanged. This tests the actual record and operation without introducing another password generation. It may advance audit/version metadata; record the observed result.

The deployed PasswordSafe service must be qualified to accept this same-value operation. If it rejects it, stop before propagation/rotation; do not quietly downgrade to read-only evidence. This is a selected implementation prerequisite, not behavior already proven by the password-change experiment.

Similarly, B performs a journaled `patch_lockout` capability operation setting admin's option to false while it is already semantically normal, followed by GET. That proves actual user-option write access without entering a suppressed state. The same-value false write may materialize a previously absent option; this is an intentional semantic no-op.

Capability proofs expire after five minutes before initial breeder staging. Recheck dependencies and repeat the safe proofs in A0 as needed. Once staging occurred, do not run old-A same-value PasswordSafe capability writes; resume the defined A1/A2/A3 recovery path instead. Preflight cannot guarantee that authorization or connectivity will remain available later, which is why B and persistent recovery remain necessary.

## 9. Planning, discovery, and classification

### 9.1 `plan`

Planning makes no persistent writes to Kubernetes, Keystone user state, PasswordSafe, or workloads. It may issue authentication tokens and read-only probes; token issuance is not claimed to be side-effect-free audit activity. It does not perform capability PATCHes, acquire the Lease, generate a replacement password, or establish a transaction.

The plan algorithm is:

1. Validate configuration, contract, manifests, probe definitions and initialized state/key identities locally.
2. Read state and Lease. Report T, phase, holder/epoch and ownership availability. An active owner makes the plan observational rather than independently executable. While another execution may still change an unfinished T, read-only commands do not perform old/new candidate A authentication rounds; they report incomplete transitional verification. Candidate probing belongs to the owning reconciler.
3. Read PasswordSafe A/B and breeder; resolve identities; read admin's lockout option using verified management access. Reconcile either stable A or a recognized active transaction. Do not test arbitrary password candidates.
4. Authenticate expected authoritative credentials once; validate B authorization. For an active owner with transitional observations, do not race it with speculative old/new authentication attempts. Report an unstable snapshot and require revalidation under ownership.
5. Perform namespace discovery, structural resolution, permitted-generation classification and topology comparison.
6. Validate action targets, update strategies, runtime baselines, manifest content, required probe coverage and fixed-A safety evidence. Missing admin-client may be reported as repairable by its forthcoming triggered recreation; missing rollout targets are errors.
7. Produce both wave plans, fixed-admin propagation, action unions, required capability tests, safety blockers, and possible resume work. Do not include passwords, tokens, raw Secret contents, or HMAC inputs.

A valid plan is advisory. `rotate` and `resume` acquire ownership and repeat relevant checks before mutating. A saved plan is not executable authority.

### 9.2 Independent discovery

Discovery must not merely iterate configured locations. List all Secrets in `openstack` with pagination and scan each for supported administrative credential representations. Use the following deterministic recognizers:

- Direct `OS_USERNAME`/`OS_PASSWORD`, plus configured fields-representation pairs; named standard admin Secrets with missing fields are errors.
- INI credential option pairs `username/password` and `os_admin_username/os_admin_password` in each explicit section, including DEFAULT, and any additional declared pair. A recognized administrative username is a candidate even when its password is unknown.
- YAML mappings containing these credential pairs, including nested mappings and one string-valued YAML-document boundary. Declared YAML documents are always parsed independently of naming heuristics.
- Password-only scalar leaves that exactly fingerprint as a known A/B generation, and declared fixed-identity fields. These are discovery evidence, not authorization for arbitrary replacement.

Use bounded document size, node count and nesting depth (maximum 1 MiB decoded field, 100,000 parsed nodes, depth 32). Reject exceeded limits for potentially administrative/configured documents. Process unconfigured Secrets page-by-page rather than retaining the namespace's full plaintext contents.

Normalize a discovered location to Secret identity plus representation type and exact writable leaf addresses. Compare this set with the fully expanded configured set. Missing paths, extra administrative representations, unknown passwords under a known administrative username, and ambiguous candidate credentials block rotation.

A recognizer must distinguish clearly non-Keystone contexts where evidence exists. Where it cannot, report an ambiguous candidate rather than silently excluding it. The optional `safety.non_keystone_classifications` list may supply exact Secret/representation selectors, invariant contextual assertions, and a discovery reference establishing a different identity system. It cannot exclude a scalar matching a known administrative generation, use wildcards, or suppress a known Keystone credential. Such classifications are reviewed configuration, not an ignore-errors switch.

Non-UTF-8/binary/opaque fields that do not fit these representations are outside automatic interpretation. Record coverage limits; an identified administrative signal in unsupported content is a blocker. Deployment qualification must establish that the supported recognizers cover the active topology. Archives or historical deployment records are not silently promoted into active propagation locations, nor silently assumed harmless without their storage role being understood.

State/key objects may be recognized as this program's exact initialized schemas rather than credential locations; this is not permission to exempt arbitrary Secrets sharing a label. Repeat discovery immediately before breeder staging and during final audit. If the paginated listing expires or cannot produce a consistent snapshot, restart discovery; do not combine partial lists.

### 9.3 Classification rules

At stable entry, source and propagated A locations must match verified A; configured fixed-B locations must match verified B. An active B location without an unfinished transaction is drift, not a reason to adopt B as stable state.

During a recognized T, classify exact declared components against the recorded A-old, A-new when staged, and B fingerprints. An old generation may remain recognizable by fingerprint after its plaintext has disappeared from current PasswordSafe. That does not make the downstream copy authoritative.

The phase permits these active-location transitions:

| Phase | Permitted observed active values | Desired value |
|---|---|---|
| PREPARE_B | A-old only | A-old |
| SWITCH_TO_B | A-old; B only with matching applied/pending mutation evidence | B |
| VERIFY_B / ROTATE_A | B only | B |
| SWITCH_TO_A | B; A-new only with matching mutation evidence | A-new |
| VERIFY_A / STABLE_A | A-new only | A-new |

Fixed-admin propagated locations stay A-old until SWITCH_TO_A, where A-old or attributable A-new is allowed. Source A state is governed separately by A0-A3. A regression from a previously verified newer value to an older value is drift, not an automatically repeatable transition. Any structurally invalid representation is a reconciliation error, never `unknown` with overwrite permission.

## 10. State machine and phase gates

The persisted phase set remains:

```text
STABLE_A
  -> PREPARE_B
  -> SWITCH_TO_B
  -> VERIFY_B
  -> ROTATE_A
  -> SWITCH_TO_A
  -> VERIFY_A
  -> STABLE_A
```

STABLE_A is either an observed pre-transaction environment or a completed transaction. Lockout handling is a mandatory substate of ROTATE_A/VERIFY_A, not a second competing high-level machine.

| Phase | Entry conditions | Work and exit conditions |
|---|---|---|
| PREPARE_B | Exclusive settled ownership; no other unfinished T; stable authoritative A; normal admin lockout; complete known topology and valid baseline. | Persist T with old/B fingerprints and object baselines. Verify existing B, grants and management capabilities; perform real safe capability PATCHes and read-backs; verify production safety inputs. Exit only with B ready and A still unmodified. |
| SWITCH_TO_B | Fresh verified B and known A-old; approved complete plan. | Journal and apply active credential changes, read each back; complete all credential mutations before executing deduplicated B actions. Exit with all active locations B and all triggered actions reconciled. |
| VERIFY_B | B propagation and action ledger complete. | Fresh B auth; all active locations B; credential-effect probes show B delivery; required workloads/functional probes pass; fixed A usage safe; A-old triplet still valid. Exit with fresh B safety certificate. |
| ROTATE_A | VERIFY_B current; topology unchanged; usable PS; ownership current; A0 or recognized resumed A1/A2/A3. | Establish/recover lockout suppression, execute exact breeder -> Keystone -> PS algorithm. Exit only in observed A3 with suppression still deliberately enabled. |
| SWITCH_TO_A | Observed A3; B remains usable while consumers still use it. | Change active B and fixed-admin A-old locations to A-new; complete Secret barrier; execute deduplicated A actions. Exit with all desired locations A-new and actions reconciled. |
| VERIFY_A | A3, A propagation and required actions complete. | Fresh authority/runtime/client/function checks; restore lockout and verify it; final stable audit; cleanup and completion receipt. Exit only with every success condition observed. |
| STABLE_A | Verified completion and cleanup. | No further password generation or propagation for this request. Release quiescent ownership and exit success. |

Any gate failure records a bounded error and `status=blocked` if ownership is still held, without erasing the phase, journal or generation. A blocked phase is unfinished and must be resumed. Phase advancement is a conditional state write after observed exit conditions; it never precedes them except for entering a phase whose next operation is explicitly journaled.

A verification certificate is the set of current-execution check results, target UIDs/generations, expected fingerprints and timestamps. It expires for a critical boundary after 60 seconds or immediately after a relevant change. Refresh it, not the password. Certificates from an earlier execution must be re-observed.

### 10.1 PREPARE_B details

Read B from its configured PasswordSafe record; require username `breakglass`, correct IDs, and unchanged fingerprint throughout the transaction. Verify project-scoped B auth, required roles and actual management permissions. Do not create B, fix its password, grant roles, or update its PasswordSafe record. B failure blocks before active consumers change.

Use the fresh verified A triplet to establish `admin_old`; record A/B identities and object UIDs. Baseline workloads must be healthy enough for later failures to be attributable to rotation. Deployment/DaemonSet targets must exist, not be paused or on an unsupported update strategy, and have a nonzero required desired population. Missing admin-client is permissible only when configured `required_before_start=false`; it will become mandatory during the first triggered action and at completion.

Perform the same-value PS and normal-lockout capability checks. A failure leaves an unfinished PREPARE_B transaction with no A credential mutation. Resume must rerun observations and uncompleted capability checks, not create another T.

### 10.2 SWITCH_TO_B / SWITCH_TO_A common algorithm

For each Secret, in deterministic Secret-name order:

```text
GET object and all represented locations
validate UID, protected content, provenance and allowed observed generations
if every declared component already equals the permitted target:
    require attribution if transition has already occurred
    record observation; do not create a new mutation/action cause
else:
    construct a structural patch for only changed location components
    persist operation intent with before/after fingerprints and action IDs
    recheck ownership and exact object preconditions
    PATCH credential leaves and local mutation receipt atomically
    GET and verify receipt, credential components, and protected content
    record operation applied and accumulate its action causes
```

After **all** Secret changes and read-backs for the wave, deduplicate action instances and persist the pending action ledger. An interrupted journal entry can reconstruct this ledger from its atomic receipt; no successful mutation may lose its action debt. Revalidate every action's prerequisite locations before execution. Execute actions sequentially in action-ID order; no cross-service dependency graph is introduced in v1.

In SWITCH_TO_A, update the fixed-admin propagated password after A3, not during breeder staging. Active sources are never inferred from whichever location changed most recently.

## 11. Admin lockout suppression and restoration

### 11.1 Durable substate

`lockout` records the exact admin user ID, initial normal representation (`absent` or `false`), state, suppression/restoration operation IDs, whether true was observed, latest actual value/time, and `restore_required`.

Legal progression:

```text
normal
  -> suppress_intent
  -> suppressed
  -> restore_intent
  -> restored
```

The intended final semantic value is false, not a restoration of an unexplained preexisting true. A supposedly stable environment with true and no recognized unfinished transaction fails closed before any normalization, consumer cutover, or password generation. An operator must investigate its origin.

### 11.2 Suppress before staging or changing A

On initial ROTATE_A entry in A0:

1. Revalidate fresh VERIFY_B evidence, authoritative A-old, PS usability, topology and capability proofs.
2. GET the exact admin user; require normal lockout and invariant user fields.
3. Persist `suppress_intent`, `restore_required=true`, and the `patch_lockout` operation from false to true before dispatch.
4. With current ownership and B management authorization, PATCH only `ignore_lockout_failure_attempts=true`.
5. GET and require actual true, unchanged user identity and other protected user options. Only then record `suppressed`.
6. Proceed to password generation and durable staging. No canonical password mutation is permitted merely because the option PATCH returned 200.

A timeout is an unknown write result, not proof that suppression failed. Reconcile it under the same operation/settlement rules. If true is not established, no breeder or A password write occurs. Consumers may remain on verified B; the transaction remains unfinished.

Keep the option true through A1/A2/A3, SWITCH_TO_A, and final A propagation/runtime/function verification. Do not place unconditional restoration in a `finally` block.

### 11.3 Restore only after A is usable

Within VERIFY_A, first establish the full A verification certificate excluding the final lockout-normal condition. Then:

1. Persist `restore_intent` and a `patch_lockout` operation from true to false.
2. Use a fresh new-A management token to PATCH false. A still-verified B management token may be used if the A token lacks permission for this specific update; this does not relax A identity/role verification.
3. GET and require normal behavior, preserving other options. The default implementation writes explicit false; accept absence only for a qualified backend that normalizes false that way.
4. Record `restored`, `restore_required=false`, and actual observation.
5. Freshly authenticate A and the admin-client again, run the final stable audit, and complete cleanup/transaction. Do not intentionally test a wrong or old password after restoration.

If restoration fails, return a distinct lockout-restoration failure even when all three password authorities already agree. Keep T unfinished in VERIFY_A, retain the actual/unknown lockout state, and expose the required recovery action. Resume this T, do not rotate again.

### 11.4 Lockout recovery matrix

| Persisted evidence and observation | Required behavior |
|---|---|
| No unfinished T, observed true | Block as unexpected stable suppression; never adopt or silently restore it. |
| `normal`, observed true | Unexplained drift; stop. A same-value capability operation does not authorize true. |
| `suppress_intent`, observed false | Establish prior request settlement; retry true after revalidating ROTATE_A entry. Do not stage A first. |
| `suppress_intent`, observed true | Recognize interruption after intended suppression only if matching target/intent/ownership context is valid; record suppressed and resume. |
| `suppressed`, observed true | Retain suppression and continue recognized transaction recovery. |
| `suppressed`, observed false before restore intent | Unexpected external change; stop rather than silently re-disable it. |
| `restore_intent`, observed true | Revalidate A completion gates, settle prior request, retry false. |
| `restore_intent`, observed normal | Verify final A state, record restoration; do not re-enable suppression or repeat password writes. |
| `restored`, observed true | Drift or stale-writer evidence; stop and expose the security regression. |
| `restored`, observed normal | Continue final verification/cleanup only. |
| User unavailable, option malformed, or user ID changed | Unknown state; no password write, no best-effort normalization. |

Process death after deliberate suppression is handled by retained intent and actual user observation. A long interruption does not justify automatic early restoration: stale consumers may still be attempting A. Such a transaction requires urgent operational attention, but safety is not improved by concealing it as completed.

## 12. ROTATE_A exact algorithm and recovery

### 12.1 Initial algorithm

The following runs only with ownership, settled predecessors, a current B safety certificate, and verified suppression:

```text
1. Obtain old A from current PS; require A0 observations and recorded fingerprint.
2. Generate 32 characters with secrets.choice(ascii_letters + digits + '_').
   Reject equality with old A or B; impose no extra character-class quotas.
3. Compute new-A fingerprint; increment stage_attempt; persist intended new
   fingerprint and a pending breeder-stage operation in ROTATE_A.
4. Conditionally PATCH breeder password plus staging provenance in one object write.
5. GET breeder; verify UID, exact password, new fingerprint and all provenance.
   Record observed durable staging. From this point, do not generate another A.
6. Revalidate suppression=true, B safety, target admin identity and ownership.
   Persist Keystone password-change intent. PATCH admin to the staged password.
7. Freshly authenticate as admin with that same staged password; validate identity,
   project/roles and expiry. Record the observed Keystone result.
8. GET PS(admin). It must contain recorded old A, or recorded new A attributable
   to this transaction. For old A, persist PS mutation intent and PATCH only the
   password to the working new A. For already-new A, do not repeat the PATCH.
9. GET PS again and compare actual password/identity/version evidence.
10. GET breeder again and freshly authenticate new A. Require the authoritative
    triplet to match the intended new fingerprint. Record A3 and leave ROTATE_A.
```

Step 3 persists only a fingerprint, not the generated password. A process dying before step 4 can lose its in-memory candidate. Regeneration is allowed only after settled observation establishes that the breeder remains old, no staging marker exists, no relevant pending request can still stage the lost generation, and neither Keystone nor PS changed. Record the abandoned pre-staging attempt as not applied before recording another fingerprint.

After any observed durable stage, recover new A exclusively from the breeder and require its fingerprint/provenance to match T. A missing staged value is not permission to generate again. Fixed-admin and active propagated values are not alternative staging stores.

### 12.2 Observed A states

Here `Keystone=new` means that a fresh new-password authentication succeeded as the correct user. It does not claim that Keystone returned its stored password. Old-password rejection is not required when new authentication succeeds. [S4]

| State | PS | Breeder | Fresh accepted credential | Recovery |
|---|---|---|---|---|
| A0 | old | old | old | Revalidate entry and suppression; stage an intended/new candidate. Regenerate only before any durable stage and after request settlement. |
| A1 | old | new + matching provenance | old | Retain breeder generation; verify B and suppression; continue Keystone change to that same new value. |
| A2 | old | new + matching provenance | new | Retain new generation; verify B/suppression; update PS to the working new value, then GET. |
| A3 | new | new | new | Verify triplet; perform no password writes; continue return propagation or final verification. |

When PS and breeder differ, require a matching active T, intended new fingerprint, atomic breeder marker and recorded staging operation. In A1/A2 the stage marker remains mandatory. In A3 its absence is allowed only after attributable cleanup intent; otherwise disappearance is unexplained local-state change.

### 12.3 Authentication observation algorithm

First validate the credential sources and provenance without attempting credentials. Obtain verified B management access and inspect actual suppression. During A1/A2 classification, deliberate candidate tests are permitted only when suppression is verified true under recognized intent.

Try the staged new credential first. A valid fresh new-A token establishes the new accepted generation. A definitive credential-rejection response may then be followed by one old-A attempt using current PS, provided PS matches the recorded old fingerprint. A transport error, 5xx, MFA/policy error, or malformed response is **unknown**, not proof of an old/new password state. Avoid repeated failed probes; stop after the bounded recognized-candidate observation round unless an actual write or resolved dependency changes the evidence.

If new fails and old succeeds with matching staging provenance, classify A1. If neither succeeds, stop. If different observations contradict each other, stop. If PS=new and breeder=new but fresh new auth fails, do not reset Keystone from the transaction's assertion; this is unexplained authoritative failure.

### 12.4 Recovery dispatch

Every resume starts with ownership/settlement, configuration/key/identity checks, fresh state discovery, and lockout reconciliation. It then computes the **earliest unsatisfied legal gate**, not simply `next_operation()` from the journal.

```text
PREPARE_B incomplete                       -> finish B preparation
partial B locations or pending B actions   -> finish SWITCH_TO_B, then VERIFY_B
all B, A0                                 -> verify B, suppress/recover suppression, rotate A
A1                                        -> preserve stage; complete Keystone then PS
A2                                        -> preserve stage; complete PS
A3, some active locations still B          -> finish SWITCH_TO_A
A3, all locations A, runtime actions owed  -> finish those action instances
A3, A runtime verified, lockout true       -> finish restoration
A3, normal lockout, final audit/cleanup owed -> audit, cleanup, complete
completed same request                    -> report receipt; never rotate again
```

Missing expected Secrets, foreign provenance, unknown credential values, changed IDs/configuration, mismatched generation fingerprints, unexpected PS versions, regressed location state, or loss of a necessary B bridge block automatic completion. Forward recovery never means forcing values to agree. There is no automatic password rollback or generic transaction-abandon command in v1.

## 13. Runtime reconciliation

### 13.1 Action tokens and obligations

For action ID X in wave W, compute a deterministic UUIDv5 token using transaction UUID T as the namespace and UTF-8 name `runtime/v1/<W>/<X>`. Do not use a current timestamp as a retry token. The action's persisted causes are the applied Secret-mutation operation IDs and changed location IDs that require it.

Before an action, verify all its dependent credential locations have reached the wave target, and that the wave's Secret barrier is complete. A retry re-observes the target token and runtime, rather than triggering another restart. The A token is distinct from the B token. No action is scheduled because a Secret write was merely attempted or because a workload exists.

An action remains an obligation until runtime verification passes. After a verified action, a later missing required Pod can reopen that same original mutation-caused obligation; it does not fabricate another credential mutation. Unexpected replacement by a foreign Pod or spec remains a conflict.

### 13.2 `rollout_restart`

Support `apps/v1 Deployment` and `apps/v1 DaemonSet` with RollingUpdate in v1. Reject paused Deployments, OnDelete DaemonSets, zero-required populations, or unsupported controller strategies before propagation. Record target UID, protected spec, desired population and baseline state.

Persist action intent, then conditionally PATCH:

```text
spec.template.metadata.annotations[
    'rotation.genestack.org/reconcile-token'
] = <stable action token>
```

Use UID/resourceVersion tests. Read back the token and resulting generation. If it already equals this action token and the recorded operation explains it, do not patch again. A conflicting template token or changed protected specification requires reconciliation, not a forced restart.

Poll at five-second intervals within the action deadline. Require all of these, not simply a successful PATCH:

- Deployment: observedGeneration reaches the patched generation; updated, ready and available replicas equal the recorded desired replicas; no unavailable replicas; old ReplicaSets have no active replicas; no old-generation nonterminal Pods remain.
- DaemonSet: observedGeneration reaches the patched generation; desired/current/updated scheduled populations agree with the approved required population; ready and available counts match; unavailable and misscheduled counts are zero; no old-token nonterminal Pods remain.
- In both cases, follow ownerReferences, not labels alone, to identify controlled Pods. Required new Pods carry the action token, have completed init containers and are Ready. The desired population must not silently shrink during verification to manufacture success.

Run the configured credential-effect checks against the new Pod UIDs and functional checks for the affected service. Pod readiness alone is not evidence that a cached credential changed. Old Pods must actually cease execution; terminating/partitioned old consumers are not ignored. A controller that cannot complete the rollout blocks the transaction; do not change budgets, force-delete, scale, or reinstall Helm releases to make it pass.

### 13.3 `recreate_pod` for openstack-admin-client

The current Genestack utility manifest is `manifests/utils/utils-openstack-client-admin.yaml`. On a normal overseer/deployment checkout its candidate host path is `/opt/genestack/manifests/utils/utils-openstack-client-admin.yaml`. The publicly inspected manifest defines Pod/container `openstack-admin-client` and obtains OS_USERNAME/OS_PASSWORD through `keystone-keystone-admin`. The actual environment must pin and provide its reviewed manifest; do not fetch moving `main` during rotation. [E5]

A Job does not automatically see `/opt/genestack`. Package the approved manifest in a read-only ConfigMap or image asset and configure its **in-container** path. Include its digest in compiled configuration. Do not mount the entire host repository or depend on a deployment host's dirty working tree.

Validate the manifest before any mutation: exactly one `v1/Pod`; correct name; namespace absent or `openstack` (supply it when absent); expected container; no controller ownerReference; no live-object UID/resourceVersion/status; credential env entries are Secret references to `keystone-keystone-admin`; no literal administrative password, OS_TOKEN, alternate cloud file override, or debug flags. Admission defaults may add fields, but conflicting credentials or ownership are errors. Require an approved image digest in the environment-provided manifest rather than silently trusting the upstream floating image tag.

The action algorithm is:

```text
1. GET target Pod.
2. If it is the already-created Pod carrying this action token, adopt only after
   verifying its UID/spec/manifest attribution, then continue at readiness.
3. If an old Pod exists, journal delete intent with its UID/resourceVersion.
   DELETE with those preconditions, ordinary grace (30 seconds), no force.
   Wait for deletion and verified cessation of the old process.
4. If absent, proceed without a fake delete. Absence is compatible with a pending
   recreate action; the configured Secret mutation remains its cause.
5. Journal create intent with manifest digest and action token. POST the validated
   Pod manifest, adding the stable reconciliation token, transaction annotation,
   and rotation.genestack.org/manifest-sha256 annotation.
6. On timeout or 409, GET. Adopt only a Pod with the exact intended token and
   validated manifest/spec; otherwise fail. Never delete an unknown successor.
7. Record new UID, wait for Ready, then execute the authentication probe below.
```

Validate the created/adopted Pod against every declared manifest field after known API default normalization, the exact credential references, the manifest-digest annotation and permitted admission additions. Admission must not replace credential sources, add an overriding token/cloud file or create controller ownership. Record the first accepted admitted specification as the protected runtime baseline. Unknown changes beyond qualified admission behavior block adoption.

POST after a confirmed absence is the chosen API equivalent of delete-then-apply: it avoids an unconditional apply modifying an unrelated concurrently created Pod. A replay never deletes the already-correct new Pod just to repeat the manual command sequence.

The Pod is mandatory after reconciliation. With `required_before_start=false`, absence before a new rotation is reported but repaired after the existing location actually changes. Production expects it to be present normally; this does not make initial absence a new credential location.

### 13.4 Client authentication probe

Use Kubernetes exec against the recorded new Pod UID and configured container, no stdin/TTY and no shell. Execute:

```text
openstack --os-auth-type v3password token issue --format json --column user_id --column project_id --column expires
```

Qualify the image's support for these columns during deployment testing. Do not silently fall back to printing a complete token. Limit captured output to 16 KiB and keep stderr/raw exceptions out of normal logs. Parse the whitelisted result and require the expected user/project IDs and a future expiry. The manifest must provide password authentication, not an existing token or an overriding cloud configuration. The explicit v3password plugin and newly launched CLI process test password authentication using the Pod's current OS_* environment rather than relying on token-auth plugin selection. Qualify that behavior in the image and reject credential/cloud overrides. [E8]

During the B wave, require the B user ID; during the A wave and completion, require A. A successful token for the wrong identity is failure. Readiness without token issuance is failure. Do not pass the administrative password in exec arguments, copy it into another temporary Secret, or require the rotation Job to have a local OpenStack CLI.

## 14. Verification and configurable service probes

### 14.1 Generic verification

Every critical gate is based on fresh observations. Generic checks include record/provenance coherence, exact credential classification, positive password authentication and identity/scope checks, resource UID/template-token checks, controller convergence, required Pod existence/readiness, and admin lockout state. A final audit rereads PasswordSafe, breeder, active/fixed locations, admin user options and required runtime state; no earlier API return code substitutes for those observations.

To avoid accepting an obviously torn final snapshot, read A authorities and lockout at the beginning and end of final verification. Require their fingerprints, user identity, protected attributes and relevant object generations to remain unchanged, allowing only attributable cleanup metadata updates. The Lease does not serialize external writers; a changed observation is a blocker, not a reason to pick the more convenient read.

### 14.2 Credential effect is different from service availability

A fresh B token from the Job proves B works, not that a service consumed B. Similarly, a successful service request while old A still works cannot by itself prove B cutover. Therefore every triggered rollout action must have a qualified **credential-effect probe** covering each replacement Pod, in addition to generic rollout readiness. The admin-client's fresh identity-specific token probe supplies its own effect evidence.

A credential-effect probe must inspect the credential source actually used by the restarted process, or perform a fresh authentication through that consumer's credential path. It must not merely reread the desired Kubernetes Secret. Reading an unrelated config file or reporting an expected identity supplied by the caller is not sufficient. The deployed file paths, container names and usable probe executables are required environment inputs; the corpus does not establish them completely.

A generic exec probe may prove exact delivered components without outputting them. The runner generates 32 random challenge bytes and passes their Base64 encoding as the nonsecret `{challenge}` argv substitution. The probe reads its actual credential and returns:

```text
SHA256(
  b'genestack-rotation-probe/v1\0' + challenge_bytes
  + uint32_big_endian(len(username_utf8)) + username_utf8
  + uint32_big_endian(len(password_utf8)) + password_utf8
)
```

Return lowercase hex in `credential_proof`; the runner computes the expected value in memory and compares it. Do not send the HMAC key to service Pods. Do not persist the challenge proof, password, or raw probe output. Pair the proof with the observed Pod UID and action token. A fixed-identity probe uses its actual/established username, not an invented mutable field.

The probe implementation and qualification evidence must establish that its source corresponds to the process's effective startup/runtime credential. This challenge proves a value match, not arbitrary process behavior. Functional checks cover the remaining operational behavior.

### 14.3 Functional checks

The environment must configure meaningful checks for affected Neutron cleanup, Octavia, Blazar, and os-metrics behavior, and any additional action-bearing services. These checks must use fresh results attributable to the post-cutover consumer state, not a cached pre-cutover success. They must be capable of detecting a broken transition, not merely return an HTTP 200 from an unrelated endpoint. At least one functional probe must cover each affected service/action grouping at VERIFY_B and VERIFY_A. Qualification tests must demonstrate failure when the relevant runtime credential is deliberately wrong.

This specification does not invent a universally correct Octavia load-balancer mutation, Blazar lease operation, exporter metric, or Neutron cleanup probe. Supply concrete read-only probes where sufficient; more invasive functional experiments belong in environment qualification or a separately reviewed probe implementation with its own bounded cleanup, not hidden phase logic.

Probe objects have exact common fields `id`, `purpose` (`credential_effect` or `functional`), `covers_actions` (nonempty action-ID list), `timeout_seconds`, and `adapter`. Supported adapter objects are:

```yaml
# Execute on every replacement Pod selected through the covered action's owner UID.
type: pod_exec
container: REQUIRED_CONTAINER
program_file: /etc/rotation/probes/REQUIRED_QUALIFIED_PROBE.py
argv: [python3, "-c", "{program}", "{challenge}"]
required_checks: [credential_source_read]
```

```yaml
# Read-only HTTP; direct admin auth alone is not consumer-effect proof.
type: http_get
url: https://REQUIRED_HOST/REQUIRED_READ_ONLY_PATH
ca_file: /etc/rotation/ca/service.pem
auth: none                    # none or phase_keystone_token
expected_status: 200
assertions:
  - path: [REQUIRED_FIELD]
    equals: REQUIRED_VALUE
```

Unknown fields are rejected. `pod_exec` output is one JSON object, at most 16 KiB, with `ok: bool`, optional `credential_proof`, and `checks: {safe_check_id: bool}`; no arbitrary diagnostics. Functional success requires `ok=true`, exactly the configured nonempty `required_checks` keys, and every corresponding value true. Effect success additionally requires the challenge proof. HTTP assertions use literal mapping paths and scalar equality only; no expressions, remote code or arbitrary HTTP verbs. Validate URL hosts/CA files from reviewed configuration and never forward tokens through redirects. Disable redirects for all credential-bearing requests.

The only argv substitutions are `{challenge}` and `{program}`. The latter is the exact UTF-8 content of the configured read-only `program_file` (maximum 64 KiB), hashed into compiled configuration before any mutation. Each placeholder must occupy an entire argv element; require exactly one `{program}` and one `{challenge}`. No password, token, shell interpolation or arbitrary runtime template evaluation is allowed. A configured executable can still be dangerous; these are trusted, versioned operational programs, not a security sandbox. Verify interpreter availability in each target container and review the program as part of deployment qualification.

### 14.4 Completion predicate

Only the following conjunction authorizes `status=completed`:

```text
A3 freshly observed
AND new admin password auth and required authorization pass
AND all configured active locations are admin_new
AND all fixed-admin propagated locations are admin_new
AND no unknown or unmanaged administrative representation was discovered
AND every applied location mutation has its action obligations satisfied
AND affected workloads meet their recorded expected population/state
AND admin-client exists, is Ready and freshly authenticates as admin
AND credential-effect and service-functional checks pass
AND admin lockout suppression has been restored and verified normal
AND no unresolved operation or stale-owner settlement remains
AND transaction-owned Secret provenance cleanup is verified
```

There is no success-with-warning exception for missing probes, missing client, unresolved actions, or failed lockout restoration. Report intermediate `credential_rotation_succeeded` separately so operators can distinguish an A3 password from a fully completed transaction.

## 15. Retries, timeouts, interruption and error handling

### 15.1 Defaults and retry rules

| Operation | Default |
|---|---|
| HTTP connect deadline | 5 seconds. |
| Total individual API call deadline | 30 seconds; enforce a wall-clock bound, not only an idle socket timeout. |
| Read attempts | At most 3 per observation; full-jitter backoff bounded by 1, 2 and 4 seconds. |
| Kubernetes semantic CAS retries | At most 3 after explicit benign-change revalidation. |
| Ownership polling | 5 seconds; wait at most 180 seconds when requested. |
| Controller rollout | 600 seconds per action. |
| Pod deletion | 120 seconds, ordinary 30-second grace. |
| Admin-client Ready | 300 seconds. |
| Probe | 60 seconds unless explicitly configured otherwise. |
| Verification freshness | 60 seconds, configurable. |
| Capability-proof freshness before staging | 300 seconds, configurable. |
| Job execution deadline | 7,200 seconds; expiry interrupts execution, not transaction lifetime. |

Disable automatic transport retries for writes. A 429 or transient read failure can be retried within the observation deadline; respect a bounded Retry-After of at most 30 seconds. TLS validation failures, malformed responses, unexpected identities and authorization failures are not transient successes.

For a write timeout, dropped connection, 5xx, or ambiguous response: retain pending intent, establish request settlement, then observe actual state. If desired state and attribution are present, record applied; if the settled state proves no write occurred, record not applied and retry under a new operation ID; if neither conclusion is justified, block. Never infer no mutation from a non-2xx response alone. Do not repeat a Keystone password reset merely because a client timed out: same-password resets can have policy/history side effects, and positive authentication may already prove completion.

A token-authenticated API 401 permits one fresh token acquisition and a re-observation. A password-authentication 401 is not automatically retried with the same failing password. A 403 is a permission failure. An unsupported API/backend 501 blocks qualification. Read-after-write mismatch is a verification failure even after a successful status code.

The configured external mutation-settlement bound is distinct from all client timeouts. Without conclusive commit/precondition-fencing evidence or a verified bound, an ambiguous dispatched mutation may require operator evidence even within a single execution; do not send a new potentially contradictory write while the first could still commit.

### 15.2 Process interruption

On SIGTERM/SIGINT, set a sticky stopping flag, stop new effects, and finish only safe observation/journaling for an already dispatched operation while still owned. Never begin password rollback or unconditional lockout restoration. If a request remains uncertain, retain pending intent. Emit a redacted interruption result.

Release ownership only after the mutator is permanently disabled, renewal is coordinated, and all dispatched consequential requests are conclusively settled. Write the quiescent execution receipt before clearing the Lease holder. Otherwise stop renewal and let ownership expire; a later owner must perform settlement. The Lease UID/epoch remains for provenance. An internal crash, OOM or force kill follows the same recovery model without relying on an exit handler.

### 15.3 Failure priorities

Credential or topology ambiguity blocks all further credential and runtime mutations. Loss of ownership blocks **all** state-changing cleanup, including lockout restoration. A failed restore after A has otherwise converged is surfaced prominently as `LOCKOUT_RESTORATION_REQUIRED`; never reduce it to a log warning under exit zero.

Do not promise unattended recovery from a partition that prevents proving former-executor termination or request settlement. Preserve the recognized transaction and identify the exact evidence needed. This is fail-closed operation, not transaction abandonment.

## 16. CLI, results and exit statuses

### 16.1 Commands

```text
keystone-admin-rotate plan   --config PATH [--output PATH]
keystone-admin-rotate status --config PATH [--output PATH]
keystone-admin-rotate verify --config PATH [--output PATH]
keystone-admin-rotate rotate --config PATH --request-id UUID [--wait-for-lease]
keystone-admin-rotate resume --config PATH --transaction-id UUID
                            [--wait-for-lease] [--settlement-evidence PATH]
```

`status` reads transaction/Lease metadata without retrieving administrative passwords. `plan` performs the advisory checks in section 9. `verify` is observational and never repairs state; with an unfinished T it reports that T's recognized condition and unmet completion gates, not a new stable state.

`rotate` starts a new T only after settled ownership and stable preflight. If the same request ID is already the unfinished current transaction, it resumes it. A different unfinished request yields `UNFINISHED_TRANSACTION`; do not create a replacement. A retained completed request returns `already_completed` and the historical receipt without generating a password. That response does not claim the present environment was freshly verified. Request IDs must not be reused after the 90-day/12-receipt deduplication horizon.

`resume` only operates on the exact existing transaction and never starts a new one. A completed current transaction can be inspected/reverified without another rotation. There is no `--force`, `--ignore-unknown`, `--skip-verify`, `--skip-lockout-restore`, or generic `abort` that erases provenance.

### 16.2 Structured output

Write newline-delimited JSON logs to stdout, with UTC timestamp, severity, event code, environment, T/E/epoch when known, phase, safe target identifier, operation/action ID, attempt, duration and outcome. The last stdout record is the result object. Optionally write the same result to a configured file and a compact version to `/dev/termination-log`.

Result schema:

```text
schema_version: 1
command: plan | status | verify | rotate | resume
environment_id: string
request_id: UUID | null
transaction_id: UUID | null
execution_id: UUID
outcome: planned | observed | completed | already_completed | blocked | interrupted | failed
phase: Phase | null
observed_a_state: A0 | A1 | A2 | A3 | stable | unknown | not_checked
credential_rotation_succeeded: bool
authority_converged: bool
runtime_verified: bool
admin_client_verified: bool
lockout_suppressed: bool | null
lockout_restored: bool
transaction_complete: bool
current_environment_verified: bool
changed_location_ids: list[str]
actions_pending: list[str]
actions_verified: list[str]
checks_failed: list[str]
error_code: str | null
retryable: bool
operator_required: bool
next_action: str | null         # safe fixed-format instruction, not command secrets
exit_code: int
```

A null observation is different from false. The result may say `credential_rotation_succeeded=true`, `lockout_restored=false`, `transaction_complete=false`; that is an actionable failure, not success. Plan-only fields listing mutations, topology differences and actions appear under a separate typed `plan` object in plan output; never serialize raw external objects.

### 16.3 Exit contract

| Code | Meaning |
|---|---|
| 0 | Command completed as specified: valid plan/status, successful verification, completed transaction, or explicit already-completed receipt. |
| 2 | Invalid CLI/configuration/schema/manifest. |
| 10 | Stable precondition, topology, credential classification, or unexpected stable lockout failure. |
| 20 | Lease busy or acquisition wait exhausted. |
| 21 | Different unfinished transaction or request/configuration identity conflict. |
| 22 | Ownership lost or conflicting concurrent object modification. |
| 30 | Dependency unavailable/timeout; no unexplained state has been repaired. |
| 31 | Authentication, authorization or unsupported backend operation. |
| 40 | Runtime, functional, authoritative read-back or final verification failure. |
| 41 | Required lockout restoration failed or could not be verified after otherwise converged A state. |
| 50 | Unknown/contradictory recovery state or required fencing/request-settlement evidence missing. |
| 70 | Internal implementation error; no automatic repair. |
| 130 / 143 | SIGINT / SIGTERM interruption. |

Exit codes are categories, not permission to blindly retry. Structured `retryable` and `operator_required` distinguish re-observation from required intervention. Ownership-loss code takes precedence over cleanup attempts; result fields still expose known outstanding lockout restoration. Status may return zero while reporting a blocked T because status inspection itself succeeded; monitoring must inspect `transaction_complete` and error fields, not only process exit.

## 17. Security and Kubernetes RBAC

### 17.1 Secret handling

Disable HTTP wire/debug logging and SDK request-body dumps. Never log passwords, tokens, authorization/subject-token headers, Kubernetes Secret data, HMAC inputs, raw PasswordSafe/user responses, raw exec output, or exception strings that might include bodies. Use allowlisted error codes and identifiers rather than attempting only regex redaction after serialization.

Protect plans, transaction records, fingerprints and timing data as operationally sensitive. Credentials remain in memory, projected authentication/key volumes, PasswordSafe, breeder and declared propagated Secret data. Do not create an application password-history store, credential temporary files, crash dumps, or extra recovery-password Secrets. Python cannot guarantee zeroization of every string copy; minimize lifetimes and disable core dumps instead of claiming guaranteed memory erasure.

Require trusted TLS and hostname verification for Kubernetes, Keystone, Rackspace Identity and PasswordSafe. Do not solve the historical IP-versus-DNS connectivity observation by disabling TLS verification. Configure DNS, trusted CA and permitted egress correctly. Disable redirects for credential-bearing clients. Kubernetes audit policy and admission/webhook logging must not capture Secret bodies or exec streams containing sensitive input; verify existing platform controls as deployment prerequisites.

### 17.2 RBAC policy

Use a dedicated ServiceAccount `keystone-admin-rotation`. Generate Role rules from the **validated environment contract**, not from wildcard service names.

| Resource | Verbs/scope |
|---|---|
| Secrets in openstack | `get,list` for namespace-wide discovery. This is necessarily broad read access; document it. |
| Exact managed Secret names plus state Secret | `patch` (and `get` as above), restricted by resourceNames. No create/delete Secrets. |
| Exact rotation Lease | `get,patch,update`, restricted by resourceNames; install it out of band. |
| Deployments, DaemonSets, ReplicaSets, Pods | `get,list,watch` as needed to resolve owners and verify runtime. |
| Jobs and CronJobs | `get,list` to inspect startup/controller references and execution ancestry. |
| StatefulSets | `get,list` for discovery only; no restart support or mutation in v1. |
| Exact action-bearing Deployments/DaemonSets | `patch`, resourceNames restricted separately for each resource kind. |
| Pod/openstack-admin-client | `delete`, resourceNames restricted; normal preconditioned deletion only. |
| Pods | `create` for recreation; Kubernetes RBAC cannot resourceName-restrict ordinary collection POST creation. |
| `pods/exec` | `create` (and `get` only if required by the qualified transport), for admin-client and configured probe targets. Dynamic rollout Pod names may require namespace-wide exec authorization. |
| Namespaces `openstack` and `kube-system` | Narrow ClusterRole `get`, resourceNames restricted, for UID checks. |

The Pod-create and potentially dynamic exec privileges are real privilege boundaries, not permissions made narrow by application code. Prefer existing admission policy restricting this ServiceAccount to the approved admin-client Pod shape and names, and qualify probe permissions carefully. Do not claim that a `resourceNames` rule makes arbitrary Pod creation safe. No new permanent admission controller is part of this implementation. The top-level-create versus exec-subresource distinction is documented Kubernetes RBAC behavior. [E6]

Do not request wildcard verbs, Secret writes outside the contract, RBAC mutation, pod-log reads, node deletion, controller scale, Helm permissions, or cluster-admin. Installation of state, Lease, configuration, key, authentication Secret, ServiceAccount/RBAC and approved manifests belongs to deployment tooling. Kubernetes API credentials use the bound ServiceAccount token, not the rotating OpenStack password.

Example generated write rules (the installer expands the Secret list):

```yaml
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list]
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [keystone-admin, keystone-keystone-admin, keystone-admin-rotation-state]
    verbs: [patch]
  - apiGroups: [coordination.k8s.io]
    resources: [leases]
    resourceNames: [keystone-admin-rotation]
    verbs: [get, patch, update]
  - apiGroups: [""]
    resources: [pods]
    resourceNames: [openstack-admin-client]
    verbs: [delete]
  - apiGroups: [""]
    resources: [pods]
    verbs: [create]
```

This fragment is illustrative and not a complete installable Role. The installer must generate all read, exact managed Secret, controller-action, and qualified exec rules described above and test them without cluster-admin.

## 18. Kubernetes Job execution and deployment

The release image contains the program and pinned dependencies. Configuration, probe definitions/programs, approved client manifest, CA certificates, AD credential and fingerprint key are mounted read-only. Supply Pod name/UID, namespace, node name and request ID through the Downward API; resolve and verify the owning Job UID from the Pod's ownerReferences.

Use these Job semantics:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: keystone-admin-rotation-REQUIRED_UNIQUE_SUFFIX
  namespace: openstack
spec:
  parallelism: 1
  completions: 1
  backoffLimit: 0
  activeDeadlineSeconds: 7200
  ttlSecondsAfterFinished: 604800
  template:
    metadata:
      annotations:
        rotation.genestack.org/request-id: REQUIRED_REQUEST_UUID
    spec:
      serviceAccountName: keystone-admin-rotation
      restartPolicy: Never
      terminationGracePeriodSeconds: 60
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
      containers:
        - name: rotation
          image: REQUIRED_IMAGE_DIGEST
          args:
            - rotate
            - --config
            - /etc/rotation/environment.yaml
            - --request-id
            - $(REQUEST_ID)
          env:
            - name: REQUEST_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.annotations['rotation.genestack.org/request-id']
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          resources:
            requests: {cpu: 100m, memory: 256Mi}
            limits: {cpu: "1", memory: 512Mi}
```

The deployment must add the documented read-only volumes, full Downward API identity variables, trusted CA files, appropriate seccomp/network policy and required ServiceAccount token access. This fragment intentionally does not fabricate environment Secret names, image digests or network CIDRs.

`restartPolicy: Never` and `backoffLimit: 0` make a failure visible instead of repeatedly executing a dangerous operation. Explicit replacement Jobs use the same request ID or `resume --transaction-id`. Duplicate Pod/process execution is still protected by the Lease, request identity and journal; `parallelism: 1` is not a correctness guarantee by itself. Job TTL does not own or delete transaction state. Retain completed execution evidence before Pod garbage collection; missing old Pods may otherwise require operator fencing evidence.

A future CronJob should set `concurrencyPolicy: Forbid`, use this same Job template, and generate a unique request ID per scheduled request. Scheduling must not bypass an unfinished T or silently auto-abandon it. CronJob concurrency controls are an additional guard, not the transaction lock. There is no scheduling code in the core program.

## 19. Test and failure-injection strategy

### 19.1 Unit and static checks

CI must pass Pyright strict, runtime schema validation, deterministic serialization tests and unit tests for every phase guard and recovery classification. Use generated credentials in fixtures, never production values. Validate `transaction.schema.json` itself and every serialized record against it with format checking enabled.

Representation tests cover direct fields, DEFAULT/non-default INI, disabled interpolation, duplicate options, malformed UTF-8/base64, missing fields, nested YAML strings, duplicate keys, aliases/merges, path mismatches, noncredential semantic preservation, multiple locations per Secret, overlap rejection and semantic no-ops. Fuzz round-trips and assert that only declared leaves can change.

Fingerprint tests cover canonical encoding, identity/domain separation, full digest equality, key loss/change, unknown generations and absence of cleartext from every persisted/output model. Seed canary passwords/tokens in all mocked response/error fields; recursively scan logs, plans, state JSON, termination messages and exception output for plaintext and base64 encodings.

### 19.2 State-machine and model tests

Build an in-memory model of PS, breeder, Keystone accepted password, lockout option, location states, action receipts and Lease ownership. Enumerate crash boundaries before intent, after intent, before dispatch, after external commit, after response, after read-back and before progress recording for **every mutation type**.

For each generated sequence, assert: no unknown overwrite; never B in breeder; never new generation after a durable stage; no Keystone A change before B verification/suppression; no PS-new before new A works; no action from a no-op; every applied location change retains action debt; no completed state with suppressed lockout, missing client, pending action or failed probe.

### 19.3 Integration qualification

Use a real test Kubernetes cluster for resourceVersion/UID conflict behavior, Lease renewals, owner references, controller rollout counters, Pod deletion/recreation, readiness and exec handling. Use a disposable Keystone/PasswordSafe qualification environment for HTTP behavior; mocks alone cannot establish deployed permissions or PasswordSafe semantics.

Qualify exact deployed Keystone releases/backends and policies, including option GET/PATCH, preservation of unrelated options, same-value false updates, normal lockout restoration and admin password mutation by B. Qualify PS Identity authentication, same-value capability PATCH, changed-password PATCH, 204/read-back behavior, version observations, expired tokens, 403 and ambiguous timeout responses.

Exercise representative real Octavia, Blazar, Neutron and exporter consumers with the configured probes. Demonstrate that a deliberately wrong runtime credential causes the intended probe to fail while a generic readiness check could still pass. Confirm that all actual credential formats in each production environment are covered and that fixed-admin exceptions are justified.

### 19.4 Required failure-injection matrix

| Injection | Required result |
|---|---|
| Unknown PS or breeder value at stable entry | No transaction credential mutation; authoritative error. |
| Missing location, extra unmanaged credential, malformed document | No overwrite; topology/representation error. |
| Unknown password under admin/B username | No overwrite, even if a desired password is available. |
| B auth/grant/capability failure | No consumer cutover and no A password change. |
| PS same-value capability denied | Fail before danger, not after A is changed. |
| Lockout capability/suppression denied or read-back false | No breeder staging or A password change. |
| Death after true suppression, before staging | Resume recognizes deliberate suppression and A0; no early restore. |
| Death before breeder commit | Recover A0; regenerate only after settlement proves no durable stage. |
| Death after breeder commit, before progress | Recover A1/A2 from matching atomic provenance; retain exact generation. |
| Death/timeout after Keystone commit | Positive new auth yields A2; do not reset again. |
| PS PATCH commits but response is lost | GET proves A3 after settlement; no blind duplicate PATCH. |
| Keystone rejects the staged password under password policy | Retain the staged generation and B/suppression; block. Never generate another after staging to try to evade the policy. |
| New A never authenticates, neither known credential works | Stop; no PS update or guessed reset. |
| A-old copied downstream after A3 without provenance | Treat as regression/conflict, not ordinary propagation debt. |
| Secret commit succeeds before action ledger update | Recover receipt and execute owed action. |
| Rollout PATCH succeeds before receipt | Observe the same token; do not trigger another rollout. |
| DaemonSet OnDelete, stuck init, insufficient replicas, old terminating Pod | Block; do not force rollout success. |
| Client initially absent | After its Secret changes, create it and require Ready plus correct B/A auth. |
| Death after deleting client | Resume creates intended Pod, without another credential mutation. |
| Client create response lost | Adopt matching token/spec UID; do not delete/recreate it again. |
| Foreign same-name client created concurrently | Fail conflict, not delete unknown Pod. |
| Client Ready but token issuance fails/wrong user | VERIFY_B or VERIFY_A fails. |
| Functional or credential-effect probe missing/fails | No phase success. |
| Restore false fails after A3/all A | Exit 41, transaction unfinished; resume restoration, not password rotation. |
| Death after false PATCH before progress | Observe normal under restore intent; verify and complete without re-suppression. |
| Stable true lockout or suppressed->false without restore intent | Explicit unexpected-state failure. |
| Two rotate Jobs / duplicate request delivery | At most one mutates; duplicate completed request never rotates again. |
| E1 pauses, Lease expires, E2 takes ownership, E1 resumes | E1 cannot continue after guard/termination; E2 makes no consequential takeover mutation until predecessor/request settlement is established. |
| Delayed old PS/Keystone/Secret write after client timeout | Prevent contradictory new writes; require settlement, not optimistic assumptions. |
| Lease/key/state Secret UID changes or state is corrupt | Fail closed, never initialize around an unfinished rotation. |
| Concurrent Secret/workload edit between GET and PATCH | CAS fails; only explicitly benign metadata changes may be replanned. |
| Configuration or manifest changes during resume | Reject digest mismatch. |
| SIGTERM/OOM/Job deadline at every phase | Preserve recoverable T and expose actual/unknown lockout state. |
| Crash during provenance cleanup or completion-record write | Resume audit/cleanup; no new generation, no lost terminal obligations. |

## 20. Source register

The source names below are the reviewed corpus references. Jira comment IDs identify provenance only; the implementation specification is not based on a fresh live Jira read.

| ID | Source and use |
|---|---|
| S1 | `synopsis(1).md`, latest available current-state summary; architecture, current restart map, authority, recovery and deferred implementation details. |
| S2 | `credential-location-contract.md`, Baseline Credential-Location Contract, comment 3461734; structural representations, 23-location baseline, role/identity and mutation semantics. |
| S3 | `superseding-ab-state-machine.md`, comment 3461106; asymmetric stable-A model; explicitly supersedes symmetric A/B exploration. |
| S4 | `ROTATE_A_Write-ordering-and-recovery-semantics.md`, comment 3462605; breeder -> Keystone -> PS order and A0/A1/A2/A3 recovery. |
| S5 | `apocalypse-persistent-transaction-state.md`, comment 3462607; persistent intent, fingerprint generations, atomic breeder provenance and observation-based recovery. |
| S6 | `apocalypse-concurrency-ownership.md`, comment 3462621; Lease, execution identity/epoch, takeover and optimistic concurrency. |
| S7 | `credential-state-transition-and-propagation.md`, comment 3461086; authoritative/derived distinction and explicit topology. Its unconditional divergence language is narrowed by S4/S5. |
| S8 | `exegesis-passwordsafe.md`, comment 3462018; Identity authentication, JSON retrieval, record addressing and lack of established conditional-update facility. |
| S9 | `exegesis-passwordsafe-pw-update.md`, comment 3462617; 2026-09-24 password-only PATCH experiment, 204 and verified JSON read-back/version change. |
| S10 | `chronicle-credential-location-discovery.md`, comment 3461711; DFW-DEV evidence for the 15 standard Secrets and INI/nested YAML representations. |
| S11 | `credential-contract(1).yaml`; rough duplicate used to identify stale comments/role spelling, not preferred over S1/S2. |
| S12 | `idempotent-steps.md`, `dont-reinstall-charts.md`, `cronjob.md`; earlier exploration retained only where confirmed by current design. |
| E1 | Official OpenStack Identity API v3 reference; fresh password authentication and administrative user PATCH. |
| E2 | Official Kubernetes client-go leaderelection documentation; explicit absence of a fencing guarantee from leader election alone. |
| E3 | Official Kubernetes API Concepts; conditional resourceVersion updates and lost-update handling. |
| E4 | Official Keystone Resource Options; `ignore_lockout_failure_attempts` user option and false/absent semantics. |
| E5 | Genestack `main` utility manifest `manifests/utils/utils-openstack-client-admin.yaml`, inspected 2026-09-25; consumer wiring, not a substitute for the pinned environment manifest. |
| E6 | Official Kubernetes Using RBAC Authorization; resourceNames restrictions, collection creates and exec subresources. |
| E7 | Official Kubernetes Pod Lifecycle / kubectl delete; force deletion does not establish process termination. |
| E8 | Official OpenStackClient Authentication documentation; explicit authentication-plugin selection and password-authentication behavior. |

External reference locations (official primary sources, inspected 2026-09-25):

```text
E1 https://docs.openstack.org/api-ref/identity/v3/
E2 https://pkg.go.dev/k8s.io/client-go/tools/leaderelection
E3 https://kubernetes.io/docs/reference/using-api/api-concepts/
E4 https://docs.openstack.org/keystone/latest/admin/resource-options.html
E5 https://raw.githubusercontent.com/rackerlabs/genestack/main/manifests/utils/utils-openstack-client-admin.yaml
E6 https://kubernetes.io/docs/reference/access-authn-authz/rbac/
E7 https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/
E8 https://docs.openstack.org/python-openstackclient/latest/cli/authentication.html
```

The user-supplied admin-client and lockout requirements are normative additions to this corpus. The newer PasswordSafe mutation experiment resolves the older Exegesis's open PATCH-versus-PUT question. No separate historical HTML parser or old symmetric-slot lifecycle is adopted.

## 21. Design Reconciliations and Deviations

### 21.1 Reconciliation of contradictory or superseded sources

**One stable identity, not two interchangeable slots.** Adopt S1/S3: A is always canonical and B is durable but transitional. Discard older inactive-account disabling, symmetric stable states, permanent API/controller and generalized workflow suggestions. The breeder is never an active-slot container.

**Recognized authoritative disagreement is exceptional, not arbitrary repair.** Earlier absolute mismatch prohibitions are narrowed by S4/S5: matching transaction intent and local provenance permit only A1/A2. All unexplained disagreement still fails closed. Progress flags cannot substitute for working credentials or matching provenance.

**Runtime mappings follow the current contract, not coarse reinstall history.** Preserve separate Octavia runtime Secret copies and startup-only standard Secret. Replace historical chart reinstalls with the eight known rollout targets. The old exporter-owner discovery note is no longer open because the current Synopsis/contract name the Deployment. The rough `propgated` spelling is invalid input, not a supported alternate role.

**Old A recovery is bounded by its need.** Retain old A through PS while A is staged/changed. Do not interpret older wording that the original credential remains recoverable as requiring permanent cleartext/history retrieval after A3. Recorded old fingerprints classify remaining fixed-admin copies without creating a password-history store.

**PasswordSafe mutation is established.** Adopt experimentally verified password-only PATCH followed by JSON GET, not PUT or history retrieval. Version remains evidence, not an invented compare-and-swap lock.

**Restart becomes runtime reconciliation.** Existing restart edges retain semantics; admin-client is a recreate action on `keystone-keystone-admin`. It is neither a new credential location nor a fake Deployment. It is recreated on both B and A waves because it consumes the active credential. Initial absence may be repaired after the actual dependency mutation; final absence is never acceptable.

**Secret cleanup timing is made unambiguous.** Keep local provenance until final A verification and lockout restoration; clean before the terminal receipt. S5's possible earlier cleanup is not used. A cleanup failure does not invalidate a working password but leaves explicit finalization work, rather than conflating credential convergence with full transaction completion.

### 21.2 Implementation details selected where the design left choices open

**B preparation does not rotate B in v1.** Verify the existing PS/Keystone B credential and authorization. A second password lifecycle would add another recovery transaction and durable staging problem without being needed for the requested one-shot A rotation. B provisioning/cadence is an explicit external responsibility.

**Small typed program and API boundary.** Use Python 3.12, Pyright strict, explicit phase functions, strict validated models and narrow adapters. Use direct Keystone/PS HTTP and Kubernetes APIs. The only required OpenStack CLI is executed in the admin-client to test that consumer's actual environment.

**State storage and schema.** Choose one precreated Opaque Secret with a versioned strict JSON schema, one unfinished current transaction and bounded completed receipts. No CRD, database, dynamic transaction-object family or password journal is necessary. Use UUID request/transaction/execution identities, 12 receipts/90-day retention, and no expiry of unfinished state.

**Keyed generation identification.** Choose full HMAC-SHA-256 with a separately retained key because old A/B entropy is not established by the new-password generation requirement. Domain-separated identity/environment fingerprints prevent confusing equal strings belonging to different identities. This adds one small operational key dependency, not another stored administrative password.

**Action debt survives a crash.** Extend local provenance to propagated Secret mutations as compact receipts, in addition to mandatory breeder provenance. This prevents a crash after Secret commit from losing its restart/recreation obligation. Stable per-wave tokens make action retries observational instead of timestamp-triggered duplicate restarts.

**Write-capability proof is a real semantic no-op.** Same-current-password PS PATCH and false-to-false lockout PATCH prove actual access before danger. Planning remains read-only. The PS no-op requires environment qualification and may advance audit/version metadata; it does not alter the established ROTATE_A credential-generation write order.

**Lockout is transaction state, not best-effort cleanup.** Persist suppression before enabling it, require read-back before staging/changing A, retain it through return propagation, and require verified restoration for success. Unexpected stable suppression is a blocker. No unconditional exit-handler restoration or automatic weakening of B's policy is introduced.

**Fencing is not overstated.** Choose conservative predecessor-process and outstanding-request settlement gates on expired ownership takeover. Lease/epoch checks alone cannot supply a server-enforced fence for PS or Keystone. Unattended takeover is allowed only when qualified settlement evidence exists; otherwise the same transaction remains blocked for explicit operator evidence. This is intentionally safer than claiming client timeouts prove that requests cannot later commit.

**Operational defaults are concrete but configurable.** Select the Lease name and 120/20/60-second ownership timings, bounded retries/deadlines, JSON logs/results, explicit exit codes, exact write RBAC, Job Never/backoff 0, and later CronJob Forbid. These defaults do not turn the Job controller into the transaction mechanism.

**Verification separates delivery and usability.** Require effect probes that establish actual B/A delivery plus functional probes capable of failing on broken consumer credentials. A token from the Job or Pod readiness alone is insufficient. Probe interfaces are generic; actual service operations remain reviewed environment inputs rather than fabricated facts.

### 21.3 Genuine unknowns are not design decisions

The exact live topology outside discovered DFW-DEV, fixed-admin consumer behavior, effective service probes, actual policy/backend capabilities, same-value PS behavior, request-settlement bounds, and pinned production manifest/network inputs remain environmental facts. The next section makes them explicit enablement gates. The specification does not declare them established merely to permit a successful run.

## 22. Remaining Discovery / Environment Inputs

| Required input | Why it is required / blocking rule |
|---|---|
| Complete environment contract, discovery coverage and non-Keystone classifications | Missing/unmanaged administrative locations or ambiguous unsupported representations block rotation. Production topology is not inferred from DFW-DEV. |
| Direct breeder and `ceilometer-keystone-admin-password` consumption evidence | Must establish no runtime/startup consumer can use a known-invalid value during A1/A2 or before fixed-A propagation. Empty action lists are insufficient. |
| External and out-of-namespace consumer inventory | The namespace contract cannot protect unknown host processes, other namespaces or external tools. Establish exclusion, migration or another reviewed protection before enablement. |
| Maintenance/writer-exclusion mechanism | Prevent Helm/sync/manual writers from reverting Secrets, PS or user state. The implementation has no cross-system conditional lock against such writers. |
| Keystone URLs, CAs, region, IDs/names, management scope and grants | Resolve and verify the intended default-domain identities/admin project and actual read/update permissions. No example record or user ID is production configuration. |
| Deployed Keystone backend/option behavior and normal lockout policy | Confirm false/true read-back, preservation of unrelated options, password-update support, auth/policy failure distinctions, compatibility with all generated 32-character values from the specified alphabet, and the policy to which false returns. |
| PasswordSafe base/Identity URLs, AD account and record IDs | Qualify JSON current retrieval, actual record update permissions, token failure behavior, same-value capability PATCH and password-only PATCH/read-back. |
| Network/DNS/TLS and Secret/audit protections | Verify access from the Job and consumer Pods without disabling certificate validation; qualify audit/admission logging and at-rest handling. |
| Former-process fencing and request-settlement evidence | Provide a verified bound or an operator process. No automatic mutating takeover through unresolved split-brain/in-flight ambiguity. |
| Fingerprint key installation, retention and recovery | Missing/changed key or UID blocks existing-record interpretation. Retain while records depend on it. |
| Pinned Genestack admin-client manifest and image digest | Mount the reviewed file into the Job; validate refs/name/container, admission results, readiness and CLI token-column support. Do not assume `/opt/genestack` exists in the Job. |
| Rollout strategies, expected populations and probe permissions | Confirm RollingUpdate behavior and capacity, target UIDs/specs, container names and exec authorization without cluster-admin. |
| Qualified credential-effect and functional probes | Supply concrete per-service/Pod checks, test bad-credential detection and pin probe content. Missing coverage blocks enablement rather than being labeled success. |
| Deployment source-of-truth persistence after rotation | Ensure later configuration generation/Helm use the new authoritative password rather than reintroducing an obsolete external override. Host-file updates are outside this program. |
| Breakglass lifecycle | Provision and maintain its credential/grants separately, including its intended rotation cadence; v1 only verifies and uses it. |

These are configuration/qualification gates, not reasons to defer implementing the state machine, schemas, adapters, actions and failure tests now.

## 23. Implementation Acceptance Criteria

An implementation is accepted only when all of these are demonstrated in the qualified environment:

1. **One-shot architecture:** a pinned Python Job with Pyright strict starts, completes or reports a bounded failure, and exits. It requires no controller, HTTP service, CRD, general workflow platform, Helm reinstall or password-history retrieval.
2. **Canonical semantics:** breeder always represents admin; a completed request returns every managed active location to admin, updates fixed-admin propagated copies, and never promotes breakglass to stable configuration.
3. **Complete structural propagation:** the complete configured topology resolves, independent discovery finds no unmanaged administrative locations, and only declared credential leaves change. Unknown values and concurrent modifications are never silently overwritten.
4. **Verified B protection:** A's live password is not changed until B authenticates with required authorization, B propagation/actions/effect probes pass, fixed-A exceptions are justified and service verification demonstrates a working transition.
5. **Lockout safety:** real write capability is established before danger; deliberate suppression is durably recorded and verified before staging/changing A; it remains active through the protected interval; normal behavior is restored and observed before completion. All specified lockout failure/recovery cases pass.
6. **Exact A write order:** breeder staging/read-back precede Keystone change/new-password authentication, which precede PS password-only PATCH/read-back and authoritative triplet verification. Normal operation never fetches PS history.
7. **Generation continuity:** a 32-character secure A-Za-z0-9_ generation is never replaced after durable staging. Every A0/A1/A2/A3 crash case resumes from observed evidence; unexplained state blocks rather than triggering a reset or rollback.
8. **Crash-safe actions:** a Secret commit cannot lose its runtime action obligation. Actions deduplicate by target and wave, retries do not gratuitously restart completed workloads, and old consumers cease execution before a cutover is accepted.
9. **Admin-client integration:** the action depends on `keystone-keystone-admin`, uses the configured pinned manifest, tolerates absence within pending recreation, preserves UID/concurrency safety, and establishes Ready plus fresh correct-identity authentication on both waves and final completion.
10. **Observed final usability:** A authorities agree, fresh A auth/authorization pass, all desired locations and runtime populations are correct, required effect/functional probes pass, and no missing client, unresolved action, unknown lockout state or failed restoration is hidden behind API return codes.
11. **Ownership and recovery:** duplicate executions cannot intentionally mutate together; lost owners stop; expired takeover waits for required predecessor/request settlement; all object mutations enforce UID/resourceVersion preconditions. Unfinished state is never expired or replaced by a new request.
12. **Persistent record integrity:** every record validates against the supplied schema and semantic invariants; provenance/intent/observations reconcile; completion cleanup and retention survive interruption without losing generations, action debt or lockout obligations.
13. **Secret confidentiality:** injected canary credentials/tokens and their encoded forms do not appear in logs, results, plans, metadata, state JSON, exceptions or ordinary temporary files. Credential-generation fingerprints remain full, keyed and tied to the correct identities/environment.
14. **Operational contract:** non-cluster-admin RBAC, Job retry/deadline behavior, CLI idempotency, structured partial-success reporting and exit statuses work as specified; the required failure-injection matrix passes and all environment gates are either evidenced or explicitly block production enablement.

The acceptance condition is a verified usable stable environment and a complete recovery record, not merely a run in which every requested API call returned successfully.
