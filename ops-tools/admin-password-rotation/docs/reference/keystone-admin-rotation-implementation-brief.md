# Keystone Administrative Password Rotation
## Implementation brief - minimal one-shot program

**Date:** 2026-09-29  
**Project:** Genestack / OSPC-2361  
**Executable:** `keystone-admin-rotate`  
**Status:** Implementation handoff; incorporates the September 28-29 design agreements.

## 1. Purpose and authority

Build the small, statically typed Python program described here, package it as a Kubernetes Job, and implement it in reviewable slices. This brief is the implementation-facing companion to `implementation-specification.md` v0.1, dated September 25, 2026. Keep that specification as the detailed requirements and rationale baseline; do not replace it with this brief.

The explicit amendments below take precedence over conflicting v0.1 text: rotate breakglass during `PREPARE_B`; use SHA-256 only for generated replacement credentials; recover old A from its recorded PasswordSafe version when exceptionally necessary; use safely repeatable runtime actions; remove HMAC infrastructure, exactly-once action machinery, the general request-settlement subsystem, and claims of hard fencing. Apply the September 29 credential-contract corrections. Unchanged safety requirements remain in force. [S1, D1-D4]

Do not implement an operator, permanent controller, HTTP service, generic workflow engine, parallel mutation executor, broad Helm redeployment, or automatic password rollback. CronJob scheduling is a later wrapper, not part of the transaction.

## 2. Deliverable and code boundaries

Retain Python 3.12 and Pyright strict checking for production code and tests. Pin tested dependencies in the release; do not install floating versions at Job startup. Use the existing small package layout:

```text
rotation/
  cli.py                # commands, safe output, exit statuses
  models.py             # validated data models, enums, tagged unions
  config.py             # configuration, contract and manifest compilation
  representations.py    # structural fields / INI / YAML adapters
  clients.py            # Kubernetes, Keystone and PasswordSafe boundaries
  state.py              # durable record, SHA-256 identifiers, Lease ownership
  actions.py            # rollout_restart, recreate_pod, verification probes
  runner.py             # explicit phase functions and recovery decisions
```

Use typed dataclasses/enums internally and strict runtime validation at external boundaries. Pydantic, the Kubernetes Python client, `httpx`, and `ruamel.yaml` remain reasonable implementation choices from v0.1. Do not create a dependency-injection framework or plugin system. [S1]

Meaningful types include `Credential`, `Identity`, `Phase`, `CredentialGeneration`, `Location`, `ObservedLocation`, `Plan`, `MutationResult`, `RuntimeAction`, `ProbeResult`, and `Transaction`. A credential wrapper must redact its string representation. Authentication returns a tagged result distinguishing successful authentication, definite credential rejection, and an indeterminate dependency/policy failure. Unknown credentials are never writable targets.

Keep external calls behind narrow typed interfaces. The runner decides what happens next; adapters do not advance transaction phases. Use direct Keystone v3 HTTP and the Kubernetes API rather than local shell commands. The deliberate CLI exception is the authentication probe executed inside `openstack-admin-client`, using that Pod's delivered environment. [S1]

## 3. Identity model and completion invariant

```text
A = admin
B = breakglass

STABLE_A -> PREPARE_B -> SWITCH_TO_B -> VERIFY_B
         -> ROTATE_A -> SWITCH_TO_A -> VERIFY_A -> STABLE_A
```

Both accounts already exist in the configured default domain. Resolve and retain user, domain, project, and role IDs; never confuse a domain name with its ID or adopt a replacement same-name user during recovery. The program does not create users or modify grants.

`Secret/openstack/keystone-admin.data.password` always represents **admin**, including while it contains a staged replacement. It never contains breakglass. Successful completion requires fresh agreement among PasswordSafe A, the breeder, and password authentication as A; all managed active locations restored to A; required runtime actions and configured probes successful; the admin-client Ready and authenticating as A; and normal admin lockout behavior verified. B remains a working, newly rotated alternate account. [S1, D1-D2]

## 4. Configuration and the credential contract

Read one environment configuration and its explicitly selected complete credential contract. Configuration identifies the environment/cluster, Keystone endpoint and scopes, PasswordSafe record IDs and authentication-file references, trusted CAs, state Secret and Lease, action definitions, reviewed manifests, timeouts, and probes. Secrets are not literal configuration values.

Each location retains its existing semantics:

```yaml
secret: <Secret name>
identity: active                 # or fixed admin
role: propagated                # source only for the breeder
representation: <named reference or structural definition>
```

Preserve `fields`, `ini`, and `yaml`, including an optional embedded YAML document selected by `document_path`. Every representation has a password; `active` also requires a username. Change only the declared credential components. The breeder is the only source supported by this implementation. [S2]

Compile legacy `restart: [deployment/name, daemonset/name]` into typed `rollout_restart` actions. Permit explicit `actions: [action-id]` for named action definitions, including Pod recreation. Require exactly one of these dependency lists per location; an empty list is valid. Internally, use only one normalized action representation. Reject overlapping writable paths, conflicting definitions for the same action target, unknown fields, malformed documents, and missing referenced definitions.

For example, the admin-client dependency is:

```yaml
locations:
  keystone-keystone-admin:
    secret: keystone-keystone-admin
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
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

Every selected location must exist. Do not silently skip missing Secrets, select locations from live existence, or encode environment selection only in comments. Use separate complete contracts per environment, or a deterministic compilation step producing them before validation. Bind the compiled configuration and manifest contents to the transaction with a configuration digest; resume must use the same effective configuration. [S1-S2, D4]

Rotating B first assumes no managed runtime consumer is already using B. Reject fixed-B locations in this initial implementation rather than adding an unreviewed second propagation cycle. Fixed-admin propagated locations remain supported only with established non-runtime safety during the interval before A return propagation; an empty restart list alone is not that evidence.

### Required inventory corrections

Remove `ceilometer-keystone-admin-password` from the administrative credential contract; it is the Ceilometer service-user password, not the Keystone admin password. Retain `ceilometer-keystone-admin`. Add `freezer-keystone-admin` and `trove-keystone-admin` to the DFW-DEV contract as `identity: active`, `role: propagated`, `fields` over `OS_USERNAME`/`OS_PASSWORD`, with `restart: []`. Their observed consumers are bootstrap `*-ks-endpoints`, `*-ks-service`, and `*-ks-user` Jobs; do not rerun these Jobs during rotation. Do not infer production presence from their DFW-DEV presence. [D4]

Preserve these runtime mappings; they are configuration, not service-specific runner branches. [S1-S3]

| Changed credential location | Required runtime action |
|---|---|
| `keystone-keystone-admin` | Recreate `Pod/openstack-admin-client` |
| `neutron-keystone-admin` | Restart `DaemonSet/neutron-netns-cleanup-cron-default` |
| `octavia-etc`, `[service_auth]` | Restart Deployments `octavia-api` and `octavia-housekeeping` |
| `octavia-worker-default`, `[service_auth]` | Restart `DaemonSet/octavia-worker-default` |
| `octavia-health-manager-default`, `[service_auth]` | Restart `DaemonSet/octavia-health-manager-default` |
| `blazar-etc`, `[DEFAULT]` admin fields | Restart Deployments `blazar-api` and `blazar-manager` |
| `openstack-config`, `clouds.yaml` | Restart `Deployment/os-metrics-prometheus-openstack-exporter` |
| `clouds-yaml-secret`, embedded generated `clouds.yaml` | No immediate restart |

`octavia-keystone-admin` itself retains an empty restart list: its init-container use is exercised when the corresponding runtime-configuration actions recreate the Pods. Do not attach additional restarts merely because a workload can see a Secret. [S3]

## 5. Discovery and structural mutation

Discovery has two distinct jobs. First, resolve every configured location structurally and classify its declared components against the credential generations allowed by the current phase. Missing, malformed, or unknown configured credentials block mutation. Second, independently scan all Secrets in `openstack` for undeclared administrative credential occurrences. [S1-S2, D4]

For the broad read-only scan, decode Secret data and search for exact known password byte sequences, including occurrences inside larger configuration documents. Map occurrences to individual declared credential leaves; declaring one path does not exempt the rest of that Secret or document. Structural recognizers may also flag identifiable Keystone admin/breakglass username-password pairs with an unknown password. An unaccounted occurrence or ambiguous administrative candidate blocks the run and reports a safe Secret/key/path identifier, never its value.

The scan grants **no mutation authority**. An undeclared match cannot become an automatic target. Unsupported encodings, opaque content, historical release archives, and consumers outside `openstack` remain explicit coverage limitations requiring review, not blanket exclusions or a claim of complete discovery. Process paginated Secret lists consistently and bound parsing work. [S1, D4]

For mutation, decode and parse through the declared representation, change only its credential leaves, serialize, reparse, and verify that all other semantic values are unchanged. Disable INI interpolation, handle `DEFAULT` deliberately, and reject ambiguous duplicates. Reject YAML tags/aliases/merge behavior that would mutate undeclared leaves. Preserve unrelated Secret data fields byte-for-byte. No global search-and-replace fallback is allowed. [S1-S2]

A no-op credential produces no rewrite and no new action obligation. Classify old A by exact comparison with the original credential retained in process memory, current PasswordSafe while it is still old, or the exact recorded historical A version during exceptional recovery. Do not persist old-password fingerprints.

## 6. Minimal durable transaction record

Retain the precreated `Secret/openstack/keystone-admin-rotation-state` containing `state.json`, and `Lease/openstack/keystone-admin-rotation`. Neither is owned by the Job. Remove the fingerprint-key Secret entirely. Use a revised transaction schema version, `2`, rather than attempting to validate the simplified record against v0.1's operation-journal schema. Update the companion schemas/examples as an implementation deliverable, not an implicit migration. [S1, D1]

Keep the envelope with environment/cluster identity, one current transaction, and bounded completed-request records. The active transaction needs only the following information:

| Group | Contents |
|---|---|
| Identity | Transaction/request IDs; execution and Pod identity; resolved Keystone IDs; configuration digest |
| Progress | Phase, active/blocked status, timestamps, safe last error |
| Credential generations | Nullable `new_a_sha256` and `new_b_sha256`; no password values |
| PasswordSafe observations | Record IDs; original A version captured before staging; observed versions needed to detect drift and explain writes |
| Credential mutation intent | Current step, target object UID/resourceVersion where applicable, affected location IDs, intended generation |
| Propagation | Applied location IDs for each of `to_b` and `to_a`; per-wave action states `pending`, `running`, or `complete` |
| Lockout | Initial normal state; suppression/restoration intent; latest observed value; `restore_required` |
| Verification | Latest bounded check results and relevant target UIDs/generations |

Use `sha256:<lowercase hex>` over the exact UTF-8 bytes of each generated replacement password. Generate 32 characters with a cryptographically secure generator from `A-Za-z0-9_`, without additional character-class quotas. Reject a candidate equal to the credential it replaces or the other account's currently known credential. Passwords, tokens, old credentials, and PasswordSafe HTML never enter this record or logs. [S1, D1-D2]

The governing sequence remains:

```text
persist intent -> perform effect -> read/verify actual state -> record progress
```

A progress field can lag reality. It never overrides reality. One current credential-mutation intent plus per-wave progress is sufficient; do not reproduce the general append-only, per-request journal from v0.1.

Before a propagated Secret write, persist which locations are changing and which actions they cause. After read-back, atomically record the applied locations and pending action obligations. If interrupted between the Secret write and recording progress, use retained intent and a fresh, attributable target observation to recover the action obligation. An already-updated Secret must not cause the restart to be forgotten.

For the breeder only, atomically write the new password and provenance annotations identifying transaction ID, new-A SHA-256, and staged state. The active record and breeder provenance must agree before an A1/A2 mismatch is accepted. Do not create an equivalent B breeder or per-action receipt/token system. [S1, D1-D2]

## 7. External operations and preflight

The PasswordSafe adapter exposes `get_current`, `update_password`, and `get_exact_history_version`. Normal operations use the established Rackspace Identity Internal v2 token flow and PasswordSafe JSON API. Password changes use the password-only PATCH followed by GET; compare the actual returned password and validate record identity/version rather than treating HTTP 204 as completion. Version advancement is evidence, not a server-enforced concurrency lock. [S4]

Historical retrieval is exceptional and limited to the exact recorded old-A version when recovery actually needs that value. Use the separately tested HTML-history adapter established by discovery; do not assume the deployed JSON historical-password API works. Never select the second entry or merely the latest previous password. Missing, ambiguous, or unparseable requested history blocks that recovery path. B recovery needs no old-B history. [S5, D1-D2]

Stable preflight requires authoritative A agreement, normal admin lockout, valid inventory and action targets, usable external access, and exclusion of conflicting credential/deployment writers. A read-only plan does not prove write permission. Retain v0.1's controlled, same-value PasswordSafe A PATCH/read-back as a mutating capability check before the dangerous phase; capture the old-A recovery version after such checks and before staging. Its acceptance by the deployed service must be qualified. Do not repeat it with old A after staging. [S1]

After B is prepared, verify its ability to update admin's lockout option by setting the already-normal value to false and reading it back before consumer cutover. Do not add expiring capability-certificate machinery. Recheck important preconditions immediately before their consequential use.

## 8. PREPARE_B: rotate the alternate account first

A remains unchanged and all active locations remain A during this phase. Read B's configured PasswordSafe record, generate B-new, persist `SHA256(B-new)`, PATCH PasswordSafe B, and GET to verify durable staging. Only then use authenticated A management access to set the recorded breakglass user's password to that same B-new. Obtain a fresh B password-authenticated token and verify the expected user/domain/project and the admin role on the admin project. Do not add an elaborate functional probe to B preparation. [D1-D2]

| Observed state | PasswordSafe B | Keystone B | Next operation |
|---|---|---|---|
| B0 | Pre-rotation value | Not yet reset by this transaction | Stage a generated B-new in PasswordSafe |
| B1 | B-new, matching recorded SHA-256 | Reset absent or not yet verified | Use A to set the same B-new; authenticate B |
| B2 | B-new | B-new freshly authenticates | Verify authorization and leave PREPARE_B |

The original B password need not work or be supplied to the administrative reset. This follows the tested admin-to-breakglass operation; it is not a self-service password change. B1 recovery can repeat the same reset using current PasswordSafe B. Never reset B again after consumers have started switching to it. [D2, K3]

A candidate lost before any durable staging can be discarded and regenerated only when that pre-staging condition is established. Once PasswordSafe contains the fingerprinted B-new, recover that exact value. A timeout followed by one read of an old value is not proof that an earlier write cannot still complete. If an unresolved write prevents determining whether staging occurred, stop for operator resolution rather than inventing a new generation. No generic request-settlement subsystem is required.

Exit requires all three: PasswordSafe B equals the intended generation, B authenticates freshly, and B has the required authorization. Old-B fingerprints, history, local provenance, and a breeder Secret are unnecessary.

## 9. Propagation waves and VERIFY_B

Implement one `propagate(target, wave)` routine for both transitions. Read and classify each Secret afresh, validate its UID and relevant invariants, calculate structural changes, persist intent, and issue a UID/resourceVersion-conditional write. Combine nonoverlapping locations in the same Secret into one write. Read back and verify. Conditional Kubernetes updates prevent silently overwriting a stale object snapshot. [S1-S2, K1]

Complete **all credential writes for a wave before any runtime action**. Then deduplicate actions by target within that wave, revalidate their credential prerequisites, and execute sequentially. The same target may legitimately run once in each wave, and additional times after interruption under at-least-once recovery.

During `SWITCH_TO_B`, active locations may be A-old or attributable B-new; the target is B-new. During `VERIFY_B` and `ROTATE_A`, they must all be B-new. During `SWITCH_TO_A`, active locations may be B-new or attributable A-new; fixed-admin propagated locations may be recognized old A until updated. Unknown values and regression after a verified transition are errors, not repair opportunities. [S1]

`VERIFY_B` requires fresh B authentication/authorization, all active locations on B, completed required actions, healthy/Ready affected workloads, successful configured probes, and the still-valid old-A authoritative triplet immediately before initial A staging. Readiness is a baseline check, not proof of every service operation. The unresolved Octavia functional-probe choice does not block implementing this gate and its probe interface. [D3]

## 10. Lockout and ROTATE_A

Before staging or changing A, persist suppression intent with `restore_required=true`; set admin's `ignore_lockout_failure_attempts=true` using B; GET and verify it. Preserve other user settings. If suppression is not established, do not stage or change A. Unexpected suppression in a supposedly stable environment is an error, not a value to adopt. [S1, K3]

Keep the established A write order:

```text
stage breeder A-new + provenance
    -> set Keystone admin to A-new using B
    -> freshly authenticate A-new
    -> PATCH PasswordSafe A to A-new and GET
```

Persist the new-A SHA-256 before the atomic breeder write. Once staged, always recover the same generation from the breeder; never generate a replacement merely because the Job restarted. A password-only administrative update targets the recorded user ID. Do not use the original-password self-service endpoint. [S1, K3]

| State | PasswordSafe A | Breeder | Freshly accepted A credential | Recovery |
|---|---|---|---|---|
| A0 | Old | Old | Old | Revalidate B and suppression, then stage |
| A1 | Old | New with matching provenance | Old | Keep staged new; change Keystone |
| A2 | Old | New with matching provenance | New | Keep staged new; update PasswordSafe |
| A3 | New | New | New | No more A password writes; finish return propagation |

These are observed states, not progress counters. An A1/A2 mismatch is allowed only with the active transaction, matching fingerprint, and breeder provenance. Check new-A authentication first. Only a definite credential rejection permits a bounded old-A test, and only while suppression is confirmed. Network, policy, malformed-response, and service errors mean unknown state. If PasswordSafe and breeder are new but new authentication fails, do not force Keystone to agree. [S1]

After A3, propagate A-new and perform the A-wave actions. In `VERIFY_A`, verify authoritative agreement, all desired location values, runtime completion, admin-client authentication as A, configured probes, and B availability. Then persist restoration intent, set the lockout-ignore option to false, GET to verify normal behavior, and recheck A/client authentication. Never deliberately test an old password after restoration. [S1]

Do not restore lockout unconditionally in `finally`: interrupted propagation may still leave stale clients. Do not report success without verified restoration. A restoration failure leaves an unfinished transaction in `VERIFY_A`; resume restores and verifies, not rotates again. A crash after restoration but before its progress write is recovered by reading the actual option and retained restoration intent.

## 11. Runtime actions and separate verification probes

Runtime actions are **at-least-once and safely repeatable**, not exactly-once. Persist their state before execution. A `running` action whose completion cannot be proved is repeated, then verified. A recorded complete action is re-observed against its recorded target UID/generation; contradictory state is drift. Additional disruption from repeating an interrupted restart is accepted. [D3]

`rollout_restart` supports the configured Deployments and DaemonSets using supported rolling-update strategies. Patch a fresh restart annotation, then wait for the controller to observe that generation, the required population to update and become Ready/available, and old consumer Pods to retire. A successful PATCH, or old Pods that remain Ready, is not completion. Reject paused/unsupported strategies, unexpected target replacement, and a shrinking population that would manufacture success. Do not force-delete Pods, alter budgets, or redeploy charts to pass the check. [S1, D3]

`recreate_pod` validates the existing named Pod against its reviewed manifest/credential references, deletes it with UID preconditions and ordinary grace, waits for deletion, creates from the provided manifest, and waits for the replacement to become Ready. If absent, create it. An uncertain interrupted recreation may repeat the whole safe sequence; do not require a stable action token or elaborate adoption protocol. Unknown or conflicting successors block rather than being blindly deleted. [S1, D3]

The Job must receive the reviewed `utils-openstack-client-admin.yaml` as a read-only mounted/image asset; it cannot assume an overseer's `/opt/genestack` exists in its container. The manifest must reference `keystone-keystone-admin`, not contain literal passwords or authentication overrides. Recreation happens in both waves when that location changes. [S1]

Keep probes separate from action handlers. A probe receives phase, expected identity, and relevant target references, and returns a bounded typed result. Implement the admin-client probe by executing a fresh password-authenticated token request inside the Pod and validating only nonsecret user/project/expiry fields; do not print the token. Require B in the B wave and A in the A wave. [S1, D3]

Additional service probes are configured independently and must succeed when configured as required. Do not invent an Octavia listener mutation, synthetic resource, or universally required per-Pod challenge protocol. Report which probes ran and which service-specific coverage is not configured; do not label untested functionality verified.

## 12. Ownership, retries, and recovery boundary

Keep one unfinished transaction per environment and cooperative Lease exclusion. Retain defaults of 120-second Lease duration, 20-second renewal interval, and a 60-second renewal deadline. A separate renewal/watchdog path sets a sticky stop flag on ownership loss. Check ownership before each consequential effect and stop issuing mutations once ownership is uncertain. Conditional state/Secret/workload updates remain mandatory. [S1]

A Lease is **not hard fencing** for Keystone or PasswordSafe; the Kubernetes leader-election implementation itself disclaims single-leader fencing. Do not substitute a locally incremented epoch for server-enforced exclusion. Before a replacement runner resumes mutations, establish that the prior runner is no longer capable of issuing writes. An expired Lease alone, an unresponsive node, or a deleted API object alone is insufficient evidence. Unresolved prior external-write outcomes require operator resolution. This is a fail-closed boundary, not a new settlement engine. [K2]

Use bounded reads/retries and the existing timeout defaults: API connect 5 seconds, bounded call 30 seconds, read attempts 3, polling 5 seconds, rollout 600 seconds, Pod deletion 120 seconds, Pod readiness 300 seconds, probe 60 seconds. Reobserve writes with uncertain results before retrying; never blindly retry an obsolete target, regenerate a staged password, or interpret a timeout as rejection. On resourceVersion conflict, discard the stale patch and revalidate; unexplained identity/credential/provenance changes block. [S1]

Resume the existing transaction from the earliest unsatisfied legal gate supported by actual state. Do not restart its completed B rotation, adopt arbitrary downstream credentials as authority, erase unfinished state, or roll passwords backward. Release ownership only after local mutation activity has stopped; ownership loss forbids cleanup writes by the old owner.

## 13. CLI, packaging, and reporting

Retain:

```text
keystone-admin-rotate plan   --config PATH
keystone-admin-rotate status --config PATH
keystone-admin-rotate verify --config PATH
keystone-admin-rotate rotate --config PATH --request-id UUID
keystone-admin-rotate resume --config PATH --transaction-id UUID
```

`plan` is advisory and performs no configuration/password/workload writes or replacement generation. It describes B preparation without requiring the old B password to work. `status` reads metadata without retrieving passwords. `verify` observes but never repairs. A mutating command acquires ownership and revalidates. A repeated retained request ID resumes its unfinished transaction or reports its completed record; it must not create a second rotation. A different request cannot bypass unfinished work. No `--force`, verification bypass, or lockout-restoration bypass is provided. [S1, D2]

Retain v0.1's exit categories; remove the settlement-evidence flag and interpret code 50 as unresolved recovery ambiguity. In particular, code 41 means lockout restoration failed after otherwise converged A state. Structured output separately reports A/B rotation, authority convergence, runtime/probe results, actual or unknown lockout status, transaction completion, and the safe next recovery action. Logs use allowlisted metadata, not raw API bodies or generic exception dumps.

The Job uses `parallelism: 1`, `completions: 1`, `restartPolicy: Never`, `backoffLimit: 0`, and `activeDeadlineSeconds: 7200`. Explicit replacement Jobs resume the transaction. Mount configuration, CAs, PasswordSafe authentication, and reviewed manifests read-only; no fingerprint key is mounted. Use a dedicated ServiceAccount with namespace discovery reads and narrowly scoped writes to the state/Lease, managed Secrets, configured workloads, and admin-client lifecycle/exec. Do not grant broad cluster-admin access. [S1]

Keep completed request records bounded as in v0.1 and retain active recovery metadata independently of Job deletion. Finalize only after verification, restoration, final inventory audit, and breeder staging-marker cleanup. Persist cleanup intent first so a crash during cleanup is distinguishable from lost provenance.

## 14. Implementation sequence and acceptance tests

Implement in five reviewable slices: typed configuration/representations and read-only planning; durable state/Lease plus fake clients; B preparation and A recovery algorithms; propagation/actions/probes; then Job/RBAC packaging and lab qualification. Each slice includes its tests; do not ask Codex to produce the entire operational program in one unreviewed change.

Unit tests must cover deployed INI/YAML fixtures, embedded YAML, duplicate/ambiguous paths, credential redaction, environment selection, undeclared matches outside a declared leaf, unknown values, no-op writes, action deduplication, and the corrected Ceilometer/Freezer/Trove inventory.

Failure-injection tests terminate execution before and after each durable boundary: B fingerprint/staging/reset; A fingerprint/breeder staging/Keystone update/PasswordSafe update; propagated Secret writes; action start/completion; suppression/restoration; and final cleanup. Required assertions include preserving staged generations, reconstructing action obligations after an unrecorded successful Secret patch, replaying unproven actions, and never fetching history on the normal uninterrupted path.

Test exact-version old-A recovery and unavailable/ambiguous history; B recovery without old B; A0-A3 and B0-B2 dispatch; wrong-identity successful tokens; transport errors distinct from rejected credentials; Lease loss; duplicate requests; stale resourceVersions; unexpected stable suppression; and restoration-only resumption after password success.

Lab acceptance requires a complete A -> B -> A cycle with **both passwords changed**, both identities usable afterward, all selected locations correct, only justified runtime actions executed, admin-client authentication verified in both waves, normal lockout restored, no secret material emitted, and demonstrated interruption recovery. Every required configured probe must pass. Implementing the brief is not evidence that these production qualifications have already passed.

## 15. Amendments and remaining environment inputs

The material amendments to v0.1 are explicit: B rotation moves into `PREPARE_B`; HMAC and old-generation fingerprints disappear; exact-version A history becomes an exceptional recovery dependency; runtime reconciliation becomes at-least-once; service probes are separated from intrinsic action completion; the generic settlement/fencing machinery disappears without claiming stronger concurrency guarantees; and the September 29 contract corrections apply. Existing strict companion schemas/examples must be revised accordingly. The original files have not been edited by this brief.

The remaining deployment inputs are the complete per-environment inventory, actual endpoint/record IDs and permissions, excluded external consumers and conflicting writers, the approved admin-client manifest/image, qualification of the same-value PasswordSafe capability check and history parser, and the chosen service-specific probes. The Octavia probe remains a selectable discovery/qualification item, not a reason to defer the core implementation. Fixed-B consumer support is deliberately outside this first version.

---

## Source notes

- **S1:** `implementation-specification.md`, v0.1, September 25, 2026. Detailed baseline; its conflicting mechanisms are amended above.
- **S2:** `credential-location-contract.md`; structural representation and reconciliation invariants.
- **S3:** `credential-contract.baseline.yaml` and the supplied credential contracts; runtime mapping baseline, subject to the September 29 corrections.
- **S4:** `exegesis-passwordsafe-pw-update.md` and the PasswordSafe integration in S1; password-only PATCH and JSON read-back.
- **S5:** `exegesis-passwordsafe-historical-credentials.md`; exact historical credentials through the deployed HTML representation, separate from current JSON retrieval.
- **D1:** September 28, 2026 implementation-brief discussion: retain the detailed specification, simplify machinery, use generated-password SHA-256, and rotate B first.
- **D2:** September 28, 2026 breakglass reset discovery/agreement: A can reset B without B-old; idempotent same-password reset and B0/B1/B2 recovery.
- **D3:** September 28, 2026 runtime-action and probe discussion: at-least-once actions, repeat unproven completion, separate configurable service verification, defer the final Octavia probe choice.
- **D4:** September 29, 2026 contract review: remove the Ceilometer service-user credential; retain the actual admin Secret; add DFW-DEV Freezer/Trove bootstrap credentials; enforce executable environment selection.
- **K1:** Kubernetes, *API Concepts*: conditional resourceVersion updates and JSON Patch consistency tests. https://kubernetes.io/docs/reference/using-api/api-concepts/
- **K2:** Kubernetes client-go, *leaderelection package*: leader election does not guarantee fencing. https://pkg.go.dev/k8s.io/client-go/tools/leaderelection
- **K3:** OpenStack, *Identity API v3*: administrative user updates, password authentication, and user resource options. https://docs.openstack.org/api-ref/identity/v3/
