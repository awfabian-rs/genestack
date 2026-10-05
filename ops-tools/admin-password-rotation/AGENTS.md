# Admin Password Rotation — Coding Agent Guidance

This file applies to:

```text
ops-tools/admin-password-rotation/
```

## Project purpose

This package implements the Genestack/OpenStack Keystone administrative password-rotation workflow.

The implementation is intentionally:

- a small, finite Python program;
- statically typed with Pyright strict mode;
- suitable for execution as a Kubernetes Job;
- transaction-aware and safely resumable;
- not a Kubernetes operator, permanent controller, HTTP service, or generic workflow engine.

## Source authority

Before making architectural or workflow changes, read the project design sources supplied with this directory.

When design sources conflict, use this precedence:

1. explicit current-task instructions and post-brief amendments documented here;
2. the current implementation brief;
3. the implementation specification where it is not superseded by the brief;
4. `docs/DESIGN.md` for architecture actually implemented in the code;
5. `README.md` for user/developer-facing package behavior.

The implementation brief intentionally amends parts of the older implementation specification. Do not resurrect superseded behavior merely because it remains described in the older specification.

Examples of current amendments include:

- `PREPARE_B` rotates/prepares the `breakglass` credential;
- generation identifiers use `sha256:<64 lowercase hex>` rather than the older HMAC design;
- generic exactly-once/request-settlement machinery is not required;
- runtime actions use at-least-once recovery semantics;
- exact historical old-A retrieval is exceptional recovery behavior rather than a normal PasswordSafe operation;
- separate same-value capability probes are not required: the first real required mutation plus postcondition verification establishes capability;
- `DISPATCH_UNRESOLVED` marks the point at which an external mutation may have reached its service, not merely the existence of persisted intent.

When an explicit task prompt scopes a particular implementation slice or correction, follow that requested scope. Do not treat an older slice-specific restriction in historical notes as overriding the current task.

## Current architectural invariants

Preserve these unless an explicit design update says otherwise:

- `admin` is the canonical administrative identity.
- `breakglass` is the durable alternate administrative identity.
- `Secret/openstack/keystone-admin.data.password` always semantically represents `admin`; it must never contain the `breakglass` credential.
- Durable transaction state records intent and recovery context, not authoritative reality.
- Observed external state takes precedence over progress flags.
- For each consequential mutation, persist pre-dispatch intent, assert current ownership, record `DISPATCH_UNRESOLVED` immediately before crossing the external dispatch boundary, perform the effect, reobserve actual state, and only then record progress.
- A proven pre-dispatch failure is not an ambiguous external mutation. A generated credential may be abandoned and regenerated only if its cleartext was never externalized; after an unresolved dispatch where application cannot be ruled out, its generation is sticky.
- Definite rejection and ambiguous dispatch are distinct recovery classes. When an API authoritatively proves an atomic conditional mutation did not apply, return to a pre-dispatch/retryable state rather than retaining `DISPATCH_UNRESOLVED`; when application cannot be ruled out, keep unresolved-dispatch state and the intended generation sticky while reobserving reality.
- PasswordSafe mutation capability is established by its first real required mutation and verified postcondition, not by a separate same-value probe.
- Before any later A credential mutation, the real admin lockout-suppression operation must be positively observed active.
- Unknown or contradictory credential state fails closed.
- Kubernetes Lease ownership is cooperative ownership, not hard fencing.
- Consequential Kubernetes mutations use object identity and optimistic concurrency.
- Passwords, tokens, raw Secret contents, and sensitive PasswordSafe responses must not appear in logs, errors, plans, transaction state, or diagnostics.
- Credential mutations are structural; do not implement arbitrary global search-and-replace.
- Broad Helm release reinstalls are not part of the normal rotation path.

## External API boundaries

Use direct APIs rather than shelling out when production code mutates external systems.

Current boundaries include:

- Kubernetes Python client for state persistence and Lease ownership;
- direct Keystone v3 HTTP for identity authentication and user operations;
- Rackspace Identity Internal v2 plus PasswordSafe HTTP for PasswordSafe access.

Do not introduce `kubectl`, `openstack`, `curl`, or shell subprocesses into production mutation paths merely because equivalent manual commands exist.

The constrained Slice 1 read-only planning path may still use older mechanisms; do not refactor unrelated code unless the task requires it.

## Workflow scope

Implement only the requested slice or correction.

Do not opportunistically implement later phases merely because interfaces make them possible.

In particular, keep these concerns separable:

```text
observation
    ->
validation/classification
    ->
decision
    ->
persisted intent
    ->
ownership check
    ->
dispatch-unresolved marker
    ->
effect
    ->
read-back verification
    ->
progress recording
```

Avoid hiding workflow decisions inside transport/client adapters.

Write `DISPATCH_UNRESOLVED` only after ownership is established and immediately
before execution crosses the external dispatch boundary. Persisted intent that is
proven not to have reached dispatch is not mutation ambiguity.

## Secret handling

Treat as sensitive:

- admin and breakglass passwords;
- newly generated passwords;
- historical passwords;
- AD service-account passwords;
- Keystone tokens;
- Rackspace Identity tokens;
- PasswordSafe tokens/responses containing credentials.

Secret-bearing types must have redacted `str()` / `repr()` behavior.

Do not include raw HTTP response bodies or Kubernetes Secret contents in exceptions.

Mutation timeouts or connection failures may have ambiguous outcomes. Do not equate transport failure with proof that a write did not occur.

## Python and typing

Use the package's configured Python target and Pyright strict mode.

Use the repository-local virtual environment at `.venv`.
Do not silently fall back to system Python.

From this package, invoke Python as:

    ./.venv/bin/python

If `.venv` is missing or unusable, stop and report it.

Prefer:

- dataclasses and finite enums for meaningful domain distinctions;
- narrow typed adapters around third-party libraries;
- runtime validation of all external data;
- behavioral fakes for workflow tests.

Avoid spreading:

```text
Any
unchecked casts
# type: ignore
unvalidated dict plumbing
```

into the typed core.

## Repository hygiene

Preserve unrelated operator-owned files and changes.

Do not:

- delete or clean unrelated untracked files;
- reset unrelated modifications;
- absorb unrelated local setup files into a change unless requested;
- create commits, push branches, or open PRs unless explicitly requested.

Make the smallest coherent change required by the current task.

## Validation

Before reporting completion, run from this package:

```bash
./.venv/bin/python -m pyright
./.venv/bin/python -m pytest -q
./scripts/check.sh
git diff --check
```

All must pass unless the task explicitly explains an environmental limitation.

Review the final diff for:

- unrelated refactors;
- generated or temporary files;
- secret-bearing diagnostics;
- accidental implementation of later slices;
- new shell-based production API access;
- weakening of optimistic-concurrency or ownership checks.

## Post-brief implementation amendments

1. PasswordSafe exact-history retrieval remains a possible exceptional recovery
   capability, but it is deferred until a concrete need is established. Slice 3C
   demonstrates that A0-A3 reconciliation does not require it, and no current
   client exposes `get_exact_history_version()`.
2. Separate same-value capability probes are not required. The first real
   mutation needed by the workflow, together with its normal postcondition
   verification, establishes capability. PasswordSafe B staging follows this
   rule; the later real admin lockout-suppression operation must likewise be
   positively observed active before any A credential mutation.
3. `DISPATCH_UNRESOLVED` is recorded only after ownership is established and the
   workflow is about to issue the external request. It means dispatch may have
   reached the external service. A failure proven to occur before that boundary
   is not ambiguous and does not by itself make a credential generation sticky.
4. An authoritative atomic conditional rejection proves non-application even
   though the dispatch boundary was crossed. After fresh reobservation, recovery
   may return to a pre-dispatch/retryable state and replace a lost in-memory
   candidate. Unresolved-dispatch semantics remain reserved for outcomes where
   the effect may have applied; those generations remain sticky. Do not infer
   non-application from status codes or responses that lack this guarantee.

## Final report

Report:

- files changed;
- behavior implemented;
- important safety/recovery semantics;
- tests added or changed;
- validation commands and results;
- deliberate deviations from the task, if any.

Do not claim to have run checks that were not actually run.
