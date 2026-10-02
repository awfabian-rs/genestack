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
- exact historical old-A retrieval is exceptional recovery behavior rather than a normal PasswordSafe operation.

When an explicit task prompt scopes a particular implementation slice or correction, follow that requested scope. Do not treat an older slice-specific restriction in historical notes as overriding the current task.

## Current architectural invariants

Preserve these unless an explicit design update says otherwise:

- `admin` is the canonical administrative identity.
- `breakglass` is the durable alternate administrative identity.
- `Secret/openstack/keystone-admin.data.password` always semantically represents `admin`; it must never contain the `breakglass` credential.
- Durable transaction state records intent and recovery context, not authoritative reality.
- Observed external state takes precedence over progress flags.
- Persist intent before consequential effects.
- Read/verify actual state after effects before recording progress.
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

Existing constrained read-only bootstrap code may still use older mechanisms; do not refactor unrelated code unless the task requires it.

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
effect
    ->
read-back verification
    ->
progress recording
```

Avoid hiding workflow decisions inside transport/client adapters.

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
- absorb local bootstrap files into a change unless requested;
- create commits, push branches, or open PRs unless explicitly requested.

Make the smallest coherent change required by the current task.

## Validation

Before reporting completion, run from this package:

```bash
python -m pyright
python -m pytest -q
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

1. PasswordSafe exact-history retrieval remains a design requirement
   for exceptional recovery, but its implementation is deferred until
   the A-recovery slice establishes the concrete need. Slice 3A does
   not expose get_exact_history_version().

## Final report

Report:

- files changed;
- behavior implemented;
- important safety/recovery semantics;
- tests added or changed;
- validation commands and results;
- deliberate deviations from the task, if any.

Do not claim to have run checks that were not actually run.
