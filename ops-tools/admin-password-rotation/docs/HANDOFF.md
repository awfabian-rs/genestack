# Handoff to the next engineer or coding agent

## What exists

A runnable local Python package, not empty scaffolding. Contract parsing, immutable
typed models, all currently contracted structural readers, SecretList validation,
live read adapter, fixture mode, reference-relative classification, bounded extra-copy
audit, dependency derivation and text/JSON CLI are implemented. Synthetic tests
exercise success and failure paths. No mutation method exists.

The archive is intended to be reviewed and committed as the first draft of the
first slice. It is not claimed to implement the entire read-only planning section
of the September implementation specification or brief. Those include authoritative
and transaction observations intentionally excluded from the agreed bootstrap.

## First review tasks

Run Pyright strict locally; it could not be installed in the bootstrap environment.
Run all tests and the two synthetic CLI examples. Review the reader's INI subset,
YAML subset, scan scope and exact no-write command construction. Preserve the
explicit incomplete/read-only output semantics while fixing any issues.

The full September 25 specification and September 29 implementation brief were
not available as original files in this build workspace. The narrower scope follows
the subsequent bootstrap agreement plus the supplied source artifacts. Bring the
original spec/brief into the branch before extending into full transaction planning;
do not treat this handoff as an authoritative replacement for them.

## Known contract review points

1. `config/credential-contract.yaml` preserves the supplied 24-location contract.
   Production's derived profile removes only Freezer/Trove. Review the intended
   environment; never make these entries silently optional. The earlier baseline
   `ceilometer-keystone-admin-password` is not reintroduced.
2. The source's os-metrics MISSING INFO comment is preserved. Its declared Deployment
   is used as a dependency reference, not asserted to exist or own live Pods.
3. The recent requirement to recreate `openstack-admin-client` belongs to the later
   runtime action model. The supplied current YAML still has only `restart` lists.
   This bootstrap does not invent a new `recreate_pod` schema, mislabel a standalone
   Pod as a Deployment, or claim that this requirement has been implemented. Explicit
   action-schema fields fail validation until deliberately supported.
4. No actual workload reads, Ready checks, transaction/Lease inspection, authority
   reconciliation or detection of historical credentials are implemented. They are
   listed as deferred in every report.

## Next bounded increment

After reviewing this bootstrap, run an explicitly selected lab observation using
read-only permissions. Do not copy raw Secret data into the agent context. Share
only the credential-free findings, and produce fully synthetic reproductions of
any unsupported representation shape. Add regression tests before widening parsing
or discovery. Review config changes independently from parser capability changes.

Only then extend read-only planning with independently validated PasswordSafe and
Keystone observations, plus transaction/ownership inspection, while retaining a
pure planner. Authentication probes need their own operational semantics; do not
confuse "no password update" with no possible audit/token/lockout side effects.
Keep a topology-only report distinct from a full preflight result.

## Later-slice constraints to carry forward, not implement now

The normal state is admin, with breakglass as a temporary A->B->A bridge, not a
second permanent normal configuration. The breeder always represents admin.
Broad matching stays read-only; any eventual writes target declared structured
credential components, never global replacement.

The current design stages A in the breeder before changing Keystone, then updates
PasswordSafe with read-back verification. Intent, local provenance and observed
state explain interruptions; an arbitrary mismatch is not permission to overwrite
an authority. Resume must preserve a durably staged generation.

The recent brief's handoff constraints favor safely repeatable at-least-once
runtime actions rather than exactly-once action tokens/receipts. Do not use Lease
expiry alone as evidence that a previous writer or ambiguous external write is
resolved. Required lockout-option restoration and verification belong in eventual
completion semantics. Confirm these details against the full brief before coding
those later slices.

## Suggested next-agent task

> Review the first-slice bootstrap in ops-tools/admin-password-rotation. Read
> AGENTS.md and docs/HANDOFF.md. Run Pyright strict and pytest; fix real defects
> without weakening checks. Preserve the read-only topology boundary and explicit
> unverified-authority status. Review source-driven contract differences and parser
> limitations; add synthetic regression tests. Do not implement mutation, runtime
> actions, transactions, Lease acquisition or Job packaging in this task. Report
> exact checks executed and unresolved questions separately.
