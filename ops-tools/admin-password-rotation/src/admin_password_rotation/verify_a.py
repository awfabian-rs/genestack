"""Slice 4I: the transaction-level ``VERIFY_A`` final verification and
transaction finalization.

``run_verify_a`` independently re-observes the resulting stable-A system state
left by ``SWITCH_TO_A``, performs only the narrowly permitted
transaction-scoped cleanup, and durably marks the transaction complete — the
final runtime phase of the A -> B -> A rotation transaction.

It preserves the boundary between the three concerns:

```text
SWITCH_TO_A      = mutate consumers back toward A (Slice 4H)
VERIFY_A         = independently prove the final state is correct
finalization     = remove temporary transaction-scoped scaffolding, only
                   after the final state is proven
```

``VERIFY_A`` is **observational about the final state**: it never propagates a
credential, never generates or resets a password, never restarts a workload as
repair, and never rewrites the admin credential.  Credential or configuration
drift discovered here fails closed; the operator re-observes and recovers from
durable state.  The only mutations this phase performs are the two
transaction-scoped finalization cleanups, each executed after the final state
is proven, under current Lease ownership, and re-verified by fresh
observation:

```text
1. prove final A/config/restart state (fresh re-observation)
2. restore the temporary lockout suppression policy (if still suppressed)
3. verify the lockout restoration (fresh observation)
4. clean the breeder transaction provenance (if still present)
5. verify the breeder still contains new A and provenance is gone
6. persist the credential-free verify-a-complete receipt
7. durably mark the transaction completed (terminal stable-A state)
```

Entry conditions are re-observed, not trusted from a stale ``SWITCH_TO_A``
result.  A transaction in ``VERIFY_A`` must carry the phase-qualified durable
``switch-to-a-complete`` receipt (at phase ``SWITCH_TO_A``, generation equal to
the transaction's A generation) plus the ``ROTATE_A`` ``rotate-a-complete``
and the ``PREPARE_B`` ``stable-a`` / ``breakglass-b2`` evidence.  A transaction
whose durable state already records completion returns the established
``ALREADY_COMPLETED`` result deterministically without re-running any checks or
mutating anything.

The final authoritative A boundary is established by the Slice 3C observation
machinery (fresh breeder read, fresh PasswordSafe A read, fresh admin Keystone
authentication) required to classify A3 at the transaction's A generation:

```text
PasswordSafe(admin)
        ==
keystone-admin.password
        ==
credential accepted by Keystone admin auth
        ==
transaction.new_a_sha256
```

The final propagated-location contract is verified over the *complete
applicable admin membership* of the current contract (the same membership the
immutable to-A wave intent was derived from): every ``role: propagated``
location whose identity is ``active`` or fixed ``admin`` must freshly parse
through its declared representation and structurally equal the verified
admin/new-A credential.  Progress flags are not proof: a location is verified
from fresh observation only.  Missing Secrets, malformed representations,
unknown credentials, breakglass/B values, old-A values, and topology drift all
fail closed.  ``keystone-admin`` is verified separately as the canonical breeder
anchor.

Restart/workload verification reuses the Slice 4D semantics observationally:
restart actions are derived exactly as ``SWITCH_TO_A`` derived them (contract
digest and stale action-ID validation), every derived action must be durably
``COMPLETE``, and every affected workload must be freshly observed rolled out
and ready with the deterministic to-A restart marker.  A durable ``COMPLETE``
flag is not laundered; the fresh observation decides.

Lockout restoration is resumable: a still-suppressed policy is restored to the
pre-rotation value (the transaction records it in
``lockout.initial_ignore_lockout_failure_attempts``) with intent persistence,
ownership assertion, dispatch, and fresh read-back verification; an already
restored policy is recognized and left alone; an ambiguous dispatch or
unverifiable state fails closed.

Breeder provenance cleanup removes only this transaction's provenance
annotations from the exact breeder object the final A3 verification was based
on (UID/resourceVersion-conditional patch); the breeder password is never
touched.  Provenance owned by another transaction, carrying a different
generation or stage, or a malformed/concurrently-changed breeder fails closed.
A breeder already free of any provenance is the recognized already-clean form.

The final durable completion persists, from the exact revision on which the
final verification was based (CAS-protected, ownership asserted immediately
before the write): the credential-free ``verify-a-complete`` receipt (A
generation only), the completion marker receipt, the completed transaction
status, the terminal ``STABLE_A`` phase, a cleared ``last_error``, the
discharged lockout state, and the durable ``completed_requests`` history entry.
The transaction record is retained as durable history; it is not deleted.
No clear-text credential appears in any receipt, state, log, or error.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol, runtime_checkable

from .a_state import (
    AReconciliationStatus, ARotationInputs, ARotationObservedState,
    observe_a_rotation_state,
)
from .breeder import (
    PROVENANCE_GENERATION, PROVENANCE_STAGE, PROVENANCE_STAGE_PENDING_KEYSTONE,
    PROVENANCE_TRANSACTION, BreederError, BreederReference, BreederSecretClient,
)
from .discovery import classify
from .errors import SafeError
from .external_http import ExternalClientError, ExternalErrorCode
from .keystone import (
    KeystoneAuthIndeterminate, KeystoneAuthObservation, KeystoneAuthRejected,
    KeystoneAuthSuccess, KeystoneClient, KeystonePasswordAuthRequest,
    KeystoneUserObservation,
)
from .model import (
    CompletedOutcome, CompletedRequest, CredentialContract,
    CredentialGeneration, CredentialState, EnvironmentIdentity,
    ExecutionIdentity, Identity, IdentityBinding, LocationRole,
    LockoutChangeState, ReferenceCredentials,
    ResolvedKeystoneIdentities, RotationPhase, RotationTransaction,
    RuntimeActionState, SecretInventory, SecretSnapshot, SecretValue,
    TransactionStatus, VerificationResult, VerificationStatus, WorkloadKind,
    WorkloadRef,
)
from .passwordsafe import IdentityAccess, PasswordSafeClient
from .prepare_b import OwnershipGuard
from .propagation import (
    CredentialSecretClient, CredentialSecretClientError,
    CredentialSecretClientErrorCode, DesiredCredential,
    credential_matches_desired,
)
from .representations import read_credential
from .restart import (
    RestartExecutionErrorCode, WorkloadClient, WorkloadClientError,
    WorkloadClientErrorCode, WorkloadSnapshot, derive_restart_actions,
    restart_request_for,
)
from .state_store import PersistedState, StateStore, StateStoreError
from .validation import is_identifier

__all__ = [
    "ConditionalPatchError", "ConditionalPatchErrorCode",
    "VerifyAErrorCode", "VerifyAError", "VerifyAOutcome", "VerifyARequest",
    "VerifyAInputs", "VerifyAResult", "run_verify_a",
]


class VerifyAErrorCode(Enum):
    NO_TRANSACTION = "verify_a_no_transaction"
    UNSUPPORTED_PHASE = "verify_a_unsupported_phase"
    ENVIRONMENT_MISMATCH = "verify_a_environment_mismatch"
    CONFIGURATION_MISMATCH = "verify_a_configuration_mismatch"
    NEW_A_GENERATION_MISSING = "verify_a_new_a_generation_missing"
    SWITCH_TO_A_PREREQUISITE_MISSING = "verify_a_switch_to_a_prerequisite_missing"
    SWITCH_TO_A_PREREQUISITE_INVALID = "verify_a_switch_to_a_prerequisite_invalid"
    ROTATE_A_PREREQUISITE_INVALID = "verify_a_rotate_a_prerequisite_invalid"
    PREPARE_B_PREREQUISITE_MISSING = "verify_a_prepare_b_prerequisite_missing"
    PREPARE_B_PREREQUISITE_INVALID = "verify_a_prepare_b_prerequisite_invalid"
    A_STATE_INVALID = "verify_a_state_invalid"
    A_STATE_INDETERMINATE = "verify_a_state_indeterminate"
    LOCATION_UNVERIFIED = "verify_a_location_unverified"
    TOPOLOGY_UNVERIFIED = "verify_a_topology_unverified"
    CONTRACT_DRIFT = "verify_a_contract_drift"
    RESTART_INCOMPLETE = "verify_a_restart_incomplete"
    WORKLOAD_UNHEALTHY = "verify_a_workload_unhealthy"
    LOCKOUT_UNRESTORABLE = "verify_a_lockout_unrestorable"
    LOCKOUT_MUTATION_FAILED = "verify_a_lockout_mutation_failed"
    LOCKOUT_UNRESOLVED = "verify_a_lockout_unresolved"
    BREEDER_PROVENANCE_MISMATCH = "verify_a_breeder_provenance_mismatch"
    BREEDER_CONFLICT = "verify_a_breeder_conflict"
    BREEDER_UNRESOLVED = "verify_a_breeder_unresolved"
    PROGRESS_PERSISTENCE_FAILED = "verify_a_progress_persistence_failed"
    EXTERNAL_DEPENDENCY = "verify_a_external_dependency"


_ERROR_MESSAGES: dict[VerifyAErrorCode, str] = {
    VerifyAErrorCode.NO_TRANSACTION:
        "There is no current transaction to finalize.",
    VerifyAErrorCode.UNSUPPORTED_PHASE:
        "The current transaction is not in the VERIFY_A phase.",
    VerifyAErrorCode.ENVIRONMENT_MISMATCH:
        "The supplied environment does not match the transaction environment.",
    VerifyAErrorCode.CONFIGURATION_MISMATCH:
        "The transaction identity or configuration does not match the request.",
    VerifyAErrorCode.NEW_A_GENERATION_MISSING:
        "The transaction has no established new-A credential generation.",
    VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_MISSING:
        "The durable switch-to-a-complete receipt is absent; SWITCH_TO_A has not durably completed.",
    VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_INVALID:
        "The durable switch-to-a-complete receipt is malformed or contradictory.",
    VerifyAErrorCode.ROTATE_A_PREREQUISITE_INVALID:
        "The durable rotate-a-complete receipt is malformed or contradictory.",
    VerifyAErrorCode.PREPARE_B_PREREQUISITE_MISSING:
        "A required durable PREPARE_B completion record is absent; VERIFY_A cannot begin.",
    VerifyAErrorCode.PREPARE_B_PREREQUISITE_INVALID:
        "A required durable PREPARE_B completion record is malformed or contradictory.",
    VerifyAErrorCode.A_STATE_INVALID:
        "The authoritative A state is not freshly observed at A3.",
    VerifyAErrorCode.A_STATE_INDETERMINATE:
        "The authoritative A state could not be freshly classified.",
    VerifyAErrorCode.LOCATION_UNVERIFIED:
        "A participating or fixed-admin location is not freshly observed at the verified admin/new-A credential.",
    VerifyAErrorCode.TOPOLOGY_UNVERIFIED:
        "The observed credential topology does not match the contract; details withheld.",
    VerifyAErrorCode.CONTRACT_DRIFT:
        "The credential contract does not match the durable propagation obligation.",
    VerifyAErrorCode.RESTART_INCOMPLETE:
        "A restart required by the SWITCH_TO_A transition has not durably completed.",
    VerifyAErrorCode.WORKLOAD_UNHEALTHY:
        "A workload affected by the SWITCH_TO_A transition is not freshly observed rolled out and ready.",
    VerifyAErrorCode.LOCKOUT_UNRESTORABLE:
        "The temporary lockout suppression policy cannot be restored to its recorded pre-rotation state.",
    VerifyAErrorCode.LOCKOUT_MUTATION_FAILED:
        "The lockout restoration mutation definitively failed.",
    VerifyAErrorCode.LOCKOUT_UNRESOLVED:
        "The lockout restoration dispatch was ambiguous and the restored state cannot be confirmed.",
    VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH:
        "The breeder provenance does not belong to this transaction or is malformed; it is not cleaned.",
    VerifyAErrorCode.BREEDER_CONFLICT:
        "The breeder Secret changed after observation; the provenance cleanup was not applied.",
    VerifyAErrorCode.BREEDER_UNRESOLVED:
        "The breeder provenance cleanup outcome cannot be verified; reobserve before continuing.",
    VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED:
        "Durable VERIFY_A progress or completion could not be persisted safely.",
    VerifyAErrorCode.EXTERNAL_DEPENDENCY:
        "An external credential-system or Kubernetes dependency is unavailable; VERIFY_A does not proceed.",
}


class VerifyAError(SafeError):
    """A value-free, stable ``VERIFY_A`` verification/finalization failure."""

    def __init__(self, kind: VerifyAErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class VerifyAOutcome(Enum):
    """Typed result vocabulary for one ``VERIFY_A`` invocation.

    ``COMPLETED`` is set only when the final stable-A state was freshly
    proven, both transaction-scoped cleanups were performed (or positively
    recognized as already done), and the durable completion was persisted in
    this invocation.  ``ALREADY_COMPLETED`` is the deterministic idempotency
    result for a transaction whose durable state already records completion:
    it is returned without re-running any check and without any mutation.
    Failures raise ``VerifyAError`` and leave the transaction resumable in
    ``VERIFY_A``.
    """

    COMPLETED = "completed"
    ALREADY_COMPLETED = "already_completed"


@dataclass(frozen=True)
class VerifyARequest:
    """Caller-supplied identity/configuration to validate against the transaction.

    Mirrors the ``SWITCH_TO_A`` resume validation: a re-execution must prove
    it is operating on the same environment and Keystone/PasswordSafe identity
    before any correctness-sensitive effect.
    """

    environment: EnvironmentIdentity
    keystone: ResolvedKeystoneIdentities
    passwordsafe_project_id: int
    passwordsafe_a_record_id: int
    passwordsafe_b_record_id: int
    execution: ExecutionIdentity
    admin_username: str = "admin"
    breakglass_username: str = "breakglass"
    project_name: str = "admin"
    breeder_reference: BreederReference = BreederReference()

    def __post_init__(self) -> None:
        for value in (
            self.passwordsafe_project_id,
            self.passwordsafe_a_record_id,
            self.passwordsafe_b_record_id,
        ):
            if isinstance(value, bool) or value <= 0:
                raise ValueError("PasswordSafe identifiers must be positive integers.")
        if self.passwordsafe_a_record_id == self.passwordsafe_b_record_id:
            raise ValueError("Admin and breakglass PasswordSafe records must differ.")
        if not is_identifier(self.admin_username):
            raise ValueError("Admin username must be a valid nonempty identifier.")
        if not is_identifier(self.breakglass_username):
            raise ValueError("Breakglass username must be a valid nonempty identifier.")
        if not self.project_name:
            raise ValueError("Keystone project name must be nonempty.")


@dataclass(frozen=True)
class VerifyAInputs:
    request: VerifyARequest
    contract: CredentialContract
    passwordsafe_access: IdentityAccess
    breeder: BreederSecretClient
    secret_client: CredentialSecretClient
    workload_client: WorkloadClient
    breeder_patch: "ConditionalBreederPatch | None" = None

    def __post_init__(self) -> None:
        if (
            self.contract.namespace != self.request.breeder_reference.namespace
            or self.contract.source.secret != self.request.breeder_reference.name
        ):
            raise ValueError("The breeder reference must identify the contract source.")


@dataclass(frozen=True)
class VerifyAResult:
    """Credential-free outcome of one ``VERIFY_A`` invocation.

    ``completed`` is true only for the ``COMPLETED`` outcome.  The transaction
    identifier, phase, and A generation name the resulting durable state; no
    credential value, token, or raw external content appears in this result.
    """

    outcome: VerifyAOutcome
    persisted: PersistedState
    transaction_id: object
    phase: RotationPhase
    new_a_generation: CredentialGeneration | None = None
    completed: bool = False

    def __repr__(self) -> str:
        return (
            f"VerifyAResult(outcome={self.outcome.value!r}, "
            f"phase={self.phase.value!r})"
        )

    __str__ = __repr__


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _assert_owned(ownership: OwnershipGuard) -> None:
    """Assert current Lease ownership in this slice's error vocabulary.

    Every correctness-sensitive durable write or external mutation performed
    by this slice (the lockout restoration, the breeder provenance cleanup,
    and the final completion write) is preceded by this assertion.  Ownership
    loss surfaces as ``PROGRESS_PERSISTENCE_FAILED`` (this slice's
    persistence/ownership category), never as a foreign slice's error type.
    """
    try:
        ownership.assert_owned()
    except SafeError:
        raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def _single_verification(
    transaction: RotationTransaction, *, check_id: str, phase: RotationPhase,
) -> VerificationResult:
    """Return the one receipt matching ``(check_id, phase)``, failing closed.

    A receipt is accepted only if it matches on both ``check_id`` and
    ``phase``: a same-named receipt originating from another phase is not this
    evidence and is treated as missing.  Zero matching receipts is a missing
    prerequisite; more than one matching receipt is an ambiguous/contradictory
    record.  The receipts are *validated*, never synthesized.
    """
    matches = tuple(
        item for item in transaction.verifications
        if item.check_id == check_id and item.phase is phase
    )
    if len(matches) == 0:
        if phase is RotationPhase.SWITCH_TO_A:
            raise VerifyAError(VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_MISSING)
        if phase is RotationPhase.ROTATE_A:
            raise VerifyAError(VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_MISSING)
        raise VerifyAError(VerifyAErrorCode.PREPARE_B_PREREQUISITE_MISSING)
    if len(matches) > 1:
        if phase in (RotationPhase.SWITCH_TO_A, RotationPhase.ROTATE_A):
            raise VerifyAError(VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_INVALID)
        raise VerifyAError(VerifyAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    return matches[0]


def _switch_to_a_complete_receipt(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> None:
    """Require the phase-qualified durable ``SWITCH_TO_A`` completion receipt.

    ``SWITCH_TO_A`` records exactly one ``switch-to-a-complete`` receipt at
    phase ``SWITCH_TO_A`` carrying the A generation when it advances the phase
    to ``VERIFY_A``.  A transaction in ``VERIFY_A`` without it has not
    durably completed the reverse cutover, so there is no verified to-A wave
    to confirm against; a same-named receipt from another phase is not that
    evidence.  The receipt is *validated*, never synthesized.
    """
    receipt = _single_verification(
        transaction, check_id="switch-to-a-complete",
        phase=RotationPhase.SWITCH_TO_A,
    )
    if receipt.status is not VerificationStatus.SUCCESS:
        raise VerifyAError(VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_INVALID)
    if receipt.credential_generation is None:
        raise VerifyAError(VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_INVALID)
    if receipt.credential_generation != generation:
        raise VerifyAError(VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_INVALID)


def _rotate_a_complete_receipt(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> None:
    """Require the phase-qualified durable ``ROTATE_A`` completion receipt.

    The authoritative-A convergence evidence must remain structurally
    consistent for the transaction to be finalizable: exactly one
    ``rotate-a-complete`` receipt at phase ``ROTATE_A`` carrying the A
    generation.  It is *validated*, never synthesized.
    """
    receipt = _single_verification(
        transaction, check_id="rotate-a-complete", phase=RotationPhase.ROTATE_A,
    )
    if receipt.status is not VerificationStatus.SUCCESS:
        raise VerifyAError(VerifyAErrorCode.ROTATE_A_PREREQUISITE_INVALID)
    if receipt.credential_generation is None:
        raise VerifyAError(VerifyAErrorCode.ROTATE_A_PREREQUISITE_INVALID)
    if receipt.credential_generation != generation:
        raise VerifyAError(VerifyAErrorCode.ROTATE_A_PREREQUISITE_INVALID)


def _prepare_b_evidence(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> VerificationResult:
    """Require the durable ``PREPARE_B`` completion evidence.

    Successful ``PREPARE_B`` leaves exactly two durable receipts, each
    explicitly at phase ``PREPARE_B``: ``stable-a`` (old-A generation plus the
    breeder UID it verified — the anchor the Slice 3C A-state machinery
    validates the current breeder identity against) and ``breakglass-b2``
    (B generation).  Both are mandatory and must be ``SUCCESS``; missing,
    wrong-phase, non-success, malformed, or generation-inconsistent evidence
    fails closed before any observation, cleanup, or completion work.
    """
    stable_a = _single_verification(
        transaction, check_id="stable-a", phase=RotationPhase.PREPARE_B,
    )
    if stable_a.status is not VerificationStatus.SUCCESS:
        raise VerifyAError(VerifyAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    b2 = _single_verification(
        transaction, check_id="breakglass-b2", phase=RotationPhase.PREPARE_B,
    )
    if b2.status is not VerificationStatus.SUCCESS:
        raise VerifyAError(VerifyAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if stable_a.credential_generation is None or stable_a.target_uid is None:
        raise VerifyAError(VerifyAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation is None:
        raise VerifyAError(VerifyAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation != generation:
        raise VerifyAError(VerifyAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    return stable_a


def _restamp_execution(
    store: StateStore, ownership: OwnershipGuard, persisted: PersistedState, *,
    execution: ExecutionIdentity, now: datetime,
) -> PersistedState:
    """Re-stamp the durable transaction's current execution on resume.

    ``transaction.execution`` records the execution currently operating the
    transaction: credential-free bookkeeping, not the fencing mechanism
    (current Lease ownership is authoritative).  A durable update to
    transaction state is itself a mutation, so ownership is asserted before
    the write; a stale execution that has lost the Lease cannot modify the
    durable transaction.  The state-store write is CAS-protected.  A no-op
    when the durable execution already matches the resuming one.
    """
    transaction = persisted.state.current_transaction
    if transaction is not None and transaction.execution == execution:
        return persisted
    _assert_owned(ownership)
    assert transaction is not None
    updated = replace(transaction, execution=execution, updated_at=now)
    try:
        return store.update(
            persisted.revision,
            replace(persisted.state, current_transaction=updated),
        )
    except StateStoreError:
        raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def _observe_a3_final(
    inputs: VerifyAInputs, transaction: RotationTransaction, *,
    breeder: SecretSnapshot,
    passwordsafe: PasswordSafeClient, keystone: KeystoneClient,
    clock: Callable[[], datetime],
) -> None:
    """Freshly re-observe and classify the authoritative A boundary; require A3.

    This is the final authoritative-A verification: it re-reads the canonical
    breeder (the caller supplies the exact snapshot used as the observation
    basis, so the later provenance cleanup mutates from the same object), the
    PasswordSafe A record, and the fresh admin Keystone authentication, all
    through the Slice 3C observation machinery.  The result must be a valid,
    freshly observed A3 at the transaction's A generation, so that
    PasswordSafe A, the canonical breeder, and the Keystone-accepting
    credential are all established as the identical new-A credential in this
    invocation.  It performs no mutation.  Any invalid, indeterminate, or
    non-A3 classification fails closed before any cleanup or completion.
    """
    request = inputs.request
    result = observe_a_rotation_state(
        ARotationInputs(
            transaction=transaction,
            contract=inputs.contract,
            inventory=SecretInventory(
                breeder.namespace, breeder.resource_version, (breeder,),
            ),
            passwordsafe_access=inputs.passwordsafe_access,
            passwordsafe_project_id=request.passwordsafe_project_id,
            admin_username=request.admin_username,
            project_name=request.project_name,
        ),
        passwordsafe=passwordsafe,
        keystone=keystone,
        clock=clock,
    )
    if result.status is AReconciliationStatus.INDETERMINATE:
        raise VerifyAError(VerifyAErrorCode.A_STATE_INDETERMINATE)
    if (
        result.status is not AReconciliationStatus.VALID
        or result.state is not ARotationObservedState.A3
    ):
        raise VerifyAError(VerifyAErrorCode.A_STATE_INVALID)


def _observe_namespace(
    inputs: VerifyAInputs,
) -> tuple[tuple[SecretSnapshot, ...], tuple[SecretSnapshot, ...], tuple[str, ...]]:
    """Freshly observe the namespace; separate the contracted and full views.

    Returns ``(contracted, namespace, missing)``:

    - ``contracted``: the one snapshot per contracted Secret name (read by
      name), used for the strict per-location structural verification.
    - ``namespace``: the full namespace listing, used by the strict topology
      verification to detect unexpected administrative-credential Secrets
      that the contract does not declare.
    - ``missing``: contracted Secret names that are absent (observed state).

    A transport-level read/list failure remains ``EXTERNAL_DEPENDENCY``; a
    missing contracted Secret is *observed state* reported by the topology and
    location verification.
    """
    contract = inputs.contract
    names = sorted({location.secret for location in contract.locations})
    seen: dict[str, SecretSnapshot] = {}
    missing: list[str] = []
    for name in names:
        try:
            seen[name] = inputs.secret_client.read(contract.namespace, name)
        except CredentialSecretClientError as exc:
            if exc.kind is CredentialSecretClientErrorCode.NOT_FOUND:
                missing.append(name)
            else:
                raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    try:
        namespace = inputs.secret_client.list(contract.namespace)
    except CredentialSecretClientError:
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    return (
        tuple(seen[name] for name in names if name in seen),
        namespace,
        tuple(missing),
    )


def _current_inventory(
    inputs: VerifyAInputs,
) -> tuple[SecretInventory, tuple[SecretSnapshot, ...], tuple[str, ...]]:
    """Freshly read every contracted Secret; build the classification view.

    Returns ``(inventory, namespace, missing)``.  A contracted Secret that is
    absent is *observed state* (a location whose expected Secret is missing),
    not a dependency failure; a transport-level read/list failure remains
    ``EXTERNAL_DEPENDENCY``.
    """
    secrets, namespace, missing = _observe_namespace(inputs)
    return (
        SecretInventory(inputs.contract.namespace, None, secrets),
        namespace,
        missing,
    )


def _verify_final_locations(
    inputs: VerifyAInputs, *,
    inventory: SecretInventory, missing_secrets: tuple[str, ...],
    references: ReferenceCredentials, desired: DesiredCredential,
) -> None:
    """Freshly verify every contracted propagated location at admin/new-A.

    The verification set is the *complete applicable admin membership* of the
    current contract — every ``role: propagated`` location whose identity is
    ``active`` **or** fixed ``admin`` (the same membership the immutable to-A
    wave intent was derived from) — not the durable changed set:
    ``applied_location_ids`` is a progress hint and never proof that a
    location converged.  Every location must freshly parse through its
    declared representation and structurally equal the verified
    admin/new-A credential per its exact declared fields:

    - ``identity: active`` locations must equal the verified new-A
      credential (username ``admin`` plus the exact new-A password where the
      representation declares a username).  A breakglass/B value, an old-A
      value, an unknown credential, a missing Secret, or a malformed
      representation all fail closed.
    - fixed ``identity: admin`` locations must classify as
      ``MATCHES_ADMIN_REFERENCE``: they remain associated with ``admin``
      throughout the transaction, so a breakglass credential, a wrong admin
      password, an unknown credential, a missing Secret, or a malformed
      representation all fail closed.

    The canonical ``keystone-admin`` source is not part of this location set;
    it is verified separately by the authoritative A3 observation and the
    provenance cleanup.
    """
    contract = inputs.contract
    missing = set(missing_secrets)
    by_name = {
        secret.name: secret for secret in inventory.secrets
        if secret.namespace == contract.namespace
    }
    for location in sorted(contract.locations, key=lambda item: item.name):
        if location.role is not LocationRole.PROPAGATED:
            continue
        if location.secret in missing:
            # A contracted propagated location whose Secret is absent is
            # unexplained state regardless of its identity binding: fail
            # closed rather than silently dropping it from the obligation.
            raise VerifyAError(VerifyAErrorCode.LOCATION_UNVERIFIED)
        snapshot = by_name.get(location.secret)
        if snapshot is None:
            raise VerifyAError(VerifyAErrorCode.LOCATION_UNVERIFIED)
        try:
            observed = read_credential(snapshot, location.representation)
        except SafeError:
            raise VerifyAError(VerifyAErrorCode.LOCATION_UNVERIFIED) from None
        if location.identity is IdentityBinding.ACTIVE:
            if not credential_matches_desired(location, observed, desired):
                raise VerifyAError(VerifyAErrorCode.LOCATION_UNVERIFIED)
        elif location.identity is IdentityBinding.ADMIN:
            if classify(location, observed, references) is not CredentialState.MATCHES_ADMIN_REFERENCE:
                raise VerifyAError(VerifyAErrorCode.LOCATION_UNVERIFIED)
        else:
            # A ``breakglass``-bound propagated location is not part of the
            # final stable-A contract; its presence is contract drift.
            raise VerifyAError(VerifyAErrorCode.TOPOLOGY_UNVERIFIED)


def _verify_topology(
    inputs: VerifyAInputs, *,
    secrets: tuple[SecretSnapshot, ...],
) -> None:
    """Fail closed on unexpected administrative-credential topology.

    Strict discovery semantics: the fresh namespace scan is checked for
    uncontracted administrative-credential Secrets: an ``OS_USERNAME`` field
    naming ``admin`` or ``breakglass`` in a Secret the contract does not
    declare is an unexpected administrative-credential location.  A missing
    expected contracted Secret is reported by the location verification
    (which also handles the breeder Secret).  Non-contract-namespace objects
    fail closed as an inconsistent observation.
    """
    contract = inputs.contract
    expected = {location.secret for location in contract.locations}
    for secret in secrets:
        if secret.namespace != contract.namespace:
            raise VerifyAError(VerifyAErrorCode.TOPOLOGY_UNVERIFIED)
        username = secret.get("OS_USERNAME")
        if (
            username is not None
            and username.reveal() in (b"admin", b"breakglass")
        ):
            if secret.name not in expected:
                raise VerifyAError(VerifyAErrorCode.TOPOLOGY_UNVERIFIED)


def _observe_workload(
    client: WorkloadClient, workload: WorkloadRef,
) -> WorkloadSnapshot:
    """Freshly read one affected workload; never dispatch."""
    try:
        if workload.kind is WorkloadKind.DEPLOYMENT:
            return client.deployment.read("openstack", workload.name)
        return client.daemonset.read("openstack", workload.name)
    except WorkloadClientError as exc:
        if exc.kind is WorkloadClientErrorCode.NOT_FOUND:
            raise VerifyAError(VerifyAErrorCode.WORKLOAD_UNHEALTHY) from None
        if exc.kind is WorkloadClientErrorCode.INVALID:
            raise VerifyAError(VerifyAErrorCode.WORKLOAD_UNHEALTHY) from None
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None


def _verify_restart_debt(
    inputs: VerifyAInputs, transaction: RotationTransaction, *,
    now: datetime,
) -> None:
    """Observational restart/workload verification of the SWITCH_TO_A debt.

    Restart obligations are derived exactly as ``SWITCH_TO_A`` derived them
    (contract digest validated against the to-A wave intent; stale durable
    action IDs fail closed), and every derived action must be durably
    ``COMPLETE``.  Every affected workload is then freshly observed through
    the Slice 4D workload abstraction and its generation-aware completion
    predicate (matching the deterministic to-A restart marker, converged
    replicas): a durable ``COMPLETE`` flag is not laundered — the fresh
    observation decides.  Nothing is restarted here; a failed or incomplete
    rollout prevents completion.
    """
    del now
    wave = transaction.propagation.to_a
    try:
        actions = derive_restart_actions(
            inputs.contract, transaction, target=Identity.ADMIN,
        )
    except SafeError as error:
        kind = getattr(error, "kind", None)
        if kind in (
            RestartExecutionErrorCode.CONTRACT_DRIFT,
            RestartExecutionErrorCode.INTENT_MISMATCH,
            RestartExecutionErrorCode.NO_WAVE_INTENT,
        ):
            raise VerifyAError(VerifyAErrorCode.CONTRACT_DRIFT) from None
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    derived_ids = {action.action_id for action in actions}
    durable_ids = {item.action_id for item in wave.runtime_actions}
    # A durable runtime action ID that is not derivable from the current
    # changed-location accounting is stale or contradictory state.
    if not durable_ids <= derived_ids:
        raise VerifyAError(VerifyAErrorCode.CONTRACT_DRIFT)
    durable_state = {
        item.action_id: item.state for item in wave.runtime_actions
    }
    for action in actions:
        if durable_state.get(action.action_id) is not RuntimeActionState.COMPLETE:
            raise VerifyAError(VerifyAErrorCode.RESTART_INCOMPLETE)
    marker = restart_request_for(wave)
    for action in actions:
        snapshot = _observe_workload(inputs.workload_client, action.workload)
        if not snapshot.complete(restart_requested=marker):
            raise VerifyAError(VerifyAErrorCode.WORKLOAD_UNHEALTHY)


def _admin_user(
    keystone: KeystoneClient, *, user_id: str, token: SecretValue,
    username: str, expected: ResolvedKeystoneIdentities, project_id: str,
) -> KeystoneUserObservation:
    """Freshly observe the admin user, validating identity invariants."""
    try:
        observed = keystone.get_user(user_id=user_id, management_token=token)
    except ExternalClientError:
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    if not (
        observed.user_id == expected.admin_user_id
        and observed.name == username
        and observed.domain_id == expected.user_domain_id
        and observed.enabled
        and observed.default_project_id in (None, project_id)
    ):
        raise VerifyAError(VerifyAErrorCode.LOCKOUT_UNRESTORABLE) from None
    return observed


def _ensure_lockout_restored(
    store: StateStore, ownership: OwnershipGuard, persisted: PersistedState, *,
    keystone: KeystoneClient, token: SecretValue, now: datetime,
) -> PersistedState:
    """Restore the temporary lockout suppression; resumable.

    Deterministic cleanup order: prove final state, **then** restore lockout.
    This cleanup is transaction-scoped and must not survive transaction
    completion.  The expected restored value is the transaction's recorded
    pre-rotation policy
    (``lockout.initial_ignore_lockout_failure_attempts``).

    Recovery semantics:

    - observed already at the expected value: recognized as restored; no
      mutation and no unnecessary state write (resume after a crash between
      the restoration dispatch and the state update).
    - observed still suppressed: persist the restoration intent, assert
      ownership, dispatch the mutation, and require a fresh read-back at the
      expected value (a proven pre-dispatch failure returns the intent to a
      retryable state; an ambiguous dispatch fails closed on
      ``LOCKOUT_UNRESOLVED``).
    - observed in any other third state: fail closed
      (``LOCKOUT_UNRESTORABLE``).
    """
    transaction = persisted.state.current_transaction
    assert transaction is not None
    expected_value = transaction.lockout.initial_ignore_lockout_failure_attempts
    lockout = transaction.lockout

    observed = _admin_user(
        keystone, user_id=transaction.keystone.admin_user_id, token=token,
        username="admin", expected=transaction.keystone,
        project_id=transaction.keystone.project_id,
    )

    if observed.ignore_lockout_failure_attempts == expected_value:
        # Already restored (crash between dispatch and durable recording):
        # recognize the correct state and leave it alone.  A durable record
        # that still claims restoration is required is stale progress; a
        # fresh, correct observation discharges it.  No mutation, and no
        # state write when the durable record already reflects the discharge.
        if (
            lockout.restore_required
            and lockout.restoration is not LockoutChangeState.EFFECT_OBSERVED
        ):
            updated = replace(transaction, lockout=replace(
                lockout,
                restoration=LockoutChangeState.EFFECT_OBSERVED,
                latest_ignore_lockout_failure_attempts=expected_value,
                restore_required=False,
            ), updated_at=now)
            _assert_owned(ownership)
            try:
                return store.update(
                    persisted.revision,
                    replace(persisted.state, current_transaction=updated),
                )
            except StateStoreError:
                raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None
        return persisted

    if lockout.suppression is not LockoutChangeState.EFFECT_OBSERVED:
        raise VerifyAError(VerifyAErrorCode.LOCKOUT_UNRESTORABLE)

    # Persist the restoration intent (pre-dispatch), then assert ownership
    # immediately before crossing the external dispatch boundary.
    updated = replace(transaction, lockout=replace(
        lockout,
        restoration=LockoutChangeState.INTENT_PERSISTED,
        latest_ignore_lockout_failure_attempts=observed.ignore_lockout_failure_attempts,
    ), updated_at=now)
    try:
        persisted = store.update(
            persisted.revision,
            replace(persisted.state, current_transaction=updated),
        )
    except StateStoreError:
        raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None
    _assert_owned(ownership)
    current = persisted.state.current_transaction
    assert current is not None
    updated = replace(current, lockout=replace(
        current.lockout,
        restoration=LockoutChangeState.DISPATCH_UNRESOLVED,
    ), updated_at=now)
    try:
        persisted = store.update(
            persisted.revision,
            replace(persisted.state, current_transaction=updated),
        )
    except StateStoreError:
        raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None

    ambiguous = False
    try:
        keystone.set_ignore_lockout_failure_attempts(
            user_id=transaction.keystone.admin_user_id,
            value=expected_value,
            management_token=token,
        )
    except ExternalClientError as error:
        if error.kind is ExternalErrorCode.MUTATION_AMBIGUOUS:
            ambiguous = True
        else:
            # Proven pre-dispatch failure: return the intent to retryable.
            current = persisted.state.current_transaction
            assert current is not None
            retry = replace(current, lockout=replace(
                current.lockout, restoration=LockoutChangeState.INTENT_PERSISTED,
            ), updated_at=now)
            try:
                persisted = store.update(
                    persisted.revision,
                    replace(persisted.state, current_transaction=retry),
                )
            except StateStoreError:
                raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None
            raise VerifyAError(VerifyAErrorCode.LOCKOUT_MUTATION_FAILED) from None

    current = persisted.state.current_transaction
    assert current is not None
    try:
        actual = _admin_user(
            keystone, user_id=transaction.keystone.admin_user_id, token=token,
            username="admin", expected=transaction.keystone,
            project_id=transaction.keystone.project_id,
        )
    except VerifyAError:
        if ambiguous:
            raise VerifyAError(VerifyAErrorCode.LOCKOUT_UNRESOLVED) from None
        raise
    if not actual.ignore_lockout_failure_attempts == expected_value:
        code = (
            VerifyAErrorCode.LOCKOUT_UNRESOLVED
            if ambiguous else VerifyAErrorCode.LOCKOUT_MUTATION_FAILED
        )
        raise VerifyAError(code)
    finished = replace(current, lockout=replace(
        current.lockout,
        restoration=LockoutChangeState.EFFECT_OBSERVED,
        latest_ignore_lockout_failure_attempts=expected_value,
        restore_required=False,
    ), updated_at=now)
    try:
        return store.update(
            persisted.revision,
            replace(persisted.state, current_transaction=finished),
        )
    except StateStoreError:
        raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def _clean_breeder_provenance(
    inputs: VerifyAInputs, *,
    ownership: OwnershipGuard,
    transaction: RotationTransaction, breeder: SecretSnapshot,
    now: datetime,
) -> None:
    """Remove this transaction's provenance from the canonical breeder.

    Called only after the final A3 verification succeeded against this exact
    breeder snapshot, so the cleanup mutates from the very object that
    justified the decision (UID/resourceVersion test ops are part of the
    conditional patch; a concurrently changed breeder is
    ``CONDITIONAL_REJECTED`` and fails closed, never silently adopted).

    The decision is made from the observed annotations:

    - no transaction provenance present: the documented clean terminal form;
      nothing to remove (resume after a crash between cleanup and state
      updates).
    - exactly this transaction's provenance (matching transaction id, A
      generation, and stage): removed, leaving every other annotation and
      **especially** the ``password`` field untouched.
    - any other provenance (different transaction, different generation or
      stage, or a malformed mix): not safe to delete; fail closed.

    The breeder provenance patch is a Kubernetes mutation: current Lease
    ownership is asserted immediately before crossing the dispatch boundary
    (only when a patch will actually be applied).  A lost owner cannot clean
    the breeder.  After a successful patch the breeder is freshly re-read and
    required to still parse to the verified new-A credential with no
    provenance remaining.
    """
    del now
    request = inputs.request
    transaction_id = str(transaction.transaction_id)
    generation = _observed_generation(inputs, breeder)
    keys = (PROVENANCE_TRANSACTION, PROVENANCE_GENERATION, PROVENANCE_STAGE)
    present = {key: breeder.annotation(key) for key in keys}
    if all(value is None for value in present.values()):
        return
    if any(value is None for value in present.values()):
        # A partial provenance set is malformed; never delete parts of a
        # marker that is not fully recognized.
        raise VerifyAError(VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH)
    if present[PROVENANCE_TRANSACTION] != transaction_id:
        raise VerifyAError(VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH)
    if present[PROVENANCE_GENERATION] != generation.value:
        raise VerifyAError(VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH)
    if present[PROVENANCE_STAGE] != PROVENANCE_STAGE_PENDING_KEYSTONE:
        raise VerifyAError(VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH)

    patch: list[dict[str, object]] = [
        {"op": "test", "path": "/metadata/uid", "value": breeder.uid},
        {
            "op": "test", "path": "/metadata/resourceVersion",
            "value": breeder.resource_version,
        },
    ]
    for key in keys:
        patch.append(
            {"op": "remove", "path": f"/metadata/annotations/{_pointer(key)}"},
        )
    patcher = inputs.breeder_patch
    if patcher is None:
        raise VerifyAError(VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH)
    # Assert ownership immediately before crossing the external dispatch
    # boundary (the conditional patch is a Kubernetes mutation).
    _assert_owned(ownership)
    try:
        patcher.patch(breeder, patch)
    except ConditionalPatchError as error:
        if error.kind is ConditionalPatchErrorCode.CONDITIONAL_REJECTED:
            raise VerifyAError(VerifyAErrorCode.BREEDER_CONFLICT) from None
        raise VerifyAError(VerifyAErrorCode.BREEDER_UNRESOLVED) from None
    except Exception:
        raise VerifyAError(VerifyAErrorCode.BREEDER_UNRESOLVED) from None

    # Fresh read-after-write verification: the breeder still parses to the
    # verified new-A credential and no provenance remains.
    try:
        observed = inputs.breeder.read(request.breeder_reference)
    except BreederError:
        raise VerifyAError(VerifyAErrorCode.BREEDER_UNRESOLVED) from None
    if observed.uid != breeder.uid:
        raise VerifyAError(VerifyAErrorCode.BREEDER_CONFLICT)
    if CredentialGeneration.from_secret(
        _observed_credential(inputs, observed),
    ) != generation:
        raise VerifyAError(VerifyAErrorCode.A_STATE_INVALID)
    if any(observed.annotation(key) is not None for key in keys):
        raise VerifyAError(VerifyAErrorCode.BREEDER_CONFLICT)


def _observed_credential(
    inputs: VerifyAInputs, breeder: SecretSnapshot,
) -> SecretValue:
    try:
        return read_credential(
            breeder, inputs.contract.source.representation,
        ).password
    except SafeError:
        raise VerifyAError(VerifyAErrorCode.A_STATE_INVALID) from None


def _observed_generation(
    inputs: VerifyAInputs, breeder: SecretSnapshot,
) -> CredentialGeneration:
    """The generation of the exact breeder credential observed in this run.

    The A3 verification already established that the breeder's credential
    equals ``transaction.new_a_sha256``; the provenance match is checked
    against the observed value, not a stored field.
    """
    password = _observed_credential(inputs, breeder)
    try:
        return CredentialGeneration.from_secret(password)
    except ValueError:
        raise VerifyAError(VerifyAErrorCode.A_STATE_INVALID) from None


# A small JSON-pointer escaper for annotation keys (mirrors breeder.py).
def _pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


class ConditionalPatchErrorCode(Enum):
    CONDITIONAL_REJECTED = "conditional_rejected"
    OUTCOME_AMBIGUOUS = "outcome_ambiguous"
    FAILURE = "failure"


class ConditionalPatchError(Exception):
    """Value-free transport failure between a patch adapter and this phase."""

    def __init__(self, kind: ConditionalPatchErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value)


@runtime_checkable
class ConditionalBreederPatch(Protocol):
    """Narrow UID/resourceVersion-conditional JSON Patch boundary.

    ``BreederSecretClient.conditional_stage`` stages a *password* plus
    provenance; the provenance cleanup needs the same conditional JSON Patch
    discipline with annotation ``remove`` ops only and no ``data`` change.
    The direct-Kubernetes production adapter and the behavioral test fake
    both implement this boundary.  A 409/412 rejection is atomic proof the
    patch did not apply; an ambiguous outcome (5xx/timeout) requires
    reobservation.
    """

    def patch(self, expected: SecretSnapshot, patch: list[dict[str, object]]) -> None: ...


def _upsert_verification(
    transaction: RotationTransaction, *,
    check_id: str, detail_code: str, generation: CredentialGeneration,
    now: datetime,
) -> RotationTransaction:
    item = VerificationResult(
        check_id=check_id,
        phase=RotationPhase.VERIFY_A,
        status=VerificationStatus.SUCCESS,
        checked_at=now,
        detail_code=detail_code,
        target_uid=None,
        credential_generation=generation,
    )
    retained = tuple(
        value for value in transaction.verifications
        if not (value.check_id == check_id and value.phase is RotationPhase.VERIFY_A)
    )
    return replace(
        transaction, verifications=(*retained, item), updated_at=now,
    )


def _complete_transaction(
    store: StateStore, persisted: PersistedState, ownership: OwnershipGuard, *,
    now: datetime, generation: CredentialGeneration,
) -> PersistedState:
    """Persist the final, durable transaction completion (ownership-fenced).

    This is ``VERIFY_A``'s terminal write, CAS-protected from the exact
    ``PersistedState`` (revision R) on which the final state and cleanup
    verification were based: any transaction-state change after R makes the
    conditional update fail rather than be silently adopted.  Current Lease
    ownership is asserted immediately before the write; a lost owner cannot
    complete the transaction.  It records, in one document:

    - the credential-free ``verify-a-complete`` receipt (A generation only,
      ``stable-a-verified``);
    - the ``rotation-complete`` marker receipt;
    - the completed transaction status with a cleared ``last_error``;
    - the terminal ``STABLE_A`` phase;
    - the discharged lockout state (restoration observed, not required);
    - the durable ``completed_requests`` history entry.

    The transaction record is retained as durable history; it is not
    deleted.
    """
    _assert_owned(ownership)
    transaction = persisted.state.current_transaction
    assert transaction is not None
    updated = _upsert_verification(
        transaction, check_id="verify-a-complete",
        detail_code="stable-a-verified", generation=generation, now=now,
    )
    updated = _upsert_verification(
        updated, check_id="rotation-complete",
        detail_code="stable-a-finalized", generation=generation, now=now,
    )
    updated = replace(
        updated,
        phase=RotationPhase.STABLE_A,
        status=TransactionStatus.COMPLETED,
        last_error=None,
        lockout=replace(
            updated.lockout,
            restore_required=False,
            restoration=LockoutChangeState.EFFECT_OBSERVED,
        ),
        updated_at=now,
    )
    completed_entry = CompletedRequest(
        request_id=transaction.request_id,
        transaction_id=transaction.transaction_id,
        completed_at=now,
        outcome=CompletedOutcome.SUCCEEDED,
    )
    if not any(
        item.transaction_id == transaction.transaction_id
        for item in persisted.state.completed_requests
    ):
        completed_requests = persisted.state.completed_requests + (completed_entry,)
    else:
        completed_requests = persisted.state.completed_requests
    new_state = replace(
        persisted.state,
        current_transaction=updated,
        completed_requests=completed_requests,
    )
    try:
        return store.update(persisted.revision, new_state)
    except StateStoreError:
        raise VerifyAError(VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def run_verify_a(
    inputs: VerifyAInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, clock: Callable[[], datetime] = _utc_now,
) -> VerifyAResult:
    """Run or finalize the ``VERIFY_A`` runtime phase.

    The composition order is fixed:

    ```text
    validate transaction / phase / identity / environment / config
        (a transaction whose durable state already records completion
         returns ALREADY_COMPLETED without re-running any checks)
    require the phase-qualified durable predecessor evidence:
        a single SUCCESS switch-to-a-complete receipt at SWITCH_TO_A whose
        generation equals the transaction's A generation, plus the
        ROTATE_A rotate-a-complete receipt and the PREPARE_B
        stable-a / breakglass-b2 evidence
        ->
    re-stamp the durable transaction's current execution on resume
        (ownership-fenced bookkeeping, no-op when already current)
        ->
    fresh authoritative-A reconciliation (Slice 3C): require a valid A3 at
        the transaction's A generation; the breeder snapshot is the basis for
        the later provenance cleanup
        ->
    fresh per-location structural verification of every propagated
        location: identity: active locations at admin/new-A; fixed
        identity: admin locations matching the verified admin reference
        ->
    strict topology verification against the contract
        ->
    restart/workload verification: every derived action durably COMPLETE
        and every affected workload freshly observed rolled out and ready
        with the deterministic to-A restart marker
        ->
    restore the temporary lockout suppression (resumable; no-op when the
        recorded pre-rotation state is already observed)
        ->
    clean the breeder transaction provenance (no-op when already clean;
        UID/resourceVersion-conditional; fresh read-back verification)
        ->
    persist the final completion (ownership-fenced, CAS from the verified
        revision): verify-a-complete + rotation-complete receipts,
        COMPLETED status, STABLE_A phase, cleared last_error, discharged
        lockout, durable completed_requests history
    ```

    Every step observes current external state; durable progress flags are
    never accepted as proof.  On any verification failure or ambiguity the
    cleanup and completion are not performed; the only durable writes a
    failed invocation may perform are the credential-free execution
    re-stamp, the resumable lockout-restoration bookkeeping, or the breeder
    read-after-write state — the transaction remains in ``VERIFY_A`` for
    re-observation, and the admin credential is untouched.
    """
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("VERIFY_A clock must return a timezone-aware value.")
    try:
        persisted = state_store.load()
    except StateStoreError:
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    transaction = persisted.state.current_transaction
    if transaction is None:
        raise VerifyAError(VerifyAErrorCode.NO_TRANSACTION)

    request = inputs.request
    # A transaction already completed is handled deterministically: the
    # established terminal state is reported without re-running any checks
    # and without any mutation.
    if (
        transaction.status is TransactionStatus.COMPLETED
        and transaction.phase is RotationPhase.STABLE_A
    ):
        return VerifyAResult(
            outcome=VerifyAOutcome.ALREADY_COMPLETED,
            persisted=persisted,
            transaction_id=transaction.transaction_id,
            phase=transaction.phase,
            new_a_generation=transaction.new_a_sha256,
            completed=True,
        )
    if transaction.phase is not RotationPhase.VERIFY_A:
        raise VerifyAError(VerifyAErrorCode.UNSUPPORTED_PHASE)

    if persisted.state.environment != request.environment:
        raise VerifyAError(VerifyAErrorCode.ENVIRONMENT_MISMATCH)
    if transaction.keystone != request.keystone:
        raise VerifyAError(VerifyAErrorCode.CONFIGURATION_MISMATCH)
    if transaction.passwordsafe.configured_a_record_id != request.passwordsafe_a_record_id:
        raise VerifyAError(VerifyAErrorCode.CONFIGURATION_MISMATCH)
    if transaction.passwordsafe.configured_b_record_id != request.passwordsafe_b_record_id:
        raise VerifyAError(VerifyAErrorCode.CONFIGURATION_MISMATCH)
    generation = transaction.new_a_sha256
    if generation is None:
        raise VerifyAError(VerifyAErrorCode.NEW_A_GENERATION_MISSING)
    b_generation = transaction.new_b_sha256
    if b_generation is None:
        raise VerifyAError(VerifyAErrorCode.NEW_A_GENERATION_MISSING)

    # Durable predecessor evidence is mandatory.  The switch-to-a-complete
    # receipt proves the reverse cutover durably passed; the rotate-a-complete
    # receipt proves the authoritative-A convergence; the PREPARE_B
    # stable-a / breakglass-b2 receipts anchor the old-A generation, the
    # breeder UID, and the B generation.  All are validated, never synthesized.
    _switch_to_a_complete_receipt(transaction, generation=generation)
    _rotate_a_complete_receipt(transaction, generation=generation)
    _prepare_b_evidence(transaction, generation=b_generation)

    # Re-stamp the durable transaction's current execution on resume
    # (transaction-wide invariant; ownership asserted inside _restamp_execution).
    persisted = _restamp_execution(
        state_store, ownership, persisted,
        execution=request.execution, now=now,
    )
    transaction = persisted.state.current_transaction
    assert transaction is not None
    generation = transaction.new_a_sha256
    assert generation is not None

    # (1) Fresh authoritative-A reconciliation: require a valid A3 at the
    # transaction's A generation.  The breeder snapshot read here is the exact
    # object the later provenance cleanup mutates from (no silent re-adopt).
    try:
        breeder = inputs.breeder.read(request.breeder_reference)
    except BreederError:
        raise VerifyAError(VerifyAErrorCode.A_STATE_INVALID) from None
    _observe_a3_final(
        inputs, transaction, breeder=breeder,
        passwordsafe=passwordsafe, keystone=keystone, clock=clock,
    )
    a_source = _observed_credential(inputs, breeder)
    desired = DesiredCredential(Identity.ADMIN, a_source)

    # (2) Fresh breakglass reference (PasswordSafe + breakglass auth) for the
    # known-credential classification set.  The B credential is read and
    # classified only — never mutated or repaired.
    b_value = _observe_b_reference(
        inputs, expected_generation=b_generation,
        passwordsafe=passwordsafe, keystone=keystone, clock=clock,
    )
    references = ReferenceCredentials(a_source, b_value)

    # (3) Fresh namespace observation and strict topology verification.
    # Topology is verified against the full namespace listing (so an
    # uncontracted administrative-credential Secret is detected) before any
    # cleanup mutation.
    inventory, namespace_secrets, missing_secrets = _current_inventory(inputs)
    _verify_topology(inputs, secrets=namespace_secrets)

    # (3c) Fresh per-location verification of the complete applicable admin
    # membership (active + fixed-admin propagated locations).
    _verify_final_locations(
        inputs, inventory=inventory, missing_secrets=missing_secrets,
        references=references, desired=desired,
    )

    # (4) Restart/workload verification: every derived action durably
    # COMPLETE and every affected workload freshly observed rolled out and
    # ready with the deterministic to-A restart marker.
    _verify_restart_debt(inputs, transaction, now=now)

    # (5) Lockout restoration (resumable; no-op when already restored).
    # The management token is the fresh admin token from the A3 observation:
    # A3 requires the new-A credential to freshly authenticate as admin with
    # the expected scope, and lockout mutation is a legitimate admin
    # operation using that authority.
    admin_token = _admin_token(
        keystone, a_source, request=request,
    )
    persisted = _ensure_lockout_restored(
        state_store, ownership, persisted,
        keystone=keystone, token=admin_token, now=clock(),
    )
    transaction = persisted.state.current_transaction
    assert transaction is not None

    # (6) Breeder provenance cleanup (no-op when already clean).
    _clean_breeder_provenance(
        inputs, ownership=ownership,
        transaction=transaction, breeder=breeder, now=clock(),
    )

    # (7) Final durable completion, CAS-protected from the verified revision.
    final_persisted = _complete_transaction(
        state_store, persisted, ownership,
        now=clock(), generation=generation,
    )
    final_transaction = final_persisted.state.current_transaction
    assert final_transaction is not None
    return VerifyAResult(
        outcome=VerifyAOutcome.COMPLETED,
        persisted=final_persisted,
        transaction_id=final_transaction.transaction_id,
        phase=final_transaction.phase,
        new_a_generation=final_transaction.new_a_sha256,
        completed=True,
    )


def _observe_b_reference(
    inputs: VerifyAInputs, *,
    expected_generation: CredentialGeneration,
    passwordsafe: PasswordSafeClient, keystone: KeystoneClient,
    clock: Callable[[], datetime],
) -> SecretValue:
    """Freshly recover and validate the breakglass credential as the B reference.

    The B value is re-derived from PasswordSafe and its generation is required
    to equal the transaction's recorded B generation before its identity is
    re-validated by a fresh, correctly-scoped breakglass Keystone
    authentication.  It is used only as the known-credential reference that
    lets the location verification recognize a participating location that is
    (incorrectly) still on the B credential; it is never propagated, mutated,
    or repaired.
    """
    request = inputs.request
    try:
        record = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=request.passwordsafe_project_id,
            credential_id=request.passwordsafe_b_record_id,
            expected_username=request.breakglass_username,
        )
    except ExternalClientError:
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    if CredentialGeneration.from_secret(record.password) != expected_generation:
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    authentication = _authenticate(
        keystone, username=request.breakglass_username,
        password=record.password, request=request.keystone,
    )
    if isinstance(authentication, KeystoneAuthIndeterminate):
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    if not isinstance(authentication, KeystoneAuthSuccess):
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY) from None
    _validate_breakglass_auth(
        authentication.observation,
        expected_user_id=request.keystone.breakglass_user_id,
        expected_username=request.breakglass_username,
        request=request.keystone,
        now=clock(),
    )
    return record.password


def _authenticate(
    client: KeystoneClient, *, username: str, password: SecretValue,
    request: ResolvedKeystoneIdentities,
) -> KeystoneAuthSuccess | KeystoneAuthRejected | KeystoneAuthIndeterminate:
    return client.authenticate_password(KeystonePasswordAuthRequest(
        username=username,
        user_domain_id=request.user_domain_id,
        project_id=request.project_id,
        password=password,
    ))


def _validate_breakglass_auth(
    authentication: KeystoneAuthObservation, *, expected_user_id: str,
    expected_username: str, request: ResolvedKeystoneIdentities, now: datetime,
) -> None:
    valid = (
        authentication.user_id == expected_user_id
        and authentication.user_name == expected_username
        and authentication.user_domain_id == request.user_domain_id
        and authentication.project_id == request.project_id
        and authentication.project_domain_id == request.project_domain_id
        and authentication.expires_at > now
        and any(role.role_id == request.role_id for role in authentication.roles)
    )
    if not valid:
        raise VerifyAError(VerifyAErrorCode.EXTERNAL_DEPENDENCY)


def _admin_token(
    keystone: KeystoneClient, password: SecretValue, *,
    request: VerifyARequest,
) -> SecretValue:
    """Fresh admin authentication establishing management authority.

    ``VERIFY_A`` must positively observe the admin lockout-suppression
    operation's preconditions using the *current* admin authority: the
    fresh A3 observation already proved the new-A credential authenticates
    as the expected admin identity/scope; this explicit authentication
    returns the management token used for the (read-only) admin user
    observation and the lockout restoration mutation.  It fails closed when
    the new-A credential does not currently authenticate as admin.
    """
    authentication = _authenticate(
        keystone, username=request.admin_username, password=password,
        request=request.keystone,
    )
    if isinstance(authentication, KeystoneAuthIndeterminate):
        raise VerifyAError(VerifyAErrorCode.A_STATE_INDETERMINATE) from None
    if not isinstance(authentication, KeystoneAuthSuccess):
        raise VerifyAError(VerifyAErrorCode.A_STATE_INVALID) from None
    return authentication.token
