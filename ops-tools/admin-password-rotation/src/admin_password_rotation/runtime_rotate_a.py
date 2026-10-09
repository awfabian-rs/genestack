"""Slice 4G: the transaction-level ``ROTATE_A`` runtime integration.

``run_rotate_a`` composes the already-implemented bounded ``ROTATE_A``
libraries — Slice 3D A0-to-A1 breeder staging
(``run_rotate_a_stage_breeder``) and Slice 3E A1/A2/A3-to-A3 core-credential
convergence (``run_rotate_a_converge``) — into the ``ROTATE_A`` runtime phase,
gated by the ``VERIFY_B`` completion evidence.  It does not re-implement any
of the correctness-sensitive mechanics: password generation, breeder staging
and provenance, Keystone/PasswordSafe mutation, ambiguous-dispatch recovery,
A-state classification, and read-after-write verification all come from the
bounded libraries and the Slice 3C observation machinery.

Entry conditions are re-observed, not trusted from a stale ``VERIFY_B``
result.  A transaction in ``ROTATE_A`` must carry the phase-qualified durable
``verify-b-complete`` receipt (at phase ``VERIFY_B``, generation equal to the
transaction's B generation) plus the durable ``PREPARE_B`` ``stable-a`` /
``breakglass-b2`` evidence that anchors the old-A reference.  A transaction
already past ``ROTATE_A`` is reported ``ALREADY_ADVANCED`` deterministically
without re-running any machinery; predecessor phases are rejected.

The composition order is fixed:

```text
validate transaction/phase/identity/environment/config
    (a transaction already past ROTATE_A returns ALREADY_ADVANCED without
     re-running the machinery)
require the phase-qualified durable completion evidence:
    a single SUCCESS verify-b-complete receipt at VERIFY_B whose generation
    equals the transaction's B generation, plus the PREPARE_B
    stable-a/breakglass-b2 receipts that anchor the old-A reference
    ->
re-stamp the durable transaction's current execution on resume
    (ownership-fenced bookkeeping, no-op when already current)
    ->
run or resume Slice 3D staging (fresh A0 only: lockout suppression, A-new
    generation, canonical breeder staging with transaction provenance;
    resumable at A1 and safe no-op when the staging reality is already ahead)
    ->
run or resume Slice 3E convergence (A1 -> Keystone reset -> A2 ->
    PasswordSafe update -> fresh A3; never generates or re-stages)
    ->
fresh A3 re-verification: the authoritative A boundary (PasswordSafe A, the
    canonical breeder, and fresh admin Keystone authentication at the
    transaction's A generation) is freshly re-observed through the Slice 3C
    machinery; this re-observation is also what resolves progress lagging
    behind an already-converged reality
    ->
advance the durable phase to SWITCH_TO_A (ownership-fenced) with the
    credential-free rotate-a-complete receipt (A generation only) and stop
```

Re-entry is safe across every interruption boundary: a crash before, during,
or after either bounded library resumes from fresh observation; the staged
A-new generation is immutable once durably established; a fresh A3 observed
before either library ran skips both without any credential mutation.  The
temporary breakglass propagation, the transaction-scoped lockout suppression,
and the breeder rotation provenance all remain exactly as the bounded
libraries left them: ``ROTATE_A`` performs no propagated-location mutation, no
workload restart, no ``SWITCH_TO_A`` / ``VERIFY_A``, no lockout restoration,
no breeder provenance cleanup, and no transaction completion.

Durable progress flags are never authority: the bounded libraries and the
Slice 3C classifier classify from observed external state, and contradictory
progress is either reconciled from observation (a completed effect whose
progress was not yet persisted) or fails closed (a recorded step that the
fresh state proves inconsistent).
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from .a_state import (
    AReconciliationStatus, ARotationInputs, ARotationObservedState,
    observe_a_rotation_state,
)
from .breeder import BreederError, BreederReference, BreederSecretClient
from .errors import SafeError
from .model import (
    CredentialContract, CredentialGeneration, EnvironmentIdentity,
    ExecutionIdentity, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, SecretInventory, SecretValue, TransactionStatus,
    VerificationResult, VerificationStatus,
)
from .passwords import generate_admin_password
from .passwordsafe import IdentityAccess, PasswordSafeClient
from .keystone import KeystoneClient
from .prepare_b import OwnershipGuard
from .rotate_a import (
    RotateAConvergeInputs, RotateAStageInputs,
    run_rotate_a_converge, run_rotate_a_stage_breeder,
)
from .state_store import PersistedState, StateStore, StateStoreError
from .validation import is_identifier

__all__ = [
    "RotateARuntimeErrorCode", "RotateARuntimeError", "RotateARuntimeOutcome",
    "RotateARuntimeRequest", "RotateARuntimeInputs", "RotateARuntimeResult",
    "run_rotate_a",
]


class RotateARuntimeErrorCode(Enum):
    NO_TRANSACTION = "rotate_a_runtime_no_transaction"
    UNSUPPORTED_PHASE = "rotate_a_runtime_unsupported_phase"
    ENVIRONMENT_MISMATCH = "rotate_a_runtime_environment_mismatch"
    B_GENERATION_MISSING = "rotate_a_runtime_b_generation_missing"
    PREPARE_B_PREREQUISITE_MISSING = "rotate_a_runtime_prepare_b_prerequisite_missing"
    PREPARE_B_PREREQUISITE_INVALID = "rotate_a_runtime_prepare_b_prerequisite_invalid"
    VERIFY_B_PREREQUISITE_MISSING = "rotate_a_runtime_verify_b_prerequisite_missing"
    VERIFY_B_PREREQUISITE_INVALID = "rotate_a_runtime_verify_b_prerequisite_invalid"
    CONFIGURATION_MISMATCH = "rotate_a_runtime_configuration_mismatch"
    STAGING_FAILED = "rotate_a_runtime_staging_failed"
    CONVERGENCE_FAILED = "rotate_a_runtime_convergence_failed"
    FINAL_STATE_INVALID = "rotate_a_runtime_final_state_invalid"
    FINAL_STATE_INDETERMINATE = "rotate_a_runtime_final_state_indeterminate"
    PROGRESS_PERSISTENCE_FAILED = "rotate_a_runtime_progress_persistence_failed"
    EXTERNAL_DEPENDENCY = "rotate_a_runtime_external_dependency"


_ERROR_MESSAGES: dict[RotateARuntimeErrorCode, str] = {
    RotateARuntimeErrorCode.NO_TRANSACTION:
        "There is no current transaction to advance through ROTATE_A.",
    RotateARuntimeErrorCode.UNSUPPORTED_PHASE:
        "The current transaction is not in the ROTATE_A phase.",
    RotateARuntimeErrorCode.ENVIRONMENT_MISMATCH:
        "The supplied environment does not match the transaction environment.",
    RotateARuntimeErrorCode.B_GENERATION_MISSING:
        "The transaction has no established breakglass credential generation.",
    RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_MISSING:
        "A required durable PREPARE_B completion record is absent; ROTATE_A cannot begin.",
    RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_INVALID:
        "A required durable PREPARE_B completion record is malformed or contradictory.",
    RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_MISSING:
        "The durable verify-b-complete receipt is absent; the B safety bridge has not durably been verified.",
    RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_INVALID:
        "The durable verify-b-complete receipt is malformed or contradictory.",
    RotateARuntimeErrorCode.CONFIGURATION_MISMATCH:
        "The transaction identity or configuration does not match the request.",
    RotateARuntimeErrorCode.STAGING_FAILED:
        "The bounded Slice 3D ROTATE_A staging capability could not be completed safely.",
    RotateARuntimeErrorCode.CONVERGENCE_FAILED:
        "The bounded Slice 3E ROTATE_A convergence capability could not be completed safely.",
    RotateARuntimeErrorCode.FINAL_STATE_INVALID:
        "The authoritative A state is not freshly observed at A3.",
    RotateARuntimeErrorCode.FINAL_STATE_INDETERMINATE:
        "The authoritative A state could not be freshly classified.",
    RotateARuntimeErrorCode.PROGRESS_PERSISTENCE_FAILED:
        "Durable ROTATE_A progress could not be persisted safely.",
    RotateARuntimeErrorCode.EXTERNAL_DEPENDENCY:
        "An external credential-system or Kubernetes dependency is unavailable; ROTATE_A does not proceed.",
}


class RotateARuntimeError(SafeError):
    """A value-free, stable ``ROTATE_A`` runtime integration failure."""

    def __init__(self, kind: RotateARuntimeErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class RotateARuntimeOutcome(Enum):
    """Typed result vocabulary for one ``ROTATE_A`` invocation.

    ``CONVERGED`` is set only when the fresh final observation established
    A3 and the phase advanced to ``SWITCH_TO_A`` in this invocation.
    ``ALREADY_ADVANCED`` is the deterministic idempotency result for a
    transaction already past ``ROTATE_A``.  Failures raise
    ``RotateARuntimeError`` (the bounded libraries' own errors are re-raised
    unchanged) and leave the transaction resumable in ``ROTATE_A``.
    """

    CONVERGED = "converged"
    ALREADY_ADVANCED = "already_advanced"


@dataclass(frozen=True)
class RotateARuntimeRequest:
    """Caller-supplied identity/configuration to validate against the transaction.

    Mirrors the ``VERIFY_B`` resume validation: a re-execution must prove it is
    operating on the same environment and Keystone/PasswordSafe identity before
    any correctness-sensitive effect.
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
class RotateARuntimeInputs:
    request: RotateARuntimeRequest
    contract: CredentialContract
    passwordsafe_access: IdentityAccess
    breeder: BreederSecretClient
    password_generator: Callable[[], "SecretValue"] = generate_admin_password

    def __post_init__(self) -> None:
        if (
            self.contract.namespace != self.request.breeder_reference.namespace
            or self.contract.source.secret != self.request.breeder_reference.name
        ):
            raise ValueError("The breeder reference must identify the contract source.")


@dataclass(frozen=True)
class RotateARuntimeResult:
    """Credential-free outcome of one ``ROTATE_A`` invocation.

    ``converged`` is true only for the ``CONVERGED`` outcome.  The
    transaction identifier, phase, and A generation name the resulting durable
    state; no credential value, token, or raw external content appears in this
    result.
    """

    outcome: RotateARuntimeOutcome
    persisted: PersistedState
    transaction_id: object
    phase: RotationPhase
    new_a_generation: CredentialGeneration | None = None
    converged: bool = False

    def __repr__(self) -> str:
        return (
            f"RotateARuntimeResult(outcome={self.outcome.value!r}, "
            f"phase={self.phase.value!r})"
        )

    __str__ = __repr__


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


Clock = Callable[[], datetime]


def _assert_owned(ownership: OwnershipGuard) -> None:
    """Assert current Lease ownership in this slice's error vocabulary.

    Every correctness-sensitive durable write performed by this slice (the
    execution re-stamp and the phase advance) is preceded by this assertion;
    the bounded libraries perform their own ownership assertions around their
    own mutation boundaries.  Ownership loss surfaces as
    ``PROGRESS_PERSISTENCE_FAILED`` (this slice's category), never as a
    foreign slice's error type.
    """
    try:
        ownership.assert_owned()
    except SafeError:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PROGRESS_PERSISTENCE_FAILED,
        ) from None


def _single_verification(
    transaction: RotationTransaction, *, check_id: str, phase: RotationPhase,
) -> VerificationResult:
    """Return the one receipt matching ``(check_id, phase)``, failing closed.

    A receipt is accepted only if it matches on both ``check_id`` and
    ``phase``: a same-named receipt originating from another phase is not this
    evidence and is treated as missing.  Zero matching receipts is a missing
    prerequisite; more than one matching receipt is an ambiguous record.  The
    receipts are *validated*, never synthesized.
    """
    matches = tuple(
        item for item in transaction.verifications
        if item.check_id == check_id and item.phase is phase
    )
    if len(matches) == 0:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_MISSING
            if phase is RotationPhase.PREPARE_B
            else RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_MISSING,
        )
    if len(matches) > 1:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_INVALID
            if phase is RotationPhase.PREPARE_B
            else RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_INVALID,
        )
    return matches[0]


def _verify_b_evidence(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> VerificationResult:
    """Require the phase-qualified durable ``VERIFY_B`` completion receipt.

    ``VERIFY_B`` records exactly one ``verify-b-complete`` receipt at phase
    ``VERIFY_B`` carrying the B generation when it advances the phase to
    ``ROTATE_A``.  A transaction in ``ROTATE_A`` without it has not durably
    passed the B safety-bridge gate, and a same-named receipt from another
    phase is not that evidence.  The receipt is *validated*, never
    synthesized.
    """
    receipt = _single_verification(
        transaction, check_id="verify-b-complete", phase=RotationPhase.VERIFY_B,
    )
    if receipt.status is not VerificationStatus.SUCCESS:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_INVALID,
        )
    if receipt.credential_generation != generation:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_INVALID,
        )
    return receipt


def _prepare_b_evidence(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> tuple[VerificationResult, VerificationResult]:
    """Require the durable ``PREPARE_B`` completion evidence.

    Successful ``PREPARE_B`` leaves exactly two durable receipts, each
    explicitly at phase ``PREPARE_B``: ``stable-a`` (old-A generation plus the
    breeder UID it verified — the anchor for all old-A and breeder-identity
    checks in the A0-A3 machinery) and ``breakglass-b2`` (B generation).  Both
    are mandatory and must be ``SUCCESS``; missing, wrong-phase, non-success,
    malformed, or generation-inconsistent evidence fails closed before any
    observation, mutation, or phase work.
    """
    stable_a = _single_verification(
        transaction, check_id="stable-a", phase=RotationPhase.PREPARE_B,
    )
    if stable_a.status is not VerificationStatus.SUCCESS:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_INVALID,
        )
    b2 = _single_verification(
        transaction, check_id="breakglass-b2", phase=RotationPhase.PREPARE_B,
    )
    if b2.status is not VerificationStatus.SUCCESS:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_INVALID,
        )
    if stable_a.credential_generation is None or stable_a.target_uid is None:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_INVALID,
        )
    if b2.credential_generation is None:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_INVALID,
        )
    if b2.credential_generation != generation:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_INVALID,
        )
    return stable_a, b2


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
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PROGRESS_PERSISTENCE_FAILED,
        ) from None


def _stage_inputs(inputs: RotateARuntimeInputs) -> RotateAStageInputs:
    request = inputs.request
    return RotateAStageInputs(
        request.environment,
        inputs.contract,
        inputs.passwordsafe_access,
        request.passwordsafe_project_id,
        admin_username=request.admin_username,
        breakglass_username=request.breakglass_username,
        project_name=request.project_name,
        breeder_reference=request.breeder_reference,
    )


def _converge_inputs(inputs: RotateARuntimeInputs) -> RotateAConvergeInputs:
    request = inputs.request
    return RotateAConvergeInputs(
        request.environment,
        inputs.contract,
        inputs.passwordsafe_access,
        request.passwordsafe_project_id,
        admin_username=request.admin_username,
        breakglass_username=request.breakglass_username,
        project_name=request.project_name,
        breeder_reference=request.breeder_reference,
    )


def _observe_final_a3(
    inputs: RotateARuntimeInputs, transaction: RotationTransaction, *,
    passwordsafe: PasswordSafeClient, keystone: KeystoneClient, clock: Clock,
) -> None:
    """Freshly observe and classify the authoritative A boundary; require A3.

    This is the runtime slice's completion verification: it re-reads the
    canonical breeder, the PasswordSafe A record, and the fresh admin
    Keystone authentication directly through the Slice 3C observation
    machinery and requires the result to be a valid, freshly observed A3.
    It performs no mutation and writes no progress; it only proves that the
    A0-A3 machinery — which the bounded libraries already brought to A3 —
    still observes the authoritative triplet at the transaction's A
    generation in this invocation.  Any invalid, indeterminate, or
    non-A3 classification fails closed before the phase advances.
    """
    request = inputs.request
    try:
        snapshot = inputs.breeder.read(request.breeder_reference)
    except BreederError:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.FINAL_STATE_INVALID,
        ) from None
    result = observe_a_rotation_state(
        ARotationInputs(
            transaction=transaction,
            contract=inputs.contract,
            inventory=SecretInventory(
                snapshot.namespace, snapshot.resource_version, (snapshot,),
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
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.FINAL_STATE_INDETERMINATE,
        )
    if (
        result.status is not AReconciliationStatus.VALID
        or result.state is not ARotationObservedState.A3
    ):
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.FINAL_STATE_INVALID,
        )


def _upsert_rotate_a_complete(
    transaction: RotationTransaction, *, checked_at: datetime,
    generation: CredentialGeneration,
) -> RotationTransaction:
    item = VerificationResult(
        check_id="rotate-a-complete",
        phase=RotationPhase.ROTATE_A,
        status=VerificationStatus.SUCCESS,
        checked_at=checked_at,
        detail_code="authoritative-a-converged",
        target_uid=None,
        credential_generation=generation,
    )
    retained = tuple(
        value for value in transaction.verifications
        if not (
            value.check_id == "rotate-a-complete"
            and value.phase is RotationPhase.ROTATE_A
        )
    )
    return replace(
        transaction, verifications=(*retained, item), updated_at=checked_at,
    )


def _advance_to_switch_to_a(
    store: StateStore, persisted: PersistedState, ownership: OwnershipGuard, *,
    now: datetime, generation: CredentialGeneration,
) -> PersistedState:
    """Advance the durable phase to ``SWITCH_TO_A`` (ownership-fenced) and stop.

    This is ``ROTATE_A``'s only *semantic* completion write: the phase advance
    plus a credential-free verification receipt (carrying only the A
    generation) recording that the authoritative A boundary was freshly
    observed at A3.  It is distinct from the ownership-fenced execution
    bookkeeping re-stamp a resume/takeover may persist earlier — bookkeeping,
    not semantic completion.  The supplied ``persisted`` is the CAS basis: it
    is the exact ``PersistedState`` (revision R) on which the fresh A3
    verification was based, so any transaction-state change after R makes the
    conditional update fail instead of being silently adopted.  Current Lease
    ownership is asserted immediately before the write; a lost owner cannot
    advance the transaction.
    """
    _assert_owned(ownership)
    transaction = persisted.state.current_transaction
    assert transaction is not None
    updated = _upsert_rotate_a_complete(
        transaction, checked_at=now, generation=generation,
    )
    updated = replace(
        updated,
        phase=RotationPhase.SWITCH_TO_A,
        status=TransactionStatus.ACTIVE,
        last_error=None,
        updated_at=now,
    )
    try:
        return store.update(
            persisted.revision,
            replace(persisted.state, current_transaction=updated),
        )
    except StateStoreError:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.PROGRESS_PERSISTENCE_FAILED,
        ) from None


def run_rotate_a(
    inputs: RotateARuntimeInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, clock: Callable[[], datetime] = _utc_now,
) -> RotateARuntimeResult:
    """Run or resume the ``ROTATE_A`` runtime phase.

    See the module docstring for the full composition order.  The bounded
    Slice 3D/3E libraries own every credential mutation and its recovery
    semantics; this function adds the runtime-phase boundary: predecessor
    evidence validation, execution re-stamping, safe re-entry across both
    libraries' interruption points, the fresh final A3 re-verification, and
    the ownership-fenced phase advance to ``SWITCH_TO_A`` with the
    credential-free ``rotate-a-complete`` receipt.
    """
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("ROTATE_A runtime clock must return a timezone-aware value.")
    try:
        persisted = state_store.load()
    except StateStoreError:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.EXTERNAL_DEPENDENCY,
        ) from None
    transaction = persisted.state.current_transaction
    if transaction is None:
        raise RotateARuntimeError(RotateARuntimeErrorCode.NO_TRANSACTION)

    request = inputs.request
    # A transaction already past ROTATE_A is handled deterministically: only
    # genuine successor phases (SWITCH_TO_A, VERIFY_A) report
    # ALREADY_ADVANCED without re-running any machinery or regressing the
    # phase.  A predecessor phase (STABLE_A, PREPARE_B, SWITCH_TO_B, VERIFY_B)
    # is not this phase's entry state: the B bridge has not durably been
    # established into ROTATE_A, so it is rejected rather than partially run.
    if transaction.phase is not RotationPhase.ROTATE_A:
        if transaction.phase in (
            RotationPhase.SWITCH_TO_A,
            RotationPhase.VERIFY_A,
        ):
            return RotateARuntimeResult(
                outcome=RotateARuntimeOutcome.ALREADY_ADVANCED,
                persisted=persisted,
                transaction_id=transaction.transaction_id,
                phase=transaction.phase,
            )
        raise RotateARuntimeError(RotateARuntimeErrorCode.UNSUPPORTED_PHASE)

    if persisted.state.environment != request.environment:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.ENVIRONMENT_MISMATCH,
        )
    if transaction.keystone != request.keystone:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.CONFIGURATION_MISMATCH,
        )
    if transaction.passwordsafe.configured_a_record_id != request.passwordsafe_a_record_id:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.CONFIGURATION_MISMATCH,
        )
    if transaction.passwordsafe.configured_b_record_id != request.passwordsafe_b_record_id:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.CONFIGURATION_MISMATCH,
        )
    generation = transaction.new_b_sha256
    if generation is None:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.B_GENERATION_MISSING,
        )

    # Durable predecessor evidence is mandatory.  The verify-b-complete
    # receipt proves the B safety bridge durably passed the gate, and the
    # PREPARE_B stable-a receipt anchors the old-A generation and breeder UID
    # that the A0-A3 machinery validates against.  Both are validated, never
    # synthesized.
    _verify_b_evidence(transaction, generation=generation)
    _prepare_b_evidence(transaction, generation=generation)

    # Re-stamp the durable transaction's current execution on resume
    # (transaction-wide invariant from the SWITCH_TO_B/VERIFY_B pass; the
    # ownership assertion inside _restamp_execution precedes the write).
    persisted = _restamp_execution(
        state_store, ownership, persisted,
        execution=request.execution, now=now,
    )
    transaction = persisted.state.current_transaction
    assert transaction is not None

    # (1) Run or resume the bounded Slice 3D staging capability.  Starting
    # from fresh A0 this establishes the transaction-scoped lockout
    # suppression, generates and durably identifies A-new, and stages the
    # canonical breeder with transaction provenance; a fresh A1 or an
    # already-ahead reality resumes without re-staging, and the generation is
    # immutable once durably established.  A bounded-library failure leaves
    # the transaction blocked in ROTATE_A for re-observation and is re-raised
    # unchanged so operators see the library's own typed category.
    stage_result = run_rotate_a_stage_breeder(
        _stage_inputs(inputs),
        state_store=state_store,
        ownership=ownership,
        passwordsafe=passwordsafe,
        keystone=keystone,
        breeder=inputs.breeder,
        password_generator=inputs.password_generator,
        clock=clock,
    )
    persisted = stage_result.persisted
    transaction = persisted.state.current_transaction
    assert transaction is not None

    # (2) Run or resume the bounded Slice 3E convergence capability.  A1
    # resets the recorded admin user to the exact staged A-new and requires
    # fresh A2; A2 updates the PasswordSafe admin record and requires fresh
    # A3; a fresh A3 performs neither A mutation.  Its own recovery semantics
    # own ambiguous-dispatch and definite-rejection handling.
    converge_result = run_rotate_a_converge(
        _converge_inputs(inputs),
        state_store=state_store,
        ownership=ownership,
        passwordsafe=passwordsafe,
        keystone=keystone,
        breeder=inputs.breeder,
        clock=clock,
    )
    persisted = converge_result.persisted
    transaction = persisted.state.current_transaction
    assert transaction is not None

    # (3) Fresh A3 re-verification: the authoritative A boundary is
    # re-observed and reclassified directly through the Slice 3C machinery
    # (fresh breeder read, fresh PasswordSafe A read, fresh admin Keystone
    # authentication), so the completion decision rests on this invocation's
    # own observation rather than on a bounded library's final observation.
    # Classification is from observed state, not from durable progress flags:
    # a record whose progress lags an already-converged reality classifies
    # from reality, and progress contradicting reality is a bounded-library
    # failure, not a shortcut to completion.
    _observe_final_a3(
        inputs, transaction, passwordsafe=passwordsafe, keystone=keystone,
        clock=clock,
    )
    # The A3 verification above was based on the exact transaction and
    # PersistedState returned by the bounded convergence (revision R).  The
    # final phase advance must CAS from that same revision R, not from a
    # fresh load: any transaction-state mutation after R (including a
    # concurrent actor or an operator edit) must cause the advance's
    # state-store update to fail rather than be silently adopted.  The
    # generation to record is the one that transaction carried at the time
    # of verification.
    final_generation = transaction.new_a_sha256
    if final_generation is None:
        raise RotateARuntimeError(
            RotateARuntimeErrorCode.FINAL_STATE_INVALID,
        )

    # (4) Advance the durable phase to SWITCH_TO_A (ownership-fenced) with
    # the credential-free completion receipt and stop.  The CAS basis is the
    # same revision R on which A3 was verified.  No SWITCH_TO_A work is
    # performed here.
    final_persisted = _advance_to_switch_to_a(
        state_store, persisted, ownership,
        now=clock(), generation=final_generation,
    )
    final_transaction = final_persisted.state.current_transaction
    assert final_transaction is not None
    return RotateARuntimeResult(
        outcome=RotateARuntimeOutcome.CONVERGED,
        persisted=final_persisted,
        transaction_id=final_transaction.transaction_id,
        phase=final_transaction.phase,
        new_a_generation=final_transaction.new_a_sha256,
        converged=True,
    )
