"""Slice 4E: transaction-level ``SWITCH_TO_B`` orchestration.

This module composes the already-implemented Slice 4B propagation-wave
planning/reconciliation, Slice 4C grouped Secret-level propagation execution,
and Slice 4D restart/action execution into the ``SWITCH_TO_B`` runtime phase.
It moves a transaction that has completed ``PREPARE_B`` through the temporary
cutover of every contracted ``identity: active`` credential location to the
verified/staged ``breakglass`` credential, executes the runtime restart actions
caused by the locations that actually changed, and advances the durable phase to
``VERIFY_B``.

It does **not** implement ``VERIFY_B``: it performs no service/authentication
health verification of the B safety bridge, and it stops immediately after the
phase advance.  It does **not** generate or stage a B credential (that is
``PREPARE_B``); it recovers the authoritative B credential from PasswordSafe,
the same mechanism ``PREPARE_B`` uses for ``B1`` recovery.

Re-entry is safe: every interruption boundary (no intent yet, intent persisted
but no propagation, partial propagation, propagation complete with restart debt
pending, restart actions running, all actions complete but phase not yet
advanced) is recovered by observing the durable wave intent, applied-location
progress, and runtime-action state, then continuing the existing transaction.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from .errors import SafeError
from .external_http import ExternalClientError
from .keystone import (
    KeystoneAuthIndeterminate, KeystoneAuthObservation, KeystoneAuthRejected,
    KeystoneAuthSuccess, KeystoneClient, KeystonePasswordAuthRequest,
)
from .model import (
    CredentialContract, CredentialGeneration, EnvironmentIdentity, ExecutionIdentity,
    Identity, ReferenceCredentials, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, RuntimeActionState, SecretInventory, SecretSnapshot,
    SecretValue, TransactionStatus, VerificationResult, VerificationStatus,
)
from .passwordsafe import IdentityAccess, PasswordSafeClient
from .prepare_b import OwnershipGuard
from .propagation import (
    CredentialSecretClient, CredentialSecretClientError, DesiredCredential,
    GroupedPropagationSession,
    execute_grouped_propagation_wave,
)
from .propagation_wave import (
    PropagationWaveError, PropagationWaveErrorCode,
    PropagationWavePlanningResult, persist_propagation_wave_intent,
    plan_or_reconcile_propagation_wave, reconcile_propagation_wave,
)
from .representations import read_credential
from .restart import WorkloadClient, execute_restart_debt
from .state_store import PersistedState, StateStore, StateStoreError
from .validation import is_identifier


class SwitchToBErrorCode(Enum):
    NO_TRANSACTION = "switch_to_b_no_transaction"
    UNSUPPORTED_PHASE = "switch_to_b_unsupported_phase"
    ENVIRONMENT_MISMATCH = "switch_to_b_environment_mismatch"
    B_GENERATION_MISSING = "switch_to_b_b_generation_missing"
    PREPARE_B_PREREQUISITE_MISSING = "switch_to_b_prepare_b_prerequisite_missing"
    PREPARE_B_PREREQUISITE_INVALID = "switch_to_b_prepare_b_prerequisite_invalid"
    CONFIGURATION_MISMATCH = "switch_to_b_configuration_mismatch"
    B_CREDENTIAL_UNRESOLVED = "switch_to_b_b_credential_unresolved"
    B_IDENTITY_MISMATCH = "switch_to_b_b_identity_mismatch"
    B_AUTH_INDETERMINATE = "switch_to_b_b_auth_indeterminate"
    ADMIN_REFERENCE_INVALID = "switch_to_b_admin_reference_invalid"
    CONTRACT_DRIFT = "switch_to_b_contract_drift"
    PROGRESS_PERSISTENCE_FAILED = "switch_to_b_progress_persistence_failed"
    EXTERNAL_DEPENDENCY = "switch_to_b_external_dependency"


_ERROR_MESSAGES: dict[SwitchToBErrorCode, str] = {
    SwitchToBErrorCode.NO_TRANSACTION:
        "There is no current transaction to advance through SWITCH_TO_B.",
    SwitchToBErrorCode.UNSUPPORTED_PHASE:
        "The current transaction is not in the SWITCH_TO_B phase.",
    SwitchToBErrorCode.ENVIRONMENT_MISMATCH:
        "The supplied environment does not match the transaction environment.",
    SwitchToBErrorCode.B_GENERATION_MISSING:
        "The transaction has no established breakglass credential generation.",
    SwitchToBErrorCode.PREPARE_B_PREREQUISITE_MISSING:
        "A required durable PREPARE_B completion record is absent; the transaction cannot be resumed.",
    SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID:
        "A required durable PREPARE_B completion record is malformed or contradictory.",
    SwitchToBErrorCode.CONFIGURATION_MISMATCH:
        "The transaction identity or configuration does not match the request.",
    SwitchToBErrorCode.B_CREDENTIAL_UNRESOLVED:
        "The breakglass credential could not be freshly obtained and verified.",
    SwitchToBErrorCode.B_IDENTITY_MISMATCH:
        "Fresh breakglass authentication does not match the recorded identity.",
    SwitchToBErrorCode.B_AUTH_INDETERMINATE:
        "Fresh breakglass authentication was indeterminate; no cutover is attempted.",
    SwitchToBErrorCode.ADMIN_REFERENCE_INVALID:
        "The canonical admin breeder credential could not be freshly observed.",
    SwitchToBErrorCode.CONTRACT_DRIFT:
        "The credential contract does not match the durable propagation obligation.",
    SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED:
        "Durable SWITCH_TO_B progress could not be persisted safely.",
    SwitchToBErrorCode.EXTERNAL_DEPENDENCY:
        "An external credential-system dependency is unavailable; no cutover is attempted.",
}


class SwitchToBError(SafeError):
    """A value-free, stable ``SWITCH_TO_B`` orchestration failure."""

    def __init__(self, kind: SwitchToBErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


@dataclass(frozen=True)
class SwitchToBRequest:
    """Caller-supplied identity/configuration to validate against the transaction.

    This mirrors the ``PREPARE_B`` resume validation: a re-execution must prove
    it is operating on the same environment and Keystone/PasswordSafe identity
    before any correctness-sensitive effect.
    """

    environment: EnvironmentIdentity
    keystone: ResolvedKeystoneIdentities
    passwordsafe_project_id: int
    passwordsafe_b_record_id: int
    execution: ExecutionIdentity
    breakglass_username: str = "breakglass"

    def __post_init__(self) -> None:
        if (
            isinstance(self.passwordsafe_project_id, bool)
            or self.passwordsafe_project_id <= 0
        ):
            raise ValueError("PasswordSafe project ID must be a positive integer.")
        if (
            isinstance(self.passwordsafe_b_record_id, bool)
            or self.passwordsafe_b_record_id <= 0
        ):
            raise ValueError("PasswordSafe breakglass record ID must be a positive integer.")
        if not is_identifier(self.breakglass_username):
            raise ValueError("Breakglass username must be a valid nonempty identifier.")


@dataclass(frozen=True)
class SwitchToBInputs:
    request: SwitchToBRequest
    contract: CredentialContract
    passwordsafe_access: IdentityAccess
    secret_client: CredentialSecretClient
    workload_client: WorkloadClient


@dataclass(frozen=True)
class SwitchToBResult:
    persisted: PersistedState
    propagated_locations: tuple[str, ...]
    restarted_actions: tuple[str, ...]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _assert_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise SwitchToBError(SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


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
        raise SwitchToBError(SwitchToBErrorCode.B_IDENTITY_MISMATCH)


def _single_verification(
    transaction: RotationTransaction, *, check_id: str, phase: RotationPhase,
) -> VerificationResult:
    """Return the one receipt matching ``(check_id, phase)``, failing closed.

    PREPARE_B upserts one receipt per ``(check_id, phase)`` pair, so a successful
    PREPARE_B leaves exactly one receipt for each required pair.  A receipt is
    accepted only if it matches on both ``check_id`` and ``phase``: a same-named
    receipt originating from another phase is not PREPARE_B evidence and is
    treated as missing.  Zero matching receipts is a missing prerequisite
    (``PREPARE_B_PREREQUISITE_MISSING``); more than one matching receipt is an
    ambiguous/contradictory record (``PREPARE_B_PREREQUISITE_INVALID``).
    """
    matches = tuple(
        item for item in transaction.verifications
        if item.check_id == check_id and item.phase is phase
    )
    if len(matches) == 0:
        raise SwitchToBError(SwitchToBErrorCode.PREPARE_B_PREREQUISITE_MISSING)
    if len(matches) > 1:
        raise SwitchToBError(SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    return matches[0]


def _verify_prepare_b_evidence(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> tuple[VerificationResult, VerificationResult]:
    """Require the durable PREPARE_B completion evidence before any SWITCH_TO_B work.

    Successful PREPARE_B leaves exactly two durable receipts, each explicitly at
    phase ``PREPARE_B``: ``stable-a`` (old-A generation plus the breeder UID it
    verified) and ``breakglass-b2`` (B generation).  Both are mandatory and must
    be ``SUCCESS``; this function returns them so the caller can re-validate them
    against fresh observation.  A missing, wrong-phase, non-success, malformed,
    or generation-inconsistent receipt fails closed.
    """
    stable_a = _single_verification(
        transaction, check_id="stable-a", phase=RotationPhase.PREPARE_B,
    )
    if stable_a.status is not VerificationStatus.SUCCESS:
        raise SwitchToBError(SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    b2 = _single_verification(
        transaction, check_id="breakglass-b2", phase=RotationPhase.PREPARE_B,
    )
    if b2.status is not VerificationStatus.SUCCESS:
        raise SwitchToBError(SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if stable_a.credential_generation is None or stable_a.target_uid is None:
        raise SwitchToBError(SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation is None:
        raise SwitchToBError(SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation != generation:
        raise SwitchToBError(SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    return stable_a, b2


def _restamp_execution(
    store: StateStore, ownership: OwnershipGuard, persisted: PersistedState, *,
    execution: ExecutionIdentity, now: datetime,
) -> PersistedState:
    """Re-stamp the durable transaction's current execution on resume.

    ``transaction.execution`` records the execution currently operating/resuming
    the transaction.  It is informational/recovery bookkeeping, **not** the
    fencing mechanism: current Lease ownership (``OwnershipGuard.assert_owned``)
    is the authoritative source of mutation permission, and the Lease remains
    authoritative.  A durable update to transaction state is itself a mutation,
    so current Lease ownership is asserted **before** this write; a stale
    execution that has lost the Lease cannot modify the durable transaction even
    for a bookkeeping-only change.  The state-store write is additionally
    CAS-protected by the revision.  On a legitimate takeover by a new owner the
    field is updated to the owner's ``ExecutionIdentity`` before subsequent
    mutating phase work.
    """
    if transaction_is_up_to_date(persisted, execution):
        return persisted
    _assert_owned(ownership)
    transaction = persisted.state.current_transaction
    assert transaction is not None
    updated = replace(transaction, execution=execution, updated_at=now)
    try:
        return store.update(
            persisted.revision,
            replace(persisted.state, current_transaction=updated),
        )
    except StateStoreError:
        raise SwitchToBError(SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def transaction_is_up_to_date(
    persisted: PersistedState, execution: ExecutionIdentity,
) -> bool:
    transaction = persisted.state.current_transaction
    return transaction is not None and transaction.execution == execution


def _upsert_switch_to_b_complete(
    transaction: RotationTransaction, *, checked_at: datetime,
    generation: CredentialGeneration,
) -> RotationTransaction:
    item = VerificationResult(
        check_id="switch-to-b-complete",
        phase=RotationPhase.SWITCH_TO_B,
        status=VerificationStatus.SUCCESS,
        checked_at=checked_at,
        detail_code="propagated-and-restarted",
        target_uid=None,
        credential_generation=generation,
    )
    retained = tuple(
        value for value in transaction.verifications
        if not (
            value.check_id == "switch-to-b-complete"
            and value.phase is RotationPhase.SWITCH_TO_B
        )
    )
    return replace(
        transaction, verifications=(*retained, item), updated_at=checked_at,
    )


def _map_propagation_error(error: PropagationWaveError) -> SwitchToBError:
    """Map a Slice 4B wave error to a stable SWITCH_TO_B failure category.

    Contract/intent drift (including membership, identity, or digest changes)
    is ``CONTRACT_DRIFT``; unknown, unparseable, or missing observed state is
    ``EXTERNAL_DEPENDENCY``; ownership loss during intent persistence is
    ``PROGRESS_PERSISTENCE_FAILED``.
    """
    if error.kind in (
        PropagationWaveErrorCode.IMMUTABLE_INTENT_CONFLICT,
        PropagationWaveErrorCode.LEGACY_PROGRESS_WITHOUT_INTENT,
        PropagationWaveErrorCode.TARGET_GENERATION_MISMATCH,
        PropagationWaveErrorCode.TRANSACTION_GENERATION_MISMATCH,
        PropagationWaveErrorCode.NO_APPLICABLE_LOCATIONS,
    ):
        return SwitchToBError(SwitchToBErrorCode.CONTRACT_DRIFT)
    if error.kind is PropagationWaveErrorCode.OWNERSHIP_LOST:
        return SwitchToBError(SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED)
    return SwitchToBError(SwitchToBErrorCode.EXTERNAL_DEPENDENCY)


def _current_inventory(inputs: SwitchToBInputs) -> SecretInventory:
    """Re-read every contracted Secret through the supplied client.

    The planning/reconciliation functions take an inventory for their up-front
    namespace and membership checks, and the grouped executor reads each Secret
    individually.  Building the inventory through the same client keeps both
    views on the same current reality.
    """
    contract = inputs.contract
    names = {location.secret for location in contract.locations}
    secrets: list[SecretSnapshot] = []
    for name in sorted(names):
        try:
            secrets.append(inputs.secret_client.read(contract.namespace, name))
        except CredentialSecretClientError:
            raise SwitchToBError(SwitchToBErrorCode.EXTERNAL_DEPENDENCY) from None
    return SecretInventory(contract.namespace, None, tuple(secrets))


def _observe_admin_reference(
    inputs: SwitchToBInputs, *, stable_a: VerificationResult,
) -> SecretValue:
    """Freshly read and validate the canonical admin breeder as the A reference.

    For ``SWITCH_TO_B`` the only comparison reference that matters for the active
    locations is the admin credential, read structurally from the canonical
    breeder Secret.  The fresh observation must agree with the durable
    ``stable-a`` receipt from ``PREPARE_B``: the breeder must still match the
    recorded stable-A generation and the breeder Secret UID that ``PREPARE_B``
    verified.  A changed or regenerated breeder fails closed, because the
    propagation reference would then be wrong.  This re-read does not synthesize
    missing evidence; it cross-checks fresh reality against the durable record.
    """
    source = inputs.contract.source
    try:
        snapshot = inputs.secret_client.read(inputs.contract.namespace, source.secret)
    except CredentialSecretClientError:
        raise SwitchToBError(SwitchToBErrorCode.ADMIN_REFERENCE_INVALID) from None
    try:
        observed = read_credential(snapshot, source.representation)
    except SafeError:
        raise SwitchToBError(SwitchToBErrorCode.ADMIN_REFERENCE_INVALID) from None
    stable_generation = stable_a.credential_generation
    stable_uid = stable_a.target_uid
    assert stable_generation is not None and stable_uid is not None
    if CredentialGeneration.from_secret(observed.password) != stable_generation:
        raise SwitchToBError(SwitchToBErrorCode.ADMIN_REFERENCE_INVALID)
    if snapshot.uid != stable_uid:
        raise SwitchToBError(SwitchToBErrorCode.ADMIN_REFERENCE_INVALID)
    return observed.password


def _persist_intent(
    store: StateStore, ownership: OwnershipGuard, persisted: PersistedState,
    planned: PropagationWavePlanningResult, *, now: datetime,
) -> PersistedState:
    try:
        return persist_propagation_wave_intent(
            store, ownership, persisted, planned, recorded_at=now,
        )
    except PropagationWaveError:
        raise SwitchToBError(SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def _advance_to_verify_b(
    store: StateStore, persisted: PersistedState, ownership: OwnershipGuard, *,
    now: datetime, generation: CredentialGeneration,
) -> PersistedState:
    """Advance the durable phase to ``VERIFY_B`` (ownership-fenced) and stop.

    This is the ``SWITCH_TO_B`` completion boundary: it persists only the phase
    advance and a credential-free verification receipt.  It performs no
    ``VERIFY_B`` service/authentication/health verification.
    """
    _assert_owned(ownership)
    transaction = persisted.state.current_transaction
    assert transaction is not None
    updated = _upsert_switch_to_b_complete(
        transaction, checked_at=now, generation=generation,
    )
    updated = replace(
        updated,
        phase=RotationPhase.VERIFY_B,
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
        raise SwitchToBError(SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def run_switch_to_b(
    inputs: SwitchToBInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, clock: Callable[[], datetime] = _utc_now,
    sleeper: Callable[[float], None] | None = None,
    poll_interval: float = 5.0,
    deadline: float = 600.0,
) -> SwitchToBResult:
    """Run or resume ``SWITCH_TO_B`` from fresh external observations.

    The composition order is fixed:

    ```text
    validate transaction/phase/identity/environment/config
    require the durable PREPARE_B completion evidence (phase-qualified
        stable-a + breakglass-b2 receipts)
        ->
    assert current Lease ownership
    re-stamp the durable transaction's current execution on resume
    re-verify the PREPARE_B evidence against the restamped transaction
        ->
    fresh breakglass B observation + authentication (identity-validated)
    fresh admin breeder observation (must match the stable-a receipt)
        ->
    plan or reconcile the immutable to-B propagation intent
        ->
    persist the intent durably (ownership-fenced) when newly created
        ->
    execute the grouped propagation wave (4C) with fresh B reference
        ->
    execute and recover the derived restart debt (4D)
        ->
    reobserve: require the wave to be safely reconciled and no debt outstanding
        ->
    advance the durable phase to VERIFY_B (ownership-fenced) and stop
    ```

    The authoritative B credential is recovered freshly from PasswordSafe and
    validated by fresh Keystone authentication before any Secret mutation; the
    recovery follows the same "current PasswordSafe value plus the recorded
    generation" discipline ``PREPARE_B`` uses for ``B1``.
    """
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("SWITCH_TO_B clock must return a timezone-aware value.")
    try:
        persisted = state_store.load()
    except StateStoreError:
        raise SwitchToBError(SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None
    transaction = persisted.state.current_transaction
    if transaction is None:
        raise SwitchToBError(SwitchToBErrorCode.NO_TRANSACTION)
    if transaction.phase is not RotationPhase.SWITCH_TO_B:
        raise SwitchToBError(SwitchToBErrorCode.UNSUPPORTED_PHASE)

    request = inputs.request
    if persisted.state.environment != request.environment:
        raise SwitchToBError(SwitchToBErrorCode.ENVIRONMENT_MISMATCH)
    if transaction.keystone != request.keystone:
        raise SwitchToBError(SwitchToBErrorCode.CONFIGURATION_MISMATCH)
    if transaction.passwordsafe.configured_b_record_id != request.passwordsafe_b_record_id:
        raise SwitchToBError(SwitchToBErrorCode.CONFIGURATION_MISMATCH)
    generation = transaction.new_b_sha256
    if generation is None:
        raise SwitchToBError(SwitchToBErrorCode.B_GENERATION_MISSING)

    # Durable PREPARE_B completion evidence is mandatory.  Phase + B generation
    # alone are not proof that PREPARE_B actually succeeded; the durable
    # ``stable-a`` and ``breakglass-b2`` receipts are the record that it did.
    # Missing, non-success, malformed, or generation-inconsistent evidence fails
    # closed before any observation, mutation, or phase work.
    stable_a_receipt, _b2_receipt = _verify_prepare_b_evidence(
        transaction, generation=generation,
    )

    # Re-stamp the durable transaction's current execution on resume.  The
    # bookkeeping field records which execution is currently operating the
    # transaction; the Lease is the authoritative permission source and is
    # asserted before this durable write.
    persisted = _restamp_execution(
        state_store, ownership, persisted,
        execution=request.execution, now=now,
    )
    transaction = persisted.state.current_transaction
    assert transaction is not None
    stable_a_receipt, _ = _verify_prepare_b_evidence(
        transaction, generation=generation,
    )

    # Fresh breakglass observation.  PREPARE_B establishes and verifies B2, but
    # this re-execution may be far later, so the authoritative B value is
    # re-derived from PasswordSafe (the same mechanism PREPARE_B uses for B1)
    # and its identity is re-validated by fresh Keystone authentication.
    try:
        record_b = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=request.passwordsafe_project_id,
            credential_id=request.passwordsafe_b_record_id,
            expected_username=request.breakglass_username,
        )
    except ExternalClientError:
        raise SwitchToBError(SwitchToBErrorCode.B_CREDENTIAL_UNRESOLVED) from None
    if CredentialGeneration.from_secret(record_b.password) != generation:
        raise SwitchToBError(SwitchToBErrorCode.B_CREDENTIAL_UNRESOLVED)
    authentication = _authenticate(
        keystone, username=request.breakglass_username,
        password=record_b.password, request=request.keystone,
    )
    if isinstance(authentication, KeystoneAuthIndeterminate):
        raise SwitchToBError(SwitchToBErrorCode.B_AUTH_INDETERMINATE)
    if not isinstance(authentication, KeystoneAuthSuccess):
        raise SwitchToBError(SwitchToBErrorCode.B_CREDENTIAL_UNRESOLVED)
    _validate_breakglass_auth(
        authentication.observation,
        expected_user_id=request.keystone.breakglass_user_id,
        expected_username=request.breakglass_username,
        request=request.keystone,
        now=clock(),
    )
    b_value = record_b.password
    desired = DesiredCredential(Identity.BREAKGLASS, b_value)
    admin_reference = _observe_admin_reference(
        inputs, stable_a=stable_a_receipt,
    )
    references = ReferenceCredentials(admin_reference, b_value)

    # (1) Plan or reconcile the immutable to-B propagation obligation.
    try:
        planned = plan_or_reconcile_propagation_wave(
            inputs.contract, _current_inventory(inputs), references,
            desired, generation, transaction.propagation.to_b,
        )
    except PropagationWaveError as error:
        raise _map_propagation_error(error) from None

    # (2) Persist the intent durably when it was newly created.
    if planned.intent_created:
        persisted = _persist_intent(
            state_store, ownership, persisted, planned, now=now,
        )
        transaction = persisted.state.current_transaction
        assert transaction is not None

    # (3) Execute the grouped propagation wave (Slice 4C).
    session = GroupedPropagationSession(state_store, persisted)
    execute_grouped_propagation_wave(
        inputs.secret_client, session, ownership,
        contract=inputs.contract, references=references,
        desired=desired, wave=planned.wave, now=clock(),
    )
    persisted = session.persisted
    transaction = persisted.state.current_transaction
    assert transaction is not None
    wave = transaction.propagation.to_b

    # (4) Execute and recover the derived restart debt (Slice 4D).
    action_result = execute_restart_debt(
        inputs.workload_client, state_store, ownership,
        contract=inputs.contract, target=Identity.BREAKGLASS, now=clock(),
        sleeper=sleeper, poll_interval=poll_interval, deadline=deadline,
    )
    if not action_result.all_complete:
        raise SwitchToBError(SwitchToBErrorCode.EXTERNAL_DEPENDENCY)
    persisted = action_result.persisted
    transaction = persisted.state.current_transaction
    assert transaction is not None
    wave = transaction.propagation.to_b

    # (5) Reobserve: require the wave to be safely reconciled against fresh
    # external Secret reality (propagation complete, no unknown state) before
    # the phase is advanced.  Restart completion is re-derived from durable
    # action state below.
    try:
        reconciliation = reconcile_propagation_wave(
            inputs.contract, _current_inventory(inputs), references,
            desired, wave,
        )
    except PropagationWaveError as error:
        raise _map_propagation_error(error) from None
    if not reconciliation.safe_to_continue:
        raise SwitchToBError(SwitchToBErrorCode.CONTRACT_DRIFT)
    if any(
        item.state is not RuntimeActionState.COMPLETE
        for item in wave.runtime_actions
    ):
        raise SwitchToBError(SwitchToBErrorCode.EXTERNAL_DEPENDENCY)

    # (6) Advance the durable phase to VERIFY_B and stop.  This is the
    # completion boundary for SWITCH_TO_B; it performs no VERIFY_B check.
    final_persisted = _advance_to_verify_b(
        state_store, persisted, ownership,
        now=clock(), generation=generation,
    )
    final_transaction = final_persisted.state.current_transaction
    assert final_transaction is not None
    return SwitchToBResult(
        persisted=final_persisted,
        propagated_locations=final_transaction.propagation.to_b.applied_location_ids,
        restarted_actions=tuple(
            item.action_id
            for item in final_transaction.propagation.to_b.runtime_actions
        ),
    )
