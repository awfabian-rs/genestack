"""Slice 4H: transaction-level ``SWITCH_TO_A`` runtime integration.

``run_switch_to_a`` composes the already-implemented Slice 4B propagation-wave
planning/reconciliation, Slice 4C grouped Secret-level propagation execution,
and Slice 4D restart/action executor into the ``SWITCH_TO_A`` runtime phase,
using the **admin** target.  It moves a transaction that ``ROTATE_A`` has
completed (phase ``SWITCH_TO_A``, the authoritative A boundary freshly observed
at A3) through the reverse cutover of every contracted ``identity: active``
credential location back from the temporary ``breakglass`` (B) credential to
the newly rotated ``admin`` (new-A) credential, executes the resulting restart
debt, and advances the durable phase to ``VERIFY_A`` with the credential-free
``switch-to-a-complete`` receipt (A generation only).

It does **not** re-implement any of the correctness-sensitive mechanics: the
propagation-wave planning/reconciliation, grouped Secret mutation, optimistic
concurrency, read-after-write verification, restart derivation/deduplication,
and rollout observation all come from the Slice 4B/4C/4D libraries.  It adds
only the runtime-phase boundary: predecessor evidence validation, the fresh
authoritative-A reconciliation that selects the propagation source, the
ownership-fenced execution re-stamp, and the phase advance.

Entry conditions are re-observed, not trusted from a stale ``ROTATE_A``
result.  A transaction in ``SWITCH_TO_A`` must carry the phase-qualified
durable ``rotate-a-complete`` receipt (at phase ``ROTATE_A``, generation equal
to the transaction's A generation) plus the ``PREPARE_B`` ``stable-a`` /
``breakglass-b2`` evidence.  A transaction already past ``SWITCH_TO_A`` (i.e.
in ``VERIFY_A``) is reported ``ALREADY_ADVANCED`` deterministically without
re-running any machinery; predecessor phases are rejected.

The authoritative new-A source is **not** trusted from any one location in
isolation.  Before propagating, the phase freshly re-derives the A3 reality
through the Slice 3C observation machinery (fresh breeder read, fresh
PasswordSafe A read, fresh admin Keystone authentication) and requires it to
classify as A3 at the transaction's A generation.  ``ROTATE_A`` writes the A
credential in the order ``breeder -> Keystone -> PasswordSafe``, so at A3 the
canonical breeder and PasswordSafe A hold the identical value; the clear-text
propagation source is the freshly read breeder value, whose generation is
required to equal ``new_a_sha256``.  The breakglass (B) credential is
recovered freshly from PasswordSafe at the recorded B generation and validated
by a fresh breakglass Keystone authentication; it is supplied only as the
known-credential reference used to classify participating locations (it is
never propagated).

The propagation target for this phase is ``admin``.  Under the contract
semantics, the admin wave's applicable membership is every ``role: propagated``
location whose identity is ``active`` **or** fixed ``admin``: the ``identity:
active`` locations converge from ``breakglass``/B to ``admin``/new-A, while
fixed-``identity: admin`` propagated locations (which were never switched to B)
are already at the new-A reference and are no-ops.  The canonical
``keystone-admin`` source is never a propagation target.  Restart debt is
accumulated only for locations that actually changed (i.e. the ``identity:
active`` ones); a fixed-admin no-op contributes no restart.

Re-entry is safe across every interruption boundary (no intent yet, intent
persisted but no propagation, partial propagation, propagation complete with
restart debt pending, restart actions running, all actions complete but phase
not yet advanced): each is recovered by observing the durable wave intent,
applied-location progress, and runtime-action state, then continuing the
existing transaction without replaying completed Secret writes or workload
restarts.  It performs no ``VERIFY_A``, no lockout restoration, no breeder
provenance cleanup, no Keystone/PasswordSafe admin mutation, no new password
generation, and no transaction completion: it stops at the ``VERIFY_A``
boundary.
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

__all__ = [
    "SwitchToAErrorCode", "SwitchToAError", "SwitchToAOutcome",
    "SwitchToARequest", "SwitchToAInputs", "SwitchToAResult", "run_switch_to_a",
]


class SwitchToAErrorCode(Enum):
    NO_TRANSACTION = "switch_to_a_no_transaction"
    UNSUPPORTED_PHASE = "switch_to_a_unsupported_phase"
    ENVIRONMENT_MISMATCH = "switch_to_a_environment_mismatch"
    CONFIGURATION_MISMATCH = "switch_to_a_configuration_mismatch"
    NEW_A_GENERATION_MISSING = "switch_to_a_new_a_generation_missing"
    ROTATE_A_PREREQUISITE_MISSING = "switch_to_a_rotate_a_prerequisite_missing"
    ROTATE_A_PREREQUISITE_INVALID = "switch_to_a_rotate_a_prerequisite_invalid"
    PREPARE_B_PREREQUISITE_MISSING = "switch_to_a_prepare_b_prerequisite_missing"
    PREPARE_B_PREREQUISITE_INVALID = "switch_to_a_prepare_b_prerequisite_invalid"
    A_STATE_INVALID = "switch_to_a_state_invalid"
    A_STATE_INDETERMINATE = "switch_to_a_state_indeterminate"
    NEW_A_GENERATION_MISMATCH = "switch_to_a_new_a_generation_mismatch"
    B_CREDENTIAL_UNRESOLVED = "switch_to_a_b_credential_unresolved"
    B_GENERATION_MISMATCH = "switch_to_a_b_generation_mismatch"
    B_AUTH_INDETERMINATE = "switch_to_a_b_auth_indeterminate"
    B_IDENTITY_MISMATCH = "switch_to_a_b_identity_mismatch"
    CONTRACT_DRIFT = "switch_to_a_contract_drift"
    PROGRESS_PERSISTENCE_FAILED = "switch_to_a_progress_persistence_failed"
    EXTERNAL_DEPENDENCY = "switch_to_a_external_dependency"


_ERROR_MESSAGES: dict[SwitchToAErrorCode, str] = {
    SwitchToAErrorCode.NO_TRANSACTION:
        "There is no current transaction to advance through SWITCH_TO_A.",
    SwitchToAErrorCode.UNSUPPORTED_PHASE:
        "The current transaction is not in the SWITCH_TO_A phase.",
    SwitchToAErrorCode.ENVIRONMENT_MISMATCH:
        "The supplied environment does not match the transaction environment.",
    SwitchToAErrorCode.CONFIGURATION_MISMATCH:
        "The transaction identity or configuration does not match the request.",
    SwitchToAErrorCode.NEW_A_GENERATION_MISSING:
        "The transaction has no established new-A credential generation.",
    SwitchToAErrorCode.ROTATE_A_PREREQUISITE_MISSING:
        "The durable rotate-a-complete receipt is absent; ROTATE_A has not durably completed.",
    SwitchToAErrorCode.ROTATE_A_PREREQUISITE_INVALID:
        "The durable rotate-a-complete receipt is malformed or contradictory.",
    SwitchToAErrorCode.PREPARE_B_PREREQUISITE_MISSING:
        "A required durable PREPARE_B completion record is absent; SWITCH_TO_A cannot begin.",
    SwitchToAErrorCode.PREPARE_B_PREREQUISITE_INVALID:
        "A required durable PREPARE_B completion record is malformed or contradictory.",
    SwitchToAErrorCode.A_STATE_INVALID:
        "The authoritative A state is not freshly observed at A3.",
    SwitchToAErrorCode.A_STATE_INDETERMINATE:
        "The authoritative A state could not be freshly classified.",
    SwitchToAErrorCode.NEW_A_GENERATION_MISMATCH:
        "The freshly observed new-A credential does not match the transaction A generation.",
    SwitchToAErrorCode.B_CREDENTIAL_UNRESOLVED:
        "The breakglass credential could not be freshly obtained and verified.",
    SwitchToAErrorCode.B_GENERATION_MISMATCH:
        "The freshly recovered breakglass credential does not match the transaction's recorded B generation; an out-of-band breakglass rotation is detected and the cutover is not attempted.",
    SwitchToAErrorCode.B_AUTH_INDETERMINATE:
        "Fresh breakglass authentication was indeterminate; no cutover is attempted.",
    SwitchToAErrorCode.B_IDENTITY_MISMATCH:
        "Fresh breakglass authentication does not match the recorded identity.",
    SwitchToAErrorCode.CONTRACT_DRIFT:
        "The credential contract does not match the durable propagation obligation.",
    SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED:
        "Durable SWITCH_TO_A progress could not be persisted safely.",
    SwitchToAErrorCode.EXTERNAL_DEPENDENCY:
        "An external credential-system or Kubernetes dependency is unavailable; SWITCH_TO_A does not proceed.",
}


class SwitchToAError(SafeError):
    """A value-free, stable ``SWITCH_TO_A`` orchestration failure."""

    def __init__(self, kind: SwitchToAErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class SwitchToAOutcome(Enum):
    """Typed result vocabulary for one ``SWITCH_TO_A`` invocation.

    ``SWITCHED`` is set only when the fresh A3 reconciliation established the
    authoritative new-A source, every contracted ``identity: active`` location
    converged to ``admin``/new-A, and the derived restart debt completed, and
    the phase advanced to ``VERIFY_A`` in this invocation.
    ``ALREADY_ADVANCED`` is the deterministic idempotency result for a
    transaction already past ``SWITCH_TO_A``.  Failures raise
    ``SwitchToAError`` and leave the transaction resumable in ``SWITCH_TO_A``.
    """

    SWITCHED = "switched"
    ALREADY_ADVANCED = "already_advanced"


@dataclass(frozen=True)
class SwitchToARequest:
    """Caller-supplied identity/configuration to validate against the transaction.

    Mirrors the ``SWITCH_TO_B``/``ROTATE_A`` resume validation: a re-execution
    must prove it is operating on the same environment and Keystone/PasswordSafe
    identity before any correctness-sensitive effect.
    """

    environment: EnvironmentIdentity
    keystone: ResolvedKeystoneIdentities
    passwordsafe_project_id: int
    passwordsafe_a_record_id: int
    passwordsafe_b_record_id: int
    execution: ExecutionIdentity
    admin_username: str = "admin"
    breakglass_username: str = "breakglass"
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


@dataclass(frozen=True)
class SwitchToAInputs:
    request: SwitchToARequest
    contract: CredentialContract
    passwordsafe_access: IdentityAccess
    breeder: BreederSecretClient
    secret_client: CredentialSecretClient
    workload_client: WorkloadClient

    def __post_init__(self) -> None:
        if (
            self.contract.namespace != self.request.breeder_reference.namespace
            or self.contract.source.secret != self.request.breeder_reference.name
        ):
            raise ValueError("The breeder reference must identify the contract source.")


@dataclass(frozen=True)
class SwitchToAResult:
    """Credential-free outcome of one ``SWITCH_TO_A`` invocation.

    ``propagated_locations`` and ``restarted_actions`` name the durable
    ``to_a`` wave's applied-location accounting and runtime-action IDs; no
    credential value, token, or raw external content appears in this result.
    """

    outcome: SwitchToAOutcome
    persisted: PersistedState
    transaction_id: object
    phase: RotationPhase
    propagated_locations: tuple[str, ...] = ()
    restarted_actions: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return (
            f"SwitchToAResult(outcome={self.outcome.value!r}, "
            f"phase={self.phase.value!r})"
        )

    __str__ = __repr__


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _assert_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise SwitchToAError(SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


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
        raise SwitchToAError(SwitchToAErrorCode.B_IDENTITY_MISMATCH)


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
        if phase is RotationPhase.ROTATE_A:
            raise SwitchToAError(SwitchToAErrorCode.ROTATE_A_PREREQUISITE_MISSING)
        raise SwitchToAError(SwitchToAErrorCode.PREPARE_B_PREREQUISITE_MISSING)
    if len(matches) > 1:
        if phase is RotationPhase.ROTATE_A:
            raise SwitchToAError(SwitchToAErrorCode.ROTATE_A_PREREQUISITE_INVALID)
        raise SwitchToAError(SwitchToAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    return matches[0]


def _rotate_a_complete_receipt(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> None:
    """Require the phase-qualified durable ``ROTATE_A`` completion receipt.

    ``ROTATE_A`` records exactly one ``rotate-a-complete`` receipt at phase
    ``ROTATE_A`` carrying the A generation when it advances the phase to
    ``SWITCH_TO_A``.  A transaction in ``SWITCH_TO_A`` without it has not
    durably completed the authoritative-A convergence, and a same-named receipt
    from another phase is not that evidence.  The receipt is *validated*,
    never synthesized.
    """
    receipt = _single_verification(
        transaction, check_id="rotate-a-complete", phase=RotationPhase.ROTATE_A,
    )
    if receipt.status is not VerificationStatus.SUCCESS:
        raise SwitchToAError(SwitchToAErrorCode.ROTATE_A_PREREQUISITE_INVALID)
    if receipt.credential_generation is None:
        raise SwitchToAError(SwitchToAErrorCode.ROTATE_A_PREREQUISITE_INVALID)
    if receipt.credential_generation != generation:
        raise SwitchToAError(SwitchToAErrorCode.ROTATE_A_PREREQUISITE_INVALID)


def _prepare_b_evidence(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> None:
    """Require the durable ``PREPARE_B`` completion evidence.

    Successful ``PREPARE_B`` leaves exactly two durable receipts, each
    explicitly at phase ``PREPARE_B``: ``stable-a`` (old-A generation plus the
    breeder UID it verified — the anchor the Slice 3C A-state machinery
    validates the current breeder identity against) and ``breakglass-b2``
    (B generation).  Both are mandatory and must be ``SUCCESS``; missing,
    wrong-phase, non-success, malformed, or generation-inconsistent evidence
    fails closed before any observation, mutation, or phase work.
    """
    stable_a = _single_verification(
        transaction, check_id="stable-a", phase=RotationPhase.PREPARE_B,
    )
    if stable_a.status is not VerificationStatus.SUCCESS:
        raise SwitchToAError(SwitchToAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    b2 = _single_verification(
        transaction, check_id="breakglass-b2", phase=RotationPhase.PREPARE_B,
    )
    if b2.status is not VerificationStatus.SUCCESS:
        raise SwitchToAError(SwitchToAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if stable_a.credential_generation is None or stable_a.target_uid is None:
        raise SwitchToAError(SwitchToAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation is None:
        raise SwitchToAError(SwitchToAErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation != generation:
        raise SwitchToAError(SwitchToAErrorCode.PREPARE_B_PREREQUISITE_INVALID)


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
        raise SwitchToAError(SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def _observe_a3_source(
    inputs: SwitchToAInputs, transaction: RotationTransaction, *,
    passwordsafe: PasswordSafeClient, keystone: KeystoneClient, clock: Callable[[], datetime],
) -> SecretValue:
    """Freshly reconcile the authoritative A boundary and require A3.

    This re-derives the authoritative new-A value from current external state
    using the Slice 3C observation machinery: a fresh breeder read, a fresh
    PasswordSafe A read, and a fresh admin Keystone authentication.  The
    result must classify as a valid A3 at the transaction's A generation, so
    that PasswordSafe A, the canonical breeder, and the Keystone-accepting
    credential are all established as the identical new-A credential.  The
    canonical breeder is the canonical Kubernetes breeder for ``admin``; its
    transaction provenance does not make its password semantically less
    authoritative.  At A3 the breeder and PasswordSafe A hold the identical
    value, and because ``ROTATE_A`` writes ``breeder -> Keystone ->
    PasswordSafe`` the breeder is the freshest A source.  Its exact value is
    the propagation source.  Any invalid, indeterminate, or non-A3
    classification fails closed; a breeder generation that does not match the
    transaction's A generation is a contradiction and also fails closed.
    """
    request = inputs.request
    try:
        snapshot = inputs.breeder.read(request.breeder_reference)
    except BreederError:
        raise SwitchToAError(SwitchToAErrorCode.A_STATE_INVALID) from None
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
        ),
        passwordsafe=passwordsafe,
        keystone=keystone,
        clock=clock,
    )
    if result.status is AReconciliationStatus.INDETERMINATE:
        raise SwitchToAError(SwitchToAErrorCode.A_STATE_INDETERMINATE)
    if (
        result.status is not AReconciliationStatus.VALID
        or result.state is not ARotationObservedState.A3
    ):
        raise SwitchToAError(SwitchToAErrorCode.A_STATE_INVALID)
    try:
        source = read_credential(
            snapshot, inputs.contract.source.representation,
        ).password
    except SafeError:
        raise SwitchToAError(SwitchToAErrorCode.A_STATE_INVALID) from None
    if CredentialGeneration.from_secret(source) != transaction.new_a_sha256:
        raise SwitchToAError(SwitchToAErrorCode.NEW_A_GENERATION_MISMATCH)
    return source


def _observe_b_reference(
    inputs: SwitchToAInputs, *,
    expected_generation: CredentialGeneration,
    passwordsafe: PasswordSafeClient, keystone: KeystoneClient,
    clock: Callable[[], datetime],
) -> SecretValue:
    """Freshly recover and validate the breakglass credential as the B reference.

    The B value is re-derived from PasswordSafe and its generation is required
    to equal the transaction's recorded B generation (the durable identity
    established by PREPARE_B and the ``breakglass-b2`` receipt) before its
    identity is re-validated by a fresh, correctly-scoped breakglass Keystone
    authentication.  It is used only as the known-credential reference that
    lets the propagation machinery recognize a participating ``identity:
    active`` location currently holding the B credential; it is never
    propagated in this phase.

    The generation check is deliberately strict and fails closed: an out-of-band
    breakglass rotation that leaves a *currently valid* credential at a
    *different* generation is not adopted silently.  The transaction's B
    generation is durable identity, and SWITCH_TO_A must not cutover against a
    breakglass reference it did not itself establish.  The credential is only
    read and classified here — it is never mutated or repaired.
    """
    request = inputs.request
    b_value = _recover_b_value(
        passwordsafe, inputs.passwordsafe_access,
        project_id=request.passwordsafe_project_id,
        record_id=request.passwordsafe_b_record_id,
        username=request.breakglass_username,
    )
    if CredentialGeneration.from_secret(b_value) != expected_generation:
        raise SwitchToAError(SwitchToAErrorCode.B_GENERATION_MISMATCH)
    authentication = _authenticate(
        keystone, username=request.breakglass_username,
        password=b_value, request=request.keystone,
    )
    if isinstance(authentication, KeystoneAuthIndeterminate):
        raise SwitchToAError(SwitchToAErrorCode.B_AUTH_INDETERMINATE)
    if not isinstance(authentication, KeystoneAuthSuccess):
        raise SwitchToAError(SwitchToAErrorCode.B_CREDENTIAL_UNRESOLVED)
    _validate_breakglass_auth(
        authentication.observation,
        expected_user_id=request.keystone.breakglass_user_id,
        expected_username=request.breakglass_username,
        request=request.keystone,
        now=clock(),
    )
    return b_value


def _recover_b_value(
    passwordsafe: PasswordSafeClient, access: IdentityAccess, *,
    project_id: int, record_id: int, username: str,
) -> SecretValue:
    try:
        record = passwordsafe.get_current(
            access=access,
            project_id=project_id,
            credential_id=record_id,
            expected_username=username,
        )
    except ExternalClientError:
        raise SwitchToAError(SwitchToAErrorCode.B_CREDENTIAL_UNRESOLVED) from None
    return record.password


def _current_inventory(inputs: SwitchToAInputs) -> SecretInventory:
    """Re-read every contracted Secret through the supplied client.

    Mirrors the ``SWITCH_TO_B`` inventory builder: the planning/reconciliation
    views and the grouped executor all read through the same client so both
    views are on the same current reality.
    """
    contract = inputs.contract
    names = {location.secret for location in contract.locations}
    secrets: list[SecretSnapshot] = []
    for name in sorted(names):
        try:
            secrets.append(inputs.secret_client.read(contract.namespace, name))
        except CredentialSecretClientError:
            raise SwitchToAError(SwitchToAErrorCode.EXTERNAL_DEPENDENCY) from None
    return SecretInventory(contract.namespace, None, tuple(secrets))


def _persist_intent(
    store: StateStore, ownership: OwnershipGuard, persisted: PersistedState,
    planned: PropagationWavePlanningResult, *, now: datetime,
) -> PersistedState:
    try:
        return persist_propagation_wave_intent(
            store, ownership, persisted, planned, recorded_at=now,
        )
    except PropagationWaveError:
        raise SwitchToAError(SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def _map_propagation_error(error: PropagationWaveError) -> SwitchToAError:
    """Map a Slice 4B/4C wave error to a stable SWITCH_TO_A failure category.

    Contract/intent drift (including membership, identity, or digest changes)
    is ``CONTRACT_DRIFT``; unknown, unparseable, or missing observed state is
    ``EXTERNAL_DEPENDENCY``; ownership loss during intent persistence or
    progress is ``PROGRESS_PERSISTENCE_FAILED``.
    """
    if error.kind in (
        PropagationWaveErrorCode.IMMUTABLE_INTENT_CONFLICT,
        PropagationWaveErrorCode.LEGACY_PROGRESS_WITHOUT_INTENT,
        PropagationWaveErrorCode.TARGET_GENERATION_MISMATCH,
        PropagationWaveErrorCode.TRANSACTION_GENERATION_MISMATCH,
        PropagationWaveErrorCode.NO_APPLICABLE_LOCATIONS,
    ):
        return SwitchToAError(SwitchToAErrorCode.CONTRACT_DRIFT)
    if error.kind is PropagationWaveErrorCode.OWNERSHIP_LOST:
        return SwitchToAError(SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED)
    return SwitchToAError(SwitchToAErrorCode.EXTERNAL_DEPENDENCY)


def _upsert_switch_to_a_complete(
    transaction: RotationTransaction, *, checked_at: datetime,
    generation: CredentialGeneration,
) -> RotationTransaction:
    item = VerificationResult(
        check_id="switch-to-a-complete",
        phase=RotationPhase.SWITCH_TO_A,
        status=VerificationStatus.SUCCESS,
        checked_at=checked_at,
        detail_code="propagated-and-restarted",
        target_uid=None,
        credential_generation=generation,
    )
    retained = tuple(
        value for value in transaction.verifications
        if not (
            value.check_id == "switch-to-a-complete"
            and value.phase is RotationPhase.SWITCH_TO_A
        )
    )
    return replace(
        transaction, verifications=(*retained, item), updated_at=checked_at,
    )


def _advance_to_verify_a(
    store: StateStore, persisted: PersistedState, ownership: OwnershipGuard, *,
    now: datetime, generation: CredentialGeneration,
) -> PersistedState:
    """Advance the durable phase to ``VERIFY_A`` (ownership-fenced) and stop.

    This is the ``SWITCH_TO_A`` completion boundary: it persists only the phase
    advance and a credential-free verification receipt.  The supplied
    ``persisted`` is the CAS basis: it is the exact ``PersistedState`` (the
    revision after the restart-debt completion) on which the completion
    decision was based, so any transaction-state change after that revision
    makes the conditional update fail rather than be silently adopted.  Current
    Lease ownership is asserted immediately before the write; a lost owner
    cannot advance the transaction.  It performs no ``VERIFY_A`` work.
    """
    _assert_owned(ownership)
    transaction = persisted.state.current_transaction
    assert transaction is not None
    updated = _upsert_switch_to_a_complete(
        transaction, checked_at=now, generation=generation,
    )
    updated = replace(
        updated,
        phase=RotationPhase.VERIFY_A,
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
        raise SwitchToAError(SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def run_switch_to_a(
    inputs: SwitchToAInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, clock: Callable[[], datetime] = _utc_now,
    sleeper: Callable[[float], None] | None = None,
    poll_interval: float = 5.0,
    deadline: float = 600.0,
) -> SwitchToAResult:
    """Run or resume the ``SWITCH_TO_A`` runtime phase.

    The composition order is fixed:

    ```text
    validate transaction / phase / identity / environment / config
        (a transaction already past SWITCH_TO_A returns ALREADY_ADVANCED
         without re-running the machinery; a predecessor phase is rejected)
    require the phase-qualified durable completion evidence:
        a single SUCCESS rotate-a-complete receipt at ROTATE_A whose
        generation equals the transaction's A generation, plus the
        PREPARE_B stable-a / breakglass-b2 receipts
        ->
    re-stamp the durable transaction's current execution on resume
        (ownership-fenced bookkeeping, no-op when already current)
        ->
    fresh authoritative-A reconciliation (Slice 3C): require a valid A3 at
        the transaction's A generation; the breeder value is the source
        ->
    fresh breakglass B reference (PasswordSafe + breakglass auth) for the
        known-credential classification set
        ->
    plan or reconcile the immutable to-A propagation intent      (4B)
        ->
    persist the intent durably when newly created (ownership-fenced) (4B)
        ->
    execute the grouped propagation wave (4C) with the fresh A reference
        ->
    execute and recover the derived restart debt (4D)
        ->
    reobserve: require the wave to be safely reconciled and no debt outstanding
        ->
    advance the durable phase to VERIFY_A (ownership-fenced) with the
        credential-free switch-to-a-complete receipt (A generation) and stop
    ```

    The authoritative new-A source is recovered freshly from the A3
    reconciliation (never trusted from any single location in isolation); the
    B credential is recovered freshly only to classify participating
    locations.  Fixed ``identity: admin`` propagated locations are no-ops; the
    canonical ``keystone-admin`` source is never switched.
    """
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("SWITCH_TO_A clock must return a timezone-aware value.")
    try:
        persisted = state_store.load()
    except StateStoreError:
        raise SwitchToAError(SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED) from None
    transaction = persisted.state.current_transaction
    if transaction is None:
        raise SwitchToAError(SwitchToAErrorCode.NO_TRANSACTION)

    request = inputs.request
    # A transaction already past SWITCH_TO_A (VERIFY_A) is handled
    # deterministically: it reports ALREADY_ADVANCED without re-running any
    # machinery or regressing the phase.  A predecessor phase is not this
    # phase's entry state, so it is rejected rather than partially run.
    if transaction.phase is not RotationPhase.SWITCH_TO_A:
        if transaction.phase is RotationPhase.VERIFY_A:
            return SwitchToAResult(
                outcome=SwitchToAOutcome.ALREADY_ADVANCED,
                persisted=persisted,
                transaction_id=transaction.transaction_id,
                phase=transaction.phase,
            )
        raise SwitchToAError(SwitchToAErrorCode.UNSUPPORTED_PHASE)

    if persisted.state.environment != request.environment:
        raise SwitchToAError(SwitchToAErrorCode.ENVIRONMENT_MISMATCH)
    if transaction.keystone != request.keystone:
        raise SwitchToAError(SwitchToAErrorCode.CONFIGURATION_MISMATCH)
    if transaction.passwordsafe.configured_a_record_id != request.passwordsafe_a_record_id:
        raise SwitchToAError(SwitchToAErrorCode.CONFIGURATION_MISMATCH)
    if transaction.passwordsafe.configured_b_record_id != request.passwordsafe_b_record_id:
        raise SwitchToAError(SwitchToAErrorCode.CONFIGURATION_MISMATCH)
    generation = transaction.new_a_sha256
    if generation is None:
        raise SwitchToAError(SwitchToAErrorCode.NEW_A_GENERATION_MISSING)
    b_generation = transaction.new_b_sha256
    if b_generation is None:
        raise SwitchToAError(SwitchToAErrorCode.NEW_A_GENERATION_MISSING)

    # Durable predecessor evidence is mandatory.  The rotate-a-complete
    # receipt proves the authoritative-A convergence durably passed; the
    # PREPARE_B stable-a / breakglass-b2 receipts anchor the old-A generation,
    # the breeder UID, and the B generation.  Both are validated, never
    # synthesized.
    _rotate_a_complete_receipt(transaction, generation=generation)
    _prepare_b_evidence(transaction, generation=b_generation)

    # Re-stamp the durable transaction's current execution on resume
    # (transaction-wide invariant from the SWITCH_TO_B/VERIFY_B/ROTATE_A
    # pass; the ownership assertion inside _restamp_execution precedes the
    # write).
    persisted = _restamp_execution(
        state_store, ownership, persisted,
        execution=request.execution, now=now,
    )
    transaction = persisted.state.current_transaction
    assert transaction is not None
    generation = transaction.new_a_sha256
    b_generation = transaction.new_b_sha256
    assert generation is not None and b_generation is not None

    # (1) Fresh authoritative-A reconciliation: require a valid A3 at the
    # transaction's A generation and obtain the propagation source from the
    # canonical breeder.  Fails closed if A3 cannot be freshly established.
    a_source = _observe_a3_source(
        inputs, transaction,
        passwordsafe=passwordsafe, keystone=keystone, clock=clock,
    )
    desired = DesiredCredential(Identity.ADMIN, a_source)

    # (2) Fresh breakglass reference for the known-credential classification
    # set (never propagated in this phase).
    b_value = _observe_b_reference(
        inputs, expected_generation=b_generation,
        passwordsafe=passwordsafe, keystone=keystone, clock=clock,
    )
    references = ReferenceCredentials(a_source, b_value)

    # (3) Plan or reconcile the immutable to-A propagation obligation.
    try:
        planned = plan_or_reconcile_propagation_wave(
            inputs.contract, _current_inventory(inputs), references,
            desired, generation, transaction.propagation.to_a,
        )
    except PropagationWaveError as error:
        raise _map_propagation_error(error) from None

    # (4) Persist the intent durably when it was newly created.
    if planned.intent_created:
        persisted = _persist_intent(
            state_store, ownership, persisted, planned, now=now,
        )
        transaction = persisted.state.current_transaction
        assert transaction is not None

    # (5) Execute the grouped propagation wave (Slice 4C) with the fresh A
    # reference: every contracted identity: active location converges from
    # breakglass/B to admin/new-A; fixed-admin locations are no-ops.
    session = GroupedPropagationSession(state_store, persisted)
    execute_grouped_propagation_wave(
        inputs.secret_client, session, ownership,
        contract=inputs.contract, references=references,
        desired=desired, wave=planned.wave, now=clock(),
    )
    persisted = session.persisted
    transaction = persisted.state.current_transaction
    assert transaction is not None
    wave = transaction.propagation.to_a

    # (6) Execute and recover the derived restart debt (Slice 4D).
    action_result = execute_restart_debt(
        inputs.workload_client, state_store, ownership,
        contract=inputs.contract, target=Identity.ADMIN, now=clock(),
        sleeper=sleeper, poll_interval=poll_interval, deadline=deadline,
    )
    if not action_result.all_complete:
        raise SwitchToAError(SwitchToAErrorCode.EXTERNAL_DEPENDENCY)
    persisted = action_result.persisted
    transaction = persisted.state.current_transaction
    assert transaction is not None
    wave = transaction.propagation.to_a

    # (7) Reobserve: require the wave to be safely reconciled against fresh
    # external Secret reality (every applied location still at target, no
    # unknown state) before the phase is advanced.  Restart completion is
    # re-derived from durable action state below.
    try:
        reconciliation = reconcile_propagation_wave(
            inputs.contract, _current_inventory(inputs), references,
            desired, wave,
        )
    except PropagationWaveError as error:
        raise _map_propagation_error(error) from None
    if not reconciliation.safe_to_continue:
        raise SwitchToAError(SwitchToAErrorCode.CONTRACT_DRIFT)
    if any(
        item.state is not RuntimeActionState.COMPLETE
        for item in wave.runtime_actions
    ):
        raise SwitchToAError(SwitchToAErrorCode.EXTERNAL_DEPENDENCY)

    # (8) Advance the durable phase to VERIFY_A (ownership-fenced) with the
    # credential-free completion receipt and stop.  The CAS basis is the
    # revision after the restart-debt completion, on which the completion
    # decision was based.  No VERIFY_A work is performed here.
    final_persisted = _advance_to_verify_a(
        state_store, persisted, ownership,
        now=clock(), generation=generation,
    )
    final_transaction = final_persisted.state.current_transaction
    assert final_transaction is not None
    return SwitchToAResult(
        outcome=SwitchToAOutcome.SWITCHED,
        persisted=final_persisted,
        transaction_id=final_transaction.transaction_id,
        phase=final_transaction.phase,
        propagated_locations=final_transaction.propagation.to_a.applied_location_ids,
        restarted_actions=tuple(
            item.action_id
            for item in final_transaction.propagation.to_a.runtime_actions
        ),
    )
