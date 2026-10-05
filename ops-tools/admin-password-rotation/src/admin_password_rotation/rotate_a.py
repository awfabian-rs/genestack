"""Bounded ROTATE_A capabilities for staging and converging A-new."""
from __future__ import annotations

import hmac
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from .a_state import (
    AReconciliationResult, AReconciliationStatus, ARotationInputs,
    ARotationObservedState, observe_a_rotation_state,
)
from .breeder import (
    BreederError, BreederErrorCode, BreederProvenance, BreederReference,
    BreederSecretClient,
)
from .errors import RepresentationError, SafeError
from .external_http import ExternalClientError, ExternalErrorCode
from .keystone import (
    KeystoneAuthIndeterminate, KeystoneAuthRejected, KeystoneAuthSuccess,
    KeystoneClient, KeystonePasswordAuthRequest, KeystoneUserObservation,
)
from .model import (
    CredentialContract, CredentialGeneration, CredentialMutationIntent,
    CredentialMutationStep, EnvironmentIdentity, IntentEffectState,
    KubernetesMutationTarget, LockoutChangeState, RotationPhase,
    RotationTransaction, SafeErrorInfo, SecretInventory, SecretSnapshot, SecretValue,
    TransactionStatus, VerificationResult, VerificationStatus,
)
from .passwords import generate_admin_password
from .passwordsafe import IdentityAccess, PasswordSafeClient, PasswordSafeCredential
from .prepare_b import OwnershipGuard
from .representations import read_credential
from .state_store import PersistedState, StateStore


class RotateAStageErrorCode(Enum):
    ENVIRONMENT_MISMATCH = "rotate_a_environment_mismatch"
    NO_TRANSACTION = "rotate_a_no_transaction"
    UNSUPPORTED_PHASE = "rotate_a_unsupported_phase"
    START_INVALID = "rotate_a_start_invalid"
    START_INDETERMINATE = "rotate_a_start_indeterminate"
    PASSWORDSAFE_ACCESS_EXPIRED = "rotate_a_passwordsafe_access_expired"
    BREAKGLASS_RECORD_INVALID = "rotate_a_breakglass_record_invalid"
    BREAKGLASS_UNAVAILABLE = "rotate_a_breakglass_unavailable"
    BREAKGLASS_REJECTED = "rotate_a_breakglass_rejected"
    BREAKGLASS_AUTH_INDETERMINATE = "rotate_a_breakglass_auth_indeterminate"
    BREAKGLASS_IDENTITY_MISMATCH = "rotate_a_breakglass_identity_mismatch"
    ADMIN_USER_MISMATCH = "rotate_a_admin_user_mismatch"
    LOCKOUT_UNMANAGED_SUPPRESSION = "rotate_a_lockout_unmanaged_suppression"
    LOCKOUT_UNRESOLVED = "rotate_a_lockout_unresolved"
    LOCKOUT_MUTATION_FAILED = "rotate_a_lockout_mutation_failed"
    LOCKOUT_OBSERVATION_FAILED = "rotate_a_lockout_observation_failed"
    OWNERSHIP_LOST = "rotate_a_ownership_lost"
    PASSWORD_GENERATION_FAILED = "rotate_a_password_generation_failed"
    ADMIN_RECORD_INVALID = "rotate_a_admin_record_invalid"
    BREEDER_IDENTITY_CHANGED = "rotate_a_breeder_identity_changed"
    BREEDER_PRECONDITION_FAILED = "rotate_a_breeder_precondition_failed"
    BREEDER_CONFLICT = "rotate_a_breeder_conflict"
    BREEDER_UNRESOLVED = "rotate_a_breeder_unresolved"
    BREEDER_UNKNOWN_CREDENTIAL = "rotate_a_breeder_unknown_credential"
    BREEDER_PROVENANCE_MISMATCH = "rotate_a_breeder_provenance_mismatch"
    BREEDER_MUTATION_FAILED = "rotate_a_breeder_mutation_failed"
    FINAL_STATE_INVALID = "rotate_a_final_state_invalid"
    FINAL_STATE_INDETERMINATE = "rotate_a_final_state_indeterminate"


_ERROR_MESSAGES = {
    kind: "Slice 3D cannot continue safely; inspect the recorded error category."
    for kind in RotateAStageErrorCode
}


class RotateAStageError(SafeError):
    def __init__(self, kind: RotateAStageErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class RotateAStageOutcome(Enum):
    A1_ESTABLISHED = "a1_established"
    A1_ALREADY_ESTABLISHED = "a1_already_established"
    AHEAD_OF_SLICE = "ahead_of_slice"


@dataclass(frozen=True)
class RotateAStageInputs:
    environment: EnvironmentIdentity
    contract: CredentialContract
    passwordsafe_access: IdentityAccess
    passwordsafe_project_id: int
    admin_username: str = "admin"
    breakglass_username: str = "breakglass"
    project_name: str = "admin"
    breeder_reference: BreederReference = BreederReference()

    def __post_init__(self) -> None:
        if isinstance(self.passwordsafe_project_id, bool) or self.passwordsafe_project_id <= 0:
            raise ValueError("PasswordSafe project ID must be positive.")
        if not self.admin_username or not self.breakglass_username or not self.project_name:
            raise ValueError("Expected identity names must be nonempty.")
        if (
            self.contract.namespace != self.breeder_reference.namespace
            or self.contract.source.secret != self.breeder_reference.name
        ):
            raise ValueError("The breeder reference must identify the contract source.")


@dataclass(frozen=True)
class RotateAStageResult:
    outcome: RotateAStageOutcome
    observed_state: ARotationObservedState
    persisted: PersistedState


class RotateAConvergeErrorCode(Enum):
    ENVIRONMENT_MISMATCH = "rotate_a_converge_environment_mismatch"
    NO_TRANSACTION = "rotate_a_converge_no_transaction"
    UNSUPPORTED_PHASE = "rotate_a_converge_unsupported_phase"
    ILLEGAL_A0_START = "rotate_a_converge_illegal_a0_start"
    START_INVALID = "rotate_a_converge_start_invalid"
    START_INDETERMINATE = "rotate_a_converge_start_indeterminate"
    PASSWORDSAFE_ACCESS_EXPIRED = "rotate_a_converge_passwordsafe_access_expired"
    BREAKGLASS_RECORD_INVALID = "rotate_a_converge_breakglass_record_invalid"
    BREAKGLASS_UNAVAILABLE = "rotate_a_converge_breakglass_unavailable"
    BREAKGLASS_REJECTED = "rotate_a_converge_breakglass_rejected"
    BREAKGLASS_AUTH_INDETERMINATE = "rotate_a_converge_breakglass_auth_indeterminate"
    BREAKGLASS_IDENTITY_MISMATCH = "rotate_a_converge_breakglass_identity_mismatch"
    ADMIN_USER_MISMATCH = "rotate_a_converge_admin_user_mismatch"
    LOCKOUT_OBSERVATION_FAILED = "rotate_a_converge_lockout_observation_failed"
    LOCKOUT_SUPPRESSION_REQUIRED = "rotate_a_converge_lockout_suppression_required"
    LOCKOUT_STATE_INCONSISTENT = "rotate_a_converge_lockout_state_inconsistent"
    BREEDER_READ_FAILED = "rotate_a_converge_breeder_read_failed"
    BREEDER_IDENTITY_CHANGED = "rotate_a_converge_breeder_identity_changed"
    BREEDER_VALUE_MISMATCH = "rotate_a_converge_breeder_value_mismatch"
    BREEDER_PROVENANCE_MISMATCH = "rotate_a_converge_breeder_provenance_mismatch"
    OWNERSHIP_LOST = "rotate_a_converge_ownership_lost"
    PROGRESS_CONTRADICTS_REALITY = "rotate_a_converge_progress_contradicts_reality"
    RESET_A_REJECTED = "rotate_a_converge_reset_a_rejected"
    RESET_A_UNRESOLVED = "rotate_a_converge_reset_a_unresolved"
    RESET_A_STATE_INVALID = "rotate_a_converge_reset_a_state_invalid"
    RESET_A_STATE_INDETERMINATE = "rotate_a_converge_reset_a_state_indeterminate"
    PASSWORDSAFE_RECORD_INVALID = "rotate_a_converge_passwordsafe_record_invalid"
    PASSWORDSAFE_UPDATE_REJECTED = "rotate_a_converge_passwordsafe_update_rejected"
    PASSWORDSAFE_UPDATE_UNRESOLVED = "rotate_a_converge_passwordsafe_update_unresolved"
    PASSWORDSAFE_UNRELATED_CREDENTIAL = "rotate_a_converge_passwordsafe_unrelated_credential"
    FINAL_STATE_INVALID = "rotate_a_converge_final_state_invalid"
    FINAL_STATE_INDETERMINATE = "rotate_a_converge_final_state_indeterminate"


_CONVERGE_ERROR_MESSAGES = {
    kind: "Slice 3E cannot continue safely; inspect the recorded error category."
    for kind in RotateAConvergeErrorCode
}


class RotateAConvergeError(SafeError):
    def __init__(self, kind: RotateAConvergeErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _CONVERGE_ERROR_MESSAGES[kind])


class RotateAConvergeOutcome(Enum):
    A3_ESTABLISHED = "a3_established"
    A3_ALREADY_ESTABLISHED = "a3_already_established"


@dataclass(frozen=True)
class RotateAConvergeInputs(RotateAStageInputs):
    """Slice 3E inputs; identical authority configuration to Slice 3D."""


@dataclass(frozen=True)
class RotateAConvergeResult:
    outcome: RotateAConvergeOutcome
    starting_state: ARotationObservedState
    observed_state: ARotationObservedState
    persisted: PersistedState


PasswordGenerator = Callable[[], SecretValue]
Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _Session:
    def __init__(self, store: StateStore, persisted: PersistedState) -> None:
        self.store = store
        self.persisted = persisted

    @property
    def transaction(self) -> RotationTransaction:
        transaction = self.persisted.state.current_transaction
        if transaction is None:
            raise RotateAStageError(RotateAStageErrorCode.NO_TRANSACTION)
        return transaction

    def write(self, transaction: RotationTransaction) -> None:
        self.persisted = self.store.update(
            self.persisted.revision,
            replace(self.persisted.state, current_transaction=transaction),
        )

    def block(self, error: RotateAStageError, now: datetime) -> None:
        self.write(replace(
            self.transaction,
            status=TransactionStatus.BLOCKED,
            last_error=SafeErrorInfo(error.kind.value, now),
            updated_at=now,
        ))


def _inventory(secret: SecretSnapshot) -> SecretInventory:
    return SecretInventory(secret.namespace, secret.resource_version, (secret,))


def _observe_a(
    session: _Session, inputs: RotateAStageInputs, *, breeder: BreederSecretClient,
    passwordsafe: PasswordSafeClient, keystone: KeystoneClient, clock: Clock,
) -> AReconciliationResult:
    try:
        snapshot = breeder.read(inputs.breeder_reference)
    except BreederError as error:
        code = (
            RotateAStageErrorCode.START_INDETERMINATE
            if error.kind is BreederErrorCode.READ_FAILED
            else RotateAStageErrorCode.START_INVALID
        )
        raise RotateAStageError(code) from None
    return observe_a_rotation_state(
        ARotationInputs(
            transaction=session.transaction,
            contract=inputs.contract,
            inventory=_inventory(snapshot),
            passwordsafe_access=inputs.passwordsafe_access,
            passwordsafe_project_id=inputs.passwordsafe_project_id,
            admin_username=inputs.admin_username,
            project_name=inputs.project_name,
        ),
        passwordsafe=passwordsafe,
        keystone=keystone,
        clock=clock,
    )


def _require_observed(result: AReconciliationResult) -> ARotationObservedState:
    if result.status is AReconciliationStatus.INVALID:
        raise RotateAStageError(RotateAStageErrorCode.START_INVALID)
    if result.status is AReconciliationStatus.INDETERMINATE:
        raise RotateAStageError(RotateAStageErrorCode.START_INDETERMINATE)
    assert result.state is not None
    return result.state


def _external_record_error(error: ExternalClientError) -> RotateAStageError:
    if error.kind in (
        ExternalErrorCode.MALFORMED_RESPONSE,
        ExternalErrorCode.RECORD_MISMATCH,
        ExternalErrorCode.NOT_FOUND,
    ):
        return RotateAStageError(RotateAStageErrorCode.BREAKGLASS_RECORD_INVALID)
    return RotateAStageError(RotateAStageErrorCode.BREAKGLASS_UNAVAILABLE)


def _validate_breakglass(
    session: _Session, inputs: RotateAStageInputs, *, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, now: datetime,
) -> tuple[PasswordSafeCredential, KeystoneAuthSuccess]:
    if inputs.passwordsafe_access.expires_at <= now:
        raise RotateAStageError(RotateAStageErrorCode.PASSWORDSAFE_ACCESS_EXPIRED)
    transaction = session.transaction
    try:
        record = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=inputs.passwordsafe_project_id,
            credential_id=transaction.passwordsafe.configured_b_record_id,
            expected_username=inputs.breakglass_username,
        )
    except ExternalClientError as error:
        raise _external_record_error(error) from None
    if (
        record.project_id != inputs.passwordsafe_project_id
        or record.credential_id != transaction.passwordsafe.configured_b_record_id
        or record.username != inputs.breakglass_username
        or isinstance(record.version, bool)
        or record.version <= 0
    ):
        raise RotateAStageError(RotateAStageErrorCode.BREAKGLASS_RECORD_INVALID)
    result = keystone.authenticate_password(KeystonePasswordAuthRequest(
        username=inputs.breakglass_username,
        user_domain_id=transaction.keystone.user_domain_id,
        project_id=transaction.keystone.project_id,
        password=record.password,
    ))
    if isinstance(result, KeystoneAuthRejected):
        raise RotateAStageError(RotateAStageErrorCode.BREAKGLASS_REJECTED)
    if isinstance(result, KeystoneAuthIndeterminate):
        raise RotateAStageError(RotateAStageErrorCode.BREAKGLASS_AUTH_INDETERMINATE)
    observed = result.observation
    expected = transaction.keystone
    if not (
        observed.user_id == expected.breakglass_user_id
        and observed.user_name == inputs.breakglass_username
        and observed.user_domain_id == expected.user_domain_id
        and observed.project_id == expected.project_id
        and observed.project_name == inputs.project_name
        and observed.project_domain_id == expected.project_domain_id
        and observed.expires_at > now
        and any(role.role_id == expected.role_id for role in observed.roles)
    ):
        raise RotateAStageError(RotateAStageErrorCode.BREAKGLASS_IDENTITY_MISMATCH)
    return record, result


def _admin_user(
    session: _Session, inputs: RotateAStageInputs, *, keystone: KeystoneClient,
    token: SecretValue,
) -> KeystoneUserObservation:
    try:
        observed = keystone.get_user(
            user_id=session.transaction.keystone.admin_user_id,
            management_token=token,
        )
    except ExternalClientError:
        raise RotateAStageError(RotateAStageErrorCode.LOCKOUT_OBSERVATION_FAILED) from None
    expected = session.transaction.keystone
    if not (
        observed.user_id == expected.admin_user_id
        and observed.name == inputs.admin_username
        and observed.domain_id == expected.user_domain_id
        and observed.enabled
        and observed.default_project_id in (None, expected.project_id)
    ):
        raise RotateAStageError(RotateAStageErrorCode.ADMIN_USER_MISMATCH)
    return observed


def _assert_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise RotateAStageError(RotateAStageErrorCode.OWNERSHIP_LOST) from None


def _ensure_lockout_suppressed(
    session: _Session, inputs: RotateAStageInputs, *, keystone: KeystoneClient,
    ownership: OwnershipGuard, token: SecretValue, now: datetime,
) -> None:
    observed = _admin_user(session, inputs, keystone=keystone, token=token)
    lockout = session.transaction.lockout
    if observed.ignore_lockout_failure_attempts:
        if not lockout.restore_required:
            raise RotateAStageError(
                RotateAStageErrorCode.LOCKOUT_UNMANAGED_SUPPRESSION,
            )
        session.write(replace(
            session.transaction,
            lockout=replace(
                lockout,
                suppression=LockoutChangeState.EFFECT_OBSERVED,
                latest_ignore_lockout_failure_attempts=True,
            ),
            status=TransactionStatus.ACTIVE,
            last_error=None,
            updated_at=now,
        ))
        return
    if lockout.restore_required and lockout.suppression in (
        LockoutChangeState.DISPATCH_UNRESOLVED,
        LockoutChangeState.EFFECT_OBSERVED,
    ):
        raise RotateAStageError(RotateAStageErrorCode.LOCKOUT_UNRESOLVED)
    if not lockout.restore_required:
        session.write(replace(
            session.transaction,
            lockout=replace(
                lockout,
                suppression=LockoutChangeState.INTENT_PERSISTED,
                latest_ignore_lockout_failure_attempts=False,
                restore_required=True,
            ),
            status=TransactionStatus.ACTIVE,
            last_error=None,
            updated_at=now,
        ))
    _assert_owned(ownership)
    session.write(replace(
        session.transaction,
        lockout=replace(
            session.transaction.lockout,
            suppression=LockoutChangeState.DISPATCH_UNRESOLVED,
            latest_ignore_lockout_failure_attempts=False,
        ),
        updated_at=now,
    ))
    ambiguous = False
    try:
        keystone.set_ignore_lockout_failure_attempts(
            user_id=session.transaction.keystone.admin_user_id,
            value=True,
            management_token=token,
        )
    except ExternalClientError as error:
        if error.kind is not ExternalErrorCode.MUTATION_AMBIGUOUS:
            session.write(replace(
                session.transaction,
                lockout=replace(
                    session.transaction.lockout,
                    suppression=LockoutChangeState.INTENT_PERSISTED,
                ),
                updated_at=now,
            ))
            raise RotateAStageError(RotateAStageErrorCode.LOCKOUT_MUTATION_FAILED) from None
        ambiguous = True
    try:
        actual = _admin_user(session, inputs, keystone=keystone, token=token)
    except RotateAStageError:
        raise RotateAStageError(RotateAStageErrorCode.LOCKOUT_UNRESOLVED) from None
    if not actual.ignore_lockout_failure_attempts:
        code = (
            RotateAStageErrorCode.LOCKOUT_UNRESOLVED
            if ambiguous else RotateAStageErrorCode.LOCKOUT_MUTATION_FAILED
        )
        raise RotateAStageError(code)
    session.write(replace(
        session.transaction,
        lockout=replace(
            session.transaction.lockout,
            suppression=LockoutChangeState.EFFECT_OBSERVED,
            latest_ignore_lockout_failure_attempts=True,
        ),
        updated_at=now,
    ))


def _same(left: SecretValue, right: SecretValue) -> bool:
    return hmac.compare_digest(left.reveal(), right.reveal())


def _candidate(
    generator: PasswordGenerator, *, old_a: SecretValue, current_b: SecretValue,
) -> SecretValue:
    for _ in range(32):
        value = generator()
        if not _same(value, old_a) and not _same(value, current_b):
            return value
    raise RotateAStageError(RotateAStageErrorCode.PASSWORD_GENERATION_FAILED)


def _admin_record(
    session: _Session, inputs: RotateAStageInputs, *, passwordsafe: PasswordSafeClient,
    expected_generation: CredentialGeneration,
) -> PasswordSafeCredential:
    try:
        record = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=inputs.passwordsafe_project_id,
            credential_id=session.transaction.passwordsafe.configured_a_record_id,
            expected_username=inputs.admin_username,
        )
    except ExternalClientError:
        raise RotateAStageError(RotateAStageErrorCode.ADMIN_RECORD_INVALID) from None
    if CredentialGeneration.from_secret(record.password) != expected_generation:
        raise RotateAStageError(RotateAStageErrorCode.ADMIN_RECORD_INVALID)
    return record


def _stage_intent(
    session: _Session, snapshot: SecretSnapshot, generation: CredentialGeneration,
    effect: IntentEffectState, now: datetime,
) -> None:
    observed_at = now if effect is IntentEffectState.OBSERVED else None
    result_version = snapshot.resource_version if observed_at is not None else None
    session.write(replace(
        session.transaction,
        new_a_sha256=generation,
        credential_mutation_intent=CredentialMutationIntent(
            CredentialMutationStep.STAGE_A_BREEDER,
            KubernetesMutationTarget(
                snapshot.namespace, snapshot.name, snapshot.uid,
                snapshot.resource_version,
            ),
            (),
            generation,
            effect,
            observed_at,
            result_version,
        ),
        status=TransactionStatus.ACTIVE,
        last_error=None,
        updated_at=now,
    ))


def _mark_stage_observed(
    session: _Session, snapshot: SecretSnapshot, *, now: datetime,
) -> None:
    current = session.transaction.credential_mutation_intent
    generation = session.transaction.new_a_sha256
    if (
        current is None
        or generation is None
        or current.step is not CredentialMutationStep.STAGE_A_BREEDER
        or current.intended_generation != generation
    ):
        raise RotateAStageError(RotateAStageErrorCode.FINAL_STATE_INVALID)
    session.write(replace(
        session.transaction,
        credential_mutation_intent=replace(
            current,
            effect_state=IntentEffectState.OBSERVED,
            effect_observed_at=now,
            resulting_resource_version=snapshot.resource_version,
        ),
        updated_at=now,
    ))


def _verify_staged_snapshot(
    session: _Session, snapshot: SecretSnapshot, *, old_generation: CredentialGeneration,
) -> bool:
    stable = next(
        item for item in session.transaction.verifications
        if item.check_id == "stable-a" and item.phase is RotationPhase.PREPARE_B
    )
    if snapshot.uid != stable.target_uid:
        raise RotateAStageError(RotateAStageErrorCode.BREEDER_IDENTITY_CHANGED)
    password = snapshot.get("password")
    if password is None:
        raise RotateAStageError(RotateAStageErrorCode.BREEDER_UNKNOWN_CREDENTIAL)
    generation = CredentialGeneration.from_secret(password)
    intended = session.transaction.new_a_sha256
    if intended is not None and generation == intended:
        if not BreederProvenance(
            session.transaction.transaction_id, intended,
        ).matches(snapshot):
            raise RotateAStageError(RotateAStageErrorCode.BREEDER_PROVENANCE_MISMATCH)
        return True
    if generation == old_generation:
        return False
    raise RotateAStageError(RotateAStageErrorCode.BREEDER_UNKNOWN_CREDENTIAL)


def _stable_generation(transaction: RotationTransaction) -> CredentialGeneration:
    generation = next((
        item.credential_generation
        for item in transaction.verifications
        if item.check_id == "stable-a"
        and item.phase is RotationPhase.PREPARE_B
        and item.status is VerificationStatus.SUCCESS
    ), None)
    if generation is None:
        raise RotateAStageError(RotateAStageErrorCode.START_INVALID)
    return generation


def _stage_breeder(
    session: _Session, inputs: RotateAStageInputs, *, breeder: BreederSecretClient,
    passwordsafe: PasswordSafeClient, ownership: OwnershipGuard,
    current_b: PasswordSafeCredential, generator: PasswordGenerator,
    old_generation: CredentialGeneration, now: datetime,
) -> None:
    snapshot = breeder.read(inputs.breeder_reference)
    already_staged = _verify_staged_snapshot(
        session, snapshot, old_generation=old_generation,
    )
    if already_staged:
        _mark_stage_observed(session, snapshot, now=now)
        return
    current = session.transaction.credential_mutation_intent
    if (
        current is not None
        and current.step is CredentialMutationStep.STAGE_A_BREEDER
        and current.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
    ):
        raise RotateAStageError(RotateAStageErrorCode.BREEDER_UNRESOLVED)
    old_a = _admin_record(
        session, inputs, passwordsafe=passwordsafe,
        expected_generation=old_generation,
    )
    value = _candidate(generator, old_a=old_a.password, current_b=current_b.password)
    generation = CredentialGeneration.from_secret(value)
    _stage_intent(
        session, snapshot, generation, IntentEffectState.UNKNOWN, now,
    )
    _assert_owned(ownership)
    _stage_intent(
        session, snapshot, generation, IntentEffectState.DISPATCH_UNRESOLVED, now,
    )
    provenance = BreederProvenance(session.transaction.transaction_id, generation)
    conditional_rejected = False
    outcome_ambiguous = False
    try:
        breeder.conditional_stage(snapshot, password=value, provenance=provenance)
    except BreederError as error:
        if error.kind is BreederErrorCode.CONDITIONAL_REJECTED:
            # Kubernetes JSON Patch test failure is atomic proof that this
            # request did not apply. Return the intent to pre-dispatch before
            # reconciling the fresh object; this generation is no longer sticky.
            _stage_intent(
                session, snapshot, generation, IntentEffectState.UNKNOWN, now,
            )
            conditional_rejected = True
        elif error.kind is BreederErrorCode.OUTCOME_AMBIGUOUS:
            outcome_ambiguous = True
        else:
            raise RotateAStageError(RotateAStageErrorCode.BREEDER_MUTATION_FAILED) from None
    try:
        observed = breeder.read(inputs.breeder_reference)
    except BreederError:
        code = (
            RotateAStageErrorCode.BREEDER_CONFLICT
            if conditional_rejected
            else RotateAStageErrorCode.BREEDER_UNRESOLVED
        )
        raise RotateAStageError(code) from None
    if _verify_staged_snapshot(
        session, observed, old_generation=old_generation,
    ):
        _mark_stage_observed(session, observed, now=now)
        return
    if conditional_rejected:
        if any(
            observed.annotation(item.key) is not None
            for item in provenance.annotations()
        ):
            raise RotateAStageError(
                RotateAStageErrorCode.BREEDER_PROVENANCE_MISMATCH,
            )
        _stage_intent(
            session, observed, generation, IntentEffectState.UNKNOWN, now,
        )
        raise RotateAStageError(RotateAStageErrorCode.BREEDER_CONFLICT)
    if outcome_ambiguous:
        raise RotateAStageError(RotateAStageErrorCode.BREEDER_UNRESOLVED)
    raise RotateAStageError(RotateAStageErrorCode.BREEDER_MUTATION_FAILED)


def _record_a1(session: _Session, *, now: datetime) -> None:
    transaction = session.transaction
    generation = transaction.new_a_sha256
    current = transaction.credential_mutation_intent
    if generation is None or current is None or current.target is None:
        raise RotateAStageError(RotateAStageErrorCode.FINAL_STATE_INVALID)
    item = VerificationResult(
        check_id="slice-3d-a1",
        phase=RotationPhase.ROTATE_A,
        status=VerificationStatus.SUCCESS,
        checked_at=now,
        detail_code="freshly-observed-a1",
        target_uid=current.target.uid,
        credential_generation=generation,
    )
    retained = tuple(
        value for value in transaction.verifications
        if not (
            value.check_id == item.check_id
            and value.phase is RotationPhase.ROTATE_A
        )
    )
    session.write(replace(
        transaction,
        verifications=(*retained, item),
        status=TransactionStatus.ACTIVE,
        last_error=None,
        updated_at=now,
    ))


def run_rotate_a_stage_breeder(
    inputs: RotateAStageInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, breeder: BreederSecretClient,
    password_generator: PasswordGenerator = generate_admin_password,
    clock: Clock = _utc_now,
) -> RotateAStageResult:
    """Run/resume only Slice 3D; successful execution stops at observed A1."""
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Slice 3D clock must return a timezone-aware value.")
    now = now.astimezone(timezone.utc)
    session = _Session(state_store, state_store.load())
    try:
        if session.persisted.state.environment != inputs.environment:
            raise RotateAStageError(RotateAStageErrorCode.ENVIRONMENT_MISMATCH)
        if session.transaction.phase is not RotationPhase.ROTATE_A:
            raise RotateAStageError(RotateAStageErrorCode.UNSUPPORTED_PHASE)
        starting = _observe_a(
            session, inputs, breeder=breeder, passwordsafe=passwordsafe,
            keystone=keystone, clock=clock,
        )
        starting_state = _require_observed(starting)
        if starting_state in (ARotationObservedState.A2, ARotationObservedState.A3):
            return RotateAStageResult(
                RotateAStageOutcome.AHEAD_OF_SLICE, starting_state, session.persisted,
            )
        if starting_state is ARotationObservedState.A1:
            snapshot = breeder.read(inputs.breeder_reference)
            observation = starting.observation
            assert observation is not None
            if not _verify_staged_snapshot(
                session, snapshot,
                old_generation=_stable_generation(session.transaction),
            ):
                raise RotateAStageError(RotateAStageErrorCode.FINAL_STATE_INVALID)
            _mark_stage_observed(session, snapshot, now=now)
            _, auth = _validate_breakglass(
                session, inputs, passwordsafe=passwordsafe, keystone=keystone, now=now,
            )
            _ensure_lockout_suppressed(
                session, inputs, keystone=keystone, ownership=ownership,
                token=auth.token, now=now,
            )
            _record_a1(session, now=now)
            return RotateAStageResult(
                RotateAStageOutcome.A1_ALREADY_ESTABLISHED,
                ARotationObservedState.A1,
                session.persisted,
            )

        observation = starting.observation
        assert observation is not None
        current_b, auth = _validate_breakglass(
            session, inputs, passwordsafe=passwordsafe, keystone=keystone, now=now,
        )
        _ensure_lockout_suppressed(
            session, inputs, keystone=keystone, ownership=ownership,
            token=auth.token, now=now,
        )
        # Suppression may have been recovered from an interrupted dispatch. A
        # fresh A observation prevents durable progress from replacing reality.
        before_stage = _observe_a(
            session, inputs, breeder=breeder, passwordsafe=passwordsafe,
            keystone=keystone, clock=clock,
        )
        if _require_observed(before_stage) is not ARotationObservedState.A0:
            raise RotateAStageError(RotateAStageErrorCode.FINAL_STATE_INVALID)
        _stage_breeder(
            session, inputs, breeder=breeder, passwordsafe=passwordsafe,
            ownership=ownership, current_b=current_b,
            generator=password_generator,
            old_generation=observation.passwordsafe_generation,
            now=now,
        )
        final = _observe_a(
            session, inputs, breeder=breeder, passwordsafe=passwordsafe,
            keystone=keystone, clock=clock,
        )
        if final.status is AReconciliationStatus.INDETERMINATE:
            raise RotateAStageError(RotateAStageErrorCode.FINAL_STATE_INDETERMINATE)
        if final.status is AReconciliationStatus.INVALID or final.state is None:
            raise RotateAStageError(RotateAStageErrorCode.FINAL_STATE_INVALID)
        if final.state in (ARotationObservedState.A2, ARotationObservedState.A3):
            return RotateAStageResult(
                RotateAStageOutcome.AHEAD_OF_SLICE, final.state, session.persisted,
            )
        if final.state is not ARotationObservedState.A1:
            raise RotateAStageError(RotateAStageErrorCode.FINAL_STATE_INVALID)
        actual = _admin_user(session, inputs, keystone=keystone, token=auth.token)
        if (
            not actual.ignore_lockout_failure_attempts
            or not session.transaction.lockout.restore_required
        ):
            raise RotateAStageError(RotateAStageErrorCode.LOCKOUT_UNRESOLVED)
        _record_a1(session, now=now)
        return RotateAStageResult(
            RotateAStageOutcome.A1_ESTABLISHED,
            ARotationObservedState.A1,
            session.persisted,
        )
    except RotateAStageError as error:
        if session.persisted.state.current_transaction is not None:
            session.block(error, now)
        raise


def _converge_error_from_stage(error: RotateAStageError) -> RotateAConvergeError:
    mapping = {
        RotateAStageErrorCode.PASSWORDSAFE_ACCESS_EXPIRED:
            RotateAConvergeErrorCode.PASSWORDSAFE_ACCESS_EXPIRED,
        RotateAStageErrorCode.BREAKGLASS_RECORD_INVALID:
            RotateAConvergeErrorCode.BREAKGLASS_RECORD_INVALID,
        RotateAStageErrorCode.BREAKGLASS_UNAVAILABLE:
            RotateAConvergeErrorCode.BREAKGLASS_UNAVAILABLE,
        RotateAStageErrorCode.BREAKGLASS_REJECTED:
            RotateAConvergeErrorCode.BREAKGLASS_REJECTED,
        RotateAStageErrorCode.BREAKGLASS_AUTH_INDETERMINATE:
            RotateAConvergeErrorCode.BREAKGLASS_AUTH_INDETERMINATE,
        RotateAStageErrorCode.BREAKGLASS_IDENTITY_MISMATCH:
            RotateAConvergeErrorCode.BREAKGLASS_IDENTITY_MISMATCH,
        RotateAStageErrorCode.ADMIN_USER_MISMATCH:
            RotateAConvergeErrorCode.ADMIN_USER_MISMATCH,
        RotateAStageErrorCode.LOCKOUT_OBSERVATION_FAILED:
            RotateAConvergeErrorCode.LOCKOUT_OBSERVATION_FAILED,
    }
    return RotateAConvergeError(
        mapping.get(error.kind, RotateAConvergeErrorCode.START_INVALID),
    )


def _observe_a_converge(
    session: _Session, inputs: RotateAConvergeInputs, *,
    breeder: BreederSecretClient, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, clock: Clock,
) -> AReconciliationResult:
    try:
        return _observe_a(
            session, inputs, breeder=breeder, passwordsafe=passwordsafe,
            keystone=keystone, clock=clock,
        )
    except RotateAStageError as error:
        if error.kind is RotateAStageErrorCode.START_INDETERMINATE:
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.START_INDETERMINATE,
            ) from None
        raise RotateAConvergeError(RotateAConvergeErrorCode.START_INVALID) from None


def _require_converge_state(
    result: AReconciliationResult,
) -> ARotationObservedState:
    if result.status is AReconciliationStatus.INVALID:
        raise RotateAConvergeError(RotateAConvergeErrorCode.START_INVALID)
    if result.status is AReconciliationStatus.INDETERMINATE:
        raise RotateAConvergeError(RotateAConvergeErrorCode.START_INDETERMINATE)
    assert result.state is not None
    return result.state


def _stable_a_verification(transaction: RotationTransaction) -> VerificationResult:
    matches = tuple(
        item for item in transaction.verifications
        if item.check_id == "stable-a"
        and item.phase is RotationPhase.PREPARE_B
        and item.status is VerificationStatus.SUCCESS
    )
    if len(matches) != 1:
        raise RotateAConvergeError(RotateAConvergeErrorCode.START_INVALID)
    stable = matches[0]
    if stable.target_uid is None or stable.credential_generation is None:
        raise RotateAConvergeError(RotateAConvergeErrorCode.START_INVALID)
    return stable


def _recover_staged_a(
    session: _Session, inputs: RotateAConvergeInputs, *,
    breeder: BreederSecretClient,
) -> SecretValue:
    intended = session.transaction.new_a_sha256
    if intended is None:
        raise RotateAConvergeError(RotateAConvergeErrorCode.BREEDER_VALUE_MISMATCH)
    try:
        snapshot = breeder.read(inputs.breeder_reference)
    except BreederError as error:
        code = (
            RotateAConvergeErrorCode.BREEDER_READ_FAILED
            if error.kind is BreederErrorCode.READ_FAILED
            else RotateAConvergeErrorCode.BREEDER_VALUE_MISMATCH
        )
        raise RotateAConvergeError(code) from None
    stable = _stable_a_verification(session.transaction)
    if snapshot.uid != stable.target_uid:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.BREEDER_IDENTITY_CHANGED,
        )
    try:
        password = read_credential(
            snapshot, inputs.contract.source.representation,
        ).password
        generation = CredentialGeneration.from_secret(password)
    except (RepresentationError, ValueError):
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.BREEDER_VALUE_MISMATCH,
        ) from None
    if generation != intended:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.BREEDER_VALUE_MISMATCH,
        )
    if not BreederProvenance(
        session.transaction.transaction_id, intended,
    ).matches(snapshot):
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.BREEDER_PROVENANCE_MISMATCH,
        )
    return password


def _require_converge_lockout(
    session: _Session, inputs: RotateAConvergeInputs, *,
    passwordsafe: PasswordSafeClient, keystone: KeystoneClient, now: datetime,
) -> KeystoneAuthSuccess:
    try:
        _, authorization = _validate_breakglass(
            session, inputs, passwordsafe=passwordsafe, keystone=keystone, now=now,
        )
        observed = _admin_user(
            session, inputs, keystone=keystone, token=authorization.token,
        )
    except RotateAStageError as error:
        raise _converge_error_from_stage(error) from None
    if not observed.ignore_lockout_failure_attempts:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.LOCKOUT_SUPPRESSION_REQUIRED,
        )
    lockout = session.transaction.lockout
    if not (
        lockout.restore_required
        and lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
        and lockout.latest_ignore_lockout_failure_attempts is True
        and lockout.restoration is LockoutChangeState.NOT_INTENDED
    ):
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.LOCKOUT_STATE_INCONSISTENT,
        )
    return authorization


def _assert_converge_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.OWNERSHIP_LOST,
        ) from None


def _write_converge_intent(
    session: _Session, *, step: CredentialMutationStep,
    effect: IntentEffectState, now: datetime,
    passwordsafe_observation: tuple[int, int] | None = None,
) -> None:
    generation = session.transaction.new_a_sha256
    if generation is None:
        raise RotateAConvergeError(RotateAConvergeErrorCode.START_INVALID)
    observed_at = now if effect is IntentEffectState.OBSERVED else None
    transaction = replace(
        session.transaction,
        credential_mutation_intent=CredentialMutationIntent(
            step, None, (), generation, effect, observed_at, None,
        ),
        status=TransactionStatus.ACTIVE,
        last_error=None,
        updated_at=now,
    )
    if passwordsafe_observation is not None:
        record_id, version = passwordsafe_observation
        transaction = replace(
            transaction,
            passwordsafe=replace(
                transaction.passwordsafe,
                observed_a_record_id=record_id,
                observed_a_version=version,
            ),
        )
    session.write(transaction)


def _record_converged_state(
    session: _Session, state: ARotationObservedState, *, now: datetime,
) -> None:
    generation = session.transaction.new_a_sha256
    stable = _stable_a_verification(session.transaction)
    if generation is None:
        raise RotateAConvergeError(RotateAConvergeErrorCode.START_INVALID)
    check_id = f"slice-3e-{state.value.lower()}"
    item = VerificationResult(
        check_id, RotationPhase.ROTATE_A, VerificationStatus.SUCCESS, now,
        f"freshly-observed-{state.value.lower()}", stable.target_uid, generation,
    )
    retained = tuple(
        value for value in session.transaction.verifications
        if not (
            value.check_id == check_id
            and value.phase is RotationPhase.ROTATE_A
        )
    )
    session.write(replace(
        session.transaction,
        verifications=(*retained, item),
        status=TransactionStatus.ACTIVE,
        last_error=None,
        updated_at=now,
    ))


def _reconcile_converge_progress(
    session: _Session, state: ARotationObservedState, *,
    observation: AReconciliationResult, now: datetime,
) -> None:
    current = session.transaction.credential_mutation_intent
    if current is None:
        return
    if state is ARotationObservedState.A1:
        if (
            current.step is CredentialMutationStep.UPDATE_A_PASSWORDSAFE
            or (
                current.step is CredentialMutationStep.RESET_A_KEYSTONE
                and current.effect_state is IntentEffectState.OBSERVED
            )
        ):
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.PROGRESS_CONTRADICTS_REALITY,
            )
        return
    if state is ARotationObservedState.A2:
        if (
            current.step is CredentialMutationStep.UPDATE_A_PASSWORDSAFE
            and current.effect_state is IntentEffectState.OBSERVED
        ):
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.PROGRESS_CONTRADICTS_REALITY,
            )
        if current.step is CredentialMutationStep.RESET_A_KEYSTONE:
            _write_converge_intent(
                session, step=current.step,
                effect=IntentEffectState.OBSERVED, now=now,
            )
        return
    if state is ARotationObservedState.A3 and current.step in (
        CredentialMutationStep.RESET_A_KEYSTONE,
        CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
    ):
        passwordsafe_observation = None
        if current.step is CredentialMutationStep.UPDATE_A_PASSWORDSAFE:
            details = observation.observation
            assert details is not None
            passwordsafe_observation = (
                details.passwordsafe_record_id,
                details.passwordsafe_version,
            )
        _write_converge_intent(
            session, step=current.step, effect=IntentEffectState.OBSERVED,
            now=now, passwordsafe_observation=passwordsafe_observation,
        )


def _reset_admin_to_staged_a(
    session: _Session, inputs: RotateAConvergeInputs, *,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, breeder: BreederSecretClient,
    management_token: SecretValue, clock: Clock, now: datetime,
) -> AReconciliationResult:
    current = session.transaction.credential_mutation_intent
    if (
        current is not None
        and current.step is CredentialMutationStep.RESET_A_KEYSTONE
        and current.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
    ):
        raise RotateAConvergeError(RotateAConvergeErrorCode.RESET_A_UNRESOLVED)
    staged = _recover_staged_a(session, inputs, breeder=breeder)
    _write_converge_intent(
        session, step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect=IntentEffectState.UNKNOWN, now=now,
    )
    _assert_converge_owned(ownership)
    _write_converge_intent(
        session, step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect=IntentEffectState.DISPATCH_UNRESOLVED, now=now,
    )
    definite_rejection = False
    try:
        keystone.set_user_password(
            user_id=session.transaction.keystone.admin_user_id,
            new_password=staged,
            management_token=management_token,
        )
    except ExternalClientError as error:
        if error.kind is ExternalErrorCode.MUTATION_AMBIGUOUS:
            pass
        else:
            definite_rejection = True
            _write_converge_intent(
                session, step=CredentialMutationStep.RESET_A_KEYSTONE,
                effect=IntentEffectState.UNKNOWN, now=now,
            )
    observed = _observe_a_converge(
        session, inputs, breeder=breeder, passwordsafe=passwordsafe,
        keystone=keystone, clock=clock,
    )
    if observed.status is AReconciliationStatus.INDETERMINATE:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.RESET_A_STATE_INDETERMINATE,
        )
    if observed.status is AReconciliationStatus.INVALID or observed.state is None:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.RESET_A_STATE_INVALID,
        )
    if observed.state is ARotationObservedState.A1:
        code = (
            RotateAConvergeErrorCode.RESET_A_REJECTED
            if definite_rejection
            else RotateAConvergeErrorCode.RESET_A_UNRESOLVED
        )
        raise RotateAConvergeError(code)
    if observed.state is ARotationObservedState.A0:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.RESET_A_STATE_INVALID,
        )
    _write_converge_intent(
        session, step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect=IntentEffectState.OBSERVED, now=now,
    )
    if observed.state is ARotationObservedState.A2:
        _record_converged_state(session, ARotationObservedState.A2, now=now)
    return observed


def _read_passwordsafe_admin(
    session: _Session, inputs: RotateAConvergeInputs, *,
    passwordsafe: PasswordSafeClient,
) -> PasswordSafeCredential:
    try:
        record = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=inputs.passwordsafe_project_id,
            credential_id=session.transaction.passwordsafe.configured_a_record_id,
            expected_username=inputs.admin_username,
        )
    except ExternalClientError:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.PASSWORDSAFE_RECORD_INVALID,
        ) from None
    if (
        record.project_id != inputs.passwordsafe_project_id
        or record.credential_id
        != session.transaction.passwordsafe.configured_a_record_id
        or record.username != inputs.admin_username
        or isinstance(record.version, bool)
        or record.version <= 0
    ):
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.PASSWORDSAFE_RECORD_INVALID,
        )
    return record


def _update_passwordsafe_admin(
    session: _Session, inputs: RotateAConvergeInputs, *,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, breeder: BreederSecretClient,
    clock: Clock, now: datetime,
) -> AReconciliationResult:
    current = session.transaction.credential_mutation_intent
    if (
        current is not None
        and current.step is CredentialMutationStep.UPDATE_A_PASSWORDSAFE
        and current.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
    ):
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_UNRESOLVED,
        )
    staged = _recover_staged_a(session, inputs, breeder=breeder)
    intended = session.transaction.new_a_sha256
    assert intended is not None
    old_generation = _stable_a_verification(
        session.transaction,
    ).credential_generation
    assert old_generation is not None
    _write_converge_intent(
        session, step=CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
        effect=IntentEffectState.UNKNOWN, now=now,
    )
    _assert_converge_owned(ownership)
    _write_converge_intent(
        session, step=CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
        effect=IntentEffectState.DISPATCH_UNRESOLVED, now=now,
    )
    definite_rejection = False
    try:
        passwordsafe.update_password(
            access=inputs.passwordsafe_access,
            project_id=inputs.passwordsafe_project_id,
            credential_id=session.transaction.passwordsafe.configured_a_record_id,
            new_password=staged,
        )
    except ExternalClientError as error:
        if error.kind is ExternalErrorCode.MUTATION_AMBIGUOUS:
            pass
        else:
            definite_rejection = True
            _write_converge_intent(
                session, step=CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
                effect=IntentEffectState.UNKNOWN, now=now,
            )
    try:
        record = _read_passwordsafe_admin(
            session, inputs, passwordsafe=passwordsafe,
        )
    except RotateAConvergeError:
        if definite_rejection:
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_REJECTED,
            ) from None
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_UNRESOLVED,
        ) from None
    try:
        actual_generation = CredentialGeneration.from_secret(record.password)
    except ValueError:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.PASSWORDSAFE_RECORD_INVALID,
        ) from None
    if actual_generation == intended and _same(record.password, staged):
        _write_converge_intent(
            session, step=CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
            effect=IntentEffectState.OBSERVED, now=now,
            passwordsafe_observation=(record.credential_id, record.version),
        )
    elif actual_generation == old_generation:
        code = (
            RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_REJECTED
            if definite_rejection
            else RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_UNRESOLVED
        )
        raise RotateAConvergeError(code)
    else:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.PASSWORDSAFE_UNRELATED_CREDENTIAL,
        )
    observed = _observe_a_converge(
        session, inputs, breeder=breeder, passwordsafe=passwordsafe,
        keystone=keystone, clock=clock,
    )
    if observed.status is AReconciliationStatus.INDETERMINATE:
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.FINAL_STATE_INDETERMINATE,
        )
    if (
        observed.status is AReconciliationStatus.INVALID
        or observed.state is not ARotationObservedState.A3
    ):
        raise RotateAConvergeError(
            RotateAConvergeErrorCode.FINAL_STATE_INVALID,
        )
    return observed


def run_rotate_a_converge(
    inputs: RotateAConvergeInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, breeder: BreederSecretClient,
    clock: Clock = _utc_now,
) -> RotateAConvergeResult:
    """Run/resume only Slice 3E; successful execution stops at observed A3."""
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Slice 3E clock must return a timezone-aware value.")
    now = now.astimezone(timezone.utc)
    session = _Session(state_store, state_store.load())
    try:
        if session.persisted.state.environment != inputs.environment:
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.ENVIRONMENT_MISMATCH,
            )
        if session.persisted.state.current_transaction is None:
            raise RotateAConvergeError(RotateAConvergeErrorCode.NO_TRANSACTION)
        if session.transaction.phase is not RotationPhase.ROTATE_A:
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.UNSUPPORTED_PHASE,
            )
        starting_result = _observe_a_converge(
            session, inputs, breeder=breeder, passwordsafe=passwordsafe,
            keystone=keystone, clock=clock,
        )
        if starting_result.state is ARotationObservedState.A0:
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.ILLEGAL_A0_START,
            )
        _recover_staged_a(session, inputs, breeder=breeder)
        starting_state = _require_converge_state(starting_result)
        authorization = _require_converge_lockout(
            session, inputs, passwordsafe=passwordsafe, keystone=keystone,
            now=now,
        )
        _reconcile_converge_progress(
            session, starting_state, observation=starting_result, now=now,
        )
        current_result = starting_result
        current_state = starting_state
        if current_state is ARotationObservedState.A1:
            current_result = _reset_admin_to_staged_a(
                session, inputs, ownership=ownership, passwordsafe=passwordsafe,
                keystone=keystone, breeder=breeder,
                management_token=authorization.token, clock=clock, now=now,
            )
            assert current_result.state is not None
            current_state = current_result.state
        if current_state is ARotationObservedState.A2:
            if starting_state is ARotationObservedState.A2:
                _record_converged_state(
                    session, ARotationObservedState.A2, now=now,
                )
            current_result = _update_passwordsafe_admin(
                session, inputs, ownership=ownership, passwordsafe=passwordsafe,
                keystone=keystone, breeder=breeder, clock=clock, now=now,
            )
            assert current_result.state is ARotationObservedState.A3
            current_state = ARotationObservedState.A3
        if current_state is not ARotationObservedState.A3:
            raise RotateAConvergeError(
                RotateAConvergeErrorCode.FINAL_STATE_INVALID,
            )
        _require_converge_lockout(
            session, inputs, passwordsafe=passwordsafe, keystone=keystone,
            now=now,
        )
        _record_converged_state(session, ARotationObservedState.A3, now=now)
        return RotateAConvergeResult(
            RotateAConvergeOutcome.A3_ALREADY_ESTABLISHED
            if starting_state is ARotationObservedState.A3
            else RotateAConvergeOutcome.A3_ESTABLISHED,
            starting_state,
            ARotationObservedState.A3,
            session.persisted,
        )
    except RotateAConvergeError as error:
        if session.persisted.state.current_transaction is not None:
            session.write(replace(
                session.transaction,
                status=TransactionStatus.BLOCKED,
                last_error=SafeErrorInfo(error.kind.value, now),
                updated_at=now,
            ))
        raise
