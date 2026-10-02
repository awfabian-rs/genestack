"""Stable-A preflight and observed-state PREPARE_B orchestration.

This module is deliberately finite.  It prepares the alternate credential and
stops after recording the transition to ``SWITCH_TO_B``; it never mutates a
managed consumer or the admin password.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol
from uuid import UUID

from .errors import SafeError
from .external_http import ExternalClientError, ExternalErrorCode
from .keystone import (
    KeystoneAuthIndeterminate, KeystoneAuthObservation, KeystoneAuthRejected,
    KeystoneAuthSuccess, KeystoneClient, KeystonePasswordAuthRequest,
    KeystoneUserObservation,
)
from .model import (
    ConfigurationDigest, CredentialContract,
    CredentialGeneration, CredentialMutationIntent, CredentialMutationStep,
    EnvironmentIdentity, ExecutionIdentity, IntentEffectState, LockoutChangeState,
    LockoutState, PasswordSafeState, PropagationState,
    PropagationWave, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, SafeErrorInfo, SecretInventory, SecretValue,
    TransactionStatus, VerificationResult, VerificationStatus,
)
from .passwords import generate_admin_password
from .passwordsafe import IdentityAccess, PasswordSafeClient, PasswordSafeCredential
from .planning import build_topology_plan
from .representations import read_credential
from .state_store import PersistedState, StateStore


class PrepareBErrorCode(Enum):
    ENVIRONMENT_MISMATCH = "prepare_b_environment_mismatch"
    REQUEST_CONFLICT = "prepare_b_request_conflict"
    TRANSACTION_CONFLICT = "prepare_b_transaction_conflict"
    CONFIGURATION_CHANGED = "prepare_b_configuration_changed"
    IDENTITY_CHANGED = "prepare_b_identity_changed"
    UNSUPPORTED_PHASE = "prepare_b_unsupported_phase"
    TOPOLOGY_UNSAFE = "prepare_b_topology_unsafe"
    BREEDER_CHANGED = "prepare_b_breeder_changed"
    STABLE_A_DISAGREEMENT = "prepare_b_stable_a_disagreement"
    A_AUTH_REJECTED = "prepare_b_a_auth_rejected"
    A_AUTH_INDETERMINATE = "prepare_b_a_auth_indeterminate"
    A_IDENTITY_MISMATCH = "prepare_b_a_identity_mismatch"
    ADMIN_USER_MISMATCH = "prepare_b_admin_user_mismatch"
    LOCKOUT_SUPPRESSED = "prepare_b_lockout_suppressed"
    PASSWORDSAFE_ACCESS_EXPIRED = "prepare_b_passwordsafe_access_expired"
    PASSWORDSAFE_B_UNRESOLVED = "prepare_b_passwordsafe_b_unresolved"
    PASSWORDSAFE_B_UNKNOWN = "prepare_b_passwordsafe_b_unknown"
    B_AUTH_INDETERMINATE = "prepare_b_b_auth_indeterminate"
    B_IDENTITY_MISMATCH = "prepare_b_b_identity_mismatch"
    B_RESET_UNRESOLVED = "prepare_b_b_reset_unresolved"
    B_RESET_FAILED = "prepare_b_b_reset_failed"
    OWNERSHIP_LOST = "prepare_b_ownership_lost"
    EXTERNAL_DEPENDENCY = "prepare_b_external_dependency"
    PASSWORD_GENERATION_FAILED = "prepare_b_password_generation_failed"


_ERROR_MESSAGES: dict[PrepareBErrorCode, str] = {
    kind: "PREPARE_B cannot continue safely; inspect the recorded error category."
    for kind in PrepareBErrorCode
}


class PrepareBError(SafeError):
    """A value-free workflow error suitable for durable recording."""

    def __init__(self, kind: PrepareBErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class OwnershipGuard(Protocol):
    @property
    def requires_recovery_gate(self) -> bool: ...

    def assert_owned(self) -> None: ...


@dataclass(frozen=True)
class PrepareBRequest:
    request_id: UUID
    transaction_id: UUID
    execution: ExecutionIdentity
    environment: EnvironmentIdentity
    configuration_digest: ConfigurationDigest
    keystone: ResolvedKeystoneIdentities
    passwordsafe_project_id: int
    passwordsafe_a_record_id: int
    passwordsafe_b_record_id: int
    admin_username: str = "admin"
    breakglass_username: str = "breakglass"
    project_name: str = "admin"

    def __post_init__(self) -> None:
        ids = (
            self.passwordsafe_project_id,
            self.passwordsafe_a_record_id,
            self.passwordsafe_b_record_id,
        )
        if any(isinstance(value, bool) or value <= 0 for value in ids):
            raise ValueError("PasswordSafe identifiers must be positive integers.")
        if self.passwordsafe_a_record_id == self.passwordsafe_b_record_id:
            raise ValueError("Admin and breakglass PasswordSafe records must differ.")
        if not self.admin_username or not self.breakglass_username or not self.project_name:
            raise ValueError("Expected Keystone names must be nonempty.")


@dataclass(frozen=True)
class PrepareBInputs:
    request: PrepareBRequest
    contract: CredentialContract
    inventory: SecretInventory
    passwordsafe_access: IdentityAccess


class PrepareBState(Enum):
    B0 = "B0"
    B1 = "B1"
    B2 = "B2"


@dataclass(frozen=True)
class PrepareBResult:
    state: PrepareBState
    persisted: PersistedState
    already_complete: bool


def classify_prepare_b(
    transaction: RotationTransaction,
    current_b: PasswordSafeCredential,
    authentication: KeystoneAuthSuccess | KeystoneAuthRejected | KeystoneAuthIndeterminate | None,
    *,
    request: PrepareBRequest,
    now: datetime,
) -> PrepareBState:
    """Classify B0/B1/B2 from current external observations.

    Durable transaction data identifies the intended generation, but never
    substitutes for the current PasswordSafe value or fresh Keystone auth.
    ``None`` authentication means the caller has not yet attempted B auth.
    """
    intended = transaction.new_b_sha256
    if (
        intended is None
        or CredentialGeneration.from_secret(current_b.password) != intended
    ):
        return PrepareBState.B0
    if authentication is None or isinstance(authentication, KeystoneAuthRejected):
        return PrepareBState.B1
    if isinstance(authentication, KeystoneAuthIndeterminate):
        raise PrepareBError(PrepareBErrorCode.B_AUTH_INDETERMINATE)
    _validate_auth(
        authentication.observation,
        expected_user_id=request.keystone.breakglass_user_id,
        expected_username=request.breakglass_username,
        request=request,
        now=now,
        error=PrepareBErrorCode.B_IDENTITY_MISMATCH,
    )
    return PrepareBState.B2


@dataclass(frozen=True)
class _StableA:
    password: SecretValue
    passwordsafe_a: PasswordSafeCredential
    passwordsafe_b: PasswordSafeCredential
    authentication: KeystoneAuthSuccess
    breeder_uid: str


PasswordGenerator = Callable[[], SecretValue]
Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _same(left: SecretValue, right: SecretValue) -> bool:
    return hmac.compare_digest(left.reveal(), right.reveal())


def _external_error(kind: ExternalErrorCode) -> PrepareBError:
    if kind is ExternalErrorCode.MUTATION_AMBIGUOUS:
        return PrepareBError(PrepareBErrorCode.EXTERNAL_DEPENDENCY)
    return PrepareBError(PrepareBErrorCode.EXTERNAL_DEPENDENCY)


def _validate_auth(
    observed: KeystoneAuthObservation, *, expected_user_id: str,
    expected_username: str, request: PrepareBRequest, now: datetime,
    error: PrepareBErrorCode,
) -> None:
    valid = (
        observed.user_id == expected_user_id
        and observed.user_name == expected_username
        and observed.user_domain_id == request.keystone.user_domain_id
        and observed.project_id == request.keystone.project_id
        and observed.project_name == request.project_name
        and observed.project_domain_id == request.keystone.project_domain_id
        and observed.expires_at > now
        and any(role.role_id == request.keystone.role_id for role in observed.roles)
    )
    if not valid:
        raise PrepareBError(error)


def _validate_admin_user(
    observed: KeystoneUserObservation, request: PrepareBRequest,
) -> None:
    if (
        observed.user_id != request.keystone.admin_user_id
        or observed.name != request.admin_username
        or observed.domain_id != request.keystone.user_domain_id
        or not observed.enabled
        or observed.default_project_id not in (None, request.keystone.project_id)
    ):
        raise PrepareBError(PrepareBErrorCode.ADMIN_USER_MISMATCH)
    if observed.ignore_lockout_failure_attempts:
        raise PrepareBError(PrepareBErrorCode.LOCKOUT_SUPPRESSED)


def _authenticate(
    client: KeystoneClient, *, username: str, password: SecretValue,
    request: PrepareBRequest,
) -> KeystoneAuthSuccess | KeystoneAuthRejected | KeystoneAuthIndeterminate:
    return client.authenticate_password(KeystonePasswordAuthRequest(
        username=username,
        user_domain_id=request.keystone.user_domain_id,
        project_id=request.keystone.project_id,
        password=password,
    ))


def _find_source(inputs: PrepareBInputs) -> tuple[SecretValue, str]:
    if not build_topology_plan(inputs.contract, inputs.inventory).topology_checks_passed:
        raise PrepareBError(PrepareBErrorCode.TOPOLOGY_UNSAFE)
    source = next(
        (item for item in inputs.inventory.secrets if item.name == inputs.contract.source.secret),
        None,
    )
    if source is None:
        raise PrepareBError(PrepareBErrorCode.TOPOLOGY_UNSAFE)
    return read_credential(source, inputs.contract.source.representation).password, source.uid


def _observe_stable_a(
    inputs: PrepareBInputs, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, *, now: datetime,
) -> _StableA:
    if inputs.passwordsafe_access.expires_at <= now:
        raise PrepareBError(PrepareBErrorCode.PASSWORDSAFE_ACCESS_EXPIRED)
    breeder, breeder_uid = _find_source(inputs)
    request = inputs.request
    try:
        record_a = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=request.passwordsafe_project_id,
            credential_id=request.passwordsafe_a_record_id,
            expected_username=request.admin_username,
        )
        record_b = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=request.passwordsafe_project_id,
            credential_id=request.passwordsafe_b_record_id,
            expected_username=request.breakglass_username,
        )
    except ExternalClientError as exc:
        raise _external_error(exc.kind) from None
    if not _same(record_a.password, breeder):
        raise PrepareBError(PrepareBErrorCode.STABLE_A_DISAGREEMENT)
    authentication = _authenticate(
        keystone, username=request.admin_username, password=breeder, request=request,
    )
    if isinstance(authentication, KeystoneAuthRejected):
        raise PrepareBError(PrepareBErrorCode.A_AUTH_REJECTED)
    if isinstance(authentication, KeystoneAuthIndeterminate):
        raise PrepareBError(PrepareBErrorCode.A_AUTH_INDETERMINATE)
    _validate_auth(
        authentication.observation,
        expected_user_id=request.keystone.admin_user_id,
        expected_username=request.admin_username,
        request=request,
        now=now,
        error=PrepareBErrorCode.A_IDENTITY_MISMATCH,
    )
    try:
        admin_user = keystone.get_user(
            user_id=request.keystone.admin_user_id,
            management_token=authentication.token,
        )
    except ExternalClientError as exc:
        raise _external_error(exc.kind) from None
    _validate_admin_user(admin_user, request)
    return _StableA(breeder, record_a, record_b, authentication, breeder_uid)


def _upsert_verification(
    transaction: RotationTransaction, *, check_id: str,
    status: VerificationStatus, checked_at: datetime, detail_code: str,
    target_uid: str | None = None,
    generation: CredentialGeneration | None = None,
) -> RotationTransaction:
    item = VerificationResult(
        check_id=check_id,
        phase=RotationPhase.PREPARE_B,
        status=status,
        checked_at=checked_at,
        detail_code=detail_code,
        target_uid=target_uid,
        credential_generation=generation,
    )
    retained = tuple(
        value for value in transaction.verifications
        if not (value.check_id == check_id and value.phase is RotationPhase.PREPARE_B)
    )
    return replace(transaction, verifications=(*retained, item), updated_at=checked_at)


class _StateSession:
    def __init__(self, store: StateStore, persisted: PersistedState) -> None:
        self.store = store
        self.persisted = persisted

    @property
    def transaction(self) -> RotationTransaction:
        result = self.persisted.state.current_transaction
        if result is None:
            raise RuntimeError("PREPARE_B state session has no transaction.")
        return result

    def write(self, transaction: RotationTransaction) -> RotationTransaction:
        document = replace(self.persisted.state, current_transaction=transaction)
        self.persisted = self.store.update(self.persisted.revision, document)
        return self.transaction

    def block(self, error: PrepareBError, now: datetime) -> None:
        transaction = replace(
            self.transaction,
            status=TransactionStatus.BLOCKED,
            last_error=SafeErrorInfo(error.kind.value, now),
            updated_at=now,
        )
        self.write(transaction)


def _prior_breeder_uid(transaction: RotationTransaction) -> str | None:
    return next((
        item.target_uid for item in transaction.verifications
        if item.check_id == "stable-a" and item.phase is RotationPhase.PREPARE_B
    ), None)


def _new_transaction(inputs: PrepareBInputs, stable: _StableA, now: datetime) -> RotationTransaction:
    request = inputs.request
    transaction = RotationTransaction(
        transaction_id=request.transaction_id,
        request_id=request.request_id,
        execution=request.execution,
        configuration_digest=request.configuration_digest,
        keystone=request.keystone,
        created_at=now,
        updated_at=now,
        phase=RotationPhase.PREPARE_B,
        status=TransactionStatus.ACTIVE,
        last_error=None,
        new_a_sha256=None,
        new_b_sha256=None,
        passwordsafe=PasswordSafeState(
            configured_a_record_id=request.passwordsafe_a_record_id,
            configured_b_record_id=request.passwordsafe_b_record_id,
            observed_a_record_id=stable.passwordsafe_a.credential_id,
            observed_b_record_id=stable.passwordsafe_b.credential_id,
            original_a_version=stable.passwordsafe_a.version,
            observed_a_version=stable.passwordsafe_a.version,
            observed_b_version=stable.passwordsafe_b.version,
        ),
        credential_mutation_intent=None,
        propagation=PropagationState(PropagationWave((), ()), PropagationWave((), ())),
        lockout=LockoutState(
            initial_ignore_lockout_failure_attempts=False,
            suppression=LockoutChangeState.NOT_INTENDED,
            restoration=LockoutChangeState.NOT_INTENDED,
            latest_ignore_lockout_failure_attempts=False,
            restore_required=False,
        ),
        verifications=(),
    )
    return _upsert_verification(
        transaction,
        check_id="stable-a",
        status=VerificationStatus.SUCCESS,
        checked_at=now,
        detail_code="freshly-verified",
        target_uid=stable.breeder_uid,
        generation=CredentialGeneration.from_secret(stable.password),
    )


def _validate_resume(transaction: RotationTransaction, request: PrepareBRequest) -> None:
    if transaction.request_id != request.request_id:
        raise PrepareBError(PrepareBErrorCode.REQUEST_CONFLICT)
    if transaction.transaction_id != request.transaction_id:
        raise PrepareBError(PrepareBErrorCode.TRANSACTION_CONFLICT)
    if transaction.configuration_digest != request.configuration_digest:
        raise PrepareBError(PrepareBErrorCode.CONFIGURATION_CHANGED)
    if transaction.keystone != request.keystone:
        raise PrepareBError(PrepareBErrorCode.IDENTITY_CHANGED)
    if (
        transaction.passwordsafe.configured_a_record_id != request.passwordsafe_a_record_id
        or transaction.passwordsafe.configured_b_record_id != request.passwordsafe_b_record_id
    ):
        raise PrepareBError(PrepareBErrorCode.CONFIGURATION_CHANGED)


def _assert_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise PrepareBError(PrepareBErrorCode.OWNERSHIP_LOST) from None


def _candidate(
    generator: PasswordGenerator, *, current_a: SecretValue, current_b: SecretValue,
) -> SecretValue:
    for _ in range(32):
        value = generator()
        if not _same(value, current_a) and not _same(value, current_b):
            return value
    raise PrepareBError(PrepareBErrorCode.PASSWORD_GENERATION_FAILED)


def _intent(
    step: CredentialMutationStep, generation: CredentialGeneration,
    effect: IntentEffectState,
) -> CredentialMutationIntent:
    return CredentialMutationIntent(step, None, (), generation, effect, None, None)


def _observe_intent(
    session: _StateSession, *, observed_at: datetime,
    passwordsafe_version: int | None = None,
) -> None:
    current = session.transaction.credential_mutation_intent
    if current is None:
        return
    intent = replace(
        current,
        effect_state=IntentEffectState.OBSERVED,
        effect_observed_at=observed_at,
    )
    transaction = replace(session.transaction, credential_mutation_intent=intent)
    if passwordsafe_version is not None:
        transaction = replace(
            transaction,
            passwordsafe=replace(
                transaction.passwordsafe, observed_b_version=passwordsafe_version,
            ),
        )
    session.write(transaction)


def _stage_b(
    session: _StateSession, stable: _StableA, inputs: PrepareBInputs,
    passwordsafe: PasswordSafeClient, ownership: OwnershipGuard,
    generator: PasswordGenerator, now: datetime,
) -> PasswordSafeCredential:
    transaction = session.transaction
    current_b = stable.passwordsafe_b
    intended = transaction.new_b_sha256
    if classify_prepare_b(
        transaction, current_b, None, request=inputs.request, now=now,
    ) is PrepareBState.B1:
        if (
            transaction.credential_mutation_intent is not None
            and transaction.credential_mutation_intent.step
            is CredentialMutationStep.STAGE_B_PASSWORDSAFE
            and transaction.credential_mutation_intent.effect_state
            is not IntentEffectState.OBSERVED
        ):
            _observe_intent(
                session, observed_at=now, passwordsafe_version=current_b.version,
            )
        return current_b

    previous_intent = transaction.credential_mutation_intent
    if intended is not None:
        if (
            previous_intent is not None
            and previous_intent.step is CredentialMutationStep.STAGE_B_PASSWORDSAFE
            and previous_intent.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
        ):
            raise PrepareBError(PrepareBErrorCode.PASSWORDSAFE_B_UNRESOLVED)
        if current_b.version != transaction.passwordsafe.observed_b_version:
            raise PrepareBError(PrepareBErrorCode.PASSWORDSAFE_B_UNKNOWN)

    value = _candidate(generator, current_a=stable.password, current_b=current_b.password)
    generation = CredentialGeneration.from_secret(value)
    transaction = replace(
        session.transaction,
        new_b_sha256=generation,
        credential_mutation_intent=_intent(
            CredentialMutationStep.STAGE_B_PASSWORDSAFE,
            generation,
            IntentEffectState.UNKNOWN,
        ),
        passwordsafe=replace(
            session.transaction.passwordsafe,
            observed_b_record_id=current_b.credential_id,
            observed_b_version=current_b.version,
        ),
        status=TransactionStatus.ACTIVE,
        last_error=None,
        updated_at=now,
    )
    session.write(transaction)
    _assert_owned(ownership)
    session.write(replace(
        session.transaction,
        credential_mutation_intent=_intent(
            CredentialMutationStep.STAGE_B_PASSWORDSAFE,
            generation,
            IntentEffectState.DISPATCH_UNRESOLVED,
        ),
        updated_at=now,
    ))
    ambiguous = False
    try:
        passwordsafe.update_password(
            access=inputs.passwordsafe_access,
            project_id=inputs.request.passwordsafe_project_id,
            credential_id=inputs.request.passwordsafe_b_record_id,
            new_password=value,
        )
    except ExternalClientError as exc:
        if exc.kind is not ExternalErrorCode.MUTATION_AMBIGUOUS:
            session.write(replace(
                session.transaction,
                credential_mutation_intent=_intent(
                    CredentialMutationStep.STAGE_B_PASSWORDSAFE,
                    generation,
                    IntentEffectState.UNKNOWN,
                ),
                updated_at=now,
            ))
            raise _external_error(exc.kind) from None
        ambiguous = True
    try:
        observed = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=inputs.request.passwordsafe_project_id,
            credential_id=inputs.request.passwordsafe_b_record_id,
            expected_username=inputs.request.breakglass_username,
        )
    except ExternalClientError:
        raise PrepareBError(PrepareBErrorCode.PASSWORDSAFE_B_UNRESOLVED) from None
    if CredentialGeneration.from_secret(observed.password) != generation:
        if ambiguous:
            raise PrepareBError(PrepareBErrorCode.PASSWORDSAFE_B_UNRESOLVED)
        raise PrepareBError(PrepareBErrorCode.PASSWORDSAFE_B_UNKNOWN)
    _observe_intent(session, observed_at=now, passwordsafe_version=observed.version)
    return observed


def _establish_b2(
    session: _StateSession, staged: PasswordSafeCredential,
    inputs: PrepareBInputs, keystone: KeystoneClient,
    ownership: OwnershipGuard, now: datetime,
) -> KeystoneAuthSuccess:
    request = inputs.request
    result = _authenticate(
        keystone,
        username=request.breakglass_username,
        password=staged.password,
        request=request,
    )
    observed_state = classify_prepare_b(
        session.transaction, staged, result, request=request, now=now,
    )
    if observed_state is PrepareBState.B2:
        assert isinstance(result, KeystoneAuthSuccess)
        current = session.transaction.credential_mutation_intent
        if (
            current is not None
            and current.step is CredentialMutationStep.RESET_B_KEYSTONE
            and current.effect_state is not IntentEffectState.OBSERVED
        ):
            _observe_intent(session, observed_at=now)
        return result

    current = session.transaction.credential_mutation_intent
    if (
        current is not None
        and current.step is CredentialMutationStep.RESET_B_KEYSTONE
        and current.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
    ):
        raise PrepareBError(PrepareBErrorCode.B_RESET_UNRESOLVED)
    generation = session.transaction.new_b_sha256
    if generation is None:
        raise RuntimeError("Staged B has no recorded generation.")
    session.write(replace(
        session.transaction,
        credential_mutation_intent=_intent(
            CredentialMutationStep.RESET_B_KEYSTONE,
            generation,
            IntentEffectState.UNKNOWN,
        ),
        updated_at=now,
    ))
    management_token = _fresh_a_token(inputs, keystone, now)
    _assert_owned(ownership)
    session.write(replace(
        session.transaction,
        credential_mutation_intent=_intent(
            CredentialMutationStep.RESET_B_KEYSTONE,
            generation,
            IntentEffectState.DISPATCH_UNRESOLVED,
        ),
        updated_at=now,
    ))
    ambiguous = False
    try:
        keystone.set_user_password(
            user_id=request.keystone.breakglass_user_id,
            new_password=staged.password,
            management_token=management_token,
        )
    except ExternalClientError as exc:
        if exc.kind is not ExternalErrorCode.MUTATION_AMBIGUOUS:
            session.write(replace(
                session.transaction,
                credential_mutation_intent=_intent(
                    CredentialMutationStep.RESET_B_KEYSTONE,
                    generation,
                    IntentEffectState.UNKNOWN,
                ),
                updated_at=now,
            ))
            raise PrepareBError(PrepareBErrorCode.B_RESET_FAILED) from None
        ambiguous = True
    if not ambiguous:
        session.write(replace(
            session.transaction,
            credential_mutation_intent=_intent(
                CredentialMutationStep.RESET_B_KEYSTONE,
                generation,
                IntentEffectState.UNKNOWN,
            ),
            updated_at=now,
        ))
    observed = _authenticate(
        keystone,
        username=request.breakglass_username,
        password=staged.password,
        request=request,
    )
    observed_state = classify_prepare_b(
        session.transaction, staged, observed, request=request, now=now,
    )
    if observed_state is PrepareBState.B1:
        if ambiguous:
            raise PrepareBError(PrepareBErrorCode.B_RESET_UNRESOLVED)
        raise PrepareBError(PrepareBErrorCode.B_RESET_FAILED)
    assert isinstance(observed, KeystoneAuthSuccess)
    _observe_intent(session, observed_at=now)
    return observed


def _fresh_a_token(
    inputs: PrepareBInputs, keystone: KeystoneClient, now: datetime,
) -> SecretValue:
    breeder, _ = _find_source(inputs)
    result = _authenticate(
        keystone,
        username=inputs.request.admin_username,
        password=breeder,
        request=inputs.request,
    )
    if isinstance(result, KeystoneAuthRejected):
        raise PrepareBError(PrepareBErrorCode.A_AUTH_REJECTED)
    if isinstance(result, KeystoneAuthIndeterminate):
        raise PrepareBError(PrepareBErrorCode.A_AUTH_INDETERMINATE)
    _validate_auth(
        result.observation,
        expected_user_id=inputs.request.keystone.admin_user_id,
        expected_username=inputs.request.admin_username,
        request=inputs.request,
        now=now,
        error=PrepareBErrorCode.A_IDENTITY_MISMATCH,
    )
    return result.token


def run_prepare_b(
    inputs: PrepareBInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, password_generator: PasswordGenerator = generate_admin_password,
    clock: Clock = _utc_now,
) -> PrepareBResult:
    """Run or resume PREPARE_B from fresh external observations.

    Every external mutation is preceded by durable pre-dispatch intent, an
    ownership assertion, and then a durable dispatch boundary.  A successful
    return has only advanced durable phase to ``SWITCH_TO_B``; no propagation
    work is performed here.
    """
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("PREPARE_B clock must return a timezone-aware value.")
    persisted = state_store.load()
    if persisted.state.environment != inputs.request.environment:
        raise PrepareBError(PrepareBErrorCode.ENVIRONMENT_MISMATCH)
    existing = persisted.state.current_transaction
    if existing is not None:
        _validate_resume(existing, inputs.request)
        if existing.phase is not RotationPhase.PREPARE_B:
            if existing.phase in (
                RotationPhase.SWITCH_TO_B, RotationPhase.VERIFY_B,
                RotationPhase.ROTATE_A, RotationPhase.SWITCH_TO_A,
                RotationPhase.VERIFY_A,
            ):
                return PrepareBResult(PrepareBState.B2, persisted, True)
            raise PrepareBError(PrepareBErrorCode.UNSUPPORTED_PHASE)

    try:
        stable = _observe_stable_a(inputs, passwordsafe, keystone, now=now)
    except PrepareBError as error:
        # A new invalid request never creates a transaction or performs a mutation.
        if existing is None:
            raise
        session = _StateSession(state_store, persisted)
        session.block(error, now)
        raise

    if existing is None:
        transaction = _new_transaction(inputs, stable, now)
        document = replace(persisted.state, current_transaction=transaction)
        persisted = state_store.update(persisted.revision, document)
    session = _StateSession(state_store, persisted)

    try:
        prior_uid = _prior_breeder_uid(session.transaction)
        if prior_uid is not None and prior_uid != stable.breeder_uid:
            raise PrepareBError(PrepareBErrorCode.BREEDER_CHANGED)
        transaction = replace(
            session.transaction,
            execution=inputs.request.execution,
            status=TransactionStatus.ACTIVE,
            last_error=None,
            passwordsafe=replace(
                session.transaction.passwordsafe,
                observed_a_record_id=stable.passwordsafe_a.credential_id,
                observed_a_version=stable.passwordsafe_a.version,
            ),
            updated_at=now,
        )
        transaction = _upsert_verification(
            transaction,
            check_id="stable-a",
            status=VerificationStatus.SUCCESS,
            checked_at=now,
            detail_code="freshly-verified",
            target_uid=stable.breeder_uid,
            generation=CredentialGeneration.from_secret(stable.password),
        )
        session.write(transaction)

        # Always use a new current-B read for classification; transaction progress
        # is evidence only and never overrides this observation.
        current_b = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=inputs.request.passwordsafe_project_id,
            credential_id=inputs.request.passwordsafe_b_record_id,
            expected_username=inputs.request.breakglass_username,
        )
        stable = replace(stable, passwordsafe_b=current_b)
        staged = _stage_b(
            session, stable, inputs, passwordsafe, ownership,
            password_generator, now,
        )
        _establish_b2(session, staged, inputs, keystone, ownership, now)

        final_a = _observe_stable_a(inputs, passwordsafe, keystone, now=clock())
        if not _same(final_a.password, stable.password):
            raise PrepareBError(PrepareBErrorCode.STABLE_A_DISAGREEMENT)
        final_b = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=inputs.request.passwordsafe_project_id,
            credential_id=inputs.request.passwordsafe_b_record_id,
            expected_username=inputs.request.breakglass_username,
        )
        generation = session.transaction.new_b_sha256
        if generation is None or CredentialGeneration.from_secret(final_b.password) != generation:
            raise PrepareBError(PrepareBErrorCode.PASSWORDSAFE_B_UNKNOWN)
        final_b_auth = _authenticate(
            keystone,
            username=inputs.request.breakglass_username,
            password=final_b.password,
            request=inputs.request,
        )
        if not isinstance(final_b_auth, KeystoneAuthSuccess):
            raise PrepareBError(
                PrepareBErrorCode.B_AUTH_INDETERMINATE
                if isinstance(final_b_auth, KeystoneAuthIndeterminate)
                else PrepareBErrorCode.B_RESET_FAILED
            )
        _validate_auth(
            final_b_auth.observation,
            expected_user_id=inputs.request.keystone.breakglass_user_id,
            expected_username=inputs.request.breakglass_username,
            request=inputs.request,
            now=clock(),
            error=PrepareBErrorCode.B_IDENTITY_MISMATCH,
        )
        transaction = _upsert_verification(
            session.transaction,
            check_id="breakglass-b2",
            status=VerificationStatus.SUCCESS,
            checked_at=clock(),
            detail_code="freshly-authorized",
            generation=generation,
        )
        transaction = replace(
            transaction,
            phase=RotationPhase.SWITCH_TO_B,
            status=TransactionStatus.ACTIVE,
            last_error=None,
            credential_mutation_intent=None,
            passwordsafe=replace(
                transaction.passwordsafe,
                observed_b_record_id=final_b.credential_id,
                observed_b_version=final_b.version,
            ),
        )
        session.write(transaction)
        return PrepareBResult(PrepareBState.B2, session.persisted, False)
    except PrepareBError as error:
        session.block(error, clock())
        raise
    except ExternalClientError as error:
        safe = _external_error(error.kind)
        session.block(safe, clock())
        raise safe from None
