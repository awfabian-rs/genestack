"""Read-only observation and reconciliation of authoritative admin credentials."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from .errors import RepresentationError
from .external_http import ExternalClientError, ExternalErrorCode
from .keystone import (
    KeystoneAuthenticationResult, KeystoneAuthenticationStatus,
    KeystoneAuthIndeterminate, KeystoneAuthRejected,
    KeystoneClient, KeystoneIndeterminateReason, KeystonePasswordAuthRequest,
)
from .model import (
    CredentialContract, CredentialGeneration, RotationPhase, RotationTransaction,
    SecretInventory, SecretValue, VerificationStatus,
)
from .passwordsafe import IdentityAccess, PasswordSafeClient
from .representations import read_credential


class ARotationObservedState(Enum):
    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"


class AReconciliationStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    INDETERMINATE = "indeterminate"


class AReconciliationReason(Enum):
    INVENTORY_NAMESPACE_MISMATCH = "inventory_namespace_mismatch"
    STABLE_A_AUTHORITY_INVALID = "stable_a_authority_invalid"
    BREEDER_MISSING = "breeder_missing"
    BREEDER_MALFORMED = "breeder_malformed"
    BREEDER_IDENTITY_CHANGED = "breeder_identity_changed"
    PASSWORDSAFE_ACCESS_EXPIRED = "passwordsafe_access_expired"
    PASSWORDSAFE_RECORD_INVALID = "passwordsafe_record_invalid"
    PASSWORDSAFE_UNAVAILABLE = "passwordsafe_unavailable"
    NO_INTENDED_GENERATION_DIVERGENCE = "no_intended_generation_divergence"
    EQUAL_UNKNOWN_GENERATION = "equal_unknown_generation"
    PASSWORDSAFE_NEW_BREEDER_OLD = "passwordsafe_new_breeder_old"
    PASSWORDSAFE_NEW_BREEDER_UNKNOWN = "passwordsafe_new_breeder_unknown"
    PASSWORDSAFE_UNKNOWN_BREEDER_NEW = "passwordsafe_unknown_breeder_new"
    DIVERGENT_UNKNOWN_GENERATIONS = "divergent_unknown_generations"
    AUTHENTICATION_NOT_OBSERVED = "authentication_not_observed"
    CURRENT_CREDENTIAL_REJECTED = "current_credential_rejected"
    NEW_CREDENTIAL_REJECTED = "new_credential_rejected"
    NO_VALID_ADMIN_CREDENTIAL = "no_valid_admin_credential"
    AUTHENTICATION_INDETERMINATE = "authentication_indeterminate"
    ADMIN_IDENTITY_SCOPE_MISMATCH = "admin_identity_scope_mismatch"
    BOTH_OLD_AND_NEW_ACCEPTED = "both_old_and_new_accepted"


class AAuthenticationCandidate(Enum):
    OLD = "old"
    NEW = "new"


@dataclass(frozen=True)
class AAuthenticationObservation:
    """Secret-free summary of one fresh Keystone password-authentication attempt."""

    candidate: AAuthenticationCandidate
    status: KeystoneAuthenticationStatus
    expected_admin: bool | None
    indeterminate_reason: KeystoneIndeterminateReason | None

    def __post_init__(self) -> None:
        if self.status is KeystoneAuthenticationStatus.SUCCESS:
            if self.expected_admin is None or self.indeterminate_reason is not None:
                raise ValueError("Successful authentication must record scope validation only.")
        elif self.status is KeystoneAuthenticationStatus.CREDENTIAL_REJECTED:
            if self.expected_admin is not None or self.indeterminate_reason is not None:
                raise ValueError("Rejected authentication cannot carry success metadata.")
        elif self.expected_admin is not None or self.indeterminate_reason is None:
            raise ValueError("Indeterminate authentication must record only its safe reason.")


@dataclass(frozen=True)
class ARotationObservation:
    """Secret-free authoritative facts used to classify A0 through A3."""

    passwordsafe_record_id: int
    passwordsafe_version: int
    passwordsafe_generation: CredentialGeneration
    breeder_uid: str
    breeder_generation: CredentialGeneration
    passwordsafe_and_breeder_equal: bool
    passwordsafe_is_established_old: bool
    breeder_is_established_old: bool
    intended_generation: CredentialGeneration | None
    authentications: tuple[AAuthenticationObservation, ...] = ()

    def __post_init__(self) -> None:
        if self.passwordsafe_record_id <= 0 or self.passwordsafe_version <= 0:
            raise ValueError("PasswordSafe observation identifiers must be positive.")
        if not self.breeder_uid:
            raise ValueError("Breeder UID must be nonempty.")
        candidates = tuple(item.candidate for item in self.authentications)
        if len(candidates) != len(set(candidates)):
            raise ValueError("Each A credential candidate may be observed at most once.")


@dataclass(frozen=True)
class AReconciliationResult:
    status: AReconciliationStatus
    state: ARotationObservedState | None
    reason: AReconciliationReason | None
    observation: ARotationObservation | None

    def __post_init__(self) -> None:
        if self.status is AReconciliationStatus.VALID:
            if self.state is None or self.reason is not None or self.observation is None:
                raise ValueError("A valid reconciliation result must contain only a state and observation.")
        elif self.state is not None or self.reason is None:
            raise ValueError("A blocked reconciliation result must contain only a reason.")


@dataclass(frozen=True)
class ARotationInputs:
    transaction: RotationTransaction
    contract: CredentialContract
    inventory: SecretInventory
    passwordsafe_access: IdentityAccess
    passwordsafe_project_id: int
    admin_username: str = "admin"
    project_name: str = "admin"

    def __post_init__(self) -> None:
        if isinstance(self.passwordsafe_project_id, bool) or self.passwordsafe_project_id <= 0:
            raise ValueError("PasswordSafe project ID must be a positive integer.")
        if not self.admin_username or not self.project_name:
            raise ValueError("Expected Keystone names must be nonempty.")


class _Topology(Enum):
    A0 = "A0"
    A1_OR_A2 = "A1_OR_A2"
    A3 = "A3"


@dataclass(frozen=True)
class _StableAAuthority:
    breeder_uid: str
    old_generation: CredentialGeneration


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _invalid(
    reason: AReconciliationReason,
    observation: ARotationObservation | None,
) -> AReconciliationResult:
    return AReconciliationResult(AReconciliationStatus.INVALID, None, reason, observation)


def _indeterminate(
    reason: AReconciliationReason,
    observation: ARotationObservation | None,
) -> AReconciliationResult:
    return AReconciliationResult(
        AReconciliationStatus.INDETERMINATE, None, reason, observation,
    )


def _valid(
    state: ARotationObservedState,
    observation: ARotationObservation,
) -> AReconciliationResult:
    return AReconciliationResult(AReconciliationStatus.VALID, state, None, observation)


def _topology(
    observation: ARotationObservation,
) -> _Topology | AReconciliationResult:
    intended = observation.intended_generation
    passwordsafe_new = (
        intended is not None and observation.passwordsafe_generation == intended
    )
    breeder_new = intended is not None and observation.breeder_generation == intended

    if intended is None:
        if not observation.passwordsafe_and_breeder_equal:
            return _invalid(
                AReconciliationReason.NO_INTENDED_GENERATION_DIVERGENCE,
                observation,
            )
        if not (
            observation.passwordsafe_is_established_old
            and observation.breeder_is_established_old
        ):
            return _invalid(AReconciliationReason.EQUAL_UNKNOWN_GENERATION, observation)
        return _Topology.A0

    if passwordsafe_new:
        if breeder_new and observation.passwordsafe_and_breeder_equal:
            return _Topology.A3
        reason = (
            AReconciliationReason.PASSWORDSAFE_NEW_BREEDER_OLD
            if observation.breeder_is_established_old
            else AReconciliationReason.PASSWORDSAFE_NEW_BREEDER_UNKNOWN
        )
        return _invalid(reason, observation)

    if breeder_new:
        if not observation.passwordsafe_is_established_old:
            return _invalid(
                AReconciliationReason.PASSWORDSAFE_UNKNOWN_BREEDER_NEW,
                observation,
            )
        return _Topology.A1_OR_A2

    if observation.passwordsafe_and_breeder_equal:
        if observation.passwordsafe_is_established_old:
            return _Topology.A0
        return _invalid(AReconciliationReason.EQUAL_UNKNOWN_GENERATION, observation)

    return _invalid(AReconciliationReason.DIVERGENT_UNKNOWN_GENERATIONS, observation)


def _authentication(
    observation: ARotationObservation,
    candidate: AAuthenticationCandidate,
) -> AAuthenticationObservation | None:
    return next(
        (item for item in observation.authentications if item.candidate is candidate),
        None,
    )


def _classify_single_candidate(
    observation: ARotationObservation,
    *, candidate: AAuthenticationCandidate,
    state: ARotationObservedState,
) -> AReconciliationResult:
    authentication = _authentication(observation, candidate)
    if authentication is None:
        return _indeterminate(
            AReconciliationReason.AUTHENTICATION_NOT_OBSERVED, observation,
        )
    if authentication.status is KeystoneAuthenticationStatus.INDETERMINATE:
        return _indeterminate(
            AReconciliationReason.AUTHENTICATION_INDETERMINATE, observation,
        )
    if authentication.status is KeystoneAuthenticationStatus.CREDENTIAL_REJECTED:
        reason = (
            AReconciliationReason.CURRENT_CREDENTIAL_REJECTED
            if candidate is AAuthenticationCandidate.OLD
            else AReconciliationReason.NEW_CREDENTIAL_REJECTED
        )
        return _invalid(reason, observation)
    if not authentication.expected_admin:
        return _invalid(
            AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH, observation,
        )
    return _valid(state, observation)


def classify_a_rotation(
    observation: ARotationObservation,
) -> AReconciliationResult:
    """Classify current authoritative reality; transaction progress is irrelevant."""
    topology = _topology(observation)
    if isinstance(topology, AReconciliationResult):
        return topology
    if topology is _Topology.A0:
        return _classify_single_candidate(
            observation,
            candidate=AAuthenticationCandidate.OLD,
            state=ARotationObservedState.A0,
        )
    if topology is _Topology.A3:
        return _classify_single_candidate(
            observation,
            candidate=AAuthenticationCandidate.NEW,
            state=ARotationObservedState.A3,
        )

    new_auth = _authentication(observation, AAuthenticationCandidate.NEW)
    old_auth = _authentication(observation, AAuthenticationCandidate.OLD)
    if new_auth is None:
        return _indeterminate(
            AReconciliationReason.AUTHENTICATION_NOT_OBSERVED, observation,
        )
    if new_auth.status is KeystoneAuthenticationStatus.INDETERMINATE:
        return _indeterminate(
            AReconciliationReason.AUTHENTICATION_INDETERMINATE, observation,
        )
    if new_auth.status is KeystoneAuthenticationStatus.SUCCESS:
        if not new_auth.expected_admin:
            return _invalid(
                AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH, observation,
            )
        if old_auth is None:
            return _indeterminate(
                AReconciliationReason.AUTHENTICATION_NOT_OBSERVED, observation,
            )
        if old_auth.status is KeystoneAuthenticationStatus.INDETERMINATE:
            return _indeterminate(
                AReconciliationReason.AUTHENTICATION_INDETERMINATE, observation,
            )
        if old_auth.status is KeystoneAuthenticationStatus.SUCCESS:
            reason = (
                AReconciliationReason.BOTH_OLD_AND_NEW_ACCEPTED
                if old_auth.expected_admin
                else AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH
            )
            return _invalid(reason, observation)
        # A2 requires the determinate distinction that A-new succeeds while
        # established old A is rejected.
        return _valid(ARotationObservedState.A2, observation)

    if old_auth is None:
        return _indeterminate(
            AReconciliationReason.AUTHENTICATION_NOT_OBSERVED, observation,
        )
    if old_auth.status is KeystoneAuthenticationStatus.INDETERMINATE:
        return _indeterminate(
            AReconciliationReason.AUTHENTICATION_INDETERMINATE, observation,
        )
    if old_auth.status is KeystoneAuthenticationStatus.CREDENTIAL_REJECTED:
        return _invalid(AReconciliationReason.NO_VALID_ADMIN_CREDENTIAL, observation)
    if not old_auth.expected_admin:
        return _invalid(
            AReconciliationReason.ADMIN_IDENTITY_SCOPE_MISMATCH, observation,
        )
    return _valid(ARotationObservedState.A1, observation)


def _stable_a_authority(
    transaction: RotationTransaction,
) -> _StableAAuthority | None:
    matches = tuple(
        item
        for item in transaction.verifications
        if item.check_id == "stable-a"
        and item.phase is RotationPhase.PREPARE_B
        and item.status is VerificationStatus.SUCCESS
    )
    if len(matches) != 1:
        return None
    verification = matches[0]
    if not verification.target_uid or verification.credential_generation is None:
        return None
    return _StableAAuthority(
        breeder_uid=verification.target_uid,
        old_generation=verification.credential_generation,
    )


def _summarize_authentication(
    result: KeystoneAuthenticationResult,
    *, candidate: AAuthenticationCandidate,
    inputs: ARotationInputs,
    now: datetime,
) -> AAuthenticationObservation:
    if isinstance(result, KeystoneAuthRejected):
        return AAuthenticationObservation(
            candidate, result.status, None, None,
        )
    if isinstance(result, KeystoneAuthIndeterminate):
        return AAuthenticationObservation(
            candidate, result.status, None, result.reason,
        )
    observed = result.observation
    expected = inputs.transaction.keystone
    valid = (
        observed.user_id == expected.admin_user_id
        and observed.user_name == inputs.admin_username
        and observed.user_domain_id == expected.user_domain_id
        and observed.project_id == expected.project_id
        and observed.project_name == inputs.project_name
        and observed.project_domain_id == expected.project_domain_id
        and observed.expires_at > now
        and any(role.role_id == expected.role_id for role in observed.roles)
    )
    return AAuthenticationObservation(candidate, result.status, valid, None)


def _authenticate(
    keystone: KeystoneClient,
    *, candidate: AAuthenticationCandidate,
    password: SecretValue,
    inputs: ARotationInputs,
    now: datetime,
) -> AAuthenticationObservation:
    expected = inputs.transaction.keystone
    result = keystone.authenticate_password(KeystonePasswordAuthRequest(
        username=inputs.admin_username,
        user_domain_id=expected.user_domain_id,
        project_id=expected.project_id,
        password=password,
    ))
    return _summarize_authentication(
        result, candidate=candidate, inputs=inputs, now=now,
    )


def _passwordsafe_error(
    error: ExternalClientError,
) -> tuple[AReconciliationStatus, AReconciliationReason]:
    if error.kind in (
        ExternalErrorCode.MALFORMED_RESPONSE,
        ExternalErrorCode.RECORD_MISMATCH,
        ExternalErrorCode.NOT_FOUND,
    ):
        return (
            AReconciliationStatus.INVALID,
            AReconciliationReason.PASSWORDSAFE_RECORD_INVALID,
        )
    return (
        AReconciliationStatus.INDETERMINATE,
        AReconciliationReason.PASSWORDSAFE_UNAVAILABLE,
    )


def observe_a_rotation_state(
    inputs: ARotationInputs,
    *,
    passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient,
    clock: Clock = _utc_now,
) -> AReconciliationResult:
    """Read and classify A authority without issuing any external mutation."""
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("A-state observation clock must return a timezone-aware value.")
    now = now.astimezone(timezone.utc)
    if inputs.inventory.namespace != inputs.contract.namespace:
        return _invalid(AReconciliationReason.INVENTORY_NAMESPACE_MISMATCH, None)

    transaction = inputs.transaction
    stable_a = _stable_a_authority(transaction)
    if stable_a is None:
        return _invalid(AReconciliationReason.STABLE_A_AUTHORITY_INVALID, None)

    source = next(
        (
            item for item in inputs.inventory.secrets
            if item.name == inputs.contract.source.secret
        ),
        None,
    )
    if source is None:
        return _invalid(AReconciliationReason.BREEDER_MISSING, None)
    if source.uid != stable_a.breeder_uid:
        return _invalid(AReconciliationReason.BREEDER_IDENTITY_CHANGED, None)
    if inputs.passwordsafe_access.expires_at <= now:
        return _indeterminate(
            AReconciliationReason.PASSWORDSAFE_ACCESS_EXPIRED, None,
        )
    try:
        breeder_password = read_credential(
            source, inputs.contract.source.representation,
        ).password
        breeder_generation = CredentialGeneration.from_secret(breeder_password)
    except (RepresentationError, ValueError):
        return _invalid(AReconciliationReason.BREEDER_MALFORMED, None)

    try:
        passwordsafe_record = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=inputs.passwordsafe_project_id,
            credential_id=transaction.passwordsafe.configured_a_record_id,
            expected_username=inputs.admin_username,
        )
        if (
            passwordsafe_record.project_id != inputs.passwordsafe_project_id
            or passwordsafe_record.credential_id
            != transaction.passwordsafe.configured_a_record_id
            or passwordsafe_record.username != inputs.admin_username
            or isinstance(passwordsafe_record.version, bool)
            or passwordsafe_record.version <= 0
        ):
            return _invalid(AReconciliationReason.PASSWORDSAFE_RECORD_INVALID, None)
        passwordsafe_generation = CredentialGeneration.from_secret(
            passwordsafe_record.password,
        )
    except ExternalClientError as error:
        status, reason = _passwordsafe_error(error)
        return (
            _invalid(reason, None)
            if status is AReconciliationStatus.INVALID
            else _indeterminate(reason, None)
        )
    except ValueError:
        return _invalid(AReconciliationReason.PASSWORDSAFE_RECORD_INVALID, None)

    same = hmac.compare_digest(
        breeder_password.reveal(), passwordsafe_record.password.reveal(),
    )
    intended = transaction.new_a_sha256
    passwordsafe_old = passwordsafe_generation == stable_a.old_generation
    breeder_old = breeder_generation == stable_a.old_generation
    observation = ARotationObservation(
        passwordsafe_record_id=passwordsafe_record.credential_id,
        passwordsafe_version=passwordsafe_record.version,
        passwordsafe_generation=passwordsafe_generation,
        breeder_uid=source.uid,
        breeder_generation=breeder_generation,
        passwordsafe_and_breeder_equal=same,
        passwordsafe_is_established_old=passwordsafe_old,
        breeder_is_established_old=breeder_old,
        intended_generation=intended,
    )
    topology = _topology(observation)
    if isinstance(topology, AReconciliationResult):
        return topology

    authentications: list[AAuthenticationObservation] = []
    if topology is _Topology.A0:
        authentications.append(_authenticate(
            keystone,
            candidate=AAuthenticationCandidate.OLD,
            password=passwordsafe_record.password,
            inputs=inputs,
            now=now,
        ))
    elif topology is _Topology.A3:
        authentications.append(_authenticate(
            keystone,
            candidate=AAuthenticationCandidate.NEW,
            password=breeder_password,
            inputs=inputs,
            now=now,
        ))
    else:
        # New-first follows the recovery design.  The bounded old observation
        # then distinguishes A1 and the anomalous case where both work.
        new_authentication = _authenticate(
            keystone,
            candidate=AAuthenticationCandidate.NEW,
            password=breeder_password,
            inputs=inputs,
            now=now,
        )
        authentications.append(new_authentication)
        if (
            new_authentication.status
            is not KeystoneAuthenticationStatus.INDETERMINATE
        ):
            authentications.append(_authenticate(
                keystone,
                candidate=AAuthenticationCandidate.OLD,
                password=passwordsafe_record.password,
                inputs=inputs,
                now=now,
            ))

    return classify_a_rotation(ARotationObservation(
        passwordsafe_record_id=observation.passwordsafe_record_id,
        passwordsafe_version=observation.passwordsafe_version,
        passwordsafe_generation=observation.passwordsafe_generation,
        breeder_uid=observation.breeder_uid,
        breeder_generation=observation.breeder_generation,
        passwordsafe_and_breeder_equal=observation.passwordsafe_and_breeder_equal,
        passwordsafe_is_established_old=observation.passwordsafe_is_established_old,
        breeder_is_established_old=observation.breeder_is_established_old,
        intended_generation=observation.intended_generation,
        authentications=tuple(authentications),
    ))
