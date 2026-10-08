"""Slice 4F: the transaction-level ``VERIFY_B`` gate.

``run_verify_b`` freshly establishes, from current external state only, that
the B safety bridge created by ``SWITCH_TO_B`` is real and sufficient to
permit ``ROTATE_A`` to begin.  It is the hard gate before ``ROTATE_A``: it
never mutates the ``admin`` credential, never writes a propagated Secret, and
never dispatches or re-runs a workload restart.  It reads and observes.
Aside from the ownership-fenced execution bookkeeping re-stamp that a
resume/takeover may first persist, the only semantic transaction write
performed by ``VERIFY_B`` is the successful ``VERIFY_B`` -> ``ROTATE_A``
phase advance plus its credential-free verification receipt.  A verification
failure never advances the phase and never writes a ``verify-b-complete``
receipt; if a re-stamp was required it may have persisted only that
credential-free execution bookkeeping.

Historical progress is never accepted as current verification.  The durable
transaction is used to know *what* should be verified (phase, B generation,
immutable wave intent, derived restart actions); fresh external observations
determine *whether it is actually true*:

```text
fresh breakglass observation (PasswordSafe) + fresh breakglass authentication
    ->
fresh admin breeder observation (must still anchor the stable-a receipt)
    ->
fresh per-location structural classification of every participating
identity: active location (all must currently be the verified B credential)
    ->
every derived restart action durably complete
    ->
fresh observation that every affected workload is rolled out and ready
    ->
advance the durable phase to ROTATE_A (ownership-fenced) and stop
```

Fixed ``identity: admin`` propagated locations and the canonical
``keystone-admin`` breeder are not part of the B transition: the breeder must
remain the old-A reference, and fixed-admin locations are not required to
hold B.  They are never treated as verification failures merely for remaining
on ``admin``.

Re-entry is safe and deterministic: a transaction already past ``VERIFY_B``
is recognized and reported without re-running the checks or regressing the
phase.  A crash after the checks but before the phase advance simply causes
the checks to run again.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from .discovery import classify
from .errors import SafeError
from .external_http import ExternalClientError
from .keystone import (
    KeystoneAuthIndeterminate, KeystoneAuthObservation, KeystoneAuthRejected,
    KeystoneAuthSuccess, KeystoneClient, KeystonePasswordAuthRequest,
)
from .model import (
    CredentialContract, CredentialGeneration, CredentialState,
    EnvironmentIdentity, ExecutionIdentity, Identity, IdentityBinding,
    LocationRole, ReferenceCredentials, ResolvedKeystoneIdentities,
    RotationPhase, RotationTransaction, RuntimeActionState, SecretInventory,
    SecretSnapshot, SecretValue, TransactionStatus, VerificationResult,
    VerificationStatus, WorkloadKind, WorkloadRef,
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
    "VerifyBErrorCode", "VerifyBError", "VerifyBOutcome", "VerifyBRequest",
    "VerifyBInputs", "VerifyBResult", "run_verify_b",
]


class VerifyBErrorCode(Enum):
    NO_TRANSACTION = "verify_b_no_transaction"
    UNSUPPORTED_PHASE = "verify_b_unsupported_phase"
    ENVIRONMENT_MISMATCH = "verify_b_environment_mismatch"
    B_GENERATION_MISSING = "verify_b_b_generation_missing"
    PREPARE_B_PREREQUISITE_MISSING = "verify_b_prepare_b_prerequisite_missing"
    PREPARE_B_PREREQUISITE_INVALID = "verify_b_prepare_b_prerequisite_invalid"
    CONFIGURATION_MISMATCH = "verify_b_configuration_mismatch"
    B_CREDENTIAL_UNRESOLVED = "verify_b_b_credential_unresolved"
    B_IDENTITY_MISMATCH = "verify_b_b_identity_mismatch"
    B_AUTH_INDETERMINATE = "verify_b_b_auth_indeterminate"
    ADMIN_REFERENCE_INVALID = "verify_b_admin_reference_invalid"
    CONTRACT_DRIFT = "verify_b_contract_drift"
    LOCATION_UNVERIFIED = "verify_b_location_unverified"
    RESTART_INCOMPLETE = "verify_b_restart_incomplete"
    WORKLOAD_UNHEALTHY = "verify_b_workload_unhealthy"
    PROGRESS_PERSISTENCE_FAILED = "verify_b_progress_persistence_failed"
    EXTERNAL_DEPENDENCY = "verify_b_external_dependency"


_ERROR_MESSAGES: dict[VerifyBErrorCode, str] = {
    VerifyBErrorCode.NO_TRANSACTION:
        "There is no current transaction to verify.",
    VerifyBErrorCode.UNSUPPORTED_PHASE:
        "The current transaction is not in the VERIFY_B phase.",
    VerifyBErrorCode.ENVIRONMENT_MISMATCH:
        "The supplied environment does not match the transaction environment.",
    VerifyBErrorCode.B_GENERATION_MISSING:
        "The transaction has no established breakglass credential generation.",
    VerifyBErrorCode.PREPARE_B_PREREQUISITE_MISSING:
        "A required durable completion record is absent; the transaction cannot be verified.",
    VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID:
        "A required durable completion record is malformed or contradictory.",
    VerifyBErrorCode.CONFIGURATION_MISMATCH:
        "The transaction identity or configuration does not match the request.",
    VerifyBErrorCode.B_CREDENTIAL_UNRESOLVED:
        "The breakglass credential could not be freshly obtained and verified.",
    VerifyBErrorCode.B_IDENTITY_MISMATCH:
        "Fresh breakglass authentication does not match the recorded identity.",
    VerifyBErrorCode.B_AUTH_INDETERMINATE:
        "Fresh breakglass authentication was indeterminate; verification does not proceed.",
    VerifyBErrorCode.ADMIN_REFERENCE_INVALID:
        "The canonical admin breeder could not be freshly observed as the stable-A reference.",
    VerifyBErrorCode.CONTRACT_DRIFT:
        "The credential contract does not match the durable propagation obligation.",
    VerifyBErrorCode.LOCATION_UNVERIFIED:
        "A participating breakglass location is not freshly observed at the verified breakglass credential.",
    VerifyBErrorCode.RESTART_INCOMPLETE:
        "A restart required by the B transition has not durably completed.",
    VerifyBErrorCode.WORKLOAD_UNHEALTHY:
        "A workload affected by the B transition is not freshly observed rolled out and ready.",
    VerifyBErrorCode.PROGRESS_PERSISTENCE_FAILED:
        "Durable VERIFY_B progress could not be persisted safely.",
    VerifyBErrorCode.EXTERNAL_DEPENDENCY:
        "An external credential-system or Kubernetes dependency is unavailable; verification does not proceed.",
}


class VerifyBError(SafeError):
    """A value-free, stable ``VERIFY_B`` verification failure."""

    def __init__(self, kind: VerifyBErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class VerifyBOutcome(Enum):
    """Typed result vocabulary for one ``VERIFY_B`` invocation.

    ``VERIFIED`` permits ``ROTATE_A`` to begin; it is set only when every
    required verification held under fresh observation at the time of the
    phase advance.  ``NOT_VERIFIED`` means the B safety bridge does not
    currently hold (a recoverable, re-observable condition); the transaction
    remains in ``VERIFY_B``.  ``ALREADY_ADVANCED`` is the deterministic
    idempotency result for a transaction that is already past ``VERIFY_B``.
    ``UNABLE_TO_VERIFY`` means the current state is invalid, contradictory, or
    missing required evidence, or an external dependency is unavailable; no
    verification receipt is written and the phase is not advanced.  A failed
    verification may persist only the credential-free execution bookkeeping
    re-stamp (the same discipline as every other phase on resume); it never
    persists a ``verify-b-complete`` receipt.  The transaction remains
    resumable in ``VERIFY_B``.
    """

    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    ALREADY_ADVANCED = "already_advanced"
    UNABLE_TO_VERIFY = "unable_to_verify"


@dataclass(frozen=True)
class VerifyBRequest:
    """Caller-supplied identity/configuration to validate against the transaction.

    Mirrors the ``SWITCH_TO_B`` resume validation: a re-execution must prove
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
class VerifyBInputs:
    request: VerifyBRequest
    contract: CredentialContract
    passwordsafe_access: IdentityAccess
    secret_client: CredentialSecretClient
    workload_client: WorkloadClient


@dataclass(frozen=True)
class VerifyBResult:
    """Credential-free outcome of one ``VERIFY_B`` invocation.

    ``verified`` is true only for the ``VERIFIED`` outcome.  The transaction
    identifier and phase name the resulting durable state; no credential
    value, token, or raw external content appears in this result.
    """

    outcome: VerifyBOutcome
    persisted: PersistedState
    transaction_id: object
    phase: RotationPhase
    verified: bool = False

    def __repr__(self) -> str:
        return (
            f"VerifyBResult(outcome={self.outcome.value!r}, "
            f"phase={self.phase.value!r})"
        )

    __str__ = __repr__


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _assert_owned(ownership: OwnershipGuard) -> None:
    """Assert current Lease ownership in this slice's error vocabulary.

    Every correctness-sensitive durable write (the execution re-stamp and the
    phase advance) is preceded by this assertion; the same discipline the
    earlier slices apply to their progress writes.  Ownership loss surfaces as
    ``PROGRESS_PERSISTENCE_FAILED`` (this slice's category), never as a
    foreign slice's error type.
    """
    try:
        ownership.assert_owned()
    except SafeError:
        raise VerifyBError(VerifyBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


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
        raise VerifyBError(VerifyBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def _verify_prepare_b_evidence(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> tuple[VerificationResult, VerificationResult]:
    """Require the durable PREPARE_B completion evidence.

    Successful PREPARE_B leaves exactly two durable receipts, each explicitly
    at phase ``PREPARE_B``: ``stable-a`` (old-A generation plus the breeder
    UID it verified) and ``breakglass-b2`` (B generation).  Both are
    mandatory and must be ``SUCCESS``; a receipt is accepted only if it
    matches on both ``check_id`` and ``phase``.  Missing, wrong-phase,
    non-success, malformed, or generation-inconsistent evidence fails closed
    before any verification work.  The receipts are *validated*, never
    synthesized.
    """
    def single(check_id: str) -> VerificationResult:
        matches = tuple(
            item for item in transaction.verifications
            if item.check_id == check_id and item.phase is RotationPhase.PREPARE_B
        )
        if len(matches) == 0:
            raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_MISSING)
        if len(matches) > 1:
            raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
        return matches[0]

    stable_a = single("stable-a")
    if stable_a.status is not VerificationStatus.SUCCESS:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    b2 = single("breakglass-b2")
    if b2.status is not VerificationStatus.SUCCESS:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if stable_a.credential_generation is None or stable_a.target_uid is None:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation is None:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if b2.credential_generation != generation:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    return stable_a, b2


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
    """Require the fresh token to be the recorded breakglass identity/scope.

    Mirrors the ``SWITCH_TO_B`` identity validation: the observed user,
    domain, project, role and expiry must all match the resolved identity,
    otherwise the success is not evidence of the breakglass bridge.
    """
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
        raise VerifyBError(VerifyBErrorCode.B_IDENTITY_MISMATCH)


def _switch_to_b_complete_receipt(
    transaction: RotationTransaction, *, generation: CredentialGeneration,
) -> VerificationResult:
    """Require the durable, phase-qualified ``SWITCH_TO_B`` completion receipt.

    ``SWITCH_TO_B`` records exactly one ``switch-to-b-complete`` receipt at
    phase ``SWITCH_TO_B`` carrying the B generation when it advances the phase
    to ``VERIFY_B``.  A transaction in ``VERIFY_B`` without it has not
    durably completed the cutover, so there is no verified B wave to confirm
    against; a same-named receipt from another phase is not that evidence, and
    more than one matching receipt is an ambiguous record.  The receipt is
    *validated*, never synthesized.
    """
    matches = tuple(
        item for item in transaction.verifications
        if item.check_id == "switch-to-b-complete"
        and item.phase is RotationPhase.SWITCH_TO_B
    )
    if len(matches) == 0:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_MISSING)
    if len(matches) > 1:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    receipt = matches[0]
    if receipt.status is not VerificationStatus.SUCCESS:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    if receipt.credential_generation != generation:
        raise VerifyBError(VerifyBErrorCode.PREPARE_B_PREREQUISITE_INVALID)
    return receipt


def _current_inventory(
    inputs: VerifyBInputs,
) -> tuple[SecretInventory, tuple[str, ...]]:
    """Re-read every contracted Secret through the supplied client.

    Mirrors the ``SWITCH_TO_B`` inventory builder: the breeder reference and
    the per-location classification views all come from the same fresh client
    reads.  A contracted Secret that is absent is *observed state* (a location
    whose expected Secret is missing), not a dependency failure; it is
    recorded here as ``None`` and reported by the classification step.  A
    transport-level read failure remains ``EXTERNAL_DEPENDENCY``.
    """
    contract = inputs.contract
    names = sorted({location.secret for location in contract.locations})
    secrets: list[SecretSnapshot] = []
    missing: list[str] = []
    for name in names:
        try:
            snapshot = inputs.secret_client.read(contract.namespace, name)
        except CredentialSecretClientError as exc:
            if exc.kind is CredentialSecretClientErrorCode.NOT_FOUND:
                missing.append(name)
            else:
                raise VerifyBError(VerifyBErrorCode.EXTERNAL_DEPENDENCY) from None
        else:
            secrets.append(snapshot)
    return SecretInventory(contract.namespace, None, tuple(secrets)), tuple(missing)


def _observe_admin_reference(
    inputs: VerifyBInputs, inventory: SecretInventory, *,
    stable_a: VerificationResult,
) -> SecretValue:
    """Freshly read and validate the canonical admin breeder as the A reference.

    Location classification compares against the known credential references;
    the admin reference is read structurally from the canonical breeder
    Secret and cross-checked against the durable ``stable-a`` receipt
    recorded by ``PREPARE_B``: the breeder must still match the recorded
    stable-A generation and the breeder Secret UID that ``PREPARE_B``
    verified.  A changed or regenerated breeder fails closed because a
    location that "still matches admin" would then be matching a wrong
    reference.  This reference is specifically used to verify that fixed
    ``identity: admin``, ``role: propagated`` locations remain on the
    correct admin credential -- a fixed-admin location must match it, and
    a breakglass credential there is an invalid state, not an early
    convergence -- and to classify the participating locations.
    """
    source = inputs.contract.source
    snapshot = next(
        (
            item for item in inventory.secrets
            if item.namespace == inputs.contract.namespace
            and item.name == source.secret
        ),
        None,
    )
    if snapshot is None:
        raise VerifyBError(VerifyBErrorCode.ADMIN_REFERENCE_INVALID)
    try:
        observed = read_credential(snapshot, source.representation)
    except SafeError:
        raise VerifyBError(VerifyBErrorCode.ADMIN_REFERENCE_INVALID) from None
    stable_generation = stable_a.credential_generation
    stable_uid = stable_a.target_uid
    assert stable_generation is not None and stable_uid is not None
    if CredentialGeneration.from_secret(observed.password) != stable_generation:
        raise VerifyBError(VerifyBErrorCode.ADMIN_REFERENCE_INVALID)
    if snapshot.uid != stable_uid:
        raise VerifyBError(VerifyBErrorCode.ADMIN_REFERENCE_INVALID)
    return observed.password


def _verify_participating_locations(
    inputs: VerifyBInputs, *,
    inventory: SecretInventory, desired: DesiredCredential,
    missing_secrets: tuple[str, ...], stable_a: VerificationResult,
) -> None:
    """Freshly classify every participating location against verified B.

    The verification set is the *complete applicable membership* of the B
    transition: every ``role: propagated``, ``identity: active`` location in
    the current contract (the same membership the immutable wave intent was
    derived from).  Progress flags (``applied_location_ids``) are not proof:
    a location may have been at target before the wave and therefore absent
    from the changed set, yet still be required to hold B now.

    Every location must freshly parse through its declared representation and
    structurally equal the verified breakglass credential -- username
    ``breakglass`` and the exact B password -- per the location's exact
    fields.  Any of: missing Secret, unparseable representation, unknown
    credential, still on ``admin``, a different breakglass password, or any
    other unrecognized state fails the gate.

    Fixed ``identity: admin`` propagated locations do *not* participate in
    the ``admin -> breakglass -> admin`` identity transition: the contract
    defines them as remaining associated with ``admin``.  They are therefore
    required to match the verified admin reference -- nothing else.  A
    fixed-admin location containing the breakglass credential is not an early
    convergence; it is an invalid state for that contract location (a
    password-only fixed-admin consumer semantically interprets the stored
    password as belonging to ``admin``).  Missing Secrets, malformed
    representations, unknown credentials, and wrong admin passwords all fail
    closed, exactly like a participating location.  The source is checked
    separately as the canonical breeder anchor.
    """
    contract = inputs.contract
    missing = set(missing_secrets)
    admin_reference = _observe_admin_reference(
        inputs, inventory, stable_a=stable_a,
    )
    by_name = {
        secret.name: secret for secret in inventory.secrets
        if secret.namespace == contract.namespace
    }
    references = ReferenceCredentials(admin_reference, desired.password)
    for location in sorted(contract.locations, key=lambda item: item.name):
        if location.role is not LocationRole.PROPAGATED:
            continue
        if location.secret in missing:
            # A contracted propagated location whose Secret is absent is
            # unexplained state regardless of its identity binding: fail
            # closed rather than silently dropping it from the obligation.
            raise VerifyBError(VerifyBErrorCode.LOCATION_UNVERIFIED)
        snapshot = by_name.get(location.secret)
        if snapshot is None:
            raise VerifyBError(VerifyBErrorCode.LOCATION_UNVERIFIED)
        try:
            observed = read_credential(snapshot, location.representation)
        except SafeError:
            raise VerifyBError(VerifyBErrorCode.LOCATION_UNVERIFIED) from None
        if location.identity is IdentityBinding.ACTIVE:
            # One failure class for every non-B state: an active location not
            # at the verified B credential is not a valid VERIFY_B state,
            # whatever its value is (still admin, unknown, or a different
            # breakglass password).  The operator inspects the durable record
            # against the fresh value; this gate only requires the verified
            # bridge.
            if not credential_matches_desired(location, observed, desired):
                raise VerifyBError(VerifyBErrorCode.LOCATION_UNVERIFIED)
        else:
            # Fixed identity: admin.  This location stays associated with
            # admin throughout the B transition: the only permitted state is
            # the verified admin reference.  A breakglass credential here is
            # not recognized (it is not an early convergence), and unknown
            # or mismatched credentials fail closed.  No mutation.
            state = classify(location, observed, references)
            if state is not CredentialState.MATCHES_ADMIN_REFERENCE:
                raise VerifyBError(VerifyBErrorCode.LOCATION_UNVERIFIED)


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
            raise VerifyBError(VerifyBErrorCode.WORKLOAD_UNHEALTHY) from None
        if exc.kind is WorkloadClientErrorCode.INVALID:
            raise VerifyBError(VerifyBErrorCode.WORKLOAD_UNHEALTHY) from None
        raise VerifyBError(VerifyBErrorCode.EXTERNAL_DEPENDENCY) from None


def _upsert_verify_b_complete(
    transaction: RotationTransaction, *, checked_at: datetime,
    generation: CredentialGeneration,
) -> RotationTransaction:
    item = VerificationResult(
        check_id="verify-b-complete",
        phase=RotationPhase.VERIFY_B,
        status=VerificationStatus.SUCCESS,
        checked_at=checked_at,
        detail_code="bridge-freshly-verified",
        target_uid=None,
        credential_generation=generation,
    )
    retained = tuple(
        value for value in transaction.verifications
        if not (
            value.check_id == "verify-b-complete"
            and value.phase is RotationPhase.VERIFY_B
        )
    )
    return replace(
        transaction, verifications=(*retained, item), updated_at=checked_at,
    )


def _advance_to_rotate_a(
    store: StateStore, persisted: PersistedState, ownership: OwnershipGuard, *,
    now: datetime, generation: CredentialGeneration,
) -> PersistedState:
    """Advance the durable phase to ``ROTATE_A`` (ownership-fenced) and stop.

    This is ``VERIFY_B``'s only *semantic* transaction write: the phase
    advance plus a credential-free verification receipt (carrying only the B
    generation) recording that the B safety bridge was freshly observed and is
    sufficient to permit ``ROTATE_A`` to begin.  It is distinct from the
    ownership-fenced execution bookkeeping re-stamp a resume/takeover may
    persist earlier -- bookkeeping, not semantic completion.  It does not mean
    merely "``SWITCH_TO_B`` returned success earlier": every required check
    held under fresh observation in this invocation.  Current Lease ownership
    is asserted immediately before the write; a lost owner cannot advance the
    transaction.
    """
    _assert_owned(ownership)
    transaction = persisted.state.current_transaction
    assert transaction is not None
    updated = _upsert_verify_b_complete(
        transaction, checked_at=now, generation=generation,
    )
    updated = replace(
        updated,
        phase=RotationPhase.ROTATE_A,
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
        raise VerifyBError(VerifyBErrorCode.PROGRESS_PERSISTENCE_FAILED) from None


def run_verify_b(
    inputs: VerifyBInputs, *, state_store: StateStore,
    ownership: OwnershipGuard, passwordsafe: PasswordSafeClient,
    keystone: KeystoneClient, clock: Callable[[], datetime] = _utc_now,
) -> VerifyBResult:
    """Run or re-observe ``VERIFY_B`` from fresh external observations.

    The composition order is fixed:

    ```text
    validate transaction/phase/identity/environment/config
    (a transaction already past VERIFY_B returns ALREADY_ADVANCED without
     re-running the checks)
    require the phase-qualified durable completion receipts:
        a single SUCCESS switch-to-b-complete receipt at SWITCH_TO_B whose
        generation equals the transaction's B generation, plus the
        PREPARE_B stable-a/breakglass-b2 evidence that anchors the admin
        reference
        ->
    re-stamp the durable transaction's current execution on resume
        (ownership-fenced bookkeeping, only when it is not up to date)
    ->
    fresh breakglass B observation (PasswordSafe) + generation match
    ->
    fresh breakglass Keystone authentication (identity-validated)
    ->
    fresh admin breeder observation (must still match the stable-a receipt)
    ->
    fresh per-location structural classification of every participating
    identity: active location (all must be the verified B credential)
    ->
    every derived restart action durably COMPLETE
    ->
    fresh observation that every affected workload is complete with the
    deterministic restart marker
    ->
    advance the durable phase to ROTATE_A (ownership-fenced) and stop
    ```

    Every step observes current external state; durable progress flags are
    never accepted as proof that a location or workload converged.  On any
    verification failure or ambiguity the ``verify-b-complete`` receipt is not
    written and the phase is not advanced; the only durable write a failed
    invocation may perform is the credential-free execution re-stamp (resume
    bookkeeping), so the transaction remains in ``VERIFY_B`` (or, for a
    predecessor phase, exactly where it was found) for re-observation, and the
    admin credential is untouched.
    """
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("VERIFY_B clock must return a timezone-aware value.")
    try:
        persisted = state_store.load()
    except StateStoreError:
        raise VerifyBError(VerifyBErrorCode.EXTERNAL_DEPENDENCY) from None
    transaction = persisted.state.current_transaction
    if transaction is None:
        raise VerifyBError(VerifyBErrorCode.NO_TRANSACTION)

    request = inputs.request
    # A transaction already past VERIFY_B is handled deterministically: only
    # genuine successor phases (ROTATE_A, SWITCH_TO_A, VERIFY_A) report
    # ALREADY_ADVANCED without re-running the checks or regressing the phase.
    # A predecessor phase (STABLE_A, PREPARE_B, or SWITCH_TO_B) is not this
    # phase's entry state: the B bridge has not durably been established by
    # this transaction, so it is rejected rather than partially verified.
    if transaction.phase is not RotationPhase.VERIFY_B:
        if transaction.phase in (
            RotationPhase.ROTATE_A,
            RotationPhase.SWITCH_TO_A,
            RotationPhase.VERIFY_A,
        ):
            return VerifyBResult(
                outcome=VerifyBOutcome.ALREADY_ADVANCED,
                persisted=persisted,
                transaction_id=transaction.transaction_id,
                phase=transaction.phase,
            )
        raise VerifyBError(VerifyBErrorCode.UNSUPPORTED_PHASE)

    if persisted.state.environment != request.environment:
        raise VerifyBError(VerifyBErrorCode.ENVIRONMENT_MISMATCH)
    if transaction.keystone != request.keystone:
        raise VerifyBError(VerifyBErrorCode.CONFIGURATION_MISMATCH)
    if transaction.passwordsafe.configured_b_record_id != request.passwordsafe_b_record_id:
        raise VerifyBError(VerifyBErrorCode.CONFIGURATION_MISMATCH)
    generation = transaction.new_b_sha256
    if generation is None:
        raise VerifyBError(VerifyBErrorCode.B_GENERATION_MISSING)

    # Durable completion evidence is mandatory.  The switch-to-b-complete
    # receipt proves the cutover phase finished durably, and the PREPARE_B
    # stable-a receipt anchors the admin reference (old-A generation and
    # breeder UID).  Both are validated, never synthesized.
    _switch_to_b_complete_receipt(transaction, generation=generation)
    stable_a_receipt, _b2_receipt = _verify_prepare_b_evidence(
        transaction, generation=generation,
    )

    # Re-stamp the durable transaction's current execution on resume
    # (transaction-wide invariant from the SWITCH_TO_B corrective pass; the
    # ownership assertion inside _restamp_execution precedes the write).
    persisted = _restamp_execution(
        state_store, ownership, persisted,
        execution=request.execution, now=now,
    )
    transaction = persisted.state.current_transaction
    assert transaction is not None

    # Fresh breakglass observation.  VERIFY_B must not infer the bridge from
    # PREPARE_B or SWITCH_TO_B having succeeded earlier: the authoritative B
    # value is re-derived from PasswordSafe (current record plus the recorded
    # generation) and its identity is re-validated by a fresh Keystone
    # authentication.
    try:
        record_b = passwordsafe.get_current(
            access=inputs.passwordsafe_access,
            project_id=request.passwordsafe_project_id,
            credential_id=request.passwordsafe_b_record_id,
            expected_username=request.breakglass_username,
        )
    except ExternalClientError:
        raise VerifyBError(VerifyBErrorCode.B_CREDENTIAL_UNRESOLVED) from None
    if CredentialGeneration.from_secret(record_b.password) != generation:
        raise VerifyBError(VerifyBErrorCode.B_CREDENTIAL_UNRESOLVED)
    authentication = _authenticate(
        keystone, username=request.breakglass_username,
        password=record_b.password, request=request.keystone,
    )
    if isinstance(authentication, KeystoneAuthIndeterminate):
        raise VerifyBError(VerifyBErrorCode.B_AUTH_INDETERMINATE)
    if not isinstance(authentication, KeystoneAuthSuccess):
        raise VerifyBError(VerifyBErrorCode.B_CREDENTIAL_UNRESOLVED)
    _validate_breakglass_auth(
        authentication.observation,
        expected_user_id=request.keystone.breakglass_user_id,
        expected_username=request.breakglass_username,
        request=request.keystone,
        now=clock(),
    )
    b_value = record_b.password
    desired = DesiredCredential(Identity.BREAKGLASS, b_value)

    # Fresh breeder reference, cross-checked against the durable stable-a
    # receipt (old-A generation and breeder UID).  A missing contracted Secret
    # is observed state, not a dependency failure; the breeder check and the
    # per-location classification below report it.
    inventory, missing_secrets = _current_inventory(inputs)

    # Every contracted propagated location must be explained by the current
    # phase: participating identity: active locations at the verified B
    # credential; fixed identity: admin locations on the verified admin
    # reference only (a breakglass credential there is invalid), with missing
    # or unparseable contracted locations failing closed.
    _verify_participating_locations(
        inputs, inventory=inventory, desired=desired,
        missing_secrets=missing_secrets, stable_a=stable_a_receipt,
    )

    # The wave must carry its immutable intent (a verified cutover always
    # does); derive the restart actions exactly as the executor did.  This
    # validates the contract digest against the intent and fails closed on
    # drift or intent mismatch.
    wave = transaction.propagation.to_b
    try:
        actions = derive_restart_actions(
            inputs.contract, transaction, target=Identity.BREAKGLASS,
        )
    except SafeError as error:
        kind = getattr(error, "kind", None)
        if kind in (
            RestartExecutionErrorCode.CONTRACT_DRIFT,
            RestartExecutionErrorCode.INTENT_MISMATCH,
            RestartExecutionErrorCode.NO_WAVE_INTENT,
        ):
            raise VerifyBError(VerifyBErrorCode.CONTRACT_DRIFT) from None
        raise VerifyBError(VerifyBErrorCode.EXTERNAL_DEPENDENCY) from None
    derived_ids = {action.action_id for action in actions}
    durable_ids = {item.action_id for item in wave.runtime_actions}
    # A durable runtime action ID that is not derivable from the current
    # changed-location accounting is stale or contradictory state.  The
    # executor (4D) rejects this in its own _ensure_actions pass; VERIFY_B
    # performs the same check observationally rather than persisting records.
    if not durable_ids <= derived_ids:
        raise VerifyBError(VerifyBErrorCode.CONTRACT_DRIFT)

    # Every derived restart action must be durably complete.  A durable
    # COMPLETE is a discharged obligation written only after a successful
    # rollout observation, but the workload is re-observed below: observed
    # Kubernetes state is the deciding evidence where practical, and an
    # unrelated later change must not be laundered into the bridge.
    durable_state = {
        item.action_id: item.state for item in wave.runtime_actions
    }
    for action in actions:
        if durable_state.get(action.action_id) is not RuntimeActionState.COMPLETE:
            raise VerifyBError(VerifyBErrorCode.RESTART_INCOMPLETE)

    # Freshly observed workload health: every affected workload must be
    # rolled out and ready, with the deterministic restart marker for this
    # wave present in the Pod template.  This reuses the Slice 4D workload
    # abstraction and its generation-aware completion predicate; it observes,
    # never dispatches.
    marker = restart_request_for(wave)
    for action in actions:
        snapshot = _observe_workload(inputs.workload_client, action.workload)
        if not snapshot.complete(restart_requested=marker):
            raise VerifyBError(VerifyBErrorCode.WORKLOAD_UNHEALTHY)

    # All required verification held under fresh observation: advance the
    # durable phase to ROTATE_A (ownership-fenced) and stop.
    final_persisted = _advance_to_rotate_a(
        state_store, persisted, ownership, now=clock(), generation=generation,
    )
    final_transaction = final_persisted.state.current_transaction
    assert final_transaction is not None
    return VerifyBResult(
        outcome=VerifyBOutcome.VERIFIED,
        persisted=final_persisted,
        transaction_id=final_transaction.transaction_id,
        phase=final_transaction.phase,
        verified=True,
    )
