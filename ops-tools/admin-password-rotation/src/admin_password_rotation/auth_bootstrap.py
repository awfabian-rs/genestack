"""Slice 5B: administrative authentication bootstrap and identity resolution.

``bootstrap_admin_session`` establishes a usable Keystone administrative
session using only the established A (admin) and B (breakglass) identities.

Credential selection is informed by the durable transaction and the recorded
credential-generation provenance, not by an indiscriminate scan of Kubernetes
Secrets:

- With no durable transaction (first execution), the canonical breeder
  credential is the only legitimate initial A candidate.
- With a durable transaction, the breeder is a candidate only while the
  transaction is before ``ROTATE_A``; once the A rotation has begun, the
  breeder's relationship to the authenticating credential is phase-dependent
  (A0-A3), so the *freshly observed authoritative-A credential* -- derived by
  the Slice 3C reconciliation machinery over the exact breeder snapshot -- is
  the legitimate candidate.

The bootstrap performs at most **one** A authentication attempt and at most
**one** B authentication attempt, in that order.  A definite A rejection
(truthfully ``CREDENTIAL_REJECTED``) falls through to the B attempt; an
indeterminate A outcome (transport failure, timeout, server error, auth-receipt
policy, malformed response) is never treated as a rejection -- it fails with an
infrastructure error and no speculative credential selection is performed.

B's PasswordSafe credential is the B candidate in every phase.  During the
``PREPARE_B`` B1 transitional state PasswordSafe B may legitimately differ from
the Keystone B credential, so a B rejection is reported as the observed state,
not as proof the user is disabled or locked out; the ``PREPARE_B`` recovery
semantics remain authoritative.

The bootstrap:

- never mutates either identity or any Kubernetes object;
- never advances, blocks, or re-stamps the durable transaction;
- never alters lockout settings and never requires a lockout-status query;
- returns a credential-free ``BootstrapResult`` carrying which identity
  authenticated, which credential generation was used (where applicable), and
  the authenticated management token (a ``SecretValue``, redacted in
  ``repr()``/``str()``).

A successful authentication proves only that the candidate credential is
presently usable for that identity at the expected project scope.  It is not
proof of authoritative-state consistency; the phase runners remain responsible
for reconciliation and their lockout preconditions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from .a_state import (
    ARotationInputs, ARotationObservedState, AReconciliationStatus,
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
    CredentialGeneration, CredentialContract, EnvironmentIdentity,
    ResolvedKeystoneIdentities, RotationPhase, RotationTransaction,
    SecretInventory, SecretValue,
)
from .passwordsafe import IdentityAccess, PasswordSafeClient, RackspaceIdentityClient
from .representations import read_credential
from .state_store import PersistedState, StateStore, StateStoreError


class BootstrapErrorCode(Enum):
    """Typed, value-free bootstrap failure categories."""

    STATE_UNAVAILABLE = "bootstrap_state_unavailable"
    ENVIRONMENT_MISMATCH = "bootstrap_environment_mismatch"
    BREEDER_UNAVAILABLE = "bootstrap_breeder_unavailable"
    A_CANDIDATE_UNAVAILABLE = "bootstrap_a_candidate_unavailable"
    A_AUTH_INDETERMINATE = "bootstrap_a_auth_indeterminate"
    A_AUTH_REJECTED = "bootstrap_a_auth_rejected"
    A_AUTH_IDENTITY_MISMATCH = "bootstrap_a_auth_identity_mismatch"
    B_CREDENTIAL_UNAVAILABLE = "bootstrap_b_credential_unavailable"
    B_AUTH_INDETERMINATE = "bootstrap_b_auth_indeterminate"
    B_AUTH_REJECTED = "bootstrap_b_auth_rejected"
    B_AUTH_IDENTITY_MISMATCH = "bootstrap_b_auth_identity_mismatch"
    IDENTITY_AUTH_INDETERMINATE = "bootstrap_identity_auth_indeterminate"
    IDENTITY_CONSISTENCY_MISMATCH = "bootstrap_identity_consistency_mismatch"
    NO_ADMIN_SESSION = "bootstrap_no_admin_session"


_ERROR_MESSAGES: dict[BootstrapErrorCode, str] = {
    BootstrapErrorCode.STATE_UNAVAILABLE:
        "The durable transaction state is unavailable; bootstrap cannot proceed.",
    BootstrapErrorCode.ENVIRONMENT_MISMATCH:
        "The durable state environment does not match the configured environment.",
    BootstrapErrorCode.BREEDER_UNAVAILABLE:
        "The canonical breeder Secret could not be read; bootstrap cannot proceed.",
    BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE:
        "The legitimate A credential candidate could not be established.",
    BootstrapErrorCode.A_AUTH_INDETERMINATE:
        "Keystone availability or response was indeterminate for the A candidate; "
        "no B fallback is attempted.",
    BootstrapErrorCode.A_AUTH_REJECTED:
        "The A candidate was definitively rejected by Keystone.",
    BootstrapErrorCode.A_AUTH_IDENTITY_MISMATCH:
        "Successful A authentication did not match the expected admin identity or scope.",
    BootstrapErrorCode.B_CREDENTIAL_UNAVAILABLE:
        "The PasswordSafe B credential could not be retrieved.",
    BootstrapErrorCode.B_AUTH_INDETERMINATE:
        "Keystone availability or response was indeterminate for the B candidate.",
    BootstrapErrorCode.B_AUTH_REJECTED:
        "The B candidate was definitively rejected by Keystone; "
        "in the B1 transitional state this is an expected observed state.",
    BootstrapErrorCode.B_AUTH_IDENTITY_MISMATCH:
        "Successful B authentication did not match the expected breakglass identity or scope.",
    BootstrapErrorCode.IDENTITY_AUTH_INDETERMINATE:
        "Rackspace Identity authentication failed or was unavailable; "
        "PasswordSafe access cannot be established.",
    BootstrapErrorCode.IDENTITY_CONSISTENCY_MISMATCH:
        "The explicitly supplied Keystone identities do not match the identities "
        "recorded in the durable transaction; bootstrap fails closed before "
        "any authentication attempt.",
    BootstrapErrorCode.NO_ADMIN_SESSION:
        "Neither legitimate administrative credential established a Keystone session.",
}


class BootstrapError(SafeError):
    """A value-free bootstrap failure suitable for operator diagnostics."""

    def __init__(self, kind: BootstrapErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class AdminIdentity(Enum):
    ADMIN = "admin"
    BREAKGLASS = "breakglass"


@dataclass(frozen=True, repr=False)
class BootstrapResult:
    """Credential-free outcome of one bootstrap invocation.

    ``token`` is the authenticated management token; it is a ``SecretValue``
    and is redacted in ``repr()``/``str()``.  ``generation`` is the credential
    generation that authenticated (where applicable); it is a stable
    ``sha256:<64 hex>`` identifier, not the credential itself.
    """

    identity: AdminIdentity
    observation: KeystoneAuthObservation
    token: SecretValue = field(repr=False)
    generation: CredentialGeneration | None = None
    transaction_phase: RotationPhase | None = None

    def __repr__(self) -> str:
        return (
            f"BootstrapResult(identity={self.identity.value!r}, "
            f"user_id={self.observation.user_id!r}, "
            f"generation={self.generation.value if self.generation else None!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _assert_identities(
    transaction: RotationTransaction,
) -> ResolvedKeystoneIdentities:
    """The transaction's recorded identity references.

    A durable transaction carries the ``ResolvedKeystoneIdentities`` it was
    created with (the live Keystone UUIDs resolved when the transaction
    began).  These are the trusted references the bootstrap authenticates and
    validates against on the resume path: they are the source, never
    synthesized from current observation.  On first execution (no durable
    transaction) there is no such source, so the caller must establish the
    identities explicitly.
    """
    return transaction.keystone


def _breeder_password(
    breeder_client: BreederSecretClient,
    reference: BreederReference,
    contract: CredentialContract,
) -> tuple[SecretValue, str]:
    try:
        snapshot = breeder_client.read(reference)
    except BreederError:
        raise BootstrapError(BootstrapErrorCode.BREEDER_UNAVAILABLE) from None
    try:
        observed = read_credential(snapshot, contract.source.representation)
    except SafeError:
        raise BootstrapError(BootstrapErrorCode.BREEDER_UNAVAILABLE) from None
    return observed.password, snapshot.uid


def _authenticate(
    keystone: KeystoneClient, *, username: str, password: SecretValue,
    domain_id: str, project_id: str,
) -> KeystoneAuthSuccess | KeystoneAuthRejected | KeystoneAuthIndeterminate:
    return keystone.authenticate_password(KeystonePasswordAuthRequest(
        username=username,
        user_domain_id=domain_id,
        project_id=project_id,
        password=password,
    ))


def _validate_auth(
    observed: KeystoneAuthObservation, *, expected_user_id: str,
    expected_username: str, expected_domain_id: str, expected_project_id: str,
    expected_project_domain_id: str, expected_role_id: str, now: datetime,
) -> None:
    if not (
        observed.user_id == expected_user_id
        and observed.user_name == expected_username
        and observed.user_domain_id == expected_domain_id
        and observed.project_id == expected_project_id
        and observed.project_domain_id == expected_project_domain_id
        and observed.expires_at > now
        and any(role.role_id == expected_role_id for role in observed.roles)
    ):
        raise BootstrapError(
            BootstrapErrorCode.A_AUTH_IDENTITY_MISMATCH
            if expected_username == "admin"
            else BootstrapErrorCode.B_AUTH_IDENTITY_MISMATCH,
        )


def _select_a_candidate(
    *, persisted: PersistedState,
    contract: CredentialContract,
    breeder: BreederSecretClient,
    breeder_reference: BreederReference,
    passwordsafe: PasswordSafeClient,
    passwordsafe_access: IdentityAccess,
    passwordsafe_project_id: int,
    passwordsafe_a_record_id: int,
    admin_username: str,
    project_name: str,
    now: datetime,
    clock: Clock,
    keystone: KeystoneClient,
) -> tuple[SecretValue, CredentialGeneration]:
    """Return the legitimate initial A credential candidate and its generation.

    Returns ``(candidate, generation)``.  Raises ``BootstrapError`` when the
    candidate cannot be established from legitimate provenance.

    For a durable transaction in ``ROTATE_A`` / ``SWITCH_TO_A`` / ``VERIFY_A``
    the candidate is the credential the Slice 3C observation just proved
    authenticable for the classified substate:

    - ``A0``: the canonical breeder (the established old-A credential).
    - ``A1``: the established old-A credential, recovered from the current
      PasswordSafe A record.  The breeder holds the staged A-new credential,
      but Keystone ``admin`` still authenticates the old credential in A1, so
      the breeder value must NOT be attempted against Keystone.
    - ``A2`` / ``A3``: the breeder value (A-new), which the observation just
      proved authenticable in those substates.

    The observation result is reused rather than re-derived; no second
    A-state classifier is introduced.
    """
    transaction = persisted.state.current_transaction
    if transaction is None:
        # First execution: the breeder is the only legitimate initial A
        # candidate (PasswordSafe A and Keystone A are expected to agree with
        # the breeder in stable state; the phase runners prove that).
        password, _uid = _breeder_password(
            breeder, breeder_reference, contract,
        )
        try:
            generation = CredentialGeneration.from_secret(password)
        except ValueError:
            raise BootstrapError(BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE) from None
        return password, generation

    # Durable transaction exists.  Determine the legitimate A candidate from
    # the phase and the recorded provenance.
    phase = transaction.phase
    if phase in (
        RotationPhase.STABLE_A, RotationPhase.PREPARE_B,
        RotationPhase.SWITCH_TO_B, RotationPhase.VERIFY_B,
    ):
        # Before ROTATE_A the breeder is expected to hold the currently
        # authenticating A credential (old-A before staging; the phase
        # runners prove the stable-A invariant).
        password, _uid = _breeder_password(
            breeder, breeder_reference, contract,
        )
        try:
            generation = CredentialGeneration.from_secret(password)
        except ValueError:
            raise BootstrapError(BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE) from None
        return password, generation

    # ROTATE_A / SWITCH_TO_A / VERIFY_A: the breeder's value may not be the
    # currently authenticating A credential (A0-A3 substates).  Derive the
    # current substate with the Slice 3C reconciliation (fresh breeder read,
    # fresh PasswordSafe A read, bounded fresh Keystone authentication) and
    # select the candidate that substate proves authenticable.
    try:
        snapshot = breeder.read(breeder_reference)
    except BreederError:
        raise BootstrapError(BootstrapErrorCode.BREEDER_UNAVAILABLE) from None
    try:
        result = observe_a_rotation_state(
            ARotationInputs(
                transaction=transaction,
                contract=contract,
                inventory=SecretInventory(
                    snapshot.namespace, snapshot.resource_version, (snapshot,),
                ),
                passwordsafe_access=passwordsafe_access,
                passwordsafe_project_id=passwordsafe_project_id,
                admin_username=admin_username,
                project_name=project_name,
            ),
            passwordsafe=passwordsafe,
            keystone=keystone,
            clock=clock,
        )
    except (ExternalClientError, BootstrapError):
        raise
    except Exception:
        raise BootstrapError(BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE) from None

    if result.status is not AReconciliationStatus.VALID or result.state is None:
        raise BootstrapError(BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE)

    if result.state is ARotationObservedState.A1:
        # A1: the breeder holds the staged A-new credential, but Keystone
        # ``admin`` still authenticates the established old-A credential.
        # The 3C observation just proved A-new is rejected and old A succeeds,
        # so attempting the breeder's A-new value would be a predictable failed
        # authentication.  The legitimate candidate is the established old-A
        # credential, recovered from the current PasswordSafe A record (which
        # equals old A in A1).  Never attempt the staged A-new in A1.
        password = _recover_a_credential(
            passwordsafe=passwordsafe,
            passwordsafe_access=passwordsafe_access,
            passwordsafe_project_id=passwordsafe_project_id,
            transaction=transaction,
            admin_username=admin_username,
        )
        return password, CredentialGeneration.from_secret(password)
    # A0: the breeder holds the established old-A credential.
    # A2: the breeder holds A-new, which the 3C machinery just proved
    #     authenticable (Keystone already accepts A-new in A2).
    # A3: the breeder holds A-new and both Keystone and PasswordSafe agree.
    try:
        observed = read_credential(snapshot, contract.source.representation)
    except SafeError:
        raise BootstrapError(BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE) from None
    return observed.password, CredentialGeneration.from_secret(observed.password)


def _recover_b_credential(
    *, passwordsafe: PasswordSafeClient,
    passwordsafe_access: IdentityAccess,
    passwordsafe_project_id: int,
    passwordsafe_b_record_id: int,
    breakglass_username: str,
) -> SecretValue:
    try:
        record = passwordsafe.get_current(
            access=passwordsafe_access,
            project_id=passwordsafe_project_id,
            credential_id=passwordsafe_b_record_id,
            expected_username=breakglass_username,
        )
    except ExternalClientError:
        raise BootstrapError(BootstrapErrorCode.B_CREDENTIAL_UNAVAILABLE) from None
    return record.password


def _recover_a_credential(
    *, passwordsafe: PasswordSafeClient,
    passwordsafe_access: IdentityAccess,
    passwordsafe_project_id: int,
    transaction: RotationTransaction,
    admin_username: str,
) -> SecretValue:
    """Recover the A credential from the current PasswordSafe A record.

    This is the legitimate A candidate for the ``A1`` substate, where the
    canonical breeder holds the staged A-new credential but Keystone ``admin``
    still authenticates the established old A.  In ``A1`` the Slice 3C
    machinery has already established, from the current PasswordSafe A
    record, that it equals the established old-A credential (and the
    transaction's ``stable-a`` provenance anchors that generation), so the
    PasswordSafe A value is the credential Keystone currently accepts.  No
    additional credential storage is consulted.
    """
    try:
        record = passwordsafe.get_current(
            access=passwordsafe_access,
            project_id=passwordsafe_project_id,
            credential_id=transaction.passwordsafe.configured_a_record_id,
            expected_username=admin_username,
        )
    except ExternalClientError:
        raise BootstrapError(BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE) from None
    return record.password


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class BootstrapDependencies:
    """A freshly resolved Rackspace Identity session for PasswordSafe access.

    ``access`` is an ``IdentityAccess`` whose token is a ``SecretValue``
    (redacted in ``repr()``/``str()``).  It is a short-lived credential for
    the PasswordSafe API and is not an administrative Keystone session.
    """

    access: IdentityAccess

    def __repr__(self) -> str:
        return f"BootstrapDependencies(expires_at={self.access.expires_at.isoformat()!r})"

    def __str__(self) -> str:
        return self.__repr__()


def bootstrap_passwordsafe_access(
    *,
    rackspace_identity: RackspaceIdentityClient,
    username: str,
    password: SecretValue,
) -> BootstrapDependencies:
    """Establish a Rackspace Identity session for PasswordSafe access.

    This is the production bootstrap for the AD service-account credential
    carried in ``RuntimeConfig.passwordsafe_identity_credential``.  It
    performs exactly one Rackspace Identity authentication; it does not read
    or mutate any Kubernetes object, transaction, or Keystone identity.

    Raises ``BootstrapError(STATE_UNAVAILABLE)`` (credential authority
    unavailable) when the identity service rejects the credential or is
    unreachable; the caller must not treat this as a Keystone administrative
    failure.
    """
    try:
        access = rackspace_identity.authenticate(username=username, password=password)
    except ExternalClientError:
        raise BootstrapError(BootstrapErrorCode.IDENTITY_AUTH_INDETERMINATE) from None
    return BootstrapDependencies(access=access)


def bootstrap_admin_session(
    *,
    keystone: KeystoneClient,
    passwordsafe: PasswordSafeClient,
    passwordsafe_access: IdentityAccess,
    passwordsafe_project_id: int,
    passwordsafe_a_record_id: int,
    passwordsafe_b_record_id: int,
    state_store: StateStore,
    breeder: BreederSecretClient,
    contract: CredentialContract,
    breeder_reference: BreederReference = BreederReference(),
    environment: EnvironmentIdentity,
    keystone_identities: ResolvedKeystoneIdentities | None = None,
    admin_username: str = "admin",
    breakglass_username: str = "breakglass",
    project_name: str = "admin",
    clock: Clock = _utc_now,
) -> BootstrapResult:
    """Establish a Keystone administrative session via A-first, B-fallback.

    Performs at most one A and one B authentication attempt.  Never mutates
    either identity, any Kubernetes object, or the durable transaction.
    Raises ``BootstrapError`` when no legitimate session can be established.

    ``keystone_identities`` are the live Keystone UUIDs (user, domain,
    project, role) required to construct a password-authentication request
    and to validate a successful scope.  A fresh process with no durable
    transaction has no cached UUIDs; in that case ``keystone_identities`` is
    ``None`` and there is no legitimate A candidate (no transaction
    provenance), so bootstrap fails closed with
    ``A_CANDIDATE_UNAVAILABLE`` rather than performing a speculative
    authentication.  The caller (the Slice 5C runner) resolves the identities
    from the durable transaction on the resume path, or via an initial
    identity-establishment sequence when no durable transaction exists; it
    must not invent UUIDs.  When a durable transaction is present, the
    transaction's recorded identities are the trusted source.  If the caller
    supplies explicit identities while a durable transaction exists, they
    must match the transaction's recorded identities exactly; a mismatch
    fails closed with ``IDENTITY_CONSISTENCY_MISMATCH`` before any Keystone
    authentication is attempted.
    """
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Bootstrap clock must return a timezone-aware value.")

    # 1. Load the durable transaction state (read-only).
    try:
        persisted = state_store.load()
    except StateStoreError:
        raise BootstrapError(BootstrapErrorCode.STATE_UNAVAILABLE) from None
    if persisted.state.environment != environment:
        raise BootstrapError(BootstrapErrorCode.ENVIRONMENT_MISMATCH)

    transaction = persisted.state.current_transaction

    # Resolve the Keystone identity references used to authenticate and to
    # validate a successful scope.  The caller may supply already-resolved
    # identities (a resume or an initial sequence that established them);
    # otherwise a durable transaction is the only trusted source.  A fresh
    # process with no durable transaction has neither, so there is no
    # legitimate A candidate and no speculative authentication is performed.
    if keystone_identities is None and transaction is None:
        raise BootstrapError(BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE)
    if keystone_identities is None:
        # A durable transaction is the only trusted source of the recorded
        # Keystone identity references on the resume path.
        assert transaction is not None  # guaranteed by the guard above
        identities = _assert_identities(transaction)
    elif transaction is not None:
        # The transaction's recorded identities are authoritative during
        # resumption.  Explicitly supplied identities must match them; a
        # mismatch means the caller is resuming against a different identity
        # scope than the one the transaction was created with, and
        # authentication must not be attempted.
        if keystone_identities != _assert_identities(transaction):
            raise BootstrapError(
                BootstrapErrorCode.IDENTITY_CONSISTENCY_MISMATCH,
            )
        identities = keystone_identities
    else:
        identities = keystone_identities

    # 2. Attempt A authentication.
    try:
        a_candidate, a_generation = _select_a_candidate(
            persisted=persisted,
            contract=contract,
            breeder=breeder,
            breeder_reference=breeder_reference,
            passwordsafe=passwordsafe,
            passwordsafe_access=passwordsafe_access,
            passwordsafe_project_id=passwordsafe_project_id,
            passwordsafe_a_record_id=passwordsafe_a_record_id,
            admin_username=admin_username,
            project_name=project_name,
            now=now,
            clock=clock,
            keystone=keystone,
        )
    except BootstrapError:
        # A candidate-establishment failure (breeder unavailable, malformed
        # transaction, reconciliation failure) is never treated as a
        # definite A rejection: fail closed without speculative B fallback.
        # The B attempt below is reached only on a definite A rejection.
        raise

    a_result = _authenticate(
        keystone,
        username=admin_username,
        password=a_candidate,
        domain_id=identities.user_domain_id,
        project_id=identities.project_id,
    )
    if isinstance(a_result, KeystoneAuthIndeterminate):
        # Indeterminate: infrastructure failure, not a rejection.  Fail
        # closed; do not fall through to B.
        raise BootstrapError(BootstrapErrorCode.A_AUTH_INDETERMINATE)
    if not isinstance(a_result, KeystoneAuthRejected):
        _validate_auth(
            a_result.observation,
            expected_user_id=identities.admin_user_id,
            expected_username=admin_username,
            expected_domain_id=identities.user_domain_id,
            expected_project_id=identities.project_id,
            expected_project_domain_id=identities.project_domain_id,
            expected_role_id=identities.role_id,
            now=clock(),
        )
        return BootstrapResult(
            identity=AdminIdentity.ADMIN,
            observation=a_result.observation,
            token=a_result.token,
            generation=a_generation,
            transaction_phase=transaction.phase if transaction else None,
        )

    # 3. A definitively rejected: attempt B.
    b_password = _recover_b_credential(
        passwordsafe=passwordsafe,
        passwordsafe_access=passwordsafe_access,
        passwordsafe_project_id=passwordsafe_project_id,
        passwordsafe_b_record_id=passwordsafe_b_record_id,
        breakglass_username=breakglass_username,
    )
    b_result = _authenticate(
        keystone,
        username=breakglass_username,
        password=b_password,
        domain_id=identities.user_domain_id,
        project_id=identities.project_id,
    )
    if isinstance(b_result, KeystoneAuthIndeterminate):
        raise BootstrapError(BootstrapErrorCode.B_AUTH_INDETERMINATE)
    if isinstance(b_result, KeystoneAuthRejected):
        # B1 transitional state: PasswordSafe B may legitimately differ from
        # Keystone B.  This is an observed state, not a lockout diagnosis.
        raise BootstrapError(
            BootstrapErrorCode.NO_ADMIN_SESSION,
        )
    _validate_auth(
        b_result.observation,
        expected_user_id=identities.breakglass_user_id,
        expected_username=breakglass_username,
        expected_domain_id=identities.user_domain_id,
        expected_project_id=identities.project_id,
        expected_project_domain_id=identities.project_domain_id,
        expected_role_id=identities.role_id,
        now=clock(),
    )
    try:
        b_generation = CredentialGeneration.from_secret(b_password)
    except ValueError:
        b_generation = None
    return BootstrapResult(
        identity=AdminIdentity.BREAKGLASS,
        observation=b_result.observation,
        token=b_result.token,
        generation=b_generation,
        transaction_phase=transaction.phase if transaction else None,
    )


# ---------------------------------------------------------------------------
# Read-only identity resolution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolvedIdentity:
    """A resolved Keystone user identity."""

    user_id: str
    name: str
    domain_id: str
    enabled: bool
    default_project_id: str | None
    ignore_lockout_failure_attempts: bool


@dataclass(frozen=True)
class IdentityResolutionResult:
    """The result of resolving A and B identities against Keystone."""

    admin: ResolvedIdentity | None = None
    breakglass: ResolvedIdentity | None = None
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.admin is not None and self.breakglass is not None and not self.errors


class IdentityResolutionError(SafeError):
    """A value-free identity-resolution failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message)


def resolve_identities(
    *,
    keystone: KeystoneClient,
    token: SecretValue,
    keystone_identities: ResolvedKeystoneIdentities,
    admin_username: str = "admin",
    breakglass_username: str = "breakglass",
) -> IdentityResolutionResult:
    """Resolve the live Keystone identities of A and B using an authenticated
    administrative session.

    Read-only: no users, projects, roles, or trusts are created or modified.
    Returns a typed result; missing, ambiguous, or disabled identities are
    reported explicitly without raising.
    """
    errors: list[str] = []
    admin: ResolvedIdentity | None = None
    breakglass: ResolvedIdentity | None = None

    for label, expected_id, expected_name in (
        ("admin", keystone_identities.admin_user_id, admin_username),
        ("breakglass", keystone_identities.breakglass_user_id, breakglass_username),
    ):
        try:
            observation = keystone.get_user(
                user_id=expected_id, management_token=token,
            )
        except ExternalClientError as exc:
            errors.append(f"{label}:{exc.kind.value}")
            continue
        if observation.name != expected_name:
            errors.append(f"{label}:name_mismatch")
            continue
        if observation.domain_id != keystone_identities.user_domain_id:
            errors.append(f"{label}:domain_mismatch")
            continue
        if not observation.enabled:
            errors.append(f"{label}:disabled")
            continue
        resolved = ResolvedIdentity(
            user_id=observation.user_id,
            name=observation.name,
            domain_id=observation.domain_id,
            enabled=observation.enabled,
            default_project_id=observation.default_project_id,
            ignore_lockout_failure_attempts=observation.ignore_lockout_failure_attempts,
        )
        if label == "admin":
            admin = resolved
        else:
            breakglass = resolved

    return IdentityResolutionResult(
        admin=admin, breakglass=breakglass, errors=tuple(errors),
    )
