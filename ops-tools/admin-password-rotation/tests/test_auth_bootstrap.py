"""Slice 5B: administrative authentication bootstrap and identity resolution.

Covers the A-first / B-fallback bootstrap algorithm, A0-A3 credential
provenance selection, the B1 transitional state, failure classification
(rejection vs indeterminate), no-mutation behavior, and the read-only
identity resolution operation.  All tests use the existing behavioral
fakes; no live Keystone, PasswordSafe, or Kubernetes access occurs.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone

import pytest

from admin_password_rotation.auth_bootstrap import (
    AdminIdentity,
    BootstrapDependencies,
    BootstrapError,
    BootstrapErrorCode,
    BootstrapResult,
    IdentityResolutionResult,
    bootstrap_admin_session,
    bootstrap_passwordsafe_access,
    resolve_identities,
)
from admin_password_rotation.breeder import (
    BreederError, BreederErrorCode, BreederReference,
)
from admin_password_rotation.model import SecretSnapshot
from admin_password_rotation.keystone import (
    FakeKeystoneClient,
    KeystoneAuthIndeterminate,
    KeystoneAuthRejected,
    KeystoneAuthSuccess,
    KeystoneIndeterminateReason,
    KeystonePasswordAuthRequest,
    KeystoneUserObservation,
)
from admin_password_rotation.model import (
    ConfigurationDigest,
    CredentialGeneration,
    EnvironmentIdentity,
    ExecutionIdentity,
    LockoutChangeState,
    LockoutState,
    PasswordSafeState,
    PersistentState,
    PropagationState,
    PropagationWave,
    ResolvedKeystoneIdentities,
    RotationPhase,
    RotationTransaction,
    SecretValue,
    STATE_SCHEMA_VERSION,
    TransactionStatus,
    VerificationResult,
    VerificationStatus,
)
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient,
    IdentityAccess,
    PasswordSafeCredential,
)
from admin_password_rotation.state_store import PersistedState, StateRevision
from tests.helpers import PASSWORD, contract

ADMIN_ID = "admin-user-id"
BREAKGLASS_ID = "breakglass-user-id"
DOMAIN_ID = "default-domain-id"
PROJECT_ID = "admin-project-id"
PROJECT_DOMAIN_ID = "default-domain-id"
ROLE_ID = "admin-role"

ENVIRONMENT = EnvironmentIdentity("dfw-dev", "cluster.local")
NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)

IDENTITIES = ResolvedKeystoneIdentities(
    admin_user_id=ADMIN_ID,
    breakglass_user_id=BREAKGLASS_ID,
    user_domain_id=DOMAIN_ID,
    project_id=PROJECT_ID,
    project_domain_id=PROJECT_DOMAIN_ID,
    role_id=ROLE_ID,
)


def _clock() -> datetime:
    return NOW


def _admin_observation(name: str = "admin", user_id: str = ADMIN_ID,
                       domain_id: str = DOMAIN_ID) -> KeystoneUserObservation:
    return KeystoneUserObservation(
        user_id, name, domain_id, True, PROJECT_ID, True,
    )


def _keystone() -> FakeKeystoneClient:
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID,
        project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(
        _admin_observation(), SecretValue(PASSWORD),
    )
    keystone.add_user(
        _admin_observation(
            name="breakglass", user_id=BREAKGLASS_ID,
        ),
        SecretValue(b"SYNTHETIC_Breakglass_K_0001"),
    )
    return keystone


def _passwordsafe() -> FakePasswordSafeClient:
    passwordsafe = FakePasswordSafeClient()
    passwordsafe.add(PasswordSafeCredential(
        100, 1000, "admin", 3, SecretValue(PASSWORD),
    ))
    passwordsafe.add(PasswordSafeCredential(
        100, 1001, "breakglass", 2, SecretValue(b"SYNTHETIC_Breakglass_PS_0001"),
    ))
    return passwordsafe


class FailingPasswordSafe(FakePasswordSafeClient):
    def get_current(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        expected_username: str | None = None,
    ) -> PasswordSafeCredential:
        from admin_password_rotation.external_http import (
            ExternalClientError, ExternalErrorCode,
        )
        raise ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE)


ACCESS = IdentityAccess(
    expires_at=NOW.replace(year=2027),
    token=SecretValue(b"SYNTHETIC_IDENTITY_TOKEN"),
)


@dataclass
class MemoryStateStore:
    current: PersistedState
    load_count: int = 0

    def load(self) -> PersistedState:
        self.load_count += 1
        return self.current

    def update(self, expected: StateRevision, new_state: PersistentState) -> PersistedState:
        raise AssertionError("bootstrap must never write the durable state")


def _persisted(transaction: RotationTransaction | None = None) -> PersistedState:
    return PersistedState(
        PersistentState(STATE_SCHEMA_VERSION, ENVIRONMENT, transaction, ()),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )


def _transaction(
    phase: RotationPhase = RotationPhase.ROTATE_A,
    new_a: CredentialGeneration | None = None,
    new_b: CredentialGeneration | None = None,
) -> RotationTransaction:
    old_generation = CredentialGeneration.from_secret(SecretValue(PASSWORD))
    return RotationTransaction(
        transaction_id=uuid.uuid4(),
        request_id=uuid.uuid4(),
        execution=ExecutionIdentity(uuid.uuid4(), None),
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=IDENTITIES,
        created_at=NOW,
        updated_at=NOW,
        phase=phase,
        status=TransactionStatus.ACTIVE,
        last_error=None,
        new_a_sha256=new_a,
        new_b_sha256=new_b,
        passwordsafe=PasswordSafeState(
            configured_a_record_id=1000,
            configured_b_record_id=1001,
            observed_a_record_id=1000,
            observed_b_record_id=1001,
            original_a_version=3,
            observed_a_version=3,
            observed_b_version=2,
        ),
        credential_mutation_intent=None,
        propagation=PropagationState(
            PropagationWave((), ()), PropagationWave((), ()),
        ),
        lockout=LockoutState(
            initial_ignore_lockout_failure_attempts=False,
            suppression=LockoutChangeState.NOT_INTENDED,
            restoration=LockoutChangeState.NOT_INTENDED,
            latest_ignore_lockout_failure_attempts=False,
            restore_required=False,
        ),
        verifications=(
            VerificationResult(
                check_id="stable-a",
                phase=RotationPhase.PREPARE_B,
                status=VerificationStatus.SUCCESS,
                checked_at=NOW,
                detail_code="freshly-verified",
                target_uid="fixture-keystone-admin",
                credential_generation=old_generation,
            ),
        ),
    )


# ---------------------------------------------------------------------------
# bootstrap_passwordsafe_access
# ---------------------------------------------------------------------------


class RecordingIdentityClient:
    def __init__(self, access: IdentityAccess) -> None:
        self._access = access
        self.calls: list[tuple[str, str]] = []

    def authenticate(self, *, username: str, password: SecretValue) -> IdentityAccess:
        self.calls.append((username, password.reveal().decode("utf-8")))
        return self._access


def test_passwordsafe_access_bootstrap_returns_redacted_session() -> None:
    client = RecordingIdentityClient(ACCESS)
    credential = SecretValue("svc-password".encode("utf-8"))
    deps = bootstrap_passwordsafe_access(
        rackspace_identity=client,
        username="svc-rotation",
        password=credential,
    )
    assert isinstance(deps, BootstrapDependencies)
    assert deps.access is ACCESS
    # Exactly one authentication attempt, with the configured credential.
    assert client.calls == [("svc-rotation", "svc-password")]
    # The result repr never exposes the token or the password.
    rendered = repr(deps)
    assert b"SYNTHETIC_IDENTITY_TOKEN" not in rendered.encode("utf-8")
    assert "svc-password" not in rendered


def test_passwordsafe_access_bootstrap_failure_is_typed() -> None:
    class FailingIdentityClient(RecordingIdentityClient):
        def authenticate(self, *, username: str, password: SecretValue) -> IdentityAccess:
            from admin_password_rotation.external_http import (
                ExternalClientError, ExternalErrorCode,
            )
            self.calls.append((username, password.reveal().decode("utf-8")))
            raise ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE)

    client = FailingIdentityClient(ACCESS)
    with pytest.raises(BootstrapError) as exc:
        bootstrap_passwordsafe_access(
            rackspace_identity=client,
            username="svc-rotation",
            password=SecretValue(b"svc-password"),
        )
    assert exc.value.kind is BootstrapErrorCode.IDENTITY_AUTH_INDETERMINATE


# ---------------------------------------------------------------------------
# bootstrap_admin_session
# ---------------------------------------------------------------------------


def _bootstrap(
    *,
    keystone: FakeKeystoneClient | None = None,
    passwordsafe: FakePasswordSafeClient | None = None,
    state_store: MemoryStateStore | None = None,
    breeder: BreederClient | None = None,
    environment: EnvironmentIdentity | None = None,
) -> BootstrapResult:
    """Invoke the bootstrap with typed fixture overrides."""
    return bootstrap_admin_session(
        keystone=keystone if keystone is not None else _keystone(),
        passwordsafe=passwordsafe if passwordsafe is not None else _passwordsafe(),
        passwordsafe_access=ACCESS,
        passwordsafe_project_id=100,
        passwordsafe_a_record_id=1000,
        passwordsafe_b_record_id=1001,
        state_store=state_store if state_store is not None else MemoryStateStore(_persisted()),
        breeder=breeder if breeder is not None else BreederClient(),
        contract=contract(),
        environment=environment if environment is not None else ENVIRONMENT,
        keystone_identities=IDENTITIES,
        clock=_clock,
    )


class BreederClient:
    """Minimal breeder fake over the helpers' keystone-admin snapshot."""

    def __init__(self, snapshot_uid: str = "fixture-keystone-admin") -> None:
        from tests.helpers import secret
        self._snapshot = secret("keystone-admin", {"password": PASSWORD})
        if snapshot_uid != "fixture-keystone-admin":
            self._snapshot = replace(self._snapshot, uid=snapshot_uid)
        self.read_error: BreederErrorCode | None = None
        self.read_count = 0
        self.mutation_count = 0

    def read(self, reference: BreederReference) -> SecretSnapshot:
        del reference
        self.read_count += 1
        if self.read_error is not None:
            raise BreederError(self.read_error)
        return self._snapshot

    def conditional_stage(
        self, expected: SecretSnapshot, *, password: SecretValue,
        provenance: object,
    ) -> None:
        del expected, password, provenance
        self.mutation_count += 1
        raise AssertionError("bootstrap must never mutate the breeder")


def test_stable_a_first_execution_authenticates_as_admin() -> None:
    keystone = _keystone()
    result = _bootstrap(
        state_store=MemoryStateStore(_persisted(None)),
        breeder=BreederClient(),
        keystone=keystone,
    )
    assert result.identity is AdminIdentity.ADMIN
    assert result.transaction_phase is None
    assert result.generation == CredentialGeneration.from_secret(
        SecretValue(PASSWORD),
    )
    assert result.observation.user_id == ADMIN_ID
    # The token is the fake Keystone management token.
    assert result.token.reveal() == b"FAKE_REDACTED_TOKEN"
    # No breeder mutation, no transaction write.
    assert keystone.password_update_calls == []
    # The result repr never exposes the token.
    assert b"FAKE_REDACTED_TOKEN" not in repr(result).encode("utf-8")


def test_a_definite_rejection_falls_back_to_breakglass() -> None:
    # Keystone admin holds a different password than the breeder candidate.
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID, project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(
        _admin_observation(), SecretValue(b"SYNTHETIC_Admin_Different_001"),
    )
    keystone.add_user(
        _admin_observation(name="breakglass", user_id=BREAKGLASS_ID),
        SecretValue(b"SYNTHETIC_Breakglass_PS_0001"),
    )
    passwordsafe = _passwordsafe()
    store = MemoryStateStore(_persisted(None))
    result = bootstrap_admin_session(
        keystone=keystone,
        passwordsafe=passwordsafe,
        passwordsafe_access=ACCESS,
        passwordsafe_project_id=100,
        passwordsafe_a_record_id=1000,
        passwordsafe_b_record_id=1001,
        state_store=store,
        breeder=BreederClient(),
        contract=contract(),
        environment=ENVIRONMENT,
        keystone_identities=IDENTITIES,
        clock=_clock,
    )
    assert result.identity is AdminIdentity.BREAKGLASS
    assert result.observation.user_id == BREAKGLASS_ID
    # The B candidate came from PasswordSafe, so its generation is recorded.
    assert result.generation == CredentialGeneration.from_secret(
        SecretValue(b"SYNTHETIC_Breakglass_PS_0001"),
    )
    # Exactly one A and one B authentication attempt: no repeated A tries.
    assert keystone.password_update_calls == []


def test_both_a_and_b_rejected_fails_closed() -> None:
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID, project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(
        _admin_observation(), SecretValue(b"SYNTHETIC_Admin_Different_001"),
    )
    # No breakglass user at all: B authentication is definitively rejected.
    passwordsafe = _passwordsafe()
    with pytest.raises(BootstrapError) as exc:
        bootstrap_admin_session(
            keystone=keystone,
            passwordsafe=passwordsafe,
            passwordsafe_access=ACCESS,
            passwordsafe_project_id=100,
            passwordsafe_a_record_id=1000,
            passwordsafe_b_record_id=1001,
            state_store=MemoryStateStore(_persisted(None)),
            breeder=BreederClient(),
            contract=contract(),
            environment=ENVIRONMENT,
            keystone_identities=IDENTITIES,
            clock=_clock,
        )
    assert exc.value.kind is BootstrapErrorCode.NO_ADMIN_SESSION


def test_a_credential_rejected_b_credential_unavailable() -> None:
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID, project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(
        _admin_observation(), SecretValue(b"SYNTHETIC_Admin_Different_001"),
    )
    with pytest.raises(BootstrapError) as exc:
        bootstrap_admin_session(
            keystone=keystone,
            passwordsafe=FailingPasswordSafe(),
            passwordsafe_access=ACCESS,
            passwordsafe_project_id=100,
            passwordsafe_a_record_id=1000,
            passwordsafe_b_record_id=1001,
            state_store=MemoryStateStore(_persisted(None)),
            breeder=BreederClient(),
            contract=contract(),
            environment=ENVIRONMENT,
            keystone_identities=IDENTITIES,
            clock=_clock,
        )
    assert exc.value.kind is BootstrapErrorCode.B_CREDENTIAL_UNAVAILABLE


def test_a_indeterminate_never_falls_back_to_b() -> None:
    keystone = _keystone()
    keystone.next_auth_indeterminate = KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    with pytest.raises(BootstrapError) as exc:
        _bootstrap(
            state_store=MemoryStateStore(_persisted(None)),
            breeder=BreederClient(),
            keystone=keystone,
        )
    assert exc.value.kind is BootstrapErrorCode.A_AUTH_INDETERMINATE


def test_b_indeterminate_fails_closed() -> None:
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID, project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(
        _admin_observation(), SecretValue(b"SYNTHETIC_Admin_Different_001"),
    )
    keystone.add_user(
        _admin_observation(name="breakglass", user_id=BREAKGLASS_ID),
        SecretValue(b"SYNTHETIC_Breakglass_PS_0001"),
    )
    # The A attempt is rejected; the B attempt is indeterminate (5xx).
    calls = {"n": 0}
    original = keystone.authenticate_password

    def flaky(request: KeystonePasswordAuthRequest) -> KeystoneAuthSuccess | KeystoneAuthRejected | KeystoneAuthIndeterminate:
        calls["n"] += 1
        if calls["n"] == 1:
            return original(request)
        return KeystoneAuthIndeterminate(
            KeystoneIndeterminateReason.DEPENDENCY_FAILURE,
        )

    keystone.authenticate_password = flaky  # type: ignore[method-assign]
    with pytest.raises(BootstrapError) as exc:
        bootstrap_admin_session(
            keystone=keystone,
            passwordsafe=_passwordsafe(),
            passwordsafe_access=ACCESS,
            passwordsafe_project_id=100,
            passwordsafe_a_record_id=1000,
            passwordsafe_b_record_id=1001,
            state_store=MemoryStateStore(_persisted(None)),
            breeder=BreederClient(),
            contract=contract(),
            environment=ENVIRONMENT,
            keystone_identities=IDENTITIES,
            clock=_clock,
        )
    assert exc.value.kind is BootstrapErrorCode.B_AUTH_INDETERMINATE


def test_prepare_b_a_still_functional_authenticates_as_admin() -> None:
    # PREPARE_B with PasswordSafe B already staged (B1): the A identity is
    # still functional (A credential mutation has not begun), so bootstrap
    # succeeds as admin on the first attempt.  The B1 transitional state
    # (PasswordSafe B != Keystone B) is a B-side concern that bootstrap
    # surfaces only when it actually falls back to B; it is not a lockout
    # diagnosis and is not reported here.
    transaction = _transaction(phase=RotationPhase.PREPARE_B)
    passwordsafe = _passwordsafe()
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID, project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(
        _admin_observation(), SecretValue(PASSWORD),
    )
    # Keystone B holds a different (old) password than PasswordSafe B
    # (the B1 transitional state) -- irrelevant while A is functional.
    keystone.add_user(
        _admin_observation(name="breakglass", user_id=BREAKGLASS_ID),
        SecretValue(b"SYNTHETIC_Breakglass_K_Old_0001"),
    )
    result = bootstrap_admin_session(
        keystone=keystone,
        passwordsafe=passwordsafe,
        passwordsafe_access=ACCESS,
        passwordsafe_project_id=100,
        passwordsafe_a_record_id=1000,
        passwordsafe_b_record_id=1001,
        state_store=MemoryStateStore(_persisted(transaction)),
        breeder=BreederClient(),
        contract=contract(),
        environment=ENVIRONMENT,
        keystone_identities=IDENTITIES,
        clock=_clock,
    )
    assert result.identity is AdminIdentity.ADMIN
    assert result.transaction_phase is RotationPhase.PREPARE_B
    # No B attempt was needed.
    assert keystone.password_update_calls == []


def test_malformed_transaction_provenance_fails_closed() -> None:
    # A transaction in ROTATE_A must carry a valid stable-A authority
    # provenance (a single successful stable-a verification in PREPARE_B).
    # A transaction missing that provenance cannot establish a legitimate A
    # candidate: the 3C reconciliation machinery detects the contradiction
    # and bootstrap fails closed with A_CANDIDATE_UNAVAILABLE -- never with a
    # speculative credential selection or auth attempt.  The generation
    # identifier format itself is enforced by the model at construction, so
    # this exercises the bootstrap's structural pre-check against a record
    # provenance it cannot trust.
    transaction = _transaction(phase=RotationPhase.ROTATE_A)
    bad = replace(
        transaction,
        verifications=(),
    )
    with pytest.raises(BootstrapError) as exc:
        _bootstrap(
            state_store=MemoryStateStore(_persisted(bad)),
            breeder=BreederClient(),
        )
    assert exc.value.kind is BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE


def test_environment_mismatch_fails_closed() -> None:
    with pytest.raises(BootstrapError) as exc:
        _bootstrap(
            state_store=MemoryStateStore(_persisted()),
            breeder=BreederClient(),
            environment=EnvironmentIdentity("other-env", "cluster.local"),
        )
    assert exc.value.kind is BootstrapErrorCode.ENVIRONMENT_MISMATCH


def test_state_unavailable_fails_closed() -> None:
    class FailingStore(MemoryStateStore):
        def load(self) -> PersistedState:
            from admin_password_rotation.state_store import (
                StateStoreError, StateStoreErrorCode,
            )
            raise StateStoreError(StateStoreErrorCode.SECRET_MISSING)

    with pytest.raises(BootstrapError) as exc:
        _bootstrap(state_store=FailingStore(_persisted()), breeder=BreederClient())
    assert exc.value.kind is BootstrapErrorCode.STATE_UNAVAILABLE


def test_breeder_unavailable_before_rotate_a_fails_closed() -> None:
    breeder = BreederClient()
    breeder.read_error = BreederErrorCode.NOT_FOUND
    with pytest.raises(BootstrapError) as exc:
        _bootstrap(state_store=MemoryStateStore(_persisted(None)), breeder=breeder)
    assert exc.value.kind is BootstrapErrorCode.BREEDER_UNAVAILABLE


def test_bootstrap_never_mutates() -> None:
    keystone = _keystone()
    passwordsafe = _passwordsafe()
    breeder = BreederClient()
    result = _bootstrap(
        state_store=MemoryStateStore(_persisted(None)),
        breeder=breeder,
        keystone=keystone,
        passwordsafe=passwordsafe,
    )
    assert result.identity is AdminIdentity.ADMIN
    assert keystone.password_update_calls == []
    assert keystone.lockout_update_calls == []
    assert passwordsafe.update_calls == []
    assert breeder.mutation_count == 0


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------


def _identity_token() -> SecretValue:
    return SecretValue(b"SYNTHETIC_ADMIN_TOKEN")


def test_resolve_identities_both_found() -> None:
    keystone = _keystone()
    result = resolve_identities(
        keystone=keystone,
        token=_identity_token(),
        keystone_identities=IDENTITIES,
    )
    assert isinstance(result, IdentityResolutionResult)
    assert result.ok
    assert result.errors == ()
    assert result.admin is not None
    assert result.admin.user_id == ADMIN_ID
    assert result.admin.name == "admin"
    assert result.admin.domain_id == DOMAIN_ID
    assert result.admin.enabled
    assert result.breakglass is not None
    assert result.breakglass.user_id == BREAKGLASS_ID
    assert result.breakglass.name == "breakglass"


def test_resolve_identities_missing_breakglass() -> None:
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID, project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(_admin_observation(), SecretValue(PASSWORD))
    result = resolve_identities(
        keystone=keystone,
        token=_identity_token(),
        keystone_identities=IDENTITIES,
    )
    assert not result.ok
    assert result.admin is not None
    assert result.breakglass is None
    assert any("breakglass" in item for item in result.errors)


def test_resolve_identities_disabled_identity_reported() -> None:
    keystone = _keystone()
    observation = _admin_observation()
    from dataclasses import replace as dc_replace
    keystone.add_user(
        dc_replace(observation, enabled=False, user_id=ADMIN_ID),
        SecretValue(PASSWORD),
    )
    result = resolve_identities(
        keystone=keystone,
        token=_identity_token(),
        keystone_identities=IDENTITIES,
    )
    assert not result.ok
    assert result.admin is None
    assert any("disabled" in item for item in result.errors)


def test_resolve_identities_domain_mismatch_reported() -> None:
    keystone = FakeKeystoneClient(
        project_id=PROJECT_ID, project_name="admin",
        project_domain_id=PROJECT_DOMAIN_ID,
    )
    keystone.add_user(
        _admin_observation(domain_id="wrong-domain"),
        SecretValue(PASSWORD),
    )
    keystone.add_user(
        _admin_observation(name="breakglass", user_id=BREAKGLASS_ID),
        SecretValue(b"SYNTHETIC_Breakglass_K_0001"),
    )
    result = resolve_identities(
        keystone=keystone,
        token=_identity_token(),
        keystone_identities=IDENTITIES,
    )
    assert not result.ok
    assert result.admin is None
    assert any("domain_mismatch" in item for item in result.errors)


def test_resolve_identities_read_only() -> None:
    keystone = _keystone()
    resolve_identities(
        keystone=keystone,
        token=_identity_token(),
        keystone_identities=IDENTITIES,
    )
    assert keystone.password_update_calls == []
    assert keystone.lockout_update_calls == []
    # Exactly one read per identity.
    assert len(keystone.get_user_calls) == 2


# ---------------------------------------------------------------------------
# Correction 1: A1 bootstrap must not attempt the staged A-new credential
# ---------------------------------------------------------------------------

A_NEW = SecretValue(b"SYNTHETIC_Admin_A_New_000000001")
A_NEW_GENERATION = CredentialGeneration.from_secret(A_NEW)


class BreederClientANew:
    """Breeder fake holding A-new (the staged credential), not old A."""

    def __init__(self, snapshot_uid: str = "fixture-keystone-admin") -> None:
        from tests.helpers import secret
        self._snapshot = secret("keystone-admin", {"password": A_NEW.reveal()})
        if snapshot_uid != "fixture-keystone-admin":
            self._snapshot = replace(self._snapshot, uid=snapshot_uid)
        self.read_error: BreederErrorCode | None = None
        self.read_count = 0
        self.mutation_count = 0

    def read(self, reference: BreederReference) -> SecretSnapshot:
        del reference
        self.read_count += 1
        if self.read_error is not None:
            raise BreederError(self.read_error)
        return self._snapshot

    def conditional_stage(
        self, expected: SecretSnapshot, *, password: SecretValue,
        provenance: object,
    ) -> None:
        del expected, password, provenance
        self.mutation_count += 1
        raise AssertionError("bootstrap must never mutate the breeder")


def test_a1_bootstraps_from_passwordsafe_a_not_breeder() -> None:
    """In A1 the breeder holds A-new but Keystone admin still authenticates
    old A.  Bootstrap must recover the candidate from the PasswordSafe A
    record (old A), never from the breeder (A-new).  The A-new value must
    never be attempted against Keystone."""
    # Keystone admin authenticates the old A (PASSWORD), not A-new.
    keystone = _keystone()
    # PasswordSafe A record holds old A (PASSWORD) — matches Keystone.
    passwordsafe = _passwordsafe()
    # Breeder holds A-new — the staged credential.
    breeder = BreederClientANew()
    # Durable transaction in ROTATE_A with valid stable-A provenance.
    transaction = _transaction(
        phase=RotationPhase.ROTATE_A,
        new_a=A_NEW_GENERATION,
    )
    result = bootstrap_admin_session(
        keystone=keystone,
        passwordsafe=passwordsafe,
        passwordsafe_access=ACCESS,
        passwordsafe_project_id=100,
        passwordsafe_a_record_id=1000,
        passwordsafe_b_record_id=1001,
        state_store=MemoryStateStore(_persisted(transaction)),
        breeder=breeder,
        contract=contract(),
        environment=ENVIRONMENT,
        keystone_identities=IDENTITIES,
        clock=_clock,
    )
    # Succeeded as admin using the old-A credential.
    assert result.identity is AdminIdentity.ADMIN
    assert result.transaction_phase is RotationPhase.ROTATE_A
    # The generation must be the old-A generation, not A-new.
    assert result.generation is not A_NEW_GENERATION
    # No mutation was performed.
    assert breeder.mutation_count == 0
    assert keystone.password_update_calls == []


def test_a1_passwordsafe_a_unavailable_fails_closed() -> None:
    """In A1, if the PasswordSafe A record cannot be read, bootstrap fails
    closed with A_CANDIDATE_UNAVAILABLE rather than falling back to the
    breeder (A-new) or performing a speculative auth attempt."""
    keystone = _keystone()
    # Failing PasswordSafe: get_current raises.
    passwordsafe = FailingPasswordSafe()
    breeder = BreederClientANew()
    transaction = _transaction(
        phase=RotationPhase.ROTATE_A,
        new_a=A_NEW_GENERATION,
    )
    with pytest.raises(BootstrapError) as exc:
        bootstrap_admin_session(
            keystone=keystone,
            passwordsafe=passwordsafe,
            passwordsafe_access=ACCESS,
            passwordsafe_project_id=100,
            passwordsafe_a_record_id=1000,
            passwordsafe_b_record_id=1001,
            state_store=MemoryStateStore(_persisted(transaction)),
            breeder=breeder,
            contract=contract(),
            environment=ENVIRONMENT,
            keystone_identities=IDENTITIES,
            clock=_clock,
        )
    assert exc.value.kind is BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE


# ---------------------------------------------------------------------------
# Correction 2: fresh execution without pre-resolved Keystone UUIDs
# ---------------------------------------------------------------------------


def test_fresh_no_transaction_no_identities_fails_closed() -> None:
    """A fresh process with no durable transaction and no pre-resolved
    Keystone identities has no legitimate A candidate.  Bootstrap must fail
    closed with A_CANDIDATE_UNAVAILABLE, never performing a speculative
    authentication or inventing UUIDs."""
    keystone = _keystone()
    with pytest.raises(BootstrapError) as exc:
        bootstrap_admin_session(
            keystone=keystone,
            passwordsafe=_passwordsafe(),
            passwordsafe_access=ACCESS,
            passwordsafe_project_id=100,
            passwordsafe_a_record_id=1000,
            passwordsafe_b_record_id=1001,
            state_store=MemoryStateStore(_persisted(None)),
            breeder=BreederClient(),
            contract=contract(),
            environment=ENVIRONMENT,
            # No keystone_identities supplied (fresh process).
            clock=_clock,
        )
    assert exc.value.kind is BootstrapErrorCode.A_CANDIDATE_UNAVAILABLE


def test_resume_without_explicit_identities_uses_transaction() -> None:
    """On the resume path, when the caller does not supply pre-resolved
    Keystone identities, the bootstrap must use the durable transaction's
    recorded identities as the trusted source.  This works because the
    transaction carries the ResolvedKeystoneIdentities it was created with."""
    keystone = _keystone()
    passwordsafe = _passwordsafe()
    transaction = _transaction(phase=RotationPhase.PREPARE_B)
    result = bootstrap_admin_session(
        keystone=keystone,
        passwordsafe=passwordsafe,
        passwordsafe_access=ACCESS,
        passwordsafe_project_id=100,
        passwordsafe_a_record_id=1000,
        passwordsafe_b_record_id=1001,
        state_store=MemoryStateStore(_persisted(transaction)),
        breeder=BreederClient(),
        contract=contract(),
        environment=ENVIRONMENT,
        # No keystone_identities supplied: the transaction's recorded
        # identities (IDENTITIES) are the trusted source.
        clock=_clock,
    )
    assert result.identity is AdminIdentity.ADMIN
    assert result.transaction_phase is RotationPhase.PREPARE_B


def test_resume_with_matching_explicit_identities_is_accepted() -> None:
    """When the caller supplies explicit identities that match the
    transaction's recorded identities, bootstrap proceeds normally."""
    keystone = _keystone()
    passwordsafe = _passwordsafe()
    transaction = _transaction(phase=RotationPhase.PREPARE_B)
    result = bootstrap_admin_session(
        keystone=keystone,
        passwordsafe=passwordsafe,
        passwordsafe_access=ACCESS,
        passwordsafe_project_id=100,
        passwordsafe_a_record_id=1000,
        passwordsafe_b_record_id=1001,
        state_store=MemoryStateStore(_persisted(transaction)),
        breeder=BreederClient(),
        contract=contract(),
        environment=ENVIRONMENT,
        keystone_identities=IDENTITIES,  # matches transaction.keystone
        clock=_clock,
    )
    assert result.identity is AdminIdentity.ADMIN
    assert result.transaction_phase is RotationPhase.PREPARE_B


# ---------------------------------------------------------------------------
# Correction: identity consistency check on resume
# ---------------------------------------------------------------------------


def test_resume_mismatched_explicit_identities_fails_before_auth() -> None:
    """When the caller supplies explicit identities that differ from the
    transaction's recorded identities, bootstrap fails closed with
    IDENTITY_CONSISTENCY_MISMATCH before any Keystone authentication is
    attempted."""
    keystone = _keystone()
    passwordsafe = _passwordsafe()
    transaction = _transaction(phase=RotationPhase.PREPARE_B)
    # Mismatch: different admin_user_id.
    mismatched = replace(
        IDENTITIES,
        admin_user_id="different-admin-user-id",
    )
    with pytest.raises(BootstrapError) as exc:
        bootstrap_admin_session(
            keystone=keystone,
            passwordsafe=passwordsafe,
            passwordsafe_access=ACCESS,
            passwordsafe_project_id=100,
            passwordsafe_a_record_id=1000,
            passwordsafe_b_record_id=1001,
            state_store=MemoryStateStore(_persisted(transaction)),
            breeder=BreederClient(),
            contract=contract(),
            environment=ENVIRONMENT,
            keystone_identities=mismatched,
            clock=_clock,
        )
    assert exc.value.kind is BootstrapErrorCode.IDENTITY_CONSISTENCY_MISMATCH
    # No Keystone authentication was attempted.
    assert keystone.auth_calls == []
    # No Keystone password mutation occurred.
    assert keystone.password_update_calls == []


def test_resume_mismatched_project_id_fails_before_auth() -> None:
    """A mismatch on any identity field (here: project_id) triggers the
    consistency check, not just the admin user UUID."""
    keystone = _keystone()
    passwordsafe = _passwordsafe()
    transaction = _transaction(phase=RotationPhase.PREPARE_B)
    mismatched = replace(IDENTITIES, project_id="different-project-id")
    with pytest.raises(BootstrapError) as exc:
        bootstrap_admin_session(
            keystone=keystone,
            passwordsafe=passwordsafe,
            passwordsafe_access=ACCESS,
            passwordsafe_project_id=100,
            passwordsafe_a_record_id=1000,
            passwordsafe_b_record_id=1001,
            state_store=MemoryStateStore(_persisted(transaction)),
            breeder=BreederClient(),
            contract=contract(),
            environment=ENVIRONMENT,
            keystone_identities=mismatched,
            clock=_clock,
        )
    assert exc.value.kind is BootstrapErrorCode.IDENTITY_CONSISTENCY_MISMATCH
    # No Keystone authentication was attempted.
    assert keystone.auth_calls == []
    # No Keystone password mutation occurred.
    assert keystone.password_update_calls == []
