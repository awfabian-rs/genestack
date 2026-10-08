"""Slice 4F: transaction-level ``VERIFY_B`` gate tests.

``run_verify_b`` must freshly establish the B safety bridge from current
external state only: fresh breakglass authentication, every participating
``identity: active`` location structurally at the verified breakglass
credential, every derived restart action durably complete, and every affected
workload freshly observed rolled out and ready.  Only then may the durable
phase advance to ``ROTATE_A``.  These tests compose the existing behavioral
fakes (the same ones the Slice 4E tests use) rather than introducing parallel
test abstractions, and use realistic grouped-Secret fixtures.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import cast
from uuid import UUID

import pytest

from admin_password_rotation.config import parse_contract
from admin_password_rotation.errors import SafeError
from admin_password_rotation.keystone import (
    FakeKeystoneClient, KeystoneIndeterminateReason, KeystoneUserObservation,
)
from admin_password_rotation.model import (
    ConfigurationDigest, CredentialGeneration, EnvironmentIdentity,
    ExecutionIdentity, Identity, LockoutChangeState, LockoutState,
    PasswordSafeState, PersistentState, PropagationState, PropagationWave,
    ReferenceCredentials, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, RuntimeActionProgress, RuntimeActionState, SecretField,
    SecretInventory, SecretSnapshot, SecretValue, TransactionStatus,
    VerificationResult, VerificationStatus,
)
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient, IdentityAccess, PasswordSafeCredential,
)
from admin_password_rotation.propagation import (
    DesiredCredential, FakeCredentialSecretClient,
)
from admin_password_rotation.propagation_wave import (
    plan_or_reconcile_propagation_wave,
)
from admin_password_rotation.restart import (
    RolloutStatus, WorkloadClient, WorkloadSnapshot,
)
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import (
    PersistedState, StateRevision, StateStore,
)
from admin_password_rotation.verify_b import (
    VerifyBError, VerifyBErrorCode, VerifyBInputs, VerifyBOutcome,
    VerifyBRequest, run_verify_b,
)

NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
ACCESS = IdentityAccess(datetime(2030, 1, 1, tzinfo=timezone.utc), SecretValue(b"ps-token"))
PROJECT_ID = 10
PS_A = 101
PS_B = 202
ADMIN = SecretValue(b"Synthetic-Old-Admin-4F")
BREAKGLASS = SecretValue(b"Synthetic-Breakglass-4F")
ADMIN_GENERATION = CredentialGeneration.from_secret(ADMIN)
BREAKGLASS_GENERATION = CredentialGeneration.from_secret(BREAKGLASS)
EXECUTION = ExecutionIdentity(
    UUID("44444444-4444-4444-8444-444444444444"), None,
)


def _contract_text() -> str:
    # Grouped Secret: two logical credential locations sharing one INI
    # document/data key, so the realistic grouped-Secret cases are exercised.
    return """namespace: openstack
locations:
  keystone-admin:
    secret: keystone-admin
    identity: admin
    role: source
    representation:
      type: fields
      password: password
    restart: []
  neutron:
    secret: neutron-keystone-admin
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart:
      - daemonset/neutron-netns-cleanup-cron-default
  octavia-etc:
    secret: octavia-etc
    identity: active
    role: propagated
    representation:
      type: ini
      key: octavia.conf
      section: service_auth
      username: username
      password: password
    restart:
      - deployment/octavia-api
      - deployment/octavia-housekeeping
  octavia-worker:
    secret: octavia-etc
    identity: active
    role: propagated
    representation:
      type: ini
      key: octavia.conf
      section: worker
      username: username
      password: password
    restart:
      - daemonset/octavia-worker-default
  no-restart:
    secret: no-restart
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart: []
"""


def _fixed_admin_contract_text() -> str:
    return """namespace: openstack
locations:
  keystone-admin:
    secret: keystone-admin
    identity: admin
    role: source
    representation:
      type: fields
      password: password
    restart: []
  admin-fixed:
    secret: admin-fixed-consumer
    identity: admin
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart: []
  active:
    secret: active-consumer
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart:
      - deployment/active-api
"""


def _pair(identity: Identity) -> tuple[bytes, bytes]:
    password = ADMIN if identity is Identity.ADMIN else BREAKGLASS
    return identity.value.encode(), password.reveal()


def snapshot(name: str, data: dict[str, bytes], *, uid: str | None = None) -> SecretSnapshot:
    return SecretSnapshot(
        "openstack", name, uid or f"uid-{name}", "7",
        tuple(SecretField(key, SecretValue(value)) for key, value in sorted(data.items())),
    )


def _ini(identity: Identity) -> bytes:
    username, password = _pair(identity)
    return (
        b"[service_auth]\nusername = " + username
        + b"\npassword = " + password + b"\n"
        b"[worker]\nusername = " + username
        + b"\npassword = " + password + b"\n"
    )


def _secrets(
    *, neutron: Identity = Identity.ADMIN,
    octavia: Identity = Identity.ADMIN,
    none: Identity = Identity.ADMIN,
    admin_fixed: Identity = Identity.ADMIN,
    active: Identity = Identity.ADMIN,
) -> dict[str, SecretSnapshot]:
    un, pw = _pair(neutron)
    oe = _ini(octavia)
    uf, pf = _pair(admin_fixed)
    ua, pa = _pair(active)
    return {
        "keystone-admin": snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        "neutron-keystone-admin": snapshot("neutron-keystone-admin", {
            "OS_USERNAME": un, "OS_PASSWORD": pw,
        }),
        "octavia-etc": snapshot("octavia-etc", {"octavia.conf": oe}),
        "no-restart": snapshot("no-restart", {
            "OS_USERNAME": _pair(none)[0], "OS_PASSWORD": _pair(none)[1],
        }),
        "admin-fixed-consumer": snapshot("admin-fixed-consumer", {
            "OS_USERNAME": uf, "OS_PASSWORD": pf,
        }),
        "active-consumer": snapshot("active-consumer", {
            "OS_USERNAME": ua, "OS_PASSWORD": pa,
        }),
    }


def _all_workload_names() -> list[str]:
    return [
        "neutron-netns-cleanup-cron-default",
        "octavia-api", "octavia-housekeeping",
        "octavia-worker-default",
    ]


def _all_action_ids() -> list[str]:
    return sorted({
        "daemonset_neutron-netns-cleanup-cron-default",
        "deployment_octavia-api",
        "deployment_octavia-housekeeping",
        "daemonset_octavia-worker-default",
    })


# ---------------------------------------------------------------------------
# Ownership / state store fakes
# ---------------------------------------------------------------------------


class Ownership:
    def __init__(self, *, fail: bool = False, fail_after: int = -1) -> None:
        self.assertions = 0
        self.fail = fail
        # Fail the assertion occurring strictly after the Nth one (1-based).
        self.fail_after = fail_after

    @property
    def requires_recovery_gate(self) -> bool:
        return False

    def assert_owned(self) -> None:
        self.assertions += 1
        if self.fail or (self.fail_after >= 0 and self.assertions > self.fail_after):
            raise SafeError("ownership_lost", "ownership lost")


class MemoryStateStore(StateStore):
    def __init__(self, current: PersistedState) -> None:
        self.current = current
        self.update_count = 0
        self.fail_update: Exception | None = None

    def load(self) -> PersistedState:
        return self.current

    def update(self, expected: StateRevision, new_state: PersistentState) -> PersistedState:
        if self.fail_update is not None:
            error = self.fail_update
            self.fail_update = None
            raise error
        assert expected == self.current.revision
        self.update_count += 1
        self.current = PersistedState(
            new_state,
            replace(expected, resource_version=str(int(expected.resource_version) + 1)),
        )
        return self.current


# ---------------------------------------------------------------------------
# Workload fakes (reused from the Slice 4E test harness)
# ---------------------------------------------------------------------------


class _FakeWorkload:
    def __init__(self, name: str) -> None:
        self.namespace = "openstack"
        self.name = name
        self.uid = f"uid-{name}"
        self.restart_requested: str | None = None
        self.metadata_generation = 1
        self.observed_generation = 1
        self.desired_replicas = 1
        self.updated_replicas = 1
        self.ready_replicas = 1
        self.unavailable_replicas = 0
        self.rollout_status = RolloutStatus.PENDING
        self.rollout_completed = False
        # When True (the default), a read auto-advances the rollout once the
        # restart marker is present.  Tests that model an unhealthy workload
        # set this to False so the fresh observation is exactly as configured.
        self.auto_advance = True
        self.restart_call_count = 0

    def snapshot(self) -> WorkloadSnapshot:
        return WorkloadSnapshot(
            namespace=self.namespace, name=self.name, uid=self.uid,
            restart_requested=self.restart_requested,
            metadata_generation=self.metadata_generation,
            observed_generation=self.observed_generation,
            ready_replicas=self.ready_replicas, desired_replicas=self.desired_replicas,
            updated_replicas=self.updated_replicas,
            unavailable_replicas=self.unavailable_replicas,
            rollout_status=self.rollout_status, condition_reason=None,
        )

    def advance(self) -> None:
        if self.auto_advance and self.restart_requested is not None and not self.rollout_completed:
            self.observed_generation = self.metadata_generation
            self.updated_replicas = self.desired_replicas
            self.ready_replicas = self.desired_replicas
            self.unavailable_replicas = 0
            self.rollout_status = RolloutStatus.SUCCEEDED
            self.rollout_completed = True

    def restart(self, request: str) -> None:
        self.restart_call_count += 1
        self.restart_requested = request
        self.metadata_generation += 1
        self.updated_replicas = 0
        self.ready_replicas = 0
        self.unavailable_replicas = self.desired_replicas
        self.rollout_status = RolloutStatus.PENDING


class _FakeDeploymentClient:
    def __init__(self, workloads: dict[str, _FakeWorkload]) -> None:
        self.workloads = workloads
        self.restart_calls: list[tuple[str, str, str]] = []

    def read(self, namespace: str, name: str) -> WorkloadSnapshot:
        workload = self.workloads[name]
        workload.advance()
        return workload.snapshot()

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
        self.restart_calls.append((namespace, name, request))
        workload = self.workloads[name]
        workload.restart(request)
        return workload.snapshot()


class _FakeDaemonSetClient:
    def __init__(self, workloads: dict[str, _FakeWorkload]) -> None:
        self.workloads = workloads
        self.restart_calls: list[tuple[str, str, str]] = []

    def read(self, namespace: str, name: str) -> WorkloadSnapshot:
        workload = self.workloads[name]
        workload.advance()
        return workload.snapshot()

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
        self.restart_calls.append((namespace, name, request))
        workload = self.workloads[name]
        workload.restart(request)
        return workload.snapshot()


class _FakeWorkloadClient:
    deployment: _FakeDeploymentClient
    daemonset: _FakeDaemonSetClient
    workloads: dict[str, _FakeWorkload]

    def __init__(self, workloads: dict[str, _FakeWorkload]) -> None:
        self.deployment = _FakeDeploymentClient(workloads)
        self.daemonset = _FakeDaemonSetClient(workloads)
        self.workloads = workloads


def _workloads(*names: str) -> dict[str, _FakeWorkload]:
    return {name: _FakeWorkload(name) for name in names}


def _restarted_workloads(wave: PropagationWave) -> dict[str, _FakeWorkload]:
    """Workloads that were restarted for the wave and have rolled out complete.

    The deterministic restart marker is present and the rollout is converged,
    so a fresh observation classifies them complete for this wave.
    """
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads(*_all_workload_names())
    for workload in workloads.values():
        workload.restart_requested = marker
        workload.metadata_generation = 2
        workload.observed_generation = 2
        workload.rollout_status = RolloutStatus.SUCCEEDED
        workload.rollout_completed = True
    return workloads


# ---------------------------------------------------------------------------
# Transaction fixtures
# ---------------------------------------------------------------------------


def _keystone_with(b_value: SecretValue) -> FakeKeystoneClient:
    client = FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    client.add_user(
        KeystoneUserObservation("admin-user", "admin", "default-domain", True,
                                "admin-project", False),
        ADMIN,
    )
    client.add_user(
        KeystoneUserObservation("breakglass-user", "breakglass", "default-domain",
                                True, "admin-project", False),
        b_value,
    )
    return client


def _passwordsafe(b_value: SecretValue) -> FakePasswordSafeClient:
    client = FakePasswordSafeClient()
    client.add(PasswordSafeCredential(PROJECT_ID, PS_A, "admin", 7, ADMIN))
    client.add(PasswordSafeCredential(PROJECT_ID, PS_B, "breakglass", 3, b_value))
    return client


def _request() -> VerifyBRequest:
    return VerifyBRequest(
        environment=EnvironmentIdentity("dfw-dev", "cluster.local"),
        keystone=ResolvedKeystoneIdentities(
            admin_user_id="admin-user", breakglass_user_id="breakglass-user",
            user_domain_id="default-domain", project_id="admin-project",
            project_domain_id="default-domain", role_id="admin-role",
        ),
        passwordsafe_project_id=PROJECT_ID,
        passwordsafe_b_record_id=PS_B,
        execution=EXECUTION,
        breakglass_username="breakglass",
    )


def _switch_to_b_receipt() -> VerificationResult:
    return VerificationResult(
        check_id="switch-to-b-complete",
        phase=RotationPhase.SWITCH_TO_B,
        status=VerificationStatus.SUCCESS,
        checked_at=NOW,
        detail_code="propagated-and-restarted",
        target_uid=None,
        credential_generation=BREAKGLASS_GENERATION,
    )


def _transaction(
    *, phase: RotationPhase = RotationPhase.VERIFY_B,
    wave: PropagationWave | None = None,
    verifications: tuple[VerificationResult, ...] | None = None,
    execution: ExecutionIdentity | None = None,
) -> RotationTransaction:
    if verifications is None:
        verifications = (
            VerificationResult(
                check_id="stable-a", phase=RotationPhase.PREPARE_B,
                status=VerificationStatus.SUCCESS, checked_at=NOW,
                detail_code="freshly-verified", target_uid="uid-keystone-admin",
                credential_generation=ADMIN_GENERATION,
            ),
            VerificationResult(
                check_id="breakglass-b2", phase=RotationPhase.PREPARE_B,
                status=VerificationStatus.SUCCESS, checked_at=NOW,
                detail_code="freshly-authorized", target_uid=None,
                credential_generation=BREAKGLASS_GENERATION,
            ),
            _switch_to_b_receipt(),
        )
    return RotationTransaction(
        transaction_id=UUID("11111111-1111-4111-8111-111111111111"),
        request_id=UUID("22222222-2222-4222-8222-222222222222"),
        execution=execution or EXECUTION,
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=ResolvedKeystoneIdentities(
            admin_user_id="admin-user", breakglass_user_id="breakglass-user",
            user_domain_id="default-domain", project_id="admin-project",
            project_domain_id="default-domain", role_id="admin-role",
        ),
        created_at=NOW,
        updated_at=NOW,
        phase=phase,
        status=TransactionStatus.ACTIVE,
        last_error=None,
        new_a_sha256=None,
        new_b_sha256=BREAKGLASS_GENERATION,
        passwordsafe=PasswordSafeState(
            configured_a_record_id=PS_A, configured_b_record_id=PS_B,
            observed_a_record_id=PS_A, observed_b_record_id=PS_B,
            original_a_version=7, observed_a_version=7, observed_b_version=3,
        ),
        credential_mutation_intent=None,
        propagation=PropagationState(
            wave if wave is not None else PropagationWave((), ()), PropagationWave((), ()),
        ),
        lockout=LockoutState(
            initial_ignore_lockout_failure_attempts=False,
            suppression=LockoutChangeState.NOT_INTENDED,
            restoration=LockoutChangeState.NOT_INTENDED,
            latest_ignore_lockout_failure_attempts=False,
            restore_required=False,
        ),
        verifications=verifications,
    )


def _state_for(transaction: RotationTransaction) -> PersistedState:
    return PersistedState(
        PersistentState(
            schema_version=2,
            environment=EnvironmentIdentity("dfw-dev", "cluster.local"),
            current_transaction=transaction,
            completed_requests=(),
        ),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )


def _planned_wave(
    secrets: dict[str, SecretSnapshot], *,
    contract_text: str = _contract_text(),
) -> PropagationWave:
    parsed = parse_contract(contract_text)
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(
        secrets["keystone-admin"].get("password") or ADMIN, BREAKGLASS,
    )
    return plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    ).wave


def _complete_wave(secrets: dict[str, SecretSnapshot]) -> PropagationWave:
    """A fully applied to-B wave: intent + applied set + COMPLETE actions.

    Modeled as the durable state left by a completed ``SWITCH_TO_B``: the
    grouped Secret (octavia-etc) is at B, every participating location is
    applied (stable sorted order, as the executor persists it), and every
    derived restart action is COMPLETE.
    """
    wave = _planned_wave(secrets)
    applied = (
        "neutron", "no-restart", "octavia-etc", "octavia-worker",
    )
    actions = tuple(
        RuntimeActionProgress(action_id, RuntimeActionState.COMPLETE)
        for action_id in _all_action_ids()
    )
    return replace(wave, applied_location_ids=applied, runtime_actions=actions)


def _run(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, owner: Ownership, *,
    contract_text: str = _contract_text(),
    b_value: SecretValue = BREAKGLASS,
    keystone_client: FakeKeystoneClient | None = None,
    passwordsafe_client: FakePasswordSafeClient | None = None,
):
    parsed = parse_contract(contract_text)
    keystone_client = keystone_client or _keystone_with(b_value)
    passwordsafe_client = passwordsafe_client or _passwordsafe(b_value)
    inputs = VerifyBInputs(
        request=_request(),
        contract=parsed,
        passwordsafe_access=ACCESS,
        secret_client=secret_client,
        workload_client=cast(WorkloadClient, workload_client),
    )
    return run_verify_b(
        inputs,
        state_store=store,
        ownership=owner,
        passwordsafe=passwordsafe_client,
        keystone=keystone_client,
        clock=lambda: NOW,
    )


def _assert_no_side_effects(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, *, phase: RotationPhase,
) -> None:
    """No Secret mutation, no restart dispatch, no phase advancement."""
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is phase
    assert transaction.new_a_sha256 is None


# ---------------------------------------------------------------------------
# 1. successful VERIFY_B
# ---------------------------------------------------------------------------


def test_successful_verify_b_advances_to_rotate_a() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    assert result.outcome is VerifyBOutcome.VERIFIED
    assert result.verified is True
    assert result.phase is RotationPhase.ROTATE_A
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A
    assert transaction.status is TransactionStatus.ACTIVE
    # The credential-free completion receipt records the freshly verified bridge.
    assert any(
        item.check_id == "verify-b-complete"
        and item.phase is RotationPhase.VERIFY_B
        and item.status is VerificationStatus.SUCCESS
        and item.credential_generation == BREAKGLASS_GENERATION
        for item in transaction.verifications
    )
    # No Secret write and no restart dispatch: verification is observational.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    # Admin credential untouched.
    assert secret_client.current("openstack", "keystone-admin").get("password") == ADMIN


# ---------------------------------------------------------------------------
# 2. breakglass authentication failure
# ---------------------------------------------------------------------------


def test_breakglass_auth_rejection_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    # PasswordSafe still holds the recorded generation but Keystone rejects it.
    ks = FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    ks.add_user(
        KeystoneUserObservation("admin-user", "admin", "default-domain", True,
                                "admin-project", False),
        ADMIN,
    )
    ks.add_user(
        KeystoneUserObservation("breakglass-user", "breakglass", "default-domain",
                                True, "admin-project", False),
        SecretValue(b"Some-Rotated-Elsewhere-B-Value"),
    )
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner, keystone_client=ks)
    assert raised.value.kind is VerifyBErrorCode.B_CREDENTIAL_UNRESOLVED
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_breakglass_auth_indeterminate_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    ks = _keystone_with(BREAKGLASS)
    ks.next_auth_indeterminate = KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner, keystone_client=ks)
    assert raised.value.kind is VerifyBErrorCode.B_AUTH_INDETERMINATE
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_breakglass_generation_drift_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    # PasswordSafe B no longer contains the recorded generation.
    drifted = _passwordsafe(SecretValue(b"Drifted-Breakglass-Generation"))
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner,
             passwordsafe_client=drifted)
    assert raised.value.kind is VerifyBErrorCode.B_CREDENTIAL_UNRESOLVED
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 3. an expected active location remains on admin
# ---------------------------------------------------------------------------


def test_location_still_on_admin_fails_closed() -> None:
    # Progress claims the complete wave (applied set + COMPLETE actions), but
    # the neutron Secret has regressed to admin: observed state wins and the
    # gate fails without advancing.
    b_secrets = _secrets(
        neutron=Identity.ADMIN, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 4. an active location contains an unknown credential
# ---------------------------------------------------------------------------


def test_unknown_credential_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    # The octavia Secret now holds an unrecognized credential in one of its
    # two grouped locations.
    tampered = replace(
        b_secrets["octavia-etc"],
        data=(
            SecretField("octavia.conf", SecretValue(
                b"[service_auth]\nusername = breakglass\n"
                b"password = " + BREAKGLASS.reveal() + b"\n"
                b"[worker]\nusername = someuser\n"
                b"password = some-unrecognized-password\n",
            )),
        ),
    )
    tampered_secrets = dict(b_secrets)
    tampered_secrets["octavia-etc"] = tampered
    secret_client = FakeCredentialSecretClient(*tampered_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    # Not overwritten.
    assert secret_client.replace_calls == 0
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 5. fixed identity: admin locations remain on admin: not a failure
# ---------------------------------------------------------------------------


def test_fixed_admin_locations_on_admin_not_a_failure() -> None:
    # A contract that also declares a fixed identity: admin propagated
    # location.  The B transition never switches it, and VERIFY_B must not
    # treat its remaining on admin as a failure.
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    # Only the active location participates in the B wave; the fixed-admin
    # location stays on admin.
    wave = _planned_wave(secrets, contract_text=_fixed_admin_contract_text())
    # The active-consumer Secret must be at B for verification.
    un, pw = _pair(Identity.BREAKGLASS)
    secrets["active-consumer"] = snapshot("active-consumer", {
        "OS_USERNAME": un, "OS_PASSWORD": pw,
    })
    # Re-plan with the active consumer at B so expected_target reflects it.
    wave = _planned_wave(secrets, contract_text=_fixed_admin_contract_text())
    applied = ("active",)
    actions = (RuntimeActionProgress("deployment_active-api", RuntimeActionState.COMPLETE),)
    wave = replace(wave, applied_location_ids=applied, runtime_actions=actions)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads("active-api")
    workloads["active-api"].restart_requested = marker
    workloads["active-api"].metadata_generation = 2
    workloads["active-api"].observed_generation = 2
    workloads["active-api"].rollout_status = RolloutStatus.SUCCEEDED
    workloads["active-api"].rollout_completed = True
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner,
                  contract_text=_fixed_admin_contract_text())
    assert result.outcome is VerifyBOutcome.VERIFIED
    assert result.phase is RotationPhase.ROTATE_A
    # The fixed admin location is untouched and remains on admin.
    assert secret_client.current("openstack", "admin-fixed-consumer").get("OS_USERNAME") == SecretValue(b"admin")
    assert secret_client.current("openstack", "admin-fixed-consumer").get("OS_PASSWORD") == ADMIN


# ---------------------------------------------------------------------------
# 6. restart required by the B wave is incomplete
# ---------------------------------------------------------------------------


def test_incomplete_restart_action_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    # One required action is still RUNNING: the durable obligation is not
    # discharged.
    wave = replace(
        wave,
        runtime_actions=tuple(
            RuntimeActionProgress(
                item.action_id,
                RuntimeActionState.RUNNING
                if item.action_id == "deployment_octavia-api"
                else item.state,
            )
            for item in wave.runtime_actions
        ),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.RESTART_INCOMPLETE
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 7. restarted Deployment unhealthy/not rolled out
# ---------------------------------------------------------------------------


def test_deployment_not_rolled_out_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workloads = _restarted_workloads(wave)
    # The octavia-api Deployment rolled back to an old generation: the
    # restart marker is gone and the observed generation has not converged.
    bad = workloads["octavia-api"]
    bad.auto_advance = False
    bad.restart_requested = None
    bad.metadata_generation = 3
    bad.observed_generation = 2
    bad.updated_replicas = 0
    bad.ready_replicas = 0
    bad.unavailable_replicas = bad.desired_replicas
    bad.rollout_status = RolloutStatus.PENDING
    bad.rollout_completed = False
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.WORKLOAD_UNHEALTHY
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_deployment_failed_rollout_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workloads = _restarted_workloads(wave)
    bad = workloads["octavia-housekeeping"]
    bad.auto_advance = False
    bad.rollout_status = RolloutStatus.FAILED
    bad.rollout_completed = False
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.WORKLOAD_UNHEALTHY
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 8. restarted DaemonSet unhealthy/not rolled out
# ---------------------------------------------------------------------------


def test_daemonset_not_rolled_out_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workloads = _restarted_workloads(wave)
    # The neutron DaemonSet: not all scheduled replicas are ready/updated.
    bad = workloads["neutron-netns-cleanup-cron-default"]
    bad.auto_advance = False
    bad.desired_replicas = 3
    bad.updated_replicas = 1
    bad.ready_replicas = 2
    bad.unavailable_replicas = 1
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.WORKLOAD_UNHEALTHY
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_workload_missing_fails_closed() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    # The octavia-worker DaemonSet was deleted after the restart: a required
    # affected workload is absent, so the bridge cannot be trusted.
    from admin_password_rotation.restart import (
        WorkloadClientError, WorkloadClientErrorCode,
    )

    class _MissingDaemonSetClient:
        def __init__(self, workloads: dict[str, _FakeWorkload]) -> None:
            self.workloads = workloads
            self.restart_calls: list[tuple[str, str, str]] = []

        def read(self, namespace: str, name: str) -> WorkloadSnapshot:
            if name == "octavia-worker-default":
                raise WorkloadClientError(WorkloadClientErrorCode.NOT_FOUND)
            workload = self.workloads[name]
            workload.advance()
            return workload.snapshot()

        def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
            self.restart_calls.append((namespace, name, request))
            workload = self.workloads[name]
            workload.restart(request)
            return workload.snapshot()

    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    workload_client.daemonset = cast(_FakeDaemonSetClient,
                                     _MissingDaemonSetClient(workload_client.workloads))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.WORKLOAD_UNHEALTHY
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 9. progress claims complete but observed state disagrees
# ---------------------------------------------------------------------------


def test_progress_complete_but_secret_regressed_observed_state_wins() -> None:
    # The durable record says every action COMPLETE and every location
    # applied, but a Secret has been changed concurrently into an
    # unexplained (unknown) state: observed state wins and the gate fails.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                       none=Identity.BREAKGLASS)
    secrets["no-restart"] = replace(
        secrets["no-restart"],
        data=(
            SecretField("OS_USERNAME", SecretValue(b"mystery")),
            SecretField("OS_PASSWORD", SecretValue(b"mystery-password")),
        ),
    )
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_progress_complete_but_workload_regressed_observed_state_wins() -> None:
    # Durable action records are COMPLETE, but the workload has since been
    # reset (marker gone, generation un-converged): the fresh observation
    # must decide, not the durable flag.
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workloads = _restarted_workloads(wave)
    workloads["octavia-api"].auto_advance = False
    workloads["octavia-api"].restart_requested = None
    workloads["octavia-api"].metadata_generation = 1
    workloads["octavia-api"].observed_generation = 1
    workloads["octavia-api"].rollout_status = RolloutStatus.PENDING
    workloads["octavia-api"].rollout_completed = False
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.WORKLOAD_UNHEALTHY
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 10. crash/retry semantics
# ---------------------------------------------------------------------------


def test_repeated_successful_observation_is_harmless() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    assert result.outcome is VerifyBOutcome.VERIFIED
    # Second invocation: the transaction is already past VERIFY_B, so the
    # checks are not re-run and the phase does not regress or double-advance.
    store2 = MemoryStateStore(store.current)
    result2 = _run(store2, secret_client, workload_client, owner)
    assert result2.outcome is VerifyBOutcome.ALREADY_ADVANCED
    assert result2.verified is False
    assert result2.phase is RotationPhase.ROTATE_A
    transaction = store2.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A
    # The verify-b-complete receipt appears exactly once.
    receipts = [
        item for item in transaction.verifications
        if item.check_id == "verify-b-complete"
    ]
    assert len(receipts) == 1
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


def test_retry_after_failure_succeeds_once_environment_corrected() -> None:
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    # First attempt: the neutron Secret regressed to admin.
    broken = _secrets(neutron=Identity.ADMIN, octavia=Identity.BREAKGLASS,
                      none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*broken.values())
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    assert store.current.state.current_transaction is not None
    assert store.current.state.current_transaction.phase is RotationPhase.VERIFY_B
    # The environment is corrected (operator reconciles the Secret back to B);
    # the same resumable invocation now succeeds.
    fixed = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                     none=Identity.BREAKGLASS)
    secret_client2 = FakeCredentialSecretClient(*fixed.values())
    result = _run(store, secret_client2, workload_client, owner)
    assert result.outcome is VerifyBOutcome.VERIFIED
    assert result.phase is RotationPhase.ROTATE_A


def test_crash_after_checks_before_phase_advance_reruns_checks() -> None:
    # Model the crash window: all checks succeed but the phase-advance write
    # is never persisted (the durable state is still VERIFY_B).  Re-invoking
    # simply re-runs the checks from fresh observation and advances.
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    transaction = _transaction(wave=wave)
    state = _state_for(transaction)
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    # Simulate the failed advance: the store rejects the phase-advance write.
    from admin_password_rotation.state_store import StateStoreError, StateStoreErrorCode
    store.fail_update = StateStoreError(StateStoreErrorCode.KUBERNETES_FAILURE)
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.PROGRESS_PERSISTENCE_FAILED
    # Durable state is unchanged: still VERIFY_B.
    assert store.current.state.current_transaction is not None
    assert store.current.state.current_transaction.phase is RotationPhase.VERIFY_B
    # Retry with a healthy store: checks re-run and the phase advances.
    result = _run(store, secret_client, workload_client, owner)
    assert result.outcome is VerifyBOutcome.VERIFIED
    assert result.phase is RotationPhase.ROTATE_A


# ---------------------------------------------------------------------------
# 11. ownership lost before committing successful verification
# ---------------------------------------------------------------------------


def test_ownership_lost_before_commit_does_not_advance() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    # Ownership passes every earlier assertion (the re-stamp is a no-op here
    # because the execution is already current) and fails the assertion that
    # precedes the phase-advance write.
    first = Ownership(fail_after=0)
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, first)
    assert raised.value.kind is VerifyBErrorCode.PROGRESS_PERSISTENCE_FAILED
    # No durable write occurred: the phase did not advance.
    assert store.update_count == 0
    assert store.current.state.current_transaction is not None
    assert store.current.state.current_transaction.phase is RotationPhase.VERIFY_B
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# 12. already-advanced transaction
# ---------------------------------------------------------------------------


def test_already_advanced_is_deterministic() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    transaction = _transaction(wave=wave)
    advanced = replace(
        transaction,
        phase=RotationPhase.ROTATE_A,
        verifications=(*transaction.verifications, VerificationResult(
            check_id="verify-b-complete", phase=RotationPhase.VERIFY_B,
            status=VerificationStatus.SUCCESS, checked_at=NOW,
            detail_code="bridge-freshly-verified", target_uid=None,
            credential_generation=BREAKGLASS_GENERATION,
        )),
    )
    state = _state_for(advanced)
    store = MemoryStateStore(state)
    # Even with externally degraded observations (secrets back on admin),
    # an already-advanced (successor-phase) transaction is reported without
    # re-running checks.
    degraded = _secrets()
    secret_client = FakeCredentialSecretClient(*degraded.values())
    workload_client = _FakeWorkloadClient(_workloads())
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    assert result.outcome is VerifyBOutcome.ALREADY_ADVANCED
    assert result.verified is False
    assert result.phase is RotationPhase.ROTATE_A
    transaction_after = store.current.state.current_transaction
    assert transaction_after is not None
    assert transaction_after.phase is RotationPhase.ROTATE_A
    assert store.update_count == 0
    assert secret_client.replace_calls == 0


def test_stable_a_phase_rejected() -> None:
    # STABLE_A is a predecessor of VERIFY_B (no transaction should even be in
    # this phase in practice): it must be rejected, not reported as
    # already-advanced.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave, phase=RotationPhase.STABLE_A))
    store = MemoryStateStore(state)
    b_secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                         none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.UNSUPPORTED_PHASE
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.STABLE_A)


def test_rotate_a_phase_is_successor() -> None:
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    transaction = _transaction(wave=wave)
    advanced = replace(
        transaction,
        phase=RotationPhase.ROTATE_A,
        verifications=(*transaction.verifications, VerificationResult(
            check_id="verify-b-complete", phase=RotationPhase.VERIFY_B,
            status=VerificationStatus.SUCCESS, checked_at=NOW,
            detail_code="bridge-freshly-verified", target_uid=None,
            credential_generation=BREAKGLASS_GENERATION,
        )),
    )
    store = MemoryStateStore(_state_for(advanced))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    assert result.outcome is VerifyBOutcome.ALREADY_ADVANCED
    assert result.verified is False
    assert result.phase is RotationPhase.ROTATE_A
    assert store.update_count == 0


def test_switch_to_a_phase_is_successor() -> None:
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    store = MemoryStateStore(
        _state_for(_transaction(wave=wave, phase=RotationPhase.SWITCH_TO_A)),
    )
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    assert result.outcome is VerifyBOutcome.ALREADY_ADVANCED
    assert result.verified is False
    assert result.phase is RotationPhase.SWITCH_TO_A
    assert store.update_count == 0


def test_verify_a_phase_is_successor() -> None:
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    store = MemoryStateStore(
        _state_for(_transaction(wave=wave, phase=RotationPhase.VERIFY_A)),
    )
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    assert result.outcome is VerifyBOutcome.ALREADY_ADVANCED
    assert result.verified is False
    assert result.phase is RotationPhase.VERIFY_A
    assert store.update_count == 0


# ---------------------------------------------------------------------------
# 13. no credential values in serialized results or exceptions
# ---------------------------------------------------------------------------


def test_no_credentials_in_result_or_diagnostics() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    serialized = serialize_state_json(result.persisted.state)
    assert ADMIN.reveal().decode() not in serialized
    assert BREAKGLASS.reveal().decode() not in serialized
    assert BREAKGLASS.reveal().decode() not in str(result)
    assert BREAKGLASS.reveal().decode() not in repr(result)
    assert ADMIN.reveal().decode() not in repr(result)
    # The failure path is also credential-free.
    broken = _secrets(neutron=Identity.ADMIN, octavia=Identity.BREAKGLASS,
                      none=Identity.BREAKGLASS)
    secret_client2 = FakeCredentialSecretClient(*broken.values())
    store2 = MemoryStateStore(_state_for(_transaction(wave=wave)))
    with pytest.raises(VerifyBError) as raised:
        _run(store2, secret_client2, workload_client, owner)
    assert BREAKGLASS.reveal().decode() not in str(raised.value)
    assert ADMIN.reveal().decode() not in str(raised.value)


# ---------------------------------------------------------------------------
# Execution re-stamping: a failed verification may persist only the
# credential-free execution bookkeeping, never a verify-b-complete receipt or
# a phase advance.
# ---------------------------------------------------------------------------


def _request_for(execution: ExecutionIdentity) -> VerifyBRequest:
    return VerifyBRequest(
        environment=EnvironmentIdentity("dfw-dev", "cluster.local"),
        keystone=ResolvedKeystoneIdentities(
            admin_user_id="admin-user", breakglass_user_id="breakglass-user",
            user_domain_id="default-domain", project_id="admin-project",
            project_domain_id="default-domain", role_id="admin-role",
        ),
        passwordsafe_project_id=PROJECT_ID,
        passwordsafe_b_record_id=PS_B,
        execution=execution,
        breakglass_username="breakglass",
    )


def _run_for(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, owner: Ownership,
    request: VerifyBRequest, *,
    contract_text: str = _contract_text(),
    b_value: SecretValue = BREAKGLASS,
    keystone_client: FakeKeystoneClient | None = None,
    passwordsafe_client: FakePasswordSafeClient | None = None,
):
    parsed = parse_contract(contract_text)
    keystone_client = keystone_client or _keystone_with(b_value)
    passwordsafe_client = passwordsafe_client or _passwordsafe(b_value)
    inputs = VerifyBInputs(
        request=request,
        contract=parsed,
        passwordsafe_access=ACCESS,
        secret_client=secret_client,
        workload_client=cast(WorkloadClient, workload_client),
    )
    return run_verify_b(
        inputs,
        state_store=store,
        ownership=owner,
        passwordsafe=passwordsafe_client,
        keystone=keystone_client,
        clock=lambda: NOW,
    )


E1 = ExecutionIdentity(UUID("11110000-0000-4000-8000-000000000001"), None)
E2 = ExecutionIdentity(UUID("22220000-0000-4000-8000-000000000002"), None)


def test_restamp_then_verification_failure_persists_only_bookkeeping() -> None:
    # A takeover resume (durable execution E1, resuming as E2) re-stamps the
    # credential-free execution bookkeeping before verification proceeds.  The
    # verification then fails (a location regressed to admin): the only
    # durable write is the re-stamp.  No verify-b-complete receipt is
    # persisted and the phase is not advanced.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave, execution=E1))
    store = MemoryStateStore(state)
    # neutron has regressed to admin: the gate fails at location verification.
    broken = _secrets(neutron=Identity.ADMIN, octavia=Identity.BREAKGLASS,
                      none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*broken.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run_for(store, secret_client, workload_client, owner,
                 _request_for(E2))
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    # Exactly one durable write: the execution re-stamp.
    assert store.update_count == 1
    current = store.current.state.current_transaction
    assert current is not None
    # The bookkeeping field records the resuming owner E2 ...
    assert current.execution == E2
    # ... but the phase did not advance and no verify-b-complete receipt
    # exists.
    assert current.phase is RotationPhase.VERIFY_B
    assert current.status is TransactionStatus.ACTIVE
    assert not any(
        item.check_id == "verify-b-complete" for item in current.verifications
    )
    # No Secret write and no restart dispatch.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


def test_same_execution_failure_persists_nothing() -> None:
    # When the resuming execution already equals the durable execution, the
    # re-stamp is a no-op: a failed verification performs zero durable writes.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave, execution=EXECUTION))
    store = MemoryStateStore(state)
    broken = _secrets(neutron=Identity.ADMIN, octavia=Identity.BREAKGLASS,
                      none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*broken.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run_for(store, secret_client, workload_client, owner,
                 _request_for(EXECUTION))
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    assert store.update_count == 0
    current = store.current.state.current_transaction
    assert current is not None
    assert current.execution == EXECUTION
    assert current.phase is RotationPhase.VERIFY_B
    assert not any(
        item.check_id == "verify-b-complete" for item in current.verifications
    )


# ---------------------------------------------------------------------------
# Fixed identity: admin propagated locations
# ---------------------------------------------------------------------------


def test_fixed_admin_location_unknown_credential_fails_closed() -> None:
    # A contracted fixed identity: admin location holding an unknown
    # credential is unexplained contracted state: fail closed, even though
    # fixed-admin locations are permitted to remain on admin.
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    secrets["active-consumer"] = snapshot("active-consumer", {
        "OS_USERNAME": _pair(Identity.BREAKGLASS)[0],
        "OS_PASSWORD": _pair(Identity.BREAKGLASS)[1],
    })
    wave = _planned_wave(secrets, contract_text=_fixed_admin_contract_text())
    wave = replace(wave, applied_location_ids=("active",), runtime_actions=(
        RuntimeActionProgress("deployment_active-api", RuntimeActionState.COMPLETE),
    ))
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    # The fixed-admin location now holds an unrecognized credential.
    secrets["admin-fixed-consumer"] = snapshot("admin-fixed-consumer", {
        "OS_USERNAME": b"someuser",
        "OS_PASSWORD": b"some-unrecognized-password",
    })
    secret_client = FakeCredentialSecretClient(*secrets.values())
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads("active-api")
    workloads["active-api"].restart_requested = marker
    workloads["active-api"].metadata_generation = 2
    workloads["active-api"].observed_generation = 2
    workloads["active-api"].rollout_status = RolloutStatus.SUCCEEDED
    workloads["active-api"].rollout_completed = True
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner,
             contract_text=_fixed_admin_contract_text())
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    # Not overwritten.
    assert secret_client.replace_calls == 0
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_fixed_admin_location_wrong_admin_password_fails_closed() -> None:
    # A fixed-admin location whose username is admin but whose password is a
    # different (unexplained) admin value is not a recognized state: fail
    # closed.
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    secrets["active-consumer"] = snapshot("active-consumer", {
        "OS_USERNAME": _pair(Identity.BREAKGLASS)[0],
        "OS_PASSWORD": _pair(Identity.BREAKGLASS)[1],
    })
    wave = _planned_wave(secrets, contract_text=_fixed_admin_contract_text())
    wave = replace(wave, applied_location_ids=("active",), runtime_actions=(
        RuntimeActionProgress("deployment_active-api", RuntimeActionState.COMPLETE),
    ))
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secrets["admin-fixed-consumer"] = snapshot("admin-fixed-consumer", {
        "OS_USERNAME": b"admin",
        "OS_PASSWORD": b"A-different-admin-password",
    })
    secret_client = FakeCredentialSecretClient(*secrets.values())
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads("active-api")
    workloads["active-api"].restart_requested = marker
    workloads["active-api"].metadata_generation = 2
    workloads["active-api"].observed_generation = 2
    workloads["active-api"].rollout_status = RolloutStatus.SUCCEEDED
    workloads["active-api"].rollout_completed = True
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner,
             contract_text=_fixed_admin_contract_text())
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_fixed_admin_location_secret_missing_fails_closed() -> None:
    # A contracted fixed identity: admin location whose Secret is absent is
    # unexplained contracted state: fail closed.
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    secrets["active-consumer"] = snapshot("active-consumer", {
        "OS_USERNAME": _pair(Identity.BREAKGLASS)[0],
        "OS_PASSWORD": _pair(Identity.BREAKGLASS)[1],
    })
    wave = _planned_wave(secrets, contract_text=_fixed_admin_contract_text())
    wave = replace(wave, applied_location_ids=("active",), runtime_actions=(
        RuntimeActionProgress("deployment_active-api", RuntimeActionState.COMPLETE),
    ))
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secrets = dict(secrets)
    del secrets["admin-fixed-consumer"]
    secret_client = FakeCredentialSecretClient(*secrets.values())
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads("active-api")
    workloads["active-api"].restart_requested = marker
    workloads["active-api"].metadata_generation = 2
    workloads["active-api"].observed_generation = 2
    workloads["active-api"].rollout_status = RolloutStatus.SUCCEEDED
    workloads["active-api"].rollout_completed = True
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner,
             contract_text=_fixed_admin_contract_text())
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_fixed_admin_location_on_breakglass_fails_closed() -> None:
    # A fixed identity: admin location containing the breakglass credential is
    # NOT an early convergence: the contract defines it as remaining
    # associated with admin, so a breakglass password there is an invalid
    # state for that contract location.  VERIFY_B fails closed.
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
        admin_fixed=Identity.BREAKGLASS,
    )
    secrets["active-consumer"] = snapshot("active-consumer", {
        "OS_USERNAME": _pair(Identity.BREAKGLASS)[0],
        "OS_PASSWORD": _pair(Identity.BREAKGLASS)[1],
    })
    wave = _planned_wave(secrets, contract_text=_fixed_admin_contract_text())
    wave = replace(wave, applied_location_ids=("active",), runtime_actions=(
        RuntimeActionProgress("deployment_active-api", RuntimeActionState.COMPLETE),
    ))
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads("active-api")
    workloads["active-api"].restart_requested = marker
    workloads["active-api"].metadata_generation = 2
    workloads["active-api"].observed_generation = 2
    workloads["active-api"].rollout_status = RolloutStatus.SUCCEEDED
    workloads["active-api"].rollout_completed = True
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner,
             contract_text=_fixed_admin_contract_text())
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    # Not overwritten.
    assert secret_client.current("openstack", "admin-fixed-consumer").get("OS_USERNAME") == SecretValue(b"breakglass")
    assert secret_client.replace_calls == 0
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_fixed_admin_location_malformed_representation_fails_closed() -> None:
    # A fixed identity: admin location whose declared representation no longer
    # parses (the INI section is gone) is unexplained contracted state: fail
    # closed rather than skipping it.
    fixed_ini_contract = (
        _fixed_admin_contract_text()
        .replace(
            """  admin-fixed:
    secret: admin-fixed-consumer
    identity: admin
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart: []""",
            """  admin-fixed:
    secret: admin-fixed-consumer
    identity: admin
    role: propagated
    representation:
      type: ini
      key: service.conf
      section: service_auth
      username: username
      password: password
    restart: []""",
        )
    )
    un, pw = _pair(Identity.BREAKGLASS)
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    secrets["active-consumer"] = snapshot("active-consumer", {
        "OS_USERNAME": un, "OS_PASSWORD": pw,
    })
    # The fixed-admin Secret holds plain env fields, not the declared INI.
    secrets["admin-fixed-consumer"] = snapshot("admin-fixed-consumer", {
        "OS_USERNAME": b"admin",
        "OS_PASSWORD": ADMIN.reveal(),
    })
    wave = _planned_wave(secrets, contract_text=fixed_ini_contract)
    wave = replace(wave, applied_location_ids=("active",), runtime_actions=(
        RuntimeActionProgress("deployment_active-api", RuntimeActionState.COMPLETE),
    ))
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads("active-api")
    workloads["active-api"].restart_requested = marker
    workloads["active-api"].metadata_generation = 2
    workloads["active-api"].observed_generation = 2
    workloads["active-api"].rollout_status = RolloutStatus.SUCCEEDED
    workloads["active-api"].rollout_completed = True
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner,
             contract_text=fixed_ini_contract)
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    assert secret_client.replace_calls == 0
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


# ---------------------------------------------------------------------------
# Guardrails: entry conditions
# ---------------------------------------------------------------------------


def test_unsupported_phase_before_verify_b_rejected() -> None:
    b_secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        none=Identity.BREAKGLASS,
    )
    wave = _complete_wave(b_secrets)
    state = _state_for(_transaction(wave=wave, phase=RotationPhase.SWITCH_TO_B))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.UNSUPPORTED_PHASE
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.SWITCH_TO_B)


def test_prepare_b_phase_rejected() -> None:
    # PREPARE_B is a predecessor of VERIFY_B: the B bridge has not durably
    # been established by this transaction, so it must be rejected rather
    # than reported as already-advanced.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave, phase=RotationPhase.PREPARE_B))
    store = MemoryStateStore(state)
    b_secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                         none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.UNSUPPORTED_PHASE
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.PREPARE_B)
    empty = PersistedState(
        PersistentState(
            schema_version=2,
            environment=EnvironmentIdentity("dfw-dev", "cluster.local"),
            current_transaction=None,
            completed_requests=(),
        ),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )
    store = MemoryStateStore(empty)
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.NO_TRANSACTION


def test_b_generation_missing_rejected() -> None:
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    transaction = _transaction(wave=wave)
    no_gen = replace(transaction, new_b_sha256=None)
    store = MemoryStateStore(_state_for(no_gen))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.B_GENERATION_MISSING


def test_missing_switch_to_b_receipt_rejected() -> None:
    # A VERIFY_B transaction without the durable switch-to-b-complete receipt
    # has no verified cutover to confirm: fail closed before any observation.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    transaction = _transaction(wave=wave)
    trimmed = replace(
        transaction,
        verifications=tuple(
            item for item in transaction.verifications
            if item.check_id != "switch-to-b-complete"
        ),
    )
    store = MemoryStateStore(_state_for(trimmed))
    b_secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                         none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.PREPARE_B_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_stale_runtime_actions_rejected() -> None:
    # A durable runtime action ID that is not derivable from the current
    # changed-location accounting indicates stale or inconsistent state:
    # fail closed as contract drift.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    wave = replace(
        wave,
        runtime_actions=(*wave.runtime_actions,
                         RuntimeActionProgress("deployment_ghost",
                                               RuntimeActionState.COMPLETE)),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    b_secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                         none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.CONTRACT_DRIFT
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_contract_drift_rejected() -> None:
    # The durable intent was planned against a contract with a different
    # restart edge; the current contract drifts from it.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    b_secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                         none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    drifted = (
        _contract_text().replace(
            "      - daemonset/octavia-worker-default\n",
            "      - daemonset/octavia-worker-extra\n",
        )
    )
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner,
             contract_text=drifted)
    assert raised.value.kind is VerifyBErrorCode.CONTRACT_DRIFT
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_breeder_replaced_fails_closed() -> None:
    # The durable stable-a receipt pins the breeder UID; a same-name
    # replacement breeder fails the admin-reference check.
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    b_secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                         none=Identity.BREAKGLASS)
    b_secrets["keystone-admin"] = replace(
        b_secrets["keystone-admin"], uid="a-replaced-breeder-uid",
    )
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.ADMIN_REFERENCE_INVALID
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)


def test_secret_missing_fails_closed() -> None:
    wave = _complete_wave(
        _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                 none=Identity.BREAKGLASS),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    # The neutron Secret has been deleted.
    b_secrets = _secrets(neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
                         none=Identity.BREAKGLASS)
    del b_secrets["neutron-keystone-admin"]
    secret_client = FakeCredentialSecretClient(*b_secrets.values())
    workload_client = _FakeWorkloadClient(_restarted_workloads(wave))
    owner = Ownership()
    with pytest.raises(VerifyBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is VerifyBErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.VERIFY_B)
