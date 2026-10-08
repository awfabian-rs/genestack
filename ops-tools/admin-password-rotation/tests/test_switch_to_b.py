"""Slice 4E: transaction-level ``SWITCH_TO_B`` orchestration tests.

These tests compose the Slice 4B/4C/4D machinery through
``run_switch_to_b`` and verify the ``SWITCH_TO_B`` phase moves a completed
``PREPARE_B`` transaction to ``VERIFY_B`` only after every contracted
``identity: active`` location is reconciled to the breakglass credential and
every derived runtime restart action is complete.  They use the existing
behavioral fakes rather than introducing parallel test abstractions.
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
    FakeKeystoneClient, KeystoneUserObservation,
)
from admin_password_rotation.model import (
    ConfigurationDigest, CredentialGeneration, EnvironmentIdentity,
    ExecutionIdentity, Identity, LockoutChangeState, LockoutState,
    PasswordSafeState, PersistentState, PropagationState, PropagationWave,
    ReferenceCredentials, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, RuntimeActionProgress, RuntimeActionState,
    SecretField, SecretInventory, SecretSnapshot, SecretValue,
    TransactionStatus, VerificationResult, VerificationStatus,
)
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient, IdentityAccess, PasswordSafeCredential,
)
from admin_password_rotation.propagation import (
    FakeCredentialSecretClient,
)
from admin_password_rotation.restart import (
    RolloutStatus, WorkloadClient, WorkloadSnapshot,
)
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import (
    PersistedState, StateRevision, StateStore,
)
from admin_password_rotation.switch_to_b import (
    SwitchToBError, SwitchToBErrorCode, SwitchToBInputs, SwitchToBRequest,
    run_switch_to_b,
)

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
ACCESS = IdentityAccess(datetime(2030, 1, 1, tzinfo=timezone.utc), SecretValue(b"ps-token"))
PROJECT_ID = 10
PS_A = 101
PS_B = 202
ADMIN = SecretValue(b"Synthetic-Old-Admin-4E")
BREAKGLASS = SecretValue(b"Synthetic-Breakglass-4E")
ADMIN_GENERATION = CredentialGeneration.from_secret(ADMIN)
BREAKGLASS_GENERATION = CredentialGeneration.from_secret(BREAKGLASS)


def _contract_text() -> str:
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
    secret: octavia-worker-default
    identity: active
    role: propagated
    representation:
      type: ini
      key: octavia.conf
      section: service_auth
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


def snapshot(name: str, data: dict[str, bytes]) -> SecretSnapshot:
    return SecretSnapshot(
        "openstack", name, f"uid-{name}", "7",
        tuple(SecretField(key, SecretValue(value)) for key, value in sorted(data.items())),
    )


def _secrets(*, neutron: Identity = Identity.ADMIN,
             octavia_etc: Identity = Identity.ADMIN,
             octavia_worker: Identity = Identity.ADMIN,
             none: Identity = Identity.ADMIN,
             admin_fixed: Identity = Identity.ADMIN,
             active: Identity = Identity.ADMIN) -> dict[str, SecretSnapshot]:
    un, pw = _pair(neutron)
    oe = _ini(octavia_etc)
    ow = _ini(octavia_worker)
    uf, pf = _pair(admin_fixed)
    ua, pa = _pair(active)
    return {
        "keystone-admin": snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        "neutron-keystone-admin": snapshot("neutron-keystone-admin", {
            "OS_USERNAME": un, "OS_PASSWORD": pw,
        }),
        "octavia-etc": snapshot("octavia-etc", {"octavia.conf": oe}),
        "octavia-worker-default": snapshot("octavia-worker-default", {"octavia.conf": ow}),
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


def _ini(identity: Identity) -> bytes:
    username, password = _pair(identity)
    return (
        b"[service_auth]\nusername = " + username
        + b"\npassword = " + password + b"\n"
    )


# ---------------------------------------------------------------------------
# Ownership / state store
# ---------------------------------------------------------------------------


class Ownership:
    def __init__(self, *, fail: bool = False) -> None:
        self.assertions = 0
        self.fail = fail
    @property
    def requires_recovery_gate(self) -> bool:
        return False
    def assert_owned(self) -> None:
        self.assertions += 1
        if self.fail:
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
# Workload fakes (reused from the Slice 4D test harness)
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
        if self.restart_requested is not None and not self.rollout_completed:
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
# External / transaction fixtures
# ---------------------------------------------------------------------------


def _keystone_users(client: FakeKeystoneClient, b_value: SecretValue) -> None:
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


def _passwordsafe(b_value: SecretValue) -> FakePasswordSafeClient:
    client = FakePasswordSafeClient()
    client.add(PasswordSafeCredential(PROJECT_ID, PS_A, "admin", 7, ADMIN))
    client.add(PasswordSafeCredential(PROJECT_ID, PS_B, "breakglass", 3, b_value))
    return client


def _request() -> SwitchToBRequest:
    return SwitchToBRequest(
        environment=EnvironmentIdentity("dfw-dev", "cluster.local"),
        keystone=ResolvedKeystoneIdentities(
            admin_user_id="admin-user", breakglass_user_id="breakglass-user",
            user_domain_id="default-domain", project_id="admin-project",
            project_domain_id="default-domain", role_id="admin-role",
        ),
        passwordsafe_project_id=PROJECT_ID,
        passwordsafe_b_record_id=PS_B,
        execution=ExecutionIdentity(
            UUID("33333333-3333-4333-8333-333333333333"), None,
        ),
        breakglass_username="breakglass",
    )


def _transaction(
    *, phase: RotationPhase = RotationPhase.SWITCH_TO_B,
    wave: PropagationWave | None = None,
    status: str = "active",
    include_prepare_b_receipts: bool = True,
    execution: ExecutionIdentity | None = None,
) -> RotationTransaction:
    transaction_id = UUID("11111111-1111-4111-8111-111111111111")
    request_id = UUID("22222222-2222-4222-8222-222222222222")
    to_a = PropagationWave((), ())
    to_b = wave if wave is not None else PropagationWave((), ())
    if include_prepare_b_receipts:
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
        )
    else:
        verifications = ()
    transaction = RotationTransaction(
        transaction_id=transaction_id,
        request_id=request_id,
        execution=execution or ExecutionIdentity(
            UUID("33333333-3333-4333-8333-333333333333"), None,
        ),
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=ResolvedKeystoneIdentities(
            admin_user_id="admin-user", breakglass_user_id="breakglass-user",
            user_domain_id="default-domain", project_id="admin-project",
            project_domain_id="default-domain", role_id="admin-role",
        ),
        created_at=NOW,
        updated_at=NOW,
        phase=phase,
        status=TransactionStatus(status),
        last_error=None,
        new_a_sha256=None,
        new_b_sha256=BREAKGLASS_GENERATION,
        passwordsafe=PasswordSafeState(
            configured_a_record_id=PS_A, configured_b_record_id=PS_B,
            observed_a_record_id=PS_A, observed_b_record_id=PS_B,
            original_a_version=7, observed_a_version=7, observed_b_version=3,
        ),
        credential_mutation_intent=None,
        propagation=PropagationState(to_b, to_a),
        lockout=LockoutState(
            initial_ignore_lockout_failure_attempts=False,
            suppression=LockoutChangeState.NOT_INTENDED,
            restoration=LockoutChangeState.NOT_INTENDED,
            latest_ignore_lockout_failure_attempts=False,
            restore_required=False,
        ),
        verifications=verifications,
    )
    return transaction


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


def _run(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, owner: Ownership, *,
    contract_text: str = _contract_text(),
    b_value: SecretValue = BREAKGLASS,
    keystone_client: FakeKeystoneClient | None = None,
    passwordsafe_client: FakePasswordSafeClient | None = None,
    poll_interval: float = 0.05,
    deadline: float = 60.0,
):
    parsed = parse_contract(contract_text)
    keystone_client = keystone_client or FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    _keystone_users(keystone_client, b_value)
    passwordsafe_client = passwordsafe_client or _passwordsafe(b_value)
    inputs = SwitchToBInputs(
        request=_request(),
        contract=parsed,
        passwordsafe_access=ACCESS,
        secret_client=secret_client,
        workload_client=cast(WorkloadClient, workload_client),
    )
    return run_switch_to_b(
        inputs,
        state_store=store,
        ownership=owner,
        passwordsafe=passwordsafe_client,
        keystone=keystone_client,
        clock=lambda: NOW,
        sleeper=lambda _seconds: None,
        poll_interval=poll_interval,
        deadline=deadline,
    )


# ---------------------------------------------------------------------------
# 1. clean PREPARE_B completion -> propagation -> actions -> complete
# ---------------------------------------------------------------------------


def test_clean_prepare_b_to_switch_to_b_complete() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_B
    assert transaction.status.value == "active"
    # Every changed active location is applied and its restart action complete.
    assert set(transaction.propagation.to_b.applied_location_ids) == {
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    }
    assert {item.action_id for item in transaction.propagation.to_b.runtime_actions} == set(_all_action_ids())
    assert all(item.state is RuntimeActionState.COMPLETE for item in transaction.propagation.to_b.runtime_actions)
    # The breakglass credential was written to the active Secrets.
    assert secret_client.current("openstack", "neutron-keystone-admin").get("OS_USERNAME") == SecretValue(b"breakglass")
    assert secret_client.current("openstack", "octavia-etc").get("octavia.conf") == SecretValue(_ini(Identity.BREAKGLASS))


# ---------------------------------------------------------------------------
# 2/3. active locations targeted to B; fixed admin locations not switched
# ---------------------------------------------------------------------------


def test_active_targeted_to_b_fixed_admin_not_switched() -> None:
    secrets = _secrets()  # fixed admin location is admin; active is admin
    parsed = parse_contract(_fixed_admin_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads("active-api"))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner,
                  contract_text=_fixed_admin_contract_text())
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_B
    # The active location switched to breakglass.
    assert secret_client.current("openstack", "active-consumer").get("OS_USERNAME") == SecretValue(b"breakglass")
    assert secret_client.current("openstack", "active-consumer").get("OS_PASSWORD") == BREAKGLASS
    # The fixed admin location remains admin.
    assert secret_client.current("openstack", "admin-fixed-consumer").get("OS_USERNAME") == SecretValue(b"admin")
    assert secret_client.current("openstack", "admin-fixed-consumer").get("OS_PASSWORD") == ADMIN
    assert "active" in transaction.propagation.to_b.applied_location_ids
    assert "admin-fixed" not in transaction.propagation.to_b.applied_location_ids


# ---------------------------------------------------------------------------
# 4. keystone-admin is never a B propagation target
# ---------------------------------------------------------------------------


def test_keystone_admin_is_not_a_b_propagation_target() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    # The breeder Secret is never touched by the B wave: it still holds the
    # admin credential and is not in the changed set.
    assert secret_client.current("openstack", "keystone-admin").get("password") == ADMIN
    applied = result.persisted.state.current_transaction
    assert applied is not None
    assert "keystone-admin" not in applied.propagation.to_b.applied_location_ids


# ---------------------------------------------------------------------------
# 5. already-B locations become no-ops
# ---------------------------------------------------------------------------


def test_already_b_locations_are_no_ops() -> None:
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia_etc=Identity.BREAKGLASS,
        octavia_worker=Identity.BREAKGLASS, none=Identity.BREAKGLASS,
    )
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads())
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    # No Secret writes and no restart dispatches (all already at target).
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_B
    # All locations were already at target at wave creation (expected_target=True),
    # so the changed set is empty and there is no restart debt.
    assert transaction.propagation.to_b.applied_location_ids == ()
    assert transaction.propagation.to_b.runtime_actions == ()


# ---------------------------------------------------------------------------
# 6/7. multiple changed locations produce deduplicated action set; no changes -> no actions
# ---------------------------------------------------------------------------


def test_multiple_changed_locations_deduplicate_actions() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    # octavia-etc drives two deployments; each workload appears exactly once.
    assert {item.action_id for item in transaction.propagation.to_b.runtime_actions} == set(_all_action_ids())
    # no-restart changed but produced no action.
    assert "no-restart" in transaction.propagation.to_b.applied_location_ids
    assert not any(item.action_id == "no-restart" for item in transaction.propagation.to_b.runtime_actions)
    # Each deduplicated workload was restarted exactly once.
    assert workload_client.workloads["octavia-api"].restart_call_count == 1
    assert workload_client.workloads["octavia-housekeeping"].restart_call_count == 1
    assert workload_client.workloads["octavia-worker-default"].restart_call_count == 1
    assert workload_client.workloads["neutron-netns-cleanup-cron-default"].restart_call_count == 1


# ---------------------------------------------------------------------------
# 8. interruption during propagation resumes without replaying completed work
# ---------------------------------------------------------------------------


def test_interrupted_propagation_resumes_without_replay() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    # Simulate a first execution that propagated neutron but died before the
    # rest: neutron Secret is now breakglass, applied has only neutron, no
    # restart actions yet.
    first = _secrets(neutron=Identity.BREAKGLASS)
    wave_after_partial = replace(
        planned.wave,
        applied_location_ids=("neutron",),
    )
    partial_state = _state_for(_transaction(wave=wave_after_partial))
    store = MemoryStateStore(partial_state)
    # The external reality reflects neutron already switched.
    secret_client = FakeCredentialSecretClient(*first.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_B
    # neutron was not rewritten a second time; only the remaining locations.
    neutron_secret = secret_client.current("openstack", "neutron-keystone-admin")
    assert neutron_secret.get("OS_USERNAME") == SecretValue(b"breakglass")
    assert set(transaction.propagation.to_b.applied_location_ids) == {
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    }
    # The restart marker is the deterministic wave marker.
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(transaction.propagation.to_b)
    assert workload_client.workloads["octavia-api"].restart_requested == marker


# ---------------------------------------------------------------------------
# 9. propagation complete / restart debt pending resumes into action execution
# ---------------------------------------------------------------------------


def test_propagation_complete_restart_debt_pending() -> None:
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia_etc=Identity.BREAKGLASS,
        octavia_worker=Identity.BREAKGLASS, none=Identity.BREAKGLASS,
    )
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    # Propagation fully applied but no runtime actions recorded yet.
    wave = replace(planned.wave, applied_location_ids=(
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    ))
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_B
    assert {item.action_id for item in transaction.propagation.to_b.runtime_actions} == set(_all_action_ids())
    assert all(item.state is RuntimeActionState.COMPLETE for item in transaction.propagation.to_b.runtime_actions)


# ---------------------------------------------------------------------------
# 10. RUNNING action recovery uses existing 4D observation/recovery behavior
# ---------------------------------------------------------------------------


def test_running_action_recovery_confirms_without_redispatch() -> None:
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia_etc=Identity.BREAKGLASS,
        octavia_worker=Identity.BREAKGLASS, none=Identity.BREAKGLASS,
    )
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    wave = replace(planned.wave, applied_location_ids=(
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    ))
    # A prior execution recorded a RUNNING action and dispatched the restart;
    # the workload rolled out complete.  Resume must confirm without re-dispatch.
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads(*_all_workload_names())
    for workload in workloads.values():
        workload.restart_requested = marker
        workload.metadata_generation = 2
        workload.observed_generation = 2
        workload.rollout_status = RolloutStatus.SUCCEEDED
        workload.rollout_completed = True
    running = replace(
        wave,
        runtime_actions=(
            RuntimeActionProgress("daemonset_neutron-netns-cleanup-cron-default", RuntimeActionState.RUNNING),
            RuntimeActionProgress("deployment_octavia-api", RuntimeActionState.RUNNING),
            RuntimeActionProgress("deployment_octavia-housekeeping", RuntimeActionState.RUNNING),
            RuntimeActionProgress("daemonset_octavia-worker-default", RuntimeActionState.RUNNING),
        ),
    )
    state_running = _state_for(_transaction(wave=running))
    store = MemoryStateStore(state_running)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_B
    assert all(item.state is RuntimeActionState.COMPLETE for item in transaction.propagation.to_b.runtime_actions)
    # No re-dispatch: every workload was already restarted.
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 11. action completion + process death -> phase completion without needless redispatch
# ---------------------------------------------------------------------------


def test_action_complete_no_redispatch_then_phase_advances() -> None:
    secrets = _secrets(
        neutron=Identity.BREAKGLASS, octavia_etc=Identity.BREAKGLASS,
        octavia_worker=Identity.BREAKGLASS, none=Identity.BREAKGLASS,
    )
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    complete_actions = tuple(
        RuntimeActionProgress(item_action_id, RuntimeActionState.COMPLETE)
        for item_action_id in _all_action_ids()
    )
    wave = replace(
        planned.wave,
        applied_location_ids=("neutron", "octavia-etc", "octavia-worker", "no-restart"),
        runtime_actions=complete_actions,
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_B
    # No restart was re-dispatched.
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 12. stale/unknown/contradictory credential state fails closed
# ---------------------------------------------------------------------------


def test_unknown_credential_state_fails_closed() -> None:
    # A location that holds an unrecognized credential (neither admin nor the
    # expected breakglass) must fail closed, not be overwritten.  Plan the wave
    # from clean secrets, then tamper the external reality so the grouped
    # executor sees an unknown credential.
    clean_secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(clean_secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    # External reality: neutron now has an unrecognized credential.
    from admin_password_rotation.model import SecretField as SF
    tampered = replace(
        clean_secrets["neutron-keystone-admin"],
        data=(SF("OS_USERNAME", SecretValue(b"someuser")),
              SF("OS_PASSWORD", SecretValue(b"some-unrecognized-password"))),
    )
    tampered_secrets = dict(clean_secrets)
    tampered_secrets["neutron-keystone-admin"] = tampered
    secret_client = FakeCredentialSecretClient(*tampered_secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    from admin_password_rotation.propagation import GroupedPropagationError
    with pytest.raises(GroupedPropagationError):
        _run(store, secret_client, workload_client, owner)
    # No restart was dispatched and phase did not advance.
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


def test_replaced_secret_uid_fails_closed() -> None:
    # Plan the wave against the original (clean) secrets, then the external
    # reality has a same-name replacement with a different UID.
    original = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(original.values())),
        ReferenceCredentials(ADMIN, BREAKGLASS), desired,
        BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    # External reality now has the replaced UID.
    replaced = dict(original)
    replaced["neutron-keystone-admin"] = replace(
        original["neutron-keystone-admin"], uid="a-different-uid",
    )
    secret_client = FakeCredentialSecretClient(*replaced.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    from admin_password_rotation.propagation import GroupedPropagationError
    with pytest.raises(GroupedPropagationError):
        _run(store, secret_client, workload_client, owner)
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 13. contract drift reported by existing machinery blocks continuation
# ---------------------------------------------------------------------------


def test_contract_drift_blocks_continuation() -> None:
    # Durable intent was planned against the base contract, but the current
    # contract passed to run_switch_to_b has a different restart edge, producing
    # a digest/membership mismatch (contract drift).
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    drifted = (
        _contract_text().replace(
            "      - deployment/octavia-api\n",
            "      - deployment/octavia-api-extra\n",
        )
    )
    from admin_password_rotation.propagation import GroupedPropagationError
    with pytest.raises(GroupedPropagationError):
        _run(store, secret_client, workload_client, owner, contract_text=drifted)
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 14. stale runtime-action state reported by 4D blocks continuation
# ---------------------------------------------------------------------------


def test_stale_runtime_action_blocks_continuation() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    # Durable intent carries a runtime action that is not derivable from the
    # current changed-location accounting: stale runtime action.  The external
    # reality must be consistent with the applied state (no-restart at target).
    wave = replace(
        planned.wave,
        applied_location_ids=("no-restart",),
        runtime_actions=(RuntimeActionProgress("deployment_ghost", RuntimeActionState.PENDING),),
    )
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    # no-restart is already at breakglass (consistent with applied_location_ids).
    consistent_secrets = _secrets(none=Identity.BREAKGLASS)
    secret_client = FakeCredentialSecretClient(*consistent_secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    from admin_password_rotation.restart import RestartExecutionError, RestartExecutionErrorCode
    with pytest.raises(RestartExecutionError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is RestartExecutionErrorCode.STALE_RUNTIME_ACTIONS
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 15/16. Lease loss before a credential or runtime-action mutation prevents dispatch
# ---------------------------------------------------------------------------


def test_lease_loss_prevents_any_mutation() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership(fail=True)
    with pytest.raises(SafeError):
        _run(store, secret_client, workload_client, owner)
    # No Secret write and no restart dispatch occurred.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    # No durable phase advancement.
    assert store.current.state.current_transaction is not None
    assert store.current.state.current_transaction.phase is RotationPhase.SWITCH_TO_B


# ---------------------------------------------------------------------------
# 17. phase advancement only after propagation and all runtime actions complete
# ---------------------------------------------------------------------------


def test_phase_advances_only_after_all_actions_complete() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    # A workload that never completes its rollout: the action stays outstanding.
    workloads = _workloads(*_all_workload_names())
    for workload in workloads.values():
        workload.desired_replicas = 2
        workload.ready_replicas = 0
        workload.updated_replicas = 0
        workload.unavailable_replicas = 2
        workload.rollout_status = RolloutStatus.PENDING
        workload.rollout_completed = True  # never advances
    class _NeverCompleteDeployment:
        def __init__(self, workloads: dict[str, _FakeWorkload]) -> None:
            self.workloads = workloads
            self.restart_calls: list[tuple[str, str, str]] = []
        def read(self, namespace: str, name: str) -> WorkloadSnapshot:
            return self.workloads[name].snapshot()
        def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
            self.restart_calls.append((namespace, name, request))
            workload = self.workloads[name]
            workload.restart_call_count += 1
            workload.restart_requested = request
            return workload.snapshot()
    workload_client = _FakeWorkloadClient(workloads)
    workload_client.deployment = cast(_FakeDeploymentClient, _NeverCompleteDeployment(workloads))
    owner = Ownership()
    with pytest.raises(SafeError):
        _run(store, secret_client, workload_client, owner,
             poll_interval=0.05, deadline=0.1)
    # Phase did not advance because the rollout never completed.
    assert store.current.state.current_transaction is not None
    assert store.current.state.current_transaction.phase is RotationPhase.SWITCH_TO_B


# ---------------------------------------------------------------------------
# 18. phase completion stops before VERIFY_B logic
# ---------------------------------------------------------------------------


def test_phase_completion_stops_before_verify_b() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    # Phase is exactly VERIFY_B (the next phase), not ROTATE_A.
    assert transaction.phase is RotationPhase.VERIFY_B
    # No ROTATE_A work: no A-new generation, lockout untouched, no ROTATE_A
    # verifications recorded.
    assert transaction.new_a_sha256 is None
    assert transaction.lockout.suppression.value == "not_intended"
    assert not any(
        item.phase is RotationPhase.ROTATE_A for item in transaction.verifications
    )
    # The credential-free completion receipt is recorded at the SWITCH_TO_B phase.
    assert any(
        item.check_id == "switch-to-b-complete"
        and item.phase is RotationPhase.SWITCH_TO_B
        and item.credential_generation == BREAKGLASS_GENERATION
        for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 19. no secrets/passwords serialized into records or diagnostics
# ---------------------------------------------------------------------------


def test_no_credentials_in_serialized_state_or_diagnostics() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run(store, secret_client, workload_client, owner)
    serialized = serialize_state_json(result.persisted.state)
    assert ADMIN.reveal().decode() not in serialized
    assert BREAKGLASS.reveal().decode() not in serialized
    current = result.persisted.state.current_transaction
    assert current is not None
    # The restart marker is deterministic and contains no credential material.
    marker = next(iter(current.propagation.to_b.runtime_actions)).action_id
    assert BREAKGLASS.reveal().decode() not in marker
    assert ADMIN.reveal().decode() not in marker
    assert BREAKGLASS.reveal().decode() not in str(result)


# ---------------------------------------------------------------------------
# Additional guardrails
# ---------------------------------------------------------------------------


def test_unsupported_phase_rejected() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave, phase=RotationPhase.VERIFY_B))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.UNSUPPORTED_PHASE


def test_no_transaction_rejected() -> None:
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
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.NO_TRANSACTION


def test_b_generation_missing_rejected() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    base = _state_for(_transaction(wave=planned.wave))
    from admin_password_rotation.model import PersistentState as PS
    transaction = base.state.current_transaction
    assert transaction is not None
    no_gen = replace(transaction, new_b_sha256=None)
    store = MemoryStateStore(PersistedState(
        PS(
            schema_version=2, environment=base.state.environment,
            current_transaction=no_gen, completed_requests=(),
        ),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    ))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.B_GENERATION_MISSING


def test_b_credential_unresolved_rejected() -> None:
    # PasswordSafe B no longer contains the recorded generation: cannot
    # establish the authoritative B value, so fail closed.
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    drifted = _passwordsafe(SecretValue(b"SomeOtherUnrelatedBreakglassValue"))
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner,
             passwordsafe_client=drifted)
    assert raised.value.kind is SwitchToBErrorCode.B_CREDENTIAL_UNRESOLVED


def test_b_auth_indeterminate_rejected() -> None:
    secrets = _secrets()
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    planned = plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    )
    state = _state_for(_transaction(wave=planned.wave))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    ks = FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    _keystone_users(ks, BREAKGLASS)
    from admin_password_rotation.keystone import KeystoneIndeterminateReason
    ks.next_auth_indeterminate = KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner, keystone_client=ks)
    assert raised.value.kind is SwitchToBErrorCode.B_AUTH_INDETERMINATE


# ---------------------------------------------------------------------------
# Fix 1 — durable PREPARE_B prerequisite validation
# ---------------------------------------------------------------------------


def _planned_wave(secrets: dict[str, SecretSnapshot]) -> PropagationWave:
    parsed = parse_contract(_contract_text())
    from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
    from admin_password_rotation.propagation import DesiredCredential
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    refs = ReferenceCredentials(ADMIN, BREAKGLASS)
    return plan_or_reconcile_propagation_wave(
        parsed, SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, BREAKGLASS_GENERATION, PropagationWave((), ()),
    ).wave


def _assert_no_side_effects(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient,
) -> None:
    """No Secret mutation, no restart dispatch, no phase advancement."""
    # No Secret write was issued at all (the fake tracks every replace call).
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_B


def test_missing_stable_a_prerequisite_fails_closed() -> None:
    # A SWITCH_TO_B transaction that lacks the durable stable-a PREPARE_B
    # receipt must fail closed rather than adopting the current breeder value.
    wave = _planned_wave(_secrets())
    state = _state_for(_transaction(wave=wave, include_prepare_b_receipts=False))
    store = MemoryStateStore(state)
    secrets = _secrets()
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.PREPARE_B_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client)


def test_missing_breakglass_b2_prerequisite_fails_closed() -> None:
    # Only the stable-a receipt is present; the breakglass-b2 completion receipt
    # is absent.  PREPARE_B did not durably record B2 success -> fail closed.
    wave = _planned_wave(_secrets())
    transaction = _transaction(wave=wave)
    # Keep stable-a, drop breakglass-b2.
    trimmed = replace(
        transaction,
        verifications=tuple(
            item for item in transaction.verifications
            if item.check_id == "stable-a"
        ),
    )
    state = _state_for(trimmed)
    store = MemoryStateStore(state)
    secrets = _secrets()
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.PREPARE_B_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client)


def test_ambiguous_duplicated_prerequisite_fails_closed() -> None:
    # Two stable-a receipts is an ambiguous/contradictory record -> fail closed.
    wave = _planned_wave(_secrets())
    transaction = _transaction(wave=wave)
    duplicated = replace(
        transaction,
        verifications=(*transaction.verifications, transaction.verifications[0]),
    )
    state = _state_for(duplicated)
    store = MemoryStateStore(state)
    secrets = _secrets()
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID
    _assert_no_side_effects(store, secret_client, workload_client)


def test_b2_generation_mismatch_fails_closed() -> None:
    # The durable breakglass-b2 receipt names a generation that disagrees with
    # the transaction's new_b_sha256 -> contradictory evidence, fail closed.
    wave = _planned_wave(_secrets())
    transaction = _transaction(wave=wave)
    wrong_gen = CredentialGeneration("sha256:" + "f" * 64)
    b2 = next(
        item for item in transaction.verifications if item.check_id == "breakglass-b2"
    )
    fixed_b2 = replace(b2, credential_generation=wrong_gen)
    swapped = replace(
        transaction,
        verifications=tuple(
            fixed_b2 if item.check_id == "breakglass-b2" else item
            for item in transaction.verifications
        ),
    )
    state = _state_for(swapped)
    store = MemoryStateStore(state)
    secrets = _secrets()
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.PREPARE_B_PREREQUISITE_INVALID
    _assert_no_side_effects(store, secret_client, workload_client)


def test_stable_a_wrong_phase_fails_closed() -> None:
    # A stable-a receipt that carries the correct check_id and metadata but was
    # recorded at a different phase (not PREPARE_B) is not PREPARE_B evidence.
    # Phase-qualified matching treats it as missing -> fail closed.
    wave = _planned_wave(_secrets())
    transaction = _transaction(wave=wave)
    wrong_phase = replace(
        transaction,
        verifications=tuple(
            replace(item, phase=RotationPhase.ROTATE_A)
            if item.check_id == "stable-a" else item
            for item in transaction.verifications
        ),
    )
    state = _state_for(wrong_phase)
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.PREPARE_B_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client)


def test_breakglass_b2_wrong_phase_fails_closed() -> None:
    # A breakglass-b2 receipt that carries the correct check_id and generation
    # but was recorded at a different phase (not PREPARE_B) is not PREPARE_B
    # evidence.  Phase-qualified matching treats it as missing -> fail closed.
    wave = _planned_wave(_secrets())
    transaction = _transaction(wave=wave)
    wrong_phase = replace(
        transaction,
        verifications=tuple(
            replace(item, phase=RotationPhase.ROTATE_A)
            if item.check_id == "breakglass-b2" else item
            for item in transaction.verifications
        ),
    )
    state = _state_for(wrong_phase)
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.PREPARE_B_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client)


def test_fresh_breeder_disagrees_with_stable_a_fails_closed() -> None:
    # The durable stable-a receipt pins the breeder UID and old-A generation, but
    # the freshly observed breeder Secret has been replaced (different UID), so
    # the fresh observation disagrees with the durable prerequisite.
    wave = _planned_wave(_secrets())
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secrets = _secrets()
    # Replace the breeder with a same-name but different-UID object holding the
    # same admin credential: the UID mismatch with the stable-a receipt blocks.
    secrets["keystone-admin"] = replace(
        secrets["keystone-admin"], uid="a-replaced-breeder-uid",
    )
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.ADMIN_REFERENCE_INVALID
    _assert_no_side_effects(store, secret_client, workload_client)


def test_fresh_breeder_generation_disagrees_fails_closed() -> None:
    # The breeder UID matches the stable-a receipt but its credential is no
    # longer the recorded old-A generation (the admin password drifted), so the
    # fresh observation disagrees with the durable prerequisite.
    wave = _planned_wave(_secrets())
    state = _state_for(_transaction(wave=wave))
    store = MemoryStateStore(state)
    secrets = _secrets()
    secrets["keystone-admin"] = replace(
        secrets["keystone-admin"],
        data=(SecretField("password", SecretValue(b"A-different-admin-value")),),
    )
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToBError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToBErrorCode.ADMIN_REFERENCE_INVALID
    _assert_no_side_effects(store, secret_client, workload_client)


# ---------------------------------------------------------------------------
# Fix 2 — transaction.execution / ExecutionIdentity semantics (current owner)
# ---------------------------------------------------------------------------

E1 = ExecutionIdentity(UUID("11110000-0000-4000-8000-000000000001"), None)
E2 = ExecutionIdentity(UUID("22220000-0000-4000-8000-000000000002"), None)


def _request_for(execution: ExecutionIdentity) -> SwitchToBRequest:
    return SwitchToBRequest(
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
    request: SwitchToBRequest, *,
    poll_interval: float = 0.05, deadline: float = 60.0,
):
    """Run ``run_switch_to_b`` with an explicit request (and its execution)."""
    inputs = SwitchToBInputs(
        request=request,
        contract=parse_contract(_contract_text()),
        passwordsafe_access=ACCESS,
        secret_client=secret_client,
        workload_client=cast(WorkloadClient, workload_client),
    )
    return run_switch_to_b(
        inputs,
        state_store=store,
        ownership=owner,
        passwordsafe=_passwordsafe(BREAKGLASS),
        keystone=_keystone_with(BREAKGLASS),
        clock=lambda: NOW,
        sleeper=lambda _seconds: None,
        poll_interval=poll_interval,
        deadline=deadline,
    )


def test_takeover_restamps_current_execution() -> None:
    # Durable transaction carries the prior owner E1; the current Lease owner is
    # E2 (request.execution).  A legitimate resume re-stamps transaction.execution
    # to E2 before any propagation work, after asserting current Lease ownership.
    secrets = _secrets()
    wave = _planned_wave(secrets)
    state = _state_for(_transaction(wave=wave, execution=E1))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    result = _run_for(store, secret_client, workload_client, owner, _request_for(E2))
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    # The durable transaction now records the resuming owner E2.
    assert transaction.execution == E2
    assert transaction.phase is RotationPhase.VERIFY_B
    # Ownership was asserted (at least before the re-stamp and the phase advance).
    assert owner.assertions >= 1


def _keystone_with(b_value: SecretValue) -> FakeKeystoneClient:
    client = FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    _keystone_users(client, b_value)
    return client


def test_stale_execution_cannot_mutate_without_lease() -> None:
    # A stale execution that no longer holds the Lease (OwnershipGuard fails)
    # cannot modify durable transaction state — including the credential-free
    # bookkeeping field — even for a "takeover" resume.
    #
    # Setup: durable transaction.execution = E1 (the prior owner).  A stale
    # execution attempts to resume on behalf of E2 (request.execution = E2),
    # but it does not hold the Lease (OwnershipGuard.assert_owned fails).  The
    # re-stamp is a durable transaction-state mutation, so ownership is asserted
    # *before* it; the stale owner is blocked there, before any Secret write,
    # restart dispatch, phase advance, or bookkeeping change.
    secrets = _secrets()
    wave = _planned_wave(secrets)
    state = _state_for(_transaction(wave=wave, execution=E1))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership(fail=True)
    with pytest.raises(SwitchToBError) as raised:
        _run_for(store, secret_client, workload_client, owner, _request_for(E2))
    # The failure is the ownership guard, surfaced as a durable-progress error.
    assert raised.value.kind is SwitchToBErrorCode.PROGRESS_PERSISTENCE_FAILED
    # The durable transaction bookkeeping is untouched: no durable state write
    # was issued at all (the re-stamp short-circuits only when up-to-date, which
    # it is not — E2 != E1 — so it was blocked at the ownership assertion).
    assert store.update_count == 0
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    _assert_no_side_effects(store, secret_client, workload_client)
    current = store.current.state.current_transaction
    assert current is not None
    # The stale execution could not re-stamp the durable field to E2; it remains
    # exactly what was persisted (E1), and the phase did not advance.
    assert current.execution == E1
    assert current.phase is RotationPhase.SWITCH_TO_B


def test_same_execution_resume_does_not_rewrite_execution() -> None:
    # When the resuming execution already equals the durable execution, the
    # re-stamp is a no-op (no redundant durable write before the wave work).
    secrets = _secrets()
    wave = _planned_wave(secrets)
    same = ExecutionIdentity(UUID("33333333-3333-4333-8333-333333333333"), None)
    state = _state_for(_transaction(wave=wave, execution=same))
    store = MemoryStateStore(state)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    inputs = SwitchToBInputs(
        request=_request_for(same),
        contract=parse_contract(_contract_text()),
        passwordsafe_access=ACCESS,
        secret_client=secret_client,
        workload_client=cast(WorkloadClient, workload_client),
    )
    result = run_switch_to_b(
        inputs, state_store=store, ownership=owner,
        passwordsafe=_passwordsafe(BREAKGLASS),
        keystone=_keystone_with(BREAKGLASS),
        clock=lambda: NOW, sleeper=lambda _seconds: None,
        poll_interval=0.05, deadline=60.0,
    )
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.execution == same
    assert transaction.phase is RotationPhase.VERIFY_B
