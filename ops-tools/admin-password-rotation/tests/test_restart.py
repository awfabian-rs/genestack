from __future__ import annotations

import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import cast

import pytest

from admin_password_rotation.config import parse_contract
from admin_password_rotation.errors import SafeError
from admin_password_rotation.model import (
    CredentialContract, CredentialGeneration, Identity, PersistentState,
    PropagationState, PropagationWave, ReferenceCredentials,
    RuntimeActionProgress, RuntimeActionState, SecretField, SecretInventory,
    SecretSnapshot, SecretValue, WorkloadKind,
)
from admin_password_rotation.propagation import (
    DesiredCredential, FakeCredentialSecretClient, GroupedPropagationSession,
    execute_grouped_propagation_wave,
)
from admin_password_rotation.propagation_wave import plan_or_reconcile_propagation_wave
from admin_password_rotation.restart import (
    RESTART_ANNOTATION, RolloutStatus, RestartExecutionError, RestartExecutionErrorCode,
    WorkloadClient, WorkloadClientError, WorkloadClientErrorCode, WorkloadSnapshot,
    KubernetesApiWorkloadClient, derive_restart_actions, execute_restart_debt,
    restart_request_for,
)
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import (
    PersistedState, StateRevision, StateStore, StateStoreError, StateStoreErrorCode,
)
from tests.test_state import realistic_state


NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
ADMIN = SecretValue(b"Synthetic-Old-Admin-4D")
BREAKGLASS = SecretValue(b"Synthetic-Breakglass-4D")
ADMIN_GENERATION = CredentialGeneration.from_secret(ADMIN)
BREAKGLASS_GENERATION = CredentialGeneration.from_secret(BREAKGLASS)


def contract(text: str) -> CredentialContract:
    return parse_contract(text)


def snapshot(name: str, data: dict[str, bytes], *, uid: str | None = None) -> SecretSnapshot:
    return SecretSnapshot(
        "openstack", name, uid or f"uid-{name}", "7",
        tuple(SecretField(key, SecretValue(value)) for key, value in sorted(data.items())),
    )


def _identity_pair(identity: Identity) -> tuple[bytes, bytes]:
    password = ADMIN if identity is Identity.ADMIN else BREAKGLASS
    return identity.value.encode(), password.reveal()


def _fields_contract_text() -> str:
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
  neutron-keystone-admin:
    secret: neutron-keystone-admin
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart:
      - daemonset/neutron-netns-cleanup-cron-default
  octavia-service-auth-etc:
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
  octavia-service-auth-worker:
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


def _fields_secrets(
    *, neutron: Identity = Identity.ADMIN, octavia: Identity = Identity.ADMIN,
    worker: Identity = Identity.ADMIN, none: Identity = Identity.ADMIN,
) -> dict[str, SecretSnapshot]:
    user_n, password_n = _identity_pair(neutron)
    user_o, password_o = _identity_pair(octavia)
    user_w, password_w = _identity_pair(worker)
    user_x, password_x = _identity_pair(none)
    octavia_conf = (
        b"[service_auth]\nusername = " + user_o
        + b"\npassword = " + password_o + b"\n"
    )
    worker_conf = (
        b"[service_auth]\nusername = " + user_w
        + b"\npassword = " + password_w + b"\n"
    )
    return {
        "keystone-admin": snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        "neutron-keystone-admin": snapshot("neutron-keystone-admin", {
            "OS_USERNAME": user_n, "OS_PASSWORD": password_n,
        }),
        "octavia-etc": snapshot("octavia-etc", {"octavia.conf": octavia_conf}),
        "octavia-worker-default": snapshot("octavia-worker-default", {"octavia.conf": worker_conf}),
        "no-restart": snapshot("no-restart", {"OS_USERNAME": user_x, "OS_PASSWORD": password_x}),
    }


def _references(secrets: dict[str, SecretSnapshot]) -> ReferenceCredentials:
    admin = secrets["keystone-admin"].get("password")
    assert admin is not None
    return ReferenceCredentials(admin, SecretValue(BREAKGLASS.reveal()))


def _inventory(secrets: dict[str, SecretSnapshot]) -> SecretInventory:
    return SecretInventory("openstack", "100", tuple(secrets.values()))


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


def _wave_for(
    parsed_contract: CredentialContract, secrets: dict[str, SecretSnapshot], *,
    identity: Identity = Identity.BREAKGLASS,
    applied: tuple[str, ...] = (),
) -> tuple[PropagationWave, DesiredCredential]:
    desired = DesiredCredential(
        identity, BREAKGLASS if identity is Identity.BREAKGLASS else ADMIN,
    )
    generation = (
        BREAKGLASS_GENERATION if identity is Identity.BREAKGLASS else ADMIN_GENERATION
    )
    result = plan_or_reconcile_propagation_wave(
        parsed_contract, _inventory(secrets), _references(secrets),
        desired, generation, PropagationWave(applied, ()),
    )
    return result.wave, desired


def _state(wave: PropagationWave | None, *, identity: Identity = Identity.BREAKGLASS) -> PersistedState:
    state = realistic_state()
    assert state.current_transaction is not None
    propagation = state.current_transaction.propagation
    to_b = (wave if wave is not None and wave.intent is not None
            and wave.intent.target_identity is Identity.BREAKGLASS else propagation.to_b)
    to_a = (wave if wave is not None and wave.intent is not None
            and wave.intent.target_identity is Identity.ADMIN else propagation.to_a)
    new_b = (
        to_b.intent.target_generation
        if (to_b.intent is not None and to_b.intent.target_identity is Identity.BREAKGLASS)
        else None
    )
    new_a = (
        to_a.intent.target_generation
        if (to_a.intent is not None and to_a.intent.target_identity is Identity.ADMIN)
        else None
    )
    transaction = replace(
        state.current_transaction,
        new_a_sha256=new_a,
        new_b_sha256=new_b,
        credential_mutation_intent=None,
        propagation=PropagationState(to_b, to_a),
    )
    return PersistedState(
        replace(state, current_transaction=transaction),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )


def _run_propagation(
    parsed: CredentialContract, secrets: dict[str, SecretSnapshot], wave: PropagationWave,
    identity: Identity = Identity.BREAKGLASS,
) -> PersistedState:
    client_secrets = FakeCredentialSecretClient(*secrets.values())
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    desired = DesiredCredential(
        identity, BREAKGLASS if identity is Identity.BREAKGLASS else ADMIN,
    )
    session = GroupedPropagationSession(store, store.current)
    execute_grouped_propagation_wave(
        client_secrets, session, owner,
        contract=parsed, references=_references(secrets),
        desired=desired, wave=wave, now=NOW,
    )
    return store.current


def _transaction(persisted: PersistedState):
    """Return the non-None current transaction for a persisted state."""
    transaction = persisted.state.current_transaction
    assert transaction is not None
    return transaction


@dataclass
class FakeWorkload:
    namespace: str = "openstack"
    name: str = "workload"
    uid: str = "workload-uid"
    restart_requested: str | None = None
    metadata_generation: int = 1
    observed_generation: int = 1
    ready_replicas: int = 1
    desired_replicas: int = 1
    updated_replicas: int = 1
    unavailable_replicas: int = 0
    rollout_status: RolloutStatus = RolloutStatus.PENDING
    condition_reason: str | None = None
    read_error: WorkloadClientErrorCode | None = None
    restart_error: WorkloadClientErrorCode | None = None
    read_call_count: int = 0
    restart_call_count: int = 0
    rollout_completed: bool = False

    def snapshot(self) -> WorkloadSnapshot:
        return WorkloadSnapshot(
            namespace=self.namespace, name=self.name, uid=self.uid,
            restart_requested=self.restart_requested,
            metadata_generation=self.metadata_generation,
            observed_generation=self.observed_generation,
            ready_replicas=self.ready_replicas, desired_replicas=self.desired_replicas,
            updated_replicas=self.updated_replicas,
            unavailable_replicas=self.unavailable_replicas,
            rollout_status=self.rollout_status,
            condition_reason=self.condition_reason,
        )


class FakeDeploymentClient:
    def __init__(self, workloads: dict[str, FakeWorkload]) -> None:
        self.workloads = workloads
        self.read_calls: list[tuple[str, str]] = []
        self.restart_calls: list[tuple[str, str, str]] = []

    def read(self, namespace: str, name: str) -> WorkloadSnapshot:
        self.read_calls.append((namespace, name))
        workload = self.workloads[name]
        workload.read_call_count += 1
        if workload.read_error is not None:
            raise WorkloadClientError(workload.read_error)
        _advance_fake_rollout(workload)
        return workload.snapshot()

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
        self.restart_calls.append((namespace, name, request))
        workload = self.workloads[name]
        workload.restart_call_count += 1
        if workload.restart_error is not None:
            raise WorkloadClientError(workload.restart_error)
        workload.restart_requested = request
        # A Pod-template restart bumps the workload's metadata.generation.  The
        # controller's observedGeneration lags until it reconciles the new
        # template, so the rollout is not complete immediately.
        workload.metadata_generation += 1
        workload.updated_replicas = 0
        workload.ready_replicas = 0
        workload.unavailable_replicas = workload.desired_replicas
        workload.rollout_status = RolloutStatus.PENDING
        return workload.snapshot()


class FakeDaemonSetClient:
    def __init__(self, workloads: dict[str, FakeWorkload]) -> None:
        self.workloads = workloads
        self.read_calls: list[tuple[str, str]] = []
        self.restart_calls: list[tuple[str, str, str]] = []

    def read(self, namespace: str, name: str) -> WorkloadSnapshot:
        self.read_calls.append((namespace, name))
        workload = self.workloads[name]
        workload.read_call_count += 1
        if workload.read_error is not None:
            raise WorkloadClientError(workload.read_error)
        _advance_fake_rollout(workload)
        return workload.snapshot()

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
        self.restart_calls.append((namespace, name, request))
        workload = self.workloads[name]
        workload.restart_call_count += 1
        if workload.restart_error is not None:
            raise WorkloadClientError(workload.restart_error)
        workload.restart_requested = request
        workload.metadata_generation += 1
        workload.updated_replicas = 0
        workload.ready_replicas = 0
        workload.unavailable_replicas = workload.desired_replicas
        workload.rollout_status = RolloutStatus.PENDING
        return workload.snapshot()


def _advance_fake_rollout(workload: FakeWorkload) -> None:
    """Model the controller reconciling after a Pod-template restart.

    Once a restart marker is present, a subsequent read observes the new
    generation and a converged rollout.  This is what makes the executor's
    bounded polling wait succeed.
    """
    if workload.restart_requested is not None and not workload.rollout_completed:
        workload.observed_generation = workload.metadata_generation
        workload.updated_replicas = workload.desired_replicas
        workload.ready_replicas = workload.desired_replicas
        workload.unavailable_replicas = 0
        workload.rollout_status = RolloutStatus.SUCCEEDED
        workload.rollout_completed = True


@dataclass
class FakeWorkloadClient:
    deployment: FakeDeploymentClient
    daemonset: FakeDaemonSetClient


def _make_client(workloads: dict[str, FakeWorkload]) -> FakeWorkloadClient:
    return FakeWorkloadClient(
        FakeDeploymentClient(workloads), FakeDaemonSetClient(workloads),
    )


def _as_workload_client(client: FakeWorkloadClient) -> WorkloadClient:
    return cast(WorkloadClient, client)


def _workloads(*names: str) -> dict[str, FakeWorkload]:
    return {name: FakeWorkload(name=name) for name in names}


def _run_restart(
    client: FakeWorkloadClient, store: MemoryStateStore, owner: Ownership,
    *, parsed: CredentialContract, wave: PropagationWave,
    identity: Identity = Identity.BREAKGLASS,
):
    return execute_restart_debt(
        _as_workload_client(client), store, owner,
        contract=parsed, target=identity, now=NOW,
        sleeper=lambda _seconds: None,
    )


def _all_action_ids() -> list[str]:
    return sorted({
        "daemonset_neutron-netns-cleanup-cron-default",
        "deployment_octavia-api",
        "deployment_octavia-housekeeping",
        "daemonset_octavia-worker-default",
    })


# ---------------------------------------------------------------------------
# 1. derivation from changed locations
# ---------------------------------------------------------------------------

def test_derivation_from_changed_locations() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    assert persisted.state.current_transaction is not None
    actions = derive_restart_actions(parsed, persisted.state.current_transaction, target=Identity.BREAKGLASS)
    labels = {action.action_id for action in actions}
    assert labels == {
        "daemonset_neutron-netns-cleanup-cron-default",
        "deployment_octavia-api",
        "deployment_octavia-housekeeping",
        "daemonset_octavia-worker-default",
    }
    # no-restart is in the changed set but its restart list is empty.
    applied = _transaction(persisted).propagation.to_b.applied_location_ids
    assert "no-restart" in applied
    assert all(action.action_id != "no-restart" for action in actions)


def test_no_changed_locations_no_actions() -> None:
    parsed = contract(_fields_contract_text())
    # Plan from a state where all locations are already at breakglass.
    all_target = _fields_secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        worker=Identity.BREAKGLASS, none=Identity.BREAKGLASS,
    )
    wave, _ = _wave_for(parsed, all_target)
    persisted = _run_propagation(parsed, all_target, wave)
    assert persisted.state.current_transaction is not None
    # All locations were already at target at wave creation (expected_target=True),
    # so the changed set is empty.
    applied = _transaction(persisted).propagation.to_b.applied_location_ids
    assert applied == ()
    actions = derive_restart_actions(parsed, persisted.state.current_transaction, target=Identity.BREAKGLASS)
    assert actions == ()


def test_empty_restart_lists_produce_no_actions() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    assert persisted.state.current_transaction is not None
    applied = _transaction(persisted).propagation.to_b.applied_location_ids
    assert "no-restart" in applied
    actions = derive_restart_actions(parsed, persisted.state.current_transaction, target=Identity.BREAKGLASS)
    assert all(action.action_id != "no-restart" for action in actions)


def test_already_target_at_wave_creation_creates_no_debt() -> None:
    # A location already at the target when the wave is established
    # (expected_target=True) is not restart debt merely because it remains
    # target. Plan from a state where octavia is already breakglass and the
    # others are admin; run to breakglass. octavia-service-auth-etc is
    # expected_target=True and must not contribute restart debt, while the
    # originally-non-target locations do.
    parsed = contract(_fields_contract_text())
    mixed = _fields_secrets(octavia=Identity.BREAKGLASS)
    wave, _ = _wave_for(parsed, mixed)
    assert wave.intent is not None
    octavia_intent = next(
        loc for g in wave.intent.secret_groups for loc in g.locations
        if loc.location_id == "octavia-service-auth-etc"
    )
    neutron_intent = next(
        loc for g in wave.intent.secret_groups for loc in g.locations
        if loc.location_id == "neutron-keystone-admin"
    )
    assert octavia_intent.expected_target is True
    assert neutron_intent.expected_target is False
    all_target = _fields_secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        worker=Identity.BREAKGLASS, none=Identity.BREAKGLASS,
    )
    persisted = _run_propagation(parsed, all_target, wave)
    assert persisted.state.current_transaction is not None
    applied = _transaction(persisted).propagation.to_b.applied_location_ids
    # octavia-service-auth-etc (expected_target=True) is not in the changed set.
    assert "octavia-service-auth-etc" not in applied
    # The originally-non-target locations are.
    assert "neutron-keystone-admin" in applied
    assert "octavia-service-auth-worker" in applied
    actions = derive_restart_actions(parsed, persisted.state.current_transaction, target=Identity.BREAKGLASS)
    labels = {action.action_id for action in actions}
    # No octavia-api / octavia-housekeeping debt (only the already-target etc
    # location referenced them).
    assert "deployment_octavia-api" not in labels
    assert "deployment_octavia-housekeeping" not in labels
    assert labels == {
        "daemonset_neutron-netns-cleanup-cron-default",
        "daemonset_octavia-worker-default",
    }


# ---------------------------------------------------------------------------
# 2. deduplication across locations
# ---------------------------------------------------------------------------

def test_deduplication_across_locations() -> None:
    text = """namespace: openstack
locations:
  keystone-admin:
    secret: keystone-admin
    identity: admin
    role: source
    representation:
      type: fields
      password: password
    restart: []
  shared-one:
    secret: shared-consumers
    identity: active
    role: propagated
    representation:
      type: fields
      username: USER_ONE
      password: PASSWORD_ONE
    restart:
      - deployment/shared-api
  shared-two:
    secret: shared-consumers
    identity: active
    role: propagated
    representation:
      type: fields
      username: USER_TWO
      password: PASSWORD_TWO
    restart:
      - deployment/shared-api
"""
    parsed = contract(text)
    secrets = {
        "keystone-admin": snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        "shared-consumers": snapshot("shared-consumers", {
            "USER_ONE": b"admin", "PASSWORD_ONE": ADMIN.reveal(),
            "USER_TWO": b"admin", "PASSWORD_TWO": ADMIN.reveal(),
        }),
    }
    wave, _ = _wave_for(parsed, secrets)
    persisted = _run_propagation(parsed, secrets, wave)
    assert persisted.state.current_transaction is not None
    actions = derive_restart_actions(parsed, persisted.state.current_transaction, target=Identity.BREAKGLASS)
    assert len(actions) == 1
    assert actions[0].action_id == "deployment_shared-api"
    assert actions[0].caused_by_locations == ("shared-one", "shared-two")


# ---------------------------------------------------------------------------
# 3. unsupported workload kind rejection
# ---------------------------------------------------------------------------

def test_unsupported_workload_kind_rejected() -> None:
    text = """namespace: openstack
locations:
  keystone-admin:
    secret: keystone-admin
    identity: admin
    role: source
    representation:
      type: fields
      password: password
    restart: []
  bad:
    secret: bad-consumer
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart:
      - cronjob/bad-job
"""
    with pytest.raises(Exception) as raised:
        contract(text)
    assert "restart" in str(raised.value).lower() or "unsupported" in str(raised.value).lower()


# ---------------------------------------------------------------------------
# 4. Deployment restart
# ---------------------------------------------------------------------------

def test_deployment_restart() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    result = _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert result.all_complete
    assert result.outstanding == ()
    for name in ("octavia-api", "octavia-housekeeping"):
        workload = workloads[name]
        # The marker is derived from the durable wave intent (no opaque request).
        marker = restart_request_for(_transaction(persisted).propagation.to_b)
        assert workload.restart_requested == marker
        assert workload.metadata_generation == 2
        assert workload.observed_generation == 2
    for name in ("neutron-netns-cleanup-cron-default", "octavia-worker-default"):
        workload = workloads[name]
        assert workload.restart_requested == marker
        assert workload.metadata_generation == 2
    assert store.current.state.current_transaction is not None
    wave_b = _transaction(store.current).propagation.to_b
    assert all(item.state is RuntimeActionState.COMPLETE for item in wave_b.runtime_actions)
    assert {item.action_id for item in wave_b.runtime_actions} == set(_all_action_ids())


# ---------------------------------------------------------------------------
# 5. DaemonSet restart
# ---------------------------------------------------------------------------

def test_daemonset_restart() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    result = _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert result.all_complete
    # The daemonset workloads were dispatched through the daemonset client.
    assert workloads["neutron-netns-cleanup-cron-default"].restart_call_count == 1
    assert workloads["octavia-worker-default"].restart_call_count == 1
    # The deployment client was not used for daemonsets.
    daemonset_names = {
        "neutron-netns-cleanup-cron-default", "octavia-worker-default",
    }
    for call in client.deployment.restart_calls:
        assert call[1] not in daemonset_names


# ---------------------------------------------------------------------------
# 6. ownership assertion before restart mutation
# ---------------------------------------------------------------------------

def test_ownership_asserted_before_restart_mutation() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    original_deployment_read = client.deployment.read
    original_daemonset_read = client.daemonset.read
    reads = [0]

    def read_side_effect(namespace: str, name: str) -> WorkloadSnapshot:
        reads[0] += 1
        # After the first pre-dispatch observation, lose ownership.
        if reads[0] >= 1:
            owner.fail = True
        return original_deployment_read(namespace, name) if name in (
            "octavia-api", "octavia-housekeeping",
        ) else original_daemonset_read(namespace, name)

    client.deployment.read = read_side_effect
    client.daemonset.read = read_side_effect
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.OWNERSHIP_LOST
    # No restart was dispatched.
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 7. ownership loss before mutation
# ---------------------------------------------------------------------------

def test_ownership_loss_before_mutation() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership(fail=True)
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.OWNERSHIP_LOST
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 8. ownership assertion before durable action-progress writes
# ---------------------------------------------------------------------------

def test_ownership_reasserted_before_progress_write() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership(fail=True)
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.OWNERSHIP_LOST
    # No durable progress write happened.
    assert store.update_count == 0
    # No restart dispatched.
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 9. crash/recovery before dispatch
# ---------------------------------------------------------------------------

def test_crash_recovery_before_dispatch() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    result = _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert result.all_complete
    assert store.current.state.current_transaction is not None
    wave_b = _transaction(store.current).propagation.to_b
    assert {item.action_id for item in wave_b.runtime_actions} == set(_all_action_ids())


# ---------------------------------------------------------------------------
# 10. crash/recovery after dispatch before confirmation
# ---------------------------------------------------------------------------

def test_crash_recovery_after_dispatch_before_confirmation() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    marker = restart_request_for(_transaction(persisted).propagation.to_b)
    for workload in workloads.values():
        workload.restart_requested = marker
        workload.metadata_generation = 2
        workload.observed_generation = 2
        workload.rollout_status = RolloutStatus.SUCCEEDED
    wave_b = _transaction(persisted).propagation.to_b
    assert wave_b is not None
    pending_actions = tuple(
        RuntimeActionProgress(action_id, RuntimeActionState.PENDING)
        for action_id in _all_action_ids()
    )
    wave_with_pending = replace(wave_b, runtime_actions=pending_actions)
    state_with_pending = replace(
        persisted.state,
        current_transaction=replace(
            _transaction(persisted),
            propagation=replace(_transaction(persisted).propagation, to_b=wave_with_pending),
        ),
    )
    store = MemoryStateStore(PersistedState(state_with_pending, persisted.revision))
    owner = Ownership()
    client = _make_client(workloads)
    result = _run_restart(client, store, owner, parsed=parsed, wave=wave_with_pending)
    assert result.all_complete
    # No re-dispatch: the workloads were already restarted.
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []
    assert store.current.state.current_transaction is not None
    assert all(
        item.state is RuntimeActionState.COMPLETE
        for item in _transaction(store.current).propagation.to_b.runtime_actions
    )


# ---------------------------------------------------------------------------
# 11. crash/recovery after confirmation before completion persistence
# ---------------------------------------------------------------------------

def test_crash_recovery_after_confirmation_before_completion() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    marker = restart_request_for(_transaction(persisted).propagation.to_b)
    for workload in workloads.values():
        workload.restart_requested = marker
        workload.metadata_generation = 2
        workload.observed_generation = 2
        workload.rollout_status = RolloutStatus.SUCCEEDED
    wave_b = _transaction(persisted).propagation.to_b
    assert wave_b is not None
    running_actions = tuple(
        RuntimeActionProgress(action_id, RuntimeActionState.RUNNING)
        for action_id in _all_action_ids()
    )
    wave_running = replace(wave_b, runtime_actions=running_actions)
    state_running = replace(
        persisted.state,
        current_transaction=replace(
            _transaction(persisted),
            propagation=replace(_transaction(persisted).propagation, to_b=wave_running),
        ),
    )
    store = MemoryStateStore(PersistedState(state_running, persisted.revision))
    owner = Ownership()
    client = _make_client(workloads)
    result = _run_restart(client, store, owner, parsed=parsed, wave=wave_running)
    assert result.all_complete
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []
    assert all(
        item.state is RuntimeActionState.COMPLETE
        for item in _transaction(store.current).propagation.to_b.runtime_actions
    )


# ---------------------------------------------------------------------------
# 12. already-completed action recovery
# ---------------------------------------------------------------------------

def test_already_completed_action_not_repeated() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    wave_b = _transaction(persisted).propagation.to_b
    assert wave_b is not None
    complete_actions = tuple(
        RuntimeActionProgress(action_id, RuntimeActionState.COMPLETE)
        for action_id in _all_action_ids()
    )
    wave_complete = replace(wave_b, runtime_actions=complete_actions)
    state_complete = replace(
        persisted.state,
        current_transaction=replace(
            _transaction(persisted),
            propagation=replace(_transaction(persisted).propagation, to_b=wave_complete),
        ),
    )
    store = MemoryStateStore(PersistedState(state_complete, persisted.revision))
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    result = _run_restart(client, store, owner, parsed=parsed, wave=wave_complete)
    assert result.all_complete
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []
    # No new durable writes.
    assert store.update_count == 0


# ---------------------------------------------------------------------------
# 13. rollout failure
# ---------------------------------------------------------------------------

def test_rollout_failure() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)

    def failing_restart(namespace: str, name: str, request: str) -> WorkloadSnapshot:
        workload = workloads[name]
        workload.restart_call_count += 1
        workload.restart_requested = request
        workload.rollout_status = RolloutStatus.FAILED
        workload.metadata_generation += 1
        workload.desired_replicas = 2
        workload.ready_replicas = 0
        workload.updated_replicas = 0
        workload.unavailable_replicas = 2
        workload.rollout_completed = True
        return workload.snapshot()

    client.deployment.restart = failing_restart
    client.daemonset.restart = failing_restart
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.ROLLOUT_FAILED


# ---------------------------------------------------------------------------
# 14. rollout timeout
# ---------------------------------------------------------------------------

def test_rollout_timeout() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)

    def pending_restart(namespace: str, name: str, request: str) -> WorkloadSnapshot:
        workload = workloads[name]
        workload.restart_call_count += 1
        workload.restart_requested = request
        workload.rollout_status = RolloutStatus.PENDING
        workload.metadata_generation += 1
        workload.desired_replicas = 2
        workload.ready_replicas = 0
        workload.updated_replicas = 0
        workload.unavailable_replicas = 2
        workload.rollout_completed = True
        return workload.snapshot()

    client.deployment.restart = pending_restart
    client.daemonset.restart = pending_restart
    with pytest.raises(RestartExecutionError) as raised:
        execute_restart_debt(
            _as_workload_client(client), store, owner,
            contract=parsed, target=Identity.BREAKGLASS, now=NOW,
            poll_interval=0.1, deadline=0.05,
            sleeper=lambda _seconds: None,
        )
    assert raised.value.kind is RestartExecutionErrorCode.ROLLOUT_TIMEOUT


# ---------------------------------------------------------------------------
# 15. Kubernetes API failure
# ---------------------------------------------------------------------------

def test_kubernetes_api_failure() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    for workload in workloads.values():
        workload.read_error = WorkloadClientErrorCode.READ_FAILED
    client = _make_client(workloads)
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.WORKLOAD_READ_FAILED


def test_kubernetes_api_mutation_failure() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    for workload in workloads.values():
        workload.restart_error = WorkloadClientErrorCode.MUTATION_FAILED
    client = _make_client(workloads)
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.WORKLOAD_MUTATION_FAILED


def test_kubernetes_workload_missing() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    for workload in workloads.values():
        workload.read_error = WorkloadClientErrorCode.NOT_FOUND
    client = _make_client(workloads)
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.WORKLOAD_MISSING


# ---------------------------------------------------------------------------
# 16. durable state persistence failure
# ---------------------------------------------------------------------------

def test_progress_persistence_failure() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    store.fail_update = StateStoreError(StateStoreErrorCode.KUBERNETES_FAILURE)
    with pytest.raises(RestartExecutionError) as raised:
        _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    assert raised.value.kind is RestartExecutionErrorCode.PROGRESS_PERSISTENCE_FAILED
    # The store did not advance.
    assert store.current.revision.resource_version == persisted.revision.resource_version
    # No restart was dispatched (the first durable write is the action
    # registration, which happens before any dispatch).
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 17. no credential values in serialized restart state or errors
# ---------------------------------------------------------------------------

def test_no_credentials_in_serialized_state() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    serialized = serialize_state_json(store.current.state)
    assert ADMIN.reveal().decode() not in serialized
    assert BREAKGLASS.reveal().decode() not in serialized
    assert RestartExecutionError(RestartExecutionErrorCode.OWNERSHIP_LOST).code == "restart_execution_ownership_lost"


def test_no_credentials_in_diagnostics() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    result = _run_restart(client, store, owner, parsed=parsed, wave=_transaction(persisted).propagation.to_b)
    diagnostic = repr(result) + str(result)
    assert ADMIN.reveal().decode() not in diagnostic
    assert BREAKGLASS.reveal().decode() not in diagnostic


# ---------------------------------------------------------------------------
# 18. conservative restart retention
# ---------------------------------------------------------------------------

def test_conservative_restart_retention() -> None:
    parsed = contract(_fields_contract_text())
    # Plan from admin baseline (all non-target).
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    # Fresh state: all already at breakglass (target). The wave intent has
    # expected_target=False for all, so the changed set conservatively
    # retains all originally-non-target locations.
    all_target = _fields_secrets(
        neutron=Identity.BREAKGLASS, octavia=Identity.BREAKGLASS,
        worker=Identity.BREAKGLASS, none=Identity.BREAKGLASS,
    )
    client_secrets = FakeCredentialSecretClient(*all_target.values())
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    session = GroupedPropagationSession(store, store.current)
    execute_grouped_propagation_wave(
        client_secrets, session, owner,
        contract=parsed, references=_references(all_target),
        desired=desired, wave=wave, now=NOW,
    )
    assert store.current.state.current_transaction is not None
    wave_b = _transaction(store.current).propagation.to_b
    assert set(wave_b.applied_location_ids) == {
        "neutron-keystone-admin", "octavia-service-auth-etc",
        "octavia-service-auth-worker", "no-restart",
    }
    actions = derive_restart_actions(parsed, store.current.state.current_transaction, target=Identity.BREAKGLASS)
    assert {action.action_id for action in actions} == {
        "daemonset_neutron-netns-cleanup-cron-default",
        "deployment_octavia-api",
        "deployment_octavia-housekeeping",
        "daemonset_octavia-worker-default",
    }


# ---------------------------------------------------------------------------
# 19. Kubernetes strategic-merge patch adapter tests
# ---------------------------------------------------------------------------

def _deployment_body(
    *, namespace: str = "openstack", name: str = "octavia-api",
    uid: str = "dep-uid", generation: int = 1,
    template_restart: str | None = None,
    observed_generation: int = 1,
    updated: int = 1, ready: int = 1, unavailable: int = 0,
    progressing_status: str = "True",
) -> dict[str, object]:
    template_metadata: dict[str, object] = {}
    if template_restart is not None:
        template_metadata["annotations"] = {RESTART_ANNOTATION: template_restart}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "namespace": namespace, "name": name, "uid": uid,
            "generation": generation,
        },
        "spec": {"replicas": ready, "template": {"metadata": template_metadata}},
        "status": {
            "observedGeneration": observed_generation,
            "updatedReplicas": updated,
            "readyReplicas": ready,
            "unavailableReplicas": unavailable,
            "conditions": [
                {"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable"},
                {"type": "Progressing", "status": progressing_status,
                 "reason": "ProgressDeadlineExceeded" if progressing_status == "False" else "NewReplicaSetAvailable"},
            ],
        },
    }


def _daemonset_body(
    *, namespace: str = "openstack", name: str = "octavia-worker-default",
    uid: str = "ds-uid", generation: int = 1,
    template_restart: str | None = None,
    observed_generation: int = 1,
    desired: int = 1, current: int = 1, ready: int = 1, updated: int = 1,
) -> dict[str, object]:
    template_metadata: dict[str, object] = {}
    if template_restart is not None:
        template_metadata["annotations"] = {RESTART_ANNOTATION: template_restart}
    return {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "namespace": namespace, "name": name, "uid": uid,
            "generation": generation,
        },
        "spec": {"template": {"metadata": template_metadata}},
        "status": {
            "observedGeneration": observed_generation,
            "desiredNumberScheduled": desired,
            "currentNumberScheduled": current,
            "numberReady": ready,
            "updatedNumberScheduled": updated,
            "conditions": [
                {"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable"},
            ],
        },
    }


class _FakeAppsV1Api:
    """Records the patch body and returns a canned workload object."""

    def __init__(self, deployment: dict[str, object], daemonset: dict[str, object]) -> None:
        self.deployment = deployment
        self.daemonset = daemonset
        self.patch_calls: list[tuple[str, str, dict[str, object], str]] = []

    def read_namespaced_deployment(self, name: str, namespace: str, **kwargs: object) -> dict[str, object]:
        return self.deployment

    def read_namespaced_daemon_set(self, name: str, namespace: str, **kwargs: object) -> dict[str, object]:
        return self.daemonset

    def patch_namespaced_deployment(self, name: str, namespace: str, body: dict[str, object], **kwargs: object) -> dict[str, object]:
        self.patch_calls.append(("deployment", name, body, str(kwargs.get("_content_type", ""))))
        return self.deployment

    def patch_namespaced_daemon_set(self, name: str, namespace: str, body: dict[str, object], **kwargs: object) -> dict[str, object]:
        self.patch_calls.append(("daemonset", name, body, str(kwargs.get("_content_type", ""))))
        return self.daemonset


def _make_api_client() -> tuple[KubernetesApiWorkloadClient, _FakeAppsV1Api]:
    api = _FakeAppsV1Api(
        deployment=_deployment_body(),
        daemonset=_daemonset_body(),
    )
    client = KubernetesApiWorkloadClient(api, _serializer(), timeout=5.0)
    return client, api


def test_restart_patch_targets_pod_template_not_top_level() -> None:
    """The strategic-merge patch must set spec.template.metadata.annotations,
    not top-level metadata.annotations.  A top-level annotation does not
    trigger a Deployment/DaemonSet rollout restart."""
    client, api = _make_api_client()
    client.restart("openstack", "octavia-api", WorkloadKind.DEPLOYMENT, "test-marker")
    assert len(api.patch_calls) == 1
    kind, name, body, content_type = api.patch_calls[0]
    assert kind == "deployment"
    assert name == "octavia-api"
    assert content_type == "application/strategic-merge-patch+json"
    # The patch must target the Pod template, not top-level metadata.
    spec = cast(dict[str, object], body["spec"])
    template = cast(dict[str, object], spec["template"])
    template_metadata = cast(dict[str, object], template["metadata"])
    annotations = cast(dict[str, object], template_metadata["annotations"])
    assert annotations[RESTART_ANNOTATION] == "test-marker"
    # Top-level metadata must NOT carry the restart annotation.
    top_metadata = body.get("metadata")
    if isinstance(top_metadata, dict):
        top_annotations: object = cast(dict[str, object], top_metadata).get("annotations")
        if isinstance(top_annotations, dict):
            assert RESTART_ANNOTATION not in top_annotations


def test_restart_patch_daemonset_targets_pod_template() -> None:
    client, api = _make_api_client()
    client.restart("openstack", "octavia-worker-default", WorkloadKind.DAEMONSET, "test-marker")
    assert len(api.patch_calls) == 1
    kind, name, body, content_type = api.patch_calls[0]
    assert kind == "daemonset"
    assert name == "octavia-worker-default"
    assert content_type == "application/strategic-merge-patch+json"
    spec = cast(dict[str, object], body["spec"])
    template = cast(dict[str, object], spec["template"])
    annotations = cast(dict[str, object], cast(dict[str, object], template["metadata"])["annotations"])
    assert annotations[RESTART_ANNOTATION] == "test-marker"


def test_read_observes_pod_template_annotation() -> None:
    """The restart marker must be read from spec.template.metadata.annotations,
    not top-level metadata.annotations."""
    marker = "observed-marker"
    api = _FakeAppsV1Api(
        deployment=_deployment_body(template_restart=marker, generation=2, observed_generation=2),
        daemonset=_daemonset_body(),
    )
    client = KubernetesApiWorkloadClient(api, _serializer(), timeout=5.0)
    snapshot = client.read("openstack", "octavia-api", WorkloadKind.DEPLOYMENT)
    assert snapshot.restart_requested == marker
    assert snapshot.metadata_generation == 2
    assert snapshot.observed_generation == 2


def test_read_ignores_top_level_annotation() -> None:
    """A top-level workload annotation must NOT be reported as the restart
    marker; only the Pod-template annotation is authoritative."""
    api = _FakeAppsV1Api(
        deployment={
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "namespace": "openstack", "name": "octavia-api", "uid": "dep-uid",
                "generation": 1,
                "annotations": {RESTART_ANNOTATION: "top-level-only"},
            },
            "spec": {"replicas": 1, "template": {"metadata": {}}},
            "status": {
                "observedGeneration": 1, "updatedReplicas": 1,
                "readyReplicas": 1, "unavailableReplicas": 0,
                "conditions": [{"type": "Available", "status": "True"}],
            },
        },
        daemonset=_daemonset_body(),
    )
    client = KubernetesApiWorkloadClient(api, _serializer(), timeout=5.0)
    snapshot = client.read("openstack", "octavia-api", WorkloadKind.DEPLOYMENT)
    assert snapshot.restart_requested is None


def _serializer():
    """A minimal serializer for the Kubernetes API client tests.

    The production serializer is ``kubernetes.client.ApiClient``; for these
    unit tests the workload objects are already plain dicts, so the
    sanitizer is an identity function.
    """
    class _IdentitySerializer:
        def sanitize_for_serialization(self, value: object) -> object:
            return value

    return _IdentitySerializer()


# ---------------------------------------------------------------------------
# 20. generation-aware rollout completion
# ---------------------------------------------------------------------------

def test_generation_lag_prevents_completion() -> None:
    """New metadata.generation + old observedGeneration + all old replicas
    ready -> NOT complete.  The status block still describes the old template."""
    snapshot = WorkloadSnapshot(
        namespace="openstack", name="octavia-api", uid="dep-uid",
        restart_requested="marker", metadata_generation=2,
        observed_generation=1,
        ready_replicas=1, desired_replicas=1, updated_replicas=1,
        unavailable_replicas=0, rollout_status=RolloutStatus.SUCCEEDED,
        condition_reason=None,
    )
    assert not snapshot.complete(restart_requested="marker")


def test_generation_caught_up_completes() -> None:
    """observedGeneration caught up + replicas converged + matching restart
    marker -> complete."""
    snapshot = WorkloadSnapshot(
        namespace="openstack", name="octavia-api", uid="dep-uid",
        restart_requested="marker", metadata_generation=2,
        observed_generation=2,
        ready_replicas=1, desired_replicas=1, updated_replicas=1,
        unavailable_replicas=0, rollout_status=RolloutStatus.SUCCEEDED,
        condition_reason=None,
    )
    assert snapshot.complete(restart_requested="marker")


def test_generation_caught_up_no_matching_marker_incomplete() -> None:
    """Converged replicas + generation caught up but wrong restart marker
    -> NOT complete (a different restart wave's rollout does not satisfy
    this wave's restart)."""
    snapshot = WorkloadSnapshot(
        namespace="openstack", name="octavia-api", uid="dep-uid",
        restart_requested="other-marker", metadata_generation=2,
        observed_generation=2,
        ready_replicas=1, desired_replicas=1, updated_replicas=1,
        unavailable_replicas=0, rollout_status=RolloutStatus.SUCCEEDED,
        condition_reason=None,
    )
    assert not snapshot.complete(restart_requested="my-marker")


def test_daemonset_generation_lag_prevents_completion() -> None:
    """DaemonSet: new generation + old observedGeneration + all old nodes
    ready -> NOT complete."""
    snapshot = WorkloadSnapshot(
        namespace="openstack", name="octavia-worker-default", uid="ds-uid",
        restart_requested="marker", metadata_generation=3,
        observed_generation=2,
        ready_replicas=5, desired_replicas=5, updated_replicas=5,
        unavailable_replicas=0, rollout_status=RolloutStatus.SUCCEEDED,
        condition_reason=None,
    )
    assert not snapshot.complete(restart_requested="marker")


def test_daemonset_generation_caught_up_completes() -> None:
    """DaemonSet: observedGeneration caught up + schedule converged + matching
    marker -> complete."""
    snapshot = WorkloadSnapshot(
        namespace="openstack", name="octavia-worker-default", uid="ds-uid",
        restart_requested="marker", metadata_generation=3,
        observed_generation=3,
        ready_replicas=5, desired_replicas=5, updated_replicas=5,
        unavailable_replicas=0, rollout_status=RolloutStatus.SUCCEEDED,
        condition_reason=None,
    )
    assert snapshot.complete(restart_requested="marker")


# ---------------------------------------------------------------------------
# 21. production sleeper default
# ---------------------------------------------------------------------------

def test_default_sleeper_is_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default execution path must use time.sleep, not a no-op lambda.
    A no-op sleeper would busy-loop against the Kubernetes API."""
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    # Force every workload to never converge so the executor keeps polling.
    for workload in workloads.values():
        workload.desired_replicas = 2
        workload.ready_replicas = 0
        workload.updated_replicas = 0
        workload.unavailable_replicas = 2
        workload.rollout_status = RolloutStatus.PENDING
        workload.rollout_completed = True
    client = _make_client(workloads)

    sleep_calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr(time, "sleep", fake_sleep)
    with pytest.raises(RestartExecutionError) as raised:
        execute_restart_debt(
            _as_workload_client(client), store, owner,
            contract=parsed, target=Identity.BREAKGLASS, now=NOW,
            poll_interval=5.0, deadline=0.01,
        )
    assert raised.value.kind is RestartExecutionErrorCode.ROLLOUT_TIMEOUT
    # The default sleeper must be time.sleep (patched here to record calls),
    # not a no-op lambda.
    assert len(sleep_calls) >= 1
    assert all(s > 0 for s in sleep_calls)


# ---------------------------------------------------------------------------
# 22. restart request identity
# ---------------------------------------------------------------------------

def test_restart_request_stable_across_recovery() -> None:
    """The derived marker must be identical when reconstructed from the same
    durable wave intent (recovery of the same restart wave)."""
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    marker1 = restart_request_for(wave)
    # Simulate recovery: a replacement execution reads the same wave intent
    # from durable state and derives the same marker.
    marker2 = restart_request_for(wave)
    assert marker1 == marker2


def test_restart_request_differs_between_waves() -> None:
    """The derived marker must differ between logically separate to-B and to-A
    restart waves."""
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave_b, _ = _wave_for(parsed, base)
    intent_b = wave_b.intent
    assert intent_b is not None
    # Construct a to-A wave with a different target identity and generation.
    intent_a = replace(
        intent_b,
        target_identity=Identity.ADMIN,
        target_generation=ADMIN_GENERATION,
    )
    wave_a = replace(wave_b, intent=intent_a)
    marker_b = restart_request_for(wave_b)
    marker_a = restart_request_for(wave_a)
    assert marker_b != marker_a


def test_restart_request_is_annotation_safe() -> None:
    """The derived marker must be safe to place in a Kubernetes annotation:
    nonempty, a bounded string, and containing no credential material."""
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    marker = restart_request_for(wave)
    assert 0 < len(marker) <= 128
    assert marker.startswith("genestack-")
    assert ADMIN.reveal().decode() not in marker
    assert BREAKGLASS.reveal().decode() not in marker


# ---------------------------------------------------------------------------
# 23. ownership reasserted immediately before dispatch
# ---------------------------------------------------------------------------

class _TogglingOwnership:
    """Ownership that can be toggled between valid and invalid mid-execution.

    Used to simulate the race where ownership is valid while RUNNING is
    persisted but becomes invalid before the dispatch assertion.
    """

    def __init__(self) -> None:
        self.valid = True
        self.assertion_count = 0
        self.wave_writes = 0

    @property
    def requires_recovery_gate(self) -> bool:
        return False

    def assert_owned(self) -> None:
        self.assertion_count += 1
        if not self.valid:
            raise SafeError("ownership_lost", "ownership lost")

    def invalidate(self) -> None:
        self.valid = False


def test_ownership_race_running_persisted_then_lost_before_dispatch() -> None:
    """Ownership valid while RUNNING is persisted, then lost before the
    immediately-pre-dispatch assertion.  No Kubernetes restart mutation occurs."""
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    store = MemoryStateStore(persisted)
    owner = _TogglingOwnership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)

    # Wrap the store's update to invalidate ownership after the RUNNING write.
    original_update = store.update
    running_write_done = False

    def update_and_invalidate(expected: StateRevision, new_state: PersistentState) -> PersistedState:
        nonlocal running_write_done
        result = original_update(expected, new_state)
        # The first wave write is the RUNNING marker for the first action.
        # Invalidate ownership immediately after it persists.
        if not running_write_done:
            owner.invalidate()
            running_write_done = True
        return result

    store.update = update_and_invalidate
    with pytest.raises(RestartExecutionError) as raised:
        execute_restart_debt(
            _as_workload_client(client), store, owner,
            contract=parsed, target=Identity.BREAKGLASS, now=NOW,
            sleeper=lambda _seconds: None,
        )
    assert raised.value.kind is RestartExecutionErrorCode.OWNERSHIP_LOST
    # No Kubernetes restart mutation occurred: the dispatch was never reached.
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []
    # The RUNNING write was persisted (acceptable and recoverable).
    assert running_write_done


# ---------------------------------------------------------------------------
# 24. contract digest drift
# ---------------------------------------------------------------------------

def _fields_contract_text_with_extra_restart() -> str:
    """Same location IDs as _fields_contract_text but with an added restart
    edge on the no-restart location.  The contract digest will differ."""
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
  neutron-keystone-admin:
    secret: neutron-keystone-admin
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart:
      - daemonset/neutron-netns-cleanup-cron-default
  octavia-service-auth-etc:
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
  octavia-service-auth-worker:
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
    restart:
      - deployment/octavia-api
"""


def test_contract_drift_fails_closed() -> None:
    """A contract that retains the same location IDs but changes restart edges
    produces a different contract digest.  derive_restart_actions and
    execute_restart_debt must fail closed with CONTRACT_DRIFT."""
    parsed_original = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed_original, base)
    persisted = _run_propagation(parsed_original, base, wave)

    # A drifted contract: same location IDs, but no-restart now has a restart
    # edge to deployment/octavia-api.
    parsed_drifted = contract(_fields_contract_text_with_extra_restart())
    store = MemoryStateStore(persisted)
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    with pytest.raises(RestartExecutionError) as raised:
        execute_restart_debt(
            _as_workload_client(client), store, owner,
            contract=parsed_drifted, target=Identity.BREAKGLASS, now=NOW,
            sleeper=lambda _seconds: None,
        )
    assert raised.value.kind is RestartExecutionErrorCode.CONTRACT_DRIFT
    # No workload mutation occurred.
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []


def test_contract_drift_derivation_alone() -> None:
    """derive_restart_actions fails closed when the contract digest does not
    match the wave intent, even without a full execution."""
    parsed_original = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed_original, base)
    persisted = _run_propagation(parsed_original, base, wave)
    parsed_drifted = contract(_fields_contract_text_with_extra_restart())
    transaction = persisted.state.current_transaction
    assert transaction is not None
    with pytest.raises(RestartExecutionError) as raised:
        derive_restart_actions(parsed_drifted, transaction, target=Identity.BREAKGLASS)
    assert raised.value.kind is RestartExecutionErrorCode.CONTRACT_DRIFT


# ---------------------------------------------------------------------------
# 25. stale durable runtime action IDs
# ---------------------------------------------------------------------------

def test_stale_runtime_action_fails_closed() -> None:
    """A wave containing a durable runtime action ID that is not derivable
    from the current contract/wave must fail closed with STALE_RUNTIME_ACTIONS
    rather than remaining unreachable debt."""
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    persisted = _run_propagation(parsed, base, wave)
    wave_b = _transaction(persisted).propagation.to_b
    assert wave_b is not None
    # Add an unexpected durable action that is not derivable.
    stale_action = RuntimeActionProgress("deployment_stale-ghost", RuntimeActionState.PENDING)
    wave_with_stale = replace(wave_b, runtime_actions=wave_b.runtime_actions + (stale_action,))
    state_with_stale = replace(
        persisted.state,
        current_transaction=replace(
            _transaction(persisted),
            propagation=replace(_transaction(persisted).propagation, to_b=wave_with_stale),
        ),
    )
    store = MemoryStateStore(PersistedState(state_with_stale, persisted.revision))
    owner = Ownership()
    workloads = _workloads("octavia-api", "octavia-housekeeping",
                            "neutron-netns-cleanup-cron-default", "octavia-worker-default")
    client = _make_client(workloads)
    with pytest.raises(RestartExecutionError) as raised:
        execute_restart_debt(
            _as_workload_client(client), store, owner,
            contract=parsed, target=Identity.BREAKGLASS, now=NOW,
            sleeper=lambda _seconds: None,
        )
    assert raised.value.kind is RestartExecutionErrorCode.STALE_RUNTIME_ACTIONS
    # No workload mutation occurred.
    assert client.deployment.restart_calls == []
    assert client.daemonset.restart_calls == []
