"""Slice 4I: transaction-level ``VERIFY_A`` final verification and
transaction finalization tests.

``run_verify_a`` independently re-observes the stable-A system state left by
``SWITCH_TO_A`` (authoritative A at A3, every participating and fixed-admin
location at admin/new-A, restart debt complete, workloads rolled out), then
performs the narrowly scoped transaction finalization (lockout restoration,
breeder provenance cleanup) and durably marks the transaction completed in the
terminal ``STABLE_A`` state.  These tests compose the existing behavioral
fakes rather than introducing parallel test abstractions.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, cast
from uuid import UUID

import pytest

from admin_password_rotation.breeder import (
    FakeBreederSecretClient,
    PROVENANCE_GENERATION, PROVENANCE_STAGE, PROVENANCE_TRANSACTION,
)
from admin_password_rotation.config import parse_contract
from admin_password_rotation.errors import SafeError
from admin_password_rotation.keystone import (
    FakeKeystoneClient, KeystoneIndeterminateReason, KeystoneUserObservation,
)
from admin_password_rotation.model import (
    ConfigurationDigest, CredentialGeneration, CredentialMutationIntent,
    CredentialMutationStep, EnvironmentIdentity, ExecutionIdentity, Identity,
    IntentEffectState, LockoutChangeState, LockoutState, PasswordSafeState,
    PersistentState, PropagationState, PropagationWave,
    ReferenceCredentials, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, RuntimeActionProgress, RuntimeActionState,
    SecretAnnotation, SecretField, SecretInventory, SecretSnapshot,
    SecretValue, TransactionStatus, VerificationResult, VerificationStatus,
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
from admin_password_rotation.restart import RolloutStatus, WorkloadClient, WorkloadSnapshot
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import (
    PersistedState, StateRevision, StateStore, StateStoreError,
    StateStoreErrorCode,
)
from admin_password_rotation.verify_a import (
    ConditionalPatchError, ConditionalPatchErrorCode,
    VerifyAError, VerifyAErrorCode, VerifyAInputs, VerifyAOutcome,
    VerifyARequest, run_verify_a,
)

NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
ENVIRONMENT = EnvironmentIdentity("dfw-dev", "cluster.local")
A_OLD = SecretValue(b"Synthetic-Old-Admin-4I")
A_NEW = SecretValue(b"Synthetic-ANew-4I-0123456789abcd")
B = SecretValue(b"Synthetic-Breakglass-4I")
OLD_GENERATION = CredentialGeneration.from_secret(A_OLD)
A_GENERATION = CredentialGeneration.from_secret(A_NEW)
B_GENERATION = CredentialGeneration.from_secret(B)
IDS = ResolvedKeystoneIdentities(
    "admin-user", "breakglass-user", "default-domain", "admin-project",
    "default-domain", "admin-role",
)
ACCESS = IdentityAccess(
    datetime(2030, 1, 1, tzinfo=timezone.utc), SecretValue(b"ps-token"),
)
EXECUTION = ExecutionIdentity(
    UUID("44444444-4444-4444-8444-444444444444"), None,
)
TX_ID = UUID("11111111-1111-4111-8111-111111111111")
BREEDER_UID = "fixture-keystone-admin"


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


def _pair(identity: str) -> tuple[bytes, bytes]:
    if identity == "admin":
        return b"admin", A_NEW.reveal()
    return b"breakglass", B.reveal()


def snapshot(name: str, data: dict[str, bytes]) -> SecretSnapshot:
    return SecretSnapshot(
        "openstack", name, f"uid-{name}", "7",
        tuple(SecretField(key, SecretValue(value)) for key, value in sorted(data.items())),
    )


def _ini(identity: str) -> bytes:
    username, password = _pair(identity)
    return (
        b"[service_auth]\nusername = " + username
        + b"\npassword = " + password + b"\n"
    )


def _breeder(
    *, with_provenance: bool = True, password: SecretValue = A_NEW,
    uid: str = BREEDER_UID,
) -> SecretSnapshot:
    base = snapshot("keystone-admin", {
        "password": password.reveal(),
        "unrelated": b"preserve-me",
    })
    annotations: tuple[SecretAnnotation, ...] = (
        SecretAnnotation("example.org/keep", "unchanged"),
    )
    if with_provenance:
        annotations = annotations + (
            SecretAnnotation(PROVENANCE_TRANSACTION, str(TX_ID)),
            SecretAnnotation(PROVENANCE_GENERATION, A_GENERATION.value),
            SecretAnnotation(PROVENANCE_STAGE, "pending-keystone"),
        )
    return replace(
        base, uid=uid, resource_version="124", annotations=annotations,
    )


def _secrets(
    *, neutron: str = "admin", octavia_etc: str = "admin",
    octavia_worker: str = "admin", none: str = "admin",
    breeder_provenance: bool = True, breeder_password: SecretValue = A_NEW,
) -> dict[str, SecretSnapshot]:
    un, pw = _pair(neutron)
    return {
        "keystone-admin": _breeder(
            with_provenance=breeder_provenance, password=breeder_password,
        ),
        "neutron-keystone-admin": snapshot("neutron-keystone-admin", {
            "OS_USERNAME": un, "OS_PASSWORD": pw,
        }),
        "octavia-etc": snapshot("octavia-etc", {"octavia.conf": _ini(octavia_etc)}),
        "octavia-worker-default": snapshot("octavia-worker-default", {"octavia.conf": _ini(octavia_worker)}),
        "no-restart": snapshot("no-restart", {
            "OS_USERNAME": _pair(none)[0], "OS_PASSWORD": _pair(none)[1],
        }),
    }


def _fixed_admin_secrets(
    *, admin_fixed: str = "admin", active: str = "admin",
    breeder_provenance: bool = True, breeder_password: SecretValue = A_NEW,
) -> dict[str, SecretSnapshot]:
    """Secrets matching the fixed-admin contract topology exactly."""
    uf, pf = _pair(admin_fixed)
    ua, pa = _pair(active)
    return {
        "keystone-admin": _breeder(
            with_provenance=breeder_provenance, password=breeder_password,
        ),
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
# Ownership / state store
# ---------------------------------------------------------------------------


class Ownership:
    def __init__(self, *, fail: bool = False, fail_after: int | None = None) -> None:
        self.assertions = 0
        self.fail = fail
        self.fail_after = fail_after

    @property
    def requires_recovery_gate(self) -> bool:
        return False

    def assert_owned(self) -> None:
        self.assertions += 1
        if self.fail or (
            self.fail_after is not None and self.assertions > self.fail_after
        ):
            raise SafeError("ownership_lost", "ownership lost")


class MemoryStateStore(StateStore):
    def __init__(self, current: PersistedState) -> None:
        self.current = current
        self.update_count = 0
        self.fail_update: Exception | None = None
        self.before_final_update: Callable[[MemoryStateStore], None] | None = None
        self.record_updates = False
        self.recorded_states: list[PersistentState] = []

    def load(self) -> PersistedState:
        return self.current

    def update(self, expected: StateRevision, new_state: PersistentState) -> PersistedState:
        # The final state-store update is the ownership-fenced completion:
        # it records the verify-a-complete receipt, the terminal STABLE_A
        # phase, and the COMPLETED status.  The hook lets a test simulate a
        # concurrent transaction-state mutation landing between the
        # completion decision and this CAS-protected advance.
        if (
            self.before_final_update is not None
            and new_state.current_transaction is not None
            and new_state.current_transaction.status is TransactionStatus.COMPLETED
        ):
            self.before_final_update(self)
        if self.fail_update is not None:
            error = self.fail_update
            self.fail_update = None
            raise error
        if expected != self.current.revision:
            raise StateStoreError(StateStoreErrorCode.CONFLICT)
        self.update_count += 1
        self.current = PersistedState(
            new_state,
            replace(expected, resource_version=str(int(expected.resource_version) + 1)),
        )
        if self.record_updates:
            self.recorded_states.append(self.current.state)
        return self.current


# ---------------------------------------------------------------------------
# Breeder conditional-patch fake
# ---------------------------------------------------------------------------


class FakeBreederPatch:
    """Behavioral fake for the provenance-removal conditional patch."""

    def __init__(self, breeder: FakeBreederSecretClient) -> None:
        self._breeder = breeder
        self.patch_calls = 0
        self.next_error: str | None = None
        self.before_patch: Callable[["FakeBreederPatch"], None] | None = None

    def patch(self, expected: SecretSnapshot, patch: list[dict[str, object]]) -> None:
        self.patch_calls += 1
        if self.before_patch is not None:
            callback = self.before_patch
            self.before_patch = None
            callback(self)
        if self.next_error is not None:
            kind = self.next_error
            self.next_error = None
            raise ConditionalPatchError(ConditionalPatchErrorCode(kind))
        snapshot = self._breeder.snapshot
        if (
            snapshot.uid != expected.uid
            or snapshot.resource_version != expected.resource_version
        ):
            raise ConditionalPatchError(
                ConditionalPatchErrorCode.CONDITIONAL_REJECTED,
            )
        removed: set[str] = set()
        for op in patch:
            if op.get("op") == "remove":
                path = op.get("path")
                if isinstance(path, str) and path.startswith(
                    "/metadata/annotations/",
                ):
                    key = path.removeprefix("/metadata/annotations/")
                    removed.add(
                        key.replace("~1", "/").replace("~0", "~"),
                    )
        annotations = tuple(
            item for item in snapshot.annotations if item.key not in removed
        )
        self._breeder.snapshot = replace(
            snapshot,
            resource_version=str(int(snapshot.resource_version) + 1),
            annotations=annotations,
        )


# ---------------------------------------------------------------------------
# Workload fakes (reused from the Slice 4D / 4E / 4H test harness)
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


def _rolled_out_workloads(wave: PropagationWave) -> dict[str, _FakeWorkload]:
    """Workloads restarted for the to-A wave and observed rolled out."""
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(wave)
    workloads = _workloads(*_all_workload_names())
    for workload in workloads.values():
        workload.restart_requested = marker
        workload.metadata_generation = 2
        workload.observed_generation = 2
        workload.rollout_status = RolloutStatus.SUCCEEDED
        workload.rollout_completed = True
        workload.auto_advance = False
    return workloads


# ---------------------------------------------------------------------------
# Transaction / external fixtures
# ---------------------------------------------------------------------------


def _switch_to_a_receipt() -> VerificationResult:
    return VerificationResult(
        "switch-to-a-complete", RotationPhase.SWITCH_TO_A,
        VerificationStatus.SUCCESS, NOW, "propagated-and-restarted",
        None, A_GENERATION,
    )


def _transaction(
    *,
    phase: RotationPhase = RotationPhase.VERIFY_A,
    status: TransactionStatus = TransactionStatus.ACTIVE,
    to_a: PropagationWave | None = None,
    include_switch_to_a_receipt: bool = True,
    include_rotate_a_receipt: bool = True,
    include_prepare_b_receipts: bool = True,
    lockout_restored: bool = False,
    execution: ExecutionIdentity | None = None,
) -> RotationTransaction:
    verifications: list[VerificationResult] = []
    if include_prepare_b_receipts:
        verifications.append(VerificationResult(
            "stable-a", RotationPhase.PREPARE_B, VerificationStatus.SUCCESS, NOW,
            "freshly-verified", BREEDER_UID, OLD_GENERATION,
        ))
        verifications.append(VerificationResult(
            "breakglass-b2", RotationPhase.PREPARE_B, VerificationStatus.SUCCESS, NOW,
            "freshly-authorized", None, B_GENERATION,
        ))
    if include_rotate_a_receipt:
        verifications.append(VerificationResult(
            "rotate-a-complete", RotationPhase.ROTATE_A, VerificationStatus.SUCCESS, NOW,
            "authoritative-a-converged", None, A_GENERATION,
        ))
    if include_switch_to_a_receipt:
        verifications.append(_switch_to_a_receipt())
    return RotationTransaction(
        transaction_id=TX_ID,
        request_id=UUID("22222222-2222-4222-8222-222222222222"),
        execution=execution or EXECUTION,
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=IDS,
        created_at=NOW,
        updated_at=NOW,
        phase=phase,
        status=status,
        last_error=None,
        new_a_sha256=A_GENERATION,
        new_b_sha256=B_GENERATION,
        passwordsafe=PasswordSafeState(101, 202, 101, 202, 7, 7, 4),
        credential_mutation_intent=CredentialMutationIntent(
            CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
            None, (), A_GENERATION, IntentEffectState.OBSERVED, NOW, None,
        ),
        propagation=PropagationState(
            PropagationWave((), ()),
            to_a if to_a is not None else PropagationWave((), ()),
        ),
        lockout=LockoutState(
            False,
            LockoutChangeState.EFFECT_OBSERVED,
            LockoutChangeState.EFFECT_OBSERVED if lockout_restored
            else LockoutChangeState.NOT_INTENDED,
            False if lockout_restored else True,
            not lockout_restored,
        ),
        verifications=tuple(verifications),
    )


def _state_for(transaction: RotationTransaction) -> PersistedState:
    return PersistedState(
        PersistentState(
            schema_version=2,
            environment=ENVIRONMENT,
            current_transaction=transaction,
            completed_requests=(),
        ),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )


def _keystone(*, suppressed: bool = True) -> FakeKeystoneClient:
    client = FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    client.add_user(KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True,
        "admin-project", suppressed,
    ), A_NEW)
    client.add_user(KeystoneUserObservation(
        "breakglass-user", "breakglass", "default-domain", True,
        "admin-project", False,
    ), B)
    return client


def _passwordsafe() -> FakePasswordSafeClient:
    client = FakePasswordSafeClient()
    client.add(PasswordSafeCredential(10, 101, "admin", 7, A_NEW))
    client.add(PasswordSafeCredential(10, 202, "breakglass", 4, B))
    return client


def _request() -> VerifyARequest:
    return VerifyARequest(
        environment=ENVIRONMENT,
        keystone=IDS,
        passwordsafe_project_id=10,
        passwordsafe_a_record_id=101,
        passwordsafe_b_record_id=202,
        execution=EXECUTION,
    )


def _complete_to_a(secrets: dict[str, SecretSnapshot] | None = None) -> PropagationWave:
    """The durable to-A wave as left by a completed ``SWITCH_TO_A``.

    Every applicable location applied, and every derived restart action
    COMPLETE — the 4H exit state.
    """
    parsed = parse_contract(_contract_text())
    desired = DesiredCredential(Identity.ADMIN, A_NEW)
    refs = ReferenceCredentials(A_NEW, B)
    planned = plan_or_reconcile_propagation_wave(
        parsed,
        SecretInventory("openstack", "100", tuple((secrets or _secrets()).values())),
        refs, desired, A_GENERATION, PropagationWave((), ()),
    )
    applied = ("neutron", "no-restart", "octavia-etc", "octavia-worker")
    actions = tuple(
        RuntimeActionProgress(action_id, RuntimeActionState.COMPLETE)
        for action_id in _all_action_ids()
    )
    return replace(planned.wave, applied_location_ids=applied, runtime_actions=actions)


def _fixed_admin_complete_to_a(
    secrets: dict[str, SecretSnapshot],
) -> PropagationWave:
    parsed = parse_contract(_fixed_admin_contract_text())
    desired = DesiredCredential(Identity.ADMIN, A_NEW)
    refs = ReferenceCredentials(A_NEW, B)
    planned = plan_or_reconcile_propagation_wave(
        parsed,
        SecretInventory("openstack", "100", tuple(secrets.values())),
        refs, desired, A_GENERATION, PropagationWave((), ()),
    )
    return replace(
        planned.wave,
        applied_location_ids=("active",),
        runtime_actions=(
            RuntimeActionProgress("deployment_active-api", RuntimeActionState.COMPLETE),
        ),
    )


def _run(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, owner: Ownership, *,
    contract_text: str = _contract_text(),
    keystone_client: FakeKeystoneClient | None = None,
    passwordsafe_client: FakePasswordSafeClient | None = None,
    breeder: FakeBreederSecretClient | None = None,
    breeder_patch: FakeBreederPatch | None = None,
):
    parsed = parse_contract(contract_text)
    inputs = VerifyAInputs(
        request=_request(),
        contract=parsed,
        passwordsafe_access=ACCESS,
        breeder=breeder or FakeBreederSecretClient(_breeder()),
        secret_client=secret_client,
        workload_client=cast(WorkloadClient, workload_client),
        breeder_patch=breeder_patch,
    )
    return run_verify_a(
        inputs,
        state_store=store,
        ownership=owner,
        passwordsafe=passwordsafe_client or _passwordsafe(),
        keystone=keystone_client or _keystone(),
        clock=lambda: NOW,
    )


def _assert_no_side_effects(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, breeder: FakeBreederSecretClient,
    patch: FakeBreederPatch | None, *, phase: RotationPhase,
) -> None:
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is phase
    assert transaction.status is not TransactionStatus.COMPLETED
    assert not any(
        item.check_id == "verify-a-complete" for item in transaction.verifications
    )
    # No propagation writes (the phase is observational about locations).
    assert secret_client.replace_calls == 0
    if patch is not None:
        assert patch.patch_calls == 0


# ---------------------------------------------------------------------------
# 1. Fully converged final A state completes successfully
# ---------------------------------------------------------------------------


def test_converged_final_state_completes() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    assert result.completed is True
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.STABLE_A
    assert transaction.status is TransactionStatus.COMPLETED
    assert transaction.last_error is None
    # verify-a-complete receipt recorded at the A generation.
    receipts = [
        item for item in transaction.verifications
        if item.check_id == "verify-a-complete"
        and item.phase is RotationPhase.VERIFY_A
    ]
    assert len(receipts) == 1
    assert receipts[0].status is VerificationStatus.SUCCESS
    assert receipts[0].detail_code == "stable-a-verified"
    assert receipts[0].credential_generation == A_GENERATION
    # Lockout restored to the recorded pre-rotation value.
    assert transaction.lockout.restore_required is False
    assert transaction.lockout.restoration is LockoutChangeState.EFFECT_OBSERVED
    assert transaction.lockout.latest_ignore_lockout_failure_attempts is False
    # Breeder provenance removed; password unchanged; unrelated preserved.
    assert patch.patch_calls == 1
    assert breeder.snapshot.get("password") == A_NEW
    assert breeder.snapshot.get("unrelated") == SecretValue(b"preserve-me")
    assert breeder.snapshot.annotation(PROVENANCE_TRANSACTION) is None
    assert breeder.snapshot.annotation(PROVENANCE_GENERATION) is None
    assert breeder.snapshot.annotation(PROVENANCE_STAGE) is None
    assert breeder.snapshot.annotation("example.org/keep") == "unchanged"
    # Durable completed history recorded.
    assert len(result.persisted.state.completed_requests) == 1
    completed = result.persisted.state.completed_requests[0]
    assert completed.transaction_id == TX_ID
    assert completed.outcome.value == "succeeded"
    # No propagation write, no restart dispatch, no admin password mutation.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


def test_converged_final_state_no_provenance_completes() -> None:
    # The breeder already carries no provenance (the documented clean
    # terminal form): recognized and left alone.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets(
        breeder_provenance=False,
    ).values())
    breeder = FakeBreederSecretClient(_breeder(with_provenance=False))
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    assert patch.patch_calls == 0
    assert breeder.snapshot.get("password") == A_NEW


# ---------------------------------------------------------------------------
# 2. Missing/invalid switch-to-a-complete receipt
# ---------------------------------------------------------------------------


def test_missing_switch_to_a_receipt_prevents_verification() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, include_switch_to_a_receipt=False,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_MISSING
    _assert_no_side_effects(
        store, secret_client, workload_client,
        FakeBreederSecretClient(_breeder()), None,
        phase=RotationPhase.VERIFY_A,
    )


def test_wrong_generation_switch_to_a_receipt_prevents_verification() -> None:
    wave = _complete_to_a()
    base = _transaction(to_a=wave, include_switch_to_a_receipt=False)
    tx = replace(base, verifications=(
        VerificationResult(
            "switch-to-a-complete", RotationPhase.SWITCH_TO_A,
            VerificationStatus.SUCCESS, NOW, "propagated-and-restarted",
            None, B_GENERATION,
        ),
        *base.verifications,
    ))
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_INVALID
    _assert_no_side_effects(
        store, secret_client, workload_client,
        FakeBreederSecretClient(_breeder()), None,
        phase=RotationPhase.VERIFY_A,
    )


def test_wrong_phase_switch_to_a_receipt_treated_missing() -> None:
    wave = _complete_to_a()
    base = _transaction(to_a=wave, include_switch_to_a_receipt=False)
    tx = replace(base, verifications=(
        VerificationResult(
            "switch-to-a-complete", RotationPhase.SWITCH_TO_B,
            VerificationStatus.SUCCESS, NOW, "propagated-and-restarted",
            None, A_GENERATION,
        ),
        *base.verifications,
    ))
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_MISSING


def test_missing_rotate_a_receipt_prevents_verification() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, include_rotate_a_receipt=False,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is VerifyAErrorCode.SWITCH_TO_A_PREREQUISITE_MISSING


def test_missing_prepare_b_evidence_prevents_verification() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, include_prepare_b_receipts=False,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is VerifyAErrorCode.PREPARE_B_PREREQUISITE_MISSING


def test_predecessor_phase_rejected() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, phase=RotationPhase.SWITCH_TO_A,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is VerifyAErrorCode.UNSUPPORTED_PHASE
    _assert_no_side_effects(
        store, secret_client, workload_client,
        FakeBreederSecretClient(_breeder()), None,
        phase=RotationPhase.SWITCH_TO_A,
    )


def test_no_transaction_rejected() -> None:
    empty = PersistedState(
        PersistentState(
            schema_version=2, environment=ENVIRONMENT,
            current_transaction=None, completed_requests=(),
        ),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )
    store = MemoryStateStore(empty)
    with pytest.raises(VerifyAError) as raised:
        _run(store, FakeCredentialSecretClient(*_secrets().values()),
             _FakeWorkloadClient(_workloads()), Ownership())
    assert raised.value.kind is VerifyAErrorCode.NO_TRANSACTION


# ---------------------------------------------------------------------------
# 3. Authoritative A verification failures
# ---------------------------------------------------------------------------


def test_passwordsafe_differs_from_breeder_no_completion() -> None:
    # PasswordSafe A drifted to the old-A generation: the fresh reconciliation
    # is not A3, so nothing is cleaned and nothing completes.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    drifted = _passwordsafe()
    drifted.add(PasswordSafeCredential(10, 101, "admin", 7, A_OLD))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone()
    ks.add_user(KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True,
        "admin-project", True,
    ), A_OLD)
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             passwordsafe_client=drifted, breeder=breeder, keystone_client=ks)
    assert raised.value.kind is VerifyAErrorCode.A_STATE_INVALID
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_keystone_new_a_auth_fails_no_completion() -> None:
    # Keystone rejects the new-A credential: the A3 boundary is not
    # established; no cleanup or completion.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    ks = _keystone()
    ks.add_user(KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True,
        "admin-project", True,
    ), SecretValue(b"Synthetic-ANew-4I-Other"))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, keystone_client=ks)
    assert raised.value.kind is VerifyAErrorCode.A_STATE_INVALID
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_a_state_indeterminate_no_completion() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    ks = _keystone()
    ks.next_auth_indeterminate = KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, keystone_client=ks)
    assert raised.value.kind is VerifyAErrorCode.A_STATE_INDETERMINATE
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


# ---------------------------------------------------------------------------
# 4-11. Location / topology verification failures
# ---------------------------------------------------------------------------


def test_active_location_still_b_no_completion() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets(neutron="breakglass").values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_active_location_unknown_credential_no_completion() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    tampered = _secrets()
    tampered["neutron-keystone-admin"] = replace(
        tampered["neutron-keystone-admin"],
        data=(
            SecretField("OS_USERNAME", SecretValue(b"someuser")),
            SecretField("OS_PASSWORD", SecretValue(b"some-unrecognized-password")),
        ),
    )
    secret_client = FakeCredentialSecretClient(*tampered.values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_active_location_old_a_no_completion() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    tampered = _secrets()
    tampered["neutron-keystone-admin"] = snapshot("neutron-keystone-admin", {
        "OS_USERNAME": b"admin", "OS_PASSWORD": A_OLD.reveal(),
    })
    secret_client = FakeCredentialSecretClient(*tampered.values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_fixed_admin_location_wrong_generation_no_completion() -> None:
    # A fixed identity: admin propagated location holding an old admin
    # password (wrong generation) fails the final stable-A verification.
    secrets = _fixed_admin_secrets(admin_fixed="admin", active="admin")
    wave = _fixed_admin_complete_to_a(secrets)
    store = MemoryStateStore(_state_for(
        _transaction(to_a=wave),
    ))
    tampered = dict(secrets)
    tampered["admin-fixed-consumer"] = snapshot("admin-fixed-consumer", {
        "OS_USERNAME": b"admin", "OS_PASSWORD": A_OLD.reveal(),
    })
    secret_client = FakeCredentialSecretClient(*tampered.values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_workloads("active-api"))
    with pytest.raises(VerifyAError) as raised:
        _run(
            store, secret_client, workload_client, Ownership(),
            contract_text=_fixed_admin_contract_text(), breeder=breeder,
        )
    assert raised.value.kind is VerifyAErrorCode.LOCATION_UNVERIFIED
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    assert transaction.status is not TransactionStatus.COMPLETED


def test_missing_expected_location_no_completion() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    missing = {k: v for k, v in _secrets().items() if k != "neutron-keystone-admin"}
    secret_client = FakeCredentialSecretClient(*missing.values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind in (
        VerifyAErrorCode.LOCATION_UNVERIFIED,
        VerifyAErrorCode.TOPOLOGY_UNVERIFIED,
    )
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_unexpected_administrative_location_no_completion() -> None:
    # An uncontracted Secret carrying an administrative credential
    # (OS_USERNAME=admin) is unexpected topology: it fails closed even though
    # every contracted location looks correct.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    extra = {k: v for k, v in _secrets().items()
             if k not in ("admin-fixed-consumer", "active-consumer")}
    extra["rogue-admin-creds"] = snapshot("rogue-admin-creds", {
        "OS_USERNAME": b"admin", "OS_PASSWORD": A_NEW.reveal(),
    })
    secret_client = FakeCredentialSecretClient(*extra.values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.TOPOLOGY_UNVERIFIED
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_malformed_representation_no_completion() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    tampered = _secrets()
    tampered["octavia-etc"] = snapshot("octavia-etc", {"octavia.conf": b"not ini at all"})
    secret_client = FakeCredentialSecretClient(*tampered.values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.LOCATION_UNVERIFIED
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


# ---------------------------------------------------------------------------
# 12-14. Restart / workload verification failures
# ---------------------------------------------------------------------------


def test_restart_debt_incomplete_no_completion() -> None:
    wave = _complete_to_a()
    partial = replace(wave, runtime_actions=(
        RuntimeActionProgress("deployment_octavia-api", RuntimeActionState.COMPLETE),
        RuntimeActionProgress("deployment_octavia-housekeeping", RuntimeActionState.PENDING),
        RuntimeActionProgress(
            "daemonset_neutron-netns-cleanup-cron-default", RuntimeActionState.COMPLETE,
        ),
        RuntimeActionProgress("daemonset_octavia-worker-default", RuntimeActionState.COMPLETE),
    ))
    store = MemoryStateStore(_state_for(_transaction(to_a=partial)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(partial))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.RESTART_INCOMPLETE
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_workload_rollout_incomplete_no_completion() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    workloads = _rolled_out_workloads(wave)
    # One workload's rollout regressed: not converged for the marker.
    workloads["octavia-api"].updated_replicas = 0
    workloads["octavia-api"].ready_replicas = 0
    workloads["octavia-api"].unavailable_replicas = 1
    workloads["octavia-api"].rollout_status = RolloutStatus.PENDING
    workload_client = _FakeWorkloadClient(workloads)
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.WORKLOAD_UNHEALTHY
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_workload_missing_marker_no_completion() -> None:
    # The durable progress says COMPLETE but the observed workload has no
    # restart marker: the fresh observation wins and blocks completion.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    workloads = _rolled_out_workloads(wave)
    workloads["octavia-api"].restart_requested = None
    workload_client = _FakeWorkloadClient(workloads)
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.WORKLOAD_UNHEALTHY
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


def test_stale_runtime_action_no_completion() -> None:
    wave = _complete_to_a()
    tampered = replace(wave, runtime_actions=(
        *wave.runtime_actions,
        RuntimeActionProgress("deployment_unknown-workload", RuntimeActionState.COMPLETE),
    ))
    store = MemoryStateStore(_state_for(_transaction(to_a=tampered)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(tampered))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(), breeder=breeder)
    assert raised.value.kind is VerifyAErrorCode.CONTRACT_DRIFT
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, None,
        phase=RotationPhase.VERIFY_A,
    )


# ---------------------------------------------------------------------------
# 15-17. Lockout restoration
# ---------------------------------------------------------------------------


def test_lockout_suppressed_is_restored() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=True)

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch, keystone_client=ks,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    assert ks.lockout_update_calls == [("admin-user", False)]
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.lockout.restore_required is False
    assert transaction.lockout.restoration is LockoutChangeState.EFFECT_OBSERVED


def test_lockout_already_restored_no_mutation() -> None:
    # Resume after a crash between the lockout restoration dispatch and the
    # durable record: Keystone already shows the restored policy; no second
    # mutation occurs and completion proceeds.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, lockout_restored=True,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=False)

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch, keystone_client=ks,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    assert ks.lockout_update_calls == []


def test_lockout_restoration_failure_prevents_completion() -> None:
    # The restoration dispatch definitively fails: no provenance cleanup, no
    # completion.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=True)
    from admin_password_rotation.external_http import ExternalErrorCode
    ks.next_mutation_error = ExternalErrorCode.AUTHORIZATION_FAILURE

    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, breeder_patch=patch, keystone_client=ks)
    assert raised.value.kind is VerifyAErrorCode.LOCKOUT_MUTATION_FAILED
    # No provenance cleanup and no completion.
    assert patch.patch_calls == 0
    assert BreederProvenance_matches(breeder.snapshot)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    assert transaction.status is not TransactionStatus.COMPLETED


def test_lockout_dispatch_unresolved_preserves_intent_bookkeeping() -> None:
    # Regression: the DISPATCH_UNRESOLVED update must build from the
    # immediately preceding durable record, not from the stale pre-intent
    # local.  The INTENT_PERSISTED state records
    # ``latest_ignore_lockout_failure_attempts`` from a fresh observation;
    # the DISPATCH_UNRESOLVED transition must carry that bookkeeping forward
    # (only ``restoration`` changes), not silently discard it.
    #
    # Setup: the durable record says the lockout was last observed at the
    # restored value (False) with no pending restoration, but the fresh
    # observation shows it is now suppressed (True).  The INTENT_PERSISTED
    # update corrects the bookkeeping to the observed True; the
    # DISPATCH_UNRESOLVED update must preserve that, not revert to the
    # stale False.
    wave = _complete_to_a()
    transaction = _transaction(to_a=wave)
    transaction = replace(
        transaction,
        lockout=LockoutState(
            initial_ignore_lockout_failure_attempts=False,
            suppression=LockoutChangeState.EFFECT_OBSERVED,
            restoration=LockoutChangeState.NOT_INTENDED,
            latest_ignore_lockout_failure_attempts=False,  # stale: says restored
            restore_required=True,
        ),
    )
    store = MemoryStateStore(_state_for(transaction))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=True)  # observed value: True (suppressed)
    from admin_password_rotation.external_http import ExternalErrorCode
    ks.next_mutation_error = ExternalErrorCode.AUTHORIZATION_FAILURE

    # Record every state the store durably accepted, in order, so the
    # INTENT_PERSISTED -> DISPATCH_UNRESOLVED transition can be inspected.
    store.record_updates = True

    with pytest.raises(VerifyAError):
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, breeder_patch=patch, keystone_client=ks)

    # The transition is INTENT_PERSISTED -> DISPATCH_UNRESOLVED ->
    # INTENT_PERSISTED (retryable).  Locate the single DISPATCH_UNRESOLVED
    # durable record.
    dispatched = [
        s for s in store.recorded_states
        if s.current_transaction is not None
        and s.current_transaction.lockout.restoration
        is LockoutChangeState.DISPATCH_UNRESOLVED
    ]
    assert len(dispatched) == 1
    dispatched_state = dispatched[0]
    assert dispatched_state.current_transaction is not None
    dispatched_lockout = dispatched_state.current_transaction.lockout

    # The observed (suppressed) value was recorded by INTENT_PERSISTED and
    # must survive the transition to DISPATCH_UNRESOLVED.  With the stale
    # local the value would regress to the initial False.
    assert dispatched_lockout.latest_ignore_lockout_failure_attempts is True
    assert dispatched_lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
    assert dispatched_lockout.restore_required is True


def test_lockout_ambiguous_unresolvable_prevents_completion() -> None:
    # The restoration dispatch is ambiguous and the fresh read-back does not
    # show the restored value: fail closed.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=True)
    ks.ambiguous_next_lockout_update_apply = False

    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, breeder_patch=patch, keystone_client=ks)
    assert raised.value.kind is VerifyAErrorCode.LOCKOUT_UNRESOLVED
    assert patch.patch_calls == 0
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.status is not TransactionStatus.COMPLETED


def BreederProvenance_matches(snapshot: SecretSnapshot) -> bool:
    return (
        snapshot.annotation(PROVENANCE_TRANSACTION) == str(TX_ID)
        and snapshot.annotation(PROVENANCE_GENERATION) == A_GENERATION.value
    )


# ---------------------------------------------------------------------------
# 18-22. Breeder provenance cleanup
# ---------------------------------------------------------------------------


def test_provenance_cleaned_password_unchanged() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    assert patch.patch_calls == 1
    assert breeder.snapshot.get("password") == A_NEW
    assert not BreederProvenance_matches(breeder.snapshot)


def test_foreign_provenance_fails_closed() -> None:
    # The breeder carries provenance belonging to another transaction: never
    # delete it.
    other_tx = UUID("99999999-9999-4999-8999-999999999999")
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    foreign = _breeder()
    annotations = tuple(
        item for item in foreign.annotations
        if item.key != PROVENANCE_TRANSACTION
    ) + (SecretAnnotation(PROVENANCE_TRANSACTION, str(other_tx)),)
    foreign = replace(foreign, annotations=annotations)
    secret_client = FakeCredentialSecretClient(*_secrets(
        breeder_provenance=False,
    ).values())
    breeder = FakeBreederSecretClient(foreign)
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, breeder_patch=patch)
    assert raised.value.kind is VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH
    assert patch.patch_calls == 0
    # The foreign provenance is untouched.
    assert breeder.snapshot.annotation(PROVENANCE_TRANSACTION) == str(other_tx)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.status is not TransactionStatus.COMPLETED


def test_concurrent_breeder_change_fails_closed() -> None:
    # The breeder changed after the A3 observation (resourceVersion bumped
    # out of band): the conditional patch is rejected and cleanup fails
    # closed.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)

    def bump(patch: FakeBreederPatch) -> None:
        del patch
        breeder.snapshot = replace(
            breeder.snapshot,
            resource_version=str(int(breeder.snapshot.resource_version) + 1),
        )
    patch.before_patch = bump
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, breeder_patch=patch)
    assert raised.value.kind is VerifyAErrorCode.BREEDER_CONFLICT
    # The provenance was not removed.
    assert BreederProvenance_matches(breeder.snapshot)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.status is not TransactionStatus.COMPLETED


def test_partial_provenance_malformed_fails_closed() -> None:
    # A partial provenance set (only the stage annotation) is malformed and
    # must not be partially deleted.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    partial = _breeder(with_provenance=False)
    partial = replace(partial, annotations=(
        SecretAnnotation(PROVENANCE_STAGE, "pending-keystone"),
    ))
    secret_client = FakeCredentialSecretClient(*_secrets(
        breeder_provenance=False,
    ).values())
    breeder = FakeBreederSecretClient(partial)
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, breeder_patch=patch)
    assert raised.value.kind is VerifyAErrorCode.BREEDER_PROVENANCE_MISMATCH
    assert patch.patch_calls == 0
    assert breeder.snapshot.annotation(PROVENANCE_STAGE) == "pending-keystone"


def test_resume_after_lockout_restoration_continues_to_provenance_cleanup() -> None:
    # Crash after lockout restoration, before provenance cleanup: the lockout
    # is recognized as restored and the provenance cleanup proceeds.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, lockout_restored=True,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=False)

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch, keystone_client=ks,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    assert ks.lockout_update_calls == []
    assert patch.patch_calls == 1
    assert not BreederProvenance_matches(breeder.snapshot)


def test_resume_after_provenance_cleanup_completes() -> None:
    # Crash after provenance cleanup, before transaction completion: the
    # clean breeder form is recognized, the breeder/A state is re-verified,
    # and completion proceeds without repeating mutations.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, lockout_restored=True,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets(
        breeder_provenance=False,
    ).values())
    breeder = FakeBreederSecretClient(_breeder(with_provenance=False))
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=False)

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch, keystone_client=ks,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    assert patch.patch_calls == 0
    assert ks.lockout_update_calls == []
    assert breeder.snapshot.get("password") == A_NEW


# ---------------------------------------------------------------------------
# 23-26. Ownership / CAS failures
# ---------------------------------------------------------------------------


def test_ownership_loss_before_lockout_prevents_mutation() -> None:
    # Lockout already restored (no lockout writes) and breeder already clean
    # (no patch): the only remaining ownership assertion is the final
    # completion's.  Failing ownership there proves a lost owner cannot
    # complete the transaction; the phase and status are unchanged.
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, lockout_restored=True,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets(
        breeder_provenance=False,
    ).values())
    breeder = FakeBreederSecretClient(_breeder(with_provenance=False))
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=False)
    owner = Ownership(fail=True)
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, owner,
             breeder=breeder, breeder_patch=patch, keystone_client=ks)
    assert raised.value.kind is VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED
    # No lockout mutation, no provenance cleanup, no completion.
    assert ks.lockout_update_calls == []
    assert patch.patch_calls == 0
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    assert transaction.status is not TransactionStatus.COMPLETED


def test_ownership_loss_before_provenance_cleanup_prevents_cleanup() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    ks = _keystone(suppressed=True)

    # Count assertions of a clean run to locate the breeder-cleanup
    # ownership assertion.  In a clean run with lockout suppressed and
    # provenance present the order is: (1) lockout restoration, (2) breeder
    # cleanup, (3) final completion.  Failing assertion (2) proves a lost
    # owner cannot clean the breeder.
    count_owner = Ownership()
    count_breeder = FakeBreederSecretClient(_breeder())
    count_patch = FakeBreederPatch(count_breeder)
    _run(
        MemoryStateStore(_state_for(_transaction(to_a=wave))),
        FakeCredentialSecretClient(*_secrets().values()),
        _FakeWorkloadClient(_rolled_out_workloads(wave)),
        count_owner,
        breeder=count_breeder,
        breeder_patch=count_patch,
    )
    total = count_owner.assertions
    assert total == 3  # lockout + breeder + completion
    # Fail on the 2nd assertion (the breeder cleanup).
    owner = Ownership(fail_after=1)
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, owner,
             breeder=breeder, breeder_patch=patch, keystone_client=ks)
    assert raised.value.kind is VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    assert transaction.status is not TransactionStatus.COMPLETED
    # No provenance cleanup and no completion occurred.
    assert patch.patch_calls == 0
    assert BreederProvenance_matches(breeder.snapshot)


def test_concurrent_state_change_before_completion_cas_failure() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))

    def mutate(store: MemoryStateStore) -> None:
        persisted = store.current
        transaction = persisted.state.current_transaction
        assert transaction is not None
        mutated = replace(
            transaction,
            lockout=replace(transaction.lockout, restore_required=False),
            updated_at=NOW,
        )
        store.current = PersistedState(
            replace(persisted.state, current_transaction=mutated),
            replace(
                persisted.revision,
                resource_version=str(int(persisted.revision.resource_version) + 1),
            ),
        )

    store.before_final_update = mutate
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))
    with pytest.raises(VerifyAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             breeder=breeder, breeder_patch=patch)
    assert raised.value.kind is VerifyAErrorCode.PROGRESS_PERSISTENCE_FAILED
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    assert transaction.status is not TransactionStatus.COMPLETED
    assert not any(
        item.check_id == "verify-a-complete" for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 27-29. Completion evidence / re-run
# ---------------------------------------------------------------------------


def test_successful_completion_writes_verify_a_complete() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    receipts = [
        item for item in transaction.verifications
        if item.check_id == "verify-a-complete"
        and item.phase is RotationPhase.VERIFY_A
    ]
    assert len(receipts) == 1
    assert receipts[0].status is VerificationStatus.SUCCESS
    assert receipts[0].credential_generation == A_GENERATION
    assert receipts[0].detail_code == "stable-a-verified"


def test_successful_completion_terminal_state() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch,
    )

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.STABLE_A
    assert transaction.status is TransactionStatus.COMPLETED
    assert transaction.last_error is None
    assert result.phase is RotationPhase.STABLE_A
    assert result.new_a_generation == A_GENERATION


def test_rerun_after_completion_is_idempotent() -> None:
    wave = _complete_to_a()
    # A transaction already completed in a prior run: terminal STABLE_A state.
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, phase=RotationPhase.STABLE_A,
        status=TransactionStatus.COMPLETED, lockout_restored=True,
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(store, secret_client, workload_client, Ownership())

    assert result.outcome is VerifyAOutcome.ALREADY_COMPLETED
    assert result.completed is True
    assert result.phase is RotationPhase.STABLE_A
    # No machinery ran: no durable update.
    assert store.update_count == 0
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


# ---------------------------------------------------------------------------
# 30-34. Guardrails
# ---------------------------------------------------------------------------


def test_breakglass_not_mutated_deleted_or_disabled() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    keystone_client = _keystone()
    passwordsafe_client = _passwordsafe()
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(
        store, secret_client, workload_client, Ownership(),
        keystone_client=keystone_client, passwordsafe_client=passwordsafe_client,
        breeder=breeder, breeder_patch=patch,
    )

    assert result.outcome is VerifyAOutcome.COMPLETED
    # No breakglass password/lockout mutation (only the admin lockout restore).
    assert keystone_client.password_update_calls == []
    assert keystone_client.lockout_update_calls == [("admin-user", False)]
    assert passwordsafe_client.update_calls == []
    # The B record is unchanged and still authenticates as breakglass.
    record = passwordsafe_client.get_current(
        access=ACCESS, project_id=10, credential_id=202,
        expected_username="breakglass",
    )
    assert record.password == B


def test_no_propagation_mutation() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    _run(store, secret_client, workload_client, Ownership(),
         breeder=breeder, breeder_patch=patch)

    # VERIFY_A never writes a propagated Secret.
    assert secret_client.replace_calls == 0


def test_no_restart_executed_as_repair() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    _run(store, secret_client, workload_client, Ownership(),
         breeder=breeder, breeder_patch=patch)

    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []


def test_no_password_generation_or_admin_mutation() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    keystone_client = _keystone()
    passwordsafe_client = _passwordsafe()
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    _run(store, secret_client, workload_client, Ownership(),
         keystone_client=keystone_client, passwordsafe_client=passwordsafe_client,
         breeder=breeder, breeder_patch=patch)

    assert keystone_client.password_update_calls == []
    assert passwordsafe_client.update_calls == []
    # The breeder password is unchanged (only its annotations were cleaned).
    assert breeder.snapshot.get("password") == A_NEW


def test_no_secrets_in_result_state_or_exceptions() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    breeder = FakeBreederSecretClient(_breeder())
    patch = FakeBreederPatch(breeder)
    workload_client = _FakeWorkloadClient(_rolled_out_workloads(wave))

    result = _run(
        store, secret_client, workload_client, Ownership(),
        breeder=breeder, breeder_patch=patch,
    )

    serialized = serialize_state_json(result.persisted.state)
    assert A_NEW.reveal().decode() not in serialized
    assert B.reveal().decode() not in serialized
    assert A_OLD.reveal().decode() not in serialized
    # No credential value in the result repr/str.
    assert A_NEW.reveal().decode() not in str(result)
    assert B.reveal().decode() not in str(result)
    # The receipt carries only the generation, not the credential.
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    receipt = next(
        item for item in transaction.verifications
        if item.check_id == "verify-a-complete"
    )
    assert receipt.credential_generation == A_GENERATION
    assert A_NEW.reveal().decode() not in str(receipt)
    # The error surface is value-free.
    error_message = VerifyAError(VerifyAErrorCode.A_STATE_INVALID).message
    assert A_NEW.reveal().decode() not in error_message


def test_environment_mismatch_rejected() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    contract = parse_contract(_contract_text())
    inputs = VerifyAInputs(
        request=VerifyARequest(
            environment=EnvironmentIdentity("other-env", "cluster.local"),
            keystone=IDS,
            passwordsafe_project_id=10,
            passwordsafe_a_record_id=101,
            passwordsafe_b_record_id=202,
            execution=EXECUTION,
        ),
        contract=contract,
        passwordsafe_access=ACCESS,
        breeder=FakeBreederSecretClient(_breeder()),
        secret_client=FakeCredentialSecretClient(*_secrets().values()),
        workload_client=cast(WorkloadClient, _FakeWorkloadClient(_workloads())),
    )
    with pytest.raises(VerifyAError) as raised:
        run_verify_a(
            inputs, state_store=store, ownership=Ownership(),
            passwordsafe=_passwordsafe(), keystone=_keystone(), clock=lambda: NOW,
        )
    assert raised.value.kind is VerifyAErrorCode.ENVIRONMENT_MISMATCH


def test_keystone_config_mismatch_rejected() -> None:
    wave = _complete_to_a()
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    contract = parse_contract(_contract_text())
    inputs = VerifyAInputs(
        request=VerifyARequest(
            environment=ENVIRONMENT,
            keystone=ResolvedKeystoneIdentities(
                "admin-user", "breakglass-user", "default-domain",
                "other-project", "default-domain", "admin-role",
            ),
            passwordsafe_project_id=10,
            passwordsafe_a_record_id=101,
            passwordsafe_b_record_id=202,
            execution=EXECUTION,
        ),
        contract=contract,
        passwordsafe_access=ACCESS,
        breeder=FakeBreederSecretClient(_breeder()),
        secret_client=FakeCredentialSecretClient(*_secrets().values()),
        workload_client=cast(WorkloadClient, _FakeWorkloadClient(_workloads())),
    )
    with pytest.raises(VerifyAError) as raised:
        run_verify_a(
            inputs, state_store=store, ownership=Ownership(),
            passwordsafe=_passwordsafe(), keystone=_keystone(), clock=lambda: NOW,
        )
    assert raised.value.kind is VerifyAErrorCode.CONFIGURATION_MISMATCH
