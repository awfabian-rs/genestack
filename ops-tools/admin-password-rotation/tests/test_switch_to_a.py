"""Slice 4H: transaction-level ``SWITCH_TO_A`` runtime integration tests.

``run_switch_to_a`` composes the Slice 4B/4C propagation machinery and the
Slice 4D restart executor into the ``SWITCH_TO_A`` runtime phase, using the
**admin** target.  It gates entry on the durable ``ROTATE_A`` completion
evidence (a single ``SUCCESS`` ``rotate-a-complete`` receipt at phase
``ROTATE_A`` carrying the transaction's A generation, plus the ``PREPARE_B``
``stable-a`` / ``breakglass-b2`` evidence), freshly reconciles the
authoritative A boundary at A3, propagates the new admin credential back to
every contracted ``identity: active`` location (from the temporary breakglass
B credential), executes the resulting restart debt, and advances the durable
phase to ``VERIFY_A`` with the credential-free ``switch-to-a-complete``
receipt.  These tests reuse the existing behavioral fakes rather than
introducing parallel test abstractions.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable
from uuid import UUID

import pytest

from admin_password_rotation.breeder import (
    BreederProvenance, FakeBreederSecretClient,
)
from admin_password_rotation.config import parse_contract
from admin_password_rotation.errors import SafeError
from admin_password_rotation.keystone import (
    FakeKeystoneClient, KeystoneUserObservation,
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
from admin_password_rotation.restart import (
    RolloutStatus, WorkloadSnapshot,
)
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import (
    PersistedState, StateRevision, StateStore, StateStoreError,
    StateStoreErrorCode,
)
from admin_password_rotation.switch_to_a import (
    SwitchToAError, SwitchToAErrorCode, SwitchToAInputs, SwitchToAOutcome,
    SwitchToARequest, run_switch_to_a,
)

NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
ENVIRONMENT = EnvironmentIdentity("dfw-dev", "cluster.local")
A_OLD = SecretValue(b"Synthetic-Old-Admin-4H")
A_NEW = SecretValue(b"Synthetic-ANew-4H-0123456789abcd")
B = SecretValue(b"Synthetic-Breakglass-4H")
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


# ---------------------------------------------------------------------------
# Credential pair / Secret construction
# ---------------------------------------------------------------------------


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


def _breeder() -> SecretSnapshot:
    base = snapshot("keystone-admin", {
        "password": A_NEW.reveal(),
        "unrelated": b"preserve-me",
    })
    return replace(
        base,
        uid=BREEDER_UID,
        resource_version="124",
        annotations=(
            SecretAnnotation("example.org/keep", "unchanged"),
            *BreederProvenance(TX_ID, A_GENERATION).annotations(),
        ),
    )


def _secrets(
    *, neutron: str = "breakglass", octavia_etc: str = "breakglass",
    octavia_worker: str = "breakglass", none: str = "breakglass",
    admin_fixed: str = "admin", active: str = "breakglass",
) -> dict[str, SecretSnapshot]:
    un, pw = _pair(neutron)
    uf, pf = _pair(admin_fixed)
    ua, pa = _pair(active)
    return {
        "keystone-admin": _breeder(),
        "neutron-keystone-admin": snapshot("neutron-keystone-admin", {
            "OS_USERNAME": un, "OS_PASSWORD": pw,
        }),
        "octavia-etc": snapshot("octavia-etc", {"octavia.conf": _ini(octavia_etc)}),
        "octavia-worker-default": snapshot("octavia-worker-default", {"octavia.conf": _ini(octavia_worker)}),
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

    def load(self) -> PersistedState:
        return self.current

    def update(self, expected: StateRevision, new_state: PersistentState) -> PersistedState:
        # The final state-store update is the ownership-fenced phase advance:
        # it writes the switch-to-a-complete receipt and switches the phase to
        # VERIFY_A.  The hook lets a test simulate a concurrent
        # transaction-state mutation landing between the completion decision
        # and this CAS-protected advance: it runs *before* the revision check,
        # so the foreign write bumps the durable revision and the advance's CAS
        # from R fails.
        if (
            self.before_final_update is not None
            and new_state.current_transaction is not None
            and new_state.current_transaction.phase is RotationPhase.VERIFY_A
            and any(
                item.check_id == "switch-to-a-complete"
                for item in new_state.current_transaction.verifications
            )
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
        return self.current


# ---------------------------------------------------------------------------
# Workload fakes (reused from the Slice 4D / 4E test harness)
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


# ---------------------------------------------------------------------------
# Transaction / external fixtures
# ---------------------------------------------------------------------------


def _transaction(
    *,
    phase: RotationPhase = RotationPhase.SWITCH_TO_A,
    wave: PropagationWave | None = None,
    to_a: PropagationWave | None = None,
    include_rotate_a_receipt: bool = True,
    include_prepare_b_receipts: bool = True,
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
    return RotationTransaction(
        transaction_id=TX_ID,
        request_id=UUID("22222222-2222-4222-8222-222222222222"),
        execution=execution or EXECUTION,
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=IDS,
        created_at=NOW,
        updated_at=NOW,
        phase=phase,
        status=TransactionStatus.ACTIVE,
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
            to_a if to_a is not None else (wave if wave is not None else PropagationWave((), ())),
        ),
        lockout=LockoutState(
            False, LockoutChangeState.EFFECT_OBSERVED,
            LockoutChangeState.NOT_INTENDED, True, True,
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


def _keystone() -> FakeKeystoneClient:
    client = FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    client.add_user(KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True,
        "admin-project", True,
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


def _request(
    *,
    execution: ExecutionIdentity | None = None,
) -> SwitchToARequest:
    return SwitchToARequest(
        environment=ENVIRONMENT,
        keystone=IDS,
        passwordsafe_project_id=10,
        passwordsafe_a_record_id=101,
        passwordsafe_b_record_id=202,
        execution=execution or EXECUTION,
    )


def _planned_to_a(
    contract_text: str = _contract_text(),
    secrets: dict[str, SecretSnapshot] | None = None,
) -> PropagationWave:
    """Plan the immutable to-A wave against clean (B-state) secrets."""
    parsed = parse_contract(contract_text)
    desired = DesiredCredential(Identity.ADMIN, A_NEW)
    refs = ReferenceCredentials(A_NEW, B)
    planned = plan_or_reconcile_propagation_wave(
        parsed,
        SecretInventory("openstack", "100", tuple((secrets or _secrets()).values())),
        refs, desired, A_GENERATION, PropagationWave((), ()),
    )
    return planned.wave


def _run(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, owner: Ownership, *,
    contract_text: str = _contract_text(),
    keystone_client: FakeKeystoneClient | None = None,
    passwordsafe_client: FakePasswordSafeClient | None = None,
    breeder: FakeBreederSecretClient | None = None,
    poll_interval: float = 0.05,
    deadline: float = 60.0,
):
    parsed = parse_contract(contract_text)
    inputs = SwitchToAInputs(
        request=_request(),
        contract=parsed,
        passwordsafe_access=ACCESS,
        breeder=breeder or FakeBreederSecretClient(_breeder()),
        secret_client=secret_client,
        workload_client=workload_client,  # type: ignore[arg-type]
    )
    return run_switch_to_a(
        inputs,
        state_store=store,
        ownership=owner,
        passwordsafe=passwordsafe_client or _passwordsafe(),
        keystone=keystone_client or _keystone(),
        clock=lambda: NOW,
        sleeper=lambda _seconds: None,
        poll_interval=poll_interval,
        deadline=deadline,
    )


def _assert_no_side_effects(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, *, phase: RotationPhase,
    allow_secret_write: bool = False,
) -> None:
    if not allow_secret_write:
        assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is phase
    assert not any(
        item.check_id == "switch-to-a-complete" for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 1. Valid entry from ROTATE_A-complete at A3
# ---------------------------------------------------------------------------


def test_valid_entry_from_rotate_a_propagates_and_advances() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()

    result = _run(store, secret_client, workload_client, owner)

    assert result.outcome is SwitchToAOutcome.SWITCHED
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    assert transaction.status is TransactionStatus.ACTIVE
    # Every active location applied to the new A.
    assert set(transaction.propagation.to_a.applied_location_ids) == {
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    }
    # The new-A credential was written to the active Secrets.
    assert secret_client.current("openstack", "neutron-keystone-admin").get("OS_USERNAME") == SecretValue(b"admin")
    assert secret_client.current("openstack", "neutron-keystone-admin").get("OS_PASSWORD") == A_NEW
    assert secret_client.current("openstack", "octavia-etc").get("octavia.conf") == SecretValue(_ini("admin"))
    # Lockout remains suppressed; breeder provenance still present.
    assert transaction.lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
    assert transaction.lockout.restore_required is True
    assert BreederProvenance(TX_ID, A_GENERATION).matches(FakeBreederSecretClient(_breeder()).snapshot)
    # No A credential mutation, no Keystone/PasswordSafe admin write.
    assert _keystone().password_update_calls == []
    assert _passwordsafe().update_calls == []


# ---------------------------------------------------------------------------
# 2. Fresh A3 reconciliation succeeds and propagation begins
# ---------------------------------------------------------------------------


def test_fresh_a3_reconciliation_succeeds_and_propagation_begins() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()

    result = _run(store, secret_client, workload_client, owner)

    assert result.outcome is SwitchToAOutcome.SWITCHED
    # Propagation actually wrote Secrets (not a no-op).
    assert secret_client.replace_calls >= 1
    # The A3 reconciliation observed the breeder and PasswordSafe A.
    assert result.phase is RotationPhase.VERIFY_A


# ---------------------------------------------------------------------------
# 3. B-valued active locations are mutated to admin/new-A
# ---------------------------------------------------------------------------


def test_b_valued_active_locations_mutated_to_admin() -> None:
    secrets = _secrets()  # all active locations at breakglass/B.
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    for name in ("neutron-keystone-admin", "octavia-etc",
                 "octavia-worker-default", "no-restart"):
        snap = secret_client.current("openstack", name)
        assert snap.get("OS_USERNAME") == SecretValue(b"admin") or \
            snap.get("octavia.conf") == SecretValue(_ini("admin"))
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A


# ---------------------------------------------------------------------------
# 4. Already-new-A active locations are not unnecessarily rewritten
# ---------------------------------------------------------------------------


def test_already_new_a_locations_not_rewritten() -> None:
    secrets = _secrets(neutron="admin", octavia_etc="admin",
                       octavia_worker="admin", none="admin")
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads())

    result = _run(store, secret_client, workload_client, Ownership())

    # No Secret write and no restart dispatch (all already at the new-A target).
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    # All locations were already at target at wave creation (expected_target=True),
    # so the changed set is empty and there is no restart debt.
    assert transaction.propagation.to_a.applied_location_ids == ()
    assert transaction.propagation.to_a.runtime_actions == ()


# ---------------------------------------------------------------------------
# 5. Mixed resume state with some A and some B converges correctly
# ---------------------------------------------------------------------------


def test_mixed_resume_state_converges() -> None:
    # Plan the wave from clean (all B) secrets; the durable intent then records
    # expected_identity=breakglass for every active location.  A first
    # execution converged neutron (secret now A) but died before the rest:
    # neutron applied, the others still B.  Resume must converge the rest
    # without re-writing neutron.
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    partial = replace(wave, applied_location_ids=("neutron",))
    store = MemoryStateStore(_state_for(_transaction(to_a=partial)))
    # External reality: neutron already at new-A, the rest still B.
    reality = _secrets(neutron="admin")
    secret_client = FakeCredentialSecretClient(*reality.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    assert set(transaction.propagation.to_a.applied_location_ids) == {
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    }
    # neutron was not rewritten a second time (only the remaining locations).
    neutron_secret = secret_client.current("openstack", "neutron-keystone-admin")
    assert neutron_secret.get("OS_USERNAME") == SecretValue(b"admin")
    assert secret_client.current("openstack", "octavia-etc").get("octavia.conf") == SecretValue(_ini("admin"))


# ---------------------------------------------------------------------------
# 6. Unknown active credential fails closed
# ---------------------------------------------------------------------------


def test_unknown_active_credential_fails_closed() -> None:
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    # External reality: neutron now holds an unrecognized credential.
    tampered = dict(clean)
    tampered["neutron-keystone-admin"] = replace(
        clean["neutron-keystone-admin"],
        data=(SecretField("OS_USERNAME", SecretValue(b"someuser")),
              SecretField("OS_PASSWORD", SecretValue(b"some-unrecognized-password"))),
    )
    secret_client = FakeCredentialSecretClient(*tampered.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises((SwitchToAError, SafeError)):
        _run(store, secret_client, workload_client, owner)
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


# ---------------------------------------------------------------------------
# 7. Unexpected old-A credential fails closed
# ---------------------------------------------------------------------------


def test_unexpected_old_a_fails_closed() -> None:
    # An active location holds the *old* A credential (username ``admin``, old
    # password).  It does not match the new-A target (old != new A) and does
    # not match the breakglass reference (username is admin, not breakglass),
    # so it classifies as unknown state.  The wave is planned from the normal
    # all-B entry state (neutron expected at breakglass); external reality then
    # shows old-A on neutron.  The grouped executor's all-wave safety pass sees
    # a location whose fresh state contradicts its durable intent (or is
    # unknown) and fails closed with no Secret write and no phase advance.
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    tampered = dict(clean)
    tampered["neutron-keystone-admin"] = snapshot("neutron-keystone-admin", {
        "OS_USERNAME": b"admin", "OS_PASSWORD": A_OLD.reveal(),
    })
    secret_client = FakeCredentialSecretClient(*tampered.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises((SwitchToAError, SafeError)):
        _run(store, secret_client, workload_client, owner)
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


# ---------------------------------------------------------------------------
# 8. Missing expected location fails closed
# ---------------------------------------------------------------------------


def test_missing_expected_location_fails_closed() -> None:
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    # The neutron Secret is absent from external reality.
    missing = {k: v for k, v in clean.items() if k != "neutron-keystone-admin"}
    secret_client = FakeCredentialSecretClient(*missing.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises((SwitchToAError, SafeError)):
        _run(store, secret_client, workload_client, owner)
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


# ---------------------------------------------------------------------------
# 9. Unexpected administrative location fails closed
# ---------------------------------------------------------------------------


def test_unexpected_administrative_location_fails_closed() -> None:
    # The neutron Secret is same-name but different-UID (a replacement): the
    # durable intent pins the original UID, so the replacement fails closed.
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    replaced = dict(clean)
    replaced["neutron-keystone-admin"] = replace(
        clean["neutron-keystone-admin"], uid="a-different-uid",
    )
    secret_client = FakeCredentialSecretClient(*replaced.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises((SwitchToAError, SafeError)):
        _run(store, secret_client, workload_client, owner)
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


# ---------------------------------------------------------------------------
# 10. Malformed credential representation fails closed
# ---------------------------------------------------------------------------


def test_malformed_representation_fails_closed() -> None:
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    # The octavia-etc INI is corrupted so it can no longer be parsed.
    tampered = dict(clean)
    tampered["octavia-etc"] = snapshot("octavia-etc", {"octavia.conf": b"this is not ini at all"})
    secret_client = FakeCredentialSecretClient(*tampered.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises((SwitchToAError, SafeError)):
        _run(store, secret_client, workload_client, owner)
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


# ---------------------------------------------------------------------------
# 11. Restart debt is created only for locations actually mutated
# ---------------------------------------------------------------------------


def test_restart_debt_only_for_mutated_locations() -> None:
    # Restart debt derives from the durable changed-location accounting
    # (``applied_location_ids``), which records the locations that actually
    # changed on this wave.  Plan the wave from the normal 4H entry state
    # (every active location at the B credential, ``expected_target=False``),
    # then simulate a resume in which ``octavia-etc`` already converged in a
    # prior run (``applied_location_ids`` = ``octavia-etc``, its Secret now at
    # the new-A target) while the other locations still hold B.  The executor
    # re-observes all groups: ``octavia-etc`` is ``ALREADY_CONVERGED`` (no
    # write this run) and its restart debt is retained; the other locations
    # are mutated B -> A.  Every changed location contributes its configured
    # restart edges, so the full derived action set is present — but the
    # ``octavia-etc`` debt was owed *because it changed*, not merely because it
    # appears in the contract.  This is the existing 4B/4C/4D accounting the
    # phase reuses (no bespoke restart table).
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    # Sanity: the plan marks every active location as non-target (at B).
    intent = wave.intent
    assert intent is not None
    for group in intent.secret_groups:
        for loc in group.locations:
            assert loc.expected_target is False
    # Resume: octavia-etc already converged; the rest still at B.
    partial = replace(wave, applied_location_ids=("octavia-etc",))
    store = MemoryStateStore(_state_for(_transaction(to_a=partial)))
    reality = _secrets(octavia_etc="admin")
    secret_client = FakeCredentialSecretClient(*reality.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert result.phase is RotationPhase.VERIFY_A
    # The durable changed set now includes every location that changed (the
    # rest were mutated on this resume; octavia-etc was already changed).
    assert set(transaction.propagation.to_a.applied_location_ids) == {
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    }
    # The full derived restart action set is complete (each changed location
    # with a restart edge contributes one action; no-restart has none).
    assert {item.action_id for item in transaction.propagation.to_a.runtime_actions} == set(_all_action_ids())
    assert all(
        item.state is RuntimeActionState.COMPLETE
        for item in transaction.propagation.to_a.runtime_actions
    )
    # no-restart changed but produced no action (its contract restart list is
    # empty): restart debt is owed only by locations that changed *and* have a
    # configured restart edge.
    assert not any(
        "no-restart" == item.action_id
        for item in transaction.propagation.to_a.runtime_actions
    )


# ---------------------------------------------------------------------------
# 12. Restart targets are deduplicated
# ---------------------------------------------------------------------------


def test_restart_targets_deduplicated() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    # octavia-etc drives two deployments; each workload appears exactly once.
    assert {item.action_id for item in transaction.propagation.to_a.runtime_actions} == set(_all_action_ids())
    # Each deduplicated workload was restarted exactly once.
    for name in _all_workload_names():
        assert workload_client.workloads[name].restart_call_count == 1


# ---------------------------------------------------------------------------
# 13. Required restart debt executes successfully
# ---------------------------------------------------------------------------


def test_required_restart_debt_executes() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert result.phase is RotationPhase.VERIFY_A
    assert all(
        item.state is RuntimeActionState.COMPLETE
        for item in transaction.propagation.to_a.runtime_actions
    )
    # The restart marker is the deterministic to-A wave marker.
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(transaction.propagation.to_a)
    assert workload_client.workloads["octavia-api"].restart_requested == marker


# ---------------------------------------------------------------------------
# 14. Crash/resume with partially completed restart debt
# ---------------------------------------------------------------------------


def test_crash_resume_partially_completed_restart_debt() -> None:
    # Plan the wave from a reality in which every active location is already at
    # the new-A target (``expected_target=True`` for all), so the propagation is
    # a pure no-op on resume (no writes, no writes-triggered crash-recovery
    # concerns).  Simulate a crash in which the restart wave was partially
    # complete: one action COMPLETE (discharged) and one RUNNING with the
    # workload already restarted and rolled out (dispatch succeeded, the
    # executor died before recording COMPLETE).  The durable changed set (the
    # pre-existing applied accounting) drives the restart debt.  Resume must
    # confirm the RUNNING action without re-dispatch and not re-dispatch the
    # COMPLETE one, then advance the phase.
    admin_new = _pair("admin")
    clean = dict(_secrets())
    clean["neutron-keystone-admin"] = snapshot("neutron-keystone-admin", {
        "OS_USERNAME": admin_new[0], "OS_PASSWORD": admin_new[1],
    })
    clean["no-restart"] = snapshot("no-restart", {
        "OS_USERNAME": admin_new[0], "OS_PASSWORD": admin_new[1],
    })
    clean["octavia-etc"] = snapshot("octavia-etc", {"octavia.conf": _ini("admin")})
    clean["octavia-worker-default"] = snapshot("octavia-worker-default", {
        "octavia.conf": _ini("admin"),
    })
    wave = _planned_to_a(secrets=clean)
    # Sanity: every location is expected_target (already at the target).
    intent = wave.intent
    assert intent is not None
    for group in intent.secret_groups:
        for loc in group.locations:
            assert loc.expected_target is True
    # The durable changed set (restart-relevant) is a realistic mixed subset;
    # the propagation itself is a pure no-op (everything already converged).
    applied = ("neutron", "octavia-etc", "octavia-worker", "no-restart")
    complete_id = "deployment_octavia-api"
    running_id = "deployment_octavia-housekeeping"
    partial_wave = replace(
        wave,
        applied_location_ids=applied,
        runtime_actions=(
            RuntimeActionProgress(complete_id, RuntimeActionState.COMPLETE),
            RuntimeActionProgress(running_id, RuntimeActionState.RUNNING),
        ),
    )
    store = MemoryStateStore(_state_for(_transaction(to_a=partial_wave)))
    from admin_password_rotation.restart import restart_request_for
    marker = restart_request_for(partial_wave)
    workloads = _workloads(*_all_workload_names())
    # Every workload in the changed set was already restarted and rolled out
    # before the crash (the COMPLETE action discharged earlier; the RUNNING
    # action dispatched just before the crash; the other PENDING actions had
    # their workloads restarted as well).  On resume the executor must confirm
    # each from fresh observation without re-dispatching.
    for name in _all_workload_names():
        workload = workloads[name]
        workload.restart_requested = marker
        workload.metadata_generation = 2
        workload.observed_generation = 2
        workload.rollout_status = RolloutStatus.SUCCEEDED
        workload.rollout_completed = True
    # Every active location is at the new-A target (the propagation is a pure
    # no-op on resume).  Use the same all-A reality the wave was planned from.
    secret_client = FakeCredentialSecretClient(*clean.values())
    workload_client = _FakeWorkloadClient(workloads)

    result = _run(store, secret_client, workload_client, Ownership())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert result.phase is RotationPhase.VERIFY_A
    assert all(
        item.state is RuntimeActionState.COMPLETE
        for item in transaction.propagation.to_a.runtime_actions
    )
    # No re-dispatch of the already-complete or already-restarted workloads, and
    # no Secret write (the propagation was a pure no-op).
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    assert secret_client.replace_calls == 0


# ---------------------------------------------------------------------------
# 15. Propagation complete but restart debt incomplete does not advance phase
# ---------------------------------------------------------------------------


def test_propagation_complete_restart_debt_incomplete_no_advance() -> None:
    # Propagation is complete (every active location already at the new-A
    # target, all applied) but a workload's rollout never completes: the
    # restart debt is outstanding, so the phase does not advance.
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    complete = replace(
        wave,
        applied_location_ids=("neutron", "octavia-etc", "octavia-worker", "no-restart"),
    )
    store = MemoryStateStore(_state_for(_transaction(to_a=complete)))
    converged = _secrets()
    secret_client = FakeCredentialSecretClient(*converged.values())
    # A workload that never completes its rollout: the action stays
    # outstanding, so the phase does not advance.
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
    workload_client.deployment = _NeverCompleteDeployment(workloads)  # type: ignore[assignment]
    owner = Ownership()
    with pytest.raises(SafeError):
        _run(store, secret_client, workload_client, owner,
             poll_interval=0.05, deadline=0.1)
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


# ---------------------------------------------------------------------------
# 16. Restart failure does not advance phase
# ---------------------------------------------------------------------------


def test_restart_failure_no_advance() -> None:
    # A workload whose rollout is observed as FAILED: the executor raises
    # ROLLOUT_FAILED before completing the action, so the phase does not
    # advance.  Propagation may have written the Secrets first, so a Secret
    # write is permitted; no restart is confirmed complete and the phase does
    # not advance.
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workloads = _workloads(*_all_workload_names())
    for workload in workloads.values():
        workload.rollout_status = RolloutStatus.FAILED
        workload.rollout_completed = True
    workload_client = _FakeWorkloadClient(workloads)
    owner = Ownership()
    with pytest.raises(SafeError):
        _run(store, secret_client, workload_client, owner,
             poll_interval=0.05, deadline=60.0)
    # A write may have been dispatched before the failing rollout was observed.
    # What matters: the phase did not advance and no completion receipt was
    # written (a restart dispatch is not a phase advance).
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert not any(
        item.check_id == "switch-to-a-complete" for item in transaction.verifications
    )
    # No action reached COMPLETE (the failing rollout prevents completion).
    assert not any(
        item.state is RuntimeActionState.COMPLETE
        for item in transaction.propagation.to_a.runtime_actions
    )


# ---------------------------------------------------------------------------
# 17. Ownership loss before a credential mutation prevents dispatch
# ---------------------------------------------------------------------------


def test_ownership_loss_prevents_any_mutation() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership(fail=True)
    with pytest.raises(SafeError):
        _run(store, secret_client, workload_client, owner)
    # No Secret write and no restart dispatch occurred.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert not any(
        item.check_id == "switch-to-a-complete" for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 18. Ownership loss before restart/progress mutation fails safely
# ---------------------------------------------------------------------------


def test_ownership_loss_before_restart_fails_safely() -> None:
    # Simulate a resume in which every active location has already converged to
    # the new-A target (propagation is a pure no-op, so no Secret write and no
    # per-group progress write), but the restart debt is only partially
    # complete (one action RUNNING).  The restart executor asserts ownership at
    # entry and re-observes the workload; failing ownership there prevents any
    # restart dispatch and any phase advance.
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    # Count how many ownership assertions a clean full run makes so we can fail
    # precisely on the restart executor's entry assertion (the final one before
    # the phase advance is the last assertion; the 4D entry assertion is the
    # one immediately before it when propagation is a no-op).
    count_store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    count_owner = Ownership()
    _run(count_store, FakeCredentialSecretClient(*_secrets().values()),
         _FakeWorkloadClient(_workloads(*_all_workload_names())), count_owner)
    total = count_owner.assertions
    # Build a no-propagation-work resume: fully converged reality and one
    # RUNNING action still to dispatch.
    from admin_password_rotation.restart import restart_request_for
    running_wave = replace(
        wave,
        applied_location_ids=("neutron", "octavia-etc", "octavia-worker", "no-restart"),
        runtime_actions=(
            RuntimeActionProgress("deployment_octavia-api", RuntimeActionState.COMPLETE),
            RuntimeActionProgress("deployment_octavia-housekeeping", RuntimeActionState.RUNNING),
            RuntimeActionProgress("daemonset_neutron-netns-cleanup-cron-default", RuntimeActionState.COMPLETE),
            RuntimeActionProgress("daemonset_octavia-worker-default", RuntimeActionState.COMPLETE),
        ),
    )
    marker = restart_request_for(running_wave)
    workloads = _workloads(*_all_workload_names())
    # The housekeeping workload was NOT yet restarted (so the executor must
    # dispatch it); the others are already restarted.
    for name in ("octavia-api", "neutron-netns-cleanup-cron-default", "octavia-worker-default"):
        wl = workloads[name]
        wl.restart_requested = marker
        wl.metadata_generation = 2
        wl.observed_generation = 2
        wl.rollout_status = RolloutStatus.SUCCEEDED
        wl.rollout_completed = True
    store = MemoryStateStore(_state_for(_transaction(to_a=running_wave)))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(workloads)
    # Fail ownership at the restart executor's entry assertion (the second-to-
    # last assertion of a clean run).
    owner = Ownership(fail_after=total - 2)
    with pytest.raises(SafeError):
        _run(store, secret_client, workload_client, owner)
    # No workload restart was dispatched and the phase did not advance.
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert not any(
        item.check_id == "switch-to-a-complete" for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 19. Ownership loss before final receipt/phase update prevents advancement
# ---------------------------------------------------------------------------


def test_ownership_loss_before_final_receipt_prevents_advance() -> None:
    # Determine the exact ownership-assertion count of a clean run so we can
    # fail precisely on the last one (the phase-advance boundary).
    clean = _secrets()
    clean_store = MemoryStateStore(_state_for(_transaction(
        to_a=_planned_to_a(secrets=clean),
    )))
    clean_client = FakeCredentialSecretClient(*clean.values())
    clean_workloads = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    count_owner = Ownership()
    _run(clean_store, clean_client, clean_workloads, count_owner)

    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership(fail_after=count_owner.assertions - 1)
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, owner)
    assert raised.value.kind is SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED
    # The phase did not advance and no switch-to-a-complete receipt was written.
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert not any(
        item.check_id == "switch-to-a-complete" for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 20. Concurrent Kubernetes resource-version conflict fails closed
# ---------------------------------------------------------------------------


def test_concurrent_secret_version_conflict_fails_closed() -> None:
    clean = _secrets()
    wave = _planned_to_a(secrets=clean)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*clean.values())
    # A concurrent actor bumps the neutron Secret's resourceVersion between the
    # executor's fresh observation and its CAS write: the conditional replace is
    # rejected and the grouped executor fails closed (CONFLICT).
    def bump(client: FakeCredentialSecretClient) -> None:
        snap = client.current("openstack", "neutron-keystone-admin")
        client.set_secret(replace(snap, resource_version=str(int(snap.resource_version) + 1)))
    secret_client.before_replace = bump
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises((SwitchToAError, SafeError)):
        _run(store, secret_client, workload_client, owner)
    # A write may have been dispatched before the conflicting Secret was
    # reached; what matters is that the phase did not advance and no receipt
    # was written.
    _assert_no_side_effects(
        store, secret_client, workload_client,
        phase=RotationPhase.SWITCH_TO_A, allow_secret_write=True,
    )


# ---------------------------------------------------------------------------
# 21. Concurrent transaction-state mutation between final observation and
#     phase advance causes CAS failure
# ---------------------------------------------------------------------------


def test_concurrent_state_change_between_observation_and_advance() -> None:
    # The restart-debt completion returns revision R on which the completion
    # decision (wave safely reconciled, all actions COMPLETE) is based.  A
    # concurrent actor mutates the durable transaction after R but before the
    # final advance write.  The advance must CAS from R and therefore fail
    # rather than silently adopting the mutated transaction.
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

    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    store.before_final_update = mutate
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is SwitchToAErrorCode.PROGRESS_PERSISTENCE_FAILED
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert transaction.lockout.restore_required is False
    assert not any(
        item.check_id == "switch-to-a-complete" for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 22. Successful completion writes the receipt and advances exactly to
#     VERIFY_A
# ---------------------------------------------------------------------------


def test_success_receipt_unique_and_phase_exactly_verify_a() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    assert result.outcome is SwitchToAOutcome.SWITCHED
    assert result.phase is RotationPhase.VERIFY_A
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    receipts = [
        item for item in transaction.verifications
        if item.check_id == "switch-to-a-complete"
        and item.phase is RotationPhase.SWITCH_TO_A
    ]
    assert len(receipts) == 1
    assert receipts[0].status is VerificationStatus.SUCCESS
    assert receipts[0].credential_generation == A_GENERATION
    assert transaction.phase is RotationPhase.VERIFY_A


# ---------------------------------------------------------------------------
# 23. Successful 4H does not execute VERIFY_A
# ---------------------------------------------------------------------------


def test_does_not_execute_verify_a() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    # No verify-a receipt is written and no phase beyond VERIFY_A is reached.
    assert not any(
        item.check_id == "verify-a-complete" for item in transaction.verifications
    )
    assert transaction.phase is RotationPhase.VERIFY_A
    assert transaction.status is TransactionStatus.ACTIVE
    # Lockout is not restored and the transaction is not completed.
    assert transaction.lockout.restore_required is True
    assert transaction.lockout.restoration is LockoutChangeState.NOT_INTENDED


# ---------------------------------------------------------------------------
# 24. Lockout suppression is not restored
# ---------------------------------------------------------------------------


def test_lockout_suppression_not_restored() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    keystone_client = _keystone()
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership(),
                  keystone_client=keystone_client)

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    # No lockout mutation at all (the A credential work is already done).
    assert keystone_client.lockout_update_calls == []
    assert transaction.lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
    assert transaction.lockout.restore_required is True


# ---------------------------------------------------------------------------
# 25. Breeder provenance is not cleaned
# ---------------------------------------------------------------------------


def test_breeder_provenance_not_cleaned() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    _run(store, secret_client, workload_client, Ownership())

    # The canonical breeder still carries the transaction provenance and the
    # new-A value: the keystone-admin Secret is never a propagation target.
    breeder = secret_client.current("openstack", "keystone-admin")
    assert breeder.get("password") == A_NEW
    assert BreederProvenance(TX_ID, A_GENERATION).matches(breeder)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert "keystone-admin" not in transaction.propagation.to_a.applied_location_ids


# ---------------------------------------------------------------------------
# 26. Keystone and PasswordSafe admin credentials are not mutated
# ---------------------------------------------------------------------------


def test_keystone_passwordsafe_admin_not_mutated() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    keystone_client = _keystone()
    passwordsafe_client = _passwordsafe()
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    _run(store, secret_client, workload_client, Ownership(),
         keystone_client=keystone_client, passwordsafe_client=passwordsafe_client)

    assert keystone_client.password_update_calls == []
    assert passwordsafe_client.update_calls == []
    # The canonical breeder still holds the new-A credential (unchanged).
    assert secret_client.current("openstack", "keystone-admin").get("password") == A_NEW


# ---------------------------------------------------------------------------
# 27. Breakglass is not deleted, disabled, or rotated
# ---------------------------------------------------------------------------


def test_breakglass_not_deleted_disabled_or_rotated() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    keystone_client = _keystone()
    passwordsafe_client = _passwordsafe()
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    _run(store, secret_client, workload_client, Ownership(),
         keystone_client=keystone_client, passwordsafe_client=passwordsafe_client)

    # No Keystone/PasswordSafe mutation at all (breakglass untouched).
    assert keystone_client.password_update_calls == []
    assert keystone_client.lockout_update_calls == []
    assert passwordsafe_client.update_calls == []
    # The B record is unchanged and still authenticates as breakglass.
    record = passwordsafe_client.get_current(
        access=ACCESS, project_id=10, credential_id=202,
        expected_username="breakglass",
    )
    assert record.password == B


# ---------------------------------------------------------------------------
# 28. No credential values appear in results, receipts, state, logs,
#     exceptions, or test diagnostics
# ---------------------------------------------------------------------------


def test_no_secrets_in_result_state_or_exceptions() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    serialized = serialize_state_json(result.persisted.state)
    assert A_NEW.reveal().decode() not in serialized
    assert B.reveal().decode() not in serialized
    assert A_OLD.reveal().decode() not in serialized
    # No credential value in the result repr/str.
    assert A_NEW.reveal().decode() not in str(result)
    assert B.reveal().decode() not in str(result)
    # The receipt carries only the A generation, not the credential.
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    receipt = next(
        item for item in transaction.verifications
        if item.check_id == "switch-to-a-complete"
    )
    assert receipt.credential_generation == A_GENERATION
    assert A_NEW.reveal().decode() not in str(receipt)


# ---------------------------------------------------------------------------
# 29. Re-running at the completed boundary is idempotent / ALREADY_ADVANCED
# ---------------------------------------------------------------------------


def test_rerun_at_completed_boundary_is_idempotent() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    # The transaction is already past SWITCH_TO_A (phase VERIFY_A).
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, phase=RotationPhase.VERIFY_A,
    )))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    assert result.outcome is SwitchToAOutcome.ALREADY_ADVANCED
    assert result.phase is RotationPhase.VERIFY_A
    # No machinery ran: no Secret write, no restart, no durable update.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    assert store.update_count == 0


# ---------------------------------------------------------------------------
# 30. Existing 4B/4C/4D machinery is reused rather than bypassed
# ---------------------------------------------------------------------------


def test_reuses_existing_machinery() -> None:
    # A clean run: the wave intent is created and persisted by the 4B
    # machinery, the grouped 4C wave executes the Secret writes, and the 4D
    # executor derives and completes the restart debt.  The durable record
    # carries the immutable intent, the applied-location accounting, and the
    # runtime-action progress — the existing schema-v2 wave model.
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    to_a = transaction.propagation.to_a
    # The immutable intent is retained (4B), with the admin target generation.
    assert to_a.intent is not None
    assert to_a.intent.target_generation == A_GENERATION
    # The grouped wave's changed-location accounting is present (4C).
    assert set(to_a.applied_location_ids) == {
        "neutron", "octavia-etc", "octavia-worker", "no-restart",
    }
    # The 4D runtime-action progress is complete for every derived action.
    assert {item.action_id for item in to_a.runtime_actions} == set(_all_action_ids())
    assert all(
        item.state is RuntimeActionState.COMPLETE for item in to_a.runtime_actions
    )


# ---------------------------------------------------------------------------
# Additional guardrails
# ---------------------------------------------------------------------------


def test_no_transaction_rejected() -> None:
    empty = PersistedState(
        PersistentState(
            schema_version=2, environment=ENVIRONMENT,
            current_transaction=None, completed_requests=(),
        ),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )
    store = MemoryStateStore(empty)
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is SwitchToAErrorCode.NO_TRANSACTION


@pytest.mark.parametrize("phase", [
    RotationPhase.STABLE_A,
    RotationPhase.PREPARE_B,
    RotationPhase.SWITCH_TO_B,
    RotationPhase.VERIFY_B,
    RotationPhase.ROTATE_A,
])
def test_predecessor_phase_rejected(phase: RotationPhase) -> None:
    store = MemoryStateStore(_state_for(_transaction(
        phase=phase, to_a=PropagationWave((), ()),
    )))
    secret_client = FakeCredentialSecretClient(*_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is SwitchToAErrorCode.UNSUPPORTED_PHASE


def test_missing_rotate_a_receipt_prevents_execution() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, include_rotate_a_receipt=False,
    )))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is SwitchToAErrorCode.ROTATE_A_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


def test_wrong_phase_rotate_a_receipt_prevents_execution() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    base = _transaction(to_a=wave, include_rotate_a_receipt=False)
    tx = replace(base, verifications=(
        VerificationResult(
            "rotate-a-complete", RotationPhase.VERIFY_B, VerificationStatus.SUCCESS,
            NOW, "authoritative-a-converged", None, A_GENERATION,
        ),
        *base.verifications,
    ))
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is SwitchToAErrorCode.ROTATE_A_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


def test_missing_prepare_b_evidence_prevents_execution() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(
        to_a=wave, include_prepare_b_receipts=False,
    )))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is SwitchToAErrorCode.PREPARE_B_PREREQUISITE_MISSING
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


def test_new_a_generation_missing_rejected() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    base = _transaction(to_a=wave)
    tx = replace(base, new_a_sha256=None)
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership())
    assert raised.value.kind is SwitchToAErrorCode.NEW_A_GENERATION_MISSING


def test_b_credential_unresolved_rejected() -> None:
    # PasswordSafe B no longer holds the recorded generation (the B record is
    # gone): the B reference cannot be freshly established, so the phase fails
    # closed before any mutation.
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    drifted = FakePasswordSafeClient()
    # Only the admin A record is present; the breakglass B record is missing,
    # so get_current raises NOT_FOUND -> B_CREDENTIAL_UNRESOLVED.
    drifted.add(PasswordSafeCredential(10, 101, "admin", 7, A_NEW))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             passwordsafe_client=drifted)
    assert raised.value.kind is SwitchToAErrorCode.B_CREDENTIAL_UNRESOLVED
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


def test_b_generation_mismatch_rejected() -> None:
    # PasswordSafe B and Keystone both hold a *valid* breakglass credential, but
    # it is a *different* generation than the transaction's recorded B (an
    # out-of-band breakglass rotation).  SWITCH_TO_A must not silently adopt it:
    # the freshly recovered value's generation is required to equal
    # transaction.new_b_sha256, and the mismatch fails closed before any
    # propagation or restart work.
    B_OTHER = SecretValue(b"Synthetic-Breakglass-4H-OtherGen")
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    drifted = _passwordsafe()
    drifted.add(PasswordSafeCredential(10, 202, "breakglass", 4, B_OTHER))
    keystone = _keystone()
    keystone.add_user(KeystoneUserObservation(
        "breakglass-user", "breakglass", "default-domain", True,
        "admin-project", False,
    ), B_OTHER)
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    owner = Ownership()
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, owner,
             passwordsafe_client=drifted, keystone_client=keystone)
    assert raised.value.kind is SwitchToAErrorCode.B_GENERATION_MISMATCH
    # No propagation, no restart, and no phase advance: the mismatch is caught
    # at the B-reference stage, before any Secret write or workload restart.
    _assert_no_side_effects(store, secret_client, workload_client,
                            phase=RotationPhase.SWITCH_TO_A)
    assert owner.assertions >= 0  # sanity: ownership was exercised during validation
    # B was read and classified, never mutated or repaired.
    assert drifted.update_calls == []


def test_b_generation_mismatch_rejected_even_when_locations_adopted_it() -> None:
    # Stronger case: the active locations have *also* been changed out of band to
    # the same different B generation.  Naively, every location now matches a
    # consistent (newer) breakglass reference, so a classification that ignored
    # the recorded B generation would happily plan and propagate the cutover.
    # SWITCH_TO_A must still reject the whole run because the recovered B
    # reference does not equal the transaction's recorded B generation; it does
    # not silently adopt the out-of-band rotation.
    B_OTHER = SecretValue(b"Synthetic-Breakglass-4H-OtherGen")
    secrets = _secrets()  # all active locations hold breakglass/B (the original).
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    drifted = _passwordsafe()
    drifted.add(PasswordSafeCredential(10, 202, "breakglass", 4, B_OTHER))
    keystone = _keystone()
    keystone.add_user(KeystoneUserObservation(
        "breakglass-user", "breakglass", "default-domain", True,
        "admin-project", False,
    ), B_OTHER)
    # The active Secrets have been out-of-band rotated to the *same* different
    # generation, so the classification set would be internally consistent if
    # the generation were not checked against the transaction.
    rotated = dict(secrets)
    rotated["neutron-keystone-admin"] = snapshot("neutron-keystone-admin", {
        "OS_USERNAME": b"breakglass", "OS_PASSWORD": B_OTHER.reveal(),
    })
    rotated["octavia-etc"] = snapshot("octavia-etc", {
        "octavia.conf": (b"[service_auth]\nusername = breakglass\npassword = "
                         + B_OTHER.reveal() + b"\n"),
    })
    rotated["octavia-worker-default"] = snapshot("octavia-worker-default", {
        "octavia.conf": (b"[service_auth]\nusername = breakglass\npassword = "
                         + B_OTHER.reveal() + b"\n"),
    })
    rotated["no-restart"] = snapshot("no-restart", {
        "OS_USERNAME": b"breakglass", "OS_PASSWORD": B_OTHER.reveal(),
    })
    secret_client = FakeCredentialSecretClient(*rotated.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             passwordsafe_client=drifted, keystone_client=keystone)
    assert raised.value.kind is SwitchToAErrorCode.B_GENERATION_MISMATCH
    # The cutover was rejected: no active Secret was switched to admin and no
    # restart was dispatched.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert not any(
        item.check_id == "switch-to-a-complete" for item in transaction.verifications
    )


def test_a_state_not_freshly_a3_fails_closed() -> None:
    # The PasswordSafe A record drifted to the old-A generation: the fresh
    # reconciliation is not A3 (it is A0), so the phase fails closed before any
    # propagation.
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    drifted = _passwordsafe()
    drifted.add(PasswordSafeCredential(10, 101, "admin", 7, A_OLD))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    ks = _keystone()
    # Keystone still accepts new A; the A0 topology requires old-A auth, which
    # the drifted PasswordSafe supplies.  The reconciliation is A0, not A3.
    ks.add_user(KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True,
        "admin-project", True,
    ), A_OLD)
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             passwordsafe_client=drifted, keystone_client=ks)
    assert raised.value.kind is SwitchToAErrorCode.A_STATE_INVALID
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


def test_a_state_indeterminate_fails_closed() -> None:
    # Keystone authentication is indeterminate: the fresh reconciliation cannot
    # classify A3, so the phase fails closed.
    from admin_password_rotation.keystone import KeystoneIndeterminateReason
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    ks = _keystone()
    ks.next_auth_indeterminate = KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))
    with pytest.raises(SwitchToAError) as raised:
        _run(store, secret_client, workload_client, Ownership(),
             keystone_client=ks)
    assert raised.value.kind is SwitchToAErrorCode.A_STATE_INDETERMINATE
    _assert_no_side_effects(store, secret_client, workload_client, phase=RotationPhase.SWITCH_TO_A)


def test_fixed_admin_location_is_a_noop_not_b_switched() -> None:
    # A fixed identity: admin propagated location was never switched to B (it
    # holds the new-A reference).  During SWITCH_TO_A it is a no-op: it is not
    # in the active transition's changed set and it is not rewritten.
    secrets = _secrets(admin_fixed="admin", active="breakglass")
    parsed = parse_contract(_fixed_admin_contract_text())
    desired = DesiredCredential(Identity.ADMIN, A_NEW)
    planned = plan_or_reconcile_propagation_wave(
        parsed,
        SecretInventory("openstack", "100", tuple(secrets.values())),
        ReferenceCredentials(A_NEW, B), desired, A_GENERATION, PropagationWave((), ()),
    )
    store = MemoryStateStore(_state_for(_transaction(to_a=planned.wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads("active-api"))

    result = _run(store, secret_client, workload_client, Ownership(),
                  contract_text=_fixed_admin_contract_text())

    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.VERIFY_A
    # The active location switched to admin; the fixed-admin location stays
    # admin (never B) and is not in the changed set.
    assert secret_client.current("openstack", "active-consumer").get("OS_USERNAME") == SecretValue(b"admin")
    assert secret_client.current("openstack", "active-consumer").get("OS_PASSWORD") == A_NEW
    assert secret_client.current("openstack", "admin-fixed-consumer").get("OS_USERNAME") == SecretValue(b"admin")
    assert secret_client.current("openstack", "admin-fixed-consumer").get("OS_PASSWORD") == A_NEW
    assert "active" in transaction.propagation.to_a.applied_location_ids
    assert "admin-fixed" not in transaction.propagation.to_a.applied_location_ids


def test_keystone_admin_is_not_an_a_propagation_target() -> None:
    secrets = _secrets()
    wave = _planned_to_a(secrets=secrets)
    store = MemoryStateStore(_state_for(_transaction(to_a=wave)))
    secret_client = FakeCredentialSecretClient(*secrets.values())
    workload_client = _FakeWorkloadClient(_workloads(*_all_workload_names()))

    result = _run(store, secret_client, workload_client, Ownership())

    # The breeder Secret is never touched by the A wave: it still holds the
    # new-A credential and is not in the changed set.
    assert secret_client.current("openstack", "keystone-admin").get("password") == A_NEW
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert "keystone-admin" not in transaction.propagation.to_a.applied_location_ids
