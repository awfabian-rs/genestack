"""Slice 4G: transaction-level ``ROTATE_A`` runtime integration tests.

``run_rotate_a`` must compose the bounded Slice 3D staging and Slice 3E
convergence libraries into the ``ROTATE_A`` runtime phase, gated by the
durable ``VERIFY_B`` completion evidence: a single ``SUCCESS``
``verify-b-complete`` receipt at phase ``VERIFY_B`` carrying the transaction's
B generation, plus the ``PREPARE_B`` ``stable-a`` / ``breakglass-b2`` evidence
that anchors the old-A generation and breeder UID.  Only a fresh final
observation of the authoritative A boundary at A3 permits the
ownership-fenced phase advance to ``SWITCH_TO_A`` with the credential-free
``rotate-a-complete`` receipt.  These tests reuse the existing behavioral
fakes (the same ones the Slice 3D/3E tests use) rather than introducing
parallel test abstractions.
"""
from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, cast
from uuid import UUID

import pytest

from admin_password_rotation.breeder import (
    BreederProvenance, BreederSecretClient, FakeBreederSecretClient,
)
from admin_password_rotation.config import parse_contract
from admin_password_rotation.errors import SafeError
from admin_password_rotation.keystone import (
    FakeKeystoneClient, KeystoneUserObservation,
)
from admin_password_rotation.model import (
    ConfigurationDigest, CredentialGeneration, CredentialMutationIntent,
    CredentialMutationStep, EnvironmentIdentity, ExecutionIdentity,
    IntentEffectState, KubernetesMutationTarget, LockoutChangeState,
    LockoutState, PasswordSafeState, PersistentState, PropagationState,
    PropagationWave, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, SecretAnnotation, SecretSnapshot,
    SecretValue, TransactionStatus, VerificationResult, VerificationStatus,
)
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient, IdentityAccess, PasswordSafeCredential,
)
from admin_password_rotation.propagation import FakeCredentialSecretClient
from admin_password_rotation.restart import (
    RolloutStatus, WorkloadSnapshot,
)
from admin_password_rotation.runtime_rotate_a import (
    RotateARuntimeError, RotateARuntimeErrorCode, RotateARuntimeInputs,
    RotateARuntimeOutcome, RotateARuntimeRequest, run_rotate_a,
)
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import (
    PersistedState, StateRevision, StateStore, StateStoreError,
    StateStoreErrorCode,
)
from tests.helpers import contract, secret

NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
ENVIRONMENT = EnvironmentIdentity("dfw-dev", "cluster.local")
A_OLD = SecretValue(b"Synthetic-Old-Admin-4G")
A_NEW_1 = SecretValue(b"Synthetic-ANew1-4G-0123456789abcd")
A_NEW_2 = SecretValue(b"Synthetic-ANew2-4G-0123456789abcd")
B = SecretValue(b"Synthetic-Breakglass-4G")
OLD_GENERATION = CredentialGeneration.from_secret(A_OLD)
A1_GENERATION = CredentialGeneration.from_secret(A_NEW_1)
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


def _a0_transaction() -> RotationTransaction:
    """A fresh ROTATE_A transaction entered from a completed VERIFY_B.

    Carries the verify-b-complete receipt at VERIFY_B (B generation), the
    PREPARE_B stable-a / breakglass-b2 evidence, and no A-new generation yet.
    """
    return RotationTransaction(
        transaction_id=TX_ID,
        request_id=UUID("22222222-2222-4222-8222-222222222222"),
        execution=EXECUTION,
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=IDS,
        created_at=NOW,
        updated_at=NOW,
        phase=RotationPhase.ROTATE_A,
        status=TransactionStatus.ACTIVE,
        last_error=None,
        new_a_sha256=None,
        new_b_sha256=B_GENERATION,
        passwordsafe=PasswordSafeState(101, 202, 101, 202, 7, 7, 4),
        credential_mutation_intent=None,
        propagation=PropagationState(
            PropagationWave((), ()), PropagationWave((), ()),
        ),
        lockout=LockoutState(
            False, LockoutChangeState.NOT_INTENDED,
            LockoutChangeState.NOT_INTENDED, False, False,
        ),
        verifications=(
            VerificationResult(
                "stable-a", RotationPhase.PREPARE_B,
                VerificationStatus.SUCCESS, NOW, "freshly-verified",
                BREEDER_UID, OLD_GENERATION,
            ),
            VerificationResult(
                "breakglass-b2", RotationPhase.PREPARE_B,
                VerificationStatus.SUCCESS, NOW, "freshly-authorized",
                None, B_GENERATION,
            ),
            VerificationResult(
                "switch-to-b-complete", RotationPhase.SWITCH_TO_B,
                VerificationStatus.SUCCESS, NOW, "propagated-and-restarted",
                None, B_GENERATION,
            ),
            VerificationResult(
                "verify-b-complete", RotationPhase.VERIFY_B,
                VerificationStatus.SUCCESS, NOW, "bridge-freshly-verified",
                None, B_GENERATION,
            ),
        ),
    )


def _staged_a1_transaction() -> RotationTransaction:
    """A ROTATE_A transaction whose new A is durably staged (A1) in the breeder."""
    intent = CredentialMutationIntent(
        CredentialMutationStep.STAGE_A_BREEDER,
        KubernetesMutationTarget(
            "openstack", "keystone-admin", BREEDER_UID, "124",
        ),
        (),
        A1_GENERATION,
        IntentEffectState.OBSERVED,
        NOW,
        "124",
    )
    return replace(
        _a0_transaction(),
        new_a_sha256=A1_GENERATION,
        credential_mutation_intent=intent,
        lockout=LockoutState(
            False, LockoutChangeState.EFFECT_OBSERVED,
            LockoutChangeState.NOT_INTENDED, True, True,
        ),
        verifications=(
            *_a0_transaction().verifications,
            VerificationResult(
                "slice-3d-a1", RotationPhase.ROTATE_A,
                VerificationStatus.SUCCESS, NOW, "freshly-observed-a1",
                BREEDER_UID, A1_GENERATION,
            ),
        ),
    )


def _converged_a3_transaction() -> RotationTransaction:
    """A ROTATE_A transaction whose A credential already converged (A3)."""
    intent = CredentialMutationIntent(
        CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
        None, (),
        A1_GENERATION,
        IntentEffectState.OBSERVED,
        NOW,
        None,
    )
    return replace(
        _a0_transaction(),
        new_a_sha256=A1_GENERATION,
        credential_mutation_intent=intent,
        lockout=LockoutState(
            False, LockoutChangeState.EFFECT_OBSERVED,
            LockoutChangeState.NOT_INTENDED, True, True,
        ),
        verifications=(
            *_a0_transaction().verifications,
            VerificationResult(
                "slice-3e-a2", RotationPhase.ROTATE_A,
                VerificationStatus.SUCCESS, NOW, "freshly-observed-a2",
                BREEDER_UID, A1_GENERATION,
            ),
            VerificationResult(
                "slice-3e-a3", RotationPhase.ROTATE_A,
                VerificationStatus.SUCCESS, NOW, "freshly-observed-a3",
                BREEDER_UID, A1_GENERATION,
            ),
        ),
    )


def _state_for(transaction: RotationTransaction) -> PersistentState:
    return PersistentState(
        schema_version=2,
        environment=ENVIRONMENT,
        current_transaction=transaction,
        completed_requests=(),
    )


class MemoryStateStore(StateStore):
    def __init__(self, state: PersistentState) -> None:
        self.current = PersistedState(
            state, StateRevision("openstack", "rotation-state", "state-uid", "1"),
        )
        self.update_count = 0
        self.before_final_update: Callable[[MemoryStateStore], None] | None = None

    def load(self) -> PersistedState:
        return self.current

    def update(
        self, expected: StateRevision, new_state: PersistentState,
    ) -> PersistedState:
        # The final state-store update is the ownership-fenced phase advance:
        # it writes the rotate-a-complete receipt and switches the phase to
        # SWITCH_TO_A.  The hook lets a test simulate a concurrent
        # transaction-state mutation landing between the fresh A3
        # observation and this CAS-protected advance: it runs *before* the
        # revision check, so the foreign write bumps the durable revision and
        # the advance's CAS from R fails.
        if (
            self.before_final_update is not None
            and new_state.current_transaction is not None
            and new_state.current_transaction.phase is RotationPhase.SWITCH_TO_A
            and any(
                item.check_id == "rotate-a-complete"
                for item in new_state.current_transaction.verifications
            )
        ):
            self.before_final_update(self)
        if expected != self.current.revision:
            raise StateStoreError(StateStoreErrorCode.CONFLICT)
        self.update_count += 1
        self.current = PersistedState(
            new_state,
            replace(expected, resource_version=str(int(expected.resource_version) + 1)),
        )
        return self.current


class Ownership:
    def __init__(self, *, fail_on: int | None = None) -> None:
        self.assertions = 0
        self.fail_on = fail_on
        self.per_call: list[int] = []
        self._call_start = 0
        self._in_call = False

    @property
    def requires_recovery_gate(self) -> bool:
        return False

    def begin_call(self) -> None:
        self._call_start = self.assertions
        self._in_call = True

    def end_call(self) -> None:
        if self._in_call:
            self.per_call.append(self.assertions - self._call_start)
            self._in_call = False

    def assert_owned(self) -> None:
        self.assertions += 1
        if self.fail_on is not None and self.assertions > self.fail_on:
            raise SafeError("ownership_lost", "ownership lost")


class _FakeWorkload:
    def __init__(self, name: str) -> None:
        self.name = name
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
            namespace="openstack", name=self.name, uid=f"uid-{self.name}",
            restart_requested=self.restart_requested,
            metadata_generation=self.metadata_generation,
            observed_generation=self.observed_generation,
            ready_replicas=self.ready_replicas,
            desired_replicas=self.desired_replicas,
            updated_replicas=self.updated_replicas,
            unavailable_replicas=self.unavailable_replicas,
            rollout_status=self.rollout_status, condition_reason=None,
        )

    def advance(self) -> None:
        if (
            self.restart_requested is not None and not self.rollout_completed
        ):
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


def staged_annotations(generation: CredentialGeneration) -> tuple[SecretAnnotation, ...]:
    return BreederProvenance(TX_ID, generation).annotations()


def breeder_snapshot(
    password: SecretValue = A_OLD, *,
    resource_version: str = "123",
    uid: str = BREEDER_UID,
    annotations: tuple[SecretAnnotation, ...] = (),
) -> SecretSnapshot:
    base = secret("keystone-admin", {
        "password": password.reveal(),
        "unrelated": b"preserve-me",
    })
    return replace(
        base,
        uid=uid,
        resource_version=resource_version,
        annotations=(
            SecretAnnotation("example.org/keep", "unchanged"), *annotations,
        ),
    )


def passwordsafe(*, admin: SecretValue = A_OLD) -> FakePasswordSafeClient:
    client = FakePasswordSafeClient()
    client.add(PasswordSafeCredential(10, 101, "admin", 7, admin))
    client.add(PasswordSafeCredential(10, 202, "breakglass", 4, B))
    return client


def keystone(
    *, admin: SecretValue = A_OLD, suppressed: bool = False,
) -> FakeKeystoneClient:
    client = FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    )
    client.add_user(KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True,
        "admin-project", suppressed,
    ), admin)
    client.add_user(KeystoneUserObservation(
        "breakglass-user", "breakglass", "default-domain", True,
        "admin-project", False,
    ), B)
    return client


def b_secrets() -> dict[str, SecretSnapshot]:
    un = b"breakglass"
    return {
        "keystone-admin": breeder_snapshot(A_OLD),
        "consumer": secret("consumer", {"OS_USERNAME": un, "OS_PASSWORD": B.reveal()}),
    }


def _request() -> RotateARuntimeRequest:
    return RotateARuntimeRequest(
        environment=ENVIRONMENT,
        keystone=IDS,
        passwordsafe_project_id=10,
        passwordsafe_a_record_id=101,
        passwordsafe_b_record_id=202,
        execution=EXECUTION,
    )


def _inputs(
    *,
    generated: SecretValue = A_NEW_1,
    contract_text: str | None = None,
    request: RotateARuntimeRequest | None = None,
    breeder: BreederSecretClient | None = None,
) -> RotateARuntimeInputs:
    parsed = parse_contract(contract_text) if contract_text else contract()
    return RotateARuntimeInputs(
        request=request or _request(),
        contract=parsed,
        passwordsafe_access=ACCESS,
        breeder=breeder if breeder is not None else cast(BreederSecretClient, None),
        password_generator=lambda: generated,
    )


def _run(
    store: MemoryStateStore, owner: Ownership,
    secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient,
    breeder: FakeBreederSecretClient,
    ps: FakePasswordSafeClient,
    ks: FakeKeystoneClient,
    *,
    generated: SecretValue = A_NEW_1,
    contract_text: str | None = None,
    request: RotateARuntimeRequest | None = None,
):
    inputs = _inputs(
        generated=generated, contract_text=contract_text,
        request=request, breeder=breeder,
    )
    return run_rotate_a(
        inputs,
        state_store=store,
        ownership=owner,
        passwordsafe=ps,
        keystone=ks,
        clock=lambda: NOW,
    )


def _assert_entry_errors(
    expected: RotateARuntimeErrorCode, store: MemoryStateStore,
    secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient,
    breeder: FakeBreederSecretClient,
    ps: FakePasswordSafeClient,
    ks: FakeKeystoneClient,
) -> None:
    with pytest.raises(RotateARuntimeError) as raised:
        _run(
            store, Ownership(), secret_client, workload_client, breeder, ps, ks,
        )
    assert raised.value.kind is expected


def _assert_no_side_effects(
    store: MemoryStateStore, secret_client: FakeCredentialSecretClient,
    workload_client: _FakeWorkloadClient, breeder: FakeBreederSecretClient,
    ks: FakeKeystoneClient, ps: FakePasswordSafeClient,
    *, phase: RotationPhase,
) -> None:
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    assert breeder.stage_calls == 0
    assert ks.lockout_update_calls == []
    assert ks.password_update_calls == []
    assert ps.update_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is phase


# ---------------------------------------------------------------------------
# 1. Valid ROTATE_A entry from successful VERIFY_B at A0
# ---------------------------------------------------------------------------


def test_valid_entry_from_verify_b_at_a0_stages_and_converges() -> None:
    store = MemoryStateStore(_state_for(_a0_transaction()))
    owner = Ownership()
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    ps = passwordsafe()
    ks = keystone()

    result = _run(
        store, owner, secret_client, workload_client, breeder, ps, ks,
    )

    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    assert result.converged is True
    assert result.phase is RotationPhase.SWITCH_TO_A
    assert result.new_a_generation == A1_GENERATION
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert transaction.status is TransactionStatus.ACTIVE
    assert transaction.new_a_sha256 == A1_GENERATION
    # Slice 3D staged the breeder with transaction provenance.
    assert breeder.stage_calls == 1
    assert breeder.snapshot.get("password") == A_NEW_1
    assert BreederProvenance(TX_ID, A1_GENERATION).matches(breeder.snapshot)
    # Slice 3D suppressed lockout; Slice 3E reset Keystone and PasswordSafe.
    assert ks.lockout_update_calls == [("admin-user", True)]
    assert ks.password_update_calls == ["admin-user"]
    assert ps.update_calls == [(10, 101)]
    # The credential-free completion receipt records the A generation.
    assert any(
        item.check_id == "rotate-a-complete"
        and item.phase is RotationPhase.ROTATE_A
        and item.status is VerificationStatus.SUCCESS
        and item.credential_generation == A1_GENERATION
        for item in transaction.verifications
    )
    # Lockout remains suppressed, restoration still required.
    assert transaction.lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
    assert transaction.lockout.restore_required
    assert transaction.lockout.restoration is LockoutChangeState.NOT_INTENDED
    # No propagated Secret was mutated and no workload was restarted.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    # The temporary breakglass propagation remains in place.
    assert secret_client.current("openstack", "consumer").get("OS_PASSWORD") == B


# ---------------------------------------------------------------------------
# 2. Successful fresh A3 persists the receipt and advances exactly to
#    SWITCH_TO_A (already covered above; this asserts the receipt appears
#    exactly once and the phase is exactly SWITCH_TO_A, not VERIFY_A).
# ---------------------------------------------------------------------------


def test_success_receipt_is_unique_and_phase_is_exactly_switch_to_a() -> None:
    store = MemoryStateStore(_state_for(_a0_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())

    result = _run(
        store, Ownership(), secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )

    assert result.phase is RotationPhase.SWITCH_TO_A
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    receipts = [
        item for item in transaction.verifications
        if item.check_id == "rotate-a-complete"
        and item.phase is RotationPhase.ROTATE_A
    ]
    assert len(receipts) == 1
    assert receipts[0].credential_generation == A1_GENERATION
    assert receipts[0].status is VerificationStatus.SUCCESS
    assert transaction.phase is RotationPhase.SWITCH_TO_A
    assert transaction.phase is not RotationPhase.VERIFY_A


# ---------------------------------------------------------------------------
# 3. A1 resume reuses the staged new-A generation
# ---------------------------------------------------------------------------


def test_a1_resume_reuses_staged_generation_and_converges() -> None:
    store = MemoryStateStore(_state_for(_staged_a1_transaction()))
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(suppressed=True)
    generated = 0

    def generator() -> SecretValue:
        nonlocal generated
        generated += 1
        return A_NEW_2

    inputs = _inputs(generated=A_NEW_2, breeder=breeder)
    inputs = replace(inputs, password_generator=generator)
    result = run_rotate_a(
        inputs,
        state_store=store, ownership=Ownership(),
        passwordsafe=passwordsafe(), keystone=ks, clock=lambda: NOW,
    )

    assert generated == 0
    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    assert result.new_a_generation == A1_GENERATION
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.new_a_sha256 == A1_GENERATION
    # The already-staged breeder is not re-staged.
    assert breeder.stage_calls == 0
    assert breeder.snapshot.get("password") == A_NEW_1
    # Convergence ran: Keystone reset + PasswordSafe update.
    assert ks.password_update_calls == ["admin-user"]
    assert transaction.phase is RotationPhase.SWITCH_TO_A


# ---------------------------------------------------------------------------
# 4. A2 resume does not generate another password and converges PasswordSafe
# ---------------------------------------------------------------------------


def test_a2_resume_does_not_generate_and_converges_passwordsafe() -> None:
    # A2: breeder staged (new A), Keystone already at new A, PasswordSafe old.
    tx = replace(
        _staged_a1_transaction(),
        credential_mutation_intent=CredentialMutationIntent(
            CredentialMutationStep.RESET_A_KEYSTONE,
            None, (),
            A1_GENERATION,
            IntentEffectState.OBSERVED,
            NOW,
            None,
        ),
    )
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(admin=A_NEW_1, suppressed=True)
    ps = passwordsafe()  # PasswordSafe still old A.

    result = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
        generated=A_NEW_2,
    )

    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    assert result.new_a_generation == A1_GENERATION
    # No Keystone reset (already A2); only the PasswordSafe update.
    assert ks.password_update_calls == []
    assert ps.update_calls == [(10, 101)]
    # No new generation: the staged generation is reused.
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.new_a_sha256 == A1_GENERATION
    assert breeder.stage_calls == 0
    assert transaction.phase is RotationPhase.SWITCH_TO_A


# ---------------------------------------------------------------------------
# 5. A3 resume performs fresh verification and advances without repeating
#    credential mutations
# ---------------------------------------------------------------------------


def test_a3_resume_verifies_fresh_and_advances_without_remutation() -> None:
    store = MemoryStateStore(_state_for(_converged_a3_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(admin=A_NEW_1, suppressed=True)
    ps = passwordsafe(admin=A_NEW_1)  # PasswordSafe already new A.

    result = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )

    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    assert result.phase is RotationPhase.SWITCH_TO_A
    # No A credential mutation repeated on resume.
    assert breeder.stage_calls == 0
    assert ks.password_update_calls == []
    assert ps.update_calls == []
    # The completion receipt was written by this invocation.
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert any(
        item.check_id == "rotate-a-complete"
        and item.phase is RotationPhase.ROTATE_A
        for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 6. Invalid / missing VERIFY_B predecessor evidence
# ---------------------------------------------------------------------------


def test_missing_verify_b_receipt_prevents_execution() -> None:
    tx = replace(
        _a0_transaction(),
        verifications=tuple(
            item for item in _a0_transaction().verifications
            if not (
                item.check_id == "verify-b-complete"
                and item.phase is RotationPhase.VERIFY_B
            )
        ),
    )
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    _assert_entry_errors(
        RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_MISSING,
        store, secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, keystone(),
        passwordsafe(), phase=RotationPhase.ROTATE_A,
    )


def test_wrong_phase_verify_b_receipt_prevents_execution() -> None:
    # A verify-b-complete receipt at the WRONG phase (SWITCH_TO_B) is not the
    # VERIFY_B evidence: treat it as missing the phase-qualified receipt.
    tx = replace(
        _a0_transaction(),
        verifications=(
            VerificationResult(
                "verify-b-complete", RotationPhase.SWITCH_TO_B,
                VerificationStatus.SUCCESS, NOW, "bridge-freshly-verified",
                None, B_GENERATION,
            ),
            *tuple(
                item for item in _a0_transaction().verifications
                if not (
                    item.check_id == "verify-b-complete"
                    and item.phase is RotationPhase.VERIFY_B
                )
            ),
        ),
    )
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    _assert_entry_errors(
        RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_MISSING,
        store, secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )


def test_non_success_verify_b_receipt_prevents_execution() -> None:
    tx = replace(
        _a0_transaction(),
        verifications=tuple(
            replace(item, status=VerificationStatus.FAILURE)
            if item.check_id == "verify-b-complete"
            else item
            for item in _a0_transaction().verifications
        ),
    )
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    _assert_entry_errors(
        RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_INVALID,
        store, secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )


def test_verify_b_generation_mismatch_prevents_execution() -> None:
    tx = replace(
        _a0_transaction(),
        verifications=tuple(
            replace(item, credential_generation=OLD_GENERATION)
            if item.check_id == "verify-b-complete"
            else item
            for item in _a0_transaction().verifications
        ),
    )
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    _assert_entry_errors(
        RotateARuntimeErrorCode.VERIFY_B_PREREQUISITE_INVALID,
        store, secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )


def test_missing_prepare_b_evidence_prevents_execution() -> None:
    tx = replace(
        _a0_transaction(),
        verifications=tuple(
            item for item in _a0_transaction().verifications
            if not (
                item.check_id == "breakglass-b2"
                and item.phase is RotationPhase.PREPARE_B
            )
        ),
    )
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    _assert_entry_errors(
        RotateARuntimeErrorCode.PREPARE_B_PREREQUISITE_MISSING,
        store, secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, keystone(),
        passwordsafe(), phase=RotationPhase.ROTATE_A,
    )


# ---------------------------------------------------------------------------
# 7. Wrong current transaction phase
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("phase", [
    RotationPhase.STABLE_A,
    RotationPhase.PREPARE_B,
    RotationPhase.SWITCH_TO_B,
    RotationPhase.VERIFY_B,
])
def test_predecessor_phase_prevents_execution(phase: RotationPhase) -> None:
    tx = replace(_a0_transaction(), phase=phase)
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    _assert_entry_errors(
        RotateARuntimeErrorCode.UNSUPPORTED_PHASE,
        store, secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, keystone(),
        passwordsafe(), phase=phase,
    )


@pytest.mark.parametrize("phase", [
    RotationPhase.SWITCH_TO_A,
    RotationPhase.VERIFY_A,
])
def test_successor_phase_reports_already_advanced(phase: RotationPhase) -> None:
    tx = replace(_converged_a3_transaction(), phase=phase)
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    result = _run(
        store, Ownership(), secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )
    assert result.outcome is RotateARuntimeOutcome.ALREADY_ADVANCED
    assert result.converged is False
    assert result.phase is phase
    assert store.update_count == 0
    assert breeder.stage_calls == 0


# ---------------------------------------------------------------------------
# 8. Ownership loss before a correctness-sensitive mutation prevents dispatch
# ---------------------------------------------------------------------------


def test_ownership_loss_before_final_receipt_prevents_advance() -> None:
    # First, count how many ownership assertions a successful A0->A3 run
    # makes (the bounded libraries assert around their mutation boundaries).
    count_store = MemoryStateStore(_state_for(_a0_transaction()))
    count_owner = Ownership()
    _run(
        count_store, count_owner,
        FakeCredentialSecretClient(*b_secrets().values()),
        _FakeWorkloadClient(_workloads()),
        FakeBreederSecretClient(breeder_snapshot()),
        passwordsafe(), keystone(),
    )
    # The final receipt/phase-advance assertion is the (N+1)th assertion
    # overall, where N is the count from a successful run.  fail_on=N means
    # "fail when assertions > N", i.e. the (N+1)th call fails, which is
    # exactly the runtime's final advance assertion.
    store = MemoryStateStore(_state_for(_a0_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    ks = keystone()
    ps = passwordsafe()
    owner = Ownership(fail_on=count_owner.assertions - 1)
    with pytest.raises(RotateARuntimeError) as raised:
        _run(
            store, owner, secret_client, workload_client, breeder, ps, ks,
        )
    assert raised.value.kind is RotateARuntimeErrorCode.PROGRESS_PERSISTENCE_FAILED
    # The A credential mutations already happened (bounded libraries), but the
    # phase did not advance and no rotate-a-complete receipt was written.
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A
    assert not any(
        item.check_id == "rotate-a-complete" for item in transaction.verifications
    )
    # The A credential is fully converged (the bounded libraries ran to A3).
    assert ks.password_update_calls == ["admin-user"]
    assert ps.update_calls == [(10, 101)]
    # No propagated Secret mutation, no restart.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []


def test_ownership_loss_during_staging_prevents_dispatch() -> None:
    # Fail the first ownership assertion (the Slice 3D lockout-suppression
    # boundary) so no mutation is dispatched.
    store = MemoryStateStore(_state_for(_a0_transaction()))
    owner = Ownership(fail_on=0)
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    ks = keystone()
    with pytest.raises(SafeError):
        _run(
            store, owner, secret_client, workload_client, breeder,
            passwordsafe(), ks,
        )
    # No lockout mutation, no breeder staging, no Keystone/PasswordSafe A write.
    assert ks.lockout_update_calls == []
    assert ks.password_update_calls == []
    assert breeder.stage_calls == 0
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A


# ---------------------------------------------------------------------------
# 8b. A concurrent transaction-state mutation between the fresh A3
#     observation and the phase advance must fail the CAS, not be adopted
# ---------------------------------------------------------------------------


def test_concurrent_state_change_between_a3_and_advance_fails_closed() -> None:
    # The bounded convergence returns revision R on which the fresh A3
    # verification is based.  A concurrent actor (or operator edit) mutates
    # the durable transaction after R but before the final advance write.
    # The advance must CAS from R and therefore fail rather than silently
    # adopting the mutated transaction: no rotate-a-complete receipt is
    # written and the phase does not advance.
    def mutate(store: MemoryStateStore) -> None:
        persisted = store.current
        transaction = persisted.state.current_transaction
        assert transaction is not None
        mutated = replace(
            transaction,
            lockout=replace(
                transaction.lockout,
                latest_ignore_lockout_failure_attempts=None,
            ),
            updated_at=NOW,
        )
        # A foreign conditional write: it bumps the durable revision, so the
        # phase advance's CAS from R no longer matches.
        store.current = PersistedState(
            replace(persisted.state, current_transaction=mutated),
            replace(
                persisted.revision,
                resource_version=str(int(persisted.revision.resource_version) + 1),
            ),
        )

    store = MemoryStateStore(_state_for(_a0_transaction()))
    store.before_final_update = mutate
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    ks = keystone()
    ps = passwordsafe()

    with pytest.raises(RotateARuntimeError) as raised:
        _run(store, Ownership(), secret_client, workload_client, breeder, ps, ks)
    assert raised.value.kind is RotateARuntimeErrorCode.PROGRESS_PERSISTENCE_FAILED

    # The advance never landed: the durable transaction is the foreign
    # mutation, still in ROTATE_A, with no rotate-a-complete receipt.
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A
    assert transaction.lockout.latest_ignore_lockout_failure_attempts is None
    assert not any(
        item.check_id == "rotate-a-complete" for item in transaction.verifications
    )
    # The A credential mutations already happened (bounded libraries), but
    # the phase did not advance.
    assert ks.password_update_calls == ["admin-user"]
    assert ps.update_calls == [(10, 101)]
    # No propagated Secret mutation and no workload restart.
    assert secret_client.replace_calls == 0
    assert workload_client.deployment.restart_calls == []


# ---------------------------------------------------------------------------
# 9. Conflicting breeder provenance fails closed
# ---------------------------------------------------------------------------


def test_conflicting_breeder_provenance_fails_closed() -> None:
    # A1 reality but the breeder carries provenance from a *different*
    # transaction: Slice 3E revalidation fails closed before any mutation.
    wrong = BreederProvenance(
        UUID("99999999-9999-4999-8999-999999999999"), A1_GENERATION,
    ).annotations()
    store = MemoryStateStore(_state_for(_staged_a1_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124", annotations=wrong,
    ))
    ks = keystone(suppressed=True)
    with pytest.raises(SafeError):
        _run(
            store, Ownership(), secret_client, workload_client, breeder,
            passwordsafe(), ks,
        )
    assert ks.password_update_calls == []
    assert breeder.stage_calls == 0
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A


# ---------------------------------------------------------------------------
# 10. Unknown authoritative state fails closed
# ---------------------------------------------------------------------------


def test_unknown_breeder_credential_fails_closed() -> None:
    # Neither old A nor the intended new A in the breeder: the A-state
    # machinery classifies the reality invalid and the bounded libraries
    # fail closed before any mutation.
    store = MemoryStateStore(_state_for(_a0_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        SecretValue(b"Unrelated-credential-4G"),
    ))
    ks = keystone()
    with pytest.raises(SafeError):
        _run(
            store, Ownership(), secret_client, workload_client, breeder,
            passwordsafe(), ks,
        )
    assert ks.lockout_update_calls == []
    assert ks.password_update_calls == []
    assert breeder.stage_calls == 0
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A


def test_a3_resume_with_regressed_passwordsafe_fails_closed() -> None:
    # Progress claims A3 but PasswordSafe has regressed to old A: fresh
    # classification is not A3, so the bounded libraries fail closed rather
    # than advancing on the stale progress flag.
    store = MemoryStateStore(_state_for(_converged_a3_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(admin=A_NEW_1, suppressed=True)
    ps = passwordsafe()  # PasswordSafe regressed to old A.
    with pytest.raises(SafeError):
        _run(
            store, Ownership(), secret_client, workload_client, breeder,
            ps, ks,
        )
    # No re-mutation on top of the contradictory progress.
    assert ks.password_update_calls == []
    assert ps.update_calls == []
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A
    assert not any(
        item.check_id == "rotate-a-complete" for item in transaction.verifications
    )


# ---------------------------------------------------------------------------
# 11. Persisted progress lagging actual observed A-state is reconciled from
#     observation
# ---------------------------------------------------------------------------


def test_progress_lagging_observed_a3_is_reconciled_from_observation() -> None:
    # Durable progress claims STAGE_A_BREEDER OBSERVED (A1) but the external
    # reality is already fully converged at A3.  Classification is from
    # observed state, so the bounded libraries skip the lagging work and the
    # fresh final observation advances the phase without re-mutating.
    tx = replace(
        _a0_transaction(),
        new_a_sha256=A1_GENERATION,
        credential_mutation_intent=CredentialMutationIntent(
            CredentialMutationStep.STAGE_A_BREEDER,
            None, (),
            A1_GENERATION,
            IntentEffectState.OBSERVED,
            NOW,
            None,
        ),
        lockout=LockoutState(
            False, LockoutChangeState.EFFECT_OBSERVED,
            LockoutChangeState.NOT_INTENDED, True, True,
        ),
    )
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(admin=A_NEW_1, suppressed=True)
    ps = passwordsafe(admin=A_NEW_1)  # already new A.

    result = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )

    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    assert result.phase is RotationPhase.SWITCH_TO_A
    # The lagging progress did not cause a re-mutation.
    assert ks.password_update_calls == []
    assert ps.update_calls == []
    assert breeder.stage_calls == 0


# ---------------------------------------------------------------------------
# 12. Ambiguous external mutation outcome follows existing reobservation
#     semantics
# ---------------------------------------------------------------------------


def test_ambiguous_keystone_reset_reobserved_and_reconciled() -> None:
    # Slice 3E's ambiguous Keystone reset (effect applied) is resolved by
    # fresh reobservation: the bounded libraries observe A2, then converge
    # PasswordSafe to A3, and the runtime advances.
    store = MemoryStateStore(_state_for(_staged_a1_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(suppressed=True)
    ks.ambiguous_next_password_update_apply = True  # applied, but ambiguous.
    ps = passwordsafe()

    result = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )

    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    assert result.phase is RotationPhase.SWITCH_TO_A
    # The ambiguous reset was reconciled from observation (no blind retry):
    # exactly one Keystone reset and one PasswordSafe update.
    assert ks.password_update_calls == ["admin-user"]
    assert ps.update_calls == [(10, 101)]


def test_ambiguous_keystone_reset_unapplied_fails_closed() -> None:
    # The ambiguous reset's effect was not applied: reobservation finds A1
    # still, the bounded libraries keep the dispatch unresolved, and the
    # runtime fails closed without advancing.
    store = MemoryStateStore(_state_for(_staged_a1_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(suppressed=True)
    ks.ambiguous_next_password_update_apply = False  # not applied.
    ps = passwordsafe()

    with pytest.raises(SafeError):
        _run(
            store, Ownership(), secret_client, workload_client, breeder, ps, ks,
        )
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.ROTATE_A
    assert not any(
        item.check_id == "rotate-a-complete" for item in transaction.verifications
    )
    assert ps.update_calls == []


# ---------------------------------------------------------------------------
# 13. No propagated credential location is modified; no workload restart;
#     lockout not restored; breeder provenance not cleaned
# ---------------------------------------------------------------------------


def test_no_propagation_restart_lockout_or_provenance_cleanup() -> None:
    store = MemoryStateStore(_state_for(_a0_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads("consumer"))
    breeder = FakeBreederSecretClient(breeder_snapshot())
    ps = passwordsafe()
    ks = keystone()

    result = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )

    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    # No propagated Secret mutation (consumer stays at breakglass).
    assert secret_client.replace_calls == 0
    assert secret_client.current("openstack", "consumer").get("OS_PASSWORD") == B
    # No workload restart of any kind.
    assert workload_client.deployment.restart_calls == []
    assert workload_client.daemonset.restart_calls == []
    assert workload_client.workloads["consumer"].restart_call_count == 0
    # Lockout not restored: suppression stays positive, restoration untouched.
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
    assert transaction.lockout.latest_ignore_lockout_failure_attempts is True
    assert transaction.lockout.restore_required is True
    assert transaction.lockout.restoration is LockoutChangeState.NOT_INTENDED
    # Breeder provenance not cleaned: the transaction provenance remains.
    assert BreederProvenance(TX_ID, A1_GENERATION).matches(breeder.snapshot)


# ---------------------------------------------------------------------------
# 14. No secret values in runtime results, persisted receipts, state, logs,
#     or exceptions
# ---------------------------------------------------------------------------


def test_no_secrets_in_result_state_or_exceptions() -> None:
    store = MemoryStateStore(_state_for(_a0_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    ps = passwordsafe()
    ks = keystone()
    result = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )
    serialized = serialize_state_json(result.persisted.state)
    rendered = (
        repr(result)
        + json.dumps(
            asdict(result),
            default=lambda value: value.value if isinstance(value, Enum)
            else str(value),
            sort_keys=True,
        )
    )
    for value in (A_OLD, A_NEW_1, B, ACCESS.token):
        assert value.reveal().decode() not in serialized
        assert value.reveal().decode() not in rendered

    # The failure path is also credential-free.
    bad_store = MemoryStateStore(_state_for(_a0_transaction()))
    bad_breeder = FakeBreederSecretClient(breeder_snapshot(
        SecretValue(b"Unrelated-credential-4G"),
    ))
    with pytest.raises(SafeError) as raised:
        _run(
            bad_store, Ownership(),
            FakeCredentialSecretClient(*b_secrets().values()),
            _FakeWorkloadClient(_workloads()),
            bad_breeder, passwordsafe(), keystone(),
        )
    for value in (A_OLD, A_NEW_1, B, ACCESS.token):
        assert value.reveal().decode() not in str(raised.value)
        assert value.reveal().decode() not in repr(raised.value)


# ---------------------------------------------------------------------------
# 15. Re-running after a crash at the phase-completion boundary is safe
# ---------------------------------------------------------------------------


def test_rerun_after_completion_is_idempotent_and_safe() -> None:
    store = MemoryStateStore(_state_for(_a0_transaction()))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    ps = passwordsafe()
    ks = keystone()

    first = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )
    assert first.outcome is RotateARuntimeOutcome.CONVERGED
    assert first.phase is RotationPhase.SWITCH_TO_A
    mutations_after_first = (
        len(ks.password_update_calls),
        len(ps.update_calls),
        breeder.stage_calls,
    )

    # Re-run after a crash at the completion boundary: the transaction is
    # already in SWITCH_TO_A, so the invocation reports ALREADY_ADVANCED
    # without re-running the bounded libraries or repeating mutations.
    second = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )
    assert second.outcome is RotateARuntimeOutcome.ALREADY_ADVANCED
    assert second.phase is RotationPhase.SWITCH_TO_A
    assert (
        len(ks.password_update_calls),
        len(ps.update_calls),
        breeder.stage_calls,
    ) == mutations_after_first
    transaction = store.current.state.current_transaction
    assert transaction is not None
    receipts = [
        item for item in transaction.verifications
        if item.check_id == "rotate-a-complete"
        and item.phase is RotationPhase.ROTATE_A
    ]
    assert len(receipts) == 1


def test_rerun_while_still_in_rotate_a_reuses_converged_state() -> None:
    # Crash after A3 was fully converged but before the phase advance: the
    # durable record is still in ROTATE_A with A3 reality.  Re-running
    # re-observes A3, performs no new A mutation, and advances once.
    tx = _converged_a3_transaction()
    store = MemoryStateStore(_state_for(tx))
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124",
        annotations=staged_annotations(A1_GENERATION),
    ))
    ks = keystone(admin=A_NEW_1, suppressed=True)
    ps = passwordsafe(admin=A_NEW_1)

    result = _run(
        store, Ownership(), secret_client, workload_client, breeder, ps, ks,
    )

    assert result.outcome is RotateARuntimeOutcome.CONVERGED
    assert result.phase is RotationPhase.SWITCH_TO_A
    assert ks.password_update_calls == []
    assert ps.update_calls == []
    assert breeder.stage_calls == 0
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    receipts = [
        item for item in transaction.verifications
        if item.check_id == "rotate-a-complete"
        and item.phase is RotationPhase.ROTATE_A
    ]
    assert len(receipts) == 1


# ---------------------------------------------------------------------------
# Environment / configuration mismatches
# ---------------------------------------------------------------------------


def test_environment_mismatch_prevents_execution() -> None:
    tx = _a0_transaction()
    store = MemoryStateStore(_state_for(tx))
    request = replace(
        _request(),
        environment=EnvironmentIdentity("other-env", "other-cluster"),
    )
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    with pytest.raises(RotateARuntimeError) as raised:
        _run(
            store, Ownership(), secret_client, workload_client, breeder,
            passwordsafe(), keystone(), request=request,
        )
    assert raised.value.kind is RotateARuntimeErrorCode.ENVIRONMENT_MISMATCH
    _assert_no_side_effects(
        store, secret_client, workload_client, breeder, keystone(),
        passwordsafe(), phase=RotationPhase.ROTATE_A,
    )


def test_no_transaction_prevents_execution() -> None:
    store = MemoryStateStore(_state_for(_a0_transaction()))
    store.current = PersistedState(
        replace(store.current.state, current_transaction=None),
        store.current.revision,
    )
    secret_client = FakeCredentialSecretClient(*b_secrets().values())
    workload_client = _FakeWorkloadClient(_workloads())
    breeder = FakeBreederSecretClient(breeder_snapshot())
    _assert_entry_errors(
        RotateARuntimeErrorCode.NO_TRANSACTION,
        store, secret_client, workload_client, breeder,
        passwordsafe(), keystone(),
    )
