from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

import pytest

from admin_password_rotation.breeder import (
    BreederErrorCode, BreederProvenance, FakeBreederSecretClient,
)
from admin_password_rotation.external_http import ExternalClientError, ExternalErrorCode
from admin_password_rotation.keystone import (
    FakeKeystoneClient, KeystoneAuthenticationResult, KeystoneAuthIndeterminate,
    KeystoneAuthSuccess, KeystoneIndeterminateReason, KeystonePasswordAuthRequest,
    KeystoneUserObservation,
)
from admin_password_rotation.model import (
    STATE_SCHEMA_VERSION, ConfigurationDigest, CredentialGeneration,
    CredentialMutationIntent, CredentialMutationStep, EnvironmentIdentity,
    ExecutionIdentity, IntentEffectState, KubernetesMutationTarget,
    LockoutChangeState, LockoutState, PasswordSafeState, PersistentState,
    PropagationState, PropagationWave, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, SecretAnnotation, SecretField, SecretSnapshot, SecretValue,
    TransactionStatus, VerificationResult, VerificationStatus,
)
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient, IdentityAccess, PasswordSafeCredential,
)
from admin_password_rotation.rotate_a import (
    RotateAConvergeError, RotateAConvergeErrorCode, RotateAConvergeInputs,
    RotateAConvergeOutcome, run_rotate_a_converge,
    RotateAStageError, RotateAStageErrorCode, RotateAStageInputs,
    RotateAStageOutcome, run_rotate_a_stage_breeder,
)
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import PersistedState, StateRevision, StateStore
from tests.helpers import PASSWORD, contract, secret


NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
ENVIRONMENT = EnvironmentIdentity("dfw-dev", "cluster.local")
A_OLD = SecretValue(PASSWORD)
A_NEW_1 = SecretValue(b"ANew1_0123456789abcdefghijklmnop")
A_NEW_2 = SecretValue(b"ANew2_0123456789abcdefghijklmnop")
B = SecretValue(b"Breakglass_0123456789abcdefghijkl")
OLD_GENERATION = CredentialGeneration.from_secret(A_OLD)
B_GENERATION = CredentialGeneration.from_secret(B)
IDS = ResolvedKeystoneIdentities(
    "admin-user", "breakglass-user", "default-domain", "admin-project",
    "default-domain", "admin-role",
)


class MemoryStateStore(StateStore):
    def __init__(self, state: PersistentState) -> None:
        self.current = PersistedState(
            state, StateRevision("openstack", "rotation-state", "state-uid", "1"),
        )
        self.history: list[PersistentState] = []
        self.crash_on_a1_verification = False

    def load(self) -> PersistedState:
        return self.current

    def update(
        self, expected: StateRevision, new_state: PersistentState,
    ) -> PersistedState:
        assert expected == self.current.revision
        self.history.append(new_state)
        self.current = PersistedState(
            new_state,
            replace(expected, resource_version=str(int(expected.resource_version) + 1)),
        )
        transaction = new_state.current_transaction
        if (
            self.crash_on_a1_verification
            and transaction is not None
            and any(item.check_id == "slice-3d-a1" for item in transaction.verifications)
        ):
            self.crash_on_a1_verification = False
            raise RuntimeError("injected process termination")
        return self.current


class CrashOnStateWrite(MemoryStateStore):
    def __init__(
        self, state: PersistentState, *, step: CredentialMutationStep | None = None,
        effect: IntentEffectState | None = None,
        verification: str | None = None, before: bool = False,
    ) -> None:
        super().__init__(state)
        self.step = step
        self.effect = effect
        self.verification = verification
        self.before = before
        self.crashed = False

    def update(
        self, expected: StateRevision, new_state: PersistentState,
    ) -> PersistedState:
        transaction = new_state.current_transaction
        intent = None if transaction is None else transaction.credential_mutation_intent
        matches_intent = (
            self.step is not None
            and intent is not None
            and intent.step is self.step
            and intent.effect_state is self.effect
        )
        matches_verification = (
            self.verification is not None
            and transaction is not None
            and any(
                item.check_id == self.verification
                for item in transaction.verifications
            )
        )
        should_crash = not self.crashed and (matches_intent or matches_verification)
        if should_crash and self.before:
            self.crashed = True
            raise RuntimeError("injected process termination")
        result = super().update(expected, new_state)
        if should_crash:
            self.crashed = True
            raise RuntimeError("injected process termination")
        return result

class Ownership:
    requires_recovery_gate = False

    def __init__(self, store: MemoryStateStore, *, fail_on: int | None = None) -> None:
        self.store = store
        self.fail_on = fail_on
        self.assertions = 0
        self.observed: list[tuple[LockoutChangeState, IntentEffectState | None]] = []

    def assert_owned(self) -> None:
        self.assertions += 1
        transaction = self.store.current.state.current_transaction
        assert transaction is not None
        intent = transaction.credential_mutation_intent
        self.observed.append((
            transaction.lockout.suppression,
            None if intent is None else intent.effect_state,
        ))
        if self.assertions == self.fail_on:
            raise RotateAStageError(RotateAStageErrorCode.OWNERSHIP_LOST)


class AlteredBreakglassKeystone(FakeKeystoneClient):
    def __init__(self, alteration: str) -> None:
        super().__init__(
            project_id="admin-project", project_name="admin",
            project_domain_id="default-domain",
        )
        self.alteration = alteration

    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        result = super().authenticate_password(request)
        if request.username != "breakglass":
            return result
        if self.alteration == "indeterminate":
            return KeystoneAuthIndeterminate(KeystoneIndeterminateReason.DEPENDENCY_FAILURE)
        if not isinstance(result, KeystoneAuthSuccess):
            return result
        observed = result.observation
        if self.alteration == "user":
            observed = replace(observed, user_id="wrong-user")
        elif self.alteration == "project":
            observed = replace(observed, project_id="wrong-project")
        elif self.alteration == "domain":
            observed = replace(observed, project_domain_id="wrong-domain")
        elif self.alteration == "role":
            observed = replace(observed, roles=())
        elif self.alteration == "expired":
            observed = replace(observed, expires_at=NOW)
        return replace(result, observation=observed)


class CrashAfterBreederApply(FakeBreederSecretClient):
    crashed = False

    def conditional_stage(
        self, expected: SecretSnapshot, *, password: SecretValue,
        provenance: BreederProvenance,
    ) -> None:
        super().conditional_stage(expected, password=password, provenance=provenance)
        if not self.crashed:
            self.crashed = True
            raise RuntimeError("injected process termination")


class CrashAfterLockoutApply(FakeKeystoneClient):
    crashed = False

    def set_ignore_lockout_failure_attempts(
        self, *, user_id: str, value: bool, management_token: SecretValue,
    ) -> None:
        super().set_ignore_lockout_failure_attempts(
            user_id=user_id, value=value, management_token=management_token,
        )
        if not self.crashed:
            self.crashed = True
            raise RuntimeError("injected process termination")


class CrashAfterAdminReset(FakeKeystoneClient):
    crashed = False

    def set_user_password(
        self, *, user_id: str, new_password: SecretValue,
        management_token: SecretValue,
    ) -> None:
        super().set_user_password(
            user_id=user_id, new_password=new_password,
            management_token=management_token,
        )
        if not self.crashed:
            self.crashed = True
            raise RuntimeError("injected process termination")


class CrashAfterPasswordSafeUpdate(FakePasswordSafeClient):
    crashed = False

    def update_password(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        new_password: SecretValue,
    ) -> None:
        super().update_password(
            access=access, project_id=project_id,
            credential_id=credential_id, new_password=new_password,
        )
        if not self.crashed:
            self.crashed = True
            raise RuntimeError("injected process termination")


def access() -> IdentityAccess:
    return IdentityAccess(
        datetime(2030, 1, 1, tzinfo=timezone.utc), SecretValue(b"ps-token"),
    )


def transaction(
    *, intended: CredentialGeneration | None = None,
    effect: IntentEffectState | None = None,
    suppressed: bool = False,
    restore_required: bool = False,
) -> RotationTransaction:
    intent = None
    if intended is not None and effect is not None:
        intent = CredentialMutationIntent(
            CredentialMutationStep.STAGE_A_BREEDER,
            KubernetesMutationTarget(
                "openstack", "keystone-admin", "fixture-keystone-admin", "123",
            ),
            (), intended, effect,
            NOW if effect is IntentEffectState.OBSERVED else None,
            "124" if effect is IntentEffectState.OBSERVED else None,
        )
    return RotationTransaction(
        UUID("11111111-1111-4111-8111-111111111111"),
        UUID("22222222-2222-4222-8222-222222222222"),
        ExecutionIdentity(UUID("33333333-3333-4333-8333-333333333333"), None),
        ConfigurationDigest("sha256:" + "c" * 64),
        IDS,
        NOW,
        NOW,
        RotationPhase.ROTATE_A,
        TransactionStatus.ACTIVE,
        None,
        intended,
        B_GENERATION,
        PasswordSafeState(101, 202, 101, 202, 7, 7, 4),
        intent,
        PropagationState(PropagationWave((), ()), PropagationWave((), ())),
        LockoutState(
            False,
            LockoutChangeState.EFFECT_OBSERVED if suppressed else LockoutChangeState.NOT_INTENDED,
            LockoutChangeState.NOT_INTENDED,
            suppressed,
            restore_required,
        ),
        (VerificationResult(
            "stable-a", RotationPhase.PREPARE_B, VerificationStatus.SUCCESS,
            NOW, "freshly-verified", "fixture-keystone-admin", OLD_GENERATION,
        ),),
    )


def state(value: RotationTransaction) -> PersistentState:
    return PersistentState(STATE_SCHEMA_VERSION, ENVIRONMENT, value, ())


def staged_annotations(generation: CredentialGeneration) -> tuple[SecretAnnotation, ...]:
    return BreederProvenance(
        UUID("11111111-1111-4111-8111-111111111111"), generation,
    ).annotations()


def breeder_snapshot(
    password: SecretValue = A_OLD, *, resource_version: str = "123",
    annotations: tuple[SecretAnnotation, ...] = (),
) -> SecretSnapshot:
    base = secret("keystone-admin", {
        "password": password.reveal(),
        "unrelated": b"preserve-me",
    })
    return replace(
        base, resource_version=resource_version, annotations=(
            SecretAnnotation("example.org/keep", "unchanged"), *annotations,
        ),
    )


def passwordsafe(*, admin: SecretValue = A_OLD, breakglass: SecretValue = B) -> FakePasswordSafeClient:
    client = FakePasswordSafeClient()
    client.add(PasswordSafeCredential(10, 101, "admin", 7, admin))
    client.add(PasswordSafeCredential(10, 202, "breakglass", 4, breakglass))
    return client


def add_users(
    client: FakeKeystoneClient, *, admin: SecretValue = A_OLD,
    suppressed: bool = False, breakglass: SecretValue = B,
) -> FakeKeystoneClient:
    client.add_user(KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True, "admin-project", suppressed,
    ), admin)
    client.add_user(KeystoneUserObservation(
        "breakglass-user", "breakglass", "default-domain", True,
        "admin-project", False,
    ), breakglass)
    return client


def keystone(
    *, admin: SecretValue = A_OLD, suppressed: bool = False,
) -> FakeKeystoneClient:
    return add_users(FakeKeystoneClient(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    ), admin=admin, suppressed=suppressed)


def inputs(*, current_access: IdentityAccess | None = None) -> RotateAStageInputs:
    return RotateAStageInputs(
        ENVIRONMENT, contract(), access() if current_access is None else current_access, 10,
    )


def run(
    store: MemoryStateStore, ps: FakePasswordSafeClient,
    ks: FakeKeystoneClient, breeder: FakeBreederSecretClient,
    owner: Ownership | None = None, *, generated: SecretValue = A_NEW_1,
):
    return run_rotate_a_stage_breeder(
        inputs(), state_store=store, ownership=owner or Ownership(store),
        passwordsafe=ps, keystone=ks, breeder=breeder,
        password_generator=lambda: generated, clock=lambda: NOW,
    )


def assert_error(
    expected: RotateAStageErrorCode, store: MemoryStateStore,
    ps: FakePasswordSafeClient, ks: FakeKeystoneClient,
    breeder: FakeBreederSecretClient, owner: Ownership | None = None,
    *, generated: SecretValue = A_NEW_1,
) -> None:
    with pytest.raises(RotateAStageError) as raised:
        run(store, ps, ks, breeder, owner, generated=generated)
    assert raised.value.kind is expected


def converge_inputs() -> RotateAConvergeInputs:
    return RotateAConvergeInputs(ENVIRONMENT, contract(), access(), 10)


def converge_transaction(
    *, step: CredentialMutationStep = CredentialMutationStep.STAGE_A_BREEDER,
    effect: IntentEffectState = IntentEffectState.OBSERVED,
    suppressed: bool = True, restore_required: bool = True,
) -> RotationTransaction:
    generation = CredentialGeneration.from_secret(A_NEW_1)
    value = transaction(
        intended=generation, effect=effect, suppressed=suppressed,
        restore_required=restore_required,
    )
    assert value.credential_mutation_intent is not None
    return replace(
        value,
        credential_mutation_intent=replace(
            value.credential_mutation_intent,
            step=step,
            target=(
                value.credential_mutation_intent.target
                if step is CredentialMutationStep.STAGE_A_BREEDER else None
            ),
            resulting_resource_version=(
                value.credential_mutation_intent.resulting_resource_version
                if step is CredentialMutationStep.STAGE_A_BREEDER else None
            ),
        ),
    )


def staged_breeder(
    password: SecretValue = A_NEW_1, *, uid: str = "fixture-keystone-admin",
    annotations: tuple[SecretAnnotation, ...] | None = None,
) -> FakeBreederSecretClient:
    generation = CredentialGeneration.from_secret(A_NEW_1)
    snapshot = breeder_snapshot(
        password, resource_version="124",
        annotations=(staged_annotations(generation) if annotations is None else annotations),
    )
    return FakeBreederSecretClient(replace(snapshot, uid=uid))


def converge(
    store: MemoryStateStore, ps: FakePasswordSafeClient,
    ks: FakeKeystoneClient, breeder: FakeBreederSecretClient,
    owner: Ownership | None = None,
):
    return run_rotate_a_converge(
        converge_inputs(), state_store=store,
        ownership=owner or Ownership(store), passwordsafe=ps,
        keystone=ks, breeder=breeder, clock=lambda: NOW,
    )


def assert_converge_error(
    expected: RotateAConvergeErrorCode, store: MemoryStateStore,
    ps: FakePasswordSafeClient, ks: FakeKeystoneClient,
    breeder: FakeBreederSecretClient, owner: Ownership | None = None,
) -> None:
    with pytest.raises(RotateAConvergeError) as raised:
        converge(store, ps, ks, breeder, owner)
    assert raised.value.kind is expected


def test_a0_suppresses_lockout_then_conditionally_stages_and_observes_a1() -> None:
    store = MemoryStateStore(state(transaction()))
    ps = passwordsafe()
    ks = keystone()
    breeder = FakeBreederSecretClient(breeder_snapshot())
    owner = Ownership(store)

    result = run(store, ps, ks, breeder, owner)

    assert result.outcome is RotateAStageOutcome.A1_ESTABLISHED
    assert result.observed_state.value == "A1"
    current = result.persisted.state.current_transaction
    assert current is not None
    assert current.phase is RotationPhase.ROTATE_A
    assert current.lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
    assert current.lockout.restore_required
    assert current.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_1)
    assert current.credential_mutation_intent is not None
    assert current.credential_mutation_intent.effect_state is IntentEffectState.OBSERVED
    assert ks.lockout_update_calls == [("admin-user", True)]
    assert ks.password_update_calls == []
    assert ps.update_calls == []
    assert breeder.stage_calls == 1
    assert breeder.snapshot.get("unrelated") == SecretValue(b"preserve-me")
    assert breeder.snapshot.annotation("example.org/keep") == "unchanged"
    assert current.new_a_sha256 is not None
    assert BreederProvenance(
        current.transaction_id, current.new_a_sha256,
    ).matches(breeder.snapshot)
    assert owner.observed == [
        (LockoutChangeState.INTENT_PERSISTED, None),
        (LockoutChangeState.EFFECT_OBSERVED, IntentEffectState.UNKNOWN),
    ]
    serialized = serialize_state_json(result.persisted.state)
    for value in (A_OLD, A_NEW_1, B):
        assert value.reveal().decode() not in serialized


@pytest.mark.parametrize("observed", ["A1", "A2", "A3"])
def test_non_a0_start_does_not_stage_another_candidate(observed: str) -> None:
    generation = CredentialGeneration.from_secret(A_NEW_1)
    tx = transaction(
        intended=generation, effect=IntentEffectState.OBSERVED,
        suppressed=True, restore_required=True,
    )
    admin_ps = A_NEW_1 if observed == "A3" else A_OLD
    admin_keystone = A_OLD if observed == "A1" else A_NEW_1
    store = MemoryStateStore(state(tx))
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124", annotations=staged_annotations(generation),
    ))
    generated = 0

    def generator() -> SecretValue:
        nonlocal generated
        generated += 1
        return A_NEW_2

    result = run_rotate_a_stage_breeder(
        inputs(), state_store=store, ownership=Ownership(store),
        passwordsafe=passwordsafe(admin=admin_ps),
        keystone=keystone(admin=admin_keystone, suppressed=True),
        breeder=breeder, password_generator=generator, clock=lambda: NOW,
    )

    assert generated == 0
    assert breeder.stage_calls == 0
    if observed == "A1":
        assert result.outcome is RotateAStageOutcome.A1_ALREADY_ESTABLISHED
    else:
        assert result.outcome is RotateAStageOutcome.AHEAD_OF_SLICE


def test_observed_a1_does_not_rewrite_a_later_step_intent() -> None:
    generation = CredentialGeneration.from_secret(A_NEW_1)
    tx = transaction(
        intended=generation, effect=IntentEffectState.OBSERVED,
        suppressed=True, restore_required=True,
    )
    assert tx.credential_mutation_intent is not None
    tx = replace(
        tx,
        credential_mutation_intent=replace(
            tx.credential_mutation_intent,
            step=CredentialMutationStep.RESET_A_KEYSTONE,
        ),
    )
    store = MemoryStateStore(state(tx))
    breeder = FakeBreederSecretClient(breeder_snapshot(
        A_NEW_1, resource_version="124", annotations=staged_annotations(generation),
    ))

    assert_error(
        RotateAStageErrorCode.FINAL_STATE_INVALID, store, passwordsafe(),
        keystone(suppressed=True), breeder,
    )
    current = store.current.state.current_transaction
    assert current is not None
    assert current.credential_mutation_intent is not None
    assert current.credential_mutation_intent.step is CredentialMutationStep.RESET_A_KEYSTONE
    assert breeder.stage_calls == 0


def test_invalid_and_indeterminate_start_block_before_external_mutation() -> None:
    invalid_store = MemoryStateStore(state(transaction()))
    invalid_breeder = FakeBreederSecretClient(breeder_snapshot(A_NEW_1))
    invalid_keystone = keystone()
    assert_error(
        RotateAStageErrorCode.START_INVALID, invalid_store, passwordsafe(),
        invalid_keystone, invalid_breeder,
    )
    assert invalid_keystone.lockout_update_calls == []
    assert invalid_breeder.stage_calls == 0

    indeterminate_store = MemoryStateStore(state(transaction()))
    indeterminate_keystone = keystone()
    indeterminate_keystone.next_auth_indeterminate = KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    indeterminate_breeder = FakeBreederSecretClient(breeder_snapshot())
    assert_error(
        RotateAStageErrorCode.START_INDETERMINATE, indeterminate_store,
        passwordsafe(), indeterminate_keystone, indeterminate_breeder,
    )
    assert indeterminate_keystone.lockout_update_calls == []
    assert indeterminate_breeder.stage_calls == 0


@pytest.mark.parametrize(
    ("alteration", "expected"),
    [
        ("rejected", RotateAStageErrorCode.BREAKGLASS_REJECTED),
        ("indeterminate", RotateAStageErrorCode.BREAKGLASS_AUTH_INDETERMINATE),
        ("user", RotateAStageErrorCode.BREAKGLASS_IDENTITY_MISMATCH),
        ("project", RotateAStageErrorCode.BREAKGLASS_IDENTITY_MISMATCH),
        ("domain", RotateAStageErrorCode.BREAKGLASS_IDENTITY_MISMATCH),
        ("role", RotateAStageErrorCode.BREAKGLASS_IDENTITY_MISMATCH),
        ("expired", RotateAStageErrorCode.BREAKGLASS_IDENTITY_MISMATCH),
    ],
)
def test_breakglass_must_be_fresh_exact_and_authorized(
    alteration: str, expected: RotateAStageErrorCode,
) -> None:
    store = MemoryStateStore(state(transaction()))
    ks = AlteredBreakglassKeystone(alteration)
    add_users(ks, breakglass=(SecretValue(b"wrong") if alteration == "rejected" else B))
    breeder = FakeBreederSecretClient(breeder_snapshot())

    assert_error(expected, store, passwordsafe(), ks, breeder)

    assert ks.lockout_update_calls == []
    assert breeder.stage_calls == 0


def test_lockout_intent_precedes_ownership_and_failed_ownership_is_predispatch() -> None:
    store = MemoryStateStore(state(transaction()))
    ks = keystone()
    breeder = FakeBreederSecretClient(breeder_snapshot())
    owner = Ownership(store, fail_on=1)

    assert_error(
        RotateAStageErrorCode.OWNERSHIP_LOST, store, passwordsafe(), ks,
        breeder, owner,
    )

    tx = store.current.state.current_transaction
    assert tx is not None
    assert tx.lockout.restore_required
    assert tx.lockout.suppression is LockoutChangeState.INTENT_PERSISTED
    assert owner.observed == [(LockoutChangeState.INTENT_PERSISTED, None)]
    assert ks.lockout_update_calls == []
    assert breeder.stage_calls == 0


@pytest.mark.parametrize("apply", [True, False])
def test_ambiguous_lockout_is_reconciled_only_from_positive_readback(apply: bool) -> None:
    store = MemoryStateStore(state(transaction()))
    ks = keystone()
    ks.ambiguous_next_lockout_update_apply = apply
    breeder = FakeBreederSecretClient(breeder_snapshot())

    if apply:
        result = run(store, passwordsafe(), ks, breeder)
        assert result.outcome is RotateAStageOutcome.A1_ESTABLISHED
    else:
        assert_error(
            RotateAStageErrorCode.LOCKOUT_UNRESOLVED, store, passwordsafe(),
            ks, breeder,
        )
        tx = store.current.state.current_transaction
        assert tx is not None
        assert tx.lockout.suppression is LockoutChangeState.DISPATCH_UNRESOLVED
        assert breeder.stage_calls == 0


def test_definite_lockout_rejection_blocks_before_generation() -> None:
    store = MemoryStateStore(state(transaction()))
    ks = keystone()
    ks.next_mutation_error = ExternalErrorCode.AUTHORIZATION_FAILURE
    breeder = FakeBreederSecretClient(breeder_snapshot())
    generated = 0

    def generator() -> SecretValue:
        nonlocal generated
        generated += 1
        return A_NEW_1

    with pytest.raises(RotateAStageError) as raised:
        run_rotate_a_stage_breeder(
            inputs(), state_store=store, ownership=Ownership(store),
            passwordsafe=passwordsafe(), keystone=ks, breeder=breeder,
            password_generator=generator, clock=lambda: NOW,
        )
    assert raised.value.kind is RotateAStageErrorCode.LOCKOUT_MUTATION_FAILED
    assert generated == 0
    assert breeder.stage_calls == 0


def test_resume_after_lockout_applied_before_readback_does_not_rewrite_true() -> None:
    store = MemoryStateStore(state(transaction()))
    ks = add_users(CrashAfterLockoutApply(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    ))
    breeder = FakeBreederSecretClient(breeder_snapshot())

    with pytest.raises(RuntimeError, match="process termination"):
        run(store, passwordsafe(), ks, breeder)
    tx = store.current.state.current_transaction
    assert tx is not None
    assert tx.lockout.suppression is LockoutChangeState.DISPATCH_UNRESOLVED
    assert tx.lockout.restore_required

    result = run(store, passwordsafe(), ks, breeder)
    assert result.outcome is RotateAStageOutcome.A1_ESTABLISHED
    assert ks.lockout_update_calls == [("admin-user", True)]


def test_existing_suppression_requires_durable_restore_intent_and_is_not_rewritten() -> None:
    unmanaged_store = MemoryStateStore(state(transaction()))
    unmanaged_keystone = keystone(suppressed=True)
    unmanaged_breeder = FakeBreederSecretClient(breeder_snapshot())
    assert_error(
        RotateAStageErrorCode.LOCKOUT_UNMANAGED_SUPPRESSION,
        unmanaged_store, passwordsafe(), unmanaged_keystone, unmanaged_breeder,
    )
    assert unmanaged_keystone.lockout_update_calls == []

    managed_store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    managed_keystone = keystone(suppressed=True)
    result = run(
        managed_store, passwordsafe(), managed_keystone,
        FakeBreederSecretClient(breeder_snapshot()),
    )
    assert result.outcome is RotateAStageOutcome.A1_ESTABLISHED
    assert managed_keystone.lockout_update_calls == []


def test_predispatch_candidate_loss_regenerates_after_process_loss() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = FakeBreederSecretClient(breeder_snapshot())
    first_owner = Ownership(store, fail_on=1)

    assert_error(
        RotateAStageErrorCode.OWNERSHIP_LOST, store, ps, ks, breeder,
        first_owner, generated=A_NEW_1,
    )
    first = store.current.state.current_transaction
    assert first is not None
    assert first.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_1)
    assert first.credential_mutation_intent is not None
    assert first.credential_mutation_intent.effect_state is IntentEffectState.UNKNOWN
    assert breeder.stage_calls == 0

    result = run(
        store, ps, ks, breeder, Ownership(store), generated=A_NEW_2,
    )
    current = result.persisted.state.current_transaction
    assert current is not None
    assert current.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_2)
    assert breeder.snapshot.get("password") == A_NEW_2


def test_postdispatch_generation_is_sticky_and_old_breeder_does_not_regenerate() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = FakeBreederSecretClient(breeder_snapshot())
    breeder.ambiguous_next_stage_apply = False

    assert_error(
        RotateAStageErrorCode.BREEDER_UNRESOLVED, store, ps, ks, breeder,
        generated=A_NEW_1,
    )
    intended = CredentialGeneration.from_secret(A_NEW_1)
    calls = 0

    def generator() -> SecretValue:
        nonlocal calls
        calls += 1
        return A_NEW_2

    with pytest.raises(RotateAStageError) as raised:
        run_rotate_a_stage_breeder(
            inputs(), state_store=store, ownership=Ownership(store),
            passwordsafe=ps, keystone=ks, breeder=breeder,
            password_generator=generator, clock=lambda: NOW,
        )
    assert raised.value.kind is RotateAStageErrorCode.BREEDER_UNRESOLVED
    current = store.current.state.current_transaction
    assert current is not None
    assert current.new_a_sha256 == intended
    assert current.credential_mutation_intent is not None
    assert (
        current.credential_mutation_intent.effect_state
        is IntentEffectState.DISPATCH_UNRESOLVED
    )
    assert calls == 0
    assert breeder.stage_calls == 1


def test_breeder_conflict_reobserves_and_never_overwrites_replacement() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    breeder = FakeBreederSecretClient(breeder_snapshot())

    def replace_object(client: FakeBreederSecretClient) -> None:
        client.snapshot = replace(
            client.snapshot, uid="replacement-uid", resource_version="1",
        )

    breeder.before_stage = replace_object
    assert_error(
        RotateAStageErrorCode.BREEDER_IDENTITY_CHANGED, store, passwordsafe(),
        keystone(suppressed=True), breeder,
    )
    assert breeder.snapshot.get("password") == A_OLD


def test_resource_version_conflict_returns_to_predispatch_and_can_regenerate() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = FakeBreederSecretClient(breeder_snapshot())
    breeder.before_stage = lambda client: setattr(
        client, "snapshot", replace(client.snapshot, resource_version="124"),
    )

    assert_error(
        RotateAStageErrorCode.BREEDER_CONFLICT, store, ps, ks, breeder,
        generated=A_NEW_1,
    )
    tx = store.current.state.current_transaction
    assert tx is not None
    assert tx.credential_mutation_intent is not None
    assert tx.credential_mutation_intent.effect_state is IntentEffectState.UNKNOWN
    assert tx.credential_mutation_intent.target is not None
    assert tx.credential_mutation_intent.target.observed_resource_version == "124"
    assert tx.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_1)
    assert breeder.snapshot.get("password") == A_OLD
    assert breeder.stage_calls == 1

    result = run(store, ps, ks, breeder, generated=A_NEW_2)

    current = result.persisted.state.current_transaction
    assert current is not None
    assert result.outcome is RotateAStageOutcome.A1_ESTABLISHED
    assert current.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_2)
    assert breeder.snapshot.get("password") == A_NEW_2
    assert breeder.stage_calls == 2


def test_conditional_rejection_reobserves_independently_staged_intended_a() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    breeder = FakeBreederSecretClient(breeder_snapshot())
    generation = CredentialGeneration.from_secret(A_NEW_1)
    breeder.before_stage = lambda client: setattr(
        client,
        "snapshot",
        replace(
            client.snapshot,
            resource_version="124",
            data=tuple(
                SecretField(item.key, A_NEW_1) if item.key == "password" else item
                for item in client.snapshot.data
            ),
            annotations=(
                *client.snapshot.annotations,
                *staged_annotations(generation),
            ),
        ),
    )

    result = run(store, passwordsafe(), keystone(suppressed=True), breeder)

    assert result.outcome is RotateAStageOutcome.A1_ESTABLISHED
    assert breeder.stage_calls == 1


def test_conditional_rejection_old_a_with_rotation_provenance_fails_closed() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    breeder = FakeBreederSecretClient(breeder_snapshot())
    generation = CredentialGeneration.from_secret(A_NEW_1)
    breeder.before_stage = lambda client: setattr(
        client,
        "snapshot",
        replace(
            client.snapshot,
            resource_version="124",
            annotations=(
                *client.snapshot.annotations,
                *staged_annotations(generation),
            ),
        ),
    )

    assert_error(
        RotateAStageErrorCode.BREEDER_PROVENANCE_MISMATCH,
        store, passwordsafe(), keystone(suppressed=True), breeder,
    )
    tx = store.current.state.current_transaction
    assert tx is not None
    assert tx.credential_mutation_intent is not None
    assert tx.credential_mutation_intent.effect_state is IntentEffectState.UNKNOWN
    assert breeder.snapshot.get("password") == A_OLD
    assert breeder.stage_calls == 1


def test_ambiguous_breeder_apply_is_recognized_by_generation_and_provenance() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    breeder = FakeBreederSecretClient(breeder_snapshot())
    breeder.ambiguous_next_stage_apply = True

    result = run(store, passwordsafe(), keystone(suppressed=True), breeder)

    assert result.outcome is RotateAStageOutcome.A1_ESTABLISHED
    assert breeder.stage_calls == 1


def test_ambiguous_breeder_readback_failure_preserves_unresolved_dispatch() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    breeder = FakeBreederSecretClient(breeder_snapshot())
    breeder.ambiguous_next_stage_apply = True
    breeder.before_stage = lambda client: setattr(
        client, "read_error", BreederErrorCode.READ_FAILED,
    )

    assert_error(
        RotateAStageErrorCode.BREEDER_UNRESOLVED, store, passwordsafe(),
        keystone(suppressed=True), breeder,
    )
    tx = store.current.state.current_transaction
    assert tx is not None
    assert tx.credential_mutation_intent is not None
    assert tx.credential_mutation_intent.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
    assert breeder.stage_calls == 1


def test_unrelated_credential_after_ambiguous_stage_fails_closed() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    breeder = FakeBreederSecretClient(breeder_snapshot())
    breeder.next_mutation_error = BreederErrorCode.OUTCOME_AMBIGUOUS
    breeder.before_stage = lambda client: setattr(
        client, "snapshot", replace(
            client.snapshot,
            data=tuple(
                SecretField(item.key, SecretValue(b"unrelated"))
                if item.key == "password" else item
                for item in client.snapshot.data
            ),
        ),
    )

    assert_error(
        RotateAStageErrorCode.BREEDER_UNKNOWN_CREDENTIAL,
        store, passwordsafe(), keystone(suppressed=True), breeder,
    )


def test_external_reality_ahead_after_staging_returns_a2_without_resetting() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    ks = keystone(suppressed=True)
    breeder = FakeBreederSecretClient(breeder_snapshot())

    def apply_and_advance(client: FakeBreederSecretClient) -> None:
        del client
        # The breeder fake applies immediately after this hook. Arrange
        # Keystone to accept the exact generated candidate before final observe.
        ks.add_user(KeystoneUserObservation(
            "admin-user", "admin", "default-domain", True,
            "admin-project", True,
        ), A_NEW_1)

    breeder.before_stage = apply_and_advance
    result = run(store, passwordsafe(), ks, breeder)

    assert result.outcome is RotateAStageOutcome.AHEAD_OF_SLICE
    assert result.observed_state.value == "A2"
    assert ks.password_update_calls == []


def test_resume_after_breeder_applied_before_readback_uses_observed_a1() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = CrashAfterBreederApply(breeder_snapshot())

    with pytest.raises(RuntimeError, match="process termination"):
        run(store, ps, ks, breeder)
    tx = store.current.state.current_transaction
    assert tx is not None
    assert tx.credential_mutation_intent is not None
    assert tx.credential_mutation_intent.effect_state is IntentEffectState.DISPATCH_UNRESOLVED

    result = run(store, ps, ks, breeder)
    assert result.outcome is RotateAStageOutcome.A1_ALREADY_ESTABLISHED
    assert breeder.stage_calls == 1


def test_resume_after_final_a1_before_completion_write_is_idempotent() -> None:
    store = MemoryStateStore(state(transaction(
        suppressed=True, restore_required=True,
    )))
    store.crash_on_a1_verification = True
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = FakeBreederSecretClient(breeder_snapshot())

    with pytest.raises(RuntimeError, match="process termination"):
        run(store, ps, ks, breeder)
    result = run(store, ps, ks, breeder)

    assert result.outcome is RotateAStageOutcome.A1_ALREADY_ESTABLISHED
    assert breeder.stage_calls == 1
    assert ks.lockout_update_calls == []


def test_result_state_and_errors_do_not_render_credentials_or_tokens() -> None:
    store = MemoryStateStore(state(transaction()))
    result = run(
        store, passwordsafe(), keystone(),
        FakeBreederSecretClient(breeder_snapshot()),
    )
    rendered = repr(result) + json.dumps(
        asdict(result),
        default=lambda value: value.value if isinstance(value, Enum) else str(value),
        sort_keys=True,
    )
    for value in (A_OLD, A_NEW_1, B, access().token):
        assert value.reveal().decode() not in rendered


def test_converge_a1_resets_exact_admin_then_updates_passwordsafe_after_a2() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = staged_breeder()
    owner = Ownership(store)
    original = breeder.snapshot

    result = converge(store, ps, ks, breeder, owner)

    assert result.outcome is RotateAConvergeOutcome.A3_ESTABLISHED
    assert result.starting_state.value == "A1"
    assert result.observed_state.value == "A3"
    assert ks.password_update_calls == ["admin-user"]
    assert ps.update_calls == [(10, 101)]
    assert breeder.snapshot == original
    assert breeder.stage_calls == 0
    assert ps.get_current(
        access=access(), project_id=10, credential_id=101,
    ).password == A_NEW_1
    current = result.persisted.state.current_transaction
    assert current is not None
    assert current.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_1)
    assert current.lockout.latest_ignore_lockout_failure_attempts is True
    assert current.lockout.restore_required
    assert current.phase is RotationPhase.ROTATE_A
    assert owner.observed == [
        (LockoutChangeState.EFFECT_OBSERVED, IntentEffectState.UNKNOWN),
        (LockoutChangeState.EFFECT_OBSERVED, IntentEffectState.UNKNOWN),
    ]
    a2_write = next(
        index for index, persisted in enumerate(store.history)
        if persisted.current_transaction is not None
        and any(
            item.check_id == "slice-3e-a2"
            for item in persisted.current_transaction.verifications
        )
    )
    update_dispatch = next(
        index for index, persisted in enumerate(store.history)
        if persisted.current_transaction is not None
        and persisted.current_transaction.credential_mutation_intent is not None
        and persisted.current_transaction.credential_mutation_intent.step
        is CredentialMutationStep.UPDATE_A_PASSWORDSAFE
        and persisted.current_transaction.credential_mutation_intent.effect_state
        is IntentEffectState.DISPATCH_UNRESOLVED
    )
    assert a2_write < update_dispatch


def test_converge_reset_ownership_failure_is_predispatch_and_resumable() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = staged_breeder()
    owner = Ownership(store, fail_on=1)

    assert_converge_error(
        RotateAConvergeErrorCode.OWNERSHIP_LOST,
        store, ps, ks, breeder, owner,
    )

    blocked = store.current.state.current_transaction
    assert blocked is not None
    assert blocked.credential_mutation_intent is not None
    assert blocked.credential_mutation_intent.step is CredentialMutationStep.RESET_A_KEYSTONE
    assert blocked.credential_mutation_intent.effect_state is IntentEffectState.UNKNOWN
    assert blocked.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_1)
    assert ks.password_update_calls == []

    result = converge(store, ps, ks, breeder)
    assert result.observed_state.value == "A3"
    assert ks.password_update_calls == ["admin-user"]


@pytest.mark.parametrize("apply", [True, False])
def test_converge_ambiguous_keystone_reset_is_resolved_by_observation(
    apply: bool,
) -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    ks.ambiguous_next_password_update_apply = apply

    if apply:
        result = converge(store, ps, ks, staged_breeder())
        assert result.observed_state.value == "A3"
        assert ps.update_calls == [(10, 101)]
    else:
        assert_converge_error(
            RotateAConvergeErrorCode.RESET_A_UNRESOLVED,
            store, ps, ks, staged_breeder(),
        )
        current = store.current.state.current_transaction
        assert current is not None
        assert current.credential_mutation_intent is not None
        assert current.credential_mutation_intent.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
        assert ps.update_calls == []
        assert_converge_error(
            RotateAConvergeErrorCode.RESET_A_UNRESOLVED,
            store, ps, ks, staged_breeder(),
        )
        assert ks.password_update_calls == ["admin-user"]


class BothAcceptedKeystone(FakeKeystoneClient):
    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        result = super().authenticate_password(request)
        if (
            request.username == "admin"
            and request.password == A_OLD
            and self.password_update_calls
        ):
            return super().authenticate_password(replace(request, password=A_NEW_1))
        return result


class IndeterminateAfterResetKeystone(FakeKeystoneClient):
    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        if request.username == "admin" and self.password_update_calls:
            return KeystoneAuthIndeterminate(
                KeystoneIndeterminateReason.DEPENDENCY_FAILURE,
            )
        return super().authenticate_password(request)


@pytest.mark.parametrize(
    ("client_type", "expected"),
    [
        (BothAcceptedKeystone, RotateAConvergeErrorCode.RESET_A_STATE_INVALID),
        (
            IndeterminateAfterResetKeystone,
            RotateAConvergeErrorCode.RESET_A_STATE_INDETERMINATE,
        ),
    ],
)
def test_converge_ambiguous_reset_blocks_invalid_or_indeterminate_auth(
    client_type: type[FakeKeystoneClient], expected: RotateAConvergeErrorCode,
) -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ks = add_users(client_type(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    ), suppressed=True)
    ks.ambiguous_next_password_update_apply = True

    assert_converge_error(expected, store, passwordsafe(), ks, staged_breeder())
    assert ks.password_update_calls == ["admin-user"]


def test_converge_starting_a2_skips_keystone_and_verifies_passwordsafe_readback() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = keystone(admin=A_NEW_1, suppressed=True)

    result = converge(store, ps, ks, staged_breeder())

    assert result.starting_state.value == "A2"
    assert result.observed_state.value == "A3"
    assert ks.password_update_calls == []
    assert ps.update_calls == [(10, 101)]
    # Initial A2 observation, explicit post-PATCH readback, final A3
    # observation, and final lockout validation all use fresh external reads.
    assert ps.get_calls.count((10, 101)) >= 3
    current = result.persisted.state.current_transaction
    assert current is not None
    assert current.passwordsafe.observed_a_record_id == 101
    assert current.passwordsafe.observed_a_version == 8


@pytest.mark.parametrize("apply", [True, False])
def test_converge_ambiguous_passwordsafe_update_is_resolved_by_readback(
    apply: bool,
) -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ps.ambiguous_next_update_apply = apply
    ks = keystone(admin=A_NEW_1, suppressed=True)

    if apply:
        result = converge(store, ps, ks, staged_breeder())
        assert result.observed_state.value == "A3"
    else:
        assert_converge_error(
            RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_UNRESOLVED,
            store, ps, ks, staged_breeder(),
        )
        current = store.current.state.current_transaction
        assert current is not None
        assert current.credential_mutation_intent is not None
        assert current.credential_mutation_intent.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
        assert current.new_a_sha256 == CredentialGeneration.from_secret(A_NEW_1)
        assert_converge_error(
            RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_UNRESOLVED,
            store, ps, ks, staged_breeder(),
        )
        assert ps.update_calls == [(10, 101)]


def test_converge_ambiguous_passwordsafe_unrelated_value_fails_closed() -> None:
    class Client(FakePasswordSafeClient):
        def update_password(
            self, *, access: IdentityAccess, project_id: int,
            credential_id: int, new_password: SecretValue,
        ) -> None:
            del access, new_password
            self.update_calls.append((project_id, credential_id))
            self.add(PasswordSafeCredential(
                project_id, credential_id, "admin", 8,
                SecretValue(b"Unrelated_0123456789abcdefghijkl"),
            ))
            raise ExternalClientError(ExternalErrorCode.MUTATION_AMBIGUOUS)

    store = MemoryStateStore(state(converge_transaction()))
    ps = Client()
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, A_OLD))
    ps.add(PasswordSafeCredential(10, 202, "breakglass", 4, B))
    ks = keystone(admin=A_NEW_1, suppressed=True)

    assert_converge_error(
        RotateAConvergeErrorCode.PASSWORDSAFE_UNRELATED_CREDENTIAL,
        store, ps, ks, staged_breeder(),
    )
    assert ps.update_calls == [(10, 101)]


@pytest.mark.parametrize("target", ["keystone", "passwordsafe"])
def test_converge_definite_rejection_is_not_left_ambiguous(target: str) -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = keystone(
        admin=A_NEW_1 if target == "passwordsafe" else A_OLD,
        suppressed=True,
    )
    if target == "keystone":
        ks.next_mutation_error = ExternalErrorCode.AUTHORIZATION_FAILURE
        expected = RotateAConvergeErrorCode.RESET_A_REJECTED
    else:
        ps.next_update_error = ExternalErrorCode.AUTHORIZATION_FAILURE
        expected = RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_REJECTED

    assert_converge_error(expected, store, ps, ks, staged_breeder())

    current = store.current.state.current_transaction
    assert current is not None
    assert current.credential_mutation_intent is not None
    assert current.credential_mutation_intent.effect_state is IntentEffectState.UNKNOWN
    if target == "passwordsafe":
        assert ps.get_calls.count((10, 101)) >= 2


def test_converge_starting_a3_is_noop_and_preserves_lockout_restore_requirement() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe(admin=A_NEW_1)
    ks = keystone(admin=A_NEW_1, suppressed=True)
    breeder = staged_breeder()

    result = converge(store, ps, ks, breeder)

    assert result.outcome is RotateAConvergeOutcome.A3_ALREADY_ESTABLISHED
    assert result.starting_state.value == "A3"
    assert ks.password_update_calls == []
    assert ps.update_calls == []
    current = result.persisted.state.current_transaction
    assert current is not None
    assert current.lockout.suppression is LockoutChangeState.EFFECT_OBSERVED
    assert current.lockout.latest_ignore_lockout_failure_attempts is True
    assert current.lockout.restore_required
    assert current.lockout.restoration is LockoutChangeState.NOT_INTENDED
    assert current.phase is RotationPhase.ROTATE_A
    assert current.status is TransactionStatus.ACTIVE


def test_converge_a1_requires_fresh_exact_breakglass_before_reset() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ks = AlteredBreakglassKeystone("project")
    add_users(ks, suppressed=True)

    assert_converge_error(
        RotateAConvergeErrorCode.BREAKGLASS_IDENTITY_MISMATCH,
        store, passwordsafe(), ks, staged_breeder(),
    )

    assert ks.password_update_calls == []
    assert ks.lockout_update_calls == []


def test_converge_a0_and_indeterminate_start_are_not_mutated() -> None:
    a0_store = MemoryStateStore(state(converge_transaction()))
    a0_ps = passwordsafe()
    a0_ks = keystone(suppressed=True)
    assert_converge_error(
        RotateAConvergeErrorCode.ILLEGAL_A0_START,
        a0_store, a0_ps, a0_ks,
        FakeBreederSecretClient(breeder_snapshot()),
    )
    assert a0_ks.password_update_calls == []
    assert a0_ps.update_calls == []

    indeterminate_store = MemoryStateStore(state(converge_transaction()))
    indeterminate_ps = passwordsafe()
    indeterminate_ks = keystone(suppressed=True)
    indeterminate_ks.next_auth_indeterminate = (
        KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    )
    assert_converge_error(
        RotateAConvergeErrorCode.START_INDETERMINATE,
        indeterminate_store, indeterminate_ps, indeterminate_ks,
        staged_breeder(),
    )
    assert indeterminate_ks.password_update_calls == []
    assert indeterminate_ps.update_calls == []


@pytest.mark.parametrize(
    ("suppressed", "restore_required", "suppression_state", "expected"),
    [
        (
            False, True, LockoutChangeState.EFFECT_OBSERVED,
            RotateAConvergeErrorCode.LOCKOUT_SUPPRESSION_REQUIRED,
        ),
        (
            True, False, LockoutChangeState.EFFECT_OBSERVED,
            RotateAConvergeErrorCode.LOCKOUT_STATE_INCONSISTENT,
        ),
        (
            True, True, LockoutChangeState.INTENT_PERSISTED,
            RotateAConvergeErrorCode.LOCKOUT_STATE_INCONSISTENT,
        ),
    ],
)
def test_converge_inconsistent_lockout_prerequisite_blocks_all_a_mutation(
    suppressed: bool, restore_required: bool,
    suppression_state: LockoutChangeState,
    expected: RotateAConvergeErrorCode,
) -> None:
    tx = converge_transaction(
        suppressed=suppressed, restore_required=restore_required,
    )
    tx = replace(tx, lockout=replace(tx.lockout, suppression=suppression_state))
    store = MemoryStateStore(state(tx))
    ps = passwordsafe()
    ks = keystone(suppressed=suppressed)

    assert_converge_error(expected, store, ps, ks, staged_breeder())

    assert ks.password_update_calls == []
    assert ps.update_calls == []
    assert ks.lockout_update_calls == []


def test_converge_indeterminate_lockout_observation_blocks_all_a_mutation() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    ks.next_get_user_error = ExternalErrorCode.DEPENDENCY_FAILURE

    assert_converge_error(
        RotateAConvergeErrorCode.LOCKOUT_OBSERVATION_FAILED,
        store, ps, ks, staged_breeder(),
    )

    assert ks.password_update_calls == []
    assert ps.update_calls == []


def test_converge_a2_with_suppression_false_blocks_passwordsafe_mutation() -> None:
    tx = converge_transaction(suppressed=False, restore_required=True)
    store = MemoryStateStore(state(tx))
    ps = passwordsafe()
    ks = keystone(admin=A_NEW_1, suppressed=False)

    assert_converge_error(
        RotateAConvergeErrorCode.LOCKOUT_SUPPRESSION_REQUIRED,
        store, ps, ks, staged_breeder(),
    )

    assert ks.password_update_calls == []
    assert ps.update_calls == []


@pytest.mark.parametrize("mismatch", ["uid", "old", "unrelated", "provenance"])
def test_converge_revalidates_breeder_authority_before_mutation(mismatch: str) -> None:
    store = MemoryStateStore(state(converge_transaction()))
    if mismatch == "uid":
        breeder = staged_breeder(uid="replacement-uid")
        expected = RotateAConvergeErrorCode.BREEDER_IDENTITY_CHANGED
    elif mismatch == "old":
        breeder = staged_breeder(A_OLD)
        expected = RotateAConvergeErrorCode.ILLEGAL_A0_START
    elif mismatch == "unrelated":
        breeder = staged_breeder(
            SecretValue(b"Unrelated_0123456789abcdefghijkl"),
        )
        expected = RotateAConvergeErrorCode.BREEDER_VALUE_MISMATCH
    else:
        wrong = BreederProvenance(
            UUID("99999999-9999-4999-8999-999999999999"),
            CredentialGeneration.from_secret(A_NEW_1),
        ).annotations()
        breeder = staged_breeder(annotations=wrong)
        expected = RotateAConvergeErrorCode.BREEDER_PROVENANCE_MISMATCH
    ps = passwordsafe()
    ks = keystone(suppressed=True)

    assert_converge_error(expected, store, ps, ks, breeder)

    assert ks.password_update_calls == []
    assert ps.update_calls == []


def test_converge_a2_revalidates_breeder_provenance_before_passwordsafe_mutation() -> None:
    wrong = BreederProvenance(
        UUID("99999999-9999-4999-8999-999999999999"),
        CredentialGeneration.from_secret(A_NEW_1),
    ).annotations()
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = keystone(admin=A_NEW_1, suppressed=True)

    assert_converge_error(
        RotateAConvergeErrorCode.BREEDER_PROVENANCE_MISMATCH,
        store, ps, ks, staged_breeder(annotations=wrong),
    )

    assert ps.update_calls == []


def test_converge_recorded_reset_success_cannot_override_fresh_a1() -> None:
    store = MemoryStateStore(state(converge_transaction(
        step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect=IntentEffectState.OBSERVED,
    )))
    ps = passwordsafe()
    ks = keystone(suppressed=True)

    assert_converge_error(
        RotateAConvergeErrorCode.PROGRESS_CONTRADICTS_REALITY,
        store, ps, ks, staged_breeder(),
    )

    assert ks.password_update_calls == []
    assert ps.update_calls == []


@pytest.mark.parametrize("observed", ["A1", "A2", "A3"])
def test_converge_generation_is_immutable_and_breeder_is_never_staged(
    observed: str,
) -> None:
    intended = CredentialGeneration.from_secret(A_NEW_1)
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe(admin=A_NEW_1 if observed == "A3" else A_OLD)
    ks = keystone(
        admin=A_OLD if observed == "A1" else A_NEW_1,
        suppressed=True,
    )
    breeder = staged_breeder()

    result = converge(store, ps, ks, breeder)

    current = result.persisted.state.current_transaction
    assert current is not None
    assert current.new_a_sha256 == intended
    assert breeder.stage_calls == 0
    assert breeder.snapshot.get("password") == A_NEW_1


def test_converge_result_and_errors_do_not_render_secrets() -> None:
    result = converge(
        MemoryStateStore(state(converge_transaction())),
        passwordsafe(), keystone(suppressed=True), staged_breeder(),
    )
    rendered = repr(result) + json.dumps(
        asdict(result),
        default=lambda value: value.value if isinstance(value, Enum) else str(value),
        sort_keys=True,
    )
    error = RotateAConvergeError(RotateAConvergeErrorCode.RESET_A_UNRESOLVED)
    rendered += repr(error) + str(error)
    for value in (A_OLD, A_NEW_1, B, access().token):
        assert value.reveal().decode() not in rendered


def test_converge_resumes_after_reset_intent_persistence() -> None:
    store = CrashOnStateWrite(
        state(converge_transaction()), step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect=IntentEffectState.UNKNOWN,
    )
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)
    assert ks.password_update_calls == []

    result = converge(store, ps, ks, breeder)
    assert result.observed_state.value == "A3"
    assert ks.password_update_calls == ["admin-user"]


def test_converge_dispatch_marker_without_keystone_effect_is_not_blindly_retried() -> None:
    store = CrashOnStateWrite(
        state(converge_transaction()), step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect=IntentEffectState.DISPATCH_UNRESOLVED,
    )
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)
    assert ks.password_update_calls == []

    assert_converge_error(
        RotateAConvergeErrorCode.RESET_A_UNRESOLVED,
        store, ps, ks, breeder,
    )
    assert ks.password_update_calls == []


def test_converge_resumes_after_keystone_reset_applied_before_observation() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = passwordsafe()
    ks = add_users(CrashAfterAdminReset(
        project_id="admin-project", project_name="admin",
        project_domain_id="default-domain",
    ), suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)

    result = converge(store, ps, ks, breeder)
    assert result.starting_state.value == "A2"
    assert result.observed_state.value == "A3"
    assert ks.password_update_calls == ["admin-user"]


def test_converge_resumes_after_a2_observation_before_progress_write() -> None:
    store = CrashOnStateWrite(
        state(converge_transaction()), step=CredentialMutationStep.RESET_A_KEYSTONE,
        effect=IntentEffectState.OBSERVED, before=True,
    )
    ps = passwordsafe()
    ks = keystone(suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)
    current = store.current.state.current_transaction
    assert current is not None
    assert current.credential_mutation_intent is not None
    assert current.credential_mutation_intent.effect_state is IntentEffectState.DISPATCH_UNRESOLVED

    result = converge(store, ps, ks, breeder)
    assert result.starting_state.value == "A2"
    assert result.observed_state.value == "A3"
    assert ks.password_update_calls == ["admin-user"]


def test_converge_resumes_after_passwordsafe_intent_persistence() -> None:
    store = CrashOnStateWrite(
        state(converge_transaction()),
        step=CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
        effect=IntentEffectState.UNKNOWN,
    )
    ps = passwordsafe()
    ks = keystone(admin=A_NEW_1, suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)
    assert ps.update_calls == []

    result = converge(store, ps, ks, breeder)
    assert result.observed_state.value == "A3"
    assert ps.update_calls == [(10, 101)]


def test_converge_dispatch_marker_without_passwordsafe_effect_is_not_retried() -> None:
    store = CrashOnStateWrite(
        state(converge_transaction()),
        step=CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
        effect=IntentEffectState.DISPATCH_UNRESOLVED,
    )
    ps = passwordsafe()
    ks = keystone(admin=A_NEW_1, suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)
    assert ps.update_calls == []

    assert_converge_error(
        RotateAConvergeErrorCode.PASSWORDSAFE_UPDATE_UNRESOLVED,
        store, ps, ks, breeder,
    )
    assert ps.update_calls == []


def test_converge_resumes_after_passwordsafe_apply_before_get_verification() -> None:
    store = MemoryStateStore(state(converge_transaction()))
    ps = CrashAfterPasswordSafeUpdate()
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, A_OLD))
    ps.add(PasswordSafeCredential(10, 202, "breakglass", 4, B))
    ks = keystone(admin=A_NEW_1, suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)

    result = converge(store, ps, ks, breeder)
    assert result.starting_state.value == "A3"
    assert result.observed_state.value == "A3"
    assert ps.update_calls == [(10, 101)]


def test_converge_resumes_after_a3_observation_before_completion_write() -> None:
    store = CrashOnStateWrite(
        state(converge_transaction()), verification="slice-3e-a3", before=True,
    )
    ps = passwordsafe()
    ks = keystone(admin=A_NEW_1, suppressed=True)
    breeder = staged_breeder()

    with pytest.raises(RuntimeError, match="process termination"):
        converge(store, ps, ks, breeder)

    result = converge(store, ps, ks, breeder)
    assert result.starting_state.value == "A3"
    assert result.observed_state.value == "A3"
    assert ps.update_calls == [(10, 101)]
    current = result.persisted.state.current_transaction
    assert current is not None
    assert any(item.check_id == "slice-3e-a3" for item in current.verifications)
