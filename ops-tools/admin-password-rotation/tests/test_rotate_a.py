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
from admin_password_rotation.external_http import ExternalErrorCode
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
