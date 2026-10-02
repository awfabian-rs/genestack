from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from uuid import UUID

import pytest

from admin_password_rotation.external_http import ExternalErrorCode
from admin_password_rotation.keystone import (
    FakeKeystoneClient, KeystoneAuthenticationResult, KeystoneAuthIndeterminate,
    KeystoneAuthSuccess, KeystoneIndeterminateReason, KeystonePasswordAuthRequest,
    KeystoneUserObservation,
)
from admin_password_rotation.model import (
    STATE_SCHEMA_VERSION, ConfigurationDigest, CredentialGeneration,
    CredentialMutationIntent, CredentialMutationStep, EnvironmentIdentity,
    ExecutionIdentity, IntentEffectState, PersistentState, ResolvedKeystoneIdentities,
    RotationPhase, SecretInventory, SecretValue, TransactionStatus,
)
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient, IdentityAccess, PasswordSafeCredential,
)
from admin_password_rotation.prepare_b import (
    PrepareBError, PrepareBErrorCode, PrepareBInputs, PrepareBRequest,
    PrepareBState, run_prepare_b,
)
from admin_password_rotation.state import parse_state_json, serialize_state_json
from admin_password_rotation.state_store import PersistedState, StateRevision, StateStore
from tests.helpers import PASSWORD, contract, inventory


NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
ENVIRONMENT = EnvironmentIdentity("dfw-dev", "cluster.local")
A = SecretValue(PASSWORD)
B_OLD = SecretValue(b"SYNTHETIC_Breakglass_Old_000001")
B_NEW = SecretValue(b"BNew_0123456789abcdefghijklmnop")
B_NEWER = SecretValue(b"BNext_0123456789abcdefghijklmno")


class MemoryStateStore(StateStore):
    def __init__(self) -> None:
        self.current = PersistedState(
            PersistentState(STATE_SCHEMA_VERSION, ENVIRONMENT, None, ()),
            StateRevision("openstack", "rotation-state", "state-uid", "1"),
        )
        self.update_count = 0
        self.fail_after_apply: int | None = None
        self.fail_on_observed_step: CredentialMutationStep | None = None
        self.fail_on_switch = False

    def load(self) -> PersistedState:
        return self.current

    def update(
        self, expected: StateRevision, new_state: PersistentState,
    ) -> PersistedState:
        assert expected == self.current.revision
        self.update_count += 1
        self.current = PersistedState(
            new_state,
            replace(expected, resource_version=str(int(expected.resource_version) + 1)),
        )
        if self.fail_after_apply == self.update_count:
            raise RuntimeError("injected process termination")
        transaction = new_state.current_transaction
        if (
            transaction is not None
            and transaction.credential_mutation_intent is not None
            and transaction.credential_mutation_intent.step is self.fail_on_observed_step
            and transaction.credential_mutation_intent.effect_state is IntentEffectState.OBSERVED
        ):
            self.fail_on_observed_step = None
            raise RuntimeError("injected process termination")
        if (
            transaction is not None
            and transaction.phase is RotationPhase.SWITCH_TO_B
            and self.fail_on_switch
        ):
            self.fail_on_switch = False
            raise RuntimeError("injected process termination")
        return self.current


class Ownership:
    def __init__(self, *, recovery: bool = False) -> None:
        self.requires_recovery_gate = recovery
        self.assertions = 0
        self.fail = False

    def assert_owned(self) -> None:
        self.assertions += 1
        if self.fail:
            raise PrepareBError(PrepareBErrorCode.OWNERSHIP_LOST)


class AmbiguousBPasswordSafe(FakePasswordSafeClient):
    def __init__(self, *, apply: bool) -> None:
        super().__init__()
        self.apply = apply
        self.triggered = False

    def update_password(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        new_password: SecretValue,
    ) -> None:
        if credential_id == 202 and not self.triggered:
            self.triggered = True
            self.ambiguous_next_update_apply = self.apply
        super().update_password(
            access=access,
            project_id=project_id,
            credential_id=credential_id,
            new_password=new_password,
        )


class AlteredAuthKeystone(FakeKeystoneClient):
    def __init__(self, *, target: str, alteration: str) -> None:
        super().__init__(
            project_id="admin-project",
            project_name="admin",
            project_domain_id="default-domain",
        )
        self.target = target
        self.alteration = alteration

    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        result = super().authenticate_password(request)
        if request.username != self.target:
            return result
        if self.alteration == "indeterminate":
            return KeystoneAuthIndeterminate(KeystoneIndeterminateReason.DEPENDENCY_FAILURE)
        if not isinstance(result, KeystoneAuthSuccess):
            return result
        observed = result.observation
        if self.alteration == "user":
            observed = replace(observed, user_id="unexpected-user")
        elif self.alteration == "project":
            observed = replace(observed, project_id="unexpected-project")
        elif self.alteration == "domain":
            observed = replace(observed, project_domain_id="unexpected-domain")
        elif self.alteration == "role":
            observed = replace(observed, roles=())
        return replace(result, observation=observed)


class ReadTrackingKeystone(FakeKeystoneClient):
    def __init__(self) -> None:
        super().__init__(
            project_id="admin-project",
            project_name="admin",
            project_domain_id="default-domain",
        )
        self.user_read_calls: list[str] = []

    def get_user(
        self, *, user_id: str, management_token: SecretValue,
    ) -> KeystoneUserObservation:
        self.user_read_calls.append(user_id)
        return super().get_user(user_id=user_id, management_token=management_token)


class CrashAfterApplyPasswordSafe(FakePasswordSafeClient):
    def __init__(self, *, credential_id: int) -> None:
        super().__init__()
        self.credential_id = credential_id
        self.crashed = False

    def update_password(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        new_password: SecretValue,
    ) -> None:
        super().update_password(
            access=access, project_id=project_id, credential_id=credential_id,
            new_password=new_password,
        )
        if credential_id == self.credential_id and not self.crashed:
            self.crashed = True
            raise RuntimeError("injected process termination")


class CrashAfterApplyKeystone(FakeKeystoneClient):
    def __init__(self) -> None:
        super().__init__(
            project_id="admin-project",
            project_name="admin",
            project_domain_id="default-domain",
        )
        self.crashed = False

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


def request() -> PrepareBRequest:
    return PrepareBRequest(
        request_id=UUID("11111111-1111-4111-8111-111111111111"),
        transaction_id=UUID("22222222-2222-4222-8222-222222222222"),
        execution=ExecutionIdentity(
            UUID("33333333-3333-4333-8333-333333333333"), None,
        ),
        environment=ENVIRONMENT,
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=ResolvedKeystoneIdentities(
            admin_user_id="admin-user",
            breakglass_user_id="breakglass-user",
            user_domain_id="default-domain",
            project_id="admin-project",
            project_domain_id="default-domain",
            role_id="admin-role",
        ),
        passwordsafe_project_id=10,
        passwordsafe_a_record_id=101,
        passwordsafe_b_record_id=202,
        project_name="admin",
    )


def access() -> IdentityAccess:
    return IdentityAccess(
        datetime(2030, 1, 1, tzinfo=timezone.utc), SecretValue(b"ps-token"),
    )


def passwordsafe(
    kind: type[FakePasswordSafeClient] = FakePasswordSafeClient,
) -> FakePasswordSafeClient:
    client = kind()
    client.add(PasswordSafeCredential(10, 101, "admin", 7, A))
    client.add(PasswordSafeCredential(10, 202, "breakglass", 3, B_OLD))
    return client


def add_keystone_users(
    client: FakeKeystoneClient, *, lockout: bool = False,
) -> FakeKeystoneClient:
    client.add_user(
        KeystoneUserObservation(
            "admin-user", "admin", "default-domain", True, "admin-project", lockout,
        ),
        A,
    )
    client.add_user(
        KeystoneUserObservation(
            "breakglass-user", "breakglass", "default-domain", True,
            "admin-project", False,
        ),
        B_OLD,
    )
    return client


def keystone(*, lockout: bool = False) -> FakeKeystoneClient:
    return add_keystone_users(FakeKeystoneClient(
        project_id="admin-project",
        project_name="admin",
        project_domain_id="default-domain",
    ), lockout=lockout)


def inputs(*, current_inventory: SecretInventory | None = None) -> PrepareBInputs:
    return PrepareBInputs(
        request(), contract(), inventory() if current_inventory is None else current_inventory,
        access(),
    )


def run(
    store: MemoryStateStore, ps: FakePasswordSafeClient,
    ks: FakeKeystoneClient, owner: Ownership | None = None,
    *, generated: SecretValue = B_NEW,
):
    return run_prepare_b(
        inputs(),
        state_store=store,
        ownership=owner or Ownership(),
        passwordsafe=ps,
        keystone=ks,
        password_generator=lambda: generated,
        clock=lambda: NOW,
    )


def test_b0_to_b2_completes_prepare_b_without_changing_a_or_consumers() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = ReadTrackingKeystone()
    add_keystone_users(ks)
    owner = Ownership()

    result = run(store, ps, ks, owner)

    assert result.state is PrepareBState.B2
    transaction = result.persisted.state.current_transaction
    assert transaction is not None
    assert transaction.phase is RotationPhase.SWITCH_TO_B
    assert transaction.status is TransactionStatus.ACTIVE
    assert transaction.credential_mutation_intent is None
    assert transaction.new_b_sha256 == CredentialGeneration.from_secret(B_NEW)
    assert transaction.new_a_sha256 is None
    assert ps.get_current(
        access=access(), project_id=10, credential_id=101,
    ).password == A
    assert ps.get_current(
        access=access(), project_id=10, credential_id=202,
    ).password == B_NEW
    assert ps.update_calls == [(10, 202)]
    assert ks.password_update_calls == ["breakglass-user"]
    assert ks.lockout_update_calls == []
    assert ks.user_read_calls.count("admin-user") >= 2
    assert owner.assertions == 2
    assert {item.check_id for item in transaction.verifications} == {
        "stable-a", "breakglass-b2",
    }
    encoded = serialize_state_json(result.persisted.state)
    for secret_value in (A, B_OLD, B_NEW):
        assert secret_value.reveal().decode() not in encoded


def test_stable_a_disagreement_blocks_before_transaction_and_all_mutations() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, SecretValue(b"different")))
    ks = keystone()

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    assert raised.value.kind is PrepareBErrorCode.STABLE_A_DISAGREEMENT
    assert store.current.state.current_transaction is None
    assert ps.update_calls == []
    assert ks.password_update_calls == []
    assert ks.lockout_update_calls == []


def test_unexpected_stable_lockout_suppression_fails_closed() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone(lockout=True)

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    assert raised.value.kind is PrepareBErrorCode.LOCKOUT_SUPPRESSED
    assert store.current.state.current_transaction is None
    assert ps.update_calls == []


def test_stable_a_rejected_blocks_before_mutation() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    ks.add_user(
        KeystoneUserObservation(
            "admin-user", "admin", "default-domain", True, "admin-project", False,
        ),
        SecretValue(b"not-the-breeder-password"),
    )

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    assert raised.value.kind is PrepareBErrorCode.A_AUTH_REJECTED
    assert store.current.state.current_transaction is None
    assert ps.update_calls == []


@pytest.mark.parametrize("alteration", ["indeterminate", "user", "project", "domain", "role"])
def test_stable_a_requires_exact_identity_scope_and_determinate_auth(
    alteration: str,
) -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = add_keystone_users(AlteredAuthKeystone(target="admin", alteration=alteration))

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    expected = (
        PrepareBErrorCode.A_AUTH_INDETERMINATE
        if alteration == "indeterminate"
        else PrepareBErrorCode.A_IDENTITY_MISMATCH
    )
    assert raised.value.kind is expected
    assert store.current.state.current_transaction is None
    assert ps.update_calls == []
    assert ks.password_update_calls == []
    assert ks.lockout_update_calls == []


def test_ownership_loss_prevents_first_and_all_later_effects() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    owner = Ownership()
    owner.fail = True

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks, owner)

    assert raised.value.kind is PrepareBErrorCode.OWNERSHIP_LOST
    assert ps.update_calls == []
    assert ks.password_update_calls == []
    assert ks.lockout_update_calls == []


def test_resume_rejects_replaced_breeder_object_before_mutation() -> None:
    store = MemoryStateStore()
    store.fail_after_apply = 1
    ps = passwordsafe()
    ks = keystone()
    with pytest.raises(RuntimeError, match="injected process termination"):
        run(store, ps, ks)

    current_inventory = inventory()
    replaced_breeder = replace(current_inventory.secrets[0], uid="replacement-uid")
    changed_inventory = replace(
        current_inventory,
        secrets=(replaced_breeder, *current_inventory.secrets[1:]),
    )
    store.fail_after_apply = None
    with pytest.raises(PrepareBError) as raised:
        run_prepare_b(
            inputs(current_inventory=changed_inventory),
            state_store=store,
            ownership=Ownership(),
            passwordsafe=ps,
            keystone=ks,
            password_generator=lambda: B_NEW,
            clock=lambda: NOW,
        )

    assert raised.value.kind is PrepareBErrorCode.BREEDER_CHANGED
    assert ps.update_calls == []
    assert ks.password_update_calls == []


def test_ambiguous_passwordsafe_b_stage_that_applied_is_observed_and_continues() -> None:
    store = MemoryStateStore()
    ps = AmbiguousBPasswordSafe(apply=True)
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, A))
    ps.add(PasswordSafeCredential(10, 202, "breakglass", 3, B_OLD))
    result = run(store, ps, keystone())
    assert result.state is PrepareBState.B2
    assert ps.update_calls.count((10, 202)) == 1


def test_ambiguous_passwordsafe_b_stage_not_applied_blocks_same_generation() -> None:
    store = MemoryStateStore()
    ps = AmbiguousBPasswordSafe(apply=False)
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, A))
    ps.add(PasswordSafeCredential(10, 202, "breakglass", 3, B_OLD))

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, keystone())

    assert raised.value.kind is PrepareBErrorCode.PASSWORDSAFE_B_UNRESOLVED
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.new_b_sha256 == CredentialGeneration.from_secret(B_NEW)
    assert transaction.credential_mutation_intent is not None
    assert transaction.credential_mutation_intent.effect_state is IntentEffectState.DISPATCH_UNRESOLVED
    assert ps.update_calls.count((10, 202)) == 1


def test_ambiguous_keystone_reset_that_applied_is_resolved_by_fresh_b_auth() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    ks.ambiguous_next_password_update_apply = True

    result = run(store, ps, ks)

    assert result.state is PrepareBState.B2
    assert ks.password_update_calls == ["breakglass-user"]


def test_ambiguous_keystone_reset_not_applied_blocks_without_new_generation() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    ks.ambiguous_next_password_update_apply = False

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    assert raised.value.kind is PrepareBErrorCode.B_RESET_UNRESOLVED
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.new_b_sha256 == CredentialGeneration.from_secret(B_NEW)
    assert ps.update_calls.count((10, 202)) == 1
    assert ks.password_update_calls == ["breakglass-user"]


@pytest.mark.parametrize("alteration", ["user", "project", "domain", "role"])
def test_b2_requires_exact_breakglass_identity_scope_and_role(alteration: str) -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = add_keystone_users(
        AlteredAuthKeystone(target="breakglass", alteration=alteration),
    )

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    assert raised.value.kind is PrepareBErrorCode.B_IDENTITY_MISMATCH
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.new_b_sha256 == CredentialGeneration.from_secret(B_NEW)
    assert transaction.phase is RotationPhase.PREPARE_B
    assert ps.update_calls.count((10, 202)) == 1


def test_indeterminate_b_auth_blocks_without_reset_or_new_generation() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = add_keystone_users(
        AlteredAuthKeystone(target="breakglass", alteration="indeterminate"),
    )

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    assert raised.value.kind is PrepareBErrorCode.B_AUTH_INDETERMINATE
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.new_b_sha256 == CredentialGeneration.from_secret(B_NEW)
    assert ks.password_update_calls == []


def test_crash_after_candidate_intent_before_dispatch_may_regenerate() -> None:
    store = MemoryStateStore()
    store.fail_after_apply = 3
    ps = passwordsafe()
    ks = keystone()

    with pytest.raises(RuntimeError, match="injected process termination"):
        run(store, ps, ks, generated=B_NEW)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert transaction.credential_mutation_intent is not None
    assert transaction.credential_mutation_intent.effect_state is IntentEffectState.UNKNOWN
    assert ps.update_calls == []

    store.fail_after_apply = None
    result = run(store, ps, ks, generated=B_NEWER)
    assert result.state is PrepareBState.B2
    assert result.persisted.state.current_transaction is not None
    assert result.persisted.state.current_transaction.new_b_sha256 == (
        CredentialGeneration.from_secret(B_NEWER)
    )


def test_crash_after_passwordsafe_b_apply_recovers_same_generation() -> None:
    store = MemoryStateStore()
    ps = CrashAfterApplyPasswordSafe(credential_id=202)
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, A))
    ps.add(PasswordSafeCredential(10, 202, "breakglass", 3, B_OLD))
    ks = keystone()

    with pytest.raises(RuntimeError, match="injected process termination"):
        run(store, ps, ks)
    result = run(store, ps, ks, generated=B_NEWER)

    assert result.state is PrepareBState.B2
    assert result.persisted.state.current_transaction is not None
    assert result.persisted.state.current_transaction.new_b_sha256 == (
        CredentialGeneration.from_secret(B_NEW)
    )
    assert ps.update_calls.count((10, 202)) == 1
    assert ps.update_calls.count((10, 101)) == 0
    assert ks.password_update_calls == ["breakglass-user"]
    assert ks.lockout_update_calls == []


def test_crash_after_passwordsafe_b_readback_recovers_without_restaging() -> None:
    store = MemoryStateStore()
    store.fail_on_observed_step = CredentialMutationStep.STAGE_B_PASSWORDSAFE
    ps = passwordsafe()
    ks = keystone()

    with pytest.raises(RuntimeError, match="injected process termination"):
        run(store, ps, ks)
    result = run(store, ps, ks, generated=B_NEWER)

    assert result.state is PrepareBState.B2
    assert ps.update_calls.count((10, 202)) == 1


def test_crash_after_keystone_b_apply_is_discovered_by_fresh_auth() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = add_keystone_users(CrashAfterApplyKeystone())

    with pytest.raises(RuntimeError, match="injected process termination"):
        run(store, ps, ks)
    result = run(store, ps, ks, generated=B_NEWER)

    assert result.state is PrepareBState.B2
    assert ks.password_update_calls == ["breakglass-user"]
    assert ps.update_calls.count((10, 202)) == 1


def test_crash_after_prepare_b_completion_returns_existing_progress() -> None:
    store = MemoryStateStore()
    store.fail_on_switch = True
    ps = passwordsafe()
    ks = keystone()

    with pytest.raises(RuntimeError, match="injected process termination"):
        run(store, ps, ks)
    result = run(store, ps, ks, generated=B_NEWER)

    assert result.state is PrepareBState.B2
    assert result.already_complete
    assert ps.update_calls.count((10, 202)) == 1
    assert ks.password_update_calls == ["breakglass-user"]


def test_completed_prepare_b_resume_does_not_rotate_b_again() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    first = run(store, ps, ks)
    updates = tuple(ps.update_calls)
    password_updates = tuple(ks.password_update_calls)

    second = run(store, ps, ks, generated=B_NEWER)

    assert first.state is PrepareBState.B2
    assert second.already_complete
    assert tuple(ps.update_calls) == updates
    assert tuple(ks.password_update_calls) == password_updates


def test_observed_b2_in_prepare_phase_performs_no_b_password_write() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    run(store, ps, ks)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    store.current = replace(
        store.current,
        state=replace(
            store.current.state,
            current_transaction=replace(transaction, phase=RotationPhase.PREPARE_B),
        ),
    )
    ps.update_calls.clear()
    ks.password_update_calls.clear()

    result = run(store, ps, ks, generated=B_NEWER)

    assert result.state is PrepareBState.B2
    assert ps.update_calls == []
    assert ks.password_update_calls == []
    assert ks.lockout_update_calls == []


def test_stale_b2_progress_is_reobserved_and_reconciled_with_same_generation() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    run(store, ps, ks)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    store.current = replace(
        store.current,
        state=replace(
            store.current.state,
            current_transaction=replace(transaction, phase=RotationPhase.PREPARE_B),
        ),
    )
    ks.add_user(
        KeystoneUserObservation(
            "breakglass-user", "breakglass", "default-domain", True,
            "admin-project", False,
        ),
        B_OLD,
    )
    ps.update_calls.clear()
    ks.password_update_calls.clear()

    result = run(store, ps, ks, generated=B_NEWER)

    resumed = result.persisted.state.current_transaction
    assert resumed is not None
    assert resumed.new_b_sha256 == CredentialGeneration.from_secret(B_NEW)
    assert ps.update_calls == []
    assert ks.password_update_calls == ["breakglass-user"]
    assert ks.lockout_update_calls == []


def test_resume_b1_uses_passwordsafe_value_and_does_not_generate_another_b() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ks = keystone()
    ks.next_mutation_error = ExternalErrorCode.AUTHORIZATION_FAILURE
    with pytest.raises(PrepareBError):
        run(store, ps, ks)
    transaction = store.current.state.current_transaction
    assert transaction is not None
    generation = transaction.new_b_sha256
    assert generation == CredentialGeneration.from_secret(B_NEW)
    # The definite failed reset is retryable with the exact staged value.
    ks.next_mutation_error = None
    result = run(store, ps, ks, generated=B_NEWER)
    assert result.state is PrepareBState.B2
    assert result.persisted.state.current_transaction is not None
    assert result.persisted.state.current_transaction.new_b_sha256 == generation
    assert ps.update_calls.count((10, 202)) == 1
    assert ps.update_calls.count((10, 101)) == 0
    assert ks.lockout_update_calls == []


def test_definite_passwordsafe_b_staging_failure_blocks_safely() -> None:
    store = MemoryStateStore()
    ps = passwordsafe()
    ps.next_update_error = ExternalErrorCode.AUTHORIZATION_FAILURE
    ks = keystone()

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, ks)

    assert raised.value.kind is PrepareBErrorCode.EXTERNAL_DEPENDENCY
    assert ps.update_calls == [(10, 202)]
    assert ps.get_current(
        access=access(), project_id=10, credential_id=101,
    ).password == A
    assert ks.password_update_calls == []
    assert ks.lockout_update_calls == []


def test_dispatched_passwordsafe_intent_with_old_value_blocks_on_takeover() -> None:
    store = MemoryStateStore()
    ps = AmbiguousBPasswordSafe(apply=False)
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, A))
    ps.add(PasswordSafeCredential(10, 202, "breakglass", 3, B_OLD))
    with pytest.raises(PrepareBError):
        run(store, ps, keystone())
    calls = ps.update_calls.count((10, 202))

    with pytest.raises(PrepareBError) as raised:
        run(store, ps, keystone(), Ownership(recovery=True), generated=B_NEWER)

    assert raised.value.kind is PrepareBErrorCode.PASSWORDSAFE_B_UNRESOLVED
    assert ps.update_calls.count((10, 202)) == calls


def test_state_validator_accepts_dispatch_unresolved_intent() -> None:
    store = MemoryStateStore()
    ps = AmbiguousBPasswordSafe(apply=False)
    ps.add(PasswordSafeCredential(10, 101, "admin", 7, A))
    ps.add(PasswordSafeCredential(10, 202, "breakglass", 3, B_OLD))
    with pytest.raises(PrepareBError):
        run(store, ps, keystone())
    transaction = store.current.state.current_transaction
    assert transaction is not None
    assert isinstance(transaction.credential_mutation_intent, CredentialMutationIntent)
    assert transaction.credential_mutation_intent.step is CredentialMutationStep.STAGE_B_PASSWORDSAFE
    encoded = serialize_state_json(store.current.state)
    assert "dispatch_unresolved" in encoded
    parsed = parse_state_json(encoded)
    assert parsed.current_transaction is not None
    assert parsed.current_transaction.credential_mutation_intent is not None
    assert (
        parsed.current_transaction.credential_mutation_intent.effect_state
        is IntentEffectState.DISPATCH_UNRESOLVED
    )
