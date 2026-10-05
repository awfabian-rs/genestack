from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from admin_password_rotation.config import parse_contract
from admin_password_rotation.errors import SafeError
from admin_password_rotation.model import (
    CredentialContract, CredentialGeneration, Identity, PersistentState,
    PropagationState, PropagationWave, ReferenceCredentials, SecretField,
    SecretInventory, SecretSnapshot, SecretValue,
)
from admin_password_rotation.propagation import DesiredCredential
from admin_password_rotation.propagation_wave import (
    LocationReconciliationDisposition, PropagationWaveError,
    PropagationWaveErrorCode, PropagationWaveReconciliation,
    WaveReconciliationStatus,
    build_candidate_propagation_wave, persist_propagation_wave_intent,
    plan_or_reconcile_propagation_wave, propagation_contract_digest,
    reconcile_propagation_wave,
)
from admin_password_rotation.state import parse_state_json, serialize_state_json
from admin_password_rotation.state_store import PersistedState, StateRevision, StateStore
from tests.test_state import realistic_state


ADMIN = SecretValue(b"Synthetic-Old-Admin-4B")
BREAKGLASS = SecretValue(b"Synthetic-Breakglass-4B")
REFERENCES = ReferenceCredentials(ADMIN, BREAKGLASS)
ADMIN_GENERATION = CredentialGeneration.from_secret(ADMIN)
BREAKGLASS_GENERATION = CredentialGeneration.from_secret(BREAKGLASS)
OTHER_GENERATION = CredentialGeneration("sha256:" + "f" * 64)


CONTRACT = """namespace: openstack
locations:
  keystone-admin:
    secret: keystone-admin
    identity: admin
    role: source
    representation:
      type: fields
      password: password
    restart: []
  active-one:
    secret: shared-consumers
    identity: active
    role: propagated
    representation:
      type: fields
      username: USER_ONE
      password: PASSWORD_ONE
    restart:
      - deployment/shared-api
  active-two:
    secret: shared-consumers
    identity: active
    role: propagated
    representation:
      type: fields
      username: USER_TWO
      password: PASSWORD_TWO
    restart:
      - deployment/shared-api
      - daemonset/shared-agent
  active-three:
    secret: separate-consumer
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart: []
  fixed-admin:
    secret: fixed-admin-consumer
    identity: admin
    role: propagated
    representation:
      type: fields
      password: password
    restart:
      - deployment/fixed-admin
"""


def snapshot(name: str, data: dict[str, bytes], *, uid: str | None = None) -> SecretSnapshot:
    return SecretSnapshot(
        "openstack", name, uid or f"uid-{name}", "7",
        tuple(
            SecretField(key, SecretValue(value))
            for key, value in sorted(data.items())
        ),
    )


def observed_inventory(
    *, one: Identity = Identity.ADMIN, two: Identity = Identity.ADMIN,
    three: Identity = Identity.ADMIN,
) -> SecretInventory:
    def pair(identity: Identity) -> tuple[bytes, bytes]:
        password = ADMIN if identity is Identity.ADMIN else BREAKGLASS
        return identity.value.encode(), password.reveal()

    user_one, password_one = pair(one)
    user_two, password_two = pair(two)
    user_three, password_three = pair(three)
    return SecretInventory("openstack", "100", (
        snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        snapshot("shared-consumers", {
            "USER_ONE": user_one, "PASSWORD_ONE": password_one,
            "USER_TWO": user_two, "PASSWORD_TWO": password_two,
            "unrelated": b"preserved",
        }),
        snapshot("separate-consumer", {
            "OS_USERNAME": user_three, "OS_PASSWORD": password_three,
        }),
        snapshot("fixed-admin-consumer", {"password": ADMIN.reveal()}),
    ))


def desired(identity: Identity) -> DesiredCredential:
    return DesiredCredential(
        identity, BREAKGLASS if identity is Identity.BREAKGLASS else ADMIN,
    )


def generation(identity: Identity) -> CredentialGeneration:
    return BREAKGLASS_GENERATION if identity is Identity.BREAKGLASS else ADMIN_GENERATION


def contract_with_unsorted_restarts() -> CredentialContract:
    contract = parse_contract(CONTRACT)
    locations = tuple(
        replace(location, restart=tuple(reversed(location.restart)))
        if location.name == "active-two" else location
        for location in contract.locations
    )
    result = replace(contract, locations=locations)
    active_two = next(item for item in result.locations if item.name == "active-two")
    assert tuple(item.label for item in active_two.restart) == (
        "deployment/shared-api", "daemonset/shared-agent",
    )
    return result


def plan(
    identity: Identity = Identity.BREAKGLASS,
    inventory: SecretInventory | None = None,
) -> tuple[PropagationWave, PropagationWaveReconciliation]:
    result = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), inventory or observed_inventory(), REFERENCES,
        desired(identity), generation(identity), PropagationWave((), ()),
    )
    return result.wave, result.reconciliation


def dispositions(
    wave_reconciliation: PropagationWaveReconciliation,
) -> dict[str, LocationReconciliationDisposition]:
    return {
        location.location_id: location.disposition
        for group in wave_reconciliation.secret_groups
        for location in group.locations
    }


def test_breakglass_wave_is_complete_and_excludes_source_and_fixed_admin() -> None:
    wave, reconciliation = plan()
    assert wave.intent is not None
    location_ids = tuple(
        location.location_id
        for group in wave.intent.secret_groups
        for location in group.locations
    )
    assert set(location_ids) == {"active-one", "active-two", "active-three"}
    assert "keystone-admin" not in location_ids
    assert "fixed-admin" not in location_ids
    assert set(dispositions(reconciliation).values()) == {
        LocationReconciliationDisposition.REQUIRES_MUTATION,
    }


def test_admin_wave_includes_active_and_fixed_admin_with_fixed_semantics() -> None:
    wave, reconciliation = plan(Identity.ADMIN)
    assert wave.intent is not None
    location_ids = {
        location.location_id
        for group in wave.intent.secret_groups
        for location in group.locations
    }
    assert location_ids == {
        "active-one", "active-two", "active-three", "fixed-admin",
    }
    assert set(dispositions(reconciliation).values()) == {
        LocationReconciliationDisposition.ALREADY_CONVERGED,
    }


def test_already_target_location_remains_in_intent_and_is_marked_converged() -> None:
    wave, reconciliation = plan(
        inventory=observed_inventory(one=Identity.BREAKGLASS),
    )
    assert wave.intent is not None
    assert dispositions(reconciliation)["active-one"] is (
        LocationReconciliationDisposition.ALREADY_CONVERGED
    )
    assert "active-one" not in {
        item.location_id for item in reconciliation.requires_mutation
    }


def test_same_secret_locations_group_and_different_secrets_do_not() -> None:
    wave, _reconciliation = plan()
    assert wave.intent is not None
    groups = {
        group.secret_name: tuple(item.location_id for item in group.locations)
        for group in wave.intent.secret_groups
    }
    assert groups == {
        "separate-consumer": ("active-three",),
        "shared-consumers": ("active-one", "active-two"),
    }


def test_grouping_and_serialized_intent_order_are_deterministic() -> None:
    contract = parse_contract(CONTRACT)
    first = build_candidate_propagation_wave(
        contract, observed_inventory(), REFERENCES, desired(Identity.BREAKGLASS),
        BREAKGLASS_GENERATION,
    ).durable_intent()
    second = build_candidate_propagation_wave(
        contract, replace(
            observed_inventory(),
            secrets=tuple(reversed(observed_inventory().secrets)),
        ), REFERENCES, desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
    ).durable_intent()
    assert first == second
    assert tuple(group.secret_name for group in first.secret_groups) == (
        "separate-consumer", "shared-consumers",
    )


def test_restart_dependencies_are_canonical_in_durable_intent_and_round_trip() -> None:
    contract = contract_with_unsorted_restarts()
    planned = plan_or_reconcile_propagation_wave(
        contract, observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        PropagationWave((), ()),
    )
    assert planned.wave.intent is not None
    active_two = next(
        location
        for group in planned.wave.intent.secret_groups
        for location in group.locations
        if location.location_id == "active-two"
    )
    assert tuple(
        item.label for item in active_two.potential_restart_dependencies
    ) == ("daemonset/shared-agent", "deployment/shared-api")

    state = realistic_state()
    assert state.current_transaction is not None
    transaction = replace(
        state.current_transaction,
        new_b_sha256=BREAKGLASS_GENERATION,
        credential_mutation_intent=None,
        propagation=replace(
            state.current_transaction.propagation,
            to_b=planned.wave,
        ),
    )
    serialized = serialize_state_json(replace(
        state, current_transaction=transaction,
    ))
    restored = parse_state_json(serialized)
    assert restored.current_transaction is not None
    assert restored.current_transaction.propagation.to_b.intent == planned.wave.intent


def test_restart_order_does_not_change_plan_or_contract_digest() -> None:
    canonical_contract = parse_contract(CONTRACT)
    unsorted_contract = contract_with_unsorted_restarts()
    canonical = build_candidate_propagation_wave(
        canonical_contract, observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
    ).durable_intent()
    unsorted = build_candidate_propagation_wave(
        unsorted_contract, observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
    ).durable_intent()
    assert propagation_contract_digest(unsorted_contract) == (
        propagation_contract_digest(canonical_contract)
    )
    assert unsorted == canonical


def test_restart_metadata_is_potential_only_and_creates_no_action_debt() -> None:
    wave, reconciliation = plan()
    assert wave.runtime_actions == ()
    assert wave.applied_location_ids == ()
    by_location = {
        item.location_id: tuple(workload.label for workload in item.potential_restart_dependencies)
        for group in reconciliation.secret_groups for item in group.locations
    }
    assert by_location["active-one"] == ("deployment/shared-api",)
    assert by_location["active-two"] == (
        "daemonset/shared-agent", "deployment/shared-api",
    )
    assert by_location["active-three"] == ()


def test_durable_wave_round_trip_contains_no_plaintext_credentials() -> None:
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        PropagationWave((), ()),
    )
    state = realistic_state()
    assert state.current_transaction is not None
    transaction = replace(
        state.current_transaction,
        new_b_sha256=BREAKGLASS_GENERATION,
        credential_mutation_intent=None,
        propagation=replace(state.current_transaction.propagation, to_b=planned.wave),
    )
    serialized = serialize_state_json(replace(state, current_transaction=transaction))
    assert BREAKGLASS.reveal().decode() not in serialized
    assert ADMIN.reveal().decode() not in serialized
    assert '"target_identity": "breakglass"' in serialized
    assert '"secret_name": "shared-consumers"' in serialized
    restored = parse_state_json(serialized)
    assert restored.current_transaction is not None
    assert restored.current_transaction.propagation.to_b.intent == planned.wave.intent


def test_existing_intent_is_reused_and_incomplete_target_is_reconciled() -> None:
    original = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        PropagationWave((), ()),
    )
    resumed = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT),
        observed_inventory(one=Identity.BREAKGLASS), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION, original.wave,
    )
    assert not resumed.intent_created
    assert resumed.wave.intent is original.wave.intent
    assert dispositions(resumed.reconciliation)["active-one"] is (
        LocationReconciliationDisposition.ALREADY_CONVERGED
    )


def test_existing_intent_does_not_allow_a_mismatched_generation_argument() -> None:
    wave, _reconciliation = plan()
    with pytest.raises(PropagationWaveError) as raised:
        plan_or_reconcile_propagation_wave(
            parse_contract(CONTRACT), observed_inventory(), REFERENCES,
            desired(Identity.BREAKGLASS), ADMIN_GENERATION, wave,
        )
    assert raised.value.kind is (
        PropagationWaveErrorCode.TARGET_GENERATION_MISMATCH
    )


def test_recorded_complete_progress_cannot_override_fresh_wrong_identity() -> None:
    wave, _reconciliation = plan()
    completed_hint = replace(wave, applied_location_ids=("active-one",))
    result = reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), completed_hint,
    )
    assert result.status is WaveReconciliationStatus.UNSAFE_OBSERVED_STATE
    assert dispositions(result)["active-one"] is (
        LocationReconciliationDisposition.RECORDED_COMPLETE_NOT_CONVERGED
    )


def test_current_state_regression_from_initial_target_contradicts_intent() -> None:
    wave, _reconciliation = plan(
        inventory=observed_inventory(one=Identity.BREAKGLASS),
    )
    result = reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), wave,
    )
    assert dispositions(result)["active-one"] is (
        LocationReconciliationDisposition.CURRENT_STATE_CONTRADICTS_INTENT
    )
    assert not result.safe_to_continue


def test_missing_secret_fails_closed() -> None:
    wave, _reconciliation = plan()
    fresh = replace(
        observed_inventory(),
        secrets=tuple(
            item for item in observed_inventory().secrets
            if item.name != "separate-consumer"
        ),
    )
    result = reconcile_propagation_wave(
        parse_contract(CONTRACT), fresh, REFERENCES,
        desired(Identity.BREAKGLASS), wave,
    )
    assert dispositions(result)["active-three"] is (
        LocationReconciliationDisposition.SECRET_MISSING
    )
    assert not result.safe_to_continue


def test_unknown_credential_state_fails_closed() -> None:
    wave, _reconciliation = plan()
    original = observed_inventory()
    shared = next(item for item in original.secrets if item.name == "shared-consumers")
    bad = replace(shared, data=tuple(
        SecretField(item.key, SecretValue(b"unknown-value"))
        if item.key == "PASSWORD_ONE" else item
        for item in shared.data
    ))
    fresh = replace(
        original,
        secrets=tuple(bad if item.name == bad.name else item for item in original.secrets),
    )
    result = reconcile_propagation_wave(
        parse_contract(CONTRACT), fresh, REFERENCES,
        desired(Identity.BREAKGLASS), wave,
    )
    assert dispositions(result)["active-one"] is (
        LocationReconciliationDisposition.CREDENTIAL_UNKNOWN
    )


def test_unparseable_representation_fails_closed() -> None:
    wave, _reconciliation = plan()
    original = observed_inventory()
    shared = next(item for item in original.secrets if item.name == "shared-consumers")
    bad = replace(
        shared,
        data=tuple(item for item in shared.data if item.key != "PASSWORD_ONE"),
    )
    fresh = replace(
        original,
        secrets=tuple(bad if item.name == bad.name else item for item in original.secrets),
    )
    result = reconcile_propagation_wave(
        parse_contract(CONTRACT), fresh, REFERENCES,
        desired(Identity.BREAKGLASS), wave,
    )
    assert dispositions(result)["active-one"] is (
        LocationReconciliationDisposition.REPRESENTATION_UNPARSEABLE
    )


def test_replaced_secret_is_distinct_even_when_content_matches() -> None:
    wave, _reconciliation = plan()
    original = observed_inventory()
    shared = next(item for item in original.secrets if item.name == "shared-consumers")
    replacement = replace(shared, uid="replacement-uid", resource_version="1")
    fresh = replace(
        original,
        secrets=tuple(
            replacement if item.name == replacement.name else item
            for item in original.secrets
        ),
    )
    result = reconcile_propagation_wave(
        parse_contract(CONTRACT), fresh, REFERENCES,
        desired(Identity.BREAKGLASS), wave,
    )
    assert dispositions(result)["active-one"] is (
        LocationReconciliationDisposition.SECRET_REPLACED
    )
    assert dispositions(result)["active-two"] is (
        LocationReconciliationDisposition.SECRET_REPLACED
    )


@pytest.mark.parametrize(
    "changed_contract",
    [
        CONTRACT.replace("identity: active", "identity: admin", 1),
        CONTRACT.replace("secret: separate-consumer", "secret: moved-consumer"),
        CONTRACT.replace("password: OS_PASSWORD", "password: DIFFERENT_PASSWORD"),
        CONTRACT.replace(
            "    restart:\n      - deployment/shared-api\n",
            "    restart: []\n",
            1,
        ),
        CONTRACT.replace(
            "  fixed-admin:\n",
            "  added-active:\n"
            "    secret: added-consumer\n"
            "    identity: active\n"
            "    role: propagated\n"
            "    representation:\n"
            "      type: fields\n"
            "      username: username\n"
            "      password: password\n"
            "    restart: []\n"
            "  fixed-admin:\n",
        ),
    ],
)
def test_contract_drift_is_detected_without_replanning(changed_contract: str) -> None:
    wave, _reconciliation = plan()
    result = reconcile_propagation_wave(
        parse_contract(changed_contract), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), wave,
    )
    assert result.status is WaveReconciliationStatus.CONTRACT_DRIFT
    assert result.secret_groups == ()


def test_candidate_planning_fails_closed_before_durable_intent() -> None:
    fresh = replace(
        observed_inventory(),
        secrets=tuple(
            item for item in observed_inventory().secrets
            if item.name != "separate-consumer"
        ),
    )
    with pytest.raises(PropagationWaveError) as raised:
        build_candidate_propagation_wave(
            parse_contract(CONTRACT), fresh, REFERENCES,
            desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        )
    assert raised.value.kind is PropagationWaveErrorCode.SECRET_MISSING


class MemoryStateStore(StateStore):
    def __init__(self, current: PersistedState) -> None:
        self.current = current
        self.update_count = 0

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
        return self.current


class Ownership:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.assertions = 0

    @property
    def requires_recovery_gate(self) -> bool:
        return False

    def assert_owned(self) -> None:
        self.assertions += 1
        if self.fail:
            raise SafeError("ownership_lost", "ownership lost")


def transaction_state(
    *, new_a: CredentialGeneration | None = None,
    new_b: CredentialGeneration | None = BREAKGLASS_GENERATION,
) -> PersistedState:
    state = realistic_state()
    assert state.current_transaction is not None
    transaction = replace(
        state.current_transaction,
        new_a_sha256=new_a,
        new_b_sha256=new_b,
        credential_mutation_intent=None,
        propagation=PropagationState(PropagationWave((), ()), PropagationWave((), ())),
    )
    return PersistedState(
        replace(state, current_transaction=transaction),
        StateRevision("openstack", "rotation-state", "state-uid", "1"),
    )


def test_persisting_new_intent_requires_ownership_and_reuses_existing_intent() -> None:
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        PropagationWave((), ()),
    )
    store = MemoryStateStore(transaction_state())
    owner = Ownership()
    persisted = persist_propagation_wave_intent(
        store, owner, store.current, planned,
        recorded_at=datetime(2026, 10, 5, 12, tzinfo=timezone.utc),
    )
    assert owner.assertions == 1
    assert store.update_count == 1
    assert persisted.state.current_transaction is not None
    assert persisted.state.current_transaction.propagation.to_b.intent == planned.wave.intent

    resumed = persist_propagation_wave_intent(
        store, Ownership(fail=True), persisted, planned,
        recorded_at=datetime(2026, 10, 5, 12, 1, tzinfo=timezone.utc),
    )
    assert resumed is persisted
    assert store.update_count == 1


def test_new_intent_is_not_persisted_after_ownership_loss() -> None:
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        PropagationWave((), ()),
    )
    store = MemoryStateStore(transaction_state())
    with pytest.raises(PropagationWaveError) as raised:
        persist_propagation_wave_intent(
            store, Ownership(fail=True), store.current, planned,
            recorded_at=datetime(2026, 10, 5, 12, tzinfo=timezone.utc),
        )
    assert raised.value.kind is PropagationWaveErrorCode.OWNERSHIP_LOST
    assert store.update_count == 0


def test_breakglass_intent_rejects_transaction_generation_mismatch() -> None:
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        PropagationWave((), ()),
    )
    store = MemoryStateStore(transaction_state(new_b=OTHER_GENERATION))
    owner = Ownership()
    with pytest.raises(PropagationWaveError) as raised:
        persist_propagation_wave_intent(
            store, owner, store.current, planned,
            recorded_at=datetime(2026, 10, 5, 12, tzinfo=timezone.utc),
        )
    assert raised.value.kind is (
        PropagationWaveErrorCode.TRANSACTION_GENERATION_MISMATCH
    )
    assert owner.assertions == 0
    assert store.update_count == 0


def test_admin_intent_requires_established_transaction_generation() -> None:
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.ADMIN), ADMIN_GENERATION, PropagationWave((), ()),
    )
    store = MemoryStateStore(transaction_state(new_a=None))
    owner = Ownership()
    with pytest.raises(PropagationWaveError) as raised:
        persist_propagation_wave_intent(
            store, owner, store.current, planned,
            recorded_at=datetime(2026, 10, 5, 12, tzinfo=timezone.utc),
        )
    assert raised.value.kind is (
        PropagationWaveErrorCode.TRANSACTION_GENERATION_MISMATCH
    )
    assert owner.assertions == 0
    assert store.update_count == 0


def test_admin_intent_rejects_transaction_generation_mismatch() -> None:
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.ADMIN), ADMIN_GENERATION, PropagationWave((), ()),
    )
    store = MemoryStateStore(transaction_state(new_a=OTHER_GENERATION))
    owner = Ownership()
    with pytest.raises(PropagationWaveError) as raised:
        persist_propagation_wave_intent(
            store, owner, store.current, planned,
            recorded_at=datetime(2026, 10, 5, 12, tzinfo=timezone.utc),
        )
    assert raised.value.kind is (
        PropagationWaveErrorCode.TRANSACTION_GENERATION_MISMATCH
    )
    assert owner.assertions == 0
    assert store.update_count == 0


def test_admin_intent_persists_when_transaction_generation_matches() -> None:
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), observed_inventory(), REFERENCES,
        desired(Identity.ADMIN), ADMIN_GENERATION, PropagationWave((), ()),
    )
    store = MemoryStateStore(transaction_state(new_a=ADMIN_GENERATION))
    owner = Ownership()
    persisted = persist_propagation_wave_intent(
        store, owner, store.current, planned,
        recorded_at=datetime(2026, 10, 5, 12, tzinfo=timezone.utc),
    )
    assert owner.assertions == 1
    assert store.update_count == 1
    assert persisted.state.current_transaction is not None
    assert persisted.state.current_transaction.propagation.to_a.intent == (
        planned.wave.intent
    )


def test_planning_and_reconciliation_do_not_mutate_secrets_or_create_restarts() -> None:
    inventory = observed_inventory()
    before = inventory
    planned = plan_or_reconcile_propagation_wave(
        parse_contract(CONTRACT), inventory, REFERENCES,
        desired(Identity.BREAKGLASS), BREAKGLASS_GENERATION,
        PropagationWave((), ()),
    )
    assert inventory == before
    assert planned.wave.applied_location_ids == ()
    assert planned.wave.runtime_actions == ()
