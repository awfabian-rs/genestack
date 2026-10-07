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
from admin_password_rotation.propagation import (
    DesiredCredential, FakeCredentialSecretClient, GroupedPropagationError,
    GroupedPropagationErrorCode, GroupedPropagationSession,
    execute_grouped_propagation_wave,
)
from admin_password_rotation.propagation_wave import (
    plan_or_reconcile_propagation_wave,
)
from admin_password_rotation.state_store import PersistedState, StateRevision, StateStore
from tests.test_state import realistic_state


NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
ADMIN = SecretValue(b"Synthetic-Old-Admin-4C")
BREAKGLASS = SecretValue(b"Synthetic-Breakglass-4C")
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


def _fields_contract_text():
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
      - daemonset/shared-agent
  separate:
    secret: separate-consumer
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart: []
"""


def _ini_contract_text():
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
  ini-one:
    secret: ini-consumer
    identity: active
    role: propagated
    representation:
      type: ini
      key: service.conf
      section: service_auth
      username: username
      password: password
    restart:
      - deployment/ini-one
  ini-two:
    secret: ini-consumer
    identity: active
    role: propagated
    representation:
      type: ini
      key: service.conf
      section: second
      username: username
      password: password
    restart:
      - deployment/ini-two
"""


def _fields_secrets(
    *, one: Identity = Identity.ADMIN, two: Identity = Identity.ADMIN,
    three: Identity = Identity.ADMIN,
) -> dict[str, SecretSnapshot]:
    user_one, password_one = _identity_pair(one)
    user_two, password_two = _identity_pair(two)
    user_three, password_three = _identity_pair(three)
    return {
        "keystone-admin": snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        "shared-consumers": snapshot("shared-consumers", {
            "USER_ONE": user_one, "PASSWORD_ONE": password_one,
            "USER_TWO": user_two, "PASSWORD_TWO": password_two,
            "unrelated": b"preserved",
        }),
        "separate-consumer": snapshot("separate-consumer", {
            "OS_USERNAME": user_three, "OS_PASSWORD": password_three,
        }),
    }


def _ini_secrets(
    *, identity: Identity = Identity.ADMIN,
) -> dict[str, SecretSnapshot]:
    username = identity.value.encode()
    password = (ADMIN if identity is Identity.ADMIN else BREAKGLASS).reveal()
    # Two distinct INI options in the same file, each claimed by one location.
    ini = (
        b"# retained comment\n[service_auth]\nusername = " + username
        + b"\npassword = " + password + b"\nregion = DFW\n"
        b"[second]\nusername = " + username
        + b"\npassword = " + password + b"\n"
        b"[database]\npassword = unrelated-db-password\n"
    )
    return {
        "keystone-admin": snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        "ini-consumer": snapshot("ini-consumer", {
            "service.conf": ini, "opaque": b"unchanged",
        }),
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

    def load(self) -> PersistedState:
        return self.current

    def update(self, expected: StateRevision, new_state: PersistentState) -> PersistedState:
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


def _state(
    wave: PropagationWave | None, *,
    identity: Identity = Identity.BREAKGLASS,
) -> PersistedState:
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


def _client(secrets: dict[str, SecretSnapshot]) -> FakeCredentialSecretClient:
    return FakeCredentialSecretClient(*secrets.values())


def _run(
    client: FakeCredentialSecretClient,
    store: MemoryStateStore,
    ownership: Ownership,
    *,
    parsed_contract: CredentialContract,
    secrets: dict[str, SecretSnapshot],
    wave: PropagationWave,
    identity: Identity = Identity.BREAKGLASS,
):
    desired = DesiredCredential(
        identity, BREAKGLASS if identity is Identity.BREAKGLASS else ADMIN,
    )
    session = GroupedPropagationSession(store, store.current)
    return execute_grouped_propagation_wave(
        client, session, ownership,
        contract=parsed_contract, references=_references(secrets),
        desired=desired, wave=wave, now=NOW,
    )


# 1. one location in one Secret mutates successfully.
def test_single_location_single_secret_mutates() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=base, wave=wave)
    # The 'separate' group has exactly one location; it writes once and
    # converges that single location.
    separate = next(g for g in result.groups if g.secret_name == "separate-consumer")
    assert separate.secret_writes == 1
    assert separate.changed_locations == ("separate",)
    final = client.current("openstack", "separate-consumer")
    assert final.get("OS_USERNAME") == SecretValue(b"breakglass")
    assert final.get("OS_PASSWORD") == BREAKGLASS


# 2. multiple logical locations in one Secret produce exactly one Kubernetes write.
def test_multiple_locations_one_secret_one_write() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=base, wave=wave)
    shared = next(g for g in result.groups if g.secret_name == "shared-consumers")
    assert shared.secret_writes == 1
    assert set(shared.changed_locations) == {"shared-one", "shared-two"}


# 3. multiple logical locations on different Secret data keys compose correctly.
def test_different_data_keys_compose() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=base, wave=wave)
    shared = next(g for g in result.groups if g.secret_name == "shared-consumers")
    assert shared.secret_writes == 1
    final = client.current("openstack", "shared-consumers")
    # All four data keys present and unrelated preserved.
    assert final.get("unrelated") == SecretValue(b"preserved")
    assert final.get("USER_ONE") == SecretValue(b"breakglass")
    assert final.get("PASSWORD_ONE") == BREAKGLASS
    assert final.get("USER_TWO") == SecretValue(b"breakglass")
    assert final.get("PASSWORD_TWO") == BREAKGLASS


# 4a. two INI locations in the same file with distinct options cannot be
# safely composed (each serializer re-serializes the whole document from its
# own parse, so the second would clobber the first) -> the group is rejected
# explicitly rather than emitting a wrong document.
def test_conflicting_same_key_overlap_rejected() -> None:
    parsed = contract(_ini_contract_text())
    base = _ini_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.GROUP_COMPOSITION_CONFLICT
    assert client.replace_calls == 0


# 4b. two INI locations in the same file whose selectors resolve to the SAME
# span compose safely (their per-location results are identical).  The overlap
# validator rejects a contract with identical selectors, so the two locations
# are constructed directly to exercise the composition driver's same-value path.
def test_same_key_same_span_composes() -> None:
    from admin_password_rotation.model import (
        CredentialLocation, IdentityBinding, IniRepresentation, LocationRole,
        WorkloadKind, WorkloadRef,
    )
    from admin_password_rotation.propagation import compose_group_replacements

    rep = IniRepresentation("service.conf", "service_auth", "password", "username")
    loc_one = CredentialLocation(
        "ini-one", "ini-consumer", IdentityBinding.ACTIVE,
        LocationRole.PROPAGATED, rep, (WorkloadRef(WorkloadKind.DEPLOYMENT, "ini-one"),),
    )
    loc_two = CredentialLocation(
        "ini-two", "ini-consumer", IdentityBinding.ACTIVE,
        LocationRole.PROPAGATED, rep, (WorkloadRef(WorkloadKind.DEPLOYMENT, "ini-two"),),
    )
    base = _ini_secrets()
    ini_secret = base["ini-consumer"]
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    composed = compose_group_replacements(ini_secret, (loc_one, loc_two), desired)
    assert len(composed) == 1
    assert composed[0].key == "service.conf"
    text_bytes = composed[0].value.reveal()
    assert b"username = breakglass" in text_bytes
    assert b"password = " + BREAKGLASS.reveal() in text_bytes
    assert b"region = DFW" in text_bytes


# 5. unrelated Secret data is preserved.
def test_unrelated_data_preserved() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    final = client.current("openstack", "shared-consumers")
    assert final.get("unrelated") == SecretValue(b"preserved")


# 6. one location already target + one requiring mutation -> one write, changed accounting only the latter.
def test_partial_group_one_write_accounting_only_changed() -> None:
    parsed = contract(_fields_contract_text())
    # Plan from all-admin (both locations need mutation in intent).
    base_all_admin = _fields_secrets()
    wave, _ = _wave_for(parsed, base_all_admin)
    # Fresh state: shared-one already breakglass, shared-two still admin.
    base_fresh = _fields_secrets(one=Identity.BREAKGLASS, two=Identity.ADMIN)
    client = _client(base_fresh)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=base_fresh, wave=wave)
    shared = next(g for g in result.groups if g.secret_name == "shared-consumers")
    assert shared.secret_writes == 1
    assert shared.changed_locations == ("shared-two",)


# 7. all locations already target -> no write.
def test_all_already_target_no_write() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    all_target = _fields_secrets(
        one=Identity.BREAKGLASS, two=Identity.BREAKGLASS, three=Identity.BREAKGLASS,
    )
    client = _client(all_target)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=all_target, wave=wave)
    assert result.secret_writes == 0
    assert result.changed_locations == ()


# 8. unknown member in a group -> no write, fail closed.
def test_unknown_member_fails_closed_no_write() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    # Make shared-one's password unknown while keeping shared-two admin.
    bad = dict(base)
    shared = base["shared-consumers"]
    bad["shared-consumers"] = replace(
        shared,
        data=tuple(
            SecretField(item.key, SecretValue(b"unknown-value"))
            if item.key == "PASSWORD_ONE" else item
            for item in shared.data
        ),
    )
    client = _client(bad)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=bad, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE
    assert client.replace_calls == 0


# 9. malformed member representation -> no write.
def test_malformed_member_fails_closed_no_write() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    bad = dict(base)
    shared = base["shared-consumers"]
    bad["shared-consumers"] = replace(
        shared,
        data=tuple(item for item in shared.data if item.key != "PASSWORD_ONE"),
    )
    client = _client(bad)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=bad, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE
    assert client.replace_calls == 0


# 10. fixed/source semantics cannot be bypassed by grouped execution.
def test_source_semantics_cannot_bypass() -> None:
    # A source-role location must never be mutated.  Build a contract where the
    # canonical source is also named in the wave group; grouped execution must
    # not touch it.  The fields contract's keystone-admin is role: source and
    # is excluded from the wave, so we verify it is never written.
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    assert "keystone-admin" not in {
        loc for group in wave.intent.secret_groups for loc in group.locations
    } if wave.intent else True
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    # keystone-admin must be unchanged.
    final = client.current("openstack", "keystone-admin")
    assert final.get("password") == ADMIN


# 11. current UID differs from persisted observed UID -> safe reconciliation failure.
def test_uid_replacement_fails_closed() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    # Replace the shared-consumers Secret with a different UID but same content.
    replaced = dict(base)
    replaced["shared-consumers"] = replace(
        base["shared-consumers"], uid="replacement-uid", resource_version="1",
    )
    client = _client(replaced)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=replaced, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE
    assert client.replace_calls == 0


# 12. fresh current resourceVersion is used for CAS, not planning-time resourceVersion.
def test_fresh_resource_version_used_for_cas() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    # Bump the resourceVersion of the fresh Secrets so planning-time RV
    # ("7") no longer matches; execution must use the fresh RV.
    bumped = {
        name: replace(sec, resource_version="77") for name, sec in base.items()
    }
    client = _client(bumped)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=bumped, wave=wave)
    # Writes succeeded using the fresh RV; resourceVersion incremented.
    assert result.secret_writes == 2
    assert client.current("openstack", "shared-consumers").resource_version != "77"


# 13. CAS conflict -> no blind retry.
def test_cas_conflict_no_blind_retry() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    # Conflicts only on the first (separate-consumer) write; the second group's
    # write would proceed but the wave already failed on the first conflict.
    client.before_replace = lambda fake: fake.replace_snapshot(replace(
        fake.current("openstack", "separate-consumer"), resource_version="999",
    ))
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.CONFLICT
    assert client.replace_calls == 1  # exactly one attempt, no retry


def _single_group_contract_text():
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
      - daemonset/shared-agent
"""


def _single_group_secrets(
    *, one: Identity = Identity.ADMIN, two: Identity = Identity.ADMIN,
) -> dict[str, SecretSnapshot]:
    user_one, password_one = _identity_pair(one)
    user_two, password_two = _identity_pair(two)
    return {
        "keystone-admin": snapshot("keystone-admin", {"password": ADMIN.reveal()}),
        "shared-consumers": snapshot("shared-consumers", {
            "USER_ONE": user_one, "PASSWORD_ONE": password_one,
            "USER_TWO": user_two, "PASSWORD_TWO": password_two,
            "unrelated": b"preserved",
        }),
    }


# 14. ambiguous write followed by fresh fully-target state -> recover as converged.
def test_ambiguous_then_converged_recovers() -> None:
    parsed = contract(_single_group_contract_text())
    base = _single_group_secrets()
    wave, _ = _wave_for(parsed, base)
    # First run: actually mutate (write succeeds, progress persisted).
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    first = _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    assert first.secret_writes == 1
    assert set(first.changed_locations) == {"shared-one", "shared-two"}
    # Simulate a crash after the write but before the progress write was
    # durable: a fresh process resumes with the fully-converged Secrets and the
    # persisted applied hint.  Recovery: no duplicate write, progress retained.
    converged = _single_group_secrets(one=Identity.BREAKGLASS, two=Identity.BREAKGLASS)
    from dataclasses import replace as _replace
    retained_wave = _replace(wave, applied_location_ids=("shared-one", "shared-two"))
    client2 = _client(converged)
    store2 = MemoryStateStore(_state(retained_wave))
    owner2 = Ownership()
    result = _run(client2, store2, owner2, parsed_contract=parsed,
                  secrets=converged, wave=retained_wave)
    assert result.secret_writes == 0
    assert client2.replace_calls == 0
    # This invocation performed no writes; the reported changed set reflects the
    # retained mutation accounting (locations previously applied and still at
    # target), which is what later restart-debt construction consumes.
    assert set(result.changed_locations) == {"shared-one", "shared-two"}
    assert store2.current.state.current_transaction is not None
    persisted_wave = store2.current.state.current_transaction.propagation.to_b
    assert set(persisted_wave.applied_location_ids) == {"shared-one", "shared-two"}


# 15. ambiguous write followed by unsafe state -> fail closed.
def test_ambiguous_then_unsafe_fails_closed() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    # After an ambiguous write the Secret is in an unsafe (unknown) state.
    unsafe = dict(base)
    shared = base["shared-consumers"]
    unsafe["shared-consumers"] = replace(
        shared,
        data=tuple(
            SecretField(item.key, SecretValue(b"unknown-value"))
            if item.key in ("PASSWORD_ONE", "PASSWORD_TWO") else item
            for item in shared.data
        ),
    )
    client = _client(unsafe)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=unsafe, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE
    assert client.replace_calls == 0


# 16. successful write requires fresh reread.
def test_successful_write_requires_fresh_reread() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    # For each group that wrote, there was a read (pre) and a read (post).
    # 2 groups wrote, 0 groups were no-op: total reads = 2 pre + 2 post = 4.
    assert client.read_calls == 4
    assert result.secret_writes == 2


# 17. post-write one member not target -> verification failure.
def test_post_write_verification_failure() -> None:
    parsed = contract(_single_group_contract_text())
    base = _single_group_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)

    def tamper(fake: FakeCredentialSecretClient) -> None:
        # After the write, revert shared-consumers' PASSWORD_ONE back to admin
        # and persist that to the fake's store so the verification re-read sees
        # the regression.
        current = fake.current("openstack", "shared-consumers")
        fake.replace_snapshot(replace(
            current,
            data=tuple(
                SecretField(item.key, SecretValue(ADMIN.reveal()))
                if item.key == "PASSWORD_ONE" else item
                for item in current.data
            ),
        ))
        fake.secrets[("openstack", "shared-consumers")] = fake.snapshot

    client.after_replace = tamper
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.POST_WRITE_VERIFICATION_FAILED


# 18. Secret replacement after write -> failure.
def test_secret_replaced_after_write_fails() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)

    def recreate(fake: FakeCredentialSecretClient) -> None:
        current = fake.current("openstack", "separate-consumer")
        fake.replace_snapshot(replace(current, uid="recreated-uid"))

    client.after_replace = recreate
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.POST_WRITE_VERIFICATION_FAILED


# 19. crash/recovery: write succeeded but progress not persisted -> no duplicate write on resume.
def test_crash_after_write_before_progress_no_duplicate_write() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    # The Secret is fully converged (write happened) but the wave has no
    # applied progress (crash before persisting).  Resume: no duplicate write.
    converged = _fields_secrets(
        one=Identity.BREAKGLASS, two=Identity.BREAKGLASS, three=Identity.BREAKGLASS,
    )
    client = _client(converged)
    store = MemoryStateStore(_state(wave))  # applied_location_ids == ()
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=converged, wave=wave)
    assert result.secret_writes == 0
    assert client.replace_calls == 0
    assert result.changed_locations == ()


# 20. progress says complete but fresh state regressed -> progress not trusted.
def test_progress_complete_but_regressed_fails_closed() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    assert wave.intent is not None
    all_ids = tuple(
        loc.location_id for g in wave.intent.secret_groups for loc in g.locations
    )
    # Claim all locations complete in progress, but fresh state is all-admin
    # (regressed).
    regressed_wave = replace(wave, applied_location_ids=all_ids)
    regressed = _fields_secrets()
    client = _client(regressed)
    store = MemoryStateStore(_state(regressed_wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed,
             secrets=regressed, wave=regressed_wave)
    assert raised.value.kind is GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE
    assert client.replace_calls == 0


# 21. changed-location accounting survives persistence/resume.
def test_changed_location_accounting_survives_resume() -> None:
    parsed = contract(_single_group_contract_text())
    base = _single_group_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=base, wave=wave)
    # This invocation actually mutated both locations.
    assert set(result.changed_locations) == {"shared-one", "shared-two"}
    # Durable progress records exactly those changed locations.
    assert store.current.state.current_transaction is not None
    persisted = store.current.state.current_transaction.propagation.to_b
    assert set(persisted.applied_location_ids) == {"shared-one", "shared-two"}
    # Resume with the fully-converged Secrets: no further writes, and the
    # persisted changed set is retained (not clobbered to empty).
    converged = _single_group_secrets(one=Identity.BREAKGLASS, two=Identity.BREAKGLASS)
    client2 = _client(converged)
    owner2 = Ownership()
    resume = _run(client2, store, owner2, parsed_contract=parsed,
                  secrets=converged, wave=persisted)
    assert resume.secret_writes == 0
    assert client2.replace_calls == 0
    assert store.current.state.current_transaction is not None
    assert set(
        store.current.state.current_transaction.propagation.to_b.applied_location_ids
    ) == {"shared-one", "shared-two"}


# 22. changed-location restart metadata is retained for later slices but no restarts occur.
def test_restart_metadata_retained_no_restarts() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=base, wave=wave)
    # shared-one (deployment/shared-api) and shared-two (deployment/shared-api,
    # daemonset/shared-agent) changed; separate has no restart deps.
    assert {ref.label for ref in result.restart_dependencies} == {
        "deployment/shared-api", "daemonset/shared-agent",
    }
    # No runtime actions were created.
    assert store.current.state.current_transaction is not None
    assert store.current.state.current_transaction.propagation.to_b.runtime_actions == ()


# 23. Secret groups execute in deterministic sequential order.
def test_groups_execute_in_deterministic_order() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    # Groups are sorted by (namespace, secret_name): separate-consumer, then
    # shared-consumers.
    assert [g.secret_name for g in result.groups] == [
        "separate-consumer", "shared-consumers",
    ]


# 24. no propagation write occurs after ownership loss.
def test_no_write_after_ownership_loss() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership(fail=True)
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.OWNERSHIP_LOST
    assert client.replace_calls == 0


# 25. credentials are absent from repr/error/state/log-facing objects.
def test_credentials_absent_from_diagnostics() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed, secrets=base, wave=wave)
    diagnostic = (
        repr(result) + str(result)
        + "".join(repr(g) + str(g) for g in result.groups)
    )
    assert ADMIN.reveal().decode() not in diagnostic
    assert BREAKGLASS.reveal().decode() not in diagnostic
    # Durable state must not contain plaintext credentials.
    from admin_password_rotation.state import serialize_state_json
    serialized = serialize_state_json(store.current.state)
    assert ADMIN.reveal().decode() not in serialized
    assert BREAKGLASS.reveal().decode() not in serialized


# Contract drift fails closed before any write.
def test_contract_drift_fails_closed() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base)
    # Change the contract (drop a location) so the digest drifts.
    drifted = contract(_fields_contract_text().replace(
        "  shared-two:", "  shared-two-removed:", 1,
    ))
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=drifted, secrets=base, wave=wave)
    assert raised.value.kind is GroupedPropagationErrorCode.CONTRACT_DRIFT
    assert client.replace_calls == 0


# Target generation mismatch fails closed.
def test_generation_mismatch_fails_closed() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    wave, _ = _wave_for(parsed, base, identity=Identity.BREAKGLASS)
    client = _client(base)
    store = MemoryStateStore(_state(wave))
    owner = Ownership()
    # Pass a desired credential whose generation does not match the intent.
    bad_desired = DesiredCredential(Identity.BREAKGLASS, SecretValue(b"other-generation"))
    session = GroupedPropagationSession(store, store.current)
    with pytest.raises(GroupedPropagationError) as raised:
        execute_grouped_propagation_wave(
            client, session, owner, contract=parsed,
            references=_references(base), desired=bad_desired, wave=wave, now=NOW,
        )
    assert raised.value.kind is GroupedPropagationErrorCode.INTENT_MISMATCH
    assert client.replace_calls == 0


# A wave with no intent fails closed.
def test_no_intent_fails_closed() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets()
    no_intent_wave = PropagationWave((), ())
    client = _client(base)
    store = MemoryStateStore(_state(no_intent_wave))
    owner = Ownership()
    with pytest.raises(GroupedPropagationError) as raised:
        _run(client, store, owner, parsed_contract=parsed,
             secrets=base, wave=no_intent_wave)
    assert raised.value.kind is GroupedPropagationErrorCode.INTENT_MISMATCH


# An admin wave (target=admin) converges to admin, preserving the distinction.
def test_admin_wave_converges_to_admin() -> None:
    parsed = contract(_fields_contract_text())
    base = _fields_secrets(
        one=Identity.BREAKGLASS, two=Identity.BREAKGLASS, three=Identity.BREAKGLASS,
    )
    wave, _ = _wave_for(parsed, base, identity=Identity.ADMIN)
    client = _client(base)
    store = MemoryStateStore(_state(wave, identity=Identity.ADMIN))
    owner = Ownership()
    result = _run(client, store, owner, parsed_contract=parsed,
                  secrets=base, wave=wave, identity=Identity.ADMIN)
    assert result.target_identity is Identity.ADMIN
    shared = next(g for g in result.groups if g.secret_name == "shared-consumers")
    assert set(shared.changed_locations) == {"shared-one", "shared-two"}
    final = client.current("openstack", "shared-consumers")
    assert final.get("USER_ONE") == SecretValue(b"admin")
    assert final.get("PASSWORD_ONE") == ADMIN
