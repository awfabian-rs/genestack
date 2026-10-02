from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from admin_password_rotation.model import (
    STATE_SCHEMA_VERSION, EnvironmentIdentity, PersistentState,
)
from admin_password_rotation.state import serialize_state_json
from admin_password_rotation.state_store import (
    KubernetesStateStore, KubectlStateSecretTransport, PersistedState, StateCommandResult,
    StateRevision, StateSecretReference, StateSecretTransportError,
    StateSecretTransportErrorCode, StateStoreError, StateStoreErrorCode,
)

REFERENCE = StateSecretReference("openstack", "keystone-admin-rotation-state")
SECRET_SENTINEL = "DO-NOT-EXPOSE-STATE-PAYLOAD"


def durable_state(environment_id: str = "dfw-dev") -> PersistentState:
    return PersistentState(
        STATE_SCHEMA_VERSION,
        EnvironmentIdentity(environment_id, "cluster.local"),
        None,
        (),
    )


def encoded_state(value: PersistentState) -> str:
    return base64.b64encode(serialize_state_json(value).encode("utf-8")).decode("ascii")


def empty_data() -> dict[str, object]:
    return {}


@dataclass
class MemoryStateSecretTransport:
    reference: StateSecretReference = REFERENCE
    exists: bool = True
    uid: str | None = "state-uid-1"
    resource_version: str | None = "10"
    data: dict[str, object] = field(default_factory=empty_data)
    labels: dict[str, str] = field(default_factory=lambda: {"managed-by": "installer"})
    annotations: dict[str, str] = field(default_factory=lambda: {"keep": "unchanged"})
    raw_override: bytes | None = None
    read_failure: bool = False
    write_failure: bool = False
    ambiguous_write: bool = False
    read_after_write_value: str | None = None
    last_encoded_state: str | None = None
    read_count: int = 0

    def __post_init__(self) -> None:
        if not self.data:
            self.data[self.reference.data_key] = encoded_state(durable_state())

    def read(self, reference: StateSecretReference) -> bytes:
        assert reference == self.reference
        self.read_count += 1
        if self.read_failure:
            raise StateSecretTransportError(StateSecretTransportErrorCode.FAILURE)
        if not self.exists:
            raise StateSecretTransportError(StateSecretTransportErrorCode.NOT_FOUND)
        if self.raw_override is not None:
            return self.raw_override
        metadata: dict[str, object] = {
            "namespace": reference.namespace,
            "name": reference.name,
            "labels": self.labels,
            "annotations": self.annotations,
        }
        if self.uid is not None:
            metadata["uid"] = self.uid
        if self.resource_version is not None:
            metadata["resourceVersion"] = self.resource_version
        return json.dumps({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": metadata,
            "data": self.data,
        }).encode("utf-8")

    def conditional_replace(
        self, expected: StateRevision, *, encoded_state: str,
    ) -> None:
        if self.write_failure:
            raise StateSecretTransportError(StateSecretTransportErrorCode.FAILURE)
        if self.ambiguous_write:
            raise StateSecretTransportError(StateSecretTransportErrorCode.OUTCOME_AMBIGUOUS)
        if (
            not self.exists
            or self.uid != expected.uid
            or self.resource_version != expected.resource_version
        ):
            raise StateSecretTransportError(StateSecretTransportErrorCode.CONDITIONAL_REJECTED)
        self.last_encoded_state = encoded_state
        self.data[self.reference.data_key] = (
            encoded_state if self.read_after_write_value is None else self.read_after_write_value
        )
        self.resource_version = str(int(expected.resource_version) + 1)


def assert_error(
    store: KubernetesStateStore,
    expected: StateStoreErrorCode,
) -> StateStoreError:
    with pytest.raises(StateStoreError) as raised:
        store.load()
    assert raised.value.kind is expected
    return raised.value


def test_load_returns_typed_state_and_exact_kubernetes_revision() -> None:
    transport = MemoryStateSecretTransport()
    loaded = KubernetesStateStore(REFERENCE, transport).load()
    assert loaded == PersistedState(
        durable_state(),
        StateRevision("openstack", "keystone-admin-rotation-state", "state-uid-1", "10"),
    )


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("missing", StateStoreErrorCode.SECRET_MISSING),
        ("key", StateStoreErrorCode.STATE_KEY_MISSING),
        ("uid", StateStoreErrorCode.UID_MISSING),
        ("resource_version", StateStoreErrorCode.RESOURCE_VERSION_MISSING),
    ],
)
def test_missing_state_infrastructure_fails_distinctly(
    change: str, expected: StateStoreErrorCode,
) -> None:
    transport = MemoryStateSecretTransport()
    if change == "missing":
        transport.exists = False
    elif change == "key":
        del transport.data[REFERENCE.data_key]
    elif change == "uid":
        transport.uid = None
    else:
        transport.resource_version = None
    assert_error(KubernetesStateStore(REFERENCE, transport), expected)


@pytest.mark.parametrize(
    "bad_value",
    [
        f"not-base64-{SECRET_SENTINEL}",
        base64.b64encode(b"\xff" + SECRET_SENTINEL.encode()).decode("ascii"),
        base64.b64encode(f"not json {SECRET_SENTINEL}".encode()).decode("ascii"),
        base64.b64encode(
            json.dumps({
                "schema_version": 3,
                "environment": {"environment_id": SECRET_SENTINEL, "cluster_id": "cluster.local"},
                "current_transaction": None,
                "completed_requests": [],
            }).encode()
        ).decode("ascii"),
    ],
)
def test_invalid_persisted_state_is_rejected_without_echoing_payload(bad_value: str) -> None:
    transport = MemoryStateSecretTransport(data={REFERENCE.data_key: bad_value})
    error = assert_error(
        KubernetesStateStore(REFERENCE, transport), StateStoreErrorCode.STATE_INVALID,
    )
    assert SECRET_SENTINEL not in str(error) + repr(error)


@pytest.mark.parametrize("raw", [b"not-json " + SECRET_SENTINEL.encode(), b"[]", b"{}"])
def test_invalid_kubernetes_secret_response_is_secret_safe(raw: bytes) -> None:
    transport = MemoryStateSecretTransport(raw_override=raw)
    error = assert_error(
        KubernetesStateStore(REFERENCE, transport), StateStoreErrorCode.SECRET_INVALID,
    )
    assert SECRET_SENTINEL not in str(error) + repr(error)


def test_conditional_update_advances_revision_and_reads_back_intended_state() -> None:
    transport = MemoryStateSecretTransport()
    store = KubernetesStateStore(REFERENCE, transport)
    observed = store.load()
    intended = durable_state("dfw-prod")
    updated = store.update(observed.revision, intended)
    assert updated.state == intended
    assert updated.revision == StateRevision(
        "openstack", "keystone-admin-rotation-state", "state-uid-1", "11",
    )
    assert transport.read_count == 2


def test_stale_resource_version_fails_without_overwriting_newer_state() -> None:
    transport = MemoryStateSecretTransport()
    store = KubernetesStateStore(REFERENCE, transport)
    runner_a = store.load()
    runner_b = store.load()
    newer = durable_state("runner-b")
    store.update(runner_b.revision, newer)

    with pytest.raises(StateStoreError) as raised:
        store.update(runner_a.revision, durable_state("runner-a"))
    assert raised.value.kind is StateStoreErrorCode.CONFLICT
    assert store.load().state == newer


def test_same_name_secret_replacement_fails_on_uid_change() -> None:
    transport = MemoryStateSecretTransport()
    store = KubernetesStateStore(REFERENCE, transport)
    observed = store.load()
    transport.uid = "replacement-uid"
    transport.resource_version = "1"

    with pytest.raises(StateStoreError) as raised:
        store.update(observed.revision, durable_state("replacement-attempt"))
    assert raised.value.kind is StateStoreErrorCode.IDENTITY_CHANGED


def test_read_after_write_mismatch_fails_closed() -> None:
    transport = MemoryStateSecretTransport(
        read_after_write_value=encoded_state(durable_state("unexpected")),
    )
    store = KubernetesStateStore(REFERENCE, transport)
    observed = store.load()
    with pytest.raises(StateStoreError) as raised:
        store.update(observed.revision, durable_state("intended"))
    assert raised.value.kind is StateStoreErrorCode.READ_AFTER_WRITE_MISMATCH


def test_update_preserves_unrelated_secret_content_and_uses_canonical_serializer() -> None:
    transport = MemoryStateSecretTransport()
    transport.data["other-key"] = base64.b64encode(b"unchanged").decode("ascii")
    original_labels = dict(transport.labels)
    original_annotations = dict(transport.annotations)
    store = KubernetesStateStore(REFERENCE, transport)
    observed = store.load()
    intended = durable_state("next-state")
    store.update(observed.revision, intended)

    assert transport.data["other-key"] == base64.b64encode(b"unchanged").decode("ascii")
    assert transport.labels == original_labels
    assert transport.annotations == original_annotations
    assert transport.last_encoded_state is not None
    assert base64.b64decode(transport.last_encoded_state).decode("utf-8") == serialize_state_json(intended)


def test_ambiguous_write_has_distinct_safe_error() -> None:
    transport = MemoryStateSecretTransport(ambiguous_write=True)
    store = KubernetesStateStore(REFERENCE, transport)
    observed = store.load()
    with pytest.raises(StateStoreError) as raised:
        store.update(observed.revision, durable_state("intended"))
    assert raised.value.kind is StateStoreErrorCode.WRITE_AMBIGUOUS


@pytest.mark.parametrize("operation", ["read", "write"])
def test_kubernetes_dependency_failure_is_distinct(operation: str) -> None:
    transport = MemoryStateSecretTransport()
    store = KubernetesStateStore(REFERENCE, transport)
    if operation == "read":
        transport.read_failure = True
        with pytest.raises(StateStoreError) as raised:
            store.load()
    else:
        observed = store.load()
        transport.write_failure = True
        with pytest.raises(StateStoreError) as raised:
            store.update(observed.revision, durable_state("intended"))
    assert raised.value.kind is StateStoreErrorCode.KUBERNETES_FAILURE


class RecordingStateRunner:
    def __init__(self, results: list[StateCommandResult]) -> None:
        self.results = results
        self.calls: list[tuple[tuple[str, ...], float, bytes | None]] = []

    def run(
        self, argv: tuple[str, ...], timeout: float, stdin: bytes | None,
    ) -> StateCommandResult:
        self.calls.append((argv, timeout, stdin))
        return self.results.pop(0)


def test_kubectl_transport_get_is_explicit_and_context_bound() -> None:
    runner = RecordingStateRunner([StateCommandResult(0, b'{"kind":"Secret"}')])
    transport = KubectlStateSecretTransport(
        context="lab;not-a-shell", kubeconfig=Path("/tmp/test config"), timeout=9, runner=runner,
    )
    assert transport.read(REFERENCE) == b'{"kind":"Secret"}'
    assert runner.calls == [((
        "kubectl", "--context=lab;not-a-shell", "--kubeconfig=/tmp/test config",
        "--namespace=openstack", "--request-timeout=9s", "get", "secret",
        "keystone-admin-rotation-state", "--output=json", "--ignore-not-found",
    ), 9, None)]


def test_kubectl_patch_uses_atomic_uid_and_resource_version_tests() -> None:
    runner = RecordingStateRunner([StateCommandResult(0, b"secret/keystone-admin-rotation-state")])
    transport = KubectlStateSecretTransport(context="lab", timeout=7, runner=runner)
    revision = StateRevision("openstack", "keystone-admin-rotation-state", "uid-1", "10")
    transport.conditional_replace(revision, encoded_state="ZW5jb2RlZA==")
    argv, timeout, stdin = runner.calls[0]
    assert argv == (
        "kubectl", "--context=lab", "--namespace=openstack", "--request-timeout=7s",
        "patch", "secret", "keystone-admin-rotation-state", "--type=json",
        "--patch-file=-", "--output=name",
    )
    assert timeout == 7
    assert "ZW5jb2RlZA==" not in argv
    assert stdin is not None
    assert json.loads(stdin) == [
        {"op": "test", "path": "/metadata/uid", "value": "uid-1"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "10"},
        {"op": "replace", "path": "/data/state.json", "value": "ZW5jb2RlZA=="},
    ]


def test_kubectl_not_found_and_failed_patch_are_typed_without_output() -> None:
    runner = RecordingStateRunner([
        StateCommandResult(0, b""),
        StateCommandResult(1, SECRET_SENTINEL.encode()),
    ])
    transport = KubectlStateSecretTransport(context="lab", runner=runner)
    with pytest.raises(StateSecretTransportError) as missing:
        transport.read(REFERENCE)
    assert missing.value.kind is StateSecretTransportErrorCode.NOT_FOUND
    with pytest.raises(StateSecretTransportError) as rejected:
        transport.conditional_replace(
            StateRevision("openstack", "keystone-admin-rotation-state", "uid", "1"),
            encoded_state="e30=",
        )
    assert rejected.value.kind is StateSecretTransportErrorCode.CONDITIONAL_REJECTED
    assert SECRET_SENTINEL not in str(rejected.value) + repr(rejected.value)
