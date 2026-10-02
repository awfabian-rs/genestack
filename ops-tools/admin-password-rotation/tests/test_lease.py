from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, cast
from uuid import UUID

import pytest

import admin_password_rotation.lease as lease_module

from admin_password_rotation.lease import (
    AcquisitionKind, ExecutionOwner, KubernetesApiLeaseTransport,
    KubernetesLeaseStore, LeaseDisposition, LeaseError,
    LeaseErrorCode, LeaseObservation, LeaseOwnership, LeaseReference, LeaseRevision,
    LeaseTiming, LeaseTransportError, LeaseTransportErrorCode, classify_lease,
)
from admin_password_rotation.kubernetes_api import KubernetesApiHandle

REFERENCE = LeaseReference("openstack", "keystone-admin-rotation")
TIMING = LeaseTiming()
NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
E1 = ExecutionOwner(UUID("11111111-1111-4111-8111-111111111111"))
E2 = ExecutionOwner(UUID("22222222-2222-4222-8222-222222222222"))
SENTINEL = "DO-NOT-EXPOSE-LEASE-DETAIL"


def lease_resource(
    *, uid: str = "lease-uid-1", resource_version: str = "10",
    holder: str | None = None, duration: int | None = None,
    acquire_time: datetime | None = None, renew_time: datetime | None = None,
    transitions: int | None = None,
) -> dict[str, object]:
    spec: dict[str, object] = {}
    if holder is not None:
        spec["holderIdentity"] = holder
    if duration is not None:
        spec["leaseDurationSeconds"] = duration
    if acquire_time is not None:
        spec["acquireTime"] = acquire_time.isoformat().replace("+00:00", "Z")
    if renew_time is not None:
        spec["renewTime"] = renew_time.isoformat().replace("+00:00", "Z")
    if transitions is not None:
        spec["leaseTransitions"] = transitions
    return {
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {
            "namespace": REFERENCE.namespace,
            "name": REFERENCE.name,
            "uid": uid,
            "resourceVersion": resource_version,
            "labels": {"managed-by": "installer"},
        },
        "spec": spec,
    }


BeforePatch = Callable[["MemoryLeaseTransport"], None]


def no_field_patches() -> list[dict[str, object]]:
    return []


@dataclass
class MemoryLeaseTransport:
    resource: dict[str, object] = field(default_factory=lease_resource)
    exists: bool = True
    read_failure: bool = False
    patch_failure: bool = False
    ambiguous_patch: bool = False
    before_patch: BeforePatch | None = None
    patch_calls: list[dict[str, object]] = field(default_factory=no_field_patches)

    def read(self, reference: LeaseReference) -> bytes:
        assert reference == REFERENCE
        if not self.exists:
            raise LeaseTransportError(LeaseTransportErrorCode.NOT_FOUND)
        if self.read_failure:
            raise LeaseTransportError(LeaseTransportErrorCode.FAILURE)
        return json.dumps(self.resource).encode("utf-8")

    def conditional_patch(
        self, expected: LeaseRevision, *, fields: dict[str, object],
    ) -> None:
        self.patch_calls.append(fields)
        if self.before_patch is not None:
            callback = self.before_patch
            self.before_patch = None
            callback(self)
        if self.patch_failure:
            raise LeaseTransportError(LeaseTransportErrorCode.FAILURE)
        if self.ambiguous_patch:
            raise LeaseTransportError(LeaseTransportErrorCode.OUTCOME_AMBIGUOUS)
        metadata = object_dict(self.resource["metadata"])
        if (
            not self.exists
            or metadata["uid"] != expected.uid
            or metadata["resourceVersion"] != expected.resource_version
        ):
            raise LeaseTransportError(LeaseTransportErrorCode.CONDITIONAL_REJECTED)
        spec = object_dict(self.resource["spec"])
        spec.update(fields)
        metadata["resourceVersion"] = str(int(expected.resource_version) + 1)


def object_dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    raw = cast(dict[object, object], value)
    assert all(isinstance(key, str) for key in raw)
    return cast(dict[str, object], raw)


def store(transport: MemoryLeaseTransport) -> KubernetesLeaseStore:
    return KubernetesLeaseStore(REFERENCE, TIMING, transport)


def held_resource(
    owner: ExecutionOwner = E1, *, renew_time: datetime = NOW,
    uid: str = "lease-uid-1", resource_version: str = "10", transitions: int = 2,
) -> dict[str, object]:
    return lease_resource(
        uid=uid, resource_version=resource_version,
        holder=owner.holder_identity, duration=120,
        acquire_time=NOW - timedelta(minutes=1), renew_time=renew_time,
        transitions=transitions,
    )


@pytest.mark.parametrize(
    "timing",
    [
        LeaseTiming(120, 20, 60),
        LeaseTiming(121, 20.5, 60.5),
    ],
)
def test_timing_accepts_valid_relationship(timing: LeaseTiming) -> None:
    assert timing.lease_duration_seconds > timing.renewal_deadline_seconds


@pytest.mark.parametrize(
    "values",
    [(0, 20, 60), (120, 0, 60), (120, 20, 20), (60, 20, 60), (120, 20, float("nan"))],
)
def test_timing_rejects_invalid_relationship(values: tuple[int, float, float]) -> None:
    with pytest.raises(ValueError):
        LeaseTiming(*values)


@pytest.mark.parametrize(
    ("resource", "owner", "expected"),
    [
        (lease_resource(), E1, LeaseDisposition.UNHELD),
        (held_resource(E1), E1, LeaseDisposition.HELD_BY_SELF),
        (held_resource(E1), E2, LeaseDisposition.HELD_BY_ANOTHER),
        (held_resource(E1, renew_time=NOW - timedelta(seconds=121)), E2, LeaseDisposition.EXPIRED),
    ],
)
def test_observation_classification(
    resource: dict[str, object], owner: ExecutionOwner, expected: LeaseDisposition,
) -> None:
    observed = store(MemoryLeaseTransport(resource)).observe()
    assert classify_lease(observed, owner, now=NOW) is expected


@pytest.mark.parametrize(
    "spec",
    [
        {"holderIdentity": E1.holder_identity, "leaseDurationSeconds": 0, "renewTime": NOW.isoformat()},
        {"holderIdentity": E1.holder_identity, "leaseDurationSeconds": 120},
        {"holderIdentity": E1.holder_identity, "leaseDurationSeconds": "120", "renewTime": NOW.isoformat()},
        {"holderIdentity": E1.holder_identity, "leaseDurationSeconds": 120, "renewTime": "not-time"},
    ],
)
def test_malformed_lease_fails_closed(spec: dict[str, object]) -> None:
    resource = lease_resource()
    resource["spec"] = spec
    with pytest.raises(LeaseError) as raised:
        store(MemoryLeaseTransport(resource)).observe()
    assert raised.value.kind is LeaseErrorCode.MALFORMED


def test_missing_lease_is_distinct() -> None:
    with pytest.raises(LeaseError) as raised:
        store(MemoryLeaseTransport(exists=False)).observe()
    assert raised.value.kind is LeaseErrorCode.MISSING


def test_malformed_lease_error_does_not_echo_payload() -> None:
    resource = lease_resource()
    resource["spec"] = {
        "holderIdentity": SENTINEL,
        "leaseDurationSeconds": 120,
        "renewTime": f"invalid-{SENTINEL}",
    }
    with pytest.raises(LeaseError) as raised:
        store(MemoryLeaseTransport(resource)).observe()
    assert raised.value.kind is LeaseErrorCode.MALFORMED
    assert SENTINEL not in str(raised.value) + repr(raised.value)


def test_fresh_acquisition_sets_owner_times_duration_and_revision() -> None:
    transport = MemoryLeaseTransport()
    acquired = store(transport).acquire(E1, now=NOW)
    assert acquired.kind is AcquisitionKind.FRESH
    assert acquired.observation.holder_identity == E1.holder_identity
    assert acquired.observation.acquire_time == NOW
    assert acquired.observation.renew_time == NOW
    assert acquired.observation.lease_duration_seconds == 120
    assert acquired.observation.lease_transitions == 1
    assert acquired.observation.revision.resource_version == "11"


def test_nonexpired_other_owner_blocks_without_mutation() -> None:
    transport = MemoryLeaseTransport(held_resource(E1))
    with pytest.raises(LeaseError) as raised:
        store(transport).acquire(E2, now=NOW)
    assert raised.value.kind is LeaseErrorCode.HELD_BY_ANOTHER
    assert transport.patch_calls == []


def test_same_owner_reacquisition_renews_without_holder_transition() -> None:
    transport = MemoryLeaseTransport(held_resource(E1, renew_time=NOW - timedelta(seconds=20)))
    acquired = store(transport).acquire(E1, now=NOW)
    assert acquired.kind is AcquisitionKind.CONTINUED
    assert acquired.observation.renew_time == NOW
    assert acquired.observation.lease_transitions == 2


def test_future_observed_renewal_is_treated_as_held_and_not_moved_backward() -> None:
    future = NOW + timedelta(seconds=30)
    transport = MemoryLeaseTransport(held_resource(E1, renew_time=future))
    acquired = store(transport).acquire(E1, now=NOW)
    assert acquired.kind is AcquisitionKind.CONTINUED
    assert acquired.observation.renew_time == future
    assert acquired.observation.lease_transitions == 2


def test_expired_takeover_is_explicit_and_increments_transition() -> None:
    transport = MemoryLeaseTransport(
        held_resource(E1, renew_time=NOW - timedelta(seconds=121)),
    )
    acquired = store(transport).acquire(E2, now=NOW)
    assert acquired.kind is AcquisitionKind.EXPIRED_TAKEOVER
    assert acquired.requires_recovery_gate
    assert acquired.observation.holder_identity == E2.holder_identity
    assert acquired.observation.lease_transitions == 3


def test_concurrent_acquisition_race_does_not_overwrite_winner() -> None:
    def e1_wins(transport: MemoryLeaseTransport) -> None:
        transport.resource = held_resource(E1, resource_version="11", transitions=0)

    transport = MemoryLeaseTransport(before_patch=e1_wins)
    with pytest.raises(LeaseError) as raised:
        store(transport).acquire(E2, now=NOW)
    assert raised.value.kind is LeaseErrorCode.CONFLICT
    assert object_dict(transport.resource["spec"])["holderIdentity"] == E1.holder_identity


def test_renewal_advances_time_and_revision_without_transition() -> None:
    transport = MemoryLeaseTransport(held_resource(E1, renew_time=NOW - timedelta(seconds=20)))
    lease_store = store(transport)
    expected = lease_store.observe()
    renewed = lease_store.renew(expected, E1, now=NOW)
    assert renewed.holder_identity == E1.holder_identity
    assert renewed.renew_time == NOW
    assert renewed.lease_transitions == 2
    assert renewed.revision.resource_version == "11"


@dataclass
class FakeClock:
    monotonic_value: float = 100.0
    wall_value: datetime = NOW

    def monotonic(self) -> float:
        return self.monotonic_value

    def wall(self) -> datetime:
        return self.wall_value

    def advance(self, seconds: float) -> None:
        self.monotonic_value += seconds
        self.wall_value += timedelta(seconds=seconds)


def ownership(
    transport: MemoryLeaseTransport, clock: FakeClock,
) -> LeaseOwnership:
    lease_store = store(transport)
    acquisition = lease_store.acquire(E1, now=clock.wall())
    return LeaseOwnership(
        lease_store, E1, acquisition, TIMING,
        monotonic=clock.monotonic, wall_clock=clock.wall,
    )


@pytest.mark.parametrize("replacement", ["holder", "uid"])
def test_stolen_or_replaced_lease_causes_sticky_loss(replacement: str) -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    guard = ownership(transport, clock)
    if replacement == "holder":
        transport.resource = held_resource(E2, resource_version="12")
    else:
        transport.resource = held_resource(E1, uid="replacement", resource_version="1")
    assert not guard.renew_once()
    assert guard.loss_reason is LeaseErrorCode.OWNERSHIP_LOST
    with pytest.raises(LeaseError, match="lease_ownership_lost"):
        guard.assert_owned()


def test_transient_renewal_failures_become_uncertain_at_deadline() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    guard = ownership(transport, clock)
    transport.read_failure = True
    clock.advance(59)
    assert not guard.renew_once()
    assert guard.loss_reason is None
    clock.advance(1)
    assert not guard.renew_once()
    assert guard.loss_reason is LeaseErrorCode.OWNERSHIP_UNCERTAIN


def test_ambiguous_renewal_outcome_immediately_becomes_uncertain() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    guard = ownership(transport, clock)
    transport.ambiguous_patch = True
    assert not guard.renew_once()
    assert guard.loss_reason is LeaseErrorCode.OWNERSHIP_UNCERTAIN
    assert len(transport.patch_calls) == 2  # acquisition plus one renewal; no retry


def test_concurrent_renewal_change_immediately_becomes_uncertain() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    guard = ownership(transport, clock)

    def e2_wins(current: MemoryLeaseTransport) -> None:
        current.resource = held_resource(E2, resource_version="12", transitions=1)

    transport.before_patch = e2_wins
    assert not guard.renew_once()
    assert guard.loss_reason is LeaseErrorCode.OWNERSHIP_UNCERTAIN
    assert object_dict(transport.resource["spec"])["holderIdentity"] == E2.holder_identity


def test_loss_is_sticky_after_apparently_healthy_observation() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    guard = ownership(transport, clock)
    transport.resource = held_resource(E2, resource_version="12")
    assert not guard.renew_once()
    transport.resource = held_resource(E1, resource_version="13")
    assert not guard.renew_once()
    assert guard.loss_reason is LeaseErrorCode.OWNERSHIP_LOST


def test_assert_owned_uses_monotonic_freshness() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    guard = ownership(transport, clock)
    guard.assert_owned()
    clock.advance(60)
    with pytest.raises(LeaseError) as raised:
        guard.assert_owned()
    assert raised.value.kind is LeaseErrorCode.OWNERSHIP_UNCERTAIN


def test_current_owner_releases_but_lost_owner_never_writes_cleanup() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    guard = ownership(transport, clock)
    guard.close()
    assert object_dict(transport.resource["spec"])["holderIdentity"] is None

    second_transport = MemoryLeaseTransport()
    lost_guard = ownership(second_transport, FakeClock())
    second_transport.resource = held_resource(E2, resource_version="12")
    assert not lost_guard.renew_once()
    writes_before_close = len(second_transport.patch_calls)
    lost_guard.close()
    assert len(second_transport.patch_calls) == writes_before_close
    assert object_dict(second_transport.resource["spec"])["holderIdentity"] == E2.holder_identity


def test_release_race_does_not_clear_new_owner() -> None:
    transport = MemoryLeaseTransport(held_resource(E1))
    lease_store = store(transport)
    expected = lease_store.observe()

    def e2_wins(current: MemoryLeaseTransport) -> None:
        current.resource = held_resource(E2, resource_version="11", transitions=3)

    transport.before_patch = e2_wins
    with pytest.raises(LeaseError) as raised:
        lease_store.release(expected, E1, now=NOW)
    assert raised.value.kind is LeaseErrorCode.CONFLICT
    assert object_dict(transport.resource["spec"])["holderIdentity"] == E2.holder_identity


class ExplodingRenewStore(KubernetesLeaseStore):
    def renew(
        self, expected: LeaseObservation, owner: ExecutionOwner, *, now: datetime,
    ) -> LeaseObservation:
        raise RuntimeError(SENTINEL)


class OneRenewalWaiter:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, event: threading.Event, seconds: float) -> bool:
        del event, seconds
        self.calls += 1
        return self.calls > 1


class RenewThenStopWaiter:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, event: threading.Event, seconds: float) -> bool:
        del seconds
        self.calls += 1
        if self.calls == 1:
            return False
        event.set()
        return True


def test_watchdog_renews_independently_without_real_sleep() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    lease_store = store(transport)
    acquired = lease_store.acquire(E1, now=clock.wall())
    clock.advance(20)
    guard = LeaseOwnership(
        lease_store, E1, acquired, TIMING,
        monotonic=clock.monotonic, wall_clock=clock.wall,
        waiter=RenewThenStopWaiter(),
    )
    guard.start()
    assert guard.wait(timeout=2)
    assert guard.loss_reason is None
    assert object_dict(transport.resource["metadata"])["resourceVersion"] == "12"
    assert object_dict(transport.resource["spec"])["renewTime"] == (
        "2026-10-02T12:00:20.000000Z"
    )
    guard.close(release=False)


def test_unexpected_renewal_worker_failure_is_visible_as_uncertain() -> None:
    clock = FakeClock()
    transport = MemoryLeaseTransport()
    base_store = store(transport)
    acquired = base_store.acquire(E1, now=clock.wall())
    exploding = ExplodingRenewStore(REFERENCE, TIMING, transport)
    waiter = OneRenewalWaiter()
    guard = LeaseOwnership(
        exploding, E1, acquired, TIMING,
        monotonic=clock.monotonic, wall_clock=clock.wall,
        waiter=waiter,
    )
    guard.start()
    assert guard.wait(timeout=2)
    assert guard.loss_reason is LeaseErrorCode.OWNERSHIP_UNCERTAIN


class ApiFailure(Exception):
    def __init__(self, status: int | None) -> None:
        self.status = status
        self.reason = SENTINEL
        self.body = SENTINEL
        super().__init__(SENTINEL)


class IdentitySerializer:
    def sanitize_for_serialization(self, value: object) -> object:
        return value


ReadCall = tuple[str, str, dict[str, object]]
PatchCall = tuple[str, str, list[dict[str, object]], dict[str, object]]


def no_read_calls() -> list[ReadCall]:
    return []


def no_patch_calls() -> list[PatchCall]:
    return []


@dataclass
class RecordingLeaseApi:
    read_result: object = field(default_factory=lease_resource)
    read_error: Exception | None = None
    patch_error: Exception | None = None
    read_calls: list[ReadCall] = field(default_factory=no_read_calls)
    patch_calls: list[PatchCall] = field(default_factory=no_patch_calls)

    def read_namespaced_lease(
        self, name: str, namespace: str, **kwargs: object,
    ) -> object:
        self.read_calls.append((name, namespace, kwargs))
        if self.read_error is not None:
            raise self.read_error
        return self.read_result

    def patch_namespaced_lease(
        self, name: str, namespace: str, body: list[dict[str, object]],
        **kwargs: object,
    ) -> object:
        self.patch_calls.append((name, namespace, body, kwargs))
        if self.patch_error is not None:
            raise self.patch_error
        return self.read_result


def api_transport(api: RecordingLeaseApi) -> KubernetesApiLeaseTransport:
    return KubernetesApiLeaseTransport(api, IdentitySerializer(), timeout=7)


def test_api_adapter_reads_through_coordination_v1_namespaced_lease() -> None:
    api = RecordingLeaseApi()
    raw = api_transport(api).read(REFERENCE)
    assert json.loads(raw) == api.read_result
    assert api.read_calls == [(
        "keystone-admin-rotation", "openstack", {"_request_timeout": 7},
    )]


def test_api_adapter_factory_requests_coordination_v1_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = RecordingLeaseApi()
    calls: list[tuple[str, str | None, Path | None]] = []

    def create_api(
        api_class_name: str, *, context: str | None = None,
        kubeconfig: Path | None = None,
    ) -> KubernetesApiHandle:
        calls.append((api_class_name, context, kubeconfig))
        return KubernetesApiHandle(api, IdentitySerializer())

    monkeypatch.setattr(lease_module, "create_kubernetes_api", create_api)
    transport = KubernetesApiLeaseTransport.from_config(context="lab", timeout=7)
    transport.read(REFERENCE)
    assert calls == [("CoordinationV1Api", "lab", None)]


def test_api_adapter_issues_atomic_uid_resource_version_patch_only() -> None:
    api = RecordingLeaseApi()
    transport = api_transport(api)
    revision = LeaseRevision("openstack", "keystone-admin-rotation", "uid-1", "10")
    fields: dict[str, object] = {
        "holderIdentity": E1.holder_identity,
        "renewTime": "2026-10-02T12:00:00.000000Z",
    }
    transport.conditional_patch(revision, fields=fields)
    assert api.patch_calls == [(
        "keystone-admin-rotation",
        "openstack",
        [
            {"op": "test", "path": "/metadata/uid", "value": "uid-1"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "10"},
            {"op": "add", "path": "/spec/holderIdentity", "value": E1.holder_identity},
            {"op": "add", "path": "/spec/renewTime", "value": "2026-10-02T12:00:00.000000Z"},
        ],
        {"_content_type": "application/json-patch+json", "_request_timeout": 7},
    )]


@pytest.mark.parametrize(
    ("operation", "status", "expected"),
    [
        ("read", 404, LeaseTransportErrorCode.NOT_FOUND),
        ("read", 500, LeaseTransportErrorCode.FAILURE),
        ("patch", 409, LeaseTransportErrorCode.CONDITIONAL_REJECTED),
        ("patch", 422, LeaseTransportErrorCode.CONDITIONAL_REJECTED),
        ("patch", None, LeaseTransportErrorCode.OUTCOME_AMBIGUOUS),
    ],
)
def test_api_adapter_errors_are_typed_and_secret_safe(
    operation: str, status: int | None, expected: LeaseTransportErrorCode,
) -> None:
    error = ApiFailure(status)
    api = RecordingLeaseApi(
        read_error=error if operation == "read" else None,
        patch_error=error if operation == "patch" else None,
    )
    with pytest.raises(LeaseTransportError) as raised:
        if operation == "read":
            api_transport(api).read(REFERENCE)
        else:
            api_transport(api).conditional_patch(
                LeaseRevision("openstack", "keystone-admin-rotation", "uid-1", "10"),
                fields={"holderIdentity": E1.holder_identity},
            )
    assert raised.value.kind is expected
    assert SENTINEL not in str(raised.value) + repr(raised.value)
