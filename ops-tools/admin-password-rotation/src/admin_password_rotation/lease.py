"""Cooperative Kubernetes Lease ownership for one rotation execution.

The Lease grants temporary permission to attempt work; it is not hard fencing
against a stale process or an external service. Durable transaction state remains
separate from the observations and local guard in this module.
"""
from __future__ import annotations

import json
import math
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol, Self, cast, runtime_checkable
from uuid import UUID

from .errors import ReadError, SafeError
from .kubernetes_api import create_kubernetes_api, validate_api_options
from .validation import is_object_name, object_mapping

MAX_LEASE_BYTES = 1024 * 1024
DEFAULT_LEASE_API_TIMEOUT_SECONDS = 30.0
_KUBERNETES_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
)


class LeaseErrorCode(Enum):
    MISSING = "lease_missing"
    MALFORMED = "lease_malformed"
    HELD_BY_ANOTHER = "lease_held_by_another"
    CONFLICT = "lease_changed_concurrently"
    IDENTITY_CHANGED = "lease_identity_changed"
    OWNERSHIP_LOST = "lease_ownership_lost"
    OWNERSHIP_UNCERTAIN = "lease_ownership_uncertain"
    KUBERNETES_FAILURE = "lease_kubernetes_failure"
    MUTATION_AMBIGUOUS = "lease_mutation_ambiguous"
    READ_AFTER_WRITE_MISMATCH = "lease_read_after_write_mismatch"


_ERROR_MESSAGES: dict[LeaseErrorCode, str] = {
    LeaseErrorCode.MISSING: "The configured ownership Lease does not exist.",
    LeaseErrorCode.MALFORMED: "The Kubernetes ownership Lease is invalid; content withheld.",
    LeaseErrorCode.HELD_BY_ANOTHER: "The ownership Lease is held by another execution.",
    LeaseErrorCode.CONFLICT: "The ownership Lease changed concurrently; reobserve before retrying.",
    LeaseErrorCode.IDENTITY_CHANGED: "The observed ownership Lease object identity changed.",
    LeaseErrorCode.OWNERSHIP_LOST: "This execution no longer owns the Kubernetes Lease.",
    LeaseErrorCode.OWNERSHIP_UNCERTAIN: "This execution cannot safely establish current Lease ownership.",
    LeaseErrorCode.KUBERNETES_FAILURE: "The Kubernetes Lease operation failed; output withheld.",
    LeaseErrorCode.MUTATION_AMBIGUOUS: "The Lease mutation outcome is ambiguous; ownership is uncertain.",
    LeaseErrorCode.READ_AFTER_WRITE_MISMATCH: "The Lease observed after mutation did not match the intended ownership.",
}


class LeaseError(SafeError):
    def __init__(self, kind: LeaseErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


@dataclass(frozen=True)
class LeaseReference:
    namespace: str
    name: str

    def __post_init__(self) -> None:
        if not is_object_name(self.namespace) or not is_object_name(self.name):
            raise ValueError("Lease namespace and name must be valid Kubernetes object names.")


@dataclass(frozen=True)
class LeaseTiming:
    lease_duration_seconds: int = 120
    renew_interval_seconds: float = 20.0
    renewal_deadline_seconds: float = 60.0

    def __post_init__(self) -> None:
        if any(isinstance(value, bool) for value in (
            self.lease_duration_seconds, self.renew_interval_seconds,
            self.renewal_deadline_seconds,
        )):
            raise ValueError("Lease timing values must be finite numbers.")
        values = (
            float(self.lease_duration_seconds), self.renew_interval_seconds,
            self.renewal_deadline_seconds,
        )
        if any(not math.isfinite(value) for value in values):
            raise ValueError("Lease timing values must be finite numbers.")
        if (
            self.lease_duration_seconds <= 0
            or self.renew_interval_seconds <= 0
            or self.renewal_deadline_seconds <= self.renew_interval_seconds
            or self.lease_duration_seconds <= self.renewal_deadline_seconds
        ):
            raise ValueError(
                "Lease timing requires 0 < renew interval < renewal deadline < lease duration.",
            )


@dataclass(frozen=True)
class ExecutionOwner:
    execution_id: UUID

    @property
    def holder_identity(self) -> str:
        return str(self.execution_id)


@dataclass(frozen=True)
class LeaseRevision:
    namespace: str
    name: str
    uid: str
    resource_version: str

    def __post_init__(self) -> None:
        if not is_object_name(self.namespace) or not is_object_name(self.name):
            raise ValueError("Lease revision namespace and name must be valid object names.")
        if not self.uid or not self.resource_version:
            raise ValueError("Lease revision UID and resourceVersion must be nonempty.")


@dataclass(frozen=True)
class LeaseObservation:
    revision: LeaseRevision
    holder_identity: str | None
    lease_duration_seconds: int | None
    acquire_time: datetime | None
    renew_time: datetime | None
    lease_transitions: int | None


class LeaseDisposition(Enum):
    UNHELD = "unheld"
    HELD_BY_SELF = "held_by_self"
    HELD_BY_ANOTHER = "held_by_another"


class AcquisitionKind(Enum):
    FRESH = "fresh"
    CONTINUED = "continued"
    EXPIRED_TAKEOVER = "expired_takeover"


@dataclass(frozen=True)
class LeaseAcquisition:
    kind: AcquisitionKind
    observation: LeaseObservation

    @property
    def requires_recovery_gate(self) -> bool:
        """An expired-owner takeover is not proof that the old process is fenced."""
        return self.kind is AcquisitionKind.EXPIRED_TAKEOVER


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Lease times must be timezone-aware.")
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or _KUBERNETES_TIMESTAMP.fullmatch(value) is None:
        raise ValueError("Invalid Lease timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise ValueError("Invalid Lease timestamp.") from None
    return _utc(parsed)


def classify_lease(
    observation: LeaseObservation, owner: ExecutionOwner,
) -> LeaseDisposition:
    """Classify the observed holder without making a wall-clock expiry claim."""
    if observation.holder_identity is None:
        return LeaseDisposition.UNHELD
    if observation.lease_duration_seconds is None or observation.renew_time is None:
        raise LeaseError(LeaseErrorCode.MALFORMED)
    if observation.holder_identity == owner.holder_identity:
        return LeaseDisposition.HELD_BY_SELF
    return LeaseDisposition.HELD_BY_ANOTHER


class LeaseTransportErrorCode(Enum):
    NOT_FOUND = "not_found"
    CONDITIONAL_REJECTED = "conditional_rejected"
    OUTCOME_AMBIGUOUS = "outcome_ambiguous"
    FAILURE = "failure"


class LeaseTransportError(Exception):
    def __init__(self, kind: LeaseTransportErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value)


class LeaseTransport(Protocol):
    def read(self, reference: LeaseReference) -> bytes: ...

    def conditional_patch(
        self, expected: LeaseRevision, *, fields: dict[str, object],
    ) -> None: ...


class _CoordinationV1LeaseApi(Protocol):
    def read_namespaced_lease(
        self, name: str, namespace: str, **kwargs: object,
    ) -> object: ...

    def patch_namespaced_lease(
        self, name: str, namespace: str, body: list[dict[str, object]],
        **kwargs: object,
    ) -> object: ...


class _KubernetesSerializer(Protocol):
    def sanitize_for_serialization(self, value: object) -> object: ...


@runtime_checkable
class _HttpStatusError(Protocol):
    status: object


def _http_status(error: Exception) -> int | None:
    if not isinstance(error, _HttpStatusError):
        return None
    status = error.status
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    return status


class KubernetesApiLeaseTransport:
    """Direct CoordinationV1 API adapter using atomic UID/RV JSON Patch tests."""

    def __init__(
        self, api: _CoordinationV1LeaseApi, serializer: _KubernetesSerializer,
        *, timeout: float = DEFAULT_LEASE_API_TIMEOUT_SECONDS,
        timing: LeaseTiming = LeaseTiming(),
    ) -> None:
        validate_api_options(context=None, timeout=timeout)
        if timeout >= timing.renewal_deadline_seconds:
            raise ReadError(
                "invalid_timeout", "Lease API timeout must be less than the renewal deadline.",
            )
        self._api = api
        self._serializer = serializer
        self._timeout = timeout

    @classmethod
    def from_config(
        cls, *, context: str | None = None, kubeconfig: Path | None = None,
        timeout: float = DEFAULT_LEASE_API_TIMEOUT_SECONDS,
        timing: LeaseTiming = LeaseTiming(),
    ) -> Self:
        validate_api_options(context=context, timeout=timeout)
        if timeout >= timing.renewal_deadline_seconds:
            raise ReadError(
                "invalid_timeout", "Lease API timeout must be less than the renewal deadline.",
            )
        try:
            handle = create_kubernetes_api(
                "CoordinationV1Api", context=context, kubeconfig=kubeconfig,
            )
        except Exception:
            raise LeaseTransportError(LeaseTransportErrorCode.FAILURE) from None
        return cls(
            cast(_CoordinationV1LeaseApi, handle.api),
            cast(_KubernetesSerializer, handle.serializer),
            timeout=timeout, timing=timing,
        )

    def read(self, reference: LeaseReference) -> bytes:
        try:
            resource = self._api.read_namespaced_lease(
                reference.name, reference.namespace, _request_timeout=self._timeout,
            )
        except Exception as exc:
            kind = (
                LeaseTransportErrorCode.NOT_FOUND
                if _http_status(exc) == 404 else LeaseTransportErrorCode.FAILURE
            )
            raise LeaseTransportError(kind) from None
        try:
            normalized = self._serializer.sanitize_for_serialization(resource)
            return json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except Exception:
            raise LeaseTransportError(LeaseTransportErrorCode.FAILURE) from None

    def conditional_patch(
        self, expected: LeaseRevision, *, fields: dict[str, object],
    ) -> None:
        patch: list[dict[str, object]] = [
            {"op": "test", "path": "/metadata/uid", "value": expected.uid},
            {
                "op": "test", "path": "/metadata/resourceVersion",
                "value": expected.resource_version,
            },
        ]
        patch.extend(
            {"op": "add", "path": f"/spec/{name}", "value": value}
            for name, value in fields.items()
        )
        try:
            self._api.patch_namespaced_lease(
                expected.name,
                expected.namespace,
                patch,
                _content_type="application/json-patch+json",
                _request_timeout=self._timeout,
            )
        except Exception as exc:
            kind = (
                LeaseTransportErrorCode.CONDITIONAL_REJECTED
                if (_http_status(exc) or 0) > 0
                else LeaseTransportErrorCode.OUTCOME_AMBIGUOUS
            )
            raise LeaseTransportError(kind) from None


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def _optional_integer(value: object, *, positive: bool) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("Invalid Lease integer.")
    if (positive and value <= 0) or (not positive and value < 0):
        raise ValueError("Invalid Lease integer.")
    return value


def _parse_lease(raw: bytes, reference: LeaseReference) -> LeaseObservation:
    if len(raw) > MAX_LEASE_BYTES:
        raise LeaseError(LeaseErrorCode.MALFORMED)
    try:
        value: object = json.loads(raw, object_pairs_hook=_json_pairs)
        root = object_mapping(value)
        if root.get("apiVersion") != "coordination.k8s.io/v1" or root.get("kind") != "Lease":
            raise ValueError("Invalid Lease kind.")
        metadata = object_mapping(root.get("metadata"))
        if metadata.get("namespace") != reference.namespace or metadata.get("name") != reference.name:
            raise ValueError("Invalid Lease identity.")
        uid = metadata.get("uid")
        resource_version = metadata.get("resourceVersion")
        if not isinstance(uid, str) or not uid:
            raise ValueError("Missing Lease UID.")
        if not isinstance(resource_version, str) or not resource_version:
            raise ValueError("Missing Lease resourceVersion.")
        spec = object_mapping(root.get("spec"))
        holder_value = spec.get("holderIdentity")
        if holder_value is not None and not isinstance(holder_value, str):
            raise ValueError("Invalid Lease holder.")
        if isinstance(holder_value, str) and (
            len(holder_value) > 128 or any(ord(char) < 32 for char in holder_value)
        ):
            raise ValueError("Invalid Lease holder.")
        holder = holder_value or None
        duration = _optional_integer(spec.get("leaseDurationSeconds"), positive=True)
        acquire_time = _parse_timestamp(spec.get("acquireTime"))
        renew_time = _parse_timestamp(spec.get("renewTime"))
        transitions = _optional_integer(spec.get("leaseTransitions"), positive=False)
        if holder is not None and (duration is None or renew_time is None):
            raise ValueError("Held Lease is missing expiry fields.")
        return LeaseObservation(
            LeaseRevision(reference.namespace, reference.name, uid, resource_version),
            holder, duration, acquire_time, renew_time, transitions,
        )
    except LeaseError:
        raise
    except (ReadError, ValueError, UnicodeError, RecursionError):
        raise LeaseError(LeaseErrorCode.MALFORMED) from None


@dataclass(frozen=True)
class _ForeignLeaseRecord:
    uid: str
    holder_identity: str
    resource_version: str


@dataclass(frozen=True)
class _ForeignLeaseObservationWindow:
    record: _ForeignLeaseRecord
    first_seen_monotonic: float


class KubernetesLeaseStore:
    """Validated observation and conditional ownership changes for one Lease."""

    def __init__(
        self, reference: LeaseReference, timing: LeaseTiming, transport: LeaseTransport,
        *, monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._reference = reference
        self._timing = timing
        self._transport = transport
        self._monotonic = monotonic
        self._foreign_lock = threading.Lock()
        self._foreign_window: _ForeignLeaseObservationWindow | None = None

    def _clear_foreign_window(self) -> None:
        with self._foreign_lock:
            self._foreign_window = None

    def _foreign_takeover_eligible(self, observed: LeaseObservation) -> bool:
        holder = observed.holder_identity
        duration = observed.lease_duration_seconds
        if holder is None or duration is None:
            raise LeaseError(LeaseErrorCode.MALFORMED)
        record = _ForeignLeaseRecord(
            observed.revision.uid, holder, observed.revision.resource_version,
        )
        observed_at = self._monotonic()
        if not math.isfinite(observed_at):
            raise LeaseError(LeaseErrorCode.OWNERSHIP_UNCERTAIN)
        with self._foreign_lock:
            window = self._foreign_window
            if (
                window is None
                or window.record != record
                or observed_at < window.first_seen_monotonic
            ):
                self._foreign_window = _ForeignLeaseObservationWindow(record, observed_at)
                return False
            return observed_at - window.first_seen_monotonic >= duration

    def observe(self) -> LeaseObservation:
        try:
            raw = self._transport.read(self._reference)
        except LeaseTransportError as exc:
            kind = (
                LeaseErrorCode.MISSING
                if exc.kind is LeaseTransportErrorCode.NOT_FOUND
                else LeaseErrorCode.KUBERNETES_FAILURE
            )
            raise LeaseError(kind) from None
        return _parse_lease(raw, self._reference)

    def _classify_rejection(self, expected: LeaseRevision) -> LeaseError:
        try:
            current = self.observe()
        except LeaseError as exc:
            if exc.kind is LeaseErrorCode.MISSING:
                return LeaseError(LeaseErrorCode.IDENTITY_CHANGED)
            return LeaseError(LeaseErrorCode.KUBERNETES_FAILURE)
        if current.revision.uid != expected.uid:
            return LeaseError(LeaseErrorCode.IDENTITY_CHANGED)
        if current.revision.resource_version != expected.resource_version:
            return LeaseError(LeaseErrorCode.CONFLICT)
        return LeaseError(LeaseErrorCode.KUBERNETES_FAILURE)

    def _patch(
        self, expected: LeaseRevision, fields: dict[str, object],
    ) -> LeaseObservation:
        try:
            self._transport.conditional_patch(expected, fields=fields)
        except LeaseTransportError as exc:
            if exc.kind is LeaseTransportErrorCode.CONDITIONAL_REJECTED:
                raise self._classify_rejection(expected) from None
            if exc.kind is LeaseTransportErrorCode.OUTCOME_AMBIGUOUS:
                raise LeaseError(LeaseErrorCode.MUTATION_AMBIGUOUS) from None
            if exc.kind is LeaseTransportErrorCode.NOT_FOUND:
                raise LeaseError(LeaseErrorCode.IDENTITY_CHANGED) from None
            raise LeaseError(LeaseErrorCode.KUBERNETES_FAILURE) from None
        try:
            observed = self.observe()
        except LeaseError:
            raise LeaseError(LeaseErrorCode.MUTATION_AMBIGUOUS) from None
        if observed.revision.uid != expected.uid:
            raise LeaseError(LeaseErrorCode.IDENTITY_CHANGED)
        if observed.revision.resource_version == expected.resource_version:
            raise LeaseError(LeaseErrorCode.MUTATION_AMBIGUOUS)
        return observed

    def acquire(self, owner: ExecutionOwner, *, now: datetime) -> LeaseAcquisition:
        current_time = _utc(now)
        observed = self.observe()
        disposition = classify_lease(observed, owner)
        takeover = disposition is LeaseDisposition.HELD_BY_ANOTHER
        if takeover and not self._foreign_takeover_eligible(observed):
            raise LeaseError(LeaseErrorCode.HELD_BY_ANOTHER)
        if not takeover:
            self._clear_foreign_window()
        if takeover:
            kind = AcquisitionKind.EXPIRED_TAKEOVER
        elif disposition is LeaseDisposition.UNHELD:
            kind = AcquisitionKind.FRESH
        else:
            kind = AcquisitionKind.CONTINUED
        changing_holder = observed.holder_identity != owner.holder_identity
        transitions = observed.lease_transitions or 0
        if changing_holder:
            transitions += 1
        acquire_time = (
            current_time
            if disposition is LeaseDisposition.UNHELD or takeover
            else observed.acquire_time or current_time
        )
        renew_time = (
            max(current_time, observed.renew_time)
            if disposition is LeaseDisposition.HELD_BY_SELF
            and observed.renew_time is not None
            else current_time
        )
        fields: dict[str, object] = {
            "holderIdentity": owner.holder_identity,
            "leaseDurationSeconds": self._timing.lease_duration_seconds,
            "acquireTime": _format_timestamp(acquire_time),
            "renewTime": _format_timestamp(renew_time),
            "leaseTransitions": transitions,
        }
        updated = self._patch(observed.revision, fields)
        if (
            updated.holder_identity != owner.holder_identity
            or updated.lease_duration_seconds != self._timing.lease_duration_seconds
            or updated.acquire_time != acquire_time
            or updated.renew_time != renew_time
            or updated.lease_transitions != transitions
        ):
            raise LeaseError(LeaseErrorCode.READ_AFTER_WRITE_MISMATCH)
        self._clear_foreign_window()
        return LeaseAcquisition(kind, updated)

    def renew(
        self, expected: LeaseObservation, owner: ExecutionOwner, *, now: datetime,
    ) -> LeaseObservation:
        current_time = _utc(now)
        observed = self.observe()
        if observed.revision.uid != expected.revision.uid:
            raise LeaseError(LeaseErrorCode.OWNERSHIP_LOST)
        if classify_lease(observed, owner) is not LeaseDisposition.HELD_BY_SELF:
            raise LeaseError(LeaseErrorCode.OWNERSHIP_LOST)
        acquire_time = observed.acquire_time or current_time
        renew_time = max(current_time, observed.renew_time or current_time)
        transitions = observed.lease_transitions or 0
        updated = self._patch(observed.revision, {
            "holderIdentity": owner.holder_identity,
            "leaseDurationSeconds": self._timing.lease_duration_seconds,
            "acquireTime": _format_timestamp(acquire_time),
            "renewTime": _format_timestamp(renew_time),
            "leaseTransitions": transitions,
        })
        if (
            updated.holder_identity != owner.holder_identity
            or updated.lease_duration_seconds != self._timing.lease_duration_seconds
            or updated.acquire_time != acquire_time
            or updated.renew_time != renew_time
            or updated.lease_transitions != transitions
        ):
            raise LeaseError(LeaseErrorCode.READ_AFTER_WRITE_MISMATCH)
        return updated

    def release(
        self, expected: LeaseObservation, owner: ExecutionOwner, *, now: datetime,
    ) -> LeaseObservation:
        _utc(now)
        observed = self.observe()
        if observed.revision.uid != expected.revision.uid:
            raise LeaseError(LeaseErrorCode.OWNERSHIP_LOST)
        if classify_lease(observed, owner) is not LeaseDisposition.HELD_BY_SELF:
            raise LeaseError(LeaseErrorCode.OWNERSHIP_LOST)
        updated = self._patch(observed.revision, {
            "holderIdentity": None,
            "leaseDurationSeconds": None,
            "acquireTime": None,
            "renewTime": None,
            "leaseTransitions": observed.lease_transitions,
        })
        if updated.holder_identity is not None:
            raise LeaseError(LeaseErrorCode.READ_AFTER_WRITE_MISMATCH)
        return updated


MonotonicClock = Callable[[], float]
WallClock = Callable[[], datetime]
Waiter = Callable[[threading.Event, float], bool]


def _wall_clock() -> datetime:
    return datetime.now(timezone.utc)


def _event_wait(event: threading.Event, seconds: float) -> bool:
    return event.wait(seconds)


class LeaseOwnership:
    """One execution's sticky local ownership guard and renewal watchdog.

    The watchdog thread is daemonized as a last-resort process-exit safeguard,
    while ``close`` always requests stop and joins it deterministically.
    """

    def __init__(
        self, store: KubernetesLeaseStore, owner: ExecutionOwner,
        acquisition: LeaseAcquisition, timing: LeaseTiming, *,
        monotonic: MonotonicClock = time.monotonic,
        wall_clock: WallClock = _wall_clock,
        waiter: Waiter | None = None,
    ) -> None:
        self._store = store
        self._owner = owner
        self._acquisition = acquisition
        self._timing = timing
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._waiter = waiter or _event_wait
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._observation = acquisition.observation
        self._last_confirmed = monotonic()
        self._loss: LeaseErrorCode | None = None
        self._thread: threading.Thread | None = None

    @property
    def acquisition_kind(self) -> AcquisitionKind:
        return self._acquisition.kind

    @property
    def requires_recovery_gate(self) -> bool:
        return self._acquisition.requires_recovery_gate

    @property
    def loss_reason(self) -> LeaseErrorCode | None:
        with self._lock:
            return self._loss

    def _lose(self, reason: LeaseErrorCode) -> None:
        with self._lock:
            if self._loss is None:
                self._loss = reason
        self._stop.set()

    def assert_owned(self) -> None:
        with self._lock:
            if self._loss is not None:
                reason = self._loss
            elif self._monotonic() - self._last_confirmed >= self._timing.renewal_deadline_seconds:
                self._loss = LeaseErrorCode.OWNERSHIP_UNCERTAIN
                reason = self._loss
            else:
                return
        self._stop.set()
        raise LeaseError(reason)

    def renew_once(self) -> bool:
        try:
            self.assert_owned()
        except LeaseError:
            return False
        with self._lock:
            expected = self._observation
        try:
            renewed = self._store.renew(expected, self._owner, now=self._wall_clock())
        except LeaseError as exc:
            immediate = {
                LeaseErrorCode.MISSING,
                LeaseErrorCode.MALFORMED,
                LeaseErrorCode.CONFLICT,
                LeaseErrorCode.IDENTITY_CHANGED,
                LeaseErrorCode.OWNERSHIP_LOST,
                LeaseErrorCode.MUTATION_AMBIGUOUS,
                LeaseErrorCode.READ_AFTER_WRITE_MISMATCH,
            }
            if exc.kind in immediate:
                self._lose(
                    LeaseErrorCode.OWNERSHIP_UNCERTAIN
                    if exc.kind in (
                        LeaseErrorCode.CONFLICT,
                        LeaseErrorCode.MUTATION_AMBIGUOUS,
                    )
                    else LeaseErrorCode.OWNERSHIP_LOST
                )
            elif self._monotonic() - self._last_confirmed >= self._timing.renewal_deadline_seconds:
                self._lose(LeaseErrorCode.OWNERSHIP_UNCERTAIN)
            return False
        except Exception:
            self._lose(LeaseErrorCode.OWNERSHIP_UNCERTAIN)
            return False
        with self._lock:
            if self._loss is not None:
                return False
            self._observation = renewed
            self._last_confirmed = self._monotonic()
        return True

    def _run(self) -> None:
        try:
            while not self._waiter(self._stop, self._timing.renew_interval_seconds):
                self.renew_once()
                if self._stop.is_set():
                    return
        except Exception:
            self._lose(LeaseErrorCode.OWNERSHIP_UNCERTAIN)

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("Lease renewal watchdog has already been started.")
            thread = threading.Thread(
                target=self._run,
                name=f"lease-renew-{self._owner.holder_identity}",
                daemon=True,
            )
            self._thread = thread
        thread.start()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for the renewal worker to stop; primarily useful for lifecycle tests."""
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def close(self, *, release: bool = True) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        may_release = False
        if release:
            try:
                self.assert_owned()
            except LeaseError:
                pass
            else:
                may_release = True
        with self._lock:
            expected = self._observation
        if may_release:
            try:
                self._store.release(expected, self._owner, now=self._wall_clock())
            except LeaseError as exc:
                self._lose(
                    LeaseErrorCode.OWNERSHIP_LOST
                    if exc.kind is LeaseErrorCode.OWNERSHIP_LOST
                    else LeaseErrorCode.OWNERSHIP_UNCERTAIN
                )
                raise
        self._lose(LeaseErrorCode.OWNERSHIP_LOST)

    def __enter__(self) -> Self:
        self.assert_owned()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class LeaseManager:
    def __init__(
        self, store: KubernetesLeaseStore, timing: LeaseTiming, *,
        monotonic: MonotonicClock = time.monotonic,
        wall_clock: WallClock = _wall_clock,
        waiter: Waiter | None = None,
    ) -> None:
        self._store = store
        self._timing = timing
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._waiter = waiter

    def acquire(
        self, owner: ExecutionOwner, *, start_watchdog: bool = True,
    ) -> LeaseOwnership:
        acquisition = self._store.acquire(owner, now=self._wall_clock())
        ownership = LeaseOwnership(
            self._store,
            owner,
            acquisition,
            self._timing,
            monotonic=self._monotonic,
            wall_clock=self._wall_clock,
            waiter=self._waiter,
        )
        if start_watchdog:
            ownership.start()
        return ownership
