"""Typed internal values. Secret-bearing records deliberately suppress repr."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias


class Identity(Enum):
    ADMIN = "admin"
    BREAKGLASS = "breakglass"


class IdentityBinding(Enum):
    ADMIN = "admin"
    BREAKGLASS = "breakglass"
    ACTIVE = "active"


class LocationRole(Enum):
    SOURCE = "source"
    PROPAGATED = "propagated"


class WorkloadKind(Enum):
    DEPLOYMENT = "deployment"
    DAEMONSET = "daemonset"


@dataclass(frozen=True)
class WorkloadRef:
    kind: WorkloadKind
    name: str

    @property
    def label(self) -> str:
        return f"{self.kind.value}/{self.name}"


YamlPath: TypeAlias = tuple[str, ...]


@dataclass(frozen=True)
class FieldsRepresentation:
    password: str
    username: str | None = None


@dataclass(frozen=True)
class IniRepresentation:
    key: str
    section: str
    password: str
    username: str | None = None


@dataclass(frozen=True)
class YamlRepresentation:
    key: str
    password_path: YamlPath
    username_path: YamlPath | None = None
    document_path: YamlPath | None = None


Representation: TypeAlias = FieldsRepresentation | IniRepresentation | YamlRepresentation


@dataclass(frozen=True)
class CredentialLocation:
    name: str
    secret: str
    identity: IdentityBinding
    role: LocationRole
    representation: Representation
    restart: tuple[WorkloadRef, ...]


@dataclass(frozen=True)
class CredentialContract:
    namespace: str
    locations: tuple[CredentialLocation, ...]

    @property
    def source(self) -> CredentialLocation:
        # The loader establishes exactly one canonical breeder source.
        return next(x for x in self.locations if x.role is LocationRole.SOURCE)


@dataclass(frozen=True, repr=False)
class SecretValue:
    _value: bytes

    def reveal(self) -> bytes:
        """Explicit escape hatch for comparisons/parsers; never use for output."""
        return self._value

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True)
class SecretField:
    key: str
    value: SecretValue = field(repr=False)


@dataclass(frozen=True)
class SecretSnapshot:
    namespace: str
    name: str
    uid: str
    resource_version: str
    data: tuple[SecretField, ...] = field(repr=False)

    def get(self, key: str) -> SecretValue | None:
        return next((x.value for x in self.data if x.key == key), None)


@dataclass(frozen=True)
class SecretInventory:
    namespace: str
    resource_version: str | None
    secrets: tuple[SecretSnapshot, ...] = field(repr=False)


@dataclass(frozen=True, repr=False)
class ObservedCredential:
    username: str | None
    password: SecretValue

    def __repr__(self) -> str:
        return "ObservedCredential(<redacted>)"


@dataclass(frozen=True)
class ReferenceCredentials:
    """Comparison inputs, NOT proof of PasswordSafe equality or authentication."""
    admin: SecretValue = field(repr=False)
    breakglass: SecretValue | None = field(default=None, repr=False)


class CredentialState(Enum):
    MATCHES_ADMIN_REFERENCE = "matches_admin_reference"
    MATCHES_BREAKGLASS_REFERENCE = "matches_breakglass_reference"
    UNVERIFIED_BREAKGLASS = "unverified_breakglass"
    UNKNOWN = "unknown"
    MISSING = "missing"
    UNREADABLE = "unreadable"
    NO_REFERENCE = "no_reference"


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    location: str | None = None
    secret: str | None = None
    key: str | None = None


@dataclass(frozen=True)
class LocationObservation:
    location: str
    secret: str
    state: CredentialState
    uid: str | None
    resource_version: str | None


@dataclass(frozen=True)
class RestartDependency:
    workload: WorkloadRef
    caused_by_locations: tuple[str, ...]


@dataclass(frozen=True)
class TopologyPlan:
    namespace: str
    inventory_resource_version: str | None
    input_mode: str
    inventory_secret_count: int
    locations: tuple[LocationObservation, ...]
    findings: tuple[Finding, ...]
    potential_restart_dependencies: tuple[RestartDependency, ...]

    @property
    def topology_checks_passed(self) -> bool:
        return not self.findings
