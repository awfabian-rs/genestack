"""Typed internal values. Secret-bearing records deliberately suppress repr."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Final, Literal, TypeAlias
from uuid import UUID


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


# Durable transaction state (schema version 2). These types contain identifiers,
# observations and intent only; credential values must never be added here.
STATE_SCHEMA_VERSION: Final[Literal[2]] = 2
_SHA256_IDENTIFIER = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class ConfigurationDigest:
    value: str

    def __post_init__(self) -> None:
        if _SHA256_IDENTIFIER.fullmatch(self.value) is None:
            raise ValueError("Configuration digest must be a lowercase SHA-256 identifier.")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class CredentialGeneration:
    value: str

    def __post_init__(self) -> None:
        if _SHA256_IDENTIFIER.fullmatch(self.value) is None:
            raise ValueError("Credential generation must be a lowercase SHA-256 identifier.")

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_secret(cls, credential: SecretValue) -> CredentialGeneration:
        raw = credential.reveal()
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Credential generation input must be valid UTF-8.") from None
        return cls(f"sha256:{hashlib.sha256(raw).hexdigest()}")


class RotationPhase(Enum):
    STABLE_A = "STABLE_A"
    PREPARE_B = "PREPARE_B"
    SWITCH_TO_B = "SWITCH_TO_B"
    VERIFY_B = "VERIFY_B"
    ROTATE_A = "ROTATE_A"
    SWITCH_TO_A = "SWITCH_TO_A"
    VERIFY_A = "VERIFY_A"


class TransactionStatus(Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    COMPLETED = "completed"


class CredentialMutationStep(Enum):
    STAGE_B_PASSWORDSAFE = "stage_b_passwordsafe"
    RESET_B_KEYSTONE = "reset_b_keystone"
    PROPAGATE_TO_B = "propagate_to_b"
    STAGE_A_BREEDER = "stage_a_breeder"
    RESET_A_KEYSTONE = "reset_a_keystone"
    UPDATE_A_PASSWORDSAFE = "update_a_passwordsafe"
    PROPAGATE_TO_A = "propagate_to_a"


class IntentEffectState(Enum):
    UNKNOWN = "effect_unknown"
    OBSERVED = "effect_observed"


class RuntimeActionState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"


class LockoutChangeState(Enum):
    NOT_INTENDED = "not_intended"
    INTENT_PERSISTED = "intent_persisted"
    EFFECT_OBSERVED = "effect_observed"


class VerificationStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    INDETERMINATE = "indeterminate"


class CompletedOutcome(Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class EnvironmentIdentity:
    environment_id: str
    cluster_id: str


@dataclass(frozen=True)
class PodIdentity:
    namespace: str
    name: str
    uid: str


@dataclass(frozen=True)
class ExecutionIdentity:
    execution_id: UUID
    pod: PodIdentity | None


@dataclass(frozen=True)
class ResolvedKeystoneIdentities:
    admin_user_id: str
    breakglass_user_id: str
    user_domain_id: str
    project_id: str
    project_domain_id: str
    role_id: str


@dataclass(frozen=True)
class SafeErrorInfo:
    code: str
    recorded_at: datetime


@dataclass(frozen=True)
class PasswordSafeState:
    configured_a_record_id: int
    configured_b_record_id: int
    observed_a_record_id: int | None
    observed_b_record_id: int | None
    original_a_version: int | None
    observed_a_version: int | None
    observed_b_version: int | None


@dataclass(frozen=True)
class KubernetesMutationTarget:
    namespace: str
    name: str
    uid: str
    observed_resource_version: str


@dataclass(frozen=True)
class CredentialMutationIntent:
    step: CredentialMutationStep
    target: KubernetesMutationTarget | None
    affected_location_ids: tuple[str, ...]
    intended_generation: CredentialGeneration
    effect_state: IntentEffectState
    effect_observed_at: datetime | None
    resulting_resource_version: str | None


@dataclass(frozen=True)
class RuntimeActionProgress:
    action_id: str
    state: RuntimeActionState


@dataclass(frozen=True)
class PropagationWave:
    applied_location_ids: tuple[str, ...]
    runtime_actions: tuple[RuntimeActionProgress, ...]


@dataclass(frozen=True)
class PropagationState:
    to_b: PropagationWave
    to_a: PropagationWave


@dataclass(frozen=True)
class LockoutState:
    initial_ignore_lockout_failure_attempts: bool
    suppression: LockoutChangeState
    restoration: LockoutChangeState
    latest_ignore_lockout_failure_attempts: bool | None
    restore_required: bool


@dataclass(frozen=True)
class VerificationResult:
    check_id: str
    phase: RotationPhase
    status: VerificationStatus
    checked_at: datetime
    detail_code: str | None
    target_uid: str | None
    credential_generation: CredentialGeneration | None


@dataclass(frozen=True)
class RotationTransaction:
    transaction_id: UUID
    request_id: UUID
    execution: ExecutionIdentity
    configuration_digest: ConfigurationDigest
    keystone: ResolvedKeystoneIdentities
    created_at: datetime
    updated_at: datetime
    phase: RotationPhase
    status: TransactionStatus
    last_error: SafeErrorInfo | None
    new_a_sha256: CredentialGeneration | None
    new_b_sha256: CredentialGeneration | None
    passwordsafe: PasswordSafeState
    credential_mutation_intent: CredentialMutationIntent | None
    propagation: PropagationState
    lockout: LockoutState
    verifications: tuple[VerificationResult, ...]


@dataclass(frozen=True)
class CompletedRequest:
    request_id: UUID
    transaction_id: UUID
    completed_at: datetime
    outcome: CompletedOutcome


@dataclass(frozen=True)
class PersistentState:
    schema_version: Literal[2]
    environment: EnvironmentIdentity
    current_transaction: RotationTransaction | None
    completed_requests: tuple[CompletedRequest, ...]
