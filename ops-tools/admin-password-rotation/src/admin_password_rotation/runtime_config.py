"""Slice 5B: typed production runtime configuration.

``RuntimeConfig`` is the static, validated configuration the production
process uses to construct its external dependencies.  It is deliberately
separate from the credential-location contract (``config.py``): the contract
describes where credentials live in the cluster, while the runtime
configuration identifies the external systems and object names the rotation
process operates against.

Validation is fully static.  Building a ``RuntimeConfig`` never connects to
Kubernetes, Keystone, or PasswordSafe, and a valid configuration never
requires any external system to be reachable.  Live availability is checked
by the explicitly invoked bootstrap operations in ``auth_bootstrap``.

Sensitive values (the Rackspace Identity service-account password) are read
from a projected file at configuration-construction time and stored in
``SecretValue``; they never appear in ``str()``/``repr()`` output or in
error messages.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import yaml

from .config import load_contract
from .errors import ReadError
from .external_http import (
    DEFAULT_CONNECT_TIMEOUT_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS,
)
from .lease import DEFAULT_LEASE_API_TIMEOUT_SECONDS, LeaseTiming
from .model import EnvironmentIdentity, SecretValue

DEFAULT_KUBERNETES_API_TIMEOUT_SECONDS = 60.0
DEFAULT_BOOTSTRAP_ADMIN_CANDIDATE_TIMEOUT_SECONDS = 120.0
DEFAULT_KEYSSTONE_TIMEOUTS = (
    DEFAULT_CONNECT_TIMEOUT_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS,
)
DEFAULT_PASSWORDSAFE_IDENTITY_TOKEN_PATH = "/v2.0/tokens"
DEFAULT_PASSWORDSAFE_IDENTITY_DOMAIN_NAME = "Rackspace"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_BREAKGLASS_USERNAME = "breakglass"
DEFAULT_DOMAIN_NAME = "default"
DEFAULT_PROJECT_NAME = "admin"
DEFAULT_ROLE_NAME = "admin"
DEFAULT_STATE_SECRET_NAME = "keystone-admin-rotation-state"
DEFAULT_LEASE_NAME = "keystone-admin-rotation"
MAX_BOOTSTRAP_TIMEOUT_SECONDS = 3600.0

CONFIG_SCHEMA_VERSION = 1


class RuntimeConfigError(ReadError):
    """A sanitized, value-free runtime-configuration failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code, _CONFIG_ERROR_MESSAGES.get(
            code, "The runtime configuration is invalid.",
        ))


_CONFIG_ERROR_MESSAGES: dict[str, str] = {
    "config_read": "Cannot read the runtime configuration file.",
    "config_invalid_yaml": "The runtime configuration is not a valid YAML mapping.",
    "config_schema_version": "The runtime configuration schema version is unsupported.",
    "config_unknown_field": "The runtime configuration contains an unsupported field.",
    "config_missing_field": "The runtime configuration is missing a required field.",
    "config_invalid_value": "A runtime configuration value has an unsupported type or value.",
    "config_invalid_timeout": "A runtime configuration timeout must be finite and positive.",
    "config_invalid_namespace": "The runtime configuration namespace must be 'openstack'.",
    "config_contract_path": "The credential contract path is missing or invalid.",
    "config_contract": "The credential contract file cannot be loaded.",
    "config_namespace_mismatch": "The contract namespace does not match the runtime namespace.",
    "config_ca_file": "A trusted CA file path is invalid.",
    "config_identity_credential": "The PasswordSafe identity credential file cannot be read.",
    "config_incompatible": "The runtime configuration is internally inconsistent.",
    "config_lease_timing": "The Lease timing values are invalid.",
}


def _require_mapping(
    value: object, *, label: str, required: frozenset[str], optional: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeConfigError("config_invalid_value")
    raw: dict[str, object] = {}
    for pair in list(cast("dict[str, object]", value).items()):
        key, item = pair
        raw[key] = item
    keys = set(raw)
    if not required <= keys:
        raise RuntimeConfigError("config_missing_field")
    if keys - required - optional:
        raise RuntimeConfigError("config_unknown_field")
    del label
    return raw


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeConfigError("config_invalid_value")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _string(value)


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuntimeConfigError("config_invalid_value")
    return value


def _url(value: object) -> str:
    text = _string(value)
    lowered = text.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        raise RuntimeConfigError("config_invalid_value")
    if any(ord(char) < 32 for char in text):
        raise RuntimeConfigError("config_invalid_value")
    return text


def _timeout(value: object, *, maximum: float = 3600.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeConfigError("config_invalid_timeout")
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= maximum:
        raise RuntimeConfigError("config_invalid_timeout")
    return result


def _ca_file(value: object) -> Path | None:
    if value is None:
        return None
    text = _string(value)
    if not text:
        raise RuntimeConfigError("config_ca_file")
    return Path(text)


def _timeout_pair(data: dict[str, object]) -> tuple[float, float]:
    connect = data.get("connect_timeout_seconds")
    request = data.get("request_timeout_seconds")
    return (
        _timeout(connect, maximum=360.0) if connect is not None
        else DEFAULT_CONNECT_TIMEOUT_SECONDS,
        _timeout(request) if request is not None else DEFAULT_REQUEST_TIMEOUT_SECONDS,
    )


@dataclass(frozen=True, repr=False)
class KeystoneSettings:
    """Validated ``keystone`` section."""

    base_url: str
    trusted_ca: Path | None
    connect: float
    request: float
    admin_username: str
    breakglass_username: str
    domain_name: str
    project_name: str
    role_name: str

    def __repr__(self) -> str:
        return f"KeystoneSettings(base_url={self.base_url!r})"


@dataclass(frozen=True, repr=False)
class PasswordSafeIdentityCredential:
    """The AD service-account credential used for PasswordSafe access.

    ``username`` is nonsecret and part of the configuration digest;
    ``password`` is sensitive and excluded from ``repr()``.
    """

    username: str
    password: SecretValue

    def __repr__(self) -> str:
        return f"PasswordSafeIdentityCredential(username={self.username!r})"

    def __str__(self) -> str:
        return f"PasswordSafeIdentityCredential(username={self.username!r})"


@dataclass(frozen=True, repr=False)
class RuntimeConfig:
    """The fully validated production runtime configuration."""

    schema_version: int
    environment: EnvironmentIdentity
    contract_path: Path
    namespace: str
    state_secret_name: str
    lease_name: str
    kube_context: str | None
    kubeconfig_path: Path | None
    kubernetes_api_timeout_seconds: float
    keystone_base_url: str
    keystone_trusted_ca: Path | None
    keystone_connect_timeout_seconds: float
    keystone_request_timeout_seconds: float
    admin_username: str
    breakglass_username: str
    domain_name: str
    project_name: str
    role_name: str
    passwordsafe_base_url: str
    passwordsafe_identity_base_url: str
    passwordsafe_trusted_ca: Path | None
    passwordsafe_connect_timeout_seconds: float
    passwordsafe_request_timeout_seconds: float
    passwordsafe_identity_token_path: str
    passwordsafe_identity_domain_name: str
    passwordsafe_identity_credential: PasswordSafeIdentityCredential
    passwordsafe_project_id: int
    passwordsafe_a_record_id: int
    passwordsafe_b_record_id: int
    lease_api_timeout_seconds: float
    lease_duration_seconds: int
    lease_renew_interval_seconds: float
    lease_renewal_deadline_seconds: float
    bootstrap_admin_candidate_timeout_seconds: float

    def __repr__(self) -> str:
        return (
            "RuntimeConfig(environment="
            f"{self.environment.environment_id!r}, "
            f"namespace={self.namespace!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def lease_timing(self) -> LeaseTiming:
        return LeaseTiming(
            lease_duration_seconds=self.lease_duration_seconds,
            renew_interval_seconds=self.lease_renew_interval_seconds,
            renewal_deadline_seconds=self.lease_renewal_deadline_seconds,
        )

    def keystone_auth_timeout(self) -> tuple[float, float]:
        return (
            self.keystone_connect_timeout_seconds,
            self.keystone_request_timeout_seconds,
        )

    def passwordsafe_auth_timeout(self) -> tuple[float, float]:
        return (
            self.passwordsafe_connect_timeout_seconds,
            self.passwordsafe_request_timeout_seconds,
        )

    def configuration_digest(self) -> str:
        """Stable, credential-free digest of the static runtime configuration.

        The digest covers every setting that identifies the external systems,
        object names, and behavior the phases consume.  It never covers the
        PasswordSafe identity credential: the AD service-account password is
        sensitive and must not appear (even hashed) in transaction records or
        logs.  It is the value a future runner places in
        ``PrepareBRequest.configuration_digest`` so a durable transaction
        detects configuration drift on resume.
        """
        material: dict[str, object] = {
            "schema_version": self.schema_version,
            "environment": (self.environment.environment_id, self.environment.cluster_id),
            "namespace": self.namespace,
            "state_secret_name": self.state_secret_name,
            "lease_name": self.lease_name,
            "kube": (self.kube_context, str(self.kubeconfig_path) if self.kubeconfig_path else None),
            "kubernetes_api_timeout_seconds": self.kubernetes_api_timeout_seconds,
            "keystone": (
                self.keystone_base_url,
                str(self.keystone_trusted_ca) if self.keystone_trusted_ca else None,
                self.keystone_connect_timeout_seconds,
                self.keystone_request_timeout_seconds,
                self.admin_username,
                self.breakglass_username,
                self.domain_name,
                self.project_name,
                self.role_name,
            ),
            "passwordsafe": (
                self.passwordsafe_base_url,
                self.passwordsafe_identity_base_url,
                str(self.passwordsafe_trusted_ca) if self.passwordsafe_trusted_ca else None,
                self.passwordsafe_connect_timeout_seconds,
                self.passwordsafe_request_timeout_seconds,
                self.passwordsafe_identity_token_path,
                self.passwordsafe_identity_domain_name,
                self.passwordsafe_identity_credential.username,
                self.passwordsafe_project_id,
                self.passwordsafe_a_record_id,
                self.passwordsafe_b_record_id,
            ),
            "lease": (
                self.lease_api_timeout_seconds,
                self.lease_duration_seconds,
                self.lease_renew_interval_seconds,
                self.lease_renewal_deadline_seconds,
            ),
            "bootstrap": (self.bootstrap_admin_candidate_timeout_seconds,),
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _environment(data: dict[str, object]) -> EnvironmentIdentity:
    section = _require_mapping(
        data.get("environment"), label="environment",
        required=frozenset({"environment_id", "cluster_id"}),
    )
    return EnvironmentIdentity(
        _string(section["environment_id"]), _string(section["cluster_id"]),
    )


def _keystone(data: dict[str, object]) -> KeystoneSettings:
    section = _require_mapping(
        data.get("keystone"), label="keystone",
        required=frozenset({"base_url"}),
        optional=frozenset({
            "trusted_ca", "connect_timeout_seconds", "request_timeout_seconds",
            "admin_username", "breakglass_username", "domain_name",
            "project_name", "role_name",
        }),
    )
    connect, request = _timeout_pair(section)
    return KeystoneSettings(
        base_url=_url(section["base_url"]),
        trusted_ca=_ca_file(section.get("trusted_ca")),
        connect=connect,
        request=request,
        admin_username=_string(
            section.get("admin_username") or DEFAULT_ADMIN_USERNAME,
        ),
        breakglass_username=_string(
            section.get("breakglass_username") or DEFAULT_BREAKGLASS_USERNAME,
        ),
        domain_name=_string(
            section.get("domain_name") or DEFAULT_DOMAIN_NAME,
        ),
        project_name=_string(
            section.get("project_name") or DEFAULT_PROJECT_NAME,
        ),
        role_name=_string(section.get("role_name") or DEFAULT_ROLE_NAME),
    )


@dataclass(frozen=True, repr=False)
class PasswordSafeSettings:
    """Validated ``passwordsafe`` section; the identity credential is sensitive."""

    base_url: str
    identity_base_url: str
    trusted_ca: Path | None
    connect: float
    request: float
    token_path: str
    domain_name: str
    credential: PasswordSafeIdentityCredential
    project_id: int
    a_record_id: int
    b_record_id: int

    def __repr__(self) -> str:
        return (
            f"PasswordSafeSettings(base_url={self.base_url!r}, "
            f"project_id={self.project_id})"
        )


def _passwordsafe(data: dict[str, object], base_dir: Path) -> PasswordSafeSettings:
    section = _require_mapping(
        data.get("passwordsafe"), label="passwordsafe",
        required=frozenset({"base_url", "project_id", "a_record_id", "b_record_id"}),
        optional=frozenset({
            "identity_base_url", "trusted_ca", "connect_timeout_seconds",
            "request_timeout_seconds", "identity_token_path",
            "identity_domain_name", "identity_username", "identity_password_file",
        }),
    )
    base_url = _url(section["base_url"])
    identity_base_url = _url(
        section.get("identity_base_url")
        if section.get("identity_base_url") is not None else base_url,
    )
    connect, request = _timeout_pair(section)
    username = section.get("identity_username")
    password_file = section.get("identity_password_file")
    if username is None and password_file is None:
        username = ""
        password_file = ""
    elif username is None or password_file is None:
        raise RuntimeConfigError("config_missing_field")
    if not _string(username):
        raise RuntimeConfigError("config_invalid_value")
    file_path = Path(_string(password_file))
    if not file_path.is_absolute():
        file_path = base_dir / file_path
    try:
        raw_password = file_path.read_bytes()
    except (OSError, UnicodeError):
        raise RuntimeConfigError("config_identity_credential") from None
    if not raw_password:
        raise RuntimeConfigError("config_invalid_value")
    token_path = _string(
        section.get("identity_token_path")
        or DEFAULT_PASSWORDSAFE_IDENTITY_TOKEN_PATH,
    )
    if not token_path.startswith("/"):
        raise RuntimeConfigError("config_invalid_value")
    identity_domain_name = _string(
        section.get("identity_domain_name")
        or DEFAULT_PASSWORDSAFE_IDENTITY_DOMAIN_NAME,
    )
    project_id = _positive_int(section["project_id"])
    a_record = _positive_int(section["a_record_id"])
    b_record = _positive_int(section["b_record_id"])
    if a_record == b_record:
        raise RuntimeConfigError("config_incompatible")
    return PasswordSafeSettings(
        base_url=base_url,
        identity_base_url=identity_base_url,
        trusted_ca=_ca_file(section.get("trusted_ca")),
        connect=connect,
        request=request,
        token_path=token_path,
        domain_name=identity_domain_name,
        credential=PasswordSafeIdentityCredential(
            _string(username), SecretValue(raw_password),
        ),
        project_id=project_id,
        a_record_id=a_record,
        b_record_id=b_record,
    )


def load_runtime_config(path: Path) -> RuntimeConfig:
    """Load and statically validate one runtime configuration file.

    The credential contract referenced by ``contract`` is loaded with the
    existing strict contract parser, and its namespace must match the
    configured namespace.  No external system is contacted.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise RuntimeConfigError("config_read") from None
    try:
        raw: object = yaml.safe_load(raw_text)
    except (yaml.YAMLError, RecursionError, ValueError):
        raise RuntimeConfigError("config_invalid_yaml") from None
    root = _require_mapping(
        raw, label="root",
        required=frozenset({"schema_version", "environment", "namespace", "contract"}),
        optional=frozenset({
            "state_secret_name", "lease_name", "kube", "keystone",
            "passwordsafe", "lease", "bootstrap",
        }),
    )
    version = root["schema_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != CONFIG_SCHEMA_VERSION:
        raise RuntimeConfigError("config_schema_version")
    environment = _environment(root)
    base_dir = path.parent
    contract_path = base_dir / _string(root["contract"])
    if not contract_path.exists() or not contract_path.is_file():
        raise RuntimeConfigError("config_contract_path")
    namespace = _string(root["namespace"])
    if namespace != "openstack":
        raise RuntimeConfigError("config_invalid_namespace")
    state_name = _string(
        root.get("state_secret_name") or DEFAULT_STATE_SECRET_NAME,
    )
    lease_name = _string(root.get("lease_name") or DEFAULT_LEASE_NAME)

    kube_raw = root.get("kube")
    kube_section: dict[str, object] = {}
    if kube_raw is not None:
        kube_section = _require_mapping(
            kube_raw, label="kube", required=frozenset(),
            optional=frozenset({
                "context", "kubeconfig", "api_timeout_seconds",
            }),
        )
    kube_context = _optional_string(kube_section.get("context"))
    kubeconfig_raw = _optional_string(kube_section.get("kubeconfig"))
    kubeconfig_path: Path | None = None
    if kubeconfig_raw is not None:
        kubeconfig_path = Path(kubeconfig_raw)
        if not kubeconfig_path.is_absolute():
            kubeconfig_path = base_dir / kubeconfig_path
        if not kubeconfig_path.exists() or not kubeconfig_path.is_file():
            raise RuntimeConfigError("config_ca_file")
    kube_timeout = _timeout(
        kube_section.get("api_timeout_seconds")
        if kube_section.get("api_timeout_seconds") is not None
        else DEFAULT_KUBERNETES_API_TIMEOUT_SECONDS,
    )
    keystone = _keystone(root)
    passwordsafe = _passwordsafe(root, base_dir)

    lease_raw = root.get("lease")
    lease_section: dict[str, object] = {}
    if lease_raw is not None:
        lease_section = _require_mapping(
            lease_raw, label="lease", required=frozenset(),
            optional=frozenset({
                "api_timeout_seconds", "duration_seconds", "renew_interval_seconds",
                "renewal_deadline_seconds",
            }),
        )
    lease_api_timeout = _timeout(
        lease_section.get("api_timeout_seconds")
        if lease_section.get("api_timeout_seconds") is not None
        else DEFAULT_LEASE_API_TIMEOUT_SECONDS,
    )
    lease_duration = _positive_int(
        lease_section.get("duration_seconds")
        if lease_section.get("duration_seconds") is not None else 120,
    )
    lease_renew_interval = _timeout(
        lease_section.get("renew_interval_seconds")
        if lease_section.get("renew_interval_seconds") is not None else 20.0,
    )
    lease_renewal_deadline = _timeout(
        lease_section.get("renewal_deadline_seconds")
        if lease_section.get("renewal_deadline_seconds") is not None else 60.0,
    )
    try:
        LeaseTiming(lease_duration, lease_renew_interval, lease_renewal_deadline)
    except ValueError:
        raise RuntimeConfigError("config_lease_timing") from None
    if lease_api_timeout >= lease_renewal_deadline:
        raise RuntimeConfigError("config_incompatible")

    bootstrap_raw = root.get("bootstrap")
    bootstrap_section: dict[str, object] = {}
    if bootstrap_raw is not None:
        bootstrap_section = _require_mapping(
            bootstrap_raw, label="bootstrap", required=frozenset(),
            optional=frozenset({"admin_candidate_timeout_seconds"}),
        )
    bootstrap_timeout = _timeout(
        bootstrap_section.get("admin_candidate_timeout_seconds")
        if bootstrap_section.get("admin_candidate_timeout_seconds") is not None
        else DEFAULT_BOOTSTRAP_ADMIN_CANDIDATE_TIMEOUT_SECONDS,
        maximum=MAX_BOOTSTRAP_TIMEOUT_SECONDS,
    )

    try:
        contract = load_contract(contract_path)
    except ReadError:
        raise RuntimeConfigError("config_contract") from None
    if contract.namespace != namespace:
        raise RuntimeConfigError("config_namespace_mismatch")

    return RuntimeConfig(
        schema_version=version,
        environment=environment,
        contract_path=contract_path,
        namespace=namespace,
        state_secret_name=state_name,
        lease_name=lease_name,
        kube_context=kube_context,
        kubeconfig_path=kubeconfig_path,
        kubernetes_api_timeout_seconds=kube_timeout,
        keystone_base_url=keystone.base_url,
        keystone_trusted_ca=keystone.trusted_ca,
        keystone_connect_timeout_seconds=keystone.connect,
        keystone_request_timeout_seconds=keystone.request,
        admin_username=keystone.admin_username,
        breakglass_username=keystone.breakglass_username,
        domain_name=keystone.domain_name,
        project_name=keystone.project_name,
        role_name=keystone.role_name,
        passwordsafe_base_url=passwordsafe.base_url,
        passwordsafe_identity_base_url=passwordsafe.identity_base_url,
        passwordsafe_trusted_ca=passwordsafe.trusted_ca,
        passwordsafe_connect_timeout_seconds=passwordsafe.connect,
        passwordsafe_request_timeout_seconds=passwordsafe.request,
        passwordsafe_identity_token_path=passwordsafe.token_path,
        passwordsafe_identity_domain_name=passwordsafe.domain_name,
        passwordsafe_identity_credential=passwordsafe.credential,
        passwordsafe_project_id=passwordsafe.project_id,
        passwordsafe_a_record_id=passwordsafe.a_record_id,
        passwordsafe_b_record_id=passwordsafe.b_record_id,
        lease_api_timeout_seconds=lease_api_timeout,
        lease_duration_seconds=lease_duration,
        lease_renew_interval_seconds=lease_renew_interval,
        lease_renewal_deadline_seconds=lease_renewal_deadline,
        bootstrap_admin_candidate_timeout_seconds=bootstrap_timeout,
    )
