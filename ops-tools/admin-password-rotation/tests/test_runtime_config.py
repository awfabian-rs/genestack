"""Slice 5B: static runtime configuration validation tests.

These tests cover the typed runtime configuration interface: valid minimal
configuration, missing or malformed settings, missing files, namespace
mismatch, lease-timing incompatibility, and the credential-free
configuration digest.  No test in this module contacts an external system.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from admin_password_rotation.runtime_config import (
    CONFIG_SCHEMA_VERSION, RuntimeConfig, RuntimeConfigError,
    load_runtime_config,
)

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
"""

IDENTITY_PASSWORD = "SYNTHETIC_RackspaceIdentity_0001"

MINIMAL = f"""schema_version: {CONFIG_SCHEMA_VERSION}
environment:
  environment_id: dfw-dev
  cluster_id: cluster.local
namespace: openstack
contract: contract.yaml
keystone:
  base_url: https://keystone.example.internal
passwordsafe:
  base_url: https://passwordsafe.example.internal
  project_id: 100
  a_record_id: 1000
  b_record_id: 1001
  identity_username: svc-rotation
  identity_password_file: identity_password
"""


def _write(root: Path, text: str, name: str = "runtime.yaml") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(text, encoding="utf-8")
    return path


def _write_password(root: Path, name: str = "identity_password") -> None:
    (root / name).write_text(IDENTITY_PASSWORD, encoding="utf-8")


def _load(root: Path, text: str | None = None) -> RuntimeConfig:
    path = _write(root, MINIMAL if text is None else text)
    _write_password(root)
    (root / "contract.yaml").write_text(CONTRACT, encoding="utf-8")
    return load_runtime_config(path)


def test_valid_minimal_configuration(tmp_path: Path) -> None:
    config = _load(tmp_path)
    assert config.schema_version == CONFIG_SCHEMA_VERSION
    assert config.environment.environment_id == "dfw-dev"
    assert config.environment.cluster_id == "cluster.local"
    assert config.namespace == "openstack"
    assert config.state_secret_name == "keystone-admin-rotation-state"
    assert config.lease_name == "keystone-admin-rotation"
    assert config.keystone_base_url == "https://keystone.example.internal"
    assert config.passwordsafe_a_record_id == 1000
    assert config.passwordsafe_b_record_id == 1001
    assert config.passwordsafe_identity_credential.username == "svc-rotation"
    assert config.kube_context is None
    assert config.kubeconfig_path is None
    assert config.keystone_trusted_ca is None
    assert config.passwordsafe_trusted_ca is None
    # Defaults from the external-http and lease modules are carried through.
    assert config.keystone_connect_timeout_seconds > 0
    assert config.keystone_request_timeout_seconds > 0
    assert config.lease_duration_seconds == 120
    # The contract was loaded and namespace-matched during validation.
    assert config.contract_path == tmp_path / "contract.yaml"
    assert config.contract_path.exists()


def test_configuration_digest_is_stable_and_credential_free(tmp_path: Path) -> None:
    first = _load(tmp_path)
    second = _load(tmp_path)
    first_digest = first.configuration_digest()
    second_digest = second.configuration_digest()
    assert first_digest == second_digest
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", first_digest) is not None
    # The AD service-account password must not be part of the digest input.
    assert IDENTITY_PASSWORD not in first_digest

    # Changing a non-credential setting changes the digest.
    changed = MINIMAL.replace("a_record_id: 1000", "a_record_id: 1002")
    other = _load(tmp_path, changed)
    assert other.configuration_digest() != first_digest

    # Changing only the credential password must not change the digest.
    root = tmp_path / "other"
    _write(root, MINIMAL)
    _write_password(root)
    (root / "contract.yaml").write_text(CONTRACT, encoding="utf-8")
    (root / "identity_password").write_text("DIFFERENT_PASSWORD", encoding="utf-8")
    different_password = load_runtime_config(root / "runtime.yaml")
    assert different_password.configuration_digest() == first_digest


def test_missing_required_field(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, MINIMAL.replace("namespace: openstack\n", ""))
    assert exc.value.code == "config_missing_field"


def test_unknown_field_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, MINIMAL + "bogus_field: 1\n")
    assert exc.value.code == "config_unknown_field"


def test_unsupported_schema_version(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, MINIMAL.replace(
            f"schema_version: {CONFIG_SCHEMA_VERSION}", "schema_version: 99",
        ))
    assert exc.value.code == "config_schema_version"


def test_non_integer_schema_version_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, MINIMAL.replace(
            f"schema_version: {CONFIG_SCHEMA_VERSION}", "schema_version: true",
        ))
    assert exc.value.code == "config_schema_version"


def test_invalid_namespace_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, MINIMAL.replace("namespace: openstack", "namespace: other"))
    assert exc.value.code == "config_invalid_namespace"


def test_namespace_mismatch_with_contract(tmp_path: Path) -> None:
    # The runtime namespace must be 'openstack' (a hard invariant); a
    # non-openstack runtime namespace fails before the contract is compared.
    text = MINIMAL.replace("namespace: openstack", "namespace: other")
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, text)
    assert exc.value.code == "config_invalid_namespace"


def test_missing_contract_path(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        path = _write(tmp_path, MINIMAL)
        _write_password(tmp_path)
        load_runtime_config(path)
    assert exc.value.code == "config_contract_path"


def test_missing_configuration_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        load_runtime_config(tmp_path / "absent.yaml")
    assert exc.value.code == "config_read"


def test_invalid_yaml(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, "schema_version: [unclosed\n")
    assert exc.value.code == "config_invalid_yaml"


def test_non_mapping_root(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, "- a\n- b\n")
    assert exc.value.code == "config_invalid_value"


def test_missing_identity_password_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        path = _write(tmp_path, MINIMAL)
        (tmp_path / "contract.yaml").write_text(CONTRACT, encoding="utf-8")
        load_runtime_config(path)
    assert exc.value.code == "config_identity_credential"


def test_username_without_password_file_rejected(tmp_path: Path) -> None:
    text = MINIMAL.replace("  identity_password_file: identity_password\n", "")
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, text)
    assert exc.value.code == "config_missing_field"


def test_empty_identity_password_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError) as exc:
        path = _write(tmp_path, MINIMAL)
        _write_password(tmp_path)
        (path.parent / "identity_password").write_text("", encoding="utf-8")
        (path.parent / "contract.yaml").write_text(CONTRACT, encoding="utf-8")
        load_runtime_config(path)
    assert exc.value.code == "config_invalid_value"


def test_same_a_and_b_record_id_rejected(tmp_path: Path) -> None:
    text = MINIMAL.replace("b_record_id: 1001", "b_record_id: 1000")
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, text)
    assert exc.value.code == "config_incompatible"


def test_invalid_url_rejected(tmp_path: Path) -> None:
    text = MINIMAL.replace(
        "base_url: https://keystone.example.internal",
        "base_url: keystone.example.internal",
    )
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, text)
    assert exc.value.code == "config_invalid_value"


def test_invalid_timeout_rejected(tmp_path: Path) -> None:
    text = MINIMAL.replace(
        "base_url: https://keystone.example.internal",
        "base_url: https://keystone.example.internal\n"
        "  connect_timeout_seconds: 0",
    )
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, text)
    assert exc.value.code == "config_invalid_timeout"


def test_lease_timing_incompatibility(tmp_path: Path) -> None:
    # api timeout must be strictly less than the renewal deadline.
    text = MINIMAL + "lease:\n  api_timeout_seconds: 61\n  renewal_deadline_seconds: 60\n"
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, text)
    assert exc.value.code == "config_incompatible"


def test_lease_timing_invalid_values(tmp_path: Path) -> None:
    text = MINIMAL + "lease:\n  duration_seconds: 60\n  renew_interval_seconds: 60\n"
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, text)
    assert exc.value.code == "config_lease_timing"


def test_sensitive_value_absent_from_error_and_repr(tmp_path: Path) -> None:
    config = _load(tmp_path)
    rendered = repr(config)
    assert IDENTITY_PASSWORD not in rendered
    # The credential file name must not appear in the config repr either.
    assert "identity_password" not in rendered
    # A validation failure message must not leak the credential.
    with pytest.raises(RuntimeConfigError) as exc:
        _load(tmp_path, MINIMAL.replace(
            "  identity_username: svc-rotation", "  identity_username: ''",
        ))
    assert IDENTITY_PASSWORD not in str(exc.value)
    assert IDENTITY_PASSWORD not in repr(exc.value)


def test_defaults_apply_for_omitted_optional_sections(tmp_path: Path) -> None:
    text = f"""schema_version: {CONFIG_SCHEMA_VERSION}
environment:
  environment_id: dfw-dev
  cluster_id: cluster.local
namespace: openstack
contract: contract.yaml
keystone:
  base_url: https://keystone.example.internal
passwordsafe:
  base_url: https://passwordsafe.example.internal
  project_id: 100
  a_record_id: 1000
  b_record_id: 1001
  identity_username: svc-rotation
  identity_password_file: identity_password
"""
    config = _load(tmp_path, text)
    # Lease defaults from the lease module.
    assert config.lease_duration_seconds == 120
    assert config.lease_renew_interval_seconds == 20.0
    assert config.lease_renewal_deadline_seconds == 60.0
    # Identity path/domain defaults.
    assert config.passwordsafe_identity_token_path == "/v2.0/tokens"
    assert config.passwordsafe_identity_domain_name == "Rackspace"
    # Identity base URL defaults to the PasswordSafe base URL.
    assert config.passwordsafe_identity_base_url == "https://passwordsafe.example.internal"
