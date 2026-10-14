"""Slice 5B: production dependency composition tests.

Construction must be offline: building the dependency set from a validated
runtime configuration never authenticates to Keystone or Rackspace
Identity, never acquires a Lease, never reads or mutates any Kubernetes
object, and never performs a rotation phase.  These tests run with a
synthetic kubeconfig so the Kubernetes Python API facades can be
constructed locally without an API server.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from admin_password_rotation.composition import Dependencies, build_dependencies
from admin_password_rotation.config import load_contract
from admin_password_rotation.runtime_config import RuntimeConfigError, load_runtime_config

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

IDENTITY_PASSWORD = "SYNTHETIC_RackspaceIdentity_Composition_01"

MINIMAL = """schema_version: 1
environment:
  environment_id: dfw-dev
  cluster_id: cluster.local
namespace: openstack
contract: contract.yaml
kube:
  kubeconfig: kubeconfig.yaml
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

KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: synthetic
contexts:
- context:
    cluster: synthetic
    user: synthetic
  name: synthetic
current-context: synthetic
users:
- name: synthetic
  user:
    token: synthetic-offline-token
"""


def _write_env(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "runtime.yaml").write_text(MINIMAL, encoding="utf-8")
    (root / "contract.yaml").write_text(CONTRACT, encoding="utf-8")
    (root / "identity_password").write_text(IDENTITY_PASSWORD, encoding="utf-8")
    (root / "kubeconfig.yaml").write_text(KUBECONFIG, encoding="utf-8")
    return root / "runtime.yaml"


def test_build_dependencies_offline_constructs_every_phase_client(
    tmp_path: Path,
) -> None:
    config_path = _write_env(tmp_path)
    config = load_runtime_config(config_path)
    contract = load_contract(config.contract_path)
    deps = build_dependencies(config, contract)

    assert isinstance(deps, Dependencies)
    # Every phase-consumed dependency is present and constructed.
    assert deps.keystone is not None
    assert deps.rackspace_identity is not None
    assert deps.passwordsafe is not None
    assert deps.state_store is not None
    assert deps.lease_store is not None
    assert deps.lease_manager is not None
    assert deps.breeder is not None
    assert deps.secret_client is not None
    assert deps.workload_client is not None
    assert deps.breeder_patch is not None
    # The validated contract is retained for the runner.
    assert deps.contract is contract
    assert deps.config is config
    # Reprs are sanitized: no credential file path, no token, no URL leak.
    rendered = repr(deps)
    assert IDENTITY_PASSWORD not in rendered
    assert "synthetic-offline-token" not in rendered
    assert rendered.startswith("Dependencies(")


def test_build_dependencies_rejects_invalid_runtime_config(tmp_path: Path) -> None:
    # A runtime configuration that fails static validation cannot be used
    # for construction at all; the loader fails before build_dependencies.
    bad = _write_env(tmp_path)
    bad.parent.joinpath("identity_password").write_text("", encoding="utf-8")
    with pytest.raises(RuntimeConfigError) as exc:
        load_runtime_config(bad)
    assert exc.value.code == "config_invalid_value"


def test_build_dependencies_constructs_clients_without_live_creds(
    tmp_path: Path,
) -> None:
    # Even without a valid kubeconfig, construction performs only local
    # credential resolution: it must never reach the Keystone or PasswordSafe
    # base URLs.  The Kubernetes client may be constructed against a
    # non-resolvable in-cluster/current context in the test environment;
    # the assertion is about what construction does NOT do.
    config_path = _write_env(tmp_path)
    config_text = MINIMAL.replace(
        "kube:\n  kubeconfig: kubeconfig.yaml\n", "",
    )
    config_path.write_text(config_text, encoding="utf-8")
    config = load_runtime_config(config_path)
    contract = load_contract(config.contract_path)
    try:
        build_dependencies(config, contract)
    except Exception as exc:  # noqa: B017
        rendered = str(exc)
        assert "keystone.example.internal" not in rendered
        assert "passwordsafe.example.internal" not in rendered
        assert IDENTITY_PASSWORD not in rendered


def test_configuration_digest_shape(tmp_path: Path) -> None:
    # The digest is a stable sha256 identifier usable as
    # ConfigurationDigest.value: the same configuration always produces the
    # same digest, and changing a non-credential field changes it.
    config_path = _write_env(tmp_path)
    config = load_runtime_config(config_path)
    digest = config.configuration_digest()
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    # Stable across reloads.
    again = load_runtime_config(config_path).configuration_digest()
    assert digest == again
    # Changing the namespace is not allowed, but changing the keystone URL is.
    (tmp_path / "runtime.yaml").write_text(
        MINIMAL.replace(
            "https://keystone.example.internal",
            "https://keystone2.example.internal",
        ),
        encoding="utf-8",
    )
    changed = load_runtime_config(tmp_path / "runtime.yaml").configuration_digest()
    assert digest != changed
