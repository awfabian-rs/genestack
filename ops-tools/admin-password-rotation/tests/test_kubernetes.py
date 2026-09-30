from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest

from admin_password_rotation.errors import ReadError
from admin_password_rotation.kubernetes import KubectlReader, SnapshotReader, SubprocessRunner, parse_inventory
from .helpers import PASSWORD, ROOT, inventory_json


class RecordingRunner:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def run(self, argv: tuple[str, ...], timeout: float) -> bytes:
        self.calls.append((argv, timeout))
        return self.raw


def test_live_adapter_only_issues_get_secrets_and_preserves_context() -> None:
    runner = RecordingRunner((ROOT / "tests/fixtures/prod-stable.json").read_bytes())
    reader = KubectlReader(context="lab;not-a-shell", kubeconfig=Path("/tmp/test config"), timeout=9, runner=runner)
    inv = reader.list_secrets("openstack")
    assert len(inv.secrets) == 23
    assert runner.calls == [((
        "kubectl", "--context=lab;not-a-shell", "--kubeconfig=/tmp/test config",
        "--namespace=openstack", "--request-timeout=9s", "get", "secrets", "-o", "json", "--chunk-size=500",
    ), 9)]


@pytest.mark.parametrize("context", ["", "-bad", "line\nbreak"])
def test_bad_context_rejected(context: str) -> None:
    with pytest.raises(ReadError):
        KubectlReader(context=context)


@pytest.mark.parametrize("timeout", [0, -1, 3601, float("nan"), float("inf")])
def test_bad_timeout_rejected(timeout: float) -> None:
    with pytest.raises(ReadError):
        KubectlReader(context="lab", timeout=timeout)


def test_other_namespace_not_read() -> None:
    runner = RecordingRunner(b"")
    with pytest.raises(ReadError):
        KubectlReader(context="lab", runner=runner).list_secrets("kube-system")
    assert runner.calls == []


def test_snapshot_base64_and_resource_versions() -> None:
    raw = inventory_json(data={"password": base64.b64encode(PASSWORD).decode()})
    result = SnapshotReader(raw).list_secrets("openstack")
    assert result.resource_version == "123"
    value = result.secrets[0].get("password")
    assert value is not None and value.reveal() == PASSWORD
    assert result.secrets[0].resource_version == "1"
    assert result.secrets[0].uid == "u"


def test_generic_kubectl_list_may_lack_collection_resource_version() -> None:
    result = parse_inventory(inventory_json(kind="List", resource_version=""), "openstack")
    assert result.resource_version is None
    assert result.secrets[0].resource_version == "1"


@pytest.mark.parametrize(("kind", "resource_version"), [
    ("SecretList", ""), ("SecretList", None), ("List", 1),
])
def test_invalid_collection_resource_version_rejected(kind: str, resource_version: object) -> None:
    with pytest.raises(ReadError, match="invalid_string"):
        parse_inventory(inventory_json(kind=kind, resource_version=resource_version), "openstack")


@pytest.mark.parametrize("data", [{"password": "not base64!!SECRET_SENTINEL"}, {"password": 4}, {"bad key": "YQ=="}, [1, 2]])
def test_bad_secret_data(data: object) -> None:
    with pytest.raises(ReadError) as error:
        parse_inventory(inventory_json(data=data), "openstack")
    assert "SECRET_SENTINEL" not in str(error.value)


@pytest.mark.parametrize("metadata", [
    {"namespace": "other", "name": "name", "uid": "u", "resourceVersion": "1"},
    {"namespace": "openstack", "name": "name", "resourceVersion": "1"},
    {"namespace": "openstack", "name": "Name", "uid": "u", "resourceVersion": "1"},
])
def test_secret_metadata_is_validated(metadata: object) -> None:
    with pytest.raises(ReadError):
        parse_inventory(inventory_json(meta=metadata), "openstack")


def test_incomplete_pagination_fails() -> None:
    raw = b'{"apiVersion":"v1","kind":"SecretList","metadata":{"resourceVersion":"1","continue":"more"},"items":[]}'
    with pytest.raises(ReadError, match="incomplete_inventory"):
        parse_inventory(raw, "openstack")


def test_duplicate_json_keys_fail() -> None:
    with pytest.raises(ReadError, match="duplicate_json_key"):
        parse_inventory(b'{"items":[],"items":[]}', "openstack")


def test_duplicate_secret_objects_fail() -> None:
    raw = b'{"apiVersion":"v1","kind":"SecretList","metadata":{"resourceVersion":"1"},"items":['
    obj = json.dumps({"apiVersion":"v1","kind":"Secret","metadata":{"namespace":"openstack","name":"same","uid":"u","resourceVersion":"1"},"data":{}}).encode()
    with pytest.raises(ReadError, match="duplicate_secret"):
        parse_inventory(raw + obj + b"," + obj + b"]}", "openstack")


@pytest.mark.parametrize("raw", [b"not json SECRET_SENTINEL", b"\xff", b"[]", b"null", b"{}"])
def test_invalid_inventory_errors_do_not_echo_input(raw: bytes) -> None:
    with pytest.raises(ReadError) as error:
        parse_inventory(raw, "openstack")
    assert "SECRET_SENTINEL" not in str(error.value)


def test_subprocess_failure_withholds_raw_stdout_and_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        return subprocess.CompletedProcess(["kubectl"], 1, b"SECRET_SENTINEL", b"SECRET_SENTINEL")
    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(ReadError) as error:
        SubprocessRunner().run(("kubectl", "get", "secrets"), 5)
    assert "SECRET_SENTINEL" not in str(error.value)


def test_timeout_withholds_captured_body(monkeypatch: pytest.MonkeyPatch) -> None:
    def timed_out(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(["kubectl"], 5, b"SECRET_SENTINEL", b"SECRET_SENTINEL")
    monkeypatch.setattr(subprocess, "run", timed_out)
    with pytest.raises(ReadError, match="kubernetes_timeout") as error:
        SubprocessRunner().run(("kubectl",), 5)
    assert "SECRET_SENTINEL" not in str(error.value)
