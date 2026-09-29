from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from admin_password_rotation.cli import main
from admin_password_rotation.kubernetes import KubectlReader
from admin_password_rotation.model import SecretInventory
from .helpers import MINIMAL, PASSWORD, ROOT


def test_validate_contract_needs_no_cluster(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(self: KubectlReader, namespace: str) -> SecretInventory:
        raise AssertionError("must not read cluster")
    monkeypatch.setattr(KubectlReader, "list_secrets", forbidden)
    assert main(["validate-contract", "--contract", str(ROOT / "config/credential-contract.yaml")]) == 0
    assert "locations=24" in capsys.readouterr().out


def test_fixture_cli_success_and_boundary(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["plan", "--contract", str(ROOT / "config/credential-contract.yaml"), "--snapshot", str(ROOT / "tests/fixtures/dfw-dev-stable.json"), "--format", "json"]) == 0
    output = capsys.readouterr().out
    assert '"rotation_ready": false' in output
    assert '"topology_checks_passed": true' in output
    assert PASSWORD.decode() not in output


def test_cli_drift_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["plan", "--contract", str(ROOT / "config/credential-contract.prod.yaml"), "--snapshot", str(ROOT / "tests/fixtures/dfw-dev-stable.json")]) == 3
    assert "undeclared_password_match" in capsys.readouterr().out


def test_live_requires_explicit_context(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["plan", "--contract", str(ROOT / "config/credential-contract.yaml"), "--live"]) == 2
    assert "context_required" in capsys.readouterr().err


def test_invalid_contract_prevents_live_read(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(MINIMAL.replace("role: source", "role: propagated"))
    def forbidden(self: KubectlReader, namespace: str) -> SecretInventory:
        raise AssertionError("read occurred before config validation")
    monkeypatch.setattr(KubectlReader, "list_secrets", forbidden)
    assert main(["plan", "--contract", str(path), "--live", "--context", "lab"]) == 2
    assert "canonical_source" in capsys.readouterr().err


def test_conflicting_snapshot_context_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["plan", "--contract", str(ROOT / "config/credential-contract.yaml"), "--snapshot", "unused", "--context", "lab"]) == 2
    assert "conflicting_input" in capsys.readouterr().err


def test_bad_json_cli_does_not_leak(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(b"SECRET_SENTINEL")
    assert main(["plan", "--contract", str(ROOT / "config/credential-contract.yaml"), "--snapshot", str(path), "--format", "json"]) == 2
    output = capsys.readouterr()
    assert "SECRET_SENTINEL" not in output.out + output.err
    assert '"code": "invalid_json"' in output.out


def test_unexpected_library_error_sanitized(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def failure(self: KubectlReader, namespace: str) -> SecretInventory:
        raise RuntimeError("SECRET_SENTINEL")
    monkeypatch.setattr(KubectlReader, "list_secrets", failure)
    assert main(["plan", "--contract", str(ROOT / "config/credential-contract.yaml"), "--live", "--context", "lab"]) == 1
    output = capsys.readouterr()
    assert "internal_error" in output.err
    assert "SECRET_SENTINEL" not in output.out + output.err


def test_no_implicit_live_mode() -> None:
    with pytest.raises(SystemExit) as error:
        main(["plan", "--contract", str(ROOT / "config/credential-contract.yaml")])
    assert error.value.code == 2


def test_module_entrypoint_stdin_snapshot() -> None:
    # Runs a new Python process, but the input mode prevents all Kubernetes I/O.
    result = subprocess.run(
        [sys.executable, "-m", "admin_password_rotation", "plan", "--contract", str(ROOT / "config/credential-contract.prod.yaml"), "--snapshot", "-", "--format", "json"],
        input=(ROOT / "tests/fixtures/prod-stable.json").read_bytes(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == 0
    assert b'"rotation_ready": false' in result.stdout
    assert PASSWORD not in result.stdout + result.stderr
