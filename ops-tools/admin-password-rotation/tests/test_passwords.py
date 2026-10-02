from __future__ import annotations

import pytest

from admin_password_rotation.model import SecretValue
from admin_password_rotation.passwords import (
    ADMIN_PASSWORD_ALPHABET,
    ADMIN_PASSWORD_LENGTH,
    generate_admin_password,
)


def test_generated_password_has_required_shape_and_redacted_representation() -> None:
    password = generate_admin_password()
    cleartext = password.reveal().decode("ascii")

    assert isinstance(password, SecretValue)
    assert len(cleartext) == ADMIN_PASSWORD_LENGTH == 32
    assert set(cleartext) <= set(ADMIN_PASSWORD_ALPHABET)
    assert cleartext not in repr(password)
    assert cleartext not in str(password)


def test_generator_uses_secrets_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def choose(alphabet: str) -> str:
        calls.append(alphabet)
        return "A"

    # The production implementation imports the cryptographic `secrets` module.
    monkeypatch.setattr("admin_password_rotation.passwords.secrets.choice", choose)
    generated = generate_admin_password()

    assert generated.reveal() == b"A" * ADMIN_PASSWORD_LENGTH
    assert calls == [ADMIN_PASSWORD_ALPHABET] * ADMIN_PASSWORD_LENGTH


def test_multiple_generated_passwords_remain_valid() -> None:
    for password in (generate_admin_password(), generate_admin_password()):
        cleartext = password.reveal().decode("ascii")
        assert len(cleartext) == 32
        assert set(cleartext) <= set(ADMIN_PASSWORD_ALPHABET)
