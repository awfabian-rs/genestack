"""Administrative credential generation primitives."""
from __future__ import annotations

import secrets
import string
from typing import Final

from .model import SecretValue


ADMIN_PASSWORD_LENGTH: Final = 32
ADMIN_PASSWORD_ALPHABET: Final = string.ascii_uppercase + string.ascii_lowercase + string.digits + "_"


def generate_admin_password() -> SecretValue:
    """Generate one 32-character credential with the operating-system CSPRNG."""
    value = "".join(secrets.choice(ADMIN_PASSWORD_ALPHABET) for _ in range(ADMIN_PASSWORD_LENGTH))
    return SecretValue(value.encode("ascii"))
