"""Only fixed, value-free messages may cross the CLI error boundary."""

class SafeError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class ConfigError(SafeError):
    pass


class ReadError(SafeError):
    pass


class RepresentationError(SafeError):
    pass
