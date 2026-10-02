from __future__ import annotations

import httpx
import pytest

from admin_password_rotation.external_http import (
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ExternalClientError,
    HttpClientSettings,
    HttpRequest,
    HttpTransportError,
    HttpTransportErrorCode,
    HttpxTransport,
)


def test_http_settings_have_bounded_defaults() -> None:
    settings = HttpClientSettings("https://identity.example.test")
    assert settings.connect_timeout_seconds == DEFAULT_CONNECT_TIMEOUT_SECONDS == 5.0
    assert settings.request_timeout_seconds == DEFAULT_REQUEST_TIMEOUT_SECONDS == 30.0


@pytest.mark.parametrize("value", [0.0, -1.0, float("inf"), float("nan")])
def test_http_settings_reject_invalid_timeouts(value: float) -> None:
    with pytest.raises(ValueError):
        HttpClientSettings("https://identity.example.test", connect_timeout_seconds=value)
    with pytest.raises(ValueError):
        HttpClientSettings("https://identity.example.test", request_timeout_seconds=value)


def test_httpx_transport_makes_one_direct_request_without_leaking_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fail_request(
        _client: httpx.Client, _method: str, _url: str,
        **_kwargs: object,
    ) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectTimeout("TRANSPORT_SECRET_SENTINEL")

    monkeypatch.setattr(httpx.Client, "request", fail_request)
    transport = HttpxTransport(HttpClientSettings("https://keystone.example.test"))
    with pytest.raises(HttpTransportError) as raised:
        transport.send(HttpRequest(
            "PATCH", "/v3/users/admin", body=b"ADMIN_SECRET_SENTINEL", mutation=True,
        ))
    transport.close()

    assert calls == 1
    assert raised.value.kind is HttpTransportErrorCode.MUTATION_AMBIGUOUS
    visible = str(raised.value) + repr(raised.value)
    assert "TRANSPORT_SECRET_SENTINEL" not in visible
    assert "ADMIN_SECRET_SENTINEL" not in visible


def test_invalid_transport_configuration_has_safe_error() -> None:
    with pytest.raises(ExternalClientError) as raised:
        HttpxTransport(HttpClientSettings("not-a-url"))
    assert "not-a-url" not in str(raised.value) + repr(raised.value)
