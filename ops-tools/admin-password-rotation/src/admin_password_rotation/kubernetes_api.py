"""Narrow construction boundary for generated Kubernetes Python API clients."""
from __future__ import annotations

import importlib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, cast

from .errors import ReadError


@dataclass(frozen=True)
class KubernetesApiHandle:
    api: object
    serializer: object


def validate_api_options(*, context: str | None, timeout: float) -> None:
    if context is not None and (
        not context or context.startswith("-") or any(ord(char) < 32 for char in context)
    ):
        raise ReadError("invalid_context", "The kubeconfig context is invalid.")
    if not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise ReadError(
            "invalid_timeout", "Timeout must be finite, positive, and at most 3600 seconds.",
        )


def create_kubernetes_api(
    api_class_name: str, *, context: str | None = None,
    kubeconfig: Path | None = None,
) -> KubernetesApiHandle:
    """Create one generated API facade with an isolated API client.

    Explicit kubeconfig selection wins. Otherwise in-cluster credentials are
    attempted before the current kubeconfig context. The untyped generated
    client is contained here and narrowed by each caller's small protocol.
    """
    client_module = importlib.import_module("kubernetes.client")
    config_module = importlib.import_module("kubernetes.config")
    config_exception_module = importlib.import_module(
        "kubernetes.config.config_exception",
    )
    api_client_type = cast(Callable[..., object], getattr(client_module, "ApiClient"))
    configuration_type = cast(
        Callable[..., object], getattr(client_module, "Configuration"),
    )
    api_type = cast(Callable[..., object], getattr(client_module, api_class_name))
    load_incluster = cast(
        Callable[..., None], getattr(config_module, "load_incluster_config"),
    )
    new_client_from_config = cast(
        Callable[..., object], getattr(config_module, "new_client_from_config"),
    )
    config_exception_type = cast(
        type[Exception], getattr(config_exception_module, "ConfigException"),
    )

    if context is not None or kubeconfig is not None:
        api_client = new_client_from_config(
            config_file=None if kubeconfig is None else str(kubeconfig),
            context=context,
            persist_config=False,
        )
    else:
        configuration = configuration_type()
        try:
            load_incluster(client_configuration=configuration)
            api_client = api_client_type(configuration=configuration)
        except config_exception_type:
            api_client = new_client_from_config(persist_config=False)
    return KubernetesApiHandle(api_type(api_client=api_client), api_client)
