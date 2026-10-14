"""Slice 5B: production dependency composition.

``build_dependencies`` assembles the production clients and stores the existing
rotation phases consume, from a validated ``RuntimeConfig``.

Construction is strictly offline.  Building the dependency structure:

- never authenticates to Keystone or Rackspace Identity/PasswordSafe;
- never acquires, renews, or releases the ownership Lease;
- never reads or mutates the transaction state Secret, the breeder Secret, or
  any propagated Secret;
- never restarts a workload;
- never advances, inspects, or repairs a rotation transaction.

The generated Kubernetes Python API clients are constructed without contacting
the API server (``create_kubernetes_api`` performs only local credential
resolution: in-cluster config when available, otherwise the selected
kubeconfig).  Live behavior -- authentication, observation, mutation -- happens
only through the explicitly invoked operations in ``auth_bootstrap`` and the
phase runners themselves.

The resulting ``Dependencies`` value is a plain frozen container; the future
transaction runner (Slice 5C) consumes it without knowing how each client was
instantiated.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .breeder import (
    BreederSecretClient, KubernetesApiBreederSecretClient,
    KubernetesApiConditionalBreederPatch,
)
from .external_http import HttpClientSettings, HttpxTransport
from .keystone import HttpKeystoneClient, KeystoneClient
from .lease import (
    KubernetesLeaseStore, KubernetesApiLeaseTransport, LeaseManager,
    LeaseReference,
)
from .kubernetes_api import KubernetesApiHandle, create_kubernetes_api
from .model import CredentialContract
from .passwordsafe import (
    HttpPasswordSafeClient, HttpRackspaceIdentityClient, PasswordSafeClient,
    RackspaceIdentityClient,
)
from .propagation import (
    CredentialSecretClient, KubernetesApiCredentialSecretClient,
)
from .restart import (
    WorkloadClient, _AppsV1Api,  # type: ignore[reportPrivateUsage]
    _KubernetesSerializer,  # type: ignore[reportPrivateUsage]
    make_workload_client,
)
from .runtime_config import RuntimeConfig
from .state_store import (
    KubernetesApiStateSecretTransport, KubernetesStateStore, StateStore,
    StateSecretReference,
)
from .verify_a import ConditionalBreederPatch


@dataclass(frozen=True)
class Dependencies:
    """The fully constructed production dependency set.

    Every member is a client, store, or manager consumed by the existing phase
    runners; none of them performs live work on construction.
    """

    config: RuntimeConfig
    contract: CredentialContract
    keystone: KeystoneClient
    rackspace_identity: RackspaceIdentityClient
    passwordsafe: PasswordSafeClient
    state_store: StateStore
    lease_store: KubernetesLeaseStore
    lease_manager: LeaseManager
    breeder: BreederSecretClient
    secret_client: CredentialSecretClient
    workload_client: WorkloadClient
    breeder_patch: ConditionalBreederPatch

    def __repr__(self) -> str:
        return (
            f"Dependencies(environment="
            f"{self.config.environment.environment_id!r}, "
            f"namespace={self.config.namespace!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def _keystone_transport(config: RuntimeConfig) -> HttpxTransport:
    return HttpxTransport(HttpClientSettings(
        base_url=config.keystone_base_url,
        trusted_ca=config.keystone_trusted_ca,
        connect_timeout_seconds=config.keystone_connect_timeout_seconds,
        request_timeout_seconds=config.keystone_request_timeout_seconds,
    ))


def _passwordsafe_identity_transport(config: RuntimeConfig) -> HttpxTransport:
    return HttpxTransport(HttpClientSettings(
        base_url=config.passwordsafe_identity_base_url,
        trusted_ca=config.passwordsafe_trusted_ca,
        connect_timeout_seconds=config.passwordsafe_connect_timeout_seconds,
        request_timeout_seconds=config.passwordsafe_request_timeout_seconds,
    ))


def _passwordsafe_transport(config: RuntimeConfig) -> HttpxTransport:
    return HttpxTransport(HttpClientSettings(
        base_url=config.passwordsafe_base_url,
        trusted_ca=config.passwordsafe_trusted_ca,
        connect_timeout_seconds=config.passwordsafe_connect_timeout_seconds,
        request_timeout_seconds=config.passwordsafe_request_timeout_seconds,
    ))


def _kubernetes_handle(
    config: RuntimeConfig, api_class_name: str,
) -> KubernetesApiHandle:
    # create_kubernetes_api performs only local credential resolution
    # (in-cluster config or the selected kubeconfig); it does not contact the
    # API server.
    return create_kubernetes_api(
        api_class_name,
        context=config.kube_context,
        kubeconfig=config.kubeconfig_path,
    )


def build_dependencies(
    config: RuntimeConfig, contract: CredentialContract,
) -> Dependencies:
    """Assemble every production client from a validated runtime configuration.

    ``contract`` must be the validated credential-location contract for
    ``config.contract_path`` (the loader already validated that its namespace
    matches); it is retained here so the dependency set carries the exact
    validated contract the phases consume.

    Construction never contacts an external system: the Kubernetes Python
    API facades are constructed by local credential resolution only
    (in-cluster config when available, otherwise the selected kubeconfig).
    Construction failures from that resolution surface as each client's own
    narrow error type (``BreederError``, ``StateStoreError``, ...).
    """
    keystone = HttpKeystoneClient(_keystone_transport(config))
    identity = HttpRackspaceIdentityClient(
        _passwordsafe_identity_transport(config),
        token_path=config.passwordsafe_identity_token_path,
        domain_name=config.passwordsafe_identity_domain_name,
    )
    passwordsafe = HttpPasswordSafeClient(_passwordsafe_transport(config))

    state_store = KubernetesStateStore(
        StateSecretReference(config.namespace, config.state_secret_name),
        KubernetesApiStateSecretTransport.from_config(
            context=config.kube_context,
            kubeconfig=config.kubeconfig_path,
            timeout=config.kubernetes_api_timeout_seconds,
        ),
    )
    lease_timing = config.lease_timing()
    lease_store = KubernetesLeaseStore(
        LeaseReference(config.namespace, config.lease_name),
        lease_timing,
        KubernetesApiLeaseTransport.from_config(
            context=config.kube_context,
            kubeconfig=config.kubeconfig_path,
            timeout=config.lease_api_timeout_seconds,
            timing=lease_timing,
        ),
    )
    lease_manager = LeaseManager(lease_store, lease_timing)

    breeder = KubernetesApiBreederSecretClient.from_config(
        context=config.kube_context,
        kubeconfig=config.kubeconfig_path,
        timeout=config.kubernetes_api_timeout_seconds,
    )
    secret_client = KubernetesApiCredentialSecretClient.from_config(
        context=config.kube_context,
        kubeconfig=config.kubeconfig_path,
        timeout=config.kubernetes_api_timeout_seconds,
    )
    apps_handle = _kubernetes_handle(config, "AppsV1Api")
    workload_client: WorkloadClient = make_workload_client(
        cast(_AppsV1Api, apps_handle.api),
        cast(_KubernetesSerializer, apps_handle.serializer),
        timeout=config.kubernetes_api_timeout_seconds,
    )
    breeder_patch = KubernetesApiConditionalBreederPatch.from_config(
        context=config.kube_context,
        kubeconfig=config.kubeconfig_path,
        timeout=config.kubernetes_api_timeout_seconds,
    )

    return Dependencies(
        config=config,
        contract=contract,
        keystone=keystone,
        rackspace_identity=identity,
        passwordsafe=passwordsafe,
        state_store=state_store,
        lease_store=lease_store,
        lease_manager=lease_manager,
        breeder=breeder,
        secret_client=secret_client,
        workload_client=workload_client,
        breeder_patch=breeder_patch,
    )
