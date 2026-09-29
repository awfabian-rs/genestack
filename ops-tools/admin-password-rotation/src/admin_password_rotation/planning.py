"""Pure topology planning over an immutable inventory; no I/O or mutation."""
from __future__ import annotations

from .discovery import classify, discover_unexpected
from .errors import ReadError, RepresentationError
from .model import (
    CredentialContract, CredentialLocation, CredentialState, Finding,
    IdentityBinding, LocationObservation, LocationRole, ReferenceCredentials,
    RestartDependency, SecretInventory, TopologyPlan, WorkloadRef,
)
from .representations import read_credential


def build_topology_plan(
    contract: CredentialContract, inventory: SecretInventory, *, input_mode: str = "snapshot",
) -> TopologyPlan:
    if inventory.namespace != contract.namespace:
        raise ReadError("namespace_mismatch", "Contract and inventory namespaces differ.")
    secrets = {x.name: x for x in inventory.secrets}
    source = secrets.get(contract.source.secret)
    references: ReferenceCredentials | None = None
    findings: list[Finding] = []
    if source is not None:
        try:
            references = ReferenceCredentials(read_credential(source, contract.source.representation).password)
        except RepresentationError:
            pass  # The ordinary location loop emits the precise safe finding.
    observations: list[LocationObservation] = []
    accepted: list[CredentialLocation] = []
    dependencies: dict[WorkloadRef, list[str]] = {}
    for location in contract.locations:
        secret = secrets.get(location.secret)
        state = CredentialState.MISSING
        if secret is None:
            findings.append(Finding("missing_secret", "A configured required Secret is absent.", location.name, location.secret))
        else:
            try:
                observed = read_credential(secret, location.representation)
                state = CredentialState.NO_REFERENCE if references is None else classify(location, observed, references)
            except RepresentationError as exc:
                state = CredentialState.UNREADABLE
                findings.append(Finding(exc.code, exc.message, location.name, location.secret))
            if state in (CredentialState.UNKNOWN, CredentialState.UNVERIFIED_BREAKGLASS, CredentialState.NO_REFERENCE):
                findings.append(Finding(state.value, "Credential state cannot be accepted as stable admin relative to the available reference.", location.name, location.secret))
            if state is CredentialState.MATCHES_ADMIN_REFERENCE:
                accepted.append(location)
                if location.role is LocationRole.PROPAGATED and location.identity is IdentityBinding.ACTIVE:
                    for target in location.restart:
                        dependencies.setdefault(target, []).append(location.name)
        observations.append(LocationObservation(
            location.name, location.secret, state,
            None if secret is None else secret.uid,
            None if secret is None else secret.resource_version,
        ))
    if references is None:
        findings.append(Finding("reference_unavailable", "Canonical breeder comparison unavailable; broad known-password audit cannot run."))
    else:
        findings.extend(discover_unexpected(contract, inventory, references, tuple(accepted)))
    restarts = tuple(
        RestartDependency(workload, tuple(sorted(set(causes))))
        for workload, causes in sorted(dependencies.items(), key=lambda x: x[0].label)
    )
    return TopologyPlan(
        contract.namespace, inventory.resource_version, input_mode, len(inventory.secrets),
        tuple(observations), tuple(findings), restarts,
    )
