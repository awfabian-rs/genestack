"""Allow-listed, credential-free output. Never serialize internal secret models."""
from __future__ import annotations

import json

from .model import TopologyPlan

DEFERRED_CHECKS = (
    "passwordsafe_equality", "keystone_authentication", "breakglass_authority",
    "transaction_and_lease_inspection", "workload_existence_and_health",
    "historical_unknown_or_encoded_credential_discovery", "mutation_permissions",
)


def public_report(plan: TopologyPlan) -> dict[str, object]:
    return {
        "schema_version": 1,
        "scope": "topology_only",
        "read_only": True,
        "input_mode": plan.input_mode,
        "namespace": plan.namespace,
        "inventory_resource_version": plan.inventory_resource_version,
        "inventory_secret_count": plan.inventory_secret_count,
        "expected_location_count": len(plan.locations),
        "comparison_basis": "unverified_canonical_breeder",
        "topology_checks_passed": plan.topology_checks_passed,
        "authoritative_state_verified": False,
        "rotation_ready": False,
        "deferred_checks": list(DEFERRED_CHECKS),
        "locations": [
            {"location": x.location, "secret": x.secret, "state": x.state.value,
             "uid": x.uid, "resource_version": x.resource_version}
            for x in plan.locations
        ],
        "findings": [
            {"code": x.code, "message": x.message, "location": x.location,
             "secret": x.secret, "key": x.key}
            for x in plan.findings
        ],
        "potential_restart_dependencies": [
            {"workload": x.workload.label, "caused_by_locations": list(x.caused_by_locations),
             "hypothetical_only": True}
            for x in plan.potential_restart_dependencies
        ],
        "planned_mutations": [],
        "executed_actions": [],
    }


def render_json(plan: TopologyPlan) -> str:
    return json.dumps(public_report(plan), indent=2, sort_keys=True)


def render_text(plan: TopologyPlan) -> str:
    lines = [
        "READ-ONLY TOPOLOGY PLAN - NOT ROTATION APPROVAL",
        f"Namespace: {plan.namespace}",
        f"Input: {plan.input_mode}",
        f"Secret inventory: {len(plan.locations)} contracted locations; {plan.inventory_secret_count} Secrets inspected",
        "Comparison: canonical breeder only; PasswordSafe and Keystone NOT verified",
        "", "Credential locations:",
    ]
    for item in plan.locations:
        lines.append(f"  {item.location}: {item.state.value}")
    lines.extend(["", "Findings:"])
    if not plan.findings:
        lines.append("  none within implemented checks")
    for finding in plan.findings:
        address = "/".join(x for x in (finding.secret, finding.key) if x)
        lines.append(f"  {finding.code} {address}: {finding.message}")
    lines.extend(["", "Potential restart dependencies (hypothetical active-identity cutover only):"])
    for item in plan.potential_restart_dependencies:
        lines.append(f"  {item.workload.label} <- {', '.join(item.caused_by_locations)}")
    if not plan.potential_restart_dependencies:
        lines.append("  none derived")
    lines.extend([
        "", f"Topology checks passed: {str(plan.topology_checks_passed).lower()}",
        "Authoritative state verified: false", "Rotation ready: false",
        "Mutations planned/executed: 0/0",
        "Deferred: " + ", ".join(DEFERRED_CHECKS),
    ])
    return "\n".join(lines)
