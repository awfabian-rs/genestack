# Source basis and explicitly chosen refinements

This archive implements the bootstrap agreed in the current conversation: typed
configuration/representations, a Kubernetes reader, read-only topology planning,
tests and a coding-agent handoff. It does not export the entire private project
corpus. The original corpus remains authoritative for future design work.

## Supplied source inputs

- `synopsis(1).md`: one-shot typed Python, temporary breakglass bridge, authoritative
  triplet, structural locations, advisory planning and no credential output.
- `credential-contract.yaml`: current concrete 24-location input; preserved without
  changes as `config/credential-contract.yaml`.
- `credential-location-contract.md`: representation and identity/role semantics,
  explicit validation, no global replacement, and causal restart dependencies.
  Its older example inventory is not used to overwrite the supplied newer YAML.
- `chronicle-credential-location-discovery.md`: evidence for fields, INI, direct
  YAML and YAML-containing-YAML as the structural representations.
- `location-discovery-chronicle.md`: September 29 evidence of shared production
  inventory and DFW-DEV-only Freezer/Trove additions.
- `static-typing-apocalyse.md`: strict Pyright; meaningful typed distinctions;
  runtime validation before trusting external state.
- `workload-restart-mapping(1).md`: runtime versus init dependencies; empty restart
  lists matter; restart only from actual changed locations in the future executor.
- `superseding-ab-state-machine.md` and
  `credential-state-transition-and-propagation.md`: admin remains canonical;
  breakglass is transitional; source and derived state must not be confused.
- `minimal-execution-architecture.md`: finite executable, not a permanent service.

The supplied artifact framework distinguishes current Synopsis/design from older
exploratory Chronicles and explicitly superseded A/B symmetry. No older symmetric
stable A/B state machine or permanent API architecture was reintroduced.

The complete September 25 specification / September 29 brief were not available
as source files here. Their full text is not reconstructed or silently replaced.
The package is deliberately the narrower bootstrap discussed after that brief.

## Bootstrap choices, not quotations from the design corpus

- Use an explicit topology-only report with permanently false readiness flags.
- Keep actual identities separate from the `active` configuration binding.
- Use frozen dataclasses and narrow runtime guards rather than a schema framework.
- Use kubectl behind the reader protocol rather than adding the Kubernetes SDK.
- Preserve the current input file and derive a second full production file by
  removing the two documented DFW-DEV-only blocks; no overlay/optional framework.
- Use strict duplicate/overlap checks and conservative YAML/INI subsets.
- Include known-password scanning with exact selector accounting, while exposing
  its limited coverage rather than claiming complete credential discovery.
- Expose only validate-contract and topology plan commands, with exit status zero
  explicitly limited to the checks actually performed.

## Public implementation references checked

Pyright configuration: https://github.com/microsoft/pyright/blob/main/docs/configuration.md

ConfigParser: https://docs.python.org/3/library/configparser.html

kubectl get: https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/

Public Genestack root: https://github.com/rackerlabs/genestack

The public root listing showed ops-tools/check_octavia_ovn, but direct retrieval of
the complete ops-tools directory and current repository files was unsuccessful.
No claim is made that every current repository convention or possible directory
collision was checked. The archive changes no files outside its own directory.
