# Reference design documents

keystone-admin-rotation-implementation-brief.md
    Current implementation-facing design baseline.
    Explicit amendments override conflicting v0.1 specification text.

keystone-admin-rotation-specification/
    September 25 v0.1 reference specification.
    Useful for compatible detail and rationale.
    NOT the current implementation schema where superseded by the brief
    or by already-implemented code.

## Post-brief amendments

- Exact historical old-A PasswordSafe retrieval remains an exceptional
  recovery requirement, but its implementation is deliberately deferred
  until the A-recovery slice establishes the concrete need. Slice 3A does
  not expose `get_exact_history_version()`.

- Separate same-value mutation capability probes are not required.
  Capability is established by the first real mutation that the workflow
  actually needs, together with the normal read-after-write or other
  postcondition verification.

  In PREPARE_B, the first PasswordSafe B staging mutation establishes
  PasswordSafe write capability. If that mutation fails definitively,
  PREPARE_B fails while A and all managed consumers remain unchanged.

  Before A rotation, the real admin lockout-suppression mutation must be
  positively observed as active before breeder staging or admin password
  mutation is permitted. A separate `false -> false` lockout capability
  probe is not required.
