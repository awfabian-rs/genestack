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
