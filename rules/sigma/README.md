# Portable Sigma examples

These are original, minimal Sigma-format examples intended as a bridge to real Windows Security telemetry. They are separate from the lab's normalized-JSON Python engine:

- `windows-repeated-authentication-failures.yml` matches an individual Windows Event ID 4625. It does **not** count five failures on its own; use SIEM aggregation or the Python time-window detector for that behavior.
- `windows-privileged-group-member-added.yml` matches Windows Security Events 4728, 4732, and 4756. A match is a triage signal, not proof of unauthorized activity.

The Sigma rule ecosystem provides a generic, portable detection format used across SIEM platforms. Validate and adapt the examples to your target product, event schema, audit policy and local false-positive patterns before production use. See https://github.com/SigmaHQ/sigma and https://github.com/SigmaHQ/sigma-specification.
