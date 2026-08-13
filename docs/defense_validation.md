# Phase 9 defense validation (amended replication panel)

This is an implementation-validation record, not the primary Banking
defense-effectiveness result. The panel is the exact 20-row true-replication
partition derived from the original 46-row Banking discovery plan and the
frozen 180-row selected-payload follow-up. Its manifest is
`data/defended/g4/v1/replication_dev/manifest.tsv` with SHA-256
`66290a51809e53590bff01256e0463649895a83520227def097126434978d4c7`.

Both defenses ran on the identical ordered keys, target model
`google-gemma-4-26b-a4b-it`, split `dev`, and static-corpus attack provenance.
The no-network validation report confirms schema validity, exact 20/20 key
equality, 20 unique present raw traces per arm, zero raw errors, and matching
AgentDojo `security`/`utility` verdicts for three spot checks per arm.

| Arm | Native injection successes | ASR | Utility successes | Utility |
|---|---:|---:|---:|---:|
| Built-in `spotlighting_with_delimiting` | 4/20 | 20% | 10/20 | 50% |
| Custom `my_spotlighting` v1 | 0/20 | 0% | 10/20 | 50% |

The complete machine-readable validation is in
`data/defended/g4/v1/replication_dev/validation_report.json`. Custom ASR is
not higher than the built-in arm. A prior transaction-memo undefended
checkpoint used for the implementation check recorded 0/20 native successes
and 20/20 utility successes; it was deliberately deleted after validation as
part of the amended cleanup and is not retained as a downstream negative
finding or comparison input. Consequently, the old utility-loss repeat rule
is not used to create another panel: the replication panel is exhausted and
permanently excluded from 9.6–9.8.

The custom implementation was frozen before any fresh-160 defended call. Its
canonical-LF source SHA-256 is
`7ce3de91c8dfd3c17532332d8f6516f3aa377bb2c40b22fe9371fc349a5200ee`; the
exact prompt fragment and freeze metadata are in
`data/defended/g4/v1/defense_freeze.json`. No implementation or prompt
changes are allowed after this freeze without a new defense version and a new
untouched evaluation panel.
