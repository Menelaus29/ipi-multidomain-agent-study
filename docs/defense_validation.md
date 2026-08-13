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

## Primary 160-fresh result

The frozen v1 custom defense was then evaluated on the isolated 160-row fresh
complement only. `data/defended/g4/v1/fresh160/validation_report.json` confirms
160/160 exact ordered keys, unique present raw traces, zero raw errors, Gemma
model provenance, holdout split, and matching index/raw verdicts. The aggregate
was run with `aggregate_results.py` and is saved in
`data/defended/g4/v1/fresh160/aggregate_summary.csv`.

| Matching partition | Native successes | ASR | Utility successes | Utility |
|---|---:|---:|---:|---:|
| Undefended fresh160 | 34/160 | 21.25% | 103/160 | 64.375% |
| Frozen `my_spotlighting` v1 | 4/160 | 2.50% | 115/160 | 71.875% |

The primary comparison in `data/defended/g4/v1/summary.csv` reports an absolute
ASR reduction of 18.75 percentage points (88.24% relative), a +7.50-point
utility change, and paired 95% bootstrap intervals from 10,000 resamples with
seed `20260805`: [13.125%, 25.000%] for ASR reduction and [2.500%, 13.125%]
for utility change. The before/after chart is
`report/figures/gemma_banking_fresh160_before_after.png` and is labeled
“160-fresh partition only.” No replication row is included in this comparison;
the replication panel remains development/validation-only permanently.
