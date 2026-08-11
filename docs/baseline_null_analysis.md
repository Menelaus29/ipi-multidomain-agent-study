# Static Baseline Null Analysis

## Scope

This analysis covers the original Phase 6 static-corpus baseline: 110 undefended
AgentDojo cases executed with `google-gemini-3.5-flash-lite`. The payloads were
fixed before these runs and received no feedback from this target model. This is
therefore a result about one static attack corpus, one model, and the selected
Workspace, Banking, and Slack task matrix. It is not a result from the later
model-adaptive calibration protocol.

The source records remain unchanged in
[`data/baseline/results.jsonl`](../data/baseline/results.jsonl), with the planned
case manifest in [`data/baseline/plan.tsv`](../data/baseline/plan.tsv). The
reproducible no-API audit writes a per-case index to
[`data/baseline/exposure_audit.csv`](../data/baseline/exposure_audit.csv) and the
aggregate counts to
[`data/baseline/exposure_summary.json`](../data/baseline/exposure_summary.json).

## Audit method

`src.analysis.audit_baseline_exposure` requires exactly 110 unique planned
cases and exact equality between the plan and result-index case keys. For every
case, it requires a distinct AgentDojo raw trace and fails if that file is
missing, empty, outside `data/baseline/raw/`, malformed, duplicated across
cases, or marked with an error. It also checks that the trace's domain and task
identifiers match the plan, that its complete message list matches the indexed
trace, and that the native AgentDojo `security` verdict agrees with
`attack_success`.

Exposure is checked only against text in model-facing tool messages. The audit
uses three ordered match modes:

- **Literal:** the injected string is an exact substring of a tool message.
- **Normalized:** the strings match after conservative serialization
  normalization: Unicode NFKC, whitespace collapsing, straightening curly
  quotes, and undoing doubled single quotes introduced by YAML-style tool
  serialization. This does not decode attack encodings.
- **Decoded:** an injection containing explicit `\uXXXX` or `\UXXXXXXXX`
  sequences matches after those sequences are decoded and the same conservative
  normalization is applied.

The audit does not search the trace's `injections` metadata as proof of
visibility; that field supplies the expected injected value. Proof requires the
value to occur in a tool result that was placed in the model conversation.

## Reproduced results

The audit completed successfully on all 110 planned cases:

| Domain | Cases | Injection visible | Attack success | Legitimate utility success |
|---|---:|---:|---:|---:|
| Workspace | 52 | 52 | 0 | 52 |
| Banking | 46 | 46 | 0 | 26 |
| Slack | 12 | 12 | 0 | 12 |
| **Total** | **110** | **110** | **0** | **90** |

All 110 injections were visible in model-facing tool content. None was an exact
literal substring after AgentDojo serialized the tool result: 102 were recovered
by serialization-normalized matching and eight Unicode-escape cases were
recovered by decoded matching. AgentDojo's native injection-task verdict was
false in every case, giving an observed static-corpus ASR of 0/110. Its native
legitimate-task utility verdict was true in 90/110 cases.

## Delivery failure versus model behavior

The 110/110 exposure result rules out failure to place the injection in the
model-facing tool output as the explanation for the zero observed ASR. The
model received content carrying the injected goal but did not execute that goal
in any recorded case.

That finding should not be overstated as 110 explicit refusals. Many traces show
the model continuing with the legitimate task rather than emitting a refusal,
and 20 Banking cases also failed AgentDojo's legitimate-utility check. The
supported conclusion is behavioral noncompliance with these injected goals
after successful delivery. The audit alone does not identify whether this came
from learned hardening, general instruction following, task-specific behavior,
or another mechanism.

## Floor effect and consequence for defense evaluation

An observed undefended ASR of zero creates a floor: a defended result cannot
show a reduction below zero. If a defense also produced 0/110, that equality
would not demonstrate that the defense prevented any attack. Relative reduction
is undefined because its undefended denominator is zero, and no defense
reduction can be calculated from this original static baseline.

The original 0/110 result must therefore remain a separate static-corpus null
finding. It cannot serve as the denominator for a defense-effectiveness claim.
Phase 6A prospectively calibrates attacks on development data, freezes the
attack set, and evaluates it on unseen held-out contexts; only a held-out
undefended baseline that passes the predeclared nonzero-success gate can support
the later matched defense comparison.

## Context from recent work

Google DeepMind describes automated red teaming, adaptive evaluation, and model
hardening against indirect prompt injection for the Gemini 2.5 family [14].
That publication provides relevant context for why older fixed attacks may
transfer poorly, but it neither reports a prompt-injection score for
Gemini 3.5 Flash-Lite nor establishes the cause of this project's result.

Hofer, Debenedetti, and Tramèr adapt automated prompt-injection search to
AgentDojo and report that their black-box TAP approach outperformed the tested
gradient-based method under practical budgets. They also find that attack
quality depends on the attacker model and that attacks optimized on smaller
models do not reliably transfer to frontier models [15]. This supports
target-specific calibration while leaving held-out evaluation untouched.

Zhan et al. show that defenses which appear effective against fixed attacks can
be bypassed by attacks adapted to the defense [16]. Their result motivates the
separate defense-adaptive evaluation in Phases 10–11; it must not be conflated
with Phase 6A's undefended model-adaptive calibration.

Bhagwatkar et al. identify weak attacks, flawed success metrics, and
implementation bugs as limitations in public agent-security benchmarks [17].
Their analysis reinforces the narrow interpretation here: saturation of a fixed
corpus/model pairing is not evidence that indirect prompt injection is solved.

## Limitations and permitted claim

This audit proves trace-level delivery and reproduces AgentDojo's native
security and utility verdicts. It does not prove that every model-internal
representation preserved every character identically, explain the model's
causal decision process, or generalize beyond the selected cases and model.

The permitted claim is:

> The original 2023–2024-style static corpus reached Gemini 3.5 Flash-Lite in
> all 110 selected AgentDojo cases but produced no native injection-task
> successes; this is a static corpus/model null result with a floor that cannot
> measure defense reduction.

This result does not establish that Gemini 3.5 Flash-Lite is immune, that prompt
injection is solved, or that a future defense prevented these attacks.

## Phase 6A pre-API protocol provenance

The following is historical provenance for the exploratory Phase 6A protocol.
The candidate manifests, calibration runner, and their raw artifacts are
intentionally archived on `phase-6a-attack-calibration` rather than copied into
the curated `main` tree. The static-null audit above remains the reproducible
result represented by this document; these hashes explain the archived
follow-up without making Phase 6A part of the public integration.

The development and held-out candidate order was generated without an API call
using fixed seed `20260807`. The development pool contains 60 contexts (20 per
domain). The holdout pool contains 1,014 contexts: 820 Workspace, 124 Banking,
and 70 Slack. All context keys are unique; the development and holdout pools
are disjoint; and the holdout pool contains none of the 22 unique contexts from
the original 110-case Phase 6 plan.

The following SHA-256 hashes are calculated over the canonical Git blob bytes
that freeze the audit, schema, quota, and candidate-split artifacts committed
before clean controls or attack calibration. Candidate selection must follow
the committed manifest order. A changed order requires a documented version
increment and new versioned manifest paths.

| Artifact | SHA-256 |
|---|---|
| `.gitattributes` | `4204dc4bbac9af24bdf26912ff25ed4a21eeaf63bcd194ec77fc74b8fb23d32e` |
| `src/analysis/audit_baseline_exposure.py` | `de7683dfdc5d8d37956d06b046c07b070168bd2f76ae2cf28543a69163441efd` |
| `data/baseline/exposure_audit.csv` | `b97530d7bcb63b0276591e827ee7e1344862072ec44886a3ac05141e109694fe` |
| `data/baseline/exposure_summary.json` | `27caae4f9aacce6ed36e0b26380979815632a105a4289d8fd8ddafc97ddc5a9a` |
| `src/schemas.py` | `5e384573e8591f8a5fa9bf742fd7dc385a6900b2207c783fd942c444f1d3f615` |
| `src/analysis/validate_schema.py` | `2434e847a58acbad033e1315a84fe011665f94ded89eade6e1b1e2d09d8f17c1` |
| `src/experiments/quota_guard.py` | `4d18ea9a7fb5f074c39e9b86eb53933ea527ae3b4e4c31d92ed968e00e86594f` |
| `src/experiments/build_attack_splits.py` | `4b3ccc9a0b5e0d0138a20d081c5523910cfe81e83c0cadd139e05f3b78d5de36` |
| `data/attack_calibration/dev_candidates.tsv` | `1b5e2542ba5fc20ad04b5b8062e9150a8ce1a4c85231653255991f17446cf725` |
| `data/attack_calibration/holdout_candidates.tsv` | `08ecfcb1c5b95ba59753c4e4ffa6dc8c228f9e51bc1029fc7316565e7178882a` |

## References

[14] Google DeepMind Security & Privacy Research Team, “Advancing Gemini's
Security Safeguards,” May 20, 2025. [Online]. Available:
https://deepmind.google/blog/advancing-geminis-security-safeguards/

[15] D. Hofer, E. Debenedetti, and F. Tramèr, “Assessing Automated Prompt
Injection Attacks in Agentic Environments,” arXiv:2606.10525, 2026. [Online].
Available: https://arxiv.org/abs/2606.10525

[16] Q. Zhan, R. Fang, H. S. Panchal, and D. Kang, “Adaptive Attacks Break
Defenses Against Indirect Prompt Injection Attacks on LLM Agents,”
arXiv:2503.00061, 2025. [Online]. Available:
https://arxiv.org/abs/2503.00061

[17] R. Bhagwatkar et al., “Indirect Prompt Injections: Are Firewalls All You
Need, or Stronger Benchmarks?” arXiv:2510.05244, 2025. [Online]. Available:
https://arxiv.org/abs/2510.05244
