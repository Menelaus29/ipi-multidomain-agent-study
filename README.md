# ipi-multidomain-agent study

Indirect Prompt Injection Attacks and Defenses across Multi-Domain LLM Agents: An Empirical Study Based on AgentDojo.

## Status

The original Gemini 3.5 Flash-Lite static corpus baseline is complete: 0/110
native AgentDojo injection successes, with all 110 payloads delivered to the
model. Phase 6A was a bounded, model-adaptive calibration attempt intended to
replace that floor; its final development search found 0/38 native successes,
so it did not qualify a held-out Gemini defense comparison. This is a
model-and-attack-set null result, not a claim of immunity.

The empirical defense track is model-separated under Gemma 4
(`gemma-4-26b-a4b-it`). Its parity baseline found 5/110 successes, all in
Banking. The selected-payload Banking follow-up found 34/160 successes on fresh
cases and 6/20 on replication cases; the frozen defense reduced the matched
fresh result to 4/160. The bounded adaptive searches bypassed 1/5 payloads in
v1, 1/5 in v2a, and 5/5 in v2b. These are Banking- and
payload-selection-specific results, and the adaptive counts are payload-level
bypass coverage rather than post-adaptive ASR.

Under the executed repository-scope decision, the complete failed Phase 6A
calibration code and raw artifacts remain branch-local on
`phase-6a-attack-calibration`, with the later full history also reachable from
`phase-8-defense-spotlighting`; they were not merged into curated `main`. The
frozen Gemma diagnostic evidence remains under `data/diagnostics/`; its replay
driver stays on the archive branch because it consumes the archived Phase 6A
manifests.

The main research track therefore keeps the original static null, the Gemma
diagnostic/baseline/follow-up evidence, shared execution and schema safeguards,
and the spotlighting implementation as separate, traceable datasets.
