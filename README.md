# ipi-multidomain-agent study

Indirect Prompt Injection Attacks and Defenses across Multi-Domain LLM Agents: An Empirical Study Based on AgentDojo.

## Status

The original Gemini 3.5 Flash-Lite static corpus baseline is complete: 0/110
native AgentDojo injection successes, with all 110 payloads delivered to the
model. Phase 6A was a bounded, model-adaptive calibration attempt intended to
replace that floor; its final development search found 0/38 native successes,
so it did not qualify a held-out Gemini defense comparison. This is a
model-and-attack-set null result, not a claim of immunity.

The empirical defense track is therefore model-separated under Gemma 4
(`gemma-4-26b-a4b-it`). Its parity baseline found 5/110 successes, all in
Banking. The predeclared selected-payload Banking follow-up found 34/160
successes on fresh cases and 6/20 on replication cases; those results are
Banking- and payload-selection-specific. A defended follow-up run is not yet
included.

The complete Phase 6A calibration code and raw artifacts remain preserved on
the `phase-6a-attack-calibration` branch, with the later full history preserved
on `phase-8-defense-spotlighting`. The curated main branch intentionally omits
the Phase 6A generator, mutation, split, clean-control, and calibration-data
bulk. The frozen Gemma diagnostic evidence remains under `data/diagnostics/`;
its replay driver stays on the archive branch because it consumes the archived
Phase 6A manifests.

The main research track therefore keeps the original static null, the Gemma
diagnostic/baseline/follow-up evidence, shared execution and schema safeguards,
and the spotlighting implementation as separate, traceable datasets.
