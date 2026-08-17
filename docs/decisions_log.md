# Decisions Log

### Phase 3.5 - Provider switch: Groq -> Google AI Studio

**Decision:** Replaced the planned Groq integration with a custom `Gemini3LLM`
factory using Google AI Studio's API-key path.

**Reason:** Groq's OpenAI-compatible endpoint had persistent schema compatibility
issues that were too complex to resolve within the project's time constraints.

**Impact:** All experiment scripts import from `src/llm_providers/google_llm_factory.py`
instead of the originally planned `scripts/groq_llm.py`; the CLI benchmark path
is permanently bypassed in favour of the Python API.

### Phase 6 - Stratified baseline matrix

**Decision:** Record one reachable user task and one native AgentDojo injection task for each payload/domain/channel case instead of the full task-by-injection expansion.

**Reason:** The channel-compatible full plan contains 6,279 task attempts, while the primary `gemini-3.6-flash` free tier is capped at 20 requests per day and benchmark attempts are multi-turn. A dry-run attempt exhausted that quota before producing its first completed record, so the full expansion is not feasible within the study timeline.

**Impact:** This initial 29-case scope was later expanded to 110 cases after the primary-model quota increased; `run_baseline.py` retains its full-matrix mode for a future rerun with still greater capacity.

### Phase 6 — Correct AgentDojo success semantics and Slack channel scope

**Decision:** Set `attack_success` equal to AgentDojo's injection-task result, and reclassify the corpus's four Slack `chat_message` cases as `web_content` cases using only native webpage injection vectors.

**Reason:** AgentDojo's installed `BaseInjectionTask.security()` contract returns `True` when the injection goal was executed, so the previous inversion was incorrect. AgentDojo v1.2.2 also has no native Slack message-body injection placeholder: `injection_dora_0` and `injection_phishing_1` are explicitly webpage vectors, while `prompt_injection_channel` modifies a channel name rather than a chat message.

**Impact:** The Workspace and Banking pilot verdicts were corrected from successful to failed attacks, and all three malformed Gemini 3.6 pilot artifacts were excluded and later deleted after a successful replacement dry run.

### Phase 6 — Goal-bound attack rendering and sleeper exclusion

**Decision:** Render every retained payload directly against the native AgentDojo injection goal, generate encoding variants from that goal at runtime, reject unresolved templates, and exclude `multi_step_sleeper` rather than simulate a missing second stage.

**Reason:** The previous renderer explicitly labeled the content untrusted, added explanatory meta-text, and combined unrelated placeholder actions with the native goal. The sleeper entries did not actually install attacker-controlled second-stage content; implementing a genuine staged environment would add substantial custom-suite complexity for little baseline benefit.

**Impact:** The malformed Gemini 3.6 pilots cannot be resumed from cache and were deleted after the successful Gemini 3.5 replacement run; the empirical corpus is 19 payloads, and AgentDojo's native `injecagent` attack is run separately as a three-suite positive control.

### Phase 6 — Primary-model and replicated-matrix expansion

**Decision:** Switch all research execution from `gemini-3.6-flash` to `gemini-3.5-flash-lite`, reserve `gemini-3.1-flash-lite` for non-recorded diagnostic fallback only, and expand the stratified matrix to two native goals and up to two native vectors per payload/domain.

**Reason:** The active Gemini 3.5 Flash-Lite quota is 15 RPM, 250k TPM, and 500 RPD, compared with the former primary's 20-RPD limit. This makes within-cell replication feasible while retaining one model across undefended, defended, and adaptive experiments.

**Impact:** This produced the 110-case static baseline (Workspace 52, Banking 46, Slack 12) with the primary model. Its planned direct reuse as the defended matrix was later superseded by the Phase 6A decision below after the observed static ASR was 0/110.

### Phase 6A — Calibrate a measurable baseline after the static 0/110 result

**Decision:** Preserve the completed 110-case corpus run as a static null result, insert a model-adaptive development/calibration phase before defense implementation, freeze three attack families, and require a prospective held-out undefended baseline with at least 15 successful attacks overall and at least five per domain before estimating defense effectiveness.

**Reason:** All 110 payloads reached Gemini 3.5 Flash-Lite, yet none executed the native AgentDojo injection goal; legitimate utility still succeeded in 90 cases. A zero undefended ASR creates a floor at which a defended zero cannot demonstrate security improvement, while recent work shows that fixed attacks can understate risk against newer, model-dependent targets and that attacks tuned after seeing evaluation cases invalidate held-out claims.

**Impact:** Phase 7 now reports the original static null separately from a frozen calibrated baseline; Phase 8.3 and all Phase 9 API execution are blocked until Phase 6A passes. New tooling and artifacts live under `src/experiments/`, `data/attack_calibration/`, and `data/calibrated_baseline/`; all new API runners use a dashboard-aware hard quota guard with a 25-request reserve. Phase 10 remains a separate defense-aware adaptive evaluation and does not overwrite the Phase 6A attack set.

### Phase 6A — Attack-set version 2 corrected mutation search

**Decision:** Preserve attack-set version 1 and its 0/40 failed calibration unchanged, and implement attack-set version 2 as a separately versioned mutation-search pipeline with canonical fenced-JSON parsing, persistent accepted-candidate feedback, bounded branching, trusted-instruction goal-achievability controls, and richer task/tool/injection-position proposer context.

**Reason:** Version 1 incorrectly rejected 33 syntactically valid candidates because Gemini wrapped the requested JSON in Markdown code fences, and malformed generations broke the feedback chain by returning later rounds to the raw seed instead of the last accepted candidate and target feedback. Its one-candidate linear chain and narrow strategy prompt also fell materially short of the broader TAP-inspired search described in SOP reference [15], so the 0/40 outcome diagnoses a search-quality failure rather than establishing that the target is unattackable.

**Impact:** Version 1 code paths and `data/attack_calibration/mutate/` artifacts, including `generator_attempts.jsonl`, remain immutable evidence of the failed calibration; reparsing the 33 fenced responses is test evidence only and must never backfill version-1 checkpoints or results. Version 2 uses distinct identifiers and output locations, retains AgentDojo's native verdict as the sole attack-success ground truth, and must be reviewed before any new quota-consuming execution or held-out evaluation.

### Phase 6A — Gemma 4 delivery-path sanity check

**Decision:** Add an explicit, replay-only `gemma4-26b-a4b` diagnostic target that replays the 18 built-in-screen cases and seven accepted v1 mutation templates through the existing AgentDojo delivery and native-verdict path.

**Reason:** The static and v1 calibration nulls require a harness-positive-control check against a less safety-tuned target, but this diagnostic is not a new study arm and must not generate, tune, freeze, or select attacks. Google’s current Gemini API documentation lists the hosted instruction-tuned model as `gemma-4-26b-a4b-it` and documents the same `google.genai.Client` generate-content and function-calling path already used here.

**Impact:** Diagnostic results, raw traces, and checkpoints are confined to `data/diagnostics/gemma4_sanity_check/` and tagged `gemma4-26b-a4b`; the runner reads calibration artifacts only as immutable inputs, never imports or writes the Phase 6A quota ledger, and cannot be selected by the calibration or baseline CLIs. Google documents RPD limits as project-scoped but model-specific, so a future Gemma execution requires its own dashboard check and does not consume the Gemini 3.5 Flash-Lite quota-guard ledger.

### Phase 6A — Gemma 4 Step 1 phase-separated trace check

**Decision:** Execute the diagnostic clean-utility pre-pass and injected replay as two explicitly ordered, independently budgeted native AgentDojo calls, with an exact Google SDK request/response capture scoped only to the diagnostic output root.

**Reason:** The original one-call diagnostic was terminated after the clean pre-pass consumed the shared process timeout, so it never reached the injected task. Separating AgentDojo's own clean and injected functions preserves the full clean signal while preventing it from starving the injected trace check.

**Impact:** A Step 1 injected run requires a fresh successful clean marker from the same isolated diagnostic output root; `google_generate_content_events.jsonl` records the exact model, system instruction, rendered messages, tool declarations, and returned responses for operator review. No renderer, verdict logic, calibration data, quota ledger, or Phase 6/6A artifact is changed.

### Phase 6A — Attack-set version 2 compact AgentDojo trace paths

**Decision:** Move only attack-set version 2 AgentDojo goal-control and mutation-target raw traces to the compact `data/a2/` namespace, and explicitly reset the zero-attempt prepared journal for `goal-control-v2:builtin:direct` before the next execution.

**Reason:** The original v2 goal-control path was 273 characters including its trace filename and failed on Windows before `journal.begin_api_attempt()` with `WinError 206`. The compact default layout preserves the full goal-control operation digest and puts that formerly failing trace at 220 characters; the longest deterministic v2 mutation target trace is 244 characters, leaving a 16-character MAX_PATH margin.

**Impact:** Version-1 paths and the quota ledger are unchanged. The reset journal had `status=prepared`, no raw or index record, and zero provider attempts, so it contains no completed API work to preserve; v2 preflight now rejects any remaining overlong AgentDojo trace path before model execution.

### Phase 6A — Attack-set version 2 goal-control logger integration

**Decision:** Wrap the v2 goal-control call to `run_task_without_injection_tasks()` in the existing `OutputLogger(str(raw_root))` pattern while retaining the compact `data/a2/` trace root; leave mutation target execution unchanged because its `benchmark_suite` path already opens `OutputLogger`.

**Reason:** The preserved `goal-control-v2:builtin:direct` journal failed before any Gemini request because the direct v2 call let `TraceLogger` inherit `Logger.get()`'s `NullLogger`, which has no `logdir`. This is a v2-runner integration gap, not a further path-length failure, and the diagnostic runner already used the correct explicit logger pattern.

**Impact:** This supersedes the prior compact-path entry's tentative journal-reset handling: the existing failed zero-attempt journal is retained as evidence and will receive a new API-attempt entry when resumed successfully. No v1 artifact, quota-ledger data, or mutation-search methodology changes.

### Phase 6A — Fail-clean AgentDojo execution and YAML renderability preflight

**Decision:** Record unexpected AgentDojo execution exceptions with their type, message, and truncated traceback in the durable operation journal, stop the active stage with a distinct non-quota exit code, and reject newly generated v2 candidates whose rendered injection makes the native AgentDojo environment invalid before any target call.

**Reason:** Socket/path errors, an empty-message failure, and a PyYAML scanner failure escaped the quota-only stage handlers as raw tracebacks. The YAML failure is deterministic candidate invalidity that can be detected through `TaskSuite.load_and_inject_default_environment()` without spending target quota; other unexpected benchmark failures must retain evidence and stop cleanly rather than be mistaken for quota exhaustion.

**Impact:** Existing validation and native-verdict acceptance rules are unchanged. The already-failed, five-request `mutation-v2:builtin:direct:c01:workspace` journal and partial raw trace remain immutable pre-validation evidence; resume recognizes that failed non-renderable target as terminal without repeating it, while future non-renderable candidates are logged as malformed generator records and never reach target execution.

### Phase 9-11 — Retarget empirical defense effectiveness to Gemma 4 26B

**Decision:** Preserve Gemini 3.5 Flash-Lite as the primary robustness finding and its failed Phase 6A.11 qualification outcome, but retarget the empirical defense-effectiveness track in Phases 9-11 to `gemma-4-26b-a4b-it`, beginning with a Phase-6-equivalent static baseline that replays the exact ordered 110-row Gemini plan and all 19 retained static-corpus payload IDs represented in it.

**Reason:** Attack-set version 2 completed cleanly with 0/38 native AgentDojo successes across all eight seeds, eight families, and three development domains; goal controls established task achievability, the Gemma diagnostic established harness validity, and every target attempt retained legitimate-task utility. Because this methodologically valid Gemini null cannot pass the Phase 6A.11/7.5 gate, it cannot support a measured defense reduction, whereas the isolated 25-case Gemma diagnostic produced two native successes (`direct`/Banking and `tool_knowledge`/Slack) and supplies the project's only empirical foothold for defense evaluation.

**Impact:** Gemini calibration data, the original 0/110 static result, and the failed 6A.11 gate remain unchanged and separately reported. New Gemma baseline artifacts live under `data/baseline_gemma4/` and default to 110-case parity rather than automatic full-matrix expansion; later Gemma defended and defense-adaptive results must remain model-separated from Gemini. The predeclared post-baseline rule is: if Gemma reaches at least 15 successes overall and at least five per domain, skip Gemma mutation search and proceed directly to Phases 8-9 with the static Gemma rows as the undefended baseline; if it is nonzero but below either threshold, stop and report total and per-domain counts for a human top-up decision; if it is zero or near zero, report the null and do not start Gemma-specific calibration automatically.

### Phase 9-11 — Banking selected-payload replication and transfer follow-up

**Decision:** After the completed Gemma parity baseline produced five native successes, all in Banking, add one fixed `gemma4-banking-followup-v1` study that evaluates the five successful payloads on a frozen 180-row Banking full-file-surface plan, analyzes its 20 repeated and 160 fresh cases separately, and permits a matched frozen-defense run only if the fresh partition contains at least five successes.

**Reason:** The original result did not pass the cross-domain gate, while an exhaustive Banking expansion or a new Gemma calibration pipeline would exceed the remaining schedule without directly testing whether the observed five-payload signal transfers. The existing filtered full-matrix path provides the required surface and goal diversity without a new live execution subsystem, provided selection bias, repeated cases, hashes, and stopping rules are declared before calls.

**Impact:** The original 110-row Gemma baseline remains immutable and is never pooled with this follow-up; `data/baseline_gemma4/banking_followup/plan.tsv` and its metadata freeze the follow-up, any later defense claim is Banking- and selected-payload-specific, and fewer than five fresh successes terminates live experimentation before a defended run.

### Phase 9-11 — Gemma defended output namespace

**Decision:** Keep Gemma undefended baseline and follow-up artifacts under `data/baseline_gemma4/`, while storing Gemma defended validation and full-run artifacts under the existing model-qualified `data/defended/g4/v1/` namespace rather than the generic `data/defended/` paths in the original Phase 9 text.

**Reason:** The shared runner already separates defended outputs by model and defense version, and the short `g4/v1` namespace preserves the tested Windows trace-path margin. This is a storage/provenance clarification only: defended Gemma rows remain separate from Gemini, calibrated-baseline, and original discovery datasets.

**Impact:** Phase 9 uses `data/defended/g4/v1/replication_dev/{builtin,custom}/` for development validation and `data/defended/g4/v1/fresh160/` for the frozen custom-defense evaluation; every defended row retains the Gemma model, plan, payload, and defense hashes, while the 20-row replication panel is excluded from defended aggregation.

### Phase 7/9 — Preserve native utility in future undefended indexes

**Decision:** Record AgentDojo's native `utility_success` boolean in every future undefended baseline index row while preserving all existing Gemini and Gemma baseline indexes and raw traces byte-for-byte as legacy artifacts.

**Reason:** The shared runner always received and raw-logged the native utility verdict, but its defense integration serialized that value only for defended rows. The later documentation described the resulting undefended nulls as "by design," even though they were a legacy serialization omission rather than an experimental or methodological requirement.

**Impact:** Future undefended runs carry utility without requiring a development/holdout split; schemas and aggregation accept both legacy null and future boolean values, and populated values are checked against raw traces. Frozen `data/baseline/`, `data/baseline_gemma4/results.jsonl`, `data/baseline_gemma4/full/results.jsonl`, and all existing raw traces remain unchanged.

### Phase 10 — Banking-only defense-adaptive scope

**Decision:** Fix the Phase 10–11 defense-adaptive evaluation to the Banking
`gemma4-banking-followup-v1` 160-fresh matched population and carry forward
only undefended-success cases stopped by frozen `my_spotlighting` v1.

**Reason:** The Gemma parity baseline produced five native AgentDojo successes,
all in Banking, so only Banking proceeded to a defended evaluation; Workspace
and Slack were never defended. Banking is therefore fixed by data availability,
not selected through a cross-domain comparison of defended ASR.

**Impact:** Adaptive artifacts live under `data/adaptive/g4/v1/`, remain
separate from the Phase 9 static defended comparison, and support only a
Banking- and selected-payload-specific finding rather than a cross-domain
defense claim.

### Phase 10 — Waiver of per-run Gemma dashboard reading

**Decision:** Omit the build_guide.md requirement to read the Gemma RPD
dashboard before each adaptive-loop API run; the code-level quota guard
(hard cap, ledger reservation, lock) remains in force.

**Reason:** The Gemma model (`gemma-4-26b-a4b-it`) has 30 RPM, 16k TPM, and
14,400 RPD — substantially more than the full five-payload adaptive loop
(≤25 target executions plus ≤25 proposer calls, well under 100 total API
requests). The operator explicitly determined that the hard quota guard's
code-level protections are sufficient without a manual dashboard reading
before each run.

**Impact:** `src/adaptive/adaptive_loop.py` still requires all four quota
arguments (`--quota-date`, `--dashboard-used`, `--dashboard-limit`,
`--max-api-requests`) and enters the `QuotaGuard` context, ensuring the
ledger is updated correctly. The waiver applies only to the manual
dashboard-verification step, not to the code-level enforcement.

### Phase 10 — Proposer output format: plain text → JSON with "template" field

**Decision:** Changed the proposer prompt to request a single JSON object
`{"template": "..."}` instead of bare plain text, and updated extraction
to parse the JSON field first (with fallback to markdown-fence stripping
and raw text) before validating the `{{goal}}` token.

**Reason:** The 10.7 live hand-test revealed that Gemma 4 produces reasoning
traces and meta-commentary (repeating the word `{{goal}}` from the task
description 4–8 times) rather than bare template text when prompted with a
plain-text fill-in-the-blank suffix. All 5 persona-04 proposer calls produced
malformed output and no attempt reached the AgentDojo target call.
Structuring the output as a named JSON field makes extraction unambiguous
regardless of model preamble or reasoning traces.

**Impact:** `_build_proposer_prompt` and `propose_mutation` in
`src/adaptive/adaptive_loop.py` changed; `TestProposerValidation` in
`tests/test_adaptive_loop.py` updated to test the new extraction path.
The fallback chain (JSON regex → full JSON parse → markdown fence → raw
text) ensures backward compatibility if the model ignores the JSON
instruction.

### Phase 10 — Proposer request counter: AgentDojo counter not incremented by raw generate_content

**Decision:** Fixed `proposer_requests` to be hardcoded `1` per completed
proposer call instead of using `get_google_request_attempt_count()` delta,
and set `proposer_requests = 1` in the `ValueError` (malformed-output) branch.

**Reason:** `get_google_request_attempt_count()` tracks AgentDojo benchmark
tool-pipeline calls, not raw `client.models.generate_content()` calls.
The delta was always 0, making `proposer_requests` report 0 even after a
real API call completed. The malformed-output branch also left the counter
at its initial value of 0.

**Impact:** `attempts.jsonl` records now correctly show `proposer_requests=1`
for any attempt where the proposer made a real API call, regardless of
whether the output passed validation.

### Phase 10 — Adaptive-loop reliability fixes: thinking, target accounting, and resume

**Decision:** Hardened the Gemma proposer/target loop by giving proposer thinking sufficient output headroom and explicitly setting minimal thinking, restoring the missing `get_google_request_attempt_count` binding used by target execution, and treating only `status=completed` rows with a boolean native verdict as terminal checkpoint entries.

**Reason:** Gemma 4 could exhaust its proposer output budget in `thought=True` content before emitting a template; the target path then crashed before request accounting because the counter name was not imported; and the checkpoint treated crash/error rows as completed, preventing retry. These fixes distinguish reasoning truncation and execution errors from genuine AgentDojo verdicts while preserving the full failure history.

**Impact:** Proposer calls now use `max_output_tokens=4096` with minimal thinking and classify thought-only responses as truncated; target calls record real request counts; error rows remain retryable; and the archived pre-fix records remain separate from the canonical completed-attempt results.

### Phase 11 — Gemma-only bypass verification reconciliation

**Decision:** On 2026-08-16, reconciled build-guide task 11.4a with the executed Gemma-only design by requiring confirmed bypasses to have completed row and raw-trace evidence that both proposer and target use `gemma-4-26b-a4b-it`, with no fallback/testing-model substitution; no separate cross-model confirmation run is required.

**Reason:** The stale task text referred to `get_google_primary_llm()` from the archived Gemini Phase 6A track, while `adaptive_loop.py` uses `get_google_gemma4_26b_llm()` for both roles to preserve consistency with the Phase 9 recorded baseline. Because the proposer and target already share the designated recorded model, a primary-versus-cross-model confirmation split is inapplicable.

**Impact:** Phase 11 case-study recording now validates the completed `data/adaptive/g4/v1/attempts.jsonl` row and referenced raw trace for Gemma model provenance before counting a bypass; no adaptive code or existing experiment artifact is changed.

### Phase 10/11 — Versioned v2 adaptive-search budget

**Decision:** Preserve the completed five-mutation v1 search unchanged and pre-register separate v2a/v2b arms with at most 20 mutations per payload across the first four eligible contexts in committed-manifest order.

**Reason:** The v1 budget was too small to distinguish strategy effects from one-context sensitivity; the new 20-query limit follows the approved PAIR/TAP-inspired bounded-search rationale and was fixed before either v2 arm made an API call.

**Impact:** Each v2 arm has a 100-attempt worst-case budget, rotates all five frozen strategies across four contexts, stops each payload on its first native AgentDojo success, and writes only to its own versioned output root.

### Phase 10/11 — v2b proposer-model ablation

**Decision:** Add a separately reported v2b ablation using `gemini-3.5-flash-lite` as proposer while retaining `gemma-4-26b-a4b-it` as the target; v2a retains Gemma for both roles as required by Phase 10.6.

**Reason:** The approved ablation tests whether proposer capability, rather than the unchanged target/defense pair, limits candidate quality; it is not a replacement for or continuation of v2a.

**Impact:** V2a and v2b have independent checkpoints, summaries, quotas, and results and must never be pooled into one adaptive-search success count.

### Phase 10/11 — Dual-key quota reservation for v2b

**Decision:** Extend `src/experiments/quota_guard.py` with a backward-compatible `MultiQuotaGuard` that reserves and reconciles the Gemini proposer and Gemma target keys under one ledger lock, using an independent proposer limiter and the existing Gemma limiter.

**Reason:** The existing process-wide limiter cannot safely cap two independently metered model quotas, while separate guards would violate the single-process lock and atomic-reservation requirement.

**Impact:** V2b requires fresh dashboard readings and explicit caps for both keys on every run; per-key ledger history is never cross-reconciled, and existing single-key runners remain unchanged.

### Phase 10/11 — Phase 6A proposer-artifact audit correction

**Decision:** Base the v2b proposer-format expectation on the committed per-stage Phase 6A files at `origin/phase-6a-attack-calibration`, because no aggregate `data/attack_calibration/attempts.jsonl` exists on that branch.

**Reason:** Read-only `git show` at commit `7c354f9a0cc74df9286287f87499709fcbfd076b` found 33/40 strict-parser malformed rows in `mutate/generator_attempts.jsonl` and only 1/40 malformed with zero refusals in `mutate_v2/generator_attempts.jsonl`. The sole v2 malformed note records an environment-renderability failure, not a refusal; five same-seed rows that were malformed under the strict parser were accepted in v2 with `fenced_json` normalization and notes stating that JSON and the goal token validated after canonical normalization.

**Impact:** The expected v2b proposer malformed/refusal rate remains approximately 2.5% or lower with the adaptive loop's equally tolerant extraction chain; this is an engineering expectation, not an executed v2b result.

### Phase 10/11 — Scoped template-02 malformed-proposer repair

**Decision:** Add `src/adaptive/repair_malformed.py`, a separate checkpoint and raw-trace namespace that regenerates and benchmarks only the sixteen v2a `template-02` rounds rejected for duplicate `{{goal}}` placeholders; the original v2a JSONL remains read-only. The repair path rejects obvious double-encoded JSON template wrappers before target execution.

**Reason:** The original rows contain no usable candidate or target verdict, so they cannot be benchmarked by resume alone. A narrowly scoped repair runner permits fresh proposals and accepts one or more goal placeholders only for this supplemental path; skipped proposer/renderability rows remain retryable, without changing normal adaptive-loop parsing or touching other payload results.

**Impact:** Repair artifacts are written under `data/adaptive/g4/v2a_repair/`, are reported separately from v2a, and require the same Gemma quota guard before any future live execution.

### Phase 11 — Logical template-02 merge for 11.4/11.5 reporting

**Decision:** For Phase 11.4/11.5 reporting, join each completed
`v2a_repair` row to its sixteen malformed `v2a` source rounds and treat the
result as one logical 20-round `v2a` `template-02` run; retain the separate raw
artifact roots only as provenance.

**Reason:** The original `v2a` rows for those rounds contain no target verdict,
while the repair execution completes the same predeclared rounds. Reporting
only the four original target evaluations would omit the complete payload view;
the user's accepted Phase 11 scope requires the repaired results to be merged,
while keeping `v2b` as a distinct proposer-model ablation.

**Impact:** `report/case_studies/` reports 20 logical `v2a` `template-02`
rounds—four original completed rows plus sixteen source-linked repair rows—with
zero native successes. The immutable JSONL/checkpoint/raw files remain under
their existing arm-specific paths, and no repair row is pooled with `v2b`.
