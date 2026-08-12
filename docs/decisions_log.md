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

**Impact:** Phase 9 uses `data/defended/g4/v1/{builtin_dev,custom_dev,full}/`; every defended row must retain the Gemma model, follow-up plan, payload, and defense hashes, with the 20 repetition and 160 fresh partitions reported separately.

### Phase 7/9 — Preserve native utility in future undefended indexes

**Decision:** Record AgentDojo's native `utility_success` boolean in every future undefended baseline index row while preserving all existing Gemini and Gemma baseline indexes and raw traces byte-for-byte as legacy artifacts.

**Reason:** The shared runner always received and raw-logged the native utility verdict, but its defense integration serialized that value only for defended rows. The later documentation described the resulting undefended nulls as "by design," even though they were a legacy serialization omission rather than an experimental or methodological requirement.

**Impact:** Future undefended runs carry utility without requiring a development/holdout split; schemas and aggregation accept both legacy null and future boolean values, and populated values are checked against raw traces. Frozen `data/baseline/`, `data/baseline_gemma4/results.jsonl`, `data/baseline_gemma4/full/results.jsonl`, and all existing raw traces remain unchanged.
