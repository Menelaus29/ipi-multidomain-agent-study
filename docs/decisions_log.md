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
