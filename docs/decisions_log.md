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

**Impact:** Phase 6 reports a 33-case stratified baseline matrix; `run_baseline.py` retains its full-matrix mode for a future rerun with sufficient primary-model capacity.
