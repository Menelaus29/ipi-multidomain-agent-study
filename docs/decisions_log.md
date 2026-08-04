# Decisions Log

### Phase 3.5 - Provider switch: Groq -> Google AI Studio

**Decision:** Replaced the planned Groq integration with a custom `Gemini3LLM`
factory using Google AI Studio's API-key path.

**Reason:** Groq's OpenAI-compatible endpoint had persistent schema compatibility
issues that were too complex to resolve within the project's time constraints.

**Impact:** All experiment scripts import from `src/llm_providers/google_llm_factory.py`
instead of the originally planned `scripts/groq_llm.py`; the CLI benchmark path
is permanently bypassed in favour of the Python API.