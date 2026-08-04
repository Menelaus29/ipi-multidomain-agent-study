"""
Google AI Studio provider factory for AgentDojo.

AgentDojo's built-in get_llm() constructs a GoogleLLM with:
    genai.Client(vertexai=True, project=GCP_PROJECT, location=GCP_LOCATION)
which requires a billed GCP project and gcloud auth. This factory uses the
free Google AI Studio path instead:
    genai.Client(api_key=GOOGLE_API_KEY)

GEMINI 3.x THINKING COMPATIBILITY (discovered 2026-08-03):
    Gemini 3.x models (3.5-flash-lite, 3.6-flash, etc.) enable "thinking"
    by default. When thinking is active, the model embeds a thought_signature
    field in every function call part. AgentDojo's GoogleLLM was written
    before Gemini 3.x and does not forward thought_signature in subsequent
    turns, causing the API to return:
        400 INVALID_ARGUMENT: Function call is missing a thought_signature
    Fix: subclass GoogleLLM and set thinking_config=ThinkingConfig(
    thinking_budget=0) in GenerateContentConfig. thinking_budget=0 is the
    documented disable flag (see google-genai ThinkingConfig). Disabling
    thinking is appropriate here — this is a tool-calling benchmark, not a
    reasoning benchmark, and thinking adds latency/tokens with no benefit.

Because GoogleLLM.__init__ accepts any genai.Client directly, no subclassing
is needed — we just swap the client constructor and pass the object through
the Python API (benchmark_suite(model=llm)), bypassing get_llm()/ModelsEnum.

WHY THIS IS SIMPLER THAN THE GROQ WRAPPER:
  - GoogleLLM already handles $defs/$ref inlining (resolve_refs()),
    additionalProperties removal, and null-arg safety (args or {}).
  - It uses native google-genai SDK types, not OpenAI JSON schema, so
    anyOf/nullable and title-key issues do not exist.
  - No subclass, no query() override, no schema normalisation needed.

PIPELINE NAME / ATTACK COMPATIBILITY:
  ToolKnowledgeAttack and ImportantInstructionsAttack call
  get_model_name_from_pipeline() at construction, which requires pipeline.name
  to contain a substring from MODEL_NAMES. gemini-3.6-flash and
  gemini-3.5-flash-lite are not in MODEL_NAMES (they postdate the installed
  AgentDojo version). Fix: embed a known Gemini key in the name.
  'gemini-2.5-flash-preview-04-17' -> 'AI model developed by Google'.

MODEL IDs (confirmed live against Google AI Studio API, 2026-08-03):
  PRIMARY_MODEL  = 'gemini-3.6-flash'    - GA, generateContent supported
  FALLBACK_MODEL = 'gemini-3.5-flash-lite' - GA, generateContent supported

Note (Phase 4.2a): This file will be relocated to src/llm_providers/google_llm_factory.py
when the full src/ tree is built.
"""
import os
from collections.abc import Sequence

from dotenv import load_dotenv
from google import genai
from google.genai import types as genai_types
from agentdojo.agent_pipeline.llms.google_llm import GoogleLLM, _function_to_google, _message_to_google, _merge_tool_result_messages, _google_to_assistant_message, chat_completion_request
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage

load_dotenv()

# Primary model — used for every RECORDED result (Phases 6, 9, 11, 12).
# Gemini 3.6 Flash: Google's current best Flash-class model.
# Free tier via Google AI Studio (GOOGLE_API_KEY). Daily quota resets midnight PT.
PRIMARY_MODEL = "gemini-3.6-flash"

# Fallback model — high volume, lower latency.
# Used ONLY for Phase 10-11 adaptive-attack mutation search.
# Never use for recorded numbers — mixing models breaks ASR comparability.
FALLBACK_MODEL = "gemini-3.5-flash-lite"

# A known AgentDojo MODEL_NAMES key embedded in pipeline.name so that
# get_model_name_from_pipeline() resolves correctly for ToolKnowledgeAttack
# and ImportantInstructionsAttack. Resolves to 'AI model developed by Google'.
_AGENTDOJO_GEMINI_ID = "gemini-2.5-flash-preview-04-17"


class Gemini3LLM(GoogleLLM):
    """GoogleLLM subclass for Gemini 3.x models with thought_signature forwarding.

    Gemini 3.x models embed a thought_signature in every function_call Part
    when thinking is active. AgentDojo's GoogleLLM converts tool calls to its
    own FunctionCall dataclass (name + args only), discarding the signature.
    When the message history is reconstructed for turn 2+, the signature is
    gone, causing: 400 INVALID_ARGUMENT - Function call is missing a
    thought_signature.

    Fix: cache the raw genai_types.Part list from the model response indexed
    by turn position in extra_args['_raw_model_parts'], then replay those Parts
    verbatim in subsequent turn inputs instead of reconstructing from the
    stripped FunctionCall objects.

    AgentDojo's internal ChatMessage format is fully preserved for
    scoring/logging — only the Google-API-facing message construction changes.
    """

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        first_message, *other_messages = messages
        if first_message["role"] == "system":
            system_instruction = first_message["content"][0]["content"]
        else:
            system_instruction = None
            other_messages = list(messages)

        # Build Google-format message history. For any prior assistant turn that
        # has cached raw Parts (including thought_signature), replay them verbatim
        # instead of reconstructing from stripped FunctionCall objects.
        raw_parts_cache: dict = extra_args.get("_raw_model_parts", {})
        google_messages = []
        for i, message in enumerate(other_messages):
            if message["role"] == "assistant" and i in raw_parts_cache:
                google_messages.append(
                    genai_types.Content(role="model", parts=raw_parts_cache[i])
                )
            else:
                google_messages.append(_message_to_google(message))
        google_messages = _merge_tool_result_messages(google_messages)

        google_functions = [_function_to_google(tool) for tool in runtime.functions.values()]
        google_tools: genai_types.ToolListUnion | None = (
            [genai_types.Tool(function_declarations=google_functions)] if google_functions else None
        )
        generation_config = genai_types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
            tools=google_tools,
            system_instruction=system_instruction,
        )
        completion = chat_completion_request(
            self.model,
            self.client,
            google_messages,  # type: ignore
            generation_config=generation_config,
        )
        output = _google_to_assistant_message(completion)

        # Cache raw Parts for this turn so the next call can replay them
        new_messages = list(messages) + [output]
        new_cache = dict(raw_parts_cache)
        raw_response_parts = (
            completion.candidates[0].content.parts
            if completion.candidates and completion.candidates[0].content
            else None
        )
        if raw_response_parts:
            # Key = index of this assistant message within other_messages next turn
            new_cache[len(other_messages)] = raw_response_parts
        new_extra_args = {**extra_args, "_raw_model_parts": new_cache}

        return query, runtime, env, new_messages, new_extra_args


def get_google_llm(model_name: str = PRIMARY_MODEL) -> Gemini3LLM:
    """
    Construct a GoogleLLM pipeline element using the free Google AI Studio path.

    The returned object is passed directly to benchmark_suite(model=...)
    or PipelineConfig(llm=...) — never converted to a model-name string,
    which would trigger ModelsEnum validation and fail.

    Args:
        model_name: Gemini model identifier. Defaults to PRIMARY_MODEL.
    Returns:
        GoogleLLM instance with .name set to include the canonical
        AgentDojo Gemini model ID so that attacks can resolve the
        human-readable model name via get_model_name_from_pipeline().
    """
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY", "").strip())
    llm = Gemini3LLM(model_name, client)
    # Name format: "google-<model_name> [gemini-2.5-flash-preview-04-17]"
    # get_model_name_from_pipeline() matches the bracketed key -> 'AI model developed by Google'
    llm.name = f"google-{model_name} [{_AGENTDOJO_GEMINI_ID}]"
    return llm


def get_google_primary_llm() -> Gemini3LLM:
    """Return a Gemini3LLM using the primary model (gemini-3.6-flash).
    Use this for all recorded experiment runs.
    """
    return get_google_llm(PRIMARY_MODEL)


def get_google_fallback_llm() -> Gemini3LLM:
    """Return a Gemini3LLM using the fallback model (gemini-3.5-flash-lite).
    Use ONLY for high-volume mutation search in the adaptive-attack loop
    (Phase 10-11). Results produced with this model must never enter the
    recorded ASR tables without a re-run on the primary model (Phase 11.4a).
    """
    return get_google_llm(FALLBACK_MODEL)


class FallbackGemini3LLM(Gemini3LLM):
    """Gemini3LLM that automatically falls back to FALLBACK_MODEL on RPD exhaustion.

    ONLY for use in test/sanity-check scripts — never for recorded benchmark runs.
    When the primary model (gemini-3.6-flash) hits its daily quota (RPD 429), this
    class switches self.model to FALLBACK_MODEL (gemini-3.5-flash-lite) for the
    remainder of the session and retries the call transparently.

    Distinction from RPM 429 (handled by tenacity retry in google_llm.py):
      - RPM 429: "GenerateRequestsPerMinutePerProjectPerModel-FreeTier" → wait+retry
      - RPD 429: "GenerateRequestsPerDayPerProjectPerModel-FreeTier"    → switch model

    The switch is permanent once triggered — no point re-testing the exhausted model
    on every subsequent call.
    """

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        from google.genai.errors import ClientError
        try:
            return super().query(query, runtime, env, messages, extra_args)
        except ClientError as e:
            # Distinguish RPD (daily) from RPM (per-minute) quota exhaustion.
            # RPM 429s are retried by tenacity and should not reach here.
            # RPD 429s exhaust tenacity retries and propagate up.
            err_str = str(e)
            if "429" in err_str and "PerDay" in err_str and self.model != FALLBACK_MODEL:
                import logging
                logging.warning(
                    f"[FallbackGemini3LLM] Daily quota exhausted for '{self.model}'. "
                    f"Switching to fallback model '{FALLBACK_MODEL}' for this session."
                )
                self.model = FALLBACK_MODEL
                self.name = f"google-{FALLBACK_MODEL} [{_AGENTDOJO_GEMINI_ID}] (fallback)"
                # Retry with fallback — extra_args cache is still valid
                return super().query(query, runtime, env, messages, extra_args)
            raise


def get_google_testing_llm() -> FallbackGemini3LLM:
    """Return a FallbackGemini3LLM for use in test/sanity-check scripts.

    Starts with gemini-3.6-flash (primary). Automatically switches to
    gemini-3.5-flash-lite if the primary model's daily quota is exhausted.

    DO NOT use this for recorded benchmark runs — results from the fallback
    model must never enter the ASR tables. Use get_google_primary_llm() for
    all recorded runs (Phase 6, 9, 11, 12).
    """
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY", "").strip())
    llm = FallbackGemini3LLM(PRIMARY_MODEL, client)
    llm.name = f"google-{PRIMARY_MODEL} [{_AGENTDOJO_GEMINI_ID}]"
    return llm
