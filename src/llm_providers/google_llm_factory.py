"""
Google AI Studio provider factory for AgentDojo.

AgentDojo's built-in get_llm() constructs a GoogleLLM with:
    genai.Client(vertexai=True, project=GCP_PROJECT, location=GCP_LOCATION)
which requires a billed GCP project and gcloud auth. This factory uses the
free Google AI Studio path instead:
    genai.Client(api_key=GOOGLE_API_KEY)

GEMINI 3.x THINKING COMPATIBILITY (discovered 2026-08-03):
    Gemini 3.x models (3.1-flash-lite, 3.5-flash-lite, etc.) enable "thinking"
    by default. When thinking is active, the model embeds a thought_signature
    field in every function call part. AgentDojo's GoogleLLM was written
    before Gemini 3.x and does not forward thought_signature in subsequent
    turns, causing the API to return:
        400 INVALID_ARGUMENT: Function call is missing a thought_signature
    Fix: subclass GoogleLLM, cache the raw response Parts, and replay them
    verbatim on subsequent turns so thought_signature is preserved.

GoogleLLM.__init__ accepts any genai.Client directly, so the subclass can use
the AI Studio API-key client and pass the object through the Python API
(benchmark_suite(model=llm)), bypassing get_llm()/ModelsEnum.

WHY THIS IS SIMPLER THAN THE GROQ WRAPPER:
  - GoogleLLM already handles $defs/$ref inlining (resolve_refs()),
    additionalProperties removal, and null-arg safety (args or {}).
  - It uses native google-genai SDK types, not OpenAI JSON schema, so
    anyOf/nullable and title-key issues do not exist.
  - Only the Gemini turn-preservation and request-reliability behavior needs
    a query() override; schema normalization remains AgentDojo's responsibility.

PIPELINE NAME / ATTACK COMPATIBILITY:
  ToolKnowledgeAttack and ImportantInstructionsAttack call
  get_model_name_from_pipeline() at construction, which requires pipeline.name
  to contain a substring from MODEL_NAMES. gemini-3.5-flash-lite and
  gemini-3.1-flash-lite are not in MODEL_NAMES (they postdate the installed
  AgentDojo version). Fix: embed a known Gemini key in the name.
  'gemini-2.5-flash-preview-04-17' -> 'AI model developed by Google'.

MODEL IDs (verified against official Google documentation, 2026-08-05):
  PRIMARY_MODEL  = 'gemini-3.5-flash-lite' - GA, generateContent supported
  FALLBACK_MODEL = 'gemini-3.1-flash-lite' - GA, generateContent supported

Note (Phase 4.2a): This file will be relocated to src/llm_providers/google_llm_factory.py
when the full src/ tree is built.
"""
import logging
import os
import threading
import time
from collections.abc import Sequence
from typing import Callable, Literal

import httpx
from dotenv import load_dotenv
from google import genai
from google.genai import types as genai_types
from google.genai.errors import ClientError, ServerError
from agentdojo.agent_pipeline.llms.google_llm import (
    GoogleLLM,
    _function_to_google,
    _google_to_assistant_message,
    _merge_tool_result_messages,
    _message_to_google,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage

load_dotenv()

# Primary model — used for all recorded runs and adaptive mutation search.
# Active free-tier constraints: 15 RPM, 250k TPM, and 500 RPD.
PRIMARY_MODEL = "gemini-3.5-flash-lite"

# Fallback model — testing/sanity recovery only. Never mix it into research
# results; a consistent primary keeps all three experiment states comparable.
FALLBACK_MODEL = "gemini-3.1-flash-lite"

# A known AgentDojo MODEL_NAMES key embedded in pipeline.name so that
# get_model_name_from_pipeline() resolves correctly for ToolKnowledgeAttack
# and ImportantInstructionsAttack. Resolves to 'AI model developed by Google'.
_AGENTDOJO_GEMINI_ID = "gemini-2.5-flash-preview-04-17"

PRIMARY_RPM_LIMIT = 15
PRIMARY_TPM_LIMIT = 250_000
PRIMARY_RPD_LIMIT = 500

# Pace to 14 RPM, one below the active 15-RPM ceiling. This applies to every
# tool-calling turn rather than merely spacing top-level benchmark cases.
REQUESTS_PER_MINUTE_SAFETY_TARGET = 14
MIN_REQUEST_INTERVAL_SECONDS = 4.5
RPM_RETRY_PAUSE_SECONDS = 65.0
MAX_RPM_RETRIES = 2
MAX_TRANSIENT_RETRIES = 2


class RequestRateLimiter:
    """Serialize request starts and expose process-local attempt accounting."""

    def __init__(
        self,
        min_interval_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if min_interval_seconds < 0:
            raise ValueError("min_interval_seconds cannot be negative")
        self.min_interval_seconds = min_interval_seconds
        self._clock = clock
        self._sleeper = sleeper
        self._next_request_at = 0.0
        self._requests_started = 0
        self._lock = threading.Lock()

    def wait_before_request(self) -> None:
        """Wait until the next permitted start time and count the attempt."""
        with self._lock:
            delay = self._next_request_at - self._clock()
            if delay > 0:
                self._sleeper(delay)
            started_at = self._clock()
            self._next_request_at = started_at + self.min_interval_seconds
            self._requests_started += 1

    def defer(self, seconds: float) -> None:
        """Prevent any request from starting until at least ``seconds`` later."""
        with self._lock:
            self._next_request_at = max(self._next_request_at, self._clock() + seconds)

    @property
    def requests_started(self) -> int:
        with self._lock:
            return self._requests_started


_REQUEST_RATE_LIMITER = RequestRateLimiter(MIN_REQUEST_INTERVAL_SECONDS)


def get_google_request_attempt_count() -> int:
    """Return Gemini request attempts started by this Python process."""
    return _REQUEST_RATE_LIMITER.requests_started


def classify_quota_error(
    error: ClientError,
) -> Literal["rpm", "rpd", "unknown"] | None:
    """Classify a Google 429 from its structured details/message when possible."""
    if getattr(error, "code", None) != 429 and "429" not in str(error):
        return None
    details = (
        f"{getattr(error, 'details', '')} "
        f"{getattr(error, 'message', '')} {error}"
    ).lower()
    compact = details.replace("_", "").replace("-", "").replace(" ", "")
    if "requestsperday" in compact or "perday" in compact or "rpd" in compact:
        return "rpd"
    if "requestsperminute" in compact or "perminute" in compact or "rpm" in compact:
        return "rpm"
    return "unknown"


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

    def __init__(
        self,
        model: str,
        client: genai.Client,
        *,
        rate_limiter: RequestRateLimiter | None = None,
    ) -> None:
        super().__init__(model, client)
        self._rate_limiter = rate_limiter or _REQUEST_RATE_LIMITER

    def _generate_content(
        self,
        google_messages: genai_types.ContentListUnion,
        generation_config: genai_types.GenerateContentConfig,
    ) -> genai_types.GenerateContentResponse:
        """Call Gemini with request-level pacing and bounded transient retries."""
        rpm_retries = 0
        transient_retries = 0
        while True:
            self._rate_limiter.wait_before_request()
            try:
                return self.client.models.generate_content(
                    model=self.model,
                    contents=google_messages,
                    config=generation_config,
                )
            except ClientError as error:
                quota_kind = classify_quota_error(error)
                if quota_kind != "rpm" or rpm_retries >= MAX_RPM_RETRIES:
                    # Daily and ambiguous quota errors must reach the baseline
                    # runner, which stops without writing an invalid result.
                    raise
                rpm_retries += 1
                logging.warning(
                    "Gemini per-minute quota reached; waiting %.0fs before retry %d/%d.",
                    RPM_RETRY_PAUSE_SECONDS,
                    rpm_retries,
                    MAX_RPM_RETRIES,
                )
                self._rate_limiter.defer(RPM_RETRY_PAUSE_SECONDS)
            except (ServerError, httpx.TimeoutException, httpx.ConnectError) as error:
                if transient_retries >= MAX_TRANSIENT_RETRIES:
                    raise
                transient_retries += 1
                delay = MIN_REQUEST_INTERVAL_SECONDS * (2 ** (transient_retries - 1))
                logging.warning(
                    "Transient Gemini error %s; waiting %.0fs before retry %d/%d.",
                    type(error).__name__,
                    delay,
                    transient_retries,
                    MAX_TRANSIENT_RETRIES,
                )
                self._rate_limiter.defer(delay)

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
            max_output_tokens=self.max_tokens,
            tools=google_tools,
            system_instruction=system_instruction,
            # The primary defaults to minimal thinking. Medium is a better fit
            # for autonomous multi-step tool use and matches the former
            # Gemini 3.6 Flash default used by this study.
            thinking_config=(
                genai_types.ThinkingConfig(
                    thinking_level=genai_types.ThinkingLevel.MEDIUM
                )
                if self.model == PRIMARY_MODEL
                else None
            ),
        )
        completion = self._generate_content(google_messages, generation_config)
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
    """Return a Gemini3LLM using the primary model (gemini-3.5-flash-lite).
    Use this for all recorded experiment runs.
    """
    return get_google_llm(PRIMARY_MODEL)


def get_google_fallback_llm() -> Gemini3LLM:
    """Return a Gemini3LLM using the fallback model (gemini-3.1-flash-lite).
    Use only for non-recorded diagnostics when the primary is unavailable.
    """
    return get_google_llm(FALLBACK_MODEL)


class FallbackGemini3LLM(Gemini3LLM):
    """Gemini3LLM that automatically falls back to FALLBACK_MODEL on RPD exhaustion.

    ONLY for use in test/sanity-check scripts — never for recorded benchmark runs.
    When the primary model (gemini-3.5-flash-lite) hits its daily quota (RPD 429), this
    class switches self.model to FALLBACK_MODEL (gemini-3.1-flash-lite) for the
    remainder of the session and retries the call transparently.

    Distinction from RPM 429 (handled by Gemini3LLM._generate_content):
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
            # RPM 429s are retried by Gemini3LLM and should not reach here.
            # RPD 429s propagate immediately.
            if classify_quota_error(e) == "rpd" and self.model != FALLBACK_MODEL:
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

    Starts with gemini-3.5-flash-lite (primary). Automatically switches to
    gemini-3.1-flash-lite if the primary model's daily quota is exhausted.

    DO NOT use this for recorded benchmark runs — results from the fallback
    model must never enter the ASR tables. Use get_google_primary_llm() for
    all recorded runs (Phase 6, 9, 11, 12).
    """
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY", "").strip())
    llm = FallbackGemini3LLM(PRIMARY_MODEL, client)
    llm.name = f"google-{PRIMARY_MODEL} [{_AGENTDOJO_GEMINI_ID}]"
    return llm
