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
  GEMMA4_26B_MODEL = 'gemma-4-26b-a4b-it' - isolated Gemma study track

Note (Phase 4.2a): This file will be relocated to src/llm_providers/google_llm_factory.py
when the full src/ tree is built.
"""
import json
import logging
import math
import os
import threading
import time
from collections import deque
from collections.abc import Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Literal

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

# This hosted Gemma model is an explicit, model-separated target. It is never
# a fallback and must not enter the Gemini Phase 6/6A calibration artifacts.
GEMMA4_26B_MODEL = "gemma-4-26b-a4b-it"
# Compatibility name retained for the already-recorded isolated diagnostic.
GEMMA4_26B_DIAGNOSTIC_MODEL = GEMMA4_26B_MODEL

# A known AgentDojo MODEL_NAMES key embedded in pipeline.name so that
# get_model_name_from_pipeline() resolves correctly for ToolKnowledgeAttack
# and ImportantInstructionsAttack. Resolves to 'AI model developed by Google'.
_AGENTDOJO_GEMINI_ID = "gemini-2.5-flash-preview-04-17"
PRIMARY_PIPELINE_NAME = f"google-{PRIMARY_MODEL} [{_AGENTDOJO_GEMINI_ID}]"
GEMMA4_26B_PIPELINE_NAME = (
    f"google-{GEMMA4_26B_MODEL} [{_AGENTDOJO_GEMINI_ID}]"
)

PRIMARY_RPM_LIMIT = 15
PRIMARY_TPM_LIMIT = 250_000
PRIMARY_RPD_LIMIT = 500
GEMMA4_26B_RPM_LIMIT = 30
GEMMA4_26B_TPM_LIMIT = 16_000
GEMMA4_26B_RPD_LIMIT = 14_400
HTTP_REQUEST_TIMEOUT_MS = 120_000

# Pace to 14 RPM, one below the active 15-RPM ceiling. This applies to every
# tool-calling turn rather than merely spacing top-level benchmark cases.
REQUESTS_PER_MINUTE_SAFETY_TARGET = 14
MIN_REQUEST_INTERVAL_SECONDS = 4.5
RPM_RETRY_PAUSE_SECONDS = 65.0
MAX_RPM_RETRIES = 2
MAX_TRANSIENT_RETRIES = 2

# Gemma's 16k TPM ceiling was reached by multi-turn Workspace diagnostics.
# Pace against a deliberately lower rolling estimate without changing request
# content. The estimator is conservative (three UTF-8 bytes/token plus fixed
# overhead), and the 14k target leaves 12.5% below the dashboard ceiling.
GEMMA4_TOKEN_SAFETY_TARGET = 14_000
# Keep a small timing cushion around the provider's nominal 60-second window.
# The request-level RPM limiter runs after token admission and can otherwise
# shift the actual send a few seconds beyond the token reservation timestamp.
TOKEN_WINDOW_SECONDS = 65.0
APPROX_BYTES_PER_TOKEN = 3
APPROX_REQUEST_TOKEN_OVERHEAD = 256

_REQUEST_ATTEMPT_OBSERVER: ContextVar[Callable[[int], None] | None] = ContextVar(
    "google_request_attempt_observer", default=None
)
_GENERATE_CONTENT_EVENT_OBSERVER: ContextVar[
    Callable[[Literal["request", "response", "error"], Any], None] | None
] = ContextVar("google_generate_content_event_observer", default=None)


@contextmanager
def observe_google_request_attempts(observer: Callable[[int], None]):
    """Notify one operation journal after every provider request start.

    The callback runs after the process-wide request counter is incremented and
    before the HTTP request is issued.  Recording at this boundary makes retry
    accounting durable even if the process is interrupted before an enclosing
    AgentDojo benchmark call returns.
    """

    token = _REQUEST_ATTEMPT_OBSERVER.set(observer)
    try:
        yield
    finally:
        _REQUEST_ATTEMPT_OBSERVER.reset(token)


@contextmanager
def observe_google_generate_content_events(
    observer: Callable[[Literal["request", "response", "error"], Any], None],
):
    """Observe exact SDK request/response objects for a scoped diagnostic.

    Normal experiment paths do not install this observer.  It does not alter
    message construction, tool schemas, retry policy, or provider selection;
    it only makes the already-constructed Google SDK payload observable when a
    caller explicitly requests a trace.
    """

    token = _GENERATE_CONTENT_EVENT_OBSERVER.set(observer)
    try:
        yield
    finally:
        _GENERATE_CONTENT_EVENT_OBSERVER.reset(token)


class RequestBudgetExceeded(RuntimeError):
    """Raised before an API call would exceed a configured process budget."""


class RequestRateLimiter:
    """Serialize request starts and expose process-local attempt accounting."""

    def __init__(
        self,
        min_interval_seconds: float,
        *,
        max_requests: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if min_interval_seconds < 0:
            raise ValueError("min_interval_seconds cannot be negative")
        if max_requests is not None and max_requests < 0:
            raise ValueError("max_requests cannot be negative")
        self.min_interval_seconds = min_interval_seconds
        self._max_requests = max_requests
        self._clock = clock
        self._sleeper = sleeper
        self._next_request_at = 0.0
        self._requests_started = 0
        self._lock = threading.Lock()

    def wait_before_request(self) -> None:
        """Wait until the next permitted start time and count the attempt."""
        with self._lock:
            if (
                self._max_requests is not None
                and self._requests_started >= self._max_requests
            ):
                raise RequestBudgetExceeded(
                    "Configured Gemini request-attempt budget exhausted "
                    f"({self._requests_started}/{self._max_requests})"
                )
            delay = self._next_request_at - self._clock()
            if delay > 0:
                self._sleeper(delay)
            started_at = self._clock()
            self._next_request_at = started_at + self.min_interval_seconds
            self._requests_started += 1
            requests_started = self._requests_started
        observer = _REQUEST_ATTEMPT_OBSERVER.get()
        if observer is not None:
            observer(requests_started)

    def defer(self, seconds: float) -> None:
        """Prevent any request from starting until at least ``seconds`` later."""
        with self._lock:
            self._next_request_at = max(self._next_request_at, self._clock() + seconds)

    def set_max_requests(self, max_requests: int | None) -> None:
        """Set an absolute process-local request ceiling without resetting usage."""
        if max_requests is not None and max_requests < 0:
            raise ValueError("max_requests cannot be negative")
        with self._lock:
            if max_requests is not None and max_requests < self._requests_started:
                raise ValueError(
                    "max_requests cannot be less than requests already started"
                )
            self._max_requests = max_requests

    @property
    def requests_started(self) -> int:
        with self._lock:
            return self._requests_started


def _token_estimate_json_default(value: Any) -> Any:
    """Return a stable JSON-compatible approximation of Google SDK objects."""

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return model_dump(mode="json", exclude_none=True)
        except TypeError:
            return model_dump(exclude_none=True)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return str(value)


def approximate_request_tokens(
    google_messages: genai_types.ContentListUnion,
    generation_config: genai_types.GenerateContentConfig,
) -> int:
    """Conservatively estimate tokens sent without making a count-tokens call.

    The estimate includes the exact message history and tool/config payload that
    will be sent. It does not mutate or truncate either object.
    """

    serialized = json.dumps(
        {"contents": google_messages, "config": generation_config},
        default=_token_estimate_json_default,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    return max(
        1,
        math.ceil(len(serialized) / APPROX_BYTES_PER_TOKEN)
        + APPROX_REQUEST_TOKEN_OVERHEAD,
    )


class TokenWindowPacer:
    """Bound approximate input tokens in a process-local rolling window."""

    def __init__(
        self,
        max_tokens: int,
        *,
        window_seconds: float = TOKEN_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_tokens < 1:
            raise ValueError("max_tokens must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_tokens = max_tokens
        self.window_seconds = window_seconds
        self._clock = clock
        self._sleeper = sleeper
        self._events: deque[tuple[float, int]] = deque()
        self._lock = threading.Lock()

    def _discard_expired(self, now: float) -> None:
        while self._events and now - self._events[0][0] >= self.window_seconds:
            self._events.popleft()

    def wait_before_tokens(self, estimated_tokens: int) -> float:
        """Wait until a turn fits, then reserve its approximate token charge.

        A single estimated request larger than the safety target is admitted
        only into an empty window and charged at the full target. That avoids an
        infinite wait while preserving the unmodified benchmark request; the
        provider remains the authority on its actual token count.
        """

        if estimated_tokens < 1:
            raise ValueError("estimated_tokens must be positive")
        charge = min(estimated_tokens, self.max_tokens)
        waited = 0.0
        with self._lock:
            while True:
                now = self._clock()
                self._discard_expired(now)
                used = sum(tokens for _, tokens in self._events)
                fits = used + charge <= self.max_tokens
                oversized_and_empty = estimated_tokens > self.max_tokens and not self._events
                if fits or oversized_and_empty:
                    self._events.append((now, charge))
                    return waited
                delay = max(0.0, self._events[0][0] + self.window_seconds - now)
                if delay == 0:
                    continue
                self._sleeper(delay)
                waited += delay


_REQUEST_RATE_LIMITER = RequestRateLimiter(MIN_REQUEST_INTERVAL_SECONDS)
_GEMMA4_TOKEN_PACER = TokenWindowPacer(GEMMA4_TOKEN_SAFETY_TARGET)


def get_google_request_attempt_count() -> int:
    """Return Gemini request attempts started by this Python process."""
    return _REQUEST_RATE_LIMITER.requests_started


def configure_google_request_attempt_limit(max_requests: int | None) -> None:
    """Prevent this process from starting more than ``max_requests`` API calls."""
    _REQUEST_RATE_LIMITER.set_max_requests(max_requests)


def classify_quota_error(
    error: ClientError,
) -> Literal["rpm", "tpm", "rpd", "unknown"] | None:
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
    if (
        "tokensperminute" in compact
        or ("tokens" in compact and "perminute" in compact)
        or "tpm" in compact
    ):
        return "tpm"
    if "requestsperminute" in compact or "rpm" in compact:
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
        token_pacer: TokenWindowPacer | None = None,
    ) -> None:
        super().__init__(model, client)
        self._rate_limiter = rate_limiter or _REQUEST_RATE_LIMITER
        self._token_pacer = token_pacer

    def _generate_content(
        self,
        google_messages: genai_types.ContentListUnion,
        generation_config: genai_types.GenerateContentConfig,
    ) -> genai_types.GenerateContentResponse:
        """Call Gemini with request-level pacing and bounded transient retries."""
        minute_quota_retries = 0
        transient_retries = 0
        estimated_tokens = (
            approximate_request_tokens(google_messages, generation_config)
            if self._token_pacer is not None
            else None
        )
        if (
            estimated_tokens is not None
            and estimated_tokens > self._token_pacer.max_tokens
        ):
            logging.warning(
                "Estimated request size %d exceeds the Gemma rolling safety target %d; "
                "sending the unchanged request only after an empty token window.",
                estimated_tokens,
                self._token_pacer.max_tokens,
            )
        while True:
            if self._token_pacer is not None and estimated_tokens is not None:
                token_delay = self._token_pacer.wait_before_tokens(estimated_tokens)
                if token_delay > 0:
                    logging.info(
                        "Gemma token pacing waited %.1fs before an estimated %d-token turn.",
                        token_delay,
                        estimated_tokens,
                    )
            self._rate_limiter.wait_before_request()
            event_observer = _GENERATE_CONTENT_EVENT_OBSERVER.get()
            if event_observer is not None:
                event_observer(
                    "request",
                    {
                        "model": self.model,
                        "contents": google_messages,
                        "config": generation_config,
                    },
                )
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=google_messages,
                    config=generation_config,
                )
                if event_observer is not None:
                    event_observer("response", response)
                return response
            except ClientError as error:
                if event_observer is not None:
                    event_observer("error", error)
                quota_kind = classify_quota_error(error)
                if (
                    quota_kind not in {"rpm", "tpm"}
                    or minute_quota_retries >= MAX_RPM_RETRIES
                ):
                    # Daily and ambiguous quota errors must reach the baseline
                    # runner, which stops without writing an invalid result.
                    raise
                minute_quota_retries += 1
                logging.warning(
                    "Google %s quota reached; waiting %.0fs before retry %d/%d.",
                    quota_kind.upper(),
                    RPM_RETRY_PAUSE_SECONDS,
                    minute_quota_retries,
                    MAX_RPM_RETRIES,
                )
                self._rate_limiter.defer(RPM_RETRY_PAUSE_SECONDS)
            except (ServerError, httpx.TimeoutException, httpx.ConnectError) as error:
                if event_observer is not None:
                    event_observer("error", error)
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
    client = genai.Client(
        api_key=os.getenv("GOOGLE_API_KEY", "").strip(),
        http_options=genai_types.HttpOptions(
            timeout=HTTP_REQUEST_TIMEOUT_MS,
            # Keep every HTTP attempt visible to this module's limiter/retry
            # accounting instead of permitting hidden SDK-level retries.
            retry_options=genai_types.HttpRetryOptions(attempts=1),
        ),
    )
    llm = Gemini3LLM(
        model_name,
        client,
        token_pacer=(
            _GEMMA4_TOKEN_PACER if model_name == GEMMA4_26B_MODEL else None
        ),
    )
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


def get_google_gemma4_26b_llm() -> Gemini3LLM:
    """Return the explicit model-separated Gemma 4 target.

    This changes only the model identifier passed to the existing
    ``Gemini3LLM``/Google AI Studio client path. It is intentionally separate
    from both primary and fallback factories and enables Gemma-only TPM pacing.
    """

    return get_google_llm(GEMMA4_26B_MODEL)


def get_google_gemma4_26b_diagnostic_llm() -> Gemini3LLM:
    """Compatibility factory for the isolated Gemma delivery diagnostic."""

    return get_google_gemma4_26b_llm()


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
    client = genai.Client(
        api_key=os.getenv("GOOGLE_API_KEY", "").strip(),
        http_options=genai_types.HttpOptions(
            timeout=HTTP_REQUEST_TIMEOUT_MS,
            retry_options=genai_types.HttpRetryOptions(attempts=1),
        ),
    )
    llm = FallbackGemini3LLM(PRIMARY_MODEL, client)
    llm.name = f"google-{PRIMARY_MODEL} [{_AGENTDOJO_GEMINI_ID}]"
    return llm
