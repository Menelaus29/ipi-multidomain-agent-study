"""
Groq provider factory for AgentDojo.

AgentDojo's built-in get_llm()/ModelsEnum only recognize a fixed list of
models and don't include Groq. Rather than patching those internals, this
builds an OpenAILLM pipeline element directly — AgentPipeline.from_config()
accepts a pre-built BasePipelineElement in place of a model-name string and
skips get_llm()/ModelsEnum entirely when you do that.

See docs/agentdojo_capabilities.md §6 for the full explanation and §2.3 of
sop.md for the provider rationale.

COMPATIBILITY FIX (discovered in Phase 3.6):
    AgentDojo uses pydantic's .model_json_schema() to generate OpenAI tool
    schemas, which emits a non-standard `"title"` key inside `parameters`
    (e.g., `"title": "Input schema for `get_balance`"`). Groq's Llama models
    fail to generate valid JSON tool calls when this field is present; instead,
    they produce XML-style output like:
        <function=get_balance/></function>
    which Groq's API then rejects with error code `tool_use_failed`.

    Fix: subclass OpenAILLM and override `.query()` to strip `title` from
    every tool's `parameters` dict before the API call is made.
    Tested: stripping `title` makes both llama-3.3-70b-versatile and
    llama-3.1-8b-instant produce correct JSON tool calls on the banking
    suite (11 tools). This fix is applied in GroqOpenAILLM.

Note (Phase 4.2a): This file will be relocated to src/llm_providers/groq_llm.py
when the full src/ tree is built. Update imports in any script that references
scripts/groq_llm.py at that point.
"""
import copy
import os
from typing import Sequence

import openai
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM,
    _function_to_openai,
    _openai_to_assistant_message,
    chat_completion_request,
)
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime
from agentdojo.types import ChatMessage

# Primary model — used for every RECORDED result (Phases 6, 9, 11, 12).
# 1K RPD / 100K TPD on Groq free tier.
PRIMARY_MODEL = "llama-3.3-70b-versatile"

# Fallback model — high volume, lower capability.
# 14.4K RPD / 500K TPD on Groq free tier.
# ONLY for Phase 10-11's adaptive-attack mutation search. Never use for
# recorded numbers — mixing models would break comparability between
# undefended/defended/adaptive figures.
FALLBACK_MODEL = "llama-3.1-8b-instant"

# Canonical AgentDojo model ID used to satisfy get_model_name_from_pipeline().
# ImportantInstructionsAttack and ToolKnowledgeAttack call that function at
# construction time and require pipeline.name to contain a substring from
# MODEL_NAMES. Groq's Llama-3.3-70b is Llama-family, so embedding
# 'meta-llama/Llama-3-70b-chat-hf' in the pipeline name gives the attack
# the expected 'AI assistant' token while remaining honest about the provider.
_AGENTDOJO_LLAMA_ID = "meta-llama/Llama-3-70b-chat-hf"


def _strip_title_recursive(obj: dict) -> dict:
    """Recursively remove all `title` keys from a JSON schema dict.

    AgentDojo's pydantic-generated schemas include `title` at both the top
    level (e.g. "Input schema for `delete_email`") and nested within each
    property's schema (e.g. "Email Id"). Groq's Llama models fail to produce
    valid JSON tool calls when any `title` key is present; stripping them
    restores correct tool-call generation.
    """
    result = {}
    for k, v in obj.items():
        if k == "title":
            continue
        if isinstance(v, dict):
            result[k] = _strip_title_recursive(v)
        else:
            result[k] = v
    return result


def _strip_title_from_tool(tool: dict) -> dict:
    """Strip all non-standard `title` keys from a tool's function schema.

    See _strip_title_recursive() for the full explanation.
    """
    t = copy.deepcopy(tool)
    if "function" in t and "parameters" in t["function"]:
        t["function"]["parameters"] = _strip_title_recursive(t["function"]["parameters"])
    return t


class GroqOpenAILLM(OpenAILLM):
    """OpenAILLM subclass that strips the non-standard `title` field from
    AgentDojo's pydantic-generated tool schemas before sending them to Groq.

    All other behaviour is identical to OpenAILLM; this class only overrides
    `.query()` to intercept the tool-schema list before the API call.
    """

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env=EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple:
        from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai

        openai_messages = [_message_to_openai(message, self.model) for message in messages]
        raw_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        # Strip the non-standard `title` field that Groq's Llama models cannot
        # handle (causes XML-style tool call generation → `tool_use_failed`).
        openai_tools = [_strip_title_from_tool(t) for t in raw_tools]

        completion = chat_completion_request(
            self.client,
            self.model,
            openai_messages,
            openai_tools,
            self.reasoning_effort,
            self.temperature,
        )
        output = _openai_to_assistant_message(completion.choices[0].message)
        messages = [*messages, output]
        return query, runtime, env, messages, extra_args


def get_groq_llm(model_name: str = PRIMARY_MODEL) -> GroqOpenAILLM:
    """
    Construct a GroqOpenAILLM pipeline element pointed at Groq's
    OpenAI-compatible endpoint.

    The returned object is passed directly to benchmark_suite(model=...)
    or PipelineConfig(llm=...) — never converted to a model-name string,
    which would trigger ModelsEnum validation and fail.

    Args:
        model_name: Groq model identifier. Defaults to PRIMARY_MODEL.

    Returns:
        GroqOpenAILLM instance with .name set to include the canonical
        AgentDojo Llama model ID so that attacks can resolve the
        human-readable model name via get_model_name_from_pipeline().
    """
    client = openai.OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )
    llm = GroqOpenAILLM(client, model_name)
    # Name format: "groq-<model_name> [meta-llama/Llama-3-70b-chat-hf]"
    # — from_config()/logging get a human-readable string, and
    # get_model_name_from_pipeline() can match the bracketed canonical ID.
    llm.name = f"groq-{model_name} [{_AGENTDOJO_LLAMA_ID}]"
    return llm


def get_groq_primary_llm() -> GroqOpenAILLM:
    """Return an LLM instance using the primary model (llama-3.3-70b-versatile).

    Use this for all recorded experiment runs.
    """
    return get_groq_llm(PRIMARY_MODEL)


def get_groq_fallback_llm() -> GroqOpenAILLM:
    """Return an LLM instance using the fallback model (llama-3.1-8b-instant).

    Use ONLY for high-volume mutation search in the adaptive-attack loop
    (Phase 10-11). Results produced with this model must never enter the
    recorded ASR tables without a re-run confirmation on the primary model
    (Phase 11.4a).
    """
    return get_groq_llm(FALLBACK_MODEL)
