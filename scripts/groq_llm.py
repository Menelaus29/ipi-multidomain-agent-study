"""
Groq provider factory for AgentDojo.

AgentDojo's built-in get_llm()/ModelsEnum only recognize a fixed list of
models and don't include Groq. Rather than patching those internals, this
builds an OpenAILLM pipeline element directly — AgentPipeline.from_config()
accepts a pre-built BasePipelineElement in place of a model-name string and
skips get_llm()/ModelsEnum entirely when you do that.

See docs/agentdojo_capabilities.md §6 for the full explanation and §2.3 of
sop.md for the provider rationale.

Note (Phase 4.2a): This file will be relocated to src/llm_providers/groq_llm.py
when the full src/ tree is built. Update imports in any script that references
scripts/groq_llm.py at that point.
"""
import os

import openai
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

# Primary model — used for every RECORDED result (Phases 6, 9, 11, 12).
# 1K RPD / 100K TPD on Groq free tier.
PRIMARY_MODEL = "llama-3.3-70b-versatile"

# Fallback model — high volume, lower capability.
# 14.4K RPD / 500K TPD on Groq free tier.
# ONLY for Phase 10-11's adaptive-attack mutation search. Never use for
# recorded numbers — mixing models would break comparability between
# undefended/defended/adaptive figures.
FALLBACK_MODEL = "llama-3.1-8b-instant"


def get_groq_llm(model_name: str = PRIMARY_MODEL) -> OpenAILLM:
    """
    Construct an OpenAILLM pipeline element pointed at Groq's
    OpenAI-compatible endpoint.

    The returned object is passed directly to benchmark_suite(model=...)
    or PipelineConfig(llm=...) — never converted to a model-name string,
    which would trigger ModelsEnum validation and fail.

    Args:
        model_name: Groq model identifier. Defaults to PRIMARY_MODEL.

    Returns:
        OpenAILLM instance with .name set to "groq-<model_name>".
        BasePipelineElement.name defaults to None; from_config()/logging
        need a real string here.
    """
    client = openai.OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )
    llm = OpenAILLM(client, model_name)
    llm.name = f"groq-{model_name}"  # BasePipelineElement.name defaults to
                                      # None; from_config()/logging need a
                                      # real string here.
    return llm


def get_groq_primary_llm() -> OpenAILLM:
    """Return an LLM instance using the primary model (llama-3.3-70b-versatile).

    Use this for all recorded experiment runs.
    """
    return get_groq_llm(PRIMARY_MODEL)


def get_groq_fallback_llm() -> OpenAILLM:
    """Return an LLM instance using the fallback model (llama-3.1-8b-instant).

    Use ONLY for high-volume mutation search in the adaptive-attack loop
    (Phase 10-11). Results produced with this model must never enter the
    recorded ASR tables without a re-run confirmation on the primary model
    (Phase 11.4a).
    """
    return get_groq_llm(FALLBACK_MODEL)
