"""Provenance helpers for AgentDojo's built-in spotlighting defense.

The implementation itself remains owned and executed by the pinned AgentDojo
dependency.  This module records exactly which installed implementation was
used so built-in validation checkpoints cannot be resumed under changed code.
"""

from __future__ import annotations

import hashlib
import inspect
from importlib.metadata import version

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline


DEFENSE_NAME = "spotlighting_with_delimiting"


def defense_version() -> str:
    """Return the installed AgentDojo version that owns the defense."""

    return f"agentdojo-{version('agentdojo')}"


def defense_source_sha256() -> str:
    """Hash the canonical source of the pipeline factory containing the defense."""

    source = inspect.getsource(AgentPipeline.from_config).replace("\r\n", "\n")
    return hashlib.sha256(source.encode("utf-8")).hexdigest()
