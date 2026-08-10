"""Shared persistence and validation helpers for AgentDojo attack calibration.

These helpers intentionally remain coupled to repository calibration records and
synthetic AgentDojo contexts.  They centralize contracts shared by attack-set
versions without generalizing the benchmark into an external-target interface.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from agentdojo.types import get_text_content_as_str

from src.experiments.build_attack_splits import AttackContext
from src.schemas import CalibrationAttempt


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def canonical_json_bytes(value: Any) -> bytes:
    """Return the repository's stable, human-readable JSON encoding."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def relative_or_absolute(path: Path) -> str:
    """Record workspace paths relatively and external paths absolutely."""

    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def resolve_recorded_path(value: str) -> Path:
    """Resolve a path previously encoded by :func:`relative_or_absolute`."""

    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def note_values(notes: str) -> dict[str, str]:
    """Parse the semicolon-delimited key/value notes used by calibration records."""

    output: dict[str, str] = {}
    for item in notes.split(";"):
        key, separator, value = item.strip().partition("=")
        if separator:
            output[key] = value
    return output


def calibration_attempt_record(record: CalibrationAttempt) -> dict[str, Any]:
    """Serialize a calibration attempt without changing the legacy v1 shape."""

    value = asdict(record)
    if record.attack_set_version is not None:
        value["attack_set_version"] = record.attack_set_version
    return value


def extract_exact_injection(
    raw_trace: Mapping[str, Any],
    context: AttackContext,
    *,
    error_type: type[Exception] = ValueError,
) -> str:
    """Validate and return the sole manifest-bound injection in a raw trace."""

    injections = raw_trace.get("injections")
    if not isinstance(injections, Mapping) or set(injections) != {
        context.injection_vector
    }:
        raise error_type(
            "calibration trace must contain exactly its manifest injection vector"
        )
    rendered = injections.get(context.injection_vector)
    if not isinstance(rendered, str) or not rendered:
        raise error_type("calibration trace contains an empty/non-string injection")
    return rendered


def feedback_payload(
    attempt: CalibrationAttempt | None,
    *,
    error_type: type[Exception] = ValueError,
) -> dict[str, Any] | None:
    """Load only the observable development feedback allowed to the proposer."""

    if attempt is None:
        return None
    raw_path = resolve_recorded_path(attempt.raw_trace_path)
    raw_trace = json.loads(raw_path.read_text(encoding="utf-8"))
    messages = raw_trace.get("messages")
    if not isinstance(messages, list):
        raise error_type(f"feedback trace lacks observable messages: {raw_path}")
    # Deliberately exclude utility, raw injections, hidden state, held-out data,
    # and all defense fields. The attacker sees only transcript + verdict.
    return {"messages": messages, "attack_success": attempt.attack_success}


def generator_request_messages(
    system: str, user_prompt: str
) -> list[dict[str, Any]]:
    """Build the exact message history consumed by the Gemini proposer."""

    return [
        {
            "role": "system",
            "content": [{"type": "text", "content": system}],
        },
        {
            "role": "user",
            "content": [{"type": "text", "content": user_prompt}],
        },
    ]


def validate_generator_message_history(
    messages: Sequence[Mapping[str, Any]],
    *,
    system: str,
    user_prompt: str,
    error_type: type[Exception] = ValueError,
) -> None:
    """Prove a persisted response was conditioned on the recorded request."""

    expected = generator_request_messages(system, user_prompt)
    if list(messages[: len(expected)]) != expected:
        raise error_type(
            "generator message history does not contain the recorded system "
            "and user prompts"
        )
    if not any(
        message.get("role") == "assistant" for message in messages[len(expected) :]
    ):
        raise error_type("generator message history lacks an assistant response")


def json_compatible(value: Any) -> Any:
    """Convert provider objects into the established JSON-compatible representation."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_compatible(item) for item in value]
    if hasattr(value, "model_dump"):
        return json_compatible(value.model_dump())
    if hasattr(value, "__dict__"):
        return json_compatible(vars(value))
    return repr(value)


def assistant_text(messages: Sequence[Mapping[str, Any]]) -> str:
    """Return text from the last assistant message in a provider history."""

    for message in reversed(messages):
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            return ""
        return get_text_content_as_str(content)
    return ""
