"""Machine-checkable records used by the experiment pipeline.

The schemas intentionally use only the Python standard library so validation
works in the minimal project environment as well as in the AgentDojo venv.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping


class SchemaValidationError(ValueError):
    """Raised when a record does not match one of the project schemas."""


def _require_string(record: Mapping[str, Any], field: str, *, path: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SchemaValidationError(f"{path}.{field} must be a non-empty string")
    return value


def _require_string_list(record: Mapping[str, Any], field: str, *, path: str) -> list[str]:
    value = record.get(field)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise SchemaValidationError(
            f"{path}.{field} must be a non-empty list of non-empty strings"
        )
    return value


@dataclass(frozen=True)
class PayloadEntry:
    """One tagged indirect-prompt-injection payload description."""

    id: str
    category: str
    channel: str
    domain: list[str]
    template: str
    source: str

    @classmethod
    def from_dict(cls, record: Mapping[str, Any], *, path: str = "record") -> "PayloadEntry":
        if not isinstance(record, Mapping):
            raise SchemaValidationError(f"{path} must be a JSON object")
        expected = {"id", "category", "channel", "domain", "template", "source"}
        _check_fields(record, expected, path=path)
        return cls(
            id=_require_string(record, "id", path=path),
            category=_require_string(record, "category", path=path),
            channel=_require_string(record, "channel", path=path),
            domain=_require_string_list(record, "domain", path=path),
            template=_require_string(record, "template", path=path),
            source=_require_string(record, "source", path=path),
        )


@dataclass(frozen=True)
class RunResult:
    """One raw experiment result, retaining the complete tool-call trace."""

    run_id: str
    timestamp: str
    domain: str
    user_task_id: str
    injection_task_id: str
    payload_id: str
    channel: str
    model: str
    defense: str
    attack_success: bool
    tool_calls: list[Any]
    notes: str

    @classmethod
    def from_dict(cls, record: Mapping[str, Any], *, path: str = "record") -> "RunResult":
        if not isinstance(record, Mapping):
            raise SchemaValidationError(f"{path} must be a JSON object")
        expected = {
            "run_id",
            "timestamp",
            "domain",
            "user_task_id",
            "injection_task_id",
            "payload_id",
            "channel",
            "model",
            "defense",
            "attack_success",
            "tool_calls",
            "notes",
        }
        _check_fields(record, expected, path=path)
        timestamp = _require_string(record, "timestamp", path=path)
        _validate_timestamp(timestamp, path=f"{path}.timestamp")
        attack_success = record.get("attack_success")
        if not isinstance(attack_success, bool):
            raise SchemaValidationError(f"{path}.attack_success must be a boolean")
        tool_calls = record.get("tool_calls")
        if not isinstance(tool_calls, list):
            raise SchemaValidationError(f"{path}.tool_calls must be a JSON list")
        notes = record.get("notes")
        if not isinstance(notes, str):
            raise SchemaValidationError(f"{path}.notes must be a string")
        return cls(
            run_id=_require_string(record, "run_id", path=path),
            timestamp=timestamp,
            domain=_require_string(record, "domain", path=path),
            user_task_id=_require_string(record, "user_task_id", path=path),
            injection_task_id=_require_string(record, "injection_task_id", path=path),
            payload_id=_require_string(record, "payload_id", path=path),
            channel=_require_string(record, "channel", path=path),
            model=_require_string(record, "model", path=path),
            defense=_require_string(record, "defense", path=path),
            attack_success=attack_success,
            tool_calls=tool_calls,
            notes=notes,
        )


def _check_fields(record: Mapping[str, Any], expected: set[str], *, path: str) -> None:
    missing = sorted(expected - set(record))
    extra = sorted(set(record) - expected)
    if missing:
        raise SchemaValidationError(f"{path} is missing field(s): {', '.join(missing)}")
    if extra:
        raise SchemaValidationError(f"{path} has unexpected field(s): {', '.join(extra)}")


def _validate_timestamp(value: str, *, path: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be an ISO-8601 timestamp") from exc
