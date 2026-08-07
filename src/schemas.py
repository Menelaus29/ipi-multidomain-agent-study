"""Machine-checkable records used by the experiment pipeline.

The schemas intentionally use only the Python standard library so validation
works in the minimal project environment as well as in the AgentDojo venv.
"""

from __future__ import annotations

import re
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


def _optional_string(
    record: Mapping[str, Any], field: str, *, path: str
) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SchemaValidationError(f"{path}.{field} must be null or a non-empty string")
    return value


def _require_string_list(
    record: Mapping[str, Any], field: str, *, path: str
) -> list[str]:
    value = record.get(field)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise SchemaValidationError(
            f"{path}.{field} must be a non-empty list of non-empty strings"
        )
    return value


def _require_bool(record: Mapping[str, Any], field: str, *, path: str) -> bool:
    value = record.get(field)
    if not isinstance(value, bool):
        raise SchemaValidationError(f"{path}.{field} must be a boolean")
    return value


def _optional_bool(record: Mapping[str, Any], field: str, *, path: str) -> bool | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise SchemaValidationError(f"{path}.{field} must be null or a boolean")
    return value


def _require_integer(
    record: Mapping[str, Any],
    field: str,
    *,
    path: str,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaValidationError(f"{path}.{field} must be an integer")
    if value < minimum:
        raise SchemaValidationError(f"{path}.{field} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise SchemaValidationError(f"{path}.{field} must be at most {maximum}")
    return value


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_sha256(record: Mapping[str, Any], field: str, *, path: str) -> str:
    value = _require_string(record, field, path=path)
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise SchemaValidationError(
            f"{path}.{field} must be a 64-character lowercase SHA-256 digest"
        )
    return value


def _optional_sha256(
    record: Mapping[str, Any], field: str, *, path: str
) -> str | None:
    value = _optional_string(record, field, path=path)
    if value is not None and _SHA256_PATTERN.fullmatch(value) is None:
        raise SchemaValidationError(
            f"{path}.{field} must be null or a 64-character lowercase SHA-256 digest"
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
class CalibrationAttempt:
    """One development-only attack-calibration attempt."""

    attempt_id: str
    timestamp: str
    split: str
    source_family: str
    seed_id: str
    parent_attempt_id: str | None
    mutation_round: int
    attacker_model: str
    target_model: str
    domain: str
    user_task_id: str
    injection_task_id: str
    injection_vector: str
    rendered_attack_sha256: str
    attack_success: bool
    utility_success: bool
    generator_request_attempts: int
    target_request_attempts: int
    raw_trace_path: str
    notes: str

    @classmethod
    def from_dict(
        cls, record: Mapping[str, Any], *, path: str = "record"
    ) -> "CalibrationAttempt":
        if not isinstance(record, Mapping):
            raise SchemaValidationError(f"{path} must be a JSON object")
        expected = {
            "attempt_id",
            "timestamp",
            "split",
            "source_family",
            "seed_id",
            "parent_attempt_id",
            "mutation_round",
            "attacker_model",
            "target_model",
            "domain",
            "user_task_id",
            "injection_task_id",
            "injection_vector",
            "rendered_attack_sha256",
            "attack_success",
            "utility_success",
            "generator_request_attempts",
            "target_request_attempts",
            "raw_trace_path",
            "notes",
        }
        _check_fields(record, expected, path=path)
        timestamp = _require_string(record, "timestamp", path=path)
        _validate_timestamp(timestamp, path=f"{path}.timestamp")
        split = _require_string(record, "split", path=path)
        if split != "dev":
            raise SchemaValidationError(
                f"{path}.split must be 'dev'; held-out attempts are not calibration attempts"
            )
        notes = record.get("notes")
        if not isinstance(notes, str):
            raise SchemaValidationError(f"{path}.notes must be a string")
        return cls(
            attempt_id=_require_string(record, "attempt_id", path=path),
            timestamp=timestamp,
            split=split,
            source_family=_require_string(record, "source_family", path=path),
            seed_id=_require_string(record, "seed_id", path=path),
            parent_attempt_id=_optional_string(record, "parent_attempt_id", path=path),
            mutation_round=_require_integer(record, "mutation_round", path=path),
            attacker_model=_require_string(record, "attacker_model", path=path),
            target_model=_require_string(record, "target_model", path=path),
            domain=_require_string(record, "domain", path=path),
            user_task_id=_require_string(record, "user_task_id", path=path),
            injection_task_id=_require_string(record, "injection_task_id", path=path),
            injection_vector=_require_string(record, "injection_vector", path=path),
            rendered_attack_sha256=_require_sha256(
                record, "rendered_attack_sha256", path=path
            ),
            attack_success=_require_bool(record, "attack_success", path=path),
            utility_success=_require_bool(record, "utility_success", path=path),
            generator_request_attempts=_require_integer(
                record, "generator_request_attempts", path=path
            ),
            target_request_attempts=_require_integer(
                record, "target_request_attempts", path=path
            ),
            raw_trace_path=_require_string(record, "raw_trace_path", path=path),
            notes=notes,
        )


@dataclass(frozen=True)
class FrozenAttack:
    """One selected attack in a versioned, immutable attack set."""

    attack_set_version: str
    attack_id: str
    source_family: str
    source_category: str
    goal_bound_template: str | None
    generator_name: str | None
    generator_parameters: dict[str, Any] | None
    selected_development_attempt: str
    development_score: int
    utf8_byte_length: int
    sha256: str

    @classmethod
    def from_dict(
        cls, record: Mapping[str, Any], *, path: str = "record"
    ) -> "FrozenAttack":
        if not isinstance(record, Mapping):
            raise SchemaValidationError(f"{path} must be a JSON object")
        expected = {
            "attack_set_version",
            "attack_id",
            "source_family",
            "source_category",
            "goal_bound_template",
            "generator_name",
            "generator_parameters",
            "selected_development_attempt",
            "development_score",
            "utf8_byte_length",
            "sha256",
        }
        _check_fields(record, expected, path=path)
        goal_bound_template = _optional_string(
            record, "goal_bound_template", path=path
        )
        generator_name = _optional_string(record, "generator_name", path=path)
        raw_parameters = record.get("generator_parameters")
        if raw_parameters is not None and not isinstance(raw_parameters, Mapping):
            raise SchemaValidationError(
                f"{path}.generator_parameters must be null or a JSON object"
            )
        if goal_bound_template is not None:
            if generator_name is not None or raw_parameters is not None:
                raise SchemaValidationError(
                    f"{path} must define either goal_bound_template or "
                    "generator_name with generator_parameters, not both"
                )
        elif generator_name is None or raw_parameters is None:
            raise SchemaValidationError(
                f"{path} must define either goal_bound_template or "
                "generator_name with generator_parameters"
            )
        return cls(
            attack_set_version=_require_string(record, "attack_set_version", path=path),
            attack_id=_require_string(record, "attack_id", path=path),
            source_family=_require_string(record, "source_family", path=path),
            source_category=_require_string(record, "source_category", path=path),
            goal_bound_template=goal_bound_template,
            generator_name=generator_name,
            generator_parameters=(
                dict(raw_parameters) if isinstance(raw_parameters, Mapping) else None
            ),
            selected_development_attempt=_require_string(
                record, "selected_development_attempt", path=path
            ),
            development_score=_require_integer(
                record, "development_score", path=path, minimum=1, maximum=3
            ),
            utf8_byte_length=_require_integer(
                record, "utf8_byte_length", path=path, minimum=1
            ),
            sha256=_require_sha256(record, "sha256", path=path),
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
    utility_success: bool | None = None
    split: str | None = None
    attack_set_version: str | None = None
    attack_sha256: str | None = None
    plan_sha256: str | None = None
    defense_version: str | None = None
    defense_sha256: str | None = None

    @classmethod
    def from_dict(
        cls,
        record: Mapping[str, Any],
        *,
        path: str = "record",
        require_attack_provenance: bool = False,
    ) -> "RunResult":
        if not isinstance(record, Mapping):
            raise SchemaValidationError(f"{path} must be a JSON object")
        required = {
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
        optional = {
            "utility_success",
            "split",
            "attack_set_version",
            "attack_sha256",
            "plan_sha256",
            "defense_version",
            "defense_sha256",
        }
        _check_fields(record, required, optional=optional, path=path)
        timestamp = _require_string(record, "timestamp", path=path)
        _validate_timestamp(timestamp, path=f"{path}.timestamp")
        attack_success = _require_bool(record, "attack_success", path=path)
        tool_calls = record.get("tool_calls")
        if not isinstance(tool_calls, list):
            raise SchemaValidationError(f"{path}.tool_calls must be a JSON list")
        notes = record.get("notes")
        if not isinstance(notes, str):
            raise SchemaValidationError(f"{path}.notes must be a string")
        utility_success = _optional_bool(record, "utility_success", path=path)
        split = _optional_string(record, "split", path=path)
        if split is not None and split not in {"dev", "holdout"}:
            raise SchemaValidationError(
                f"{path}.split must be 'dev', 'holdout', or null"
            )
        attack_set_version = _optional_string(
            record, "attack_set_version", path=path
        )
        attack_sha256 = _optional_sha256(record, "attack_sha256", path=path)
        plan_sha256 = _optional_sha256(record, "plan_sha256", path=path)
        defense_version = _optional_string(record, "defense_version", path=path)
        defense_sha256 = _optional_sha256(record, "defense_sha256", path=path)
        defense = _require_string(record, "defense", path=path)

        if (split is None) != (utility_success is None):
            raise SchemaValidationError(
                f"{path}.split and {path}.utility_success must be populated together"
            )
        if plan_sha256 is not None and split is None:
            raise SchemaValidationError(
                f"{path}.plan_sha256 requires split and utility_success"
            )

        attack_provenance = (attack_set_version, attack_sha256)
        has_attack_provenance = any(value is not None for value in attack_provenance)
        is_new_defended_row = defense not in {"none", "none-positive-control"}
        if require_attack_provenance or has_attack_provenance or is_new_defended_row:
            missing_provenance = [
                field
                for field, value in (
                    ("utility_success", utility_success),
                    ("split", split),
                    ("attack_set_version", attack_set_version),
                    ("attack_sha256", attack_sha256),
                    ("plan_sha256", plan_sha256),
                )
                if value is None
            ]
            if missing_provenance:
                raise SchemaValidationError(
                    f"{path} has incomplete calibrated-run provenance; missing value(s): "
                    f"{', '.join(missing_provenance)}"
                )
        if (defense_version is None) != (defense_sha256 is None):
            raise SchemaValidationError(
                f"{path}.defense_version and {path}.defense_sha256 must be "
                "populated together"
            )
        if is_new_defended_row and defense_version is None:
            raise SchemaValidationError(
                f"{path} defended rows must populate defense_version and defense_sha256"
            )
        if defense == "none" and defense_version is not None:
            raise SchemaValidationError(
                f"{path} undefended rows must not populate defense provenance"
            )
        return cls(
            run_id=_require_string(record, "run_id", path=path),
            timestamp=timestamp,
            domain=_require_string(record, "domain", path=path),
            user_task_id=_require_string(record, "user_task_id", path=path),
            injection_task_id=_require_string(record, "injection_task_id", path=path),
            payload_id=_require_string(record, "payload_id", path=path),
            channel=_require_string(record, "channel", path=path),
            model=_require_string(record, "model", path=path),
            defense=defense,
            attack_success=attack_success,
            tool_calls=tool_calls,
            notes=notes,
            utility_success=utility_success,
            split=split,
            attack_set_version=attack_set_version,
            attack_sha256=attack_sha256,
            plan_sha256=plan_sha256,
            defense_version=defense_version,
            defense_sha256=defense_sha256,
        )

    @classmethod
    def from_calibrated_dict(
        cls, record: Mapping[str, Any], *, path: str = "record"
    ) -> "RunResult":
        """Validate a calibrated or matched defended result with full provenance."""

        return cls.from_dict(
            record, path=path, require_attack_provenance=True
        )

    @classmethod
    def from_clean_control_dict(
        cls, record: Mapping[str, Any], *, path: str = "record"
    ) -> "RunResult":
        """Validate a no-injection utility control before an attack set exists."""

        result = cls.from_dict(record, path=path)
        if result.split is None or result.utility_success is None:
            raise SchemaValidationError(
                f"{path} clean-control rows must populate split and utility_success"
            )
        if result.attack_set_version is not None or result.attack_sha256 is not None:
            raise SchemaValidationError(
                f"{path} clean-control rows must not populate attack provenance"
            )
        if result.defense != "none":
            raise SchemaValidationError(
                f"{path} clean-control rows must use defense='none'"
            )
        if result.defense_version is not None or result.defense_sha256 is not None:
            raise SchemaValidationError(
                f"{path} clean-control rows must not populate defense provenance"
            )
        if result.attack_success:
            raise SchemaValidationError(
                f"{path} clean-control rows must have attack_success=false"
            )
        return result


def _check_fields(
    record: Mapping[str, Any],
    required: set[str],
    *,
    optional: set[str] | None = None,
    path: str,
) -> None:
    allowed = required | (optional or set())
    missing = sorted(required - set(record))
    extra = sorted(set(record) - allowed)
    if missing:
        raise SchemaValidationError(f"{path} is missing field(s): {', '.join(missing)}")
    if extra:
        raise SchemaValidationError(f"{path} has unexpected field(s): {', '.join(extra)}")


def _validate_timestamp(value: str, *, path: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaValidationError(f"{path} must be an ISO-8601 timestamp") from exc
