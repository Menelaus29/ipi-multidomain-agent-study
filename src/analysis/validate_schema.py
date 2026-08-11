"""Validate payload JSON or experiment JSONL records.

Examples:
    python -m src.analysis.validate_schema src/payloads/corpus.json --schema payload
    python -m src.analysis.validate_schema data/baseline/results.jsonl --schema run
    python -m src.analysis.validate_schema results.jsonl --schema calibrated-run
    python -m src.analysis.validate_schema controls.jsonl --schema clean-control-run
    python -m src.analysis.validate_schema attempts.jsonl --schema calibration-attempt
    python -m src.analysis.validate_schema generator_attempts.jsonl --schema v2-generator-attempt
    python -m src.analysis.validate_schema goal_controls.jsonl --schema goal-achievability-control
    python -m src.analysis.validate_schema frozen_attacks.v1.json --schema frozen-attack

With ``--schema auto`` (the default), the schema is inferred from distinctive
record fields. The legacy ``--kind`` spelling remains supported as an alias.
Use ``calibrated-run`` for attack-bearing Phase 6A/defended results and
``clean-control-run`` for pre-freeze no-injection utility controls.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.schemas import (
    CalibrationAttempt,
    FrozenAttack,
    GoalAchievabilityControl,
    PayloadEntry,
    RunResult,
    SchemaValidationError,
    V2GeneratorAttempt,
)


SCHEMAS = {
    "payload": PayloadEntry.from_dict,
    "run": RunResult.from_dict,
    "calibrated-run": RunResult.from_calibrated_dict,
    "clean-control-run": RunResult.from_clean_control_dict,
    "calibration-attempt": CalibrationAttempt.from_dict,
    "v2-generator-attempt": V2GeneratorAttempt.from_dict,
    "goal-achievability-control": GoalAchievabilityControl.from_dict,
    "frozen-attack": FrozenAttack.from_dict,
}


def _read_records(path: Path) -> tuple[list[Any], str]:
    if not path.is_file():
        raise SchemaValidationError(f"input file does not exist: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return [], "empty"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records: list[Any] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SchemaValidationError(
                    f"line {line_number} is not valid JSON: {exc.msg}"
                ) from exc
        return records, "jsonl"
    if isinstance(parsed, list):
        return parsed, "json"
    return [parsed], "json"


def validate_file(path: Path, kind: str = "auto") -> int:
    records, _ = _read_records(path)
    if kind == "auto":
        kind = _infer_schema(path, records)
    if kind not in SCHEMAS:
        choices = ", ".join(("auto", *SCHEMAS))
        raise SchemaValidationError(f"schema must be one of: {choices} (got {kind!r})")
    validator = SCHEMAS[kind]
    for index, record in enumerate(records, start=1):
        validator(record, path=f"{path}:{index}")
    print(f"OK: {path} ({len(records)} {kind} record(s))")
    return 0


def _infer_schema(path: Path, records: list[Any]) -> str:
    if path.name == "corpus.json":
        return "payload"
    first = records[0] if records else None
    if not isinstance(first, dict):
        return "run"
    if "generation_id" in first and "attack_set_version" in first:
        return "v2-generator-attempt"
    if "control_id" in first and "attack_set_version" in first:
        return "goal-achievability-control"
    if "attempt_id" in first:
        return "calibration-attempt"
    if (
        "attack_id" in first
        and "attack_set_version" in first
        and "run_id" not in first
    ):
        return "frozen-attack"
    if "id" in first and "template" in first and "payload_id" not in first:
        return "payload"
    return "run"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="JSON or JSONL file to validate")
    parser.add_argument(
        "--schema",
        "--kind",
        dest="schema",
        choices=("auto", *SCHEMAS),
        default="auto",
        help="record schema; auto infers it from distinctive record fields",
    )
    args = parser.parse_args(argv)
    try:
        return validate_file(args.path, args.schema)
    except (OSError, SchemaValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
