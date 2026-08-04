"""Validate payload JSON or experiment JSONL records.

Examples:
    python -m src.analysis.validate_schema src/payloads/corpus.json --kind payload
    python -m src.analysis.validate_schema data/baseline/results.jsonl --kind run

With ``--kind auto`` (the default), a top-level JSON list is treated as a
payload corpus and JSONL/single JSON objects are treated as run results.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from src.schemas import PayloadEntry, RunResult, SchemaValidationError


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
    records, encoding = _read_records(path)
    if kind == "auto":
        kind = "payload" if encoding == "json" and _looks_like_payload_file(path, records) else "run"
    if kind not in {"payload", "run"}:
        raise SchemaValidationError(f"kind must be one of: auto, payload, run (got {kind!r})")
    schema = PayloadEntry if kind == "payload" else RunResult
    for index, record in enumerate(records, start=1):
        schema.from_dict(record, path=f"{path}:{index}")
    print(f"OK: {path} ({len(records)} {kind} record(s))")
    return 0


def _looks_like_payload_file(path: Path, records: Iterable[Any]) -> bool:
    if path.name == "corpus.json":
        return True
    first = next(iter(records), None)
    return isinstance(first, dict) and "template" in first and "payload_id" not in first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="JSON or JSONL file to validate")
    parser.add_argument(
        "--kind",
        choices=("auto", "payload", "run"),
        default="auto",
        help="record schema; auto infers corpus.json as payload and otherwise uses run",
    )
    args = parser.parse_args(argv)
    try:
        return validate_file(args.path, args.kind)
    except (OSError, SchemaValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
