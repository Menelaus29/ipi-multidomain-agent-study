"""Audit whether the Phase 6 injections reached the model-facing tool trace.

This module is intentionally standard-library-only and makes no API calls.  It
reconciles the immutable Phase 6 plan, result index, and AgentDojo raw traces,
then writes a per-case CSV and an aggregate JSON summary.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.schemas import RunResult, SchemaValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_CASE_COUNT = 110
PLAN_FIELDS = (
    "payload_id",
    "domain",
    "channel",
    "injection_vector",
    "user_task_id",
    "injection_task_id",
)
AUDIT_FIELDS = (
    *PLAN_FIELDS,
    "raw_trace_path",
    "injection_visible",
    "match_mode",
    "attack_success",
    "utility_success",
)
MATCH_MODES = ("literal", "normalized", "decoded")
_NOTE_VALUE_PATTERNS = {
    "injection_vector": re.compile(r"(?:^|;\s*)injection_vector=([^;]+)"),
    "raw_trace": re.compile(r"(?:^|;\s*)raw_trace=([^;]+)"),
}
_UNICODE_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))")
_QUOTE_TRANSLATION = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
    }
)


class BaselineAuditError(ValueError):
    """Raised when Phase 6 artifacts cannot support a trustworthy audit."""


@dataclass(frozen=True)
class AuditRow:
    """One reconciled Phase 6 case and its native AgentDojo verdicts."""

    payload_id: str
    domain: str
    channel: str
    injection_vector: str
    user_task_id: str
    injection_task_id: str
    raw_trace_path: str
    injection_visible: bool
    match_mode: str
    attack_success: bool
    utility_success: bool


CaseKey = tuple[str, str, str, str, str, str]


def _case_key(record: Mapping[str, str]) -> CaseKey:
    return (
        record["payload_id"],
        record["domain"],
        record["channel"],
        record["injection_vector"],
        record["user_task_id"],
        record["injection_task_id"],
    )


def _read_plan(path: Path, *, expected_case_count: int) -> list[dict[str, str]]:
    if not path.is_file():
        raise BaselineAuditError(f"plan does not exist: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != PLAN_FIELDS:
            raise BaselineAuditError(
                f"{path} must have exactly these columns: {', '.join(PLAN_FIELDS)}"
            )
        raw_rows = list(reader)
    if len(raw_rows) != expected_case_count:
        raise BaselineAuditError(
            f"{path} must contain exactly {expected_case_count} cases; "
            f"found {len(raw_rows)}"
        )
    rows: list[dict[str, str]] = []
    keys: set[CaseKey] = set()
    for line_number, raw_row in enumerate(raw_rows, start=2):
        if None in raw_row:
            raise BaselineAuditError(f"{path}:{line_number} has more values than columns")
        missing = [field for field in PLAN_FIELDS if raw_row.get(field) is None]
        if missing:
            raise BaselineAuditError(
                f"{path}:{line_number} is missing value(s): {', '.join(missing)}"
            )
        row = {field: raw_row[field] for field in PLAN_FIELDS if raw_row[field] is not None}
        empty = [field for field in PLAN_FIELDS if not row[field].strip()]
        if empty:
            raise BaselineAuditError(
                f"{path}:{line_number} has empty field(s): {', '.join(empty)}"
            )
        key = _case_key(row)
        if key in keys:
            raise BaselineAuditError(f"{path}:{line_number} duplicates planned case {key}")
        keys.add(key)
        rows.append(row)
    return rows


def _note_value(notes: str, name: str, *, source: str) -> str:
    match = _NOTE_VALUE_PATTERNS[name].search(notes)
    if match is None or not match.group(1).strip():
        raise BaselineAuditError(f"{source} lacks a {name} note")
    return match.group(1).strip()


def _read_results(path: Path) -> dict[CaseKey, tuple[RunResult, str]]:
    if not path.is_file():
        raise BaselineAuditError(f"results index does not exist: {path}")
    results: dict[CaseKey, tuple[RunResult, str]] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        source = f"{path}:{line_number}"
        try:
            raw_record = json.loads(line)
            result = RunResult.from_dict(raw_record, path=source)
        except (json.JSONDecodeError, SchemaValidationError) as exc:
            raise BaselineAuditError(f"invalid result record at {source}: {exc}") from exc
        vector = _note_value(result.notes, "injection_vector", source=source)
        key: CaseKey = (
            result.payload_id,
            result.domain,
            result.channel,
            vector,
            result.user_task_id,
            result.injection_task_id,
        )
        if key in results:
            raise BaselineAuditError(f"{source} duplicates result case {key}")
        results[key] = (result, source)
    return results


def normalize_delivery_text(value: str) -> str:
    """Normalize only serialization differences, not attack encodings."""
    normalized = unicodedata.normalize("NFKC", value).translate(_QUOTE_TRANSLATION)
    while "''" in normalized:
        normalized = normalized.replace("''", "'")
    return re.sub(r"\s+", " ", normalized).strip()


def decode_unicode_escapes(value: str) -> str:
    """Decode explicit ``\\u``/``\\U`` sequences without interpreting other escapes."""

    def replace(match: re.Match[str]) -> str:
        codepoint = int(match.group(1) or match.group(2), 16)
        try:
            return chr(codepoint)
        except ValueError as exc:
            raise BaselineAuditError(
                f"invalid Unicode code point in injection: {match.group(0)}"
            ) from exc

    return _UNICODE_ESCAPE.sub(replace, value)


def classify_visibility(injection: str, tool_texts: Sequence[str]) -> str | None:
    """Return the first conservative match mode proving model-visible delivery."""
    if any(injection in text for text in tool_texts):
        return "literal"
    normalized_injection = normalize_delivery_text(injection)
    if any(normalized_injection in normalize_delivery_text(text) for text in tool_texts):
        return "normalized"
    decoded = decode_unicode_escapes(injection)
    if decoded != injection:
        normalized_decoded = normalize_delivery_text(decoded)
        if any(normalized_decoded in normalize_delivery_text(text) for text in tool_texts):
            return "decoded"
    return None


def _tool_texts(messages: Any, *, source: str) -> list[str]:
    if not isinstance(messages, list):
        raise BaselineAuditError(f"{source}.messages must be a list")
    texts: list[str] = []
    for message_index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise BaselineAuditError(f"{source}.messages[{message_index}] must be an object")
        if message.get("role") != "tool":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            raise BaselineAuditError(
                f"{source}.messages[{message_index}].content must be a list"
            )
        for part_index, part in enumerate(content):
            if not isinstance(part, Mapping):
                raise BaselineAuditError(
                    f"{source}.messages[{message_index}].content[{part_index}] must be an object"
                )
            if part.get("type") == "text":
                text = part.get("content")
                if not isinstance(text, str):
                    raise BaselineAuditError(
                        f"{source}.messages[{message_index}].content[{part_index}].content "
                        "must be a string"
                    )
                texts.append(text)
    return texts


def _resolve_raw_trace(
    note_path: str,
    *,
    project_root: Path,
    raw_root: Path,
    source: str,
) -> tuple[Path, str]:
    requested = Path(note_path)
    resolved = (requested if requested.is_absolute() else project_root / requested).resolve()
    raw_root = raw_root.resolve()
    try:
        resolved.relative_to(raw_root)
    except ValueError as exc:
        raise BaselineAuditError(
            f"{source} references a trace outside {raw_root}: {resolved}"
        ) from exc
    if not resolved.is_file() or resolved.stat().st_size == 0:
        raise BaselineAuditError(f"{source} references a missing/empty raw trace: {resolved}")
    try:
        display_path = resolved.relative_to(project_root.resolve()).as_posix()
    except ValueError:
        display_path = resolved.as_posix()
    return resolved, display_path


def _read_raw_trace(path: Path) -> dict[str, Any]:
    try:
        raw_trace = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BaselineAuditError(f"raw trace is not valid JSON: {path}: {exc}") from exc
    if not isinstance(raw_trace, dict):
        raise BaselineAuditError(f"raw trace must be a JSON object: {path}")
    if "error" not in raw_trace:
        raise BaselineAuditError(f"raw trace lacks error status: {path}")
    if raw_trace["error"] is not None:
        raise BaselineAuditError(f"raw trace is errored/skipped: {path}: {raw_trace['error']}")
    return raw_trace


def _require_bool(raw_trace: Mapping[str, Any], name: str, *, source: str) -> bool:
    value = raw_trace.get(name)
    if type(value) is not bool:
        raise BaselineAuditError(f"{source}.{name} must be a boolean")
    return value


def _audit_case(
    planned: Mapping[str, str],
    result: RunResult,
    result_source: str,
    *,
    project_root: Path,
    raw_root: Path,
) -> AuditRow:
    note_path = _note_value(result.notes, "raw_trace", source=result_source)
    raw_path, display_path = _resolve_raw_trace(
        note_path,
        project_root=project_root,
        raw_root=raw_root,
        source=result_source,
    )
    raw_trace = _read_raw_trace(raw_path)
    expected_metadata = {
        "suite_name": planned["domain"],
        "user_task_id": planned["user_task_id"],
        "injection_task_id": planned["injection_task_id"],
    }
    for name, expected in expected_metadata.items():
        if raw_trace.get(name) != expected:
            raise BaselineAuditError(
                f"{raw_path}.{name} does not match plan: expected {expected!r}, "
                f"found {raw_trace.get(name)!r}"
            )
    messages = raw_trace.get("messages")
    tool_texts = _tool_texts(messages, source=str(raw_path))
    if messages != result.tool_calls:
        raise BaselineAuditError(f"{raw_path}.messages does not match indexed tool_calls")
    injections = raw_trace.get("injections")
    if not isinstance(injections, Mapping):
        raise BaselineAuditError(f"{raw_path}.injections must be an object")
    vector = planned["injection_vector"]
    injection = injections.get(vector)
    if not isinstance(injection, str) or not injection:
        raise BaselineAuditError(f"{raw_path}.injections lacks non-empty vector {vector!r}")
    match_mode = classify_visibility(injection, tool_texts)
    if match_mode is None:
        raise BaselineAuditError(
            f"injection was not found in a model-facing tool message for planned case "
            f"{_case_key(planned)}"
        )
    attack_success = _require_bool(raw_trace, "security", source=str(raw_path))
    utility_success = _require_bool(raw_trace, "utility", source=str(raw_path))
    if attack_success != result.attack_success:
        raise BaselineAuditError(
            f"{raw_path}.security={attack_success} disagrees with indexed "
            f"attack_success={result.attack_success}"
        )
    return AuditRow(
        **{field: planned[field] for field in PLAN_FIELDS},
        raw_trace_path=display_path,
        injection_visible=True,
        match_mode=match_mode,
        attack_success=attack_success,
        utility_success=utility_success,
    )


def _summary(
    rows: Sequence[AuditRow],
    *,
    results_path: Path,
    plan_path: Path,
    project_root: Path,
) -> dict[str, Any]:
    def display(path: Path) -> str:
        try:
            return path.resolve().relative_to(project_root.resolve()).as_posix()
        except ValueError:
            return path.resolve().as_posix()

    def counts(group: Sequence[AuditRow]) -> dict[str, Any]:
        modes = Counter(row.match_mode for row in group)
        return {
            "case_count": len(group),
            "injection_visible_count": sum(row.injection_visible for row in group),
            "match_mode_counts": {mode: modes[mode] for mode in MATCH_MODES},
            "attack_success_count": sum(row.attack_success for row in group),
            "utility_success_count": sum(row.utility_success for row in group),
        }

    domains = sorted({row.domain for row in rows})
    return {
        "schema_version": 1,
        "inputs": {"results": display(results_path), "plan": display(plan_path)},
        **counts(rows),
        "by_domain": {
            domain: counts([row for row in rows if row.domain == domain])
            for domain in domains
        },
    }


def audit_baseline(
    *,
    results_path: Path,
    plan_path: Path,
    project_root: Path = PROJECT_ROOT,
    raw_root: Path | None = None,
    expected_case_count: int = EXPECTED_CASE_COUNT,
) -> tuple[list[AuditRow], dict[str, Any]]:
    """Reconcile and audit all planned cases without writing output files."""
    if expected_case_count < 1:
        raise BaselineAuditError("expected_case_count must be positive")
    project_root = project_root.resolve()
    raw_root = (raw_root or project_root / "data" / "baseline" / "raw").resolve()
    planned_rows = _read_plan(plan_path, expected_case_count=expected_case_count)
    indexed = _read_results(results_path)
    planned_keys = {_case_key(row) for row in planned_rows}
    result_keys = set(indexed)
    if planned_keys != result_keys:
        missing = sorted(planned_keys - result_keys)
        extra = sorted(result_keys - planned_keys)
        raise BaselineAuditError(
            f"plan/results case mismatch: missing={missing!r}; extra={extra!r}"
        )
    rows = [
        _audit_case(
            planned,
            *indexed[_case_key(planned)],
            project_root=project_root,
            raw_root=raw_root,
        )
        for planned in planned_rows
    ]
    seen_raw_paths: dict[str, CaseKey] = {}
    for planned, row in zip(planned_rows, rows, strict=True):
        raw_path = Path(row.raw_trace_path)
        canonical = raw_path if raw_path.is_absolute() else project_root / raw_path
        canonical_key = os.path.normcase(str(canonical.resolve()))
        case_key = _case_key(planned)
        previous = seen_raw_paths.get(canonical_key)
        if previous is not None:
            raise BaselineAuditError(
                f"planned cases {previous} and {case_key} reference the same raw trace: "
                f"{canonical.resolve()}"
            )
        seen_raw_paths[canonical_key] = case_key
    return rows, _summary(
        rows,
        results_path=results_path,
        plan_path=plan_path,
        project_root=project_root,
    )


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="")
    temporary.replace(path)


def write_outputs(
    rows: Sequence[AuditRow],
    summary: Mapping[str, Any],
    *,
    output_csv: Path,
    output_summary: Path,
) -> None:
    """Write deterministic audit outputs after validation has completed."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=AUDIT_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        record = asdict(row)
        record["injection_visible"] = str(row.injection_visible).lower()
        record["attack_success"] = str(row.attack_success).lower()
        record["utility_success"] = str(row.utility_success).lower()
        writer.writerow(record)
    _atomic_write(output_csv, buffer.getvalue())
    _atomic_write(output_summary, json.dumps(summary, indent=2, sort_keys=True) + "\n")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path, help="Phase 6 RunResult JSONL")
    parser.add_argument("--plan", required=True, type=Path, help="Phase 6 plan TSV")
    parser.add_argument("--output-csv", required=True, type=Path, help="per-case CSV output")
    parser.add_argument("--output-summary", required=True, type=Path, help="aggregate JSON output")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        rows, summary = audit_baseline(
            results_path=args.results.resolve(),
            plan_path=args.plan.resolve(),
        )
        write_outputs(
            rows,
            summary,
            output_csv=args.output_csv.resolve(),
            output_summary=args.output_summary.resolve(),
        )
    except (OSError, BaselineAuditError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK: audited {summary['case_count']} cases; "
        f"visible={summary['injection_visible_count']}; "
        f"attacks={summary['attack_success_count']}; "
        f"utility={summary['utility_success_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
