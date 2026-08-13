"""No-network validation for the frozen Gemma Banking fresh160 defense run."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Sequence

from src.defenses.my_spotlighting import BEGIN_MARKER
from src.schemas import RunResult


CASE_FIELDS = (
    "payload_id",
    "domain",
    "channel",
    "injection_vector",
    "user_task_id",
    "injection_task_id",
)
PLAN = Path("data/baseline_gemma4/banking_followup/plan_fresh160.tsv")
ROOT = Path("data/defended/g4/v1/fresh160")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PLAN_SHA256 = "0fcf3aadc5700ef5e1c40b5d5b5fc7242c7eaeb8a1225b525f1305e20cdf6f6b"
EXPECTED_DEFENSE_SHA256 = "7ce3de91c8dfd3c17532332d8f6516f3aa377bb2c40b22fe9371fc349a5200ee"
EXPECTED_MODEL = "google-gemma-4-26b-a4b-it"
BENCHMARK_VERSION = "v1.2.2"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_plan(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != CASE_FIELDS:
            raise ValueError(f"unexpected plan columns: {reader.fieldnames}")
        rows = [dict(row) for row in reader]
    if len(rows) != 160:
        raise ValueError(f"expected 160 plan rows, found {len(rows)}")
    return rows


def _key(row: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(row[field]) for field in CASE_FIELDS)


def _note(notes: str, name: str) -> str:
    match = re.search(rf"(?:^|;\s*){re.escape(name)}=([^;]+)", notes)
    if match is None:
        raise ValueError(f"result notes lack {name}")
    return match.group(1)


def _resolve_raw_path(reference: str, *, raw_root: Path) -> tuple[Path, Path]:
    """Return the displayed note path and a contained canonical path."""

    displayed = Path(reference)
    candidate = displayed if displayed.is_absolute() else PROJECT_ROOT / displayed
    canonical = candidate.resolve()
    try:
        canonical.relative_to(raw_root.resolve())
    except ValueError as exc:
        raise ValueError(f"raw trace is outside the result raw directory: {reference}") from exc
    return displayed, canonical


def validate(*, plan_path: Path = PLAN, results_path: Path = ROOT / "results.jsonl", output: Path | None = None) -> dict[str, Any]:
    plan_path = plan_path.resolve()
    results_path = results_path.resolve()
    plan_rows = _read_plan(plan_path)
    plan_sha = _sha256(plan_path)
    if plan_sha != EXPECTED_PLAN_SHA256:
        raise ValueError(f"fresh160 plan hash mismatch: {plan_sha}")
    expected_keys = [_key(row) for row in plan_rows]
    results: list[RunResult] = []
    for line_number, line in enumerate(results_path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            results.append(RunResult.from_calibrated_dict(json.loads(line), path=f"{results_path}:{line_number}"))
    actual_keys: list[tuple[str, ...]] = []
    traces: set[str] = set()
    checks: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        vector = _note(result.notes, "injection_vector")
        key = (result.payload_id, result.domain, result.channel, vector, result.user_task_id, result.injection_task_id)
        actual_keys.append(key)
        if result.model != EXPECTED_MODEL or result.defense != "my_spotlighting":
            raise ValueError(f"row {index} has wrong model/defense")
        if result.split != "holdout" or result.plan_sha256 != EXPECTED_PLAN_SHA256:
            raise ValueError(f"row {index} has wrong split/plan provenance")
        if result.defense_version != "v1" or result.defense_sha256 != EXPECTED_DEFENSE_SHA256:
            raise ValueError(f"row {index} has wrong defense provenance")
        if result.attack_set_version != "static-corpus-v1" or not result.attack_sha256:
            raise ValueError(f"row {index} has incomplete attack provenance")
        raw_reference, raw_path = _resolve_raw_path(
            _note(result.notes, "raw_trace"), raw_root=results_path.parent / "r"
        )
        canonical = str(raw_path).lower()
        if canonical in traces:
            raise ValueError(f"duplicate raw trace: {raw_path}")
        traces.add(canonical)
        if not raw_path.is_file():
            raise ValueError(f"missing raw trace: {raw_path}")
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        if raw.get("error") is not None:
            raise ValueError(f"errored raw trace: {raw_path}")
        if raw.get("security") != result.attack_success or raw.get("utility") != result.utility_success:
            raise ValueError(f"raw/index verdict mismatch: {raw_path}")
        if raw.get("messages") != result.tool_calls:
            raise ValueError(f"raw/index message mismatch: {raw_path}")
        if (
            raw.get("suite_name") != result.domain
            or raw.get("user_task_id") != result.user_task_id
            or raw.get("injection_task_id") != result.injection_task_id
            or raw.get("benchmark_version") != BENCHMARK_VERSION
        ):
            raise ValueError(f"raw/index case metadata mismatch: {raw_path}")
        pipeline_name = raw.get("pipeline_name")
        if not isinstance(pipeline_name, str) or not pipeline_name.startswith(result.model):
            raise ValueError(f"raw/index model metadata mismatch: {raw_path}")
        injections = raw.get("injections")
        if not isinstance(injections, Mapping) or vector not in injections:
            raise ValueError(f"raw trace lacks rendered injection {vector!r}: {raw_path}")
        rendered = injections[vector]
        if not isinstance(rendered, str):
            raise ValueError(f"raw rendered injection is not text: {raw_path}")
        if hashlib.sha256(rendered.encode("utf-8")).hexdigest() != result.attack_sha256:
            raise ValueError(f"raw/index attack hash mismatch: {raw_path}")
        tool_messages = [message for message in raw.get("messages", []) if message.get("role") == "tool"]
        checks.append({
            "row_index": index,
            "case_key": list(key),
            "index_attack_success": result.attack_success,
            "raw_security": raw.get("security"),
            "index_utility_success": result.utility_success,
            "raw_utility": raw.get("utility"),
            "raw_trace": str(raw_reference),
            "tool_message_count": len(tool_messages),
            "trace_bytes": raw_path.stat().st_size,
            "first_tool_wrapped": BEGIN_MARKER in json.dumps(tool_messages[0], ensure_ascii=False) if tool_messages else False,
        })
    if len(results) != 160 or actual_keys != expected_keys or len(set(actual_keys)) != 160:
        raise ValueError("fresh160 results are not exactly the ordered 160-row plan")
    report = {
        "schema_version": 1,
        "plan": str(plan_path),
        "plan_sha256": plan_sha,
        "results": str(results_path),
        "row_count": len(results),
        "unique_key_count": len(set(actual_keys)),
        "exact_ordered_key_equality": True,
        "missing_trace_count": 0,
        "errored_trace_count": 0,
        "duplicate_trace_count": 0,
        "native_attack_successes": sum(result.attack_success for result in results),
        "legitimate_utility_successes": sum(bool(result.utility_success) for result in results),
        "model": [EXPECTED_MODEL],
        "defense": ["my_spotlighting"],
        "defense_sha256": [EXPECTED_DEFENSE_SHA256],
        "spot_checks": [checks[index] for index in (0, 79, 159)],
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=PLAN)
    parser.add_argument("--results", type=Path, default=ROOT / "results.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "validation_report.json")
    args = parser.parse_args(argv)
    report = validate(plan_path=args.plan, results_path=args.results, output=args.output)
    print(f"OK: {report['row_count']} fresh160 rows, {report['native_attack_successes']} native successes, {report['legitimate_utility_successes']} utility successes, exact keys/raw traces")
    for check in report["spot_checks"]:
        print(json.dumps(check, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
