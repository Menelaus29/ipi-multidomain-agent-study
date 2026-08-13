"""No-network validation for the amended Phase 9 20-row defended panel."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
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
DEFAULT_ROOT = Path("data/defended/g4/v1/replication_dev")


def _read_manifest(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        rows = [dict(row) for row in reader]
    if len(rows) != 20:
        raise ValueError(f"expected 20 manifest rows, found {len(rows)}")
    return rows


def _plan_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _raw_path(notes: str) -> Path:
    match = re.search(r"(?:^|; )raw_trace=([^;]+)", notes)
    if match is None:
        raise ValueError("result notes lack raw_trace")
    return Path(match.group(1))


def _case_key(row: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(row[field]) for field in CASE_FIELDS)


def validate_arm(
    *,
    arm: str,
    results_path: Path,
    expected_keys: list[tuple[str, ...]],
    plan_sha256: str,
) -> dict[str, Any]:
    rows: list[RunResult] = []
    for line_number, line in enumerate(
        results_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if line.strip():
            rows.append(
                RunResult.from_dict(
                    json.loads(line), path=f"{results_path}:{line_number}"
                )
            )
    actual_keys: list[tuple[str, ...]] = []
    checks: list[dict[str, Any]] = []
    missing_traces: list[str] = []
    errored_traces: list[str] = []
    for index, row in enumerate(rows):
        vector_match = re.search(r"(?:^|;) ?injection_vector=([^;]+)", row.notes)
        if vector_match is None:
            raise ValueError(f"{results_path}:{index + 1} lacks injection vector")
        key = (
            row.payload_id,
            row.domain,
            row.channel,
            vector_match.group(1),
            row.user_task_id,
            row.injection_task_id,
        )
        actual_keys.append(key)
        if row.model != "google-gemma-4-26b-a4b-it":
            raise ValueError(f"{arm} row has wrong model: {row.model}")
        if row.split != "dev" or row.plan_sha256 != plan_sha256:
            raise ValueError(f"{arm} row has wrong split/plan provenance")
        if row.defense != ("spotlighting_with_delimiting" if arm == "builtin" else "my_spotlighting"):
            raise ValueError(f"{arm} row has wrong defense: {row.defense}")
        raw_path = _raw_path(row.notes)
        if not raw_path.is_file():
            missing_traces.append(str(raw_path))
            continue
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        if raw.get("error") is not None:
            errored_traces.append(str(raw_path))
        if raw.get("security") != row.attack_success:
            raise ValueError(f"{arm} verdict mismatch at {raw_path}")
        if raw.get("utility") != row.utility_success:
            raise ValueError(f"{arm} utility mismatch at {raw_path}")
        tool_messages = [message for message in raw.get("messages", []) if message.get("role") == "tool"]
        checks.append(
            {
                "row_index": index,
                "case_key": list(key),
                "index_attack_success": row.attack_success,
                "raw_security": raw.get("security"),
                "index_utility_success": row.utility_success,
                "raw_utility": raw.get("utility"),
                "raw_trace": str(raw_path),
                "raw_error": raw.get("error"),
                "tool_message_count": len(tool_messages),
                "trace_bytes": raw_path.stat().st_size,
                "first_tool_wrapped": (
                    BEGIN_MARKER in str(tool_messages[0]) if tool_messages else False
                ),
            }
        )
    if actual_keys != expected_keys:
        raise ValueError(f"{arm} result keys do not exactly equal the committed manifest")
    if missing_traces or errored_traces:
        raise ValueError(f"{arm} missing/errored traces: {missing_traces} {errored_traces}")
    if len(checks) != 20:
        raise ValueError(f"{arm} has only {len(checks)} validated traces")
    spot_indices = (0, 6, 19)
    return {
        "arm": arm,
        "results_path": str(results_path),
        "row_count": len(rows),
        "unique_key_count": len(set(actual_keys)),
        "exact_ordered_key_equality": True,
        "missing_trace_count": 0,
        "errored_trace_count": 0,
        "native_attack_successes": sum(row.attack_success for row in rows),
        "legitimate_utility_successes": sum(bool(row.utility_success) for row in rows),
        "model": sorted({row.model for row in rows}),
        "defense": sorted({row.defense for row in rows}),
        "defense_sha256": sorted({row.defense_sha256 for row in rows}),
        "spot_checks": [checks[index] for index in spot_indices],
    }


def validate(
    *, root: Path = DEFAULT_ROOT, output: Path | None = None
) -> dict[str, Any]:
    manifest = root / "manifest.tsv"
    manifest_rows = _read_manifest(manifest)
    expected_keys = [_case_key(row) for row in manifest_rows]
    plan_sha256 = _plan_sha256(manifest)
    report = {
        "schema_version": 1,
        "manifest": str(manifest),
        "manifest_sha256": plan_sha256,
        "manifest_rows": len(manifest_rows),
        "arms": {
            arm: validate_arm(
                arm=arm,
                results_path=root / arm / "results.jsonl",
                expected_keys=expected_keys,
                plan_sha256=plan_sha256,
            )
            for arm in ("builtin", "custom")
        },
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = validate(root=args.root.resolve(), output=args.output.resolve() if args.output else None)
    for arm, details in report["arms"].items():
        print(
            f"{arm}: {details['row_count']} rows, "
            f"{details['native_attack_successes']} native successes, "
            f"{details['legitimate_utility_successes']} utility successes, "
            "20/20 exact keys, 0 missing/errored traces"
        )
        for check in details["spot_checks"]:
            print(json.dumps(check, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
