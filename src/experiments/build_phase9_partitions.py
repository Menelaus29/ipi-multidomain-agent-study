"""Build the amended Phase 9 replication-development and fresh plans.

This no-network tool derives both partitions by comparing the exact
``(payload_id, user_task_id, injection_task_id)`` triples in the frozen
Banking follow-up plan with the original Banking discovery plan. It never
uses the follow-up plan's pre-existing partition labels or attack outcomes.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Sequence

from src.experiments.run_baseline import PLAN_FIELDS


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DISCOVERY_PLAN = PROJECT_ROOT / "data" / "baseline" / "plan.tsv"
DEFAULT_FOLLOWUP_PLAN = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "banking_followup" / "plan.tsv"
)
DEFAULT_RECONCILIATION = (
    PROJECT_ROOT
    / "data"
    / "baseline_gemma4"
    / "full"
    / "reconciliation_report.json"
)
DEFAULT_REPLICATION_PLAN = (
    PROJECT_ROOT
    / "data"
    / "defended"
    / "g4"
    / "v1"
    / "replication_dev"
    / "manifest.tsv"
)
DEFAULT_FRESH_PLAN = (
    PROJECT_ROOT
    / "data"
    / "baseline_gemma4"
    / "banking_followup"
    / "plan_fresh160.tsv"
)
DEFAULT_METADATA = DEFAULT_REPLICATION_PLAN.with_name("manifest_metadata.json")
DEFAULT_UNDEFENDED_RESULTS = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "results.jsonl"
)
COMPARISON_FIELDS = ("payload_id", "user_task_id", "injection_task_id")


class PartitionDerivationError(ValueError):
    """Raised when committed inputs cannot reproduce the declared split."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_plan(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != PLAN_FIELDS:
            raise PartitionDerivationError(
                f"{path} has unexpected columns: {reader.fieldnames}"
            )
        rows = [dict(row) for row in reader]
    keys = [tuple(row[field] for field in PLAN_FIELDS) for row in rows]
    if len(keys) != len(set(keys)):
        raise PartitionDerivationError(f"{path} contains duplicate case keys")
    return rows


def derive_partitions(
    discovery_rows: Sequence[dict[str, str]],
    followup_rows: Sequence[dict[str, str]],
    reconciliation: dict[str, Any],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return ordered replication and fresh rows without using split labels."""

    discovery_banking = [row for row in discovery_rows if row["domain"] == "banking"]
    if len(discovery_banking) != 46:
        raise PartitionDerivationError(
            f"expected 46 original Banking rows, found {len(discovery_banking)}"
        )
    discovery_triples = {
        tuple(row[field] for field in COMPARISON_FIELDS)
        for row in discovery_banking
    }
    replication = [
        row
        for row in followup_rows
        if tuple(row[field] for field in COMPARISON_FIELDS) in discovery_triples
    ]
    fresh = [
        row
        for row in followup_rows
        if tuple(row[field] for field in COMPARISON_FIELDS) not in discovery_triples
    ]
    if (len(replication), len(fresh)) != (20, 160):
        raise PartitionDerivationError(
            "expected a 20/160 replication/fresh split, found "
            f"{len(replication)}/{len(fresh)}"
        )

    evidence = reconciliation.get("replication_evidence")
    if not isinstance(evidence, list):
        raise PartitionDerivationError("reconciliation report lacks replication evidence")
    evidence_triples = {
        tuple(str(row[field]) for field in COMPARISON_FIELDS)
        for row in evidence
    }
    derived_triples = {
        tuple(row[field] for field in COMPARISON_FIELDS) for row in replication
    }
    if evidence_triples != derived_triples:
        raise PartitionDerivationError(
            "derived replication triples disagree with reconciliation evidence"
        )
    counts = reconciliation.get("counts", {})
    if counts.get("replication_rows") != 20 or counts.get("fresh_rows") != 160:
        raise PartitionDerivationError("reconciliation report does not declare 20/160")
    return replication, fresh


def _write_plan(path: Path, rows: Sequence[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PLAN_FIELDS, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def verify_undefended_reuse(
    replication_rows: Sequence[dict[str, str]], results_path: Path
) -> dict[str, Any]:
    """Verify the exact replication triples in the existing live Gemma index."""

    expected = {
        tuple(row[field] for field in COMPARISON_FIELDS)
        for row in replication_rows
    }
    matched: dict[tuple[str, ...], dict[str, Any]] = {}
    for line_number, line in enumerate(
        results_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        record = json.loads(line)
        key = tuple(str(record[field]) for field in COMPARISON_FIELDS)
        if key not in expected:
            continue
        if key in matched:
            raise PartitionDerivationError(
                f"{results_path}:{line_number} duplicates replication key {key}"
            )
        matched[key] = record
    if set(matched) != expected:
        raise PartitionDerivationError(
            "existing undefended index does not exactly cover the replication panel"
        )
    raw_paths: list[Path] = []
    for key, record in matched.items():
        notes = record.get("notes")
        if not isinstance(notes, str):
            raise PartitionDerivationError(f"undefended row {key} lacks notes")
        match = re.search(r"(?:^|; )raw_trace=([^;]+)", notes)
        if match is None:
            raise PartitionDerivationError(f"undefended row {key} lacks raw_trace")
        raw_path = PROJECT_ROOT / match.group(1)
        if not raw_path.is_file():
            raise PartitionDerivationError(f"missing undefended raw trace: {raw_path}")
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        if raw.get("error") is not None:
            raise PartitionDerivationError(f"errored undefended raw trace: {raw_path}")
        raw_paths.append(raw_path)
    return {
        "results_path": results_path.relative_to(PROJECT_ROOT).as_posix(),
        "results_sha256": _sha256(results_path),
        "selection_used_attack_results": False,
        "filter_fields": list(COMPARISON_FIELDS),
        "matching_rows": len(matched),
        "native_attack_successes": sum(
            bool(record.get("attack_success")) for record in matched.values()
        ),
        "target_models": sorted({str(record.get("model")) for record in matched.values()}),
        "unique_raw_traces_present": len(set(raw_paths)),
        "errored_raw_traces": 0,
        "undefended_rerun_performed": False,
    }


def build_artifacts(
    *,
    discovery_plan: Path,
    followup_plan: Path,
    reconciliation_path: Path,
    replication_output: Path,
    fresh_output: Path,
    metadata_output: Path,
    undefended_results: Path,
) -> dict[str, Any]:
    discovery_rows = _read_plan(discovery_plan)
    followup_rows = _read_plan(followup_plan)
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    replication, fresh = derive_partitions(
        discovery_rows, followup_rows, reconciliation
    )
    _write_plan(replication_output, replication)
    _write_plan(fresh_output, fresh)
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "study_id": "gemma4-banking-followup-v1",
        "analysis_role": "Phase 9 replication-development partition derivation",
        "derivation_rule": (
            "Preserve frozen follow-up order; classify a row as replication iff "
            "its (payload_id, user_task_id, injection_task_id) triple occurs in "
            "the 46-row Banking subset of the original discovery plan."
        ),
        "comparison_fields": list(COMPARISON_FIELDS),
        "followup_partition_labels_used": False,
        "attack_results_used_for_selection": False,
        "source_paths": {
            "discovery_plan": discovery_plan.relative_to(PROJECT_ROOT).as_posix(),
            "followup_plan": followup_plan.relative_to(PROJECT_ROOT).as_posix(),
            "reconciliation_report": reconciliation_path.relative_to(PROJECT_ROOT).as_posix(),
        },
        "source_sha256": {
            "discovery_plan": _sha256(discovery_plan),
            "followup_plan": _sha256(followup_plan),
            "reconciliation_report": _sha256(reconciliation_path),
        },
        "original_banking_rows": 46,
        "replication_rows": len(replication),
        "fresh_rows": len(fresh),
        "replication_plan_path": replication_output.relative_to(PROJECT_ROOT).as_posix(),
        "replication_plan_sha256": _sha256(replication_output),
        "fresh_plan_path": fresh_output.relative_to(PROJECT_ROOT).as_posix(),
        "fresh_plan_sha256": _sha256(fresh_output),
        "replication_exclusion": (
            "Development-only after reuse in Phase 9.2-9.5; permanently excluded "
            "from Phase 9.6-9.8 defended evaluation and primary comparison."
        ),
        "undefended_reuse_validation": verify_undefended_reuse(
            replication, undefended_results
        ),
    }
    metadata_output.parent.mkdir(parents=True, exist_ok=True)
    metadata_output.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return metadata


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery-plan", type=Path, default=DEFAULT_DISCOVERY_PLAN)
    parser.add_argument("--followup-plan", type=Path, default=DEFAULT_FOLLOWUP_PLAN)
    parser.add_argument("--reconciliation", type=Path, default=DEFAULT_RECONCILIATION)
    parser.add_argument("--replication-output", type=Path, default=DEFAULT_REPLICATION_PLAN)
    parser.add_argument("--fresh-output", type=Path, default=DEFAULT_FRESH_PLAN)
    parser.add_argument("--metadata-output", type=Path, default=DEFAULT_METADATA)
    parser.add_argument(
        "--undefended-results", type=Path, default=DEFAULT_UNDEFENDED_RESULTS
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    metadata = build_artifacts(
        discovery_plan=args.discovery_plan.resolve(),
        followup_plan=args.followup_plan.resolve(),
        reconciliation_path=args.reconciliation.resolve(),
        replication_output=args.replication_output.resolve(),
        fresh_output=args.fresh_output.resolve(),
        metadata_output=args.metadata_output.resolve(),
        undefended_results=args.undefended_results.resolve(),
    )
    print(
        "Derived Phase 9 partitions: "
        f"replication={metadata['replication_rows']} "
        f"fresh={metadata['fresh_rows']} "
        f"replication_sha256={metadata['replication_plan_sha256']} "
        f"fresh_sha256={metadata['fresh_plan_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
