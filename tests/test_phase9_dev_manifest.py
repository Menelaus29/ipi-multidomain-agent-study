"""No-API integrity tests for the amended Phase 9 replication panel."""

from __future__ import annotations

import csv
import hashlib
import json
import unittest
from pathlib import Path

from src.experiments import build_phase9_partitions


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_ROOT = PROJECT_ROOT / "data" / "defended" / "g4" / "v1" / "replication_dev"
MANIFEST_PATH = MANIFEST_ROOT / "manifest.tsv"
METADATA_PATH = MANIFEST_ROOT / "manifest_metadata.json"
DISCOVERY_PLAN_PATH = PROJECT_ROOT / "data" / "baseline" / "plan.tsv"
FOLLOWUP_PLAN_PATH = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "banking_followup" / "plan.tsv"
)
FRESH_PLAN_PATH = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "banking_followup" / "plan_fresh160.tsv"
)
RECONCILIATION_PATH = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "reconciliation_report.json"
)
CASE_FIELDS = (
    "payload_id",
    "domain",
    "channel",
    "injection_vector",
    "user_task_id",
    "injection_task_id",
)


def _read_plan(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != CASE_FIELDS:
            raise AssertionError(f"unexpected plan columns in {path}: {reader.fieldnames}")
        return list(reader)


def _key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[field] for field in CASE_FIELDS)


class Phase9DevelopmentManifestTests(unittest.TestCase):
    def test_manifest_matches_deterministic_triple_derivation(self) -> None:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        rows = _read_plan(MANIFEST_PATH)
        discovery = _read_plan(DISCOVERY_PLAN_PATH)
        followup = _read_plan(FOLLOWUP_PLAN_PATH)
        reconciliation = json.loads(RECONCILIATION_PATH.read_text(encoding="utf-8"))
        replication, fresh = build_phase9_partitions.derive_partitions(
            discovery, followup, reconciliation
        )

        self.assertEqual([_key(row) for row in rows], [_key(row) for row in replication])
        self.assertEqual(20, len(rows))
        self.assertEqual(160, len(fresh))
        self.assertEqual(len(rows), len({_key(row) for row in rows}))
        self.assertEqual(
            metadata["replication_plan_sha256"],
            hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            metadata["fresh_plan_sha256"],
            hashlib.sha256(FRESH_PLAN_PATH.read_bytes()).hexdigest(),
        )
        self.assertFalse(metadata["followup_partition_labels_used"])
        self.assertFalse(metadata["attack_results_used_for_selection"])

    def test_manifest_is_the_replication_subset_and_fresh_is_disjoint(self) -> None:
        manifest = {_key(row) for row in _read_plan(MANIFEST_PATH)}
        fresh = {_key(row) for row in _read_plan(FRESH_PLAN_PATH)}
        followup = {_key(row) for row in _read_plan(FOLLOWUP_PLAN_PATH)}
        self.assertEqual(20, len(manifest))
        self.assertEqual(160, len(fresh))
        self.assertFalse(manifest & fresh)
        self.assertEqual(followup, manifest | fresh)

    def test_manifest_has_expected_banking_file_surface_coverage(self) -> None:
        rows = _read_plan(MANIFEST_PATH)
        self.assertEqual({"banking"}, {row["domain"] for row in rows})
        self.assertEqual({"file_content"}, {row["channel"] for row in rows})
        self.assertEqual({"injection_address_change", "injection_bill_text"}, {row["injection_vector"] for row in rows})
        self.assertEqual({"user_task_0", "user_task_13"}, {row["user_task_id"] for row in rows})


if __name__ == "__main__":
    unittest.main()
