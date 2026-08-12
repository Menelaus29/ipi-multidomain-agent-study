"""No-API integrity tests for the frozen Phase 9 development manifest."""

from __future__ import annotations

import csv
import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from src.experiments import run_baseline
from src.schemas import RunResult


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_ROOT = PROJECT_ROOT / "data" / "defended" / "g4" / "v1"
MANIFEST_PATH = MANIFEST_ROOT / "dev_manifest.tsv"
METADATA_PATH = MANIFEST_ROOT / "dev_manifest_metadata.json"
SOURCE_PLAN_PATH = PROJECT_ROOT / "data" / "baseline" / "plan.tsv"
UNDEFENDED_RESULTS_PATH = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "results.jsonl"
)
FOLLOWUP_PLAN_PATH = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "banking_followup" / "plan.tsv"
)
EXPECTED_PAYLOAD_IDS = (
    "persona-04",
    "encoding-03",
    "fake-system-04",
    "template-02",
    "template-03",
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


def _result_key(result: RunResult) -> tuple[str, ...]:
    vector = run_baseline._vector_from_notes(result.notes)
    if vector is None:
        raise AssertionError(f"missing injection vector in result {result.run_id}")
    return (
        result.payload_id,
        result.domain,
        result.channel,
        vector,
        result.user_task_id,
        result.injection_task_id,
    )


class Phase9DevelopmentManifestTests(unittest.TestCase):
    def test_manifest_matches_metadata_and_deterministic_gemma_planner(self) -> None:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        rows = _read_plan(MANIFEST_PATH)
        arguments = [
            "--target",
            "gemma4-26b",
            "--domain",
            "workspace",
            "--plan",
        ]
        for payload_id in EXPECTED_PAYLOAD_IDS:
            arguments.extend(("--payload-id", payload_id))
        args = run_baseline.parse_args(arguments)
        regenerated = run_baseline.select_cases(
            args, run_baseline.load_corpus(), run_baseline.GEMMA4_TARGET
        )
        regenerated_keys = [
            (
                payload.id,
                domain,
                payload.channel,
                vector,
                user_task_id,
                injection_task_id,
            )
            for payload, domain, vector, user_task_id, injection_task_id in regenerated
        ]

        self.assertEqual(20, len(rows))
        self.assertEqual(len(rows), len({_key(row) for row in rows}))
        self.assertEqual([_key(row) for row in rows], regenerated_keys)
        self.assertEqual(metadata["case_count"], len(rows))
        self.assertEqual(
            metadata["plan_sha256"],
            hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            metadata["plan_sha256"],
            run_baseline.case_plan_sha256(regenerated),
        )

    def test_manifest_is_disjoint_from_the_complete_banking_followup(self) -> None:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        development = {_key(row) for row in _read_plan(MANIFEST_PATH)}
        followup = {_key(row) for row in _read_plan(FOLLOWUP_PLAN_PATH)}

        self.assertFalse(development & followup)
        self.assertEqual(metadata["excluded_followup_case_count"], len(followup))
        self.assertEqual(
            metadata["excluded_followup_plan_sha256"],
            hashlib.sha256(FOLLOWUP_PLAN_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            metadata["source_plan_sha256"],
            hashlib.sha256(SOURCE_PLAN_PATH.read_bytes()).hexdigest(),
        )

    def test_manifest_has_expected_coverage_and_matching_undefended_rows(self) -> None:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        rows = _read_plan(MANIFEST_PATH)
        undefended: dict[tuple[str, ...], RunResult] = {}
        for line_number, line in enumerate(
            UNDEFENDED_RESULTS_PATH.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            result = RunResult.from_dict(
                json.loads(line), path=f"{UNDEFENDED_RESULTS_PATH}:{line_number}"
            )
            key = _result_key(result)
            self.assertNotIn(key, undefended)
            undefended[key] = result

        self.assertEqual(list(EXPECTED_PAYLOAD_IDS), metadata["payload_ids"])
        self.assertEqual(set(EXPECTED_PAYLOAD_IDS), {row["payload_id"] for row in rows})
        self.assertEqual({"workspace"}, {row["domain"] for row in rows})
        self.assertEqual({"file_content"}, {row["channel"] for row in rows})
        self.assertEqual({"user_task_26"}, {row["user_task_id"] for row in rows})
        self.assertEqual(
            {"drive_feedback_injection": 10, "drive_keywords_stuffing_injection": 10},
            Counter(row["injection_vector"] for row in rows),
        )
        self.assertEqual(
            {"injection_task_0": 10, "injection_task_1": 10},
            Counter(row["injection_task_id"] for row in rows),
        )
        matched = [undefended[_key(row)] for row in rows]
        self.assertEqual(20, len(matched))
        self.assertTrue(
            all(result.model == "google-gemma-4-26b-a4b-it" for result in matched)
        )
        self.assertTrue(all(result.defense == "none" for result in matched))


if __name__ == "__main__":
    unittest.main()
