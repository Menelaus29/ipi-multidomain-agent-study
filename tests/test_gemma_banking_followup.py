"""No-API integrity tests for the frozen Gemma Banking follow-up protocol."""

from __future__ import annotations

import csv
import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from src.defenses.my_spotlighting import defense_source_sha256
from src.experiments import run_baseline


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FOLLOWUP_ROOT = PROJECT_ROOT / "data" / "baseline_gemma4" / "banking_followup"
PLAN_PATH = FOLLOWUP_ROOT / "plan.tsv"
METADATA_PATH = FOLLOWUP_ROOT / "plan_metadata.json"
DISCOVERY_PLAN_PATH = PROJECT_ROOT / "data" / "baseline" / "plan.tsv"
EXPECTED_PAYLOAD_IDS = {
    "persona-04",
    "encoding-03",
    "fake-system-04",
    "template-02",
    "template-03",
}
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


class GemmaBankingFollowupTests(unittest.TestCase):
    def test_frozen_plan_matches_metadata_and_current_deterministic_planner(self) -> None:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        rows = _read_plan(PLAN_PATH)
        payloads = [
            payload
            for payload in run_baseline.load_corpus()
            if payload.id in EXPECTED_PAYLOAD_IDS
        ]
        regenerated = list(
            run_baseline.iter_cases(payloads, domains={"banking"}, matrix="full")
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

        self.assertEqual(180, len(rows))
        self.assertEqual(len(rows), len({_key(row) for row in rows}))
        self.assertEqual([_key(row) for row in rows], regenerated_keys)
        self.assertEqual(metadata["case_count"], len(rows))
        self.assertEqual(
            metadata["plan_sha256"],
            hashlib.sha256(PLAN_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            metadata["plan_sha256"],
            run_baseline.case_plan_sha256(regenerated),
        )

    def test_fresh_and_replication_partitions_are_exact_and_disjoint(self) -> None:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        followup = {_key(row) for row in _read_plan(PLAN_PATH)}
        discovery = {_key(row) for row in _read_plan(DISCOVERY_PLAN_PATH)}
        replication = followup & discovery
        fresh = followup - discovery

        self.assertEqual(metadata["replication_case_count"], len(replication))
        self.assertEqual(metadata["fresh_case_count"], len(fresh))
        self.assertFalse(replication & fresh)
        self.assertEqual(followup, replication | fresh)
        self.assertEqual(
            metadata["reference_discovery_plan_sha256"],
            hashlib.sha256(DISCOVERY_PLAN_PATH.read_bytes()).hexdigest(),
        )

    def test_plan_has_the_predeclared_payload_surface_and_goal_coverage(self) -> None:
        rows = _read_plan(PLAN_PATH)

        self.assertEqual(EXPECTED_PAYLOAD_IDS, {row["payload_id"] for row in rows})
        self.assertEqual({"banking"}, {row["domain"] for row in rows})
        self.assertEqual({"file_content"}, {row["channel"] for row in rows})
        self.assertEqual(
            {
                "injection_address_change": 45,
                "injection_bill_text": 45,
                "injection_landloard_notice": 90,
            },
            Counter(row["injection_vector"] for row in rows),
        )
        self.assertEqual(
            {f"injection_task_{index}" for index in range(9)},
            {row["injection_task_id"] for row in rows},
        )

    def test_defense_hash_was_frozen_before_followup_execution(self) -> None:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))

        self.assertEqual("my_spotlighting", metadata["defense_name"])
        self.assertEqual("v1", metadata["defense_version"])
        self.assertEqual(metadata["defense_sha256"], defense_source_sha256())


if __name__ == "__main__":
    unittest.main()
