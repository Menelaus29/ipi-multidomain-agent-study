"""No-network integrity tests for the Phase 10 adaptive-v1 design."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import unittest
from collections import Counter
from pathlib import Path
from typing import Any

from src.defenses.my_spotlighting import (
    BEGIN_MARKER,
    DATA_PREFIX,
    END_MARKER,
    defense_source_sha256,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ADAPTIVE_ROOT = PROJECT_ROOT / "data" / "adaptive" / "g4" / "v1"
STRATEGY_PATH = ADAPTIVE_ROOT / "strategy_manifest.json"
DESIGN_FREEZE_PATH = ADAPTIVE_ROOT / "design_freeze.json"
ELIGIBLE_PATH = ADAPTIVE_ROOT / "eligible_stopped_cases.tsv"
FRESH_PLAN_PATH = (
    PROJECT_ROOT
    / "data"
    / "baseline_gemma4"
    / "banking_followup"
    / "plan_fresh160.tsv"
)
CORPUS_PATH = PROJECT_ROOT / "src" / "payloads" / "corpus.json"
CASE_FIELDS = (
    "payload_id",
    "domain",
    "channel",
    "injection_vector",
    "user_task_id",
    "injection_task_id",
)
EXPECTED_PAYLOAD_ORDER = (
    "persona-04",
    "encoding-03",
    "fake-system-04",
    "template-02",
    "template-03",
)
EXPECTED_STRATEGY_IDS = (
    "delimiter-line-collision",
    "nested-marker-imitation",
    "escape-newline-reconstruction",
    "cross-span-instruction-framing",
    "policy-task-laundering",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_lf_sha256(path: Path) -> str:
    """Hash text artifacts after normalizing checkout CRLF to LF."""

    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != CASE_FIELDS:
            raise AssertionError(f"unexpected case columns in {path}: {reader.fieldnames}")
        return list(reader)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _key(row: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(row[field]) for field in CASE_FIELDS)


def _result_key(row: dict[str, Any]) -> tuple[str, ...]:
    match = re.search(r"(?:^|;\s*)injection_vector=([^;]+)", str(row["notes"]))
    if match is None:
        raise AssertionError("result notes lack injection_vector")
    return (
        str(row["payload_id"]),
        str(row["domain"]),
        str(row["channel"]),
        match.group(1).strip(),
        str(row["user_task_id"]),
        str(row["injection_task_id"]),
    )


class AdaptiveDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(STRATEGY_PATH.read_text(encoding="utf-8"))

    def test_source_artifact_hashes_and_frozen_defense_match(self) -> None:
        source_artifacts = self.manifest["source_artifacts"]
        for prefix in (
            "followup_metadata",
            "fresh_plan",
            "undefended_results",
            "defended_results",
        ):
            path = PROJECT_ROOT / source_artifacts[f"{prefix}_path"]
            self.assertEqual(source_artifacts[f"{prefix}_sha256"], _sha256(path))

        corpus_path = PROJECT_ROOT / source_artifacts["payload_corpus_path"]
        self.assertEqual(
            source_artifacts["payload_corpus_sha256_canonical_lf"],
            _canonical_lf_sha256(corpus_path),
        )

        target = self.manifest["target_defense"]
        freeze_path = PROJECT_ROOT / target["freeze_path"]
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        self.assertEqual(target["freeze_sha256"], _sha256(freeze_path))
        self.assertEqual(target["source_sha256_canonical_lf"], defense_source_sha256())
        self.assertEqual(
            target["source_sha256_canonical_lf"],
            freeze["source_sha256_canonical_lf"],
        )
        self.assertEqual(target["begin_marker"], freeze["markers"]["begin"])
        self.assertEqual(target["end_marker"], freeze["markers"]["end"])
        self.assertEqual(target["data_prefix"], freeze["markers"]["data_prefix"])
        self.assertEqual(BEGIN_MARKER, target["begin_marker"])
        self.assertEqual(END_MARKER, target["end_marker"])
        self.assertEqual(DATA_PREFIX, target["data_prefix"])

    def test_eligible_cases_are_exactly_the_ordered_stopped_fresh_successes(self) -> None:
        source_artifacts = self.manifest["source_artifacts"]
        plan = _read_tsv(PROJECT_ROOT / source_artifacts["fresh_plan_path"])
        eligible = _read_tsv(ELIGIBLE_PATH)
        undefended = _read_jsonl(
            PROJECT_ROOT / source_artifacts["undefended_results_path"]
        )
        defended = _read_jsonl(
            PROJECT_ROOT / source_artifacts["defended_results_path"]
        )
        undefended_by_key = {_result_key(row): row for row in undefended}
        defended_by_key = {_result_key(row): row for row in defended}
        plan_keys = [_key(row) for row in plan]

        self.assertEqual(160, len(plan_keys))
        self.assertEqual(160, len(set(plan_keys)))
        self.assertEqual(len(undefended), len(undefended_by_key))
        self.assertEqual(len(defended), len(defended_by_key))
        self.assertTrue(set(plan_keys) <= set(undefended_by_key))
        self.assertEqual(set(plan_keys), set(defended_by_key))

        undefended_success_keys = [
            key for key in plan_keys if undefended_by_key[key]["attack_success"] is True
        ]
        expected_eligible_keys = [
            key
            for key in undefended_success_keys
            if defended_by_key[key]["attack_success"] is False
        ]
        surviving_keys = [
            key
            for key in undefended_success_keys
            if defended_by_key[key]["attack_success"] is True
        ]

        self.assertEqual(34, len(undefended_success_keys))
        self.assertEqual(30, len(expected_eligible_keys))
        self.assertEqual(4, len(surviving_keys))
        self.assertEqual({"encoding-03"}, {key[0] for key in surviving_keys})
        self.assertEqual(expected_eligible_keys, [_key(row) for row in eligible])
        self.assertEqual(len(eligible), len({_key(row) for row in eligible}))
        self.assertEqual({"banking"}, {row["domain"] for row in eligible})
        self.assertEqual({"file_content"}, {row["channel"] for row in eligible})

        eligibility = self.manifest["eligibility"]
        self.assertEqual(eligibility["fresh_case_count"], len(plan_keys))
        self.assertEqual(
            eligibility["undefended_native_success_count"],
            len(undefended_success_keys),
        )
        self.assertEqual(eligibility["stopped_case_count"], len(eligible))
        self.assertEqual(
            eligibility["defended_native_success_count_among_undefended_successes"],
            len(surviving_keys),
        )
        self.assertEqual(
            eligibility["eligible_case_manifest_sha256_canonical_lf"],
            _canonical_lf_sha256(ELIGIBLE_PATH),
        )
        self.assertEqual(
            "CRLF normalized to LF before SHA-256",
            eligibility["eligible_case_manifest_hash_normalization"],
        )

    def test_payload_counts_categories_and_order_are_preserved(self) -> None:
        source_artifacts = self.manifest["source_artifacts"]
        plan_keys = [_key(row) for row in _read_tsv(FRESH_PLAN_PATH)]
        undefended_by_key = {
            _result_key(row): row
            for row in _read_jsonl(
                PROJECT_ROOT / source_artifacts["undefended_results_path"]
            )
        }
        defended_by_key = {
            _result_key(row): row
            for row in _read_jsonl(
                PROJECT_ROOT / source_artifacts["defended_results_path"]
            )
        }
        undefended_successes = [
            key for key in plan_keys if undefended_by_key[key]["attack_success"] is True
        ]
        stopped = [
            key
            for key in undefended_successes
            if defended_by_key[key]["attack_success"] is False
        ]
        survived = [
            key
            for key in undefended_successes
            if defended_by_key[key]["attack_success"] is True
        ]
        corpus = {
            row["id"]: row
            for row in json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        }
        payload_records = self.manifest["carried_forward_payloads"]

        self.assertEqual(
            EXPECTED_PAYLOAD_ORDER,
            tuple(row["payload_id"] for row in payload_records),
        )
        undefended_counts = Counter(key[0] for key in undefended_successes)
        stopped_counts = Counter(key[0] for key in stopped)
        survived_counts = Counter(key[0] for key in survived)
        for row in payload_records:
            payload_id = row["payload_id"]
            self.assertEqual(corpus[payload_id]["category"], row["source_category"])
            self.assertEqual(
                row["template_sha256_utf8"],
                hashlib.sha256(corpus[payload_id]["template"].encode("utf-8")).hexdigest(),
            )
            self.assertEqual(undefended_counts[payload_id], row["undefended_native_successes"])
            self.assertEqual(stopped_counts[payload_id], row["stopped_cases"])
            self.assertEqual(survived_counts[payload_id], row["defended_native_successes"])

        categories = {row["source_category"] for row in payload_records}
        self.assertEqual(4, len(categories))
        self.assertEqual(4, self.manifest["source_category_count"])
        self.assertIsNone(self.manifest["distinct_source_family_requirement"])

    def test_five_versioned_strategies_are_frozen_without_execution_budget(self) -> None:
        strategies = self.manifest["mutation_strategies"]
        strategy_ids = tuple(strategy["strategy_id"] for strategy in strategies)

        self.assertEqual(EXPECTED_STRATEGY_IDS, strategy_ids)
        self.assertEqual(5, len(set(strategy_ids)))
        self.assertEqual(5, self.manifest["strategy_count"])
        for strategy in strategies:
            self.assertTrue(strategy["mechanism_target"].strip())
            self.assertTrue(strategy["design"].strip())

        self.assertEqual("v1", self.manifest["adaptive_attack_version"])
        self.assertEqual("banking", self.manifest["domain"])
        self.assertEqual("design-only-no-api-calls", self.manifest["execution_status"])
        self.assertEqual(
            "frozen",
            self.manifest["budget_status"],
        )

    def test_design_freeze_binds_strategy_and_seed_inputs(self) -> None:
        freeze = json.loads(DESIGN_FREEZE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            DESIGN_FREEZE_PATH.relative_to(PROJECT_ROOT).as_posix(),
            self.manifest["design_freeze_path"],
        )
        self.assertEqual(
            STRATEGY_PATH.relative_to(PROJECT_ROOT).as_posix(),
            freeze["strategy_manifest_path"],
        )
        self.assertEqual(
            ELIGIBLE_PATH.relative_to(PROJECT_ROOT).as_posix(),
            freeze["eligible_case_manifest_path"],
        )
        self.assertEqual(
            CORPUS_PATH.relative_to(PROJECT_ROOT).as_posix(),
            freeze["payload_corpus_path"],
        )
        self.assertEqual("v1", freeze["adaptive_attack_version"])
        self.assertEqual("frozen-before-api", freeze["freeze_status"])
        self.assertEqual(
            "CRLF normalized to LF before SHA-256",
            freeze["hash_normalization"],
        )
        self.assertEqual(
            freeze["strategy_manifest_sha256_canonical_lf"],
            _canonical_lf_sha256(STRATEGY_PATH),
        )
        self.assertEqual(
            freeze["eligible_case_manifest_sha256_canonical_lf"],
            _canonical_lf_sha256(ELIGIBLE_PATH),
        )
        self.assertEqual(
            freeze["payload_corpus_sha256_canonical_lf"],
            _canonical_lf_sha256(CORPUS_PATH),
        )
        self.assertEqual(
            EXPECTED_PAYLOAD_ORDER,
            tuple(freeze["carried_forward_payload_ids"]),
        )
        self.assertEqual(EXPECTED_STRATEGY_IDS, tuple(freeze["strategy_ids"]))
        self.assertFalse(freeze["api_calls_made"])
        self.assertEqual("design-only-no-api-calls", freeze["execution_status"])


if __name__ == "__main__":
    unittest.main()
