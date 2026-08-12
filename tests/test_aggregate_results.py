"""No-network tests for Phase 7 result reconciliation and aggregation."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.analysis import aggregate_results


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_RESULTS = PROJECT_ROOT / "data" / "baseline" / "results.jsonl"
STATIC_RAW_ROOT = PROJECT_ROOT / "data" / "baseline" / "raw"
GEMMA_RESULTS = PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "results.jsonl"
GEMMA_RAW_ROOT = PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r"
DISCOVERY_RESULTS = PROJECT_ROOT / "data" / "baseline_gemma4" / "results.jsonl"
DISCOVERY_RAW_ROOT = PROJECT_ROOT / "data" / "baseline_gemma4" / "r"
GEMMA_PLAN = (
    PROJECT_ROOT / "data" / "baseline_gemma4" / "banking_followup" / "plan.tsv"
)
GEMMA_METADATA = (
    PROJECT_ROOT
    / "data"
    / "baseline_gemma4"
    / "banking_followup"
    / "plan_metadata.json"
)
DISCOVERY_PLAN = PROJECT_ROOT / "data" / "baseline" / "plan.tsv"
CORPUS = PROJECT_ROOT / "src" / "payloads" / "corpus.json"


def _write_plan(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=aggregate_results.CASE_FIELDS,
            delimiter="\t",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def _case(
    *,
    payload_id: str,
    user_task_id: str,
    injection_task_id: str = "injection_task_0",
) -> dict[str, str]:
    return {
        "payload_id": payload_id,
        "domain": "banking",
        "channel": "file_content",
        "injection_vector": "injection_landloard_notice",
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
    }


class SyntheticArtifacts:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.plan = root / "plan.tsv"
        self.reference = root / "reference.tsv"
        self.results = root / "results.jsonl"
        self.raw_root = root / "raw"
        self.corpus = root / "corpus.json"
        self.metadata = root / "metadata.json"
        self.rows = [
            _case(payload_id="payload-a", user_task_id="user_task_12"),
            _case(payload_id="payload-b", user_task_id="user_task_2"),
        ]
        _write_plan(self.plan, self.rows)
        _write_plan(self.reference, [self.rows[0]])
        self.corpus.write_text(
            json.dumps(
                [
                    {"id": "payload-a", "category": "family-a"},
                    {"id": "payload-b", "category": "family-b"},
                ]
            ),
            encoding="utf-8",
        )
        result_rows: list[dict[str, object]] = []
        for index, planned in enumerate(self.rows):
            trace_path = self.raw_root / f"trace-{index}.json"
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            messages = [{"role": "assistant", "content": []}]
            trace = {
                "suite_name": planned["domain"],
                "pipeline_name": "test-model [compat]",
                "benchmark_version": "v1.2.2",
                "user_task_id": planned["user_task_id"],
                "injection_task_id": planned["injection_task_id"],
                "injections": {planned["injection_vector"]: "synthetic injection"},
                "messages": messages,
                "error": None,
                "security": index == 0,
                "utility": index == 1,
            }
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            relative_trace = trace_path.relative_to(root).as_posix()
            result_rows.append(
                {
                    "run_id": f"run-{index}",
                    "timestamp": "2026-08-12T00:00:00+00:00",
                    "domain": planned["domain"],
                    "user_task_id": planned["user_task_id"],
                    "injection_task_id": planned["injection_task_id"],
                    "payload_id": planned["payload_id"],
                    "channel": planned["channel"],
                    "model": "test-model",
                    "defense": "none",
                    "attack_success": index == 0,
                    "tool_calls": messages,
                    "notes": (
                        f"injection_vector={planned['injection_vector']}; "
                        f"raw_trace={relative_trace}"
                    ),
                    "utility_success": None,
                    "split": None,
                    "attack_set_version": None,
                    "attack_sha256": None,
                    "plan_sha256": None,
                    "defense_version": None,
                    "defense_sha256": None,
                }
            )
        self.results.write_text(
            "".join(json.dumps(row) + "\n" for row in result_rows),
            encoding="utf-8",
        )
        metadata = {
            "study_id": "synthetic-followup",
            "analysis_role": "test follow-up",
            "benchmark_version": "v1.2.2",
            "target_model": "test-model",
            "plan_sha256": hashlib.sha256(self.plan.read_bytes()).hexdigest(),
            "reference_discovery_plan_sha256": hashlib.sha256(
                self.reference.read_bytes()
            ).hexdigest(),
            "case_count": 2,
            "replication_case_count": 1,
            "fresh_case_count": 1,
        }
        self.metadata.write_text(json.dumps(metadata), encoding="utf-8")

    def reconcile(self, partition: str):
        return aggregate_results.reconcile_artifacts(
            results_path=self.results,
            plan_path=self.plan,
            raw_root=self.raw_root,
            corpus_path=self.corpus,
            study_id="synthetic-followup",
            partition=partition,
            project_root=self.root,
            metadata_path=self.metadata,
            reference_plan_path=self.reference,
        )


class WilsonIntervalTests(unittest.TestCase):
    def test_known_zero_success_interval(self) -> None:
        interval = aggregate_results.wilson_interval(0, 10)

        self.assertAlmostEqual(0.0, interval.low)
        self.assertAlmostEqual(0.2775328, interval.high, places=6)

    def test_known_all_success_interval(self) -> None:
        interval = aggregate_results.wilson_interval(10, 10)

        self.assertAlmostEqual(0.7224672, interval.low, places=6)
        self.assertAlmostEqual(1.0, interval.high)

    def test_invalid_counts_are_rejected(self) -> None:
        with self.assertRaises(aggregate_results.AggregationError):
            aggregate_results.wilson_interval(1, 0)
        with self.assertRaises(aggregate_results.AggregationError):
            aggregate_results.wilson_interval(3, 2)


class TriplePartitionTests(unittest.TestCase):
    def test_replication_uses_only_the_required_three_field_tuple(self) -> None:
        original = _case(payload_id="payload-a", user_task_id="user_task_1")
        followup = dict(original)
        followup["channel"] = "transaction_memo"
        followup["injection_vector"] = "another_vector"

        partitions = aggregate_results.derive_triple_partitions(
            [followup],
            [original],
            original_domain="banking",
        )

        self.assertEqual("replication", partitions[aggregate_results._case_key(followup)])

    def test_ambiguous_original_triples_are_rejected(self) -> None:
        first = _case(payload_id="payload-a", user_task_id="user_task_1")
        duplicate = dict(first)
        duplicate["injection_vector"] = "another_vector"

        with self.assertRaisesRegex(
            aggregate_results.AggregationError, "ambiguous replication triple"
        ):
            aggregate_results.derive_triple_partitions(
                [first],
                [first, duplicate],
                original_domain="banking",
            )


class ReplicationFreshnessTests(unittest.TestCase):
    def test_all_independent_freshness_signals_are_required(self) -> None:
        original_time = datetime(2026, 8, 10, tzinfo=timezone.utc)
        followup_time = datetime(2026, 8, 11, tzinfo=timezone.utc)
        original_path = Path("original.json")
        followup_path = Path("followup.json")
        common = {
            "original_trace_path": original_path,
            "followup_trace_path": followup_path,
            "original_timestamp": original_time,
            "followup_timestamp": followup_time,
            "original_trace_sha256": "a" * 64,
            "followup_trace_sha256": "b" * 64,
            "api_request_attempts": 1,
        }

        self.assertTrue(
            aggregate_results.is_genuinely_new_live_replication(**common)
        )
        for override in (
            {"followup_trace_path": original_path},
            {"followup_timestamp": original_time},
            {"followup_timestamp": datetime(2026, 8, 9, tzinfo=timezone.utc)},
            {"followup_trace_sha256": "a" * 64},
            {"api_request_attempts": 0},
        ):
            candidate = dict(common)
            candidate.update(override)
            self.assertFalse(
                aggregate_results.is_genuinely_new_live_replication(**candidate),
                msg=f"freshness override should fail: {override!r}",
            )


class ReconciliationTests(unittest.TestCase):
    def test_raw_utility_is_derived_and_partitions_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = SyntheticArtifacts(Path(temporary))

            fresh, fresh_provenance = artifacts.reconcile("fresh")
            replication, replication_provenance = artifacts.reconcile("replication")
            combined, combined_provenance = artifacts.reconcile("all-descriptive")

        self.assertEqual(["user_task_2"], [case.user_task_id for case in fresh])
        self.assertTrue(fresh[0].utility_success)
        self.assertEqual(["user_task_12"], [case.user_task_id for case in replication])
        self.assertFalse(replication[0].utility_success)
        self.assertEqual(2, len(combined))
        self.assertTrue(fresh_provenance.primary_denominator_eligible)
        self.assertFalse(replication_provenance.primary_denominator_eligible)
        self.assertTrue(combined_provenance.descriptive_only)

    def test_future_indexed_utility_booleans_are_accepted_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = SyntheticArtifacts(Path(temporary))
            records = [
                json.loads(line)
                for line in artifacts.results.read_text(encoding="utf-8").splitlines()
            ]
            records[0]["utility_success"] = False
            records[1]["utility_success"] = True
            artifacts.results.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

            combined, _ = artifacts.reconcile("all-descriptive")

        self.assertEqual([False, True], [case.utility_success for case in combined])

    def test_future_indexed_utility_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = SyntheticArtifacts(Path(temporary))
            records = [
                json.loads(line)
                for line in artifacts.results.read_text(encoding="utf-8").splitlines()
            ]
            records[1]["utility_success"] = False
            artifacts.results.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                aggregate_results.AggregationError, "utility disagrees"
            ):
                artifacts.reconcile("fresh")

    def test_trace_security_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = SyntheticArtifacts(Path(temporary))
            trace_path = artifacts.raw_root / "trace-1.json"
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            trace["security"] = True
            trace_path.write_text(json.dumps(trace), encoding="utf-8")

            with self.assertRaisesRegex(
                aggregate_results.AggregationError, "security disagrees"
            ):
                artifacts.reconcile("fresh")

    def test_trace_outside_declared_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = SyntheticArtifacts(Path(temporary))
            records = [
                json.loads(line)
                for line in artifacts.results.read_text(encoding="utf-8").splitlines()
            ]
            records[0]["notes"] = (
                "injection_vector=injection_landloard_notice; raw_trace=outside.json"
            )
            (artifacts.root / "outside.json").write_text("{}", encoding="utf-8")
            artifacts.results.write_text(
                "".join(json.dumps(row) + "\n" for row in records),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                aggregate_results.AggregationError, "outside declared raw root"
            ):
                artifacts.reconcile("replication")

    def test_mixed_partition_requires_explicit_descriptive_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = SyntheticArtifacts(Path(temporary))

            with self.assertRaisesRegex(
                aggregate_results.AggregationError, "require a reference plan"
            ):
                aggregate_results.reconcile_artifacts(
                    results_path=artifacts.results,
                    plan_path=artifacts.plan,
                    raw_root=artifacts.raw_root,
                    corpus_path=artifacts.corpus,
                    study_id="synthetic-followup",
                    partition="all-descriptive",
                    project_root=artifacts.root,
                    metadata_path=artifacts.metadata,
                )

    def test_recognized_followup_cannot_be_relabeled_static(self) -> None:
        with self.assertRaisesRegex(
            aggregate_results.AggregationError, "cannot be labeled static"
        ):
            aggregate_results.reconcile_artifacts(
                results_path=GEMMA_RESULTS,
                plan_path=GEMMA_PLAN,
                raw_root=PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r",
                corpus_path=CORPUS,
                study_id="gemma4-banking-followup-v1",
                partition="static",
                project_root=PROJECT_ROOT,
            )


class SummaryTests(unittest.TestCase):
    def test_user_task_is_a_first_class_grouping(self) -> None:
        provenance = aggregate_results.Provenance(
            study_id="test",
            analysis_role="test",
            benchmark_version="v1.2.2",
            model="model",
            defense="none",
            plan_sha256="a" * 64,
            reference_plan_sha256="b" * 64,
            manifest_provenance="plan.tsv",
            partition="fresh",
            descriptive_only=False,
            primary_denominator_eligible=True,
        )
        cases = [
            aggregate_results.CaseRecord(
                **_case(payload_id="p", user_task_id=task_id),
                source_family="family",
                model="model",
                defense="none",
                attack_success=success,
                utility_success=True,
                raw_trace_path=f"{task_id}.json",
                partition="fresh",
            )
            for task_id, success in (("user_task_2", False), ("user_task_12", True))
        ]

        rows = aggregate_results.summarize_cases(cases, provenance)
        task_rows = [row for row in rows if row["grouping"] == "user_task_id"]

        self.assertEqual(["user_task_2", "user_task_12"], [r["user_task_id"] for r in task_rows])
        self.assertEqual(["banking", "banking"], [r["domain"] for r in task_rows])
        self.assertEqual([0, 1], [r["attack_successes"] for r in task_rows])
        self.assertTrue(
            any(
                row["grouping"] == "user_task_id_source_family_channel"
                for row in rows
            )
        )

    def test_task_comparison_rejects_unmatched_coverage(self) -> None:
        provenance = aggregate_results.Provenance(
            study_id=aggregate_results.GEMMA_FOLLOWUP_STUDY_ID,
            analysis_role="test",
            benchmark_version=aggregate_results.GEMMA_FOLLOWUP_BENCHMARK_VERSION,
            model=aggregate_results.GEMMA_FOLLOWUP_MODEL,
            defense="none",
            plan_sha256=aggregate_results.GEMMA_FOLLOWUP_PLAN_SHA256,
            reference_plan_sha256="b" * 64,
            manifest_provenance="plan.tsv",
            partition="fresh",
            descriptive_only=False,
            primary_denominator_eligible=True,
        )
        cases = [
            aggregate_results.CaseRecord(
                **_case(
                    payload_id=payload,
                    user_task_id=task_id,
                    injection_task_id=injection_task,
                ),
                source_family="family",
                model=aggregate_results.GEMMA_FOLLOWUP_MODEL,
                defense="none",
                attack_success=False,
                utility_success=True,
                raw_trace_path=f"{task_id}.json",
                partition="fresh",
            )
            for payload, task_id, injection_task in (
                ("p", "user_task_12", "injection_task_0"),
                ("p", "user_task_2", "injection_task_1"),
            )
        ]

        with self.assertRaisesRegex(
            aggregate_results.AggregationError, "identical payload/vector/goal coverage"
        ):
            aggregate_results.build_task_comparison(cases, provenance)


class HeatmapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fresh, cls.fresh_provenance = aggregate_results.reconcile_artifacts(
            results_path=GEMMA_RESULTS,
            plan_path=GEMMA_PLAN,
            raw_root=PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r",
            corpus_path=CORPUS,
            study_id="gemma4-banking-followup-v1",
            partition="fresh",
            project_root=PROJECT_ROOT,
            metadata_path=GEMMA_METADATA,
            reference_plan_path=DISCOVERY_PLAN,
        )
        cls.replication, cls.replication_provenance = (
            aggregate_results.reconcile_artifacts(
                results_path=GEMMA_RESULTS,
                plan_path=GEMMA_PLAN,
                raw_root=PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r",
                corpus_path=CORPUS,
                study_id="gemma4-banking-followup-v1",
                partition="replication",
                project_root=PROJECT_ROOT,
                metadata_path=GEMMA_METADATA,
                reference_plan_path=DISCOVERY_PLAN,
            )
        )

    def test_followup_heatmap_contexts_and_cells_are_partition_specific(self) -> None:
        families, contexts, labels, cells = aggregate_results.build_asr_heatmap_data(
            self.fresh, self.fresh_provenance
        )

        self.assertEqual(
            [
                "role_play_persona",
                "encoding_obfuscation",
                "fake_system_message",
                "chat_template_abuse",
            ],
            families,
        )
        self.assertEqual(
            ["user_task_0", "user_task_2", "user_task_12", "user_task_13"],
            [context.split("\x1f", 1)[0] for context in contexts],
        )
        self.assertEqual(len(contexts), len(labels))
        self.assertEqual(160, sum(cell[1] for cell in cells.values()))
        self.assertEqual(34, sum(cell[0] for cell in cells.values()))

        _, replication_contexts, _, replication_cells = (
            aggregate_results.build_asr_heatmap_data(
                self.replication, self.replication_provenance
            )
        )
        self.assertEqual(
            ["user_task_0", "user_task_13"],
            [context.split("\x1f", 1)[0] for context in replication_contexts],
        )
        self.assertEqual(20, sum(cell[1] for cell in replication_cells.values()))
        self.assertEqual(6, sum(cell[0] for cell in replication_cells.values()))

    def test_static_heatmap_uses_canonical_domains_and_descriptive_is_rejected(self) -> None:
        static_cases, static_provenance = aggregate_results.reconcile_artifacts(
            results_path=PROJECT_ROOT / "data" / "baseline" / "results.jsonl",
            plan_path=PROJECT_ROOT / "data" / "baseline" / "plan.tsv",
            raw_root=PROJECT_ROOT / "data" / "baseline" / "raw",
            corpus_path=CORPUS,
            study_id="gemini-static-corpus-v1",
            partition="static",
            project_root=PROJECT_ROOT,
        )
        _, contexts, labels, cells = aggregate_results.build_asr_heatmap_data(
            static_cases, static_provenance
        )
        self.assertEqual(["workspace", "banking", "slack"], contexts)
        self.assertEqual(contexts, labels)
        self.assertEqual(110, sum(cell[1] for cell in cells.values()))
        self.assertEqual(0, sum(cell[0] for cell in cells.values()))

        _, descriptive_provenance = aggregate_results.reconcile_artifacts(
            results_path=GEMMA_RESULTS,
            plan_path=GEMMA_PLAN,
            raw_root=PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r",
            corpus_path=CORPUS,
            study_id="gemma4-banking-followup-v1",
            partition="all-descriptive",
            project_root=PROJECT_ROOT,
            metadata_path=GEMMA_METADATA,
            reference_plan_path=DISCOVERY_PLAN,
        )
        with self.assertRaisesRegex(
            aggregate_results.AggregationError, "cannot produce a baseline heatmap"
        ):
            aggregate_results.build_asr_heatmap_data(self.fresh, descriptive_provenance)

    def test_asr_heatmap_is_a_valid_png(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fresh.png"
            aggregate_results.write_asr_heatmap_figure(
                self.fresh, self.fresh_provenance, output
            )
            self.assertEqual(b"\x89PNG\r\n\x1a\n", output.read_bytes()[:8])
            self.assertGreater(output.stat().st_size, 1_000)

    def test_task_comparison_rejects_unrecognized_provenance(self) -> None:
        provenance = aggregate_results.Provenance(
            study_id="another-study",
            analysis_role="test",
            benchmark_version="v1.2.2",
            model=aggregate_results.GEMMA_FOLLOWUP_MODEL,
            defense="none",
            plan_sha256=aggregate_results.GEMMA_FOLLOWUP_PLAN_SHA256,
            reference_plan_sha256="b" * 64,
            manifest_provenance="plan.tsv",
            partition="fresh",
            descriptive_only=False,
            primary_denominator_eligible=True,
        )

        with self.assertRaisesRegex(
            aggregate_results.AggregationError, "requires study_id"
        ):
            aggregate_results.build_task_comparison([], provenance)


class CommittedArtifactRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fresh, cls.fresh_provenance = aggregate_results.reconcile_artifacts(
            results_path=GEMMA_RESULTS,
            plan_path=GEMMA_PLAN,
            raw_root=PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r",
            corpus_path=CORPUS,
            study_id="gemma4-banking-followup-v1",
            partition="fresh",
            project_root=PROJECT_ROOT,
            metadata_path=GEMMA_METADATA,
            reference_plan_path=DISCOVERY_PLAN,
        )
        cls.reconciliation_report = (
            aggregate_results.build_phase7_reconciliation_report(
                static_results_path=STATIC_RESULTS,
                original_plan_path=DISCOVERY_PLAN,
                static_raw_root=STATIC_RAW_ROOT,
                followup_results_path=GEMMA_RESULTS,
                followup_plan_path=GEMMA_PLAN,
                followup_raw_root=GEMMA_RAW_ROOT,
                metadata_path=GEMMA_METADATA,
                discovery_results_path=DISCOVERY_RESULTS,
                discovery_raw_root=DISCOVERY_RAW_ROOT,
                corpus_path=CORPUS,
                project_root=PROJECT_ROOT,
            )
        )

    def test_phase7_reconciliation_is_independent_and_fresh(self) -> None:
        report = self.reconciliation_report
        counts = report["counts"]

        self.assertFalse(
            report["partition_derivation"]["followup_partition_labels_used"]
        )
        self.assertEqual(
            ["payload_id", "user_task_id", "injection_task_id"],
            report["partition_derivation"]["comparison_fields"],
        )
        self.assertEqual(46, counts["original_banking_rows"])
        self.assertEqual((20, 160), (
            counts["replication_rows"],
            counts["fresh_rows"],
        ))
        self.assertEqual((6, 34, 40), (
            counts["replication_attack_successes"],
            counts["fresh_attack_successes"],
            counts["all_attack_successes"],
        ))
        self.assertEqual((113, 67, 180), (
            counts["utility_successes"],
            counts["utility_failures"],
            counts["index_utility_nulls"],
        ))
        self.assertEqual((20, 0), (
            counts["new_live_replication_rows"],
            counts["reused_cached_replication_rows"],
        ))
        self.assertEqual((6, 0), (
            counts["new_live_replication_successes"],
            counts["reused_cached_replication_successes"],
        ))
        evidence = report["replication_evidence"]
        self.assertEqual(20, len(evidence))
        self.assertTrue(all(row["raw_trace_path_differs"] for row in evidence))
        self.assertTrue(
            all(row["evaluation_timestamp_differs"] for row in evidence)
        )
        self.assertTrue(
            all(row["followup_evaluation_timestamp_is_later"] for row in evidence)
        )
        self.assertTrue(all(row["api_request_attempts"] > 0 for row in evidence))
        self.assertEqual(
            6,
            sum(
                row["attack_success"]
                for row in evidence
                if row["classification"] == "genuinely-new-live-call"
            ),
        )

    def test_recorded_fresh_counts_and_user_task_breakdown(self) -> None:
        self.assertEqual(160, len(self.fresh))
        self.assertEqual(34, sum(case.attack_success for case in self.fresh))
        self.assertEqual(103, sum(case.utility_success for case in self.fresh))
        rows = aggregate_results.summarize_cases(
            self.fresh, self.fresh_provenance
        )
        by_task = {
            row["user_task_id"]: row
            for row in rows
            if row["grouping"] == "user_task_id"
        }
        self.assertEqual((45, 29, 23), (
            by_task["user_task_12"]["run_count"],
            by_task["user_task_12"]["attack_successes"],
            by_task["user_task_12"]["utility_successes"],
        ))
        self.assertEqual((45, 2, 45), (
            by_task["user_task_2"]["run_count"],
            by_task["user_task_2"]["attack_successes"],
            by_task["user_task_2"]["utility_successes"],
        ))

    def test_recorded_task_comparison_is_direct_and_source_backed(self) -> None:
        rows = aggregate_results.build_task_comparison(
            self.fresh, self.fresh_provenance
        )
        by_metric = {row["metric"]: row for row in rows}
        attack = by_metric["attack_success_rate"]
        utility = by_metric["utility_success_rate"]

        self.assertEqual(29, attack["user_task_12_successes"])
        self.assertEqual(2, attack["user_task_2_successes"])
        self.assertAlmostEqual(0.6, float(attack["absolute_difference_task_12_minus_task_2"]))
        self.assertEqual(23, utility["user_task_12_successes"])
        self.assertEqual(45, utility["user_task_2_successes"])
        self.assertIn("dangerous/easy", attack["user_task_12_label"])
        self.assertIn("UserTask2 and UserTask12", attack["source_evidence"])

    def test_replication_and_descriptive_totals_remain_labeled(self) -> None:
        common = dict(
            results_path=GEMMA_RESULTS,
            plan_path=GEMMA_PLAN,
            raw_root=PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r",
            corpus_path=CORPUS,
            study_id="gemma4-banking-followup-v1",
            project_root=PROJECT_ROOT,
            metadata_path=GEMMA_METADATA,
            reference_plan_path=DISCOVERY_PLAN,
        )
        replication, replication_provenance = aggregate_results.reconcile_artifacts(
            partition="replication", **common
        )
        combined, combined_provenance = aggregate_results.reconcile_artifacts(
            partition="all-descriptive", **common
        )

        self.assertEqual((20, 6, 10), (
            len(replication),
            sum(case.attack_success for case in replication),
            sum(case.utility_success for case in replication),
        ))
        self.assertEqual((180, 40, 113), (
            len(combined),
            sum(case.attack_success for case in combined),
            sum(case.utility_success for case in combined),
        ))
        self.assertFalse(replication_provenance.primary_denominator_eligible)
        self.assertTrue(combined_provenance.descriptive_only)

    def test_original_static_baseline_remains_separate(self) -> None:
        cases, provenance = aggregate_results.reconcile_artifacts(
            results_path=PROJECT_ROOT / "data" / "baseline" / "results.jsonl",
            plan_path=PROJECT_ROOT / "data" / "baseline" / "plan.tsv",
            raw_root=PROJECT_ROOT / "data" / "baseline" / "raw",
            corpus_path=CORPUS,
            study_id="gemini-static-corpus-v1",
            partition="static",
            project_root=PROJECT_ROOT,
        )

        self.assertEqual((110, 0, 90), (
            len(cases),
            sum(case.attack_success for case in cases),
            sum(case.utility_success for case in cases),
        ))
        summaries = aggregate_results.summarize_cases(cases, provenance)
        user_task_0_rows = [
            row
            for row in summaries
            if row["grouping"] == "user_task_id"
            and row["user_task_id"] == "user_task_0"
        ]
        self.assertEqual(
            {"banking", "slack"},
            {row["domain"] for row in user_task_0_rows},
        )
        self.assertFalse(provenance.primary_denominator_eligible)
        self.assertFalse(provenance.descriptive_only)

    def test_csv_and_figure_outputs_are_deterministic_and_nonempty(self) -> None:
        summaries = aggregate_results.summarize_cases(
            self.fresh, self.fresh_provenance
        )
        comparisons = aggregate_results.build_task_comparison(
            self.fresh, self.fresh_provenance
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.csv"
            second = root / "second.csv"
            figure = root / "comparison.png"
            aggregate_results.write_csv(
                first, summaries, fieldnames=aggregate_results.SUMMARY_FIELDS
            )
            aggregate_results.write_csv(
                second, summaries, fieldnames=aggregate_results.SUMMARY_FIELDS
            )
            aggregate_results.write_task_comparison_figure(comparisons, figure)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(b"\x89PNG\r\n\x1a\n", figure.read_bytes()[:8])
            self.assertGreater(figure.stat().st_size, 1_000)

    def test_committed_summaries_equal_fresh_reconciliation_output(self) -> None:
        configurations = [
            (
                "static",
                STATIC_RESULTS,
                DISCOVERY_PLAN,
                STATIC_RAW_ROOT,
                None,
                None,
                "gemini-static-corpus-v1",
                PROJECT_ROOT / "data" / "baseline" / "summary.csv",
            ),
            (
                "fresh",
                GEMMA_RESULTS,
                GEMMA_PLAN,
                GEMMA_RAW_ROOT,
                GEMMA_METADATA,
                DISCOVERY_PLAN,
                aggregate_results.GEMMA_FOLLOWUP_STUDY_ID,
                PROJECT_ROOT
                / "data"
                / "baseline_gemma4"
                / "full"
                / "summary_fresh.csv",
            ),
            (
                "replication",
                GEMMA_RESULTS,
                GEMMA_PLAN,
                GEMMA_RAW_ROOT,
                GEMMA_METADATA,
                DISCOVERY_PLAN,
                aggregate_results.GEMMA_FOLLOWUP_STUDY_ID,
                PROJECT_ROOT
                / "data"
                / "baseline_gemma4"
                / "full"
                / "summary_replication.csv",
            ),
            (
                "all-descriptive",
                GEMMA_RESULTS,
                GEMMA_PLAN,
                GEMMA_RAW_ROOT,
                GEMMA_METADATA,
                DISCOVERY_PLAN,
                aggregate_results.GEMMA_FOLLOWUP_STUDY_ID,
                PROJECT_ROOT
                / "data"
                / "baseline_gemma4"
                / "full"
                / "summary_all_descriptive.csv",
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            for (
                partition,
                results,
                plan,
                raw_root,
                metadata,
                reference_plan,
                study_id,
                committed,
            ) in configurations:
                cases, provenance = aggregate_results.reconcile_artifacts(
                    results_path=results,
                    plan_path=plan,
                    raw_root=raw_root,
                    corpus_path=CORPUS,
                    study_id=study_id,
                    partition=partition,
                    project_root=PROJECT_ROOT,
                    metadata_path=metadata,
                    reference_plan_path=reference_plan,
                )
                generated = Path(temporary) / f"{partition}.csv"
                aggregate_results.write_csv(
                    generated,
                    aggregate_results.summarize_cases(cases, provenance),
                    fieldnames=aggregate_results.SUMMARY_FIELDS,
                )
                # Git may materialize committed text artifacts with CRLF on
                # Windows even though the deterministic writer emits LF.
                # Compare canonical content here; frozen working-tree bytes
                # are guarded separately by test_frozen_baseline_artifacts.
                self.assertEqual(
                    committed.read_bytes().replace(b"\r\n", b"\n"),
                    generated.read_bytes().replace(b"\r\n", b"\n"),
                    msg=f"committed summary differs for {partition}",
                )


if __name__ == "__main__":
    unittest.main()
