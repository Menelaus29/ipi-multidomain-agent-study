"""No-network tests for the isolated Gemma 4 delivery-path diagnostic."""

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.experiments import run_gemma4_sanity_check as diagnostic
from src.experiments.build_attack_splits import AttackContext
from src.llm_providers import google_llm_factory


class Gemma4DiagnosticTests(unittest.TestCase):
    def test_unexpected_step1_exception_returns_clean_nonquota_exit(self) -> None:
        stderr = StringIO()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with (
                patch.object(diagnostic, "validate_output_root", return_value=root),
                patch.object(
                    diagnostic,
                    "execute_clean_prepass",
                    side_effect=RuntimeError("synthetic diagnostic failure"),
                ),
                redirect_stderr(stderr),
            ):
                result = diagnostic.main(
                    [
                        "--diagnostic-target",
                        diagnostic.DIAGNOSTIC_TARGET,
                        "--output-root",
                        str(root),
                        "--max-runs",
                        "1",
                        "--stage",
                        "clean",
                    ]
                )

        self.assertEqual(diagnostic.UNEXPECTED_EXECUTION_EXIT_CODE, result)
        self.assertIn("RuntimeError: synthetic diagnostic failure", stderr.getvalue())
        self.assertNotIn("Traceback (most recent call last)", stderr.getvalue())

    def test_replay_corpus_is_locked_to_18_builtins_and_7_v1_candidates(self) -> None:
        cases = diagnostic.load_replay_cases()

        self.assertEqual(25, len(cases))
        self.assertEqual(18, sum(case.source_group == "builtin_v1" for case in cases))
        self.assertEqual(7, sum(case.source_group == "mutation_v1" for case in cases))
        self.assertEqual(
            ["workspace", "banking", "slack"],
            [case.context.domain for case in cases[:3]],
        )
        self.assertTrue(all(case.template is None for case in cases[:18]))
        self.assertTrue(all(case.template is not None for case in cases[18:]))

    def test_explicit_target_flag_and_isolated_output_root_are_required(self) -> None:
        with self.assertRaises(SystemExit):
            diagnostic.parse_args([])
        args = diagnostic.parse_args(["--diagnostic-target", diagnostic.DIAGNOSTIC_TARGET])
        self.assertEqual(diagnostic.DIAGNOSTIC_TARGET, args.diagnostic_target)
        with self.assertRaises(diagnostic.DiagnosticReplayError):
            diagnostic.validate_output_root(diagnostic.CALIBRATION_ROOT / "diagnostic")

    def test_gemma_factory_only_swaps_the_existing_model_identifier(self) -> None:
        sentinel = object()
        with patch.object(google_llm_factory, "get_google_llm", return_value=sentinel) as factory:
            result = google_llm_factory.get_google_gemma4_26b_diagnostic_llm()

        self.assertIs(sentinel, result)
        factory.assert_called_once_with(google_llm_factory.GEMMA4_26B_DIAGNOSTIC_MODEL)

    def test_cached_trace_is_indexed_without_constructing_a_model_or_calling_benchmark(self) -> None:
        case = diagnostic.ReplayCase(
            "mutation_v1",
            "mutation:test:r01",
            "test_family",
            AttackContext(
                "workspace",
                "file_content",
                "drive_feedback_injection",
                "user_task_19",
                "injection_task_7",
            ),
            "replay exactly this existing template: {{goal}}",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results_path = root / "results.jsonl"
            raw_root = root / "raw"
            attack_name = diagnostic._register_attack(case)
            spec = diagnostic._operation_spec(
                case, results_path=results_path, raw_root=raw_root, attack_name=attack_name
            )
            spec.raw_trace_path.parent.mkdir(parents=True)
            spec.raw_trace_path.write_text(
                json.dumps(
                    {
                        "suite_name": case.context.domain,
                        "pipeline_name": diagnostic.DIAGNOSTIC_PIPELINE_NAME,
                        "benchmark_version": diagnostic.BENCHMARK_VERSION,
                        "user_task_id": case.context.user_task_id,
                        "injection_task_id": case.context.injection_task_id,
                        "attack_type": attack_name,
                        "injections": {case.context.injection_vector: "rendered existing goal"},
                        "messages": [{"role": "assistant"}],
                        "security": True,
                        "utility": False,
                        "evaluation_timestamp": "2026-08-08T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch.object(diagnostic, "get_google_gemma4_26b_diagnostic_llm") as llm,
                patch.object(diagnostic, "benchmark_suite") as benchmark,
            ):
                record = diagnostic.execute_replay(
                    case, results_path=results_path, raw_root=raw_root
                )

            llm.assert_not_called()
            benchmark.assert_not_called()
            self.assertEqual(diagnostic.DIAGNOSTIC_TARGET, record.diagnostic_target)
            self.assertTrue(record.attack_success)
            self.assertFalse(record.utility_success)
            self.assertEqual({case.replay_id}, diagnostic.load_completed_replays(results_path, raw_root=raw_root))

    def test_diagnostic_module_does_not_depend_on_quota_guard(self) -> None:
        source = Path(diagnostic.__file__).read_text(encoding="utf-8")
        self.assertNotIn("quota_guard", source)
        self.assertNotIn("get_google_primary_llm", source)

    def test_windows_trace_path_guard_rejects_overlong_injected_trace(self) -> None:
        with patch.object(diagnostic.os, "name", "nt"):
            with self.assertRaises(diagnostic.DiagnosticReplayError):
                diagnostic._require_windows_trace_path_fits(Path("x" * 260))


if __name__ == "__main__":
    unittest.main()
