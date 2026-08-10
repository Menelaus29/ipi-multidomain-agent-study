"""No-network tests for the Phase 6A clean-control runner."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from contextlib import nullcontext, redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.experiments import run_clean_controls
from src.schemas import RunResult


def _write_manifest(path: Path, rows: list[tuple[object, ...]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(
            (
                "candidate_rank",
                "domain",
                "channel",
                "injection_vector",
                "user_task_id",
                "injection_task_id",
            )
        )
        writer.writerows(rows)


def _rows() -> list[tuple[object, ...]]:
    return [
        (1, "workspace", "file_content", "workspace_vector_0", "user_task_0", "injection_task_0"),
        (2, "banking", "file_content", "banking_vector_0", "user_task_0", "injection_task_0"),
        (3, "slack", "web_content", "slack_vector_0", "user_task_0", "injection_task_1"),
        (4, "workspace", "email_body", "workspace_vector_1", "user_task_1", "injection_task_1"),
        (5, "banking", "transaction_memo", "banking_vector_1", "user_task_1", "injection_task_1"),
        (6, "slack", "web_content", "slack_vector_1", "user_task_1", "injection_task_2"),
    ]


def _result(
    row: run_clean_controls.RankedContext,
    *,
    manifest_hash: str,
    utility: bool,
    split: str = "dev",
    raw_path: Path | None = None,
) -> RunResult:
    context = row.context
    return RunResult(
        run_id=run_clean_controls.clean_operation_id(
            row, manifest_sha256=manifest_hash, split=split
        ),
        timestamp="2026-08-07T00:00:00+00:00",
        domain=context.domain,
        user_task_id=context.user_task_id,
        injection_task_id=context.injection_task_id,
        payload_id="none-clean-control",
        channel=context.channel,
        model="google-gemini-3.5-flash-lite",
        defense="none",
        attack_success=False,
        tool_calls=[],
        notes=(
            f"injection_vector={context.injection_vector}; "
            f"candidate_rank={row.candidate_rank}"
            + (f"; raw_trace={raw_path}" if raw_path is not None else "")
        ),
        utility_success=utility,
        split=split,
        plan_sha256=manifest_hash,
    )


class ManifestTests(unittest.TestCase):
    def test_canonical_candidate_files_are_pinned_to_their_splits(self) -> None:
        self.assertEqual(
            "dev",
            run_clean_controls.infer_split(
                run_clean_controls.DEFAULT_DEV_CANDIDATES, None
            ),
        )
        self.assertEqual(
            "holdout",
            run_clean_controls.infer_split(
                run_clean_controls.DEFAULT_HOLDOUT_CANDIDATES, "holdout"
            ),
        )
        with self.assertRaisesRegex(
            run_clean_controls.CleanControlError, "cannot be labeled"
        ):
            run_clean_controls.infer_split(
                run_clean_controls.DEFAULT_DEV_CANDIDATES, "holdout"
            )
        with self.assertRaisesRegex(
            run_clean_controls.CleanControlError, "cannot be labeled"
        ):
            run_clean_controls.infer_split(
                run_clean_controls.DEFAULT_HOLDOUT_CANDIDATES, "dev"
            )

    def test_committed_canonical_candidate_hashes_are_validated(self) -> None:
        for split, path in (
            ("dev", run_clean_controls.DEFAULT_DEV_CANDIDATES),
            ("holdout", run_clean_controls.DEFAULT_HOLDOUT_CANDIDATES),
        ):
            with self.subTest(split=split):
                manifest = run_clean_controls.load_context_manifest(path)
                run_clean_controls.validate_canonical_source_provenance(
                    manifest, split=split
                )

        canonical = run_clean_controls.load_context_manifest(
            run_clean_controls.DEFAULT_DEV_CANDIDATES
        )
        changed = run_clean_controls.ContextManifest(
            canonical.path,
            "0" * 64,
            canonical.rows,
        )
        with self.assertRaisesRegex(
            run_clean_controls.CleanControlError, "SHA-256 changed"
        ):
            run_clean_controls.validate_canonical_source_provenance(
                changed, split="dev"
            )

    def test_manifest_order_hash_and_noncontiguous_selection_ranks_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            selected_path = root / "selected.tsv"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            content = run_clean_controls.render_selection(
                (manifest.rows[0], manifest.rows[3])
            )
            selected_path.write_bytes(content)
            selected = run_clean_controls.load_context_manifest(selected_path)

        self.assertEqual([1, 4], [row.candidate_rank for row in selected.rows])
        self.assertEqual(64, len(manifest.sha256))
        self.assertNotIn(b"\r\n", content)

    def test_duplicate_context_or_nonincreasing_rank_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "bad.tsv"
            rows = _rows()[:2]
            rows[1] = (1, *rows[0][1:])
            _write_manifest(path, rows)
            with self.assertRaises(run_clean_controls.CleanControlError):
                run_clean_controls.load_context_manifest(path)


class SelectionTests(unittest.TestCase):
    def test_development_selection_reserves_missing_surface_slot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            rows = [
                (1, "workspace", "file_content", "file_1", "user_task_1", "injection_task_1"),
                (2, "workspace", "file_content", "file_2", "user_task_2", "injection_task_2"),
                (3, "workspace", "calendar_event", "calendar_1", "user_task_3", "injection_task_3"),
                (4, "workspace", "file_content", "file_3", "user_task_4", "injection_task_4"),
                (6, "workspace", "file_content", "file_4", "user_task_6", "injection_task_6"),
                (7, "workspace", "calendar_event", "calendar_2", "user_task_7", "injection_task_7"),
                (8, "workspace", "file_content", "file_5", "user_task_8", "injection_task_8"),
                (21, "workspace", "email_body", "email_1", "user_task_21", "injection_task_21"),
            ]
            _write_manifest(source, rows)
            manifest = run_clean_controls.load_context_manifest(source)
            checkpoints = {
                row.key: _result(
                    row,
                    manifest_hash=manifest.sha256,
                    utility=True,
                )
                for row in manifest.rows[:6]
            }

            selected, counts = run_clean_controls.selected_contexts(
                manifest,
                checkpoints,
                per_domain=6,
                require_development_coverage=True,
            )
            self.assertEqual([1, 2, 3, 4, 6], [row.candidate_rank for row in selected])
            self.assertEqual(5, counts["workspace"])
            self.assertFalse(
                run_clean_controls._candidate_advances_development_coverage(
                    manifest.rows[6], manifest, checkpoints
                )
            )
            self.assertTrue(
                run_clean_controls._candidate_advances_development_coverage(
                    manifest.rows[7], manifest, checkpoints
                )
            )

            email_row = manifest.rows[7]
            checkpoints[email_row.key] = _result(
                email_row,
                manifest_hash=manifest.sha256,
                utility=True,
            )
            selected, counts = run_clean_controls.selected_contexts(
                manifest,
                checkpoints,
                per_domain=6,
                require_development_coverage=True,
            )

        self.assertEqual(
            [1, 2, 3, 4, 6, 21],
            [row.candidate_rank for row in selected],
        )
        self.assertEqual(6, counts["workspace"])

    def test_clean_operation_ids_are_stable_and_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "source.tsv"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            row = manifest.rows[0]
            first = run_clean_controls.clean_operation_id(
                row, manifest_sha256=manifest.sha256, split="dev"
            )
            second = run_clean_controls.clean_operation_id(
                row, manifest_sha256=manifest.sha256, split="dev"
            )
            changed_plan = run_clean_controls.clean_operation_id(
                row, manifest_sha256="f" * 64, split="dev"
            )
            changed_split = run_clean_controls.clean_operation_id(
                row, manifest_sha256=manifest.sha256, split="holdout"
            )
            changed_context = run_clean_controls.clean_operation_id(
                manifest.rows[3], manifest_sha256=manifest.sha256, split="dev"
            )

        self.assertEqual(first, second)
        self.assertEqual(36, len(first))
        self.assertEqual(4, len({first, changed_plan, changed_split, changed_context}))

    def test_cursor_records_deterministic_per_domain_next_unread_ranks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            selection = root / "selection.tsv"
            state_path = root / "holdout_A.state.json"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            completed: dict[tuple[str, str, str, str], RunResult] = {}

            def fake_execute(
                row: run_clean_controls.RankedContext, **_: object
            ) -> RunResult:
                result = _result(
                    row,
                    manifest_hash=manifest.sha256,
                    utility=True,
                    split="holdout",
                )
                completed[row.key] = result
                return result

            with patch.object(
                run_clean_controls, "execute_clean_control", side_effect=fake_execute
            ):
                status = run_clean_controls.run_controls(
                    manifest=manifest,
                    selection_output=selection,
                    per_domain=1,
                    split="holdout",
                    results_path=root / "results.jsonl",
                    raw_root=root / "raw",
                    state_output=state_path,
                )
            first_bytes = state_path.read_bytes()
            expected_bytes = run_clean_controls.render_control_state(
                manifest,
                completed,
                split="holdout",
                per_domain=1,
            )
            state = json.loads(first_bytes)

        self.assertEqual(0, status)
        self.assertEqual(first_bytes, expected_bytes)
        self.assertTrue(state["selection_complete"])
        self.assertEqual(
            {"workspace": 4, "banking": 5, "slack": 6},
            state["next_unread_candidate_rank"],
        )
        self.assertEqual(
            {"workspace": [1], "banking": [2], "slack": [3]},
            state["selected_candidate_ranks"],
        )
        self.assertNotIn("timestamp", state)

    def test_first_success_per_domain_is_selected_in_manifest_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            selection = root / "selection.tsv"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            calls: list[int] = []

            def fake_execute(row: run_clean_controls.RankedContext, **_: object) -> RunResult:
                calls.append(row.candidate_rank)
                return _result(
                    row,
                    manifest_hash=manifest.sha256,
                    utility=row.candidate_rank >= 4,
                )

            with patch.object(
                run_clean_controls, "execute_clean_control", side_effect=fake_execute
            ):
                status = run_clean_controls.run_controls(
                    manifest=manifest,
                    selection_output=selection,
                    per_domain=1,
                    split="dev",
                    results_path=root / "results.jsonl",
                    raw_root=root / "raw",
                )
            selected = run_clean_controls.load_context_manifest(selection)

        self.assertEqual(0, status)
        self.assertEqual([1, 2, 3, 4, 5, 6], calls)
        self.assertEqual([4, 5, 6], [row.candidate_rank for row in selected.rows])

    def test_completed_selection_resumes_without_repeating_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            results_path = root / "results.jsonl"
            selection = root / "selection.tsv"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            successful = [manifest.rows[index] for index in (0, 1, 2)]
            raw_root = root / "raw"
            records: list[RunResult] = []
            for row in successful:
                raw_path = raw_root / f"rank-{row.candidate_rank}.json"
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_text(
                    json.dumps(
                        {
                            "suite_name": row.context.domain,
                            "pipeline_name": run_clean_controls.PRIMARY_PIPELINE_NAME,
                            "benchmark_version": run_clean_controls.BENCHMARK_VERSION,
                            "user_task_id": row.context.user_task_id,
                            "injection_task_id": None,
                            "attack_type": None,
                            "messages": [],
                            "injections": {},
                            "utility": True,
                            "security": True,
                            "error": None,
                        }
                    ),
                    encoding="utf-8",
                )
                records.append(
                    _result(
                        row,
                        manifest_hash=manifest.sha256,
                        utility=True,
                        raw_path=raw_path,
                    )
                )
            results_path.write_text(
                "".join(
                    json.dumps(record.__dict__)
                    + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )
            with patch.object(run_clean_controls, "execute_clean_control") as execute:
                status = run_clean_controls.run_controls(
                    manifest=manifest,
                    selection_output=selection,
                    per_domain=1,
                    split="dev",
                    results_path=results_path,
                    raw_root=raw_root,
                )
            selected = run_clean_controls.load_context_manifest(selection)

        self.assertEqual(0, status)
        execute.assert_not_called()
        self.assertEqual([1, 2, 3], [row.candidate_rank for row in selected.rows])

    def test_resume_rejects_missing_raw_trace_and_wrong_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            results_path = root / "results.jsonl"
            raw_root = root / "raw"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            record = _result(
                manifest.rows[0],
                manifest_hash=manifest.sha256,
                utility=True,
                raw_path=raw_root / "missing.json",
            )
            results_path.write_text(
                json.dumps(record.__dict__) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                run_clean_controls.CleanControlError, "does not exist"
            ):
                run_clean_controls.load_control_checkpoints(
                    results_path,
                    manifest=manifest,
                    split="dev",
                    raw_root=raw_root,
                )

            wrong_model = {**record.__dict__, "model": "google-gemini-3.1-flash-lite"}
            results_path.write_text(
                json.dumps(wrong_model) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                run_clean_controls.CleanControlError, "primary model"
            ):
                run_clean_controls.load_control_checkpoints(
                    results_path,
                    manifest=manifest,
                    split="dev",
                    raw_root=raw_root,
                )

    def test_same_split_checkpoint_plan_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            results_path = root / "results.jsonl"
            raw_root = root / "raw"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            record = _result(
                manifest.rows[0],
                manifest_hash="f" * 64,
                utility=True,
                raw_path=raw_root / "not-needed.json",
            )
            results_path.write_text(
                json.dumps(record.__dict__) + "\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                run_clean_controls.CleanControlError, "plan_sha256"
            ):
                run_clean_controls.load_control_checkpoints(
                    results_path,
                    manifest=manifest,
                    split="dev",
                    raw_root=raw_root,
                )

            # Rows from the other split remain logically separate and ignored.
            other_split = {**record.__dict__, "split": "holdout"}
            results_path.write_text(
                json.dumps(other_split) + "\n", encoding="utf-8"
            )
            self.assertEqual(
                {},
                run_clean_controls.load_control_checkpoints(
                    results_path,
                    manifest=manifest,
                    split="dev",
                    raw_root=raw_root,
                ),
            )

    def test_checkpoint_rejects_nondeterministic_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            results_path = root / "results.jsonl"
            raw_root = root / "raw"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            record = _result(
                manifest.rows[0],
                manifest_hash=manifest.sha256,
                utility=True,
                raw_path=raw_root / "not-needed.json",
            )
            changed = {**record.__dict__, "run_id": "unrelated-run"}
            results_path.write_text(
                json.dumps(changed) + "\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                run_clean_controls.CleanControlError, "deterministic"
            ):
                run_clean_controls.load_control_checkpoints(
                    results_path,
                    manifest=manifest,
                    split="dev",
                    raw_root=raw_root,
                )

    def test_excluded_overlap_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "source.tsv"
            _write_manifest(path, _rows())
            manifest = run_clean_controls.load_context_manifest(path)
            with self.assertRaisesRegex(
                run_clean_controls.CleanControlError, "overlaps excluded"
            ):
                run_clean_controls.run_controls(
                    manifest=manifest,
                    selection_output=path.with_name("selection.tsv"),
                    per_domain=1,
                    split="dev",
                    results_path=path.with_name("results.jsonl"),
                    raw_root=path.with_name("raw"),
                    excluded_keys={manifest.rows[0].key},
                )


class ExecutionBoundaryTests(unittest.TestCase):
    def test_clean_execution_uses_agentdojo_attack_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            row = manifest.rows[0]
            raw_root = root / "data" / "attack_calibration" / "clean_controls" / "raw"
            spec = run_clean_controls._clean_operation_spec(
                row,
                manifest_sha256=manifest.sha256,
                split="dev",
                results_path=root / "results.jsonl",
                raw_root=raw_root,
            )
            trace_path = spec.raw_trace_path

            def fake_benchmark(**_: object) -> dict[str, object]:
                trace_path.parent.mkdir(parents=True, exist_ok=True)
                trace_path.write_text(
                    json.dumps(
                        {
                            "suite_name": "workspace",
                            "pipeline_name": run_clean_controls.PRIMARY_PIPELINE_NAME,
                            "benchmark_version": run_clean_controls.BENCHMARK_VERSION,
                            "user_task_id": "user_task_0",
                            "injection_task_id": None,
                            "attack_type": None,
                            "messages": [{"role": "assistant", "content": []}],
                            "injections": {},
                            "error": None,
                            "utility": True,
                            "security": True,
                            "duration": 1.0,
                        }
                    ),
                    encoding="utf-8",
                )
                return {"utility_results": {("user_task_0", ""): True}}

            with (
                patch.object(run_clean_controls, "PROJECT_ROOT", root),
                patch.object(run_clean_controls, "get_suite", return_value=object()),
                patch.object(
                    run_clean_controls,
                    "get_google_primary_llm",
                    return_value=SimpleNamespace(
                        name=run_clean_controls.PRIMARY_PIPELINE_NAME
                    ),
                ),
                patch.object(
                    run_clean_controls,
                    "get_google_request_attempt_count",
                    return_value=0,
                ),
                patch.object(
                    run_clean_controls,
                    "benchmark_suite",
                    side_effect=fake_benchmark,
                ) as benchmark,
            ):
                result = run_clean_controls.execute_clean_control(
                    row,
                    manifest_sha256=manifest.sha256,
                    split="dev",
                    results_path=root / "results.jsonl",
                    raw_root=raw_root,
                )

        self.assertTrue(result.utility_success)
        self.assertFalse(result.attack_success)
        self.assertIsNone(benchmark.call_args.kwargs["attack"])
        self.assertEqual(
            raw_root
            / "dev"
            / "workspace"
            / "contexts"
            / spec.operation_id,
            benchmark.call_args.kwargs["logdir"],
        )

    def test_clean_raw_paths_are_distinct_for_distinct_contexts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            rows = _rows()
            rows[3] = (
                4,
                "workspace",
                "email_body",
                "workspace_vector_1",
                "user_task_0",
                "injection_task_1",
            )
            _write_manifest(source, rows)
            manifest = run_clean_controls.load_context_manifest(source)
            first = run_clean_controls._clean_operation_spec(
                manifest.rows[0],
                manifest_sha256=manifest.sha256,
                split="dev",
                results_path=root / "results.jsonl",
                raw_root=root / "raw",
            )
            second = run_clean_controls._clean_operation_spec(
                manifest.rows[3],
                manifest_sha256=manifest.sha256,
                split="dev",
                results_path=root / "results.jsonl",
                raw_root=root / "raw",
            )

        self.assertEqual(first.user_task_id, second.user_task_id)
        self.assertNotEqual(
            first.context_injection_task_id, second.context_injection_task_id
        )
        self.assertNotEqual(first.raw_trace_path, second.raw_trace_path)

    def test_cli_has_no_attack_result_input_and_enters_quota_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.tsv"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            argv = [
                "--input",
                str(source),
                "--selection-output",
                str(root / "selection.tsv"),
                "--results-path",
                str(root / "results.jsonl"),
                "--raw-root",
                str(root / "raw"),
                "--state-output",
                str(root / "state.json"),
                "--per-domain",
                "1",
                "--split",
                "dev",
                "--quota-date",
                "2026-08-07",
                "--dashboard-used",
                "0",
                "--dashboard-limit",
                "500",
                "--max-api-requests",
                "10",
            ]
            with (
                patch.object(run_clean_controls, "load_context_manifest", return_value=manifest),
                patch.object(run_clean_controls, "quota_guard_from_args", return_value=nullcontext()) as guard,
                patch.object(run_clean_controls, "run_controls", return_value=0),
            ):
                status = run_clean_controls.main(argv)

        self.assertEqual(0, status)
        guard.assert_called_once()
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                run_clean_controls.parse_args([*argv, "--attack-results", "x.jsonl"])


class PreflightOrderingTests(unittest.TestCase):
    def _argv(self, root: Path, source: Path, *, per_domain: int = 1) -> list[str]:
        return [
            "--input",
            str(source),
            "--selection-output",
            str(root / "selection.tsv"),
            "--per-domain",
            str(per_domain),
            "--split",
            "dev",
            "--results-path",
            str(root / "results.jsonl"),
            "--raw-root",
            str(root / "raw"),
            "--state-output",
            str(root / "state.json"),
            "--quota-date",
            "2026-08-07",
            "--dashboard-used",
            "0",
            "--dashboard-limit",
            "500",
            "--max-api-requests",
            "10",
        ]

    def test_invalid_count_and_insufficient_rows_never_enter_quota_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "candidate-pool.tsv"
            _write_manifest(source, _rows())
            for per_domain, message in ((0, "at least 1"), (3, "cannot supply")):
                with self.subTest(per_domain=per_domain):
                    with patch.object(run_clean_controls, "quota_guard_from_args") as guard:
                        with self.assertRaisesRegex(
                            run_clean_controls.CleanControlError, message
                        ):
                            run_clean_controls.main(
                                self._argv(root, source, per_domain=per_domain)
                            )
                    guard.assert_not_called()

            invalid_quota_argv = self._argv(root, source)
            max_requests_index = invalid_quota_argv.index("--max-api-requests") + 1
            invalid_quota_argv[max_requests_index] = "0"
            with patch.object(run_clean_controls, "quota_guard_from_args") as guard:
                with self.assertRaisesRegex(RuntimeError, "max_api_requests"):
                    run_clean_controls.main(invalid_quota_argv)
            guard.assert_not_called()

    def test_output_collision_and_corrupt_state_never_enter_quota_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "candidate-pool.tsv"
            _write_manifest(source, _rows())
            collision_argv = self._argv(root, source)
            results_index = collision_argv.index("--results-path") + 1
            collision_argv[results_index] = str(root / "selection.tsv")
            with patch.object(run_clean_controls, "quota_guard_from_args") as guard:
                with self.assertRaisesRegex(
                    run_clean_controls.CleanControlError, "must be distinct"
                ):
                    run_clean_controls.main(collision_argv)
            guard.assert_not_called()

            (root / "state.json").write_text("{}\n", encoding="utf-8")
            with patch.object(run_clean_controls, "quota_guard_from_args") as guard:
                with self.assertRaisesRegex(
                    run_clean_controls.CleanControlError, "invalid fields"
                ):
                    run_clean_controls.main(self._argv(root, source))
            guard.assert_not_called()

    def test_manifest_hash_mismatch_never_enters_quota_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "candidate-pool.tsv"
            _write_manifest(source, _rows())
            manifest = run_clean_controls.load_context_manifest(source)
            record = _result(
                manifest.rows[0],
                manifest_hash="f" * 64,
                utility=True,
                raw_path=root / "raw" / "unneeded.json",
            )
            (root / "results.jsonl").write_text(
                json.dumps(record.__dict__) + "\n", encoding="utf-8"
            )
            with patch.object(run_clean_controls, "quota_guard_from_args") as guard:
                with self.assertRaisesRegex(
                    run_clean_controls.CleanControlError, "plan_sha256"
                ):
                    run_clean_controls.main(self._argv(root, source))
            guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
