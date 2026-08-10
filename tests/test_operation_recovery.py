"""No-network interruption and cache-recovery tests for Phase 6A operations."""

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.experiments import calibrate_attacks, run_clean_controls
from src.experiments.build_attack_splits import AttackContext
from src.experiments.operation_journal import (
    OperationJournal,
    OperationJournalError,
    OperationSpec,
    append_jsonl_atomic,
    atomic_write_json,
    execute_journaled_agentdojo_benchmark,
)
from src.experiments.run_baseline import BenchmarkTraceError
from src.llm_providers.google_llm_factory import (
    FALLBACK_MODEL,
    PRIMARY_PIPELINE_NAME,
    RequestRateLimiter,
    observe_google_request_attempts,
)


ORIGINAL_TRACE_TIMESTAMP = "2026-08-07T01:02:03+00:00"


class RequestHarness:
    """Expose deterministic provider-attempt notifications to runner fakes."""

    def __init__(self) -> None:
        self.count = 0
        self._callback = None

    @contextmanager
    def observe(self, callback):  # type: ignore[no-untyped-def]
        self._callback = callback
        try:
            yield
        finally:
            self._callback = None

    def request(self, count: int = 1) -> None:
        if self._callback is None:
            raise AssertionError("request made outside the operation observer")
        for _ in range(count):
            self.count += 1
            self._callback(self.count)


def _target_kwargs(root: Path) -> dict[str, object]:
    return {
        "context": AttackContext(
            "workspace",
            "file_content",
            "workspace_vector_0",
            "user_task_0",
            "injection_task_0",
        ),
        "attempt_id": "builtin:direct:workspace",
        "source_family": "direct",
        "source_category": "agentdojo_builtin",
        "seed_id": "builtin:direct",
        "parent_attempt_id": None,
        "mutation_round": 0,
        "attacker_model": "agentdojo-builtin",
        "generator_request_attempts": 0,
        "attack_name": calibrate_attacks._safe_attack_name(
            "calibration_builtin", "direct", "workspace_vector_0"
        ),
        "results_path": root / "target" / "attempts.jsonl",
        "raw_root": root / "target" / "raw",
    }


def _target_spec(kwargs: dict[str, object]) -> OperationSpec:
    return calibrate_attacks._target_operation_spec(**kwargs)  # type: ignore[arg-type]


def _clean_values(root: Path) -> tuple[run_clean_controls.RankedContext, dict[str, object]]:
    row = run_clean_controls.RankedContext(
        1,
        AttackContext(
            "workspace",
            "file_content",
            "workspace_vector_0",
            "user_task_0",
            "injection_task_0",
        ),
    )
    kwargs: dict[str, object] = {
        "manifest_sha256": "a" * 64,
        "split": "dev",
        "results_path": root / "clean" / "results.jsonl",
        "raw_root": root / "clean" / "raw",
    }
    return row, kwargs


def _clean_spec(
    row: run_clean_controls.RankedContext, kwargs: dict[str, object]
) -> OperationSpec:
    return run_clean_controls._clean_operation_spec(row, **kwargs)  # type: ignore[arg-type]


def _trace(
    spec: OperationSpec,
    *,
    error: str | None = None,
    assistant_messages: int = 2,
    overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    injections = (
        {}
        if spec.expected_raw_injection_vector is None
        else {spec.expected_raw_injection_vector: "rendered synthetic goal"}
    )
    value: dict[str, object] = {
        "suite_name": spec.suite_name,
        "pipeline_name": spec.pipeline_name,
        "benchmark_version": spec.benchmark_version,
        "user_task_id": spec.user_task_id,
        "injection_task_id": spec.raw_injection_task_id,
        "attack_type": spec.attack_name,
        "injections": injections,
        "messages": [
            {"role": "assistant", "content": []}
            for _ in range(assistant_messages)
        ],
        "error": error,
        "utility": True,
        "security": False if spec.attack_name is not None else True,
        "duration": 1.25,
        "evaluation_timestamp": ORIGINAL_TRACE_TIMESTAMP,
    }
    value.update(overrides or {})
    return value


def _write_trace(spec: OperationSpec, **kwargs: object) -> dict[str, object]:
    value = _trace(spec, **kwargs)  # type: ignore[arg-type]
    spec.raw_trace_path.parent.mkdir(parents=True, exist_ok=True)
    spec.raw_trace_path.write_text(json.dumps(value), encoding="utf-8")
    return value


def _target_results(kwargs: dict[str, object]) -> dict[str, object]:
    context = kwargs["context"]
    assert isinstance(context, AttackContext)
    key = (context.user_task_id, context.injection_task_id)
    return {
        "security_results": {key: False},
        "utility_results": {key: True},
    }


def _clean_results() -> dict[str, object]:
    return {"utility_results": {("user_task_0", ""): True}}


@contextmanager
def _runner_patches(module, harness: RequestHarness):  # type: ignore[no-untyped-def]
    with ExitStack() as stack:
        stack.enter_context(patch.object(module, "get_suite", return_value=object()))
        stack.enter_context(
            patch.object(
                module,
                "get_google_primary_llm",
                return_value=SimpleNamespace(name=PRIMARY_PIPELINE_NAME),
            )
        )
        stack.enter_context(
            patch.object(
                module,
                "get_google_request_attempt_count",
                side_effect=lambda: harness.count,
            )
        )
        stack.enter_context(
            patch.object(module, "observe_google_request_attempts", new=harness.observe)
        )
        yield


class ProviderObserverTests(unittest.TestCase):
    def test_provider_notifies_after_every_request_start(self) -> None:
        observed: list[int] = []
        limiter = RequestRateLimiter(0, clock=lambda: 0.0, sleeper=lambda _: None)
        with observe_google_request_attempts(observed.append):
            limiter.wait_before_request()
            limiter.wait_before_request()
        self.assertEqual([1, 2], observed)


class SharedPersistenceTests(unittest.TestCase):
    def test_unexpected_benchmark_exception_is_journaled_with_traceback_and_preserves_raw(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            spec = OperationSpec(
                operation_id="synthetic-target",
                operation_kind="calibration_target",
                domain="workspace",
                suite_name="workspace",
                model=PRIMARY_PIPELINE_NAME.split(" [", 1)[0],
                pipeline_name=PRIMARY_PIPELINE_NAME,
                benchmark_version="v1.2.2",
                user_task_id="user_task_0",
                context_injection_task_id="injection_task_0",
                raw_injection_task_id="injection_task_0",
                channel="file_content",
                injection_vector="workspace_vector_0",
                attack_id="synthetic-target",
                attack_name="synthetic_attack",
                expected_raw_injection_vector="workspace_vector_0",
                operation_metadata={"test": True},
                raw_trace_path=root / "raw" / "partial.json",
                index_path=root / "attempts.jsonl",
            )
            journal = OperationJournal.open(root / "operations", spec)
            harness = RequestHarness()

            def fail_after_partial_raw() -> dict[str, object]:
                harness.request()
                spec.raw_trace_path.write_text(
                    json.dumps({"partial": "preserve me"}), encoding="utf-8"
                )
                raise RuntimeError("synthetic non-quota target failure")

            with self.assertRaisesRegex(RuntimeError, "synthetic non-quota"):
                execute_journaled_agentdojo_benchmark(
                    journal=journal,
                    force_rerun=False,
                    benchmark=fail_after_partial_raw,
                    observe_attempts=harness.observe,
                    get_attempt_count=lambda: harness.count,
                    benchmark_kwargs={},
                )

            state = json.loads(journal.path.read_text(encoding="utf-8"))
            self.assertEqual("failed", state["status"])
            self.assertEqual(1, state["request_attempts"])
            diagnostic = state["failures"][-1]["error"]
            self.assertIn("exception_type=builtins.RuntimeError", diagnostic)
            self.assertIn("message=synthetic non-quota target failure", diagnostic)
            self.assertIn("Traceback (most recent call last)", diagnostic)
            self.assertEqual(
                {"partial": "preserve me"},
                json.loads(spec.raw_trace_path.read_text(encoding="utf-8")),
            )

    def test_atomic_json_and_jsonl_helpers_preserve_existing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            state_path = root / "state.json"
            self.assertTrue(atomic_write_json(state_path, {"state": "ready"}))
            self.assertFalse(atomic_write_json(state_path, {"state": "ready"}))
            with self.assertRaises(OperationJournalError):
                atomic_write_json(state_path, {"state": "changed"}, refuse_changed=True)

            checkpoint = root / "checkpoint.jsonl"
            append_jsonl_atomic(checkpoint, {"id": "one"})
            append_jsonl_atomic(checkpoint, {"id": "two"})

            self.assertEqual(
                [{"id": "one"}, {"id": "two"}],
                [json.loads(line) for line in checkpoint.read_text(encoding="utf-8").splitlines()],
            )

    def test_journaled_zero_attempt_is_not_reclassified_from_partial_raw(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            spec = _target_spec(_target_kwargs(root))
            journal = OperationJournal.open(root / "operations", spec)
            attempt_index, _ = journal.begin_api_attempt(force_rerun=False)
            journal.record_failure("failed before provider", attempt_index=attempt_index)

            journal.ensure_nonzero_inferred_attempts({"messages": []})

            state = json.loads(journal.path.read_text(encoding="utf-8"))
        self.assertEqual(0, state["request_attempts"])
        self.assertEqual("provider_observer", state["request_count_source"])

    def test_prejournal_raw_cache_still_infers_conservative_attempt_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            spec = _target_spec(_target_kwargs(root))
            journal = OperationJournal.open(root / "operations", spec)

            journal.ensure_nonzero_inferred_attempts(
                {
                    "messages": [
                        {"role": "assistant"},
                        {"role": "assistant"},
                    ]
                }
            )

            state = json.loads(journal.path.read_text(encoding="utf-8"))
        self.assertEqual(2, state["request_attempts"])
        self.assertEqual("raw_trace_inferred_lower_bound", state["request_count_source"])


class TargetRecoveryTests(unittest.TestCase):
    def test_target_trace_layout_does_not_repeat_domain_in_log_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            spec = _target_spec(_target_kwargs(root))

        self.assertEqual(
            (
                PRIMARY_PIPELINE_NAME,
                "workspace",
                "user_task_0",
            ),
            spec.raw_trace_path.relative_to(root / "target" / "raw").parts[:3],
        )

    def test_target_creates_exact_raw_trace_parent_before_benchmark(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            harness = RequestHarness()

            def benchmark_once(**_: object) -> dict[str, object]:
                self.assertTrue(spec.raw_trace_path.parent.is_dir())
                self.assertEqual(
                    spec.raw_trace_path.parents[4],
                    _["logdir"],
                )
                harness.request(1)
                _write_trace(spec)
                return _target_results(kwargs)

            with (
                _runner_patches(calibrate_attacks, harness),
                patch.object(
                    calibrate_attacks, "benchmark_suite", side_effect=benchmark_once
                ),
            ):
                record = calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

        self.assertEqual(spec.operation_id, record.attempt_id)
        self.assertEqual(1, record.target_request_attempts)

    def test_raw_only_recovery_uses_original_identity_timestamp_and_nonzero_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            _write_trace(spec, assistant_messages=3)
            with (
                patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
                patch.object(calibrate_attacks, "benchmark_suite") as benchmark,
            ):
                record = calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

        llm.assert_not_called()
        benchmark.assert_not_called()
        self.assertEqual(spec.operation_id, record.attempt_id)
        self.assertEqual(ORIGINAL_TRACE_TIMESTAMP, record.timestamp)
        self.assertEqual(3, record.target_request_attempts)

    def test_raw_write_before_completion_sidecar_recovers_without_duplicate_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            harness = RequestHarness()

            def benchmark_once(**_: object) -> dict[str, object]:
                harness.request(4)
                _write_trace(spec)
                return _target_results(kwargs)

            with (
                _runner_patches(calibrate_attacks, harness),
                patch.object(
                    calibrate_attacks, "benchmark_suite", side_effect=benchmark_once
                ),
                patch.object(
                    OperationJournal, "mark_api_returned", side_effect=KeyboardInterrupt
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

            journal_path = next((kwargs["results_path"].parent / "operations").glob("*.json"))  # type: ignore[union-attr]
            pending = json.loads(journal_path.read_text(encoding="utf-8"))
            original_timestamp = pending["timestamp"]
            self.assertEqual("running", pending["status"])
            self.assertEqual(4, pending["request_attempts"])
            self.assertEqual(spec.operation_id, pending["operation_id"])
            self.assertEqual("calibration_target", pending["operation_kind"])
            self.assertEqual(spec.domain, pending["domain"])
            self.assertEqual(spec.suite_name, pending["suite_name"])
            self.assertEqual(spec.model, pending["model"])
            self.assertEqual(spec.pipeline_name, pending["pipeline_name"])
            self.assertEqual(spec.benchmark_version, pending["benchmark_version"])
            self.assertEqual(spec.user_task_id, pending["user_task_id"])
            self.assertEqual(
                spec.context_injection_task_id,
                pending["context_injection_task_id"],
            )
            self.assertEqual(spec.channel, pending["channel"])
            self.assertEqual(spec.injection_vector, pending["injection_vector"])
            self.assertEqual(spec.attack_name, pending["attack_name"])
            self.assertEqual(
                str(spec.raw_trace_path.resolve()), pending["raw_trace_path"]
            )

            with (
                patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
                patch.object(calibrate_attacks, "benchmark_suite") as benchmark,
            ):
                record = calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

            lines = kwargs["results_path"].read_text(encoding="utf-8").splitlines()  # type: ignore[union-attr]
        llm.assert_not_called()
        benchmark.assert_not_called()
        self.assertEqual(1, len(lines))
        self.assertEqual(original_timestamp, record.timestamp)
        self.assertEqual(4, record.target_request_attempts)

    def test_running_target_with_started_request_and_no_raw_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            journal = OperationJournal.open(
                kwargs["results_path"].parent / "operations", spec  # type: ignore[union-attr]
            )
            attempt_index, base_count = journal.begin_api_attempt(force_rerun=False)
            journal.observe_request_count(
                attempt_index=attempt_index,
                base_count=base_count,
                process_count_before=0,
                process_count_now=1,
            )

            with (
                patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
                patch.object(calibrate_attacks, "benchmark_suite") as benchmark,
                self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError,
                    "refusing to repeat ambiguous API work",
                ),
            ):
                calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

        llm.assert_not_called()
        benchmark.assert_not_called()

    def test_api_returned_target_without_raw_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            journal = OperationJournal.open(
                kwargs["results_path"].parent / "operations", spec  # type: ignore[union-attr]
            )
            attempt_index, base_count = journal.begin_api_attempt(force_rerun=False)
            journal.observe_request_count(
                attempt_index=attempt_index,
                base_count=base_count,
                process_count_before=0,
                process_count_now=1,
            )
            journal.mark_api_returned(attempt_index=attempt_index)

            with (
                patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
                patch.object(calibrate_attacks, "benchmark_suite") as benchmark,
                self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError,
                    "missing raw evidence in state api_returned",
                ),
            ):
                calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

        llm.assert_not_called()
        benchmark.assert_not_called()

    def test_completed_sidecar_before_jsonl_recovers_exact_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            harness = RequestHarness()

            def benchmark_once(**_: object) -> dict[str, object]:
                harness.request(2)
                _write_trace(spec)
                return _target_results(kwargs)

            with (
                _runner_patches(calibrate_attacks, harness),
                patch.object(
                    calibrate_attacks, "benchmark_suite", side_effect=benchmark_once
                ),
                patch.object(
                    calibrate_attacks, "append_jsonl_once", side_effect=KeyboardInterrupt
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

            journal_path = next((kwargs["results_path"].parent / "operations").glob("*.json"))  # type: ignore[union-attr]
            pending = json.loads(journal_path.read_text(encoding="utf-8"))
            self.assertEqual("completed", pending["status"])
            stored = pending["result_record"]

            with (
                patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
                patch.object(calibrate_attacks, "benchmark_suite") as benchmark,
            ):
                recovered = calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

        llm.assert_not_called()
        benchmark.assert_not_called()
        self.assertEqual(stored, recovered.__dict__)
        self.assertEqual(2, recovered.target_request_attempts)

    def test_api_response_without_raw_preserves_count_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            harness = RequestHarness()

            def missing_raw(**_: object) -> dict[str, object]:
                harness.request(2)
                return _target_results(kwargs)

            with (
                _runner_patches(calibrate_attacks, harness),
                patch.object(calibrate_attacks, "benchmark_suite", side_effect=missing_raw),
                self.assertRaisesRegex(BenchmarkTraceError, "without writing"),
            ):
                calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

            def completed_retry(**_: object) -> dict[str, object]:
                harness.request(1)
                _write_trace(spec)
                return _target_results(kwargs)

            with (
                _runner_patches(calibrate_attacks, harness),
                patch.object(
                    calibrate_attacks, "benchmark_suite", side_effect=completed_retry
                ),
            ):
                record = calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

        self.assertEqual(3, record.target_request_attempts)

    def test_errored_cache_is_logged_and_exact_case_is_force_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            harness = RequestHarness()
            calls: list[bool] = []

            def errored(**call: object) -> dict[str, object]:
                calls.append(bool(call["force_rerun"]))
                harness.request(2)
                _write_trace(spec, error="synthetic 503 skip")
                return _target_results(kwargs)

            with (
                _runner_patches(calibrate_attacks, harness),
                patch.object(calibrate_attacks, "benchmark_suite", side_effect=errored),
                self.assertRaisesRegex(BenchmarkTraceError, "errored/skipped"),
            ):
                calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

            def successful(**call: object) -> dict[str, object]:
                calls.append(bool(call["force_rerun"]))
                harness.request(1)
                _write_trace(spec)
                return _target_results(kwargs)

            with (
                _runner_patches(calibrate_attacks, harness),
                patch.object(
                    calibrate_attacks, "benchmark_suite", side_effect=successful
                ),
            ):
                record = calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]

            journal_path = next((kwargs["results_path"].parent / "operations").glob("*.json"))  # type: ignore[union-attr]
            journal = json.loads(journal_path.read_text(encoding="utf-8"))

        self.assertEqual([False, True], calls)
        self.assertEqual(3, record.target_request_attempts)
        self.assertEqual(1, len(journal["failures"]))
        self.assertIn("synthetic 503 skip", journal["failures"][0]["error"])

    def test_target_raw_provenance_is_validated_before_reuse(self) -> None:
        cases = {
            "pipeline_name": "wrong-pipeline",
            "fallback_pipeline_name": f"google-{FALLBACK_MODEL} [fallback]",
            "suite_name": "banking",
            "benchmark_version": "wrong-version",
            "user_task_id": "user_task_wrong",
            "injection_task_id": "injection_task_wrong",
            "attack_type": "wrong-attack",
            "injections": {"wrong_vector": "rendered"},
        }
        for field, value in cases.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                kwargs = _target_kwargs(root)
                spec = _target_spec(kwargs)
                trace_field = "pipeline_name" if field == "fallback_pipeline_name" else field
                _write_trace(spec, overrides={trace_field: value})
                with (
                    patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
                    self.assertRaises(calibrate_attacks.CalibrationError),
                ):
                    calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]
                llm.assert_not_called()

    def test_indexed_target_checkpoint_revalidates_raw_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            value = _write_trace(spec)
            calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]
            context = kwargs["context"]
            assert isinstance(context, AttackContext)
            manifest = run_clean_controls.ContextManifest(
                root / "dev_manifest.tsv",
                "a" * 64,
                (run_clean_controls.RankedContext(1, context),),
            )
            loaded = calibrate_attacks.load_calibration_attempts(
                kwargs["results_path"],  # type: ignore[arg-type]
                manifest=manifest,
                raw_root=kwargs["raw_root"],  # type: ignore[arg-type]
            )
            self.assertEqual({spec.operation_id}, set(loaded))

            value["benchmark_version"] = "changed-version"
            spec.raw_trace_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(calibrate_attacks.CalibrationError):
                calibrate_attacks.load_calibration_attempts(
                    kwargs["results_path"],  # type: ignore[arg-type]
                    manifest=manifest,
                    raw_root=kwargs["raw_root"],  # type: ignore[arg-type]
                )

    def test_sidecar_rejects_changed_context_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            kwargs = _target_kwargs(root)
            spec = _target_spec(kwargs)
            OperationJournal.open(root / "target" / "operations", spec)
            original = kwargs["context"]
            assert isinstance(original, AttackContext)
            kwargs["context"] = AttackContext(
                original.domain,
                "email_body",
                original.injection_vector,
                original.user_task_id,
                original.injection_task_id,
            )
            with self.assertRaises(OperationJournalError):
                calibrate_attacks.execute_target_attempt(**kwargs)  # type: ignore[arg-type]


class CleanRecoveryTests(unittest.TestCase):
    def test_clean_raw_only_recovery_uses_stable_id_timestamp_and_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            row, kwargs = _clean_values(root)
            spec = _clean_spec(row, kwargs)
            _write_trace(spec, assistant_messages=3)
            with (
                patch.object(run_clean_controls, "get_google_primary_llm") as llm,
                patch.object(run_clean_controls, "benchmark_suite") as benchmark,
            ):
                record = run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]

        llm.assert_not_called()
        benchmark.assert_not_called()
        self.assertEqual(spec.operation_id, record.run_id)
        self.assertEqual(ORIGINAL_TRACE_TIMESTAMP, record.timestamp)
        self.assertEqual("3", run_clean_controls._note_value(record.notes, "api_request_attempts"))

    def test_clean_raw_write_before_sidecar_and_sidecar_before_index_both_recover(self) -> None:
        for boundary in ("raw", "sidecar"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                row, kwargs = _clean_values(root)
                spec = _clean_spec(row, kwargs)
                harness = RequestHarness()

                def benchmark_once(**_: object) -> dict[str, object]:
                    harness.request(2)
                    _write_trace(spec)
                    return _clean_results()

                boundary_patch = (
                    patch.object(
                        OperationJournal,
                        "mark_api_returned",
                        side_effect=KeyboardInterrupt,
                    )
                    if boundary == "raw"
                    else patch.object(
                        run_clean_controls,
                        "append_jsonl_once",
                        side_effect=KeyboardInterrupt,
                    )
                )
                with (
                    _runner_patches(run_clean_controls, harness),
                    patch.object(
                        run_clean_controls,
                        "benchmark_suite",
                        side_effect=benchmark_once,
                    ),
                    boundary_patch,
                    self.assertRaises(KeyboardInterrupt),
                ):
                    run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]

                journal_files = list(
                    (kwargs["results_path"].parent / "operations").glob("*.json")  # type: ignore[union-attr]
                )
                self.assertEqual(1, len(journal_files))
                operation_timestamp = json.loads(
                    journal_files[0].read_text(encoding="utf-8")
                )["timestamp"]

                with (
                    patch.object(run_clean_controls, "get_google_primary_llm") as llm,
                    patch.object(run_clean_controls, "benchmark_suite") as benchmark,
                ):
                    record = run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]

                llm.assert_not_called()
                benchmark.assert_not_called()
                self.assertEqual(operation_timestamp, record.timestamp)
                self.assertEqual(
                    "2",
                    run_clean_controls._note_value(
                        record.notes, "api_request_attempts"
                    ),
                )
                self.assertEqual(
                    1,
                    len(kwargs["results_path"].read_text(encoding="utf-8").splitlines()),  # type: ignore[union-attr]
                )

    def test_clean_missing_or_incomplete_cache_can_retry_without_losing_counts(self) -> None:
        for failure_kind in ("missing", "errored", "incomplete"):
            with self.subTest(failure_kind=failure_kind), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                row, kwargs = _clean_values(root)
                spec = _clean_spec(row, kwargs)
                harness = RequestHarness()
                calls: list[bool] = []

                def first(**call: object) -> dict[str, object]:
                    calls.append(bool(call["force_rerun"]))
                    harness.request(2)
                    if failure_kind == "errored":
                        _write_trace(spec, error="synthetic clean skip")
                    elif failure_kind == "incomplete":
                        _write_trace(
                            spec,
                            overrides={"utility": None, "security": None},
                        )
                    return _clean_results()

                with (
                    _runner_patches(run_clean_controls, harness),
                    patch.object(run_clean_controls, "benchmark_suite", side_effect=first),
                    self.assertRaises(BenchmarkTraceError),
                ):
                    run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]

                def second(**call: object) -> dict[str, object]:
                    calls.append(bool(call["force_rerun"]))
                    harness.request(1)
                    _write_trace(spec)
                    return _clean_results()

                with (
                    _runner_patches(run_clean_controls, harness),
                    patch.object(
                        run_clean_controls, "benchmark_suite", side_effect=second
                    ),
                ):
                    record = run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]

                self.assertEqual(
                    "3",
                    run_clean_controls._note_value(
                        record.notes, "api_request_attempts"
                    ),
                )
                self.assertEqual(failure_kind in {"errored", "incomplete"}, calls[1])

    def test_clean_raw_provenance_is_validated_before_reuse(self) -> None:
        cases = {
            "pipeline_name": "wrong-pipeline",
            "fallback_pipeline_name": f"google-{FALLBACK_MODEL} [fallback]",
            "suite_name": "banking",
            "benchmark_version": "wrong-version",
            "user_task_id": "user_task_wrong",
            "injection_task_id": "injection_task_wrong",
            "attack_type": "unexpected-attack",
            "injections": {"unexpected": "injection"},
        }
        for field, value in cases.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                row, kwargs = _clean_values(root)
                spec = _clean_spec(row, kwargs)
                trace_field = "pipeline_name" if field == "fallback_pipeline_name" else field
                _write_trace(spec, overrides={trace_field: value})
                with (
                    patch.object(run_clean_controls, "get_google_primary_llm") as llm,
                    self.assertRaises(run_clean_controls.CleanControlError),
                ):
                    run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]
                llm.assert_not_called()
                self.assertFalse(kwargs["results_path"].exists())  # type: ignore[union-attr]

    def test_native_utility_mismatch_is_rejected_before_first_index_append(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            row, kwargs = _clean_values(root)
            spec = _clean_spec(row, kwargs)
            harness = RequestHarness()

            def benchmark_once(**_: object) -> dict[str, object]:
                harness.request()
                _write_trace(spec, overrides={"utility": False})
                return _clean_results()

            with (
                _runner_patches(run_clean_controls, harness),
                patch.object(
                    run_clean_controls,
                    "benchmark_suite",
                    side_effect=benchmark_once,
                ),
                self.assertRaises(BenchmarkTraceError),
            ):
                run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]

            self.assertFalse(kwargs["results_path"].exists())  # type: ignore[union-attr]

    def test_clean_plan_context_mismatch_is_rejected_before_index_append(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            row, kwargs = _clean_values(root)
            spec = _clean_spec(row, kwargs)
            journal = OperationJournal.open(
                kwargs["results_path"].parent / "operations", spec  # type: ignore[union-attr]
            )
            raw_trace = _trace(spec)
            changed_rank = run_clean_controls.RankedContext(
                row.candidate_rank + 1, row.context
            )

            with self.assertRaisesRegex(
                run_clean_controls.CleanControlError, "provenance|metadata"
            ):
                run_clean_controls._clean_record_from_raw(
                    journal,
                    raw_trace,
                    row=changed_rank,
                    manifest_sha256=str(kwargs["manifest_sha256"]),
                    split=str(kwargs["split"]),
                )

            self.assertFalse(kwargs["results_path"].exists())  # type: ignore[union-attr]

    def test_indexed_clean_checkpoint_revalidates_raw_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            row, kwargs = _clean_values(root)
            spec = _clean_spec(row, kwargs)
            value = _write_trace(spec)
            run_clean_controls.execute_clean_control(row, **kwargs)  # type: ignore[arg-type]
            manifest = run_clean_controls.ContextManifest(
                root / "candidate.tsv",
                str(kwargs["manifest_sha256"]),
                (row,),
            )
            loaded = run_clean_controls.load_control_checkpoints(
                kwargs["results_path"],  # type: ignore[arg-type]
                manifest=manifest,
                split="dev",
                raw_root=kwargs["raw_root"],  # type: ignore[arg-type]
            )
            self.assertEqual({row.key}, set(loaded))

            value["pipeline_name"] = "changed-pipeline"
            spec.raw_trace_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(run_clean_controls.CleanControlError):
                run_clean_controls.load_control_checkpoints(
                    kwargs["results_path"],  # type: ignore[arg-type]
                    manifest=manifest,
                    split="dev",
                    raw_root=kwargs["raw_root"],  # type: ignore[arg-type]
                )


if __name__ == "__main__":
    unittest.main()
