"""No-API tests for the Phase 6 baseline runner."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.experiments import run_baseline
from src.schemas import RunResult


class _FakeSuite:
    def __init__(self, domain: str) -> None:
        self.injection_tasks = {
            "injection_task_0": object(),
            "injection_task_1": object(),
        }
        self._vectors = {
            vector: ""
            for vectors in run_baseline.CHANNEL_VECTORS[domain].values()
            for vector in vectors
        }

    def get_injection_vector_defaults(self) -> dict[str, str]:
        return self._vectors


class RunBaselineTests(unittest.TestCase):
    def test_stratified_plan_has_one_case_per_payload_domain(self) -> None:
        payloads = run_baseline.load_corpus()

        def fake_suite(_: str, domain: str) -> _FakeSuite:
            return _FakeSuite(domain)

        with (
            patch.object(run_baseline, "get_suite", side_effect=fake_suite),
            patch.object(
                run_baseline,
                "eligible_user_tasks",
                side_effect=lambda _, __, vector: [f"user-for-{vector}"],
            ),
        ):
            cases = list(run_baseline.iter_cases(payloads))

        self.assertEqual(33, len(cases))
        self.assertEqual(
            {"workspace": 14, "banking": 14, "slack": 5},
            dict(Counter(domain for _, domain, _, _, _ in cases)),
        )

    def test_plan_manifest_contains_every_case(self) -> None:
        payload = run_baseline.load_corpus()[0]
        cases = [(payload, "workspace", "email_events_injection", "user_task_14", "injection_task_0")]
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "plan.tsv"
            run_baseline.write_plan(cases, path)
            lines = path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(
            "payload_id\tdomain\tchannel\tinjection_vector\tuser_task_id\tinjection_task_id",
            lines[0],
        )
        self.assertEqual(
            "direct-01\tworkspace\temail_body\temail_events_injection\tuser_task_14\tinjection_task_0",
            lines[1],
        )

    def test_completed_cases_reads_a_valid_checkpoint(self) -> None:
        record = RunResult(
            run_id="run-1",
            timestamp="2026-08-04T00:00:00+00:00",
            domain="workspace",
            user_task_id="user_task_14",
            injection_task_id="injection_task_0",
            payload_id="direct-01",
            channel="email_body",
            model="google-gemini-3.6-flash",
            defense="none",
            attack_success=False,
            tool_calls=[],
            notes="injection_vector=email_events_injection; raw_trace=data/baseline/raw/workspace/example.json",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "results.jsonl"
            path.write_text(json.dumps(record.__dict__) + "\n", encoding="utf-8")
            completed = run_baseline.completed_cases(path)

        self.assertEqual(
            {("direct-01", "workspace", "email_events_injection", "user_task_14", "injection_task_0")},
            completed,
        )

    def test_quota_detection_requires_a_google_429(self) -> None:
        self.assertTrue(run_baseline.is_quota_exhausted(Exception("429 RESOURCE_EXHAUSTED: quota exceeded")))
        self.assertFalse(run_baseline.is_quota_exhausted(Exception("500 internal server error")))

    def test_quota_error_stops_cleanly_without_losing_prior_checkpoints(self) -> None:
        class FakeClientError(Exception):
            pass

        payload = run_baseline.load_corpus()[0]
        case = (payload, "workspace", "email_events_injection", "user_task_14", "injection_task_0")
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = StringIO()
            with (
                patch.object(run_baseline, "load_corpus", return_value=[payload]),
                patch.object(run_baseline, "iter_cases", return_value=iter([case])),
                patch.object(run_baseline, "completed_cases", return_value=set()),
                patch.object(
                    run_baseline,
                    "execute_case",
                    side_effect=FakeClientError("429 RESOURCE_EXHAUSTED: quota exceeded"),
                ),
                patch.object(run_baseline, "ClientError", FakeClientError),
                redirect_stderr(output),
            ):
                status = run_baseline.main(["--max-runs", "1", "--results-path", str(Path(temporary_directory) / "results.jsonl")])

        self.assertEqual(2, status)
        self.assertIn("Stopping cleanly", output.getvalue())


if __name__ == "__main__":
    unittest.main()
