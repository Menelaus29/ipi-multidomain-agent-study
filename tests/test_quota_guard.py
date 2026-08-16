"""No-network tests for the Phase 6A quota guard."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from google.genai import types as genai_types
from google.genai.errors import ClientError

from src.experiments.quota_guard import (
    ConcurrentQuotaRunError,
    MultiQuotaGuard,
    QuotaGuard,
    QuotaGuardError,
    QuotaValidationError,
    add_quota_arguments,
    pacific_quota_date,
    quota_guard_from_args,
)
from src.llm_providers.google_llm_factory import (
    GEMMA4_26B_MODEL,
    GEMMA4_26B_RPD_LIMIT,
    PRIMARY_MODEL,
    Gemini3LLM,
    RequestBudgetExceeded,
    RequestRateLimiter,
)


FIXED_NOW = datetime(2026, 8, 6, 12, 0, tzinfo=timezone.utc)
FIXED_DATE = "2026-08-06"


class _AttemptState:
    def __init__(self) -> None:
        self.count = 0
        self.configured: list[int | None] = []

    def get(self) -> int:
        return self.count

    def configure(self, limit: int | None) -> None:
        self.configured.append(limit)


class _FakeTime:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _FakeModels:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def generate_content(self, **_: object) -> object:
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _FakeClient:
    def __init__(self, outcomes: list[object]) -> None:
        self.models = _FakeModels(outcomes)


def _rpm_error() -> ClientError:
    return ClientError(
        429,
        {
            "error": {
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {
                        "quotaId": (
                            "GenerateRequestsPerMinutePerProjectPerModel-FreeTier"
                        )
                    }
                ],
            }
        },
    )


def _records(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


class PacificDateTests(unittest.TestCase):
    def test_midnight_boundary_uses_standard_time(self) -> None:
        self.assertEqual(
            "2026-01-14",
            pacific_quota_date(
                datetime(2026, 1, 15, 7, 59, tzinfo=timezone.utc)
            ),
        )
        self.assertEqual(
            "2026-01-15",
            pacific_quota_date(
                datetime(2026, 1, 15, 8, 0, tzinfo=timezone.utc)
            ),
        )

    def test_midnight_boundary_uses_daylight_saving_time(self) -> None:
        self.assertEqual(
            "2026-07-14",
            pacific_quota_date(
                datetime(2026, 7, 15, 6, 59, tzinfo=timezone.utc)
            ),
        )
        self.assertEqual(
            "2026-07-15",
            pacific_quota_date(
                datetime(2026, 7, 15, 7, 0, tzinfo=timezone.utc)
            ),
        )


class QuotaArgumentTests(unittest.TestCase):
    def test_api_only_parser_requires_all_arguments(self) -> None:
        parser = argparse.ArgumentParser(exit_on_error=False)
        add_quota_arguments(parser)
        with self.assertRaises(argparse.ArgumentError):
            parser.parse_args([])

    def test_mixed_mode_parser_defers_requirement_to_guard(self) -> None:
        parser = argparse.ArgumentParser(exit_on_error=False)
        add_quota_arguments(parser, required=False)
        args = parser.parse_args([])
        with self.assertRaisesRegex(QuotaValidationError, "--quota-date"):
            quota_guard_from_args(args)


class QuotaGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.ledger = Path(self.temporary_directory.name) / "quota_ledger.jsonl"
        self.attempts = _AttemptState()

    def guard(
        self,
        *,
        quota_date: str = FIXED_DATE,
        dashboard_used: int = 0,
        dashboard_limit: int = 500,
        max_api_requests: int = 100,
        quota_key: str = PRIMARY_MODEL,
        study_rpd_limit: int = 500,
        output: StringIO | None = None,
    ) -> QuotaGuard:
        return QuotaGuard(
            quota_date=quota_date,
            dashboard_used=dashboard_used,
            dashboard_limit=dashboard_limit,
            max_api_requests=max_api_requests,
            quota_key=quota_key,
            study_rpd_limit=study_rpd_limit,
            ledger_path=self.ledger,
            now_utc=lambda: FIXED_NOW,
            configure_attempt_limit=self.attempts.configure,
            get_attempt_count=self.attempts.get,
            output=output or StringIO(),
        )

    def test_rejects_stale_and_noncanonical_dates(self) -> None:
        for quota_date in ("2026-08-05", "2026-8-6", "not-a-date"):
            with self.subTest(quota_date=quota_date):
                with self.assertRaises(QuotaValidationError):
                    with self.guard(quota_date=quota_date):
                        pass

    def test_rejects_invalid_counts_and_dashboard_relationship(self) -> None:
        invalid = (
            {"dashboard_used": -1},
            {"dashboard_limit": -1},
            {"max_api_requests": -1},
            {"dashboard_limit": 0},
            {"max_api_requests": 0},
            {"dashboard_used": 101, "dashboard_limit": 100},
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(QuotaValidationError):
                    with self.guard(**values):
                        pass
                self.assertFalse(self.ledger.exists())

    def test_rejects_nonpositive_safe_budget(self) -> None:
        with self.assertRaisesRegex(QuotaValidationError, "No positive"):
            with self.guard(dashboard_used=75, dashboard_limit=100):
                pass

    def test_caps_at_study_limit_and_prints_requested_and_effective_values(
        self,
    ) -> None:
        output = StringIO()
        with self.guard(
            dashboard_used=100,
            dashboard_limit=1000,
            max_api_requests=450,
            output=output,
        ) as guard:
            self.assertEqual(500, guard.effective_limit)
            self.assertEqual(375, guard.effective_cap)

        self.assertIn("requested=450", output.getvalue())
        self.assertIn("effective=375", output.getvalue())
        self.assertEqual([375], self.attempts.configured)

    def test_honors_a_lower_displayed_limit(self) -> None:
        with self.guard(
            dashboard_used=10,
            dashboard_limit=100,
            max_api_requests=200,
        ) as guard:
            self.assertEqual(100, guard.effective_limit)
            self.assertEqual(65, guard.effective_cap)

    def test_reserves_before_body_and_reconciles_actual_attempts(self) -> None:
        with self.guard(dashboard_used=50, max_api_requests=100) as guard:
            reserved = _records(self.ledger)
            self.assertEqual(1, len(reserved))
            self.assertEqual(100, reserved[0]["reserved_attempts"])
            self.assertIsNone(reserved[0]["actual_attempts"])
            self.attempts.count += 7
            self.assertEqual(100, guard.effective_cap)

        reconciled = _records(self.ledger)
        self.assertEqual(7, reconciled[0]["actual_attempts"])
        self.assertIsNotNone(reconciled[0]["reconciled_at"])

    def test_ledger_high_water_wins_when_dashboard_is_lower(self) -> None:
        with self.guard(dashboard_used=100, max_api_requests=100):
            self.attempts.count += 20

        with self.guard(
            dashboard_used=80,
            max_api_requests=500,
        ) as second:
            self.assertEqual(120, second.known_used)
            self.assertEqual(355, second.effective_cap)

    def test_interruption_retains_reservation_until_fresh_observation(self) -> None:
        with self.assertRaises(KeyboardInterrupt):
            with self.guard(dashboard_used=30, max_api_requests=100):
                self.attempts.count += 7
                raise KeyboardInterrupt

        interrupted = _records(self.ledger)
        self.assertIsNone(interrupted[0]["actual_attempts"])
        self.assertIsNone(interrupted[0]["interruption_resolved_at"])

        with self.guard(
            dashboard_used=37,
            max_api_requests=500,
        ) as resumed:
            self.assertEqual(37, resumed.known_used)
            self.assertEqual(438, resumed.effective_cap)

        resolved = _records(self.ledger)
        self.assertIsNotNone(resolved[0]["interruption_resolved_at"])
        self.assertEqual(37, resolved[0]["resolution_dashboard_used"])

    def test_zero_attempt_exception_reconciles_without_stranding_reservation(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "validation failed"):
            with self.guard(dashboard_used=30, max_api_requests=100):
                raise RuntimeError("validation failed")

        record = _records(self.ledger)[0]
        self.assertEqual(0, record["actual_attempts"])
        self.assertIsNotNone(record["reconciled_at"])
        self.assertIsNone(record["interruption_resolved_at"])

    def test_exception_after_attempt_retains_conservative_reservation(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            with self.guard(dashboard_used=30, max_api_requests=100):
                self.attempts.count += 1
                raise RuntimeError("interrupted")

        record = _records(self.ledger)[0]
        self.assertIsNone(record["actual_attempts"])
        self.assertIsNone(record["reconciled_at"])

    def test_lock_contention_rejects_a_second_process_session(self) -> None:
        first = self.guard(max_api_requests=50)
        with first:
            with self.assertRaises(ConcurrentQuotaRunError):
                with self.guard(max_api_requests=50):
                    pass

    def test_model_keys_do_not_share_daily_usage_or_reservations(self) -> None:
        with self.guard(dashboard_used=100, max_api_requests=100):
            self.attempts.count += 20

        with self.guard(
            dashboard_used=0,
            dashboard_limit=GEMMA4_26B_RPD_LIMIT,
            max_api_requests=1_000,
            quota_key=GEMMA4_26B_MODEL,
            study_rpd_limit=GEMMA4_26B_RPD_LIMIT,
        ) as gemma:
            self.assertEqual(0, gemma.known_used)
            self.assertEqual(GEMMA4_26B_RPD_LIMIT, gemma.effective_limit)
            self.assertEqual(1_000, gemma.effective_cap)

        records = _records(self.ledger)
        self.assertEqual(
            [PRIMARY_MODEL, GEMMA4_26B_MODEL],
            [record["quota_key"] for record in records],
        )

    def test_v1_ledger_records_migrate_as_primary_model_records(self) -> None:
        legacy = {
            "schema_version": 1,
            "quota_date": FIXED_DATE,
            "reserved_at": FIXED_NOW.isoformat(),
            "dashboard_used": 10,
            "dashboard_limit": 500,
            "effective_limit": 500,
            "known_used_before": 10,
            "requested_cap": 20,
            "reserved_attempts": 20,
            "reconciled_at": FIXED_NOW.isoformat(),
            "actual_attempts": 5,
            "interruption_resolved_at": None,
            "resolution_dashboard_used": None,
        }
        self.ledger.write_text(json.dumps(legacy) + "\n", encoding="utf-8")

        with self.guard(dashboard_used=15, max_api_requests=10):
            pass

        records = _records(self.ledger)
        self.assertTrue(all(record["schema_version"] == 2 for record in records))
        self.assertEqual(PRIMARY_MODEL, records[0]["quota_key"])
        self.assertEqual(500, records[0]["study_rpd_limit"])

    def test_ledger_contains_only_quota_metadata(self) -> None:
        with self.guard(max_api_requests=50):
            pass
        record = _records(self.ledger)[0]
        self.assertEqual(
            {
                "schema_version",
                "quota_key",
                "study_rpd_limit",
                "quota_date",
                "reserved_at",
                "dashboard_used",
                "dashboard_limit",
                "effective_limit",
                "known_used_before",
                "requested_cap",
                "reserved_attempts",
                "reconciled_at",
                "actual_attempts",
                "interruption_resolved_at",
                "resolution_dashboard_used",
            },
            set(record),
        )
        serialized = json.dumps(record).lower()
        self.assertNotIn("api_key", serialized)
        self.assertNotIn("prompt", serialized)
        self.assertNotIn("content", serialized)


class RetryAccountingTests(unittest.TestCase):
    def test_retry_consumes_the_request_attempt_cap(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            0.0,
            max_requests=2,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )
        expected = object()
        client = _FakeClient([_rpm_error(), expected])
        llm = Gemini3LLM(
            "test-model", client, rate_limiter=limiter  # type: ignore[arg-type]
        )

        actual = llm._generate_content([], genai_types.GenerateContentConfig())

        self.assertIs(expected, actual)
        self.assertEqual(2, limiter.requests_started)
        self.assertEqual(2, client.models.calls)

    def test_cap_stops_before_a_retry_can_make_an_extra_call(self) -> None:
        fake_time = _FakeTime()
        limiter = RequestRateLimiter(
            0.0,
            max_requests=1,
            clock=fake_time.monotonic,
            sleeper=fake_time.sleep,
        )
        client = _FakeClient([_rpm_error(), object()])
        llm = Gemini3LLM(
            "test-model", client, rate_limiter=limiter  # type: ignore[arg-type]
        )

        with self.assertRaises(RequestBudgetExceeded):
            llm._generate_content([], genai_types.GenerateContentConfig())

        self.assertEqual(1, limiter.requests_started)
        self.assertEqual(1, client.models.calls)


class MultiQuotaGuardTests(unittest.TestCase):
    """Dual-key reservation for the v2b adaptive arm (Gemini + Gemma)."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.ledger = Path(self.temporary_directory.name) / "quota_ledger.jsonl"
        self.proposer_attempts = _AttemptState()
        self.target_attempts = _AttemptState()

    def proposer_guard(
        self,
        *,
        dashboard_used: int = 0,
        dashboard_limit: int = 500,
        max_api_requests: int = 100,
        output: StringIO | None = None,
    ) -> QuotaGuard:
        return QuotaGuard(
            quota_date=FIXED_DATE,
            dashboard_used=dashboard_used,
            dashboard_limit=dashboard_limit,
            max_api_requests=max_api_requests,
            quota_key=PRIMARY_MODEL,
            study_rpd_limit=500,
            ledger_path=self.ledger,
            now_utc=lambda: FIXED_NOW,
            configure_attempt_limit=self.proposer_attempts.configure,
            get_attempt_count=self.proposer_attempts.get,
            output=output or StringIO(),
        )

    def target_guard(
        self,
        *,
        dashboard_used: int = 0,
        dashboard_limit: int = GEMMA4_26B_RPD_LIMIT,
        max_api_requests: int = 800,
        output: StringIO | None = None,
    ) -> QuotaGuard:
        return QuotaGuard(
            quota_date=FIXED_DATE,
            dashboard_used=dashboard_used,
            dashboard_limit=dashboard_limit,
            max_api_requests=max_api_requests,
            quota_key=GEMMA4_26B_MODEL,
            study_rpd_limit=GEMMA4_26B_RPD_LIMIT,
            ledger_path=self.ledger,
            now_utc=lambda: FIXED_NOW,
            configure_attempt_limit=self.target_attempts.configure,
            get_attempt_count=self.target_attempts.get,
            output=output or StringIO(),
        )

    def test_reserves_both_keys_in_one_ledger_write(self) -> None:
        with MultiQuotaGuard(
            [self.proposer_guard(), self.target_guard()]
        ) as multi:
            records = _records(self.ledger)
            self.assertEqual(
                [PRIMARY_MODEL, GEMMA4_26B_MODEL],
                [record["quota_key"] for record in records],
            )
            self.assertTrue(all(record["reserved_attempts"] > 0 for record in records))
            self.assertEqual([100], self.proposer_attempts.configured)
            self.assertEqual([800], self.target_attempts.configured)
            self.assertEqual(2, len(multi.guards))

    def test_reconciles_each_key_from_its_own_counter_only(self) -> None:
        with MultiQuotaGuard(
            [self.proposer_guard(), self.target_guard()]
        ):
            self.proposer_attempts.count += 3
            self.target_attempts.count += 7

        records = _records(self.ledger)
        by_key = {record["quota_key"]: record for record in records}
        self.assertEqual(3, by_key[PRIMARY_MODEL]["actual_attempts"])
        self.assertEqual(7, by_key[GEMMA4_26B_MODEL]["actual_attempts"])
        self.assertIsNotNone(by_key[PRIMARY_MODEL]["reconciled_at"])
        self.assertIsNotNone(by_key[GEMMA4_26B_MODEL]["reconciled_at"])

    def test_one_key_cannot_reserve_blocks_all_keys(self) -> None:
        # 500 - 490 - 25 reserve leaves nothing for the proposer key.
        with self.assertRaises(QuotaValidationError):
            with MultiQuotaGuard(
                [
                    self.proposer_guard(dashboard_used=490),
                    self.target_guard(),
                ]
            ):
                pass
        self.assertFalse(self.ledger.exists())
        self.assertEqual([], self.proposer_attempts.configured)
        self.assertEqual([], self.target_attempts.configured)

    def test_interruption_retains_both_reservations(self) -> None:
        class Boom(RuntimeError):
            pass

        with self.assertRaises(Boom):
            with MultiQuotaGuard(
                [self.proposer_guard(), self.target_guard()]
            ):
                self.proposer_attempts.count += 2
                self.target_attempts.count += 5
                raise Boom

        records = _records(self.ledger)
        self.assertEqual(2, len(records))
        for record in records:
            self.assertIsNone(record["reconciled_at"])
            self.assertIsNone(record["actual_attempts"])

        # A later run with fresh dashboard readings resolves both open
        # reservations and reserves again under the same keys.
        with MultiQuotaGuard(
            [self.proposer_guard(), self.target_guard()]
        ):
            pass
        records = _records(self.ledger)
        self.assertEqual(4, len(records))
        resolved = [r for r in records if r["interruption_resolved_at"] is not None]
        self.assertEqual(2, len(resolved))

    def test_exception_with_zero_attempts_on_one_key_reconciles_only_it(self) -> None:
        class Boom(RuntimeError):
            pass

        with self.assertRaises(Boom):
            with MultiQuotaGuard(
                [self.proposer_guard(), self.target_guard()]
            ):
                self.target_attempts.count += 4
                raise Boom

        by_key = {record["quota_key"]: record for record in _records(self.ledger)}
        # The proposer made no request, so its reservation reconciles to 0;
        # the target key retains its conservative open reservation.
        self.assertEqual(0, by_key[PRIMARY_MODEL]["actual_attempts"])
        self.assertIsNone(by_key[GEMMA4_26B_MODEL]["reconciled_at"])
        self.assertIsNone(by_key[GEMMA4_26B_MODEL]["actual_attempts"])

    def test_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(QuotaGuardError):
            MultiQuotaGuard([self.proposer_guard(), self.proposer_guard()])

    def test_rejects_empty_guard_list(self) -> None:
        with self.assertRaises(QuotaGuardError):
            MultiQuotaGuard([])

    def test_rejects_mixed_ledger_paths(self) -> None:
        other = QuotaGuard(
            quota_date=FIXED_DATE,
            dashboard_used=0,
            dashboard_limit=500,
            max_api_requests=10,
            quota_key=GEMMA4_26B_MODEL,
            study_rpd_limit=GEMMA4_26B_RPD_LIMIT,
            ledger_path=Path(self.temporary_directory.name) / "other.jsonl",
            now_utc=lambda: FIXED_NOW,
            configure_attempt_limit=self.target_attempts.configure,
            get_attempt_count=self.target_attempts.get,
            output=StringIO(),
        )
        with self.assertRaises(QuotaGuardError):
            MultiQuotaGuard([self.proposer_guard(), other])

    def test_lock_contention_rejects_a_second_process_session(self) -> None:
        first = MultiQuotaGuard([self.proposer_guard(), self.target_guard()])
        with first:
            with self.assertRaises(ConcurrentQuotaRunError):
                with MultiQuotaGuard(
                    [self.proposer_guard(), self.target_guard()]
                ):
                    pass


if __name__ == "__main__":
    unittest.main()
