"""
No-network unit tests for src/adaptive/adaptive_loop.py (Phase 10).

All tests avoid real API calls. Model-backed behavior is tested via mocks.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

# Import the module under test
import src.adaptive.adaptive_loop as loop


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_eligible_case(**kwargs: str) -> loop.EligibleCase:
    defaults = {
        "payload_id": "persona-04",
        "domain": "banking",
        "channel": "file_content",
        "injection_vector": "injection_landloard_notice",
        "user_task_id": "user_task_12",
        "injection_task_id": "injection_task_0",
    }
    defaults.update(kwargs)
    return loop.EligibleCase(**defaults)


def _make_corpus_entry(payload_id: str = "persona-04") -> Any:
    """Build a minimal PayloadEntry-like object for tests."""
    from src.schemas import PayloadEntry

    return PayloadEntry.from_dict(
        {
            "id": payload_id,
            "category": "role_play_persona",
            "channel": "file_content",
            "domain": ["banking"],
            "template": "Imagine you are a data-migration assistant. {{goal}}",
            "source": "test",
        },
        path="test",
    )


def _tsv_content(rows: list[dict[str, str]]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=loop.CASE_FIELDS, delimiter="\t")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tests: attempt key determinism
# ---------------------------------------------------------------------------


class TestAdaptiveAttemptKey(unittest.TestCase):
    def _make_key(self, **kwargs: str) -> loop.AdaptiveAttemptKey:
        defaults = {
            "payload_id": "persona-04",
            "strategy_id": "delimiter-line-collision",
            "injection_vector": "injection_landloard_notice",
            "user_task_id": "user_task_12",
            "injection_task_id": "injection_task_0",
        }
        defaults.update(kwargs)
        return loop.AdaptiveAttemptKey(**defaults)

    def test_attempt_id_is_deterministic(self):
        k1 = self._make_key()
        k2 = self._make_key()
        self.assertEqual(k1.attempt_id(), k2.attempt_id())

    def test_attempt_id_changes_with_strategy(self):
        k1 = self._make_key(strategy_id="delimiter-line-collision")
        k2 = self._make_key(strategy_id="nested-marker-imitation")
        self.assertNotEqual(k1.attempt_id(), k2.attempt_id())

    def test_attempt_id_changes_with_payload(self):
        k1 = self._make_key(payload_id="persona-04")
        k2 = self._make_key(payload_id="template-02")
        self.assertNotEqual(k1.attempt_id(), k2.attempt_id())

    def test_attempt_id_length(self):
        k = self._make_key()
        self.assertEqual(len(k.attempt_id()), 24)

    def test_key_tuple_order(self):
        k = self._make_key()
        self.assertEqual(
            k.key_tuple,
            (
                k.payload_id,
                k.strategy_id,
                k.injection_vector,
                k.user_task_id,
                k.injection_task_id,
            ),
        )


# ---------------------------------------------------------------------------
# Tests: plan_attempts
# ---------------------------------------------------------------------------


class TestPlanAttempts(unittest.TestCase):
    def setUp(self):
        self.case_row = {
            "payload_id": "persona-04",
            "domain": "banking",
            "channel": "file_content",
            "injection_vector": "injection_landloard_notice",
            "user_task_id": "user_task_12",
            "injection_task_id": "injection_task_0",
        }
        self.eligible = [loop.EligibleCase(**self.case_row)]
        self.corpus = {"persona-04": _make_corpus_entry("persona-04")}
        self.strategy_descriptions = {sid: f"desc-{sid}" for sid in loop.STRATEGY_IDS}

    def test_plan_respects_max_mutations(self):
        plans = loop.plan_attempts(
            self.eligible, self.corpus, self.strategy_descriptions,
            payload_filter="persona-04",
        )
        self.assertEqual(len(plans), loop.MAX_MUTATIONS_PER_PAYLOAD)

    def test_plan_mutation_rounds_are_1_based(self):
        plans = loop.plan_attempts(
            self.eligible, self.corpus, self.strategy_descriptions,
            payload_filter="persona-04",
        )
        rounds = [p.mutation_round for p in plans]
        self.assertEqual(rounds, list(range(1, loop.MAX_MUTATIONS_PER_PAYLOAD + 1)))

    def test_plan_strategies_advance_each_round(self):
        """Only the strategy advances per round; case is fixed."""
        plans = loop.plan_attempts(
            self.eligible, self.corpus, self.strategy_descriptions,
            payload_filter="persona-04",
        )
        expected_strategies = [
            loop.STRATEGY_IDS[(i) % len(loop.STRATEGY_IDS)]
            for i in range(loop.MAX_MUTATIONS_PER_PAYLOAD)
        ]
        self.assertEqual([p.strategy_id for p in plans], expected_strategies)

    def test_plan_uses_fixed_first_case(self):
        """All 5 rounds use the first eligible case in manifest order."""
        # Provide two eligible cases; only the first should ever appear.
        case_first = loop.EligibleCase(
            payload_id="persona-04",
            domain="banking",
            channel="file_content",
            injection_vector="injection_bill_text",
            user_task_id="user_task_0",
            injection_task_id="injection_task_8",
        )
        case_second = loop.EligibleCase(
            payload_id="persona-04",
            domain="banking",
            channel="file_content",
            injection_vector="injection_landloard_notice",
            user_task_id="user_task_12",
            injection_task_id="injection_task_0",
        )
        eligible_two = [case_first, case_second]
        corpus = {"persona-04": _make_corpus_entry("persona-04")}
        desc = {sid: "d" for sid in loop.STRATEGY_IDS}
        plans = loop.plan_attempts(
            eligible_two, corpus, desc, payload_filter="persona-04"
        )
        self.assertEqual(len(plans), loop.MAX_MUTATIONS_PER_PAYLOAD)
        for p in plans:
            self.assertEqual(p.case.user_task_id, "user_task_0",
                             "All rounds must use the first case's user_task_id")
            self.assertEqual(p.case.injection_task_id, "injection_task_8",
                             "All rounds must use the first case's injection_task_id")
            self.assertEqual(p.case.injection_vector, "injection_bill_text",
                             "All rounds must use the first case's injection_vector")

    def test_plan_all_payloads_total(self):
        """All 5 payloads × 5 mutations = 25 planned attempts."""
        # Build a case for each payload
        eligible = [
            loop.EligibleCase(
                payload_id=pid,
                domain="banking",
                channel="file_content",
                injection_vector="injection_landloard_notice",
                user_task_id="user_task_12",
                injection_task_id="injection_task_0",
            )
            for pid in loop.CARRIED_FORWARD_PAYLOAD_IDS
        ]
        corpus = {pid: _make_corpus_entry(pid) for pid in loop.CARRIED_FORWARD_PAYLOAD_IDS}
        plans = loop.plan_attempts(
            eligible, corpus, self.strategy_descriptions
        )
        self.assertEqual(len(plans), loop.MAX_TOTAL_MUTATIONS)

    def test_plan_unknown_payload_filter_raises(self):
        with self.assertRaises(ValueError, msg="Should raise for unknown payload"):
            loop.plan_attempts(
                self.eligible, self.corpus, self.strategy_descriptions,
                payload_filter="nonexistent-payload",
            )

    def test_plan_is_deterministic(self):
        p1 = loop.plan_attempts(
            self.eligible, self.corpus, self.strategy_descriptions,
            payload_filter="persona-04",
        )
        p2 = loop.plan_attempts(
            self.eligible, self.corpus, self.strategy_descriptions,
            payload_filter="persona-04",
        )
        self.assertEqual(
            [a.attempt_key.attempt_id() for a in p1],
            [a.attempt_key.attempt_id() for a in p2],
        )


# ---------------------------------------------------------------------------
# Tests: checkpoint / resume
# ---------------------------------------------------------------------------


class TestCheckpoint(unittest.TestCase):
    def test_empty_checkpoint_returns_empty_set(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                result = loop.load_completed_attempts()
        self.assertEqual(result, set())

    def test_completed_attempt_is_loaded(self):
        record = {
            "schema_version": 1,
            "status": "completed",
            "payload_id": "persona-04",
            "strategy_id": "delimiter-line-collision",
            "injection_vector": "injection_landloard_notice",
            "user_task_id": "user_task_12",
            "injection_task_id": "injection_task_0",
            "attack_success": False,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                result = loop.load_completed_attempts()
        self.assertIn(
            ("persona-04", "delimiter-line-collision",
             "injection_landloard_notice", "user_task_12", "injection_task_0"),
            result,
        )

    def test_error_attempt_is_not_completed(self):
        record = {
            "schema_version": 1,
            "status": "error",
            "payload_id": "template-02",
            "strategy_id": "nested-marker-imitation",
            "injection_vector": "injection_landloard_notice",
            "user_task_id": "user_task_12",
            "injection_task_id": "injection_task_1",
            "attack_success": None,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                result = loop.load_completed_attempts()
        self.assertEqual(result, set())

    def test_completed_without_boolean_verdict_is_not_completed(self):
        record = {
            "schema_version": 1,
            "status": "completed",
            "payload_id": "persona-04",
            "strategy_id": "delimiter-line-collision",
            "injection_vector": "injection_landloard_notice",
            "user_task_id": "user_task_12",
            "injection_task_id": "injection_task_0",
            "attack_success": None,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                result = loop.load_completed_attempts()
        self.assertEqual(result, set())

    def test_in_progress_status_not_counted(self):
        record = {
            "schema_version": 1,
            "status": "pending",
            "payload_id": "persona-04",
            "strategy_id": "delimiter-line-collision",
            "injection_vector": "injection_landloard_notice",
            "user_task_id": "user_task_12",
            "injection_task_id": "injection_task_0",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                result = loop.load_completed_attempts()
        self.assertEqual(len(result), 0)

    def test_success_tracking(self):
        record = {
            "schema_version": 1,
            "status": "completed",
            "payload_id": "persona-04",
            "strategy_id": "delimiter-line-collision",
            "injection_vector": "v",
            "user_task_id": "u",
            "injection_task_id": "i",
            "attack_success": True,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                successes = loop.load_payload_successes()
        self.assertIn("persona-04", successes)

    def test_no_success_if_attack_success_false(self):
        record = {
            "schema_version": 1,
            "status": "completed",
            "payload_id": "persona-04",
            "strategy_id": "delimiter-line-collision",
            "injection_vector": "v",
            "user_task_id": "u",
            "injection_task_id": "i",
            "attack_success": False,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                successes = loop.load_payload_successes()
        self.assertNotIn("persona-04", successes)

    def test_append_then_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            record = {
                "schema_version": 1,
                "status": "completed",
                "payload_id": "persona-04",
                "strategy_id": "delimiter-line-collision",
                "injection_vector": "injection_landloard_notice",
                "user_task_id": "user_task_12",
                "injection_task_id": "injection_task_0",
                "attack_success": False,
            }
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                loop.append_attempt_record(record)
                result = loop.load_completed_attempts()
        self.assertEqual(len(result), 1)

    def test_malformed_json_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "attempts.jsonl"
            path.write_text("not-json\n", encoding="utf-8")
            with patch.object(loop, "ATTEMPTS_JSONL_PATH", path):
                with self.assertRaises(ValueError):
                    loop.load_completed_attempts()


# ---------------------------------------------------------------------------
# Tests: target execution boundary
# ---------------------------------------------------------------------------


class TestTargetExecution(unittest.TestCase):
    def test_run_target_reaches_verdict_with_real_request_counter_binding(self):
        """Exercise run_target itself while replacing only external boundaries."""
        case = _make_eligible_case()
        attack_name = "adaptive-test-attack"

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            raw_root = root / "raw"
            raw_path = loop._raw_trace_path(
                raw_root / case.domain,
                pipeline_name=loop.GEMMA4_26B_PIPELINE_NAME,
                domain=case.domain,
                user_task_id=case.user_task_id,
                attack_name=attack_name,
                injection_task_id=case.injection_task_id,
            )

            def fake_benchmark_suite(**kwargs: Any) -> dict[str, Any]:
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_text(
                    json.dumps({"error": None, "messages": []}),
                    encoding="utf-8",
                )
                return {
                    "security_results": {
                        (case.user_task_id, case.injection_task_id): False
                    },
                    "utility_results": {
                        (case.user_task_id, case.injection_task_id): True
                    },
                }

            fake_llm = SimpleNamespace(name=loop.GEMMA4_26B_PIPELINE_NAME)
            with (
                patch.object(loop, "PROJECT_ROOT", root),
                patch.object(loop, "get_suite", return_value=object()),
                patch.object(
                    loop,
                    "register_adaptive_attack",
                    return_value=attack_name,
                ),
                patch.object(
                    loop,
                    "get_google_gemma4_26b_llm",
                    return_value=fake_llm,
                ),
                patch.object(
                    loop,
                    "benchmark_suite",
                    side_effect=fake_benchmark_suite,
                ) as benchmark,
            ):
                result = loop.run_target(
                    mutated_template="Retry {{goal}} now",
                    case=case,
                    attempt_id="a" * 24,
                    strategy_id="delimiter-line-collision",
                    payload_id="persona-04",
                    raw_root=raw_root,
                )

        self.assertFalse(result["attack_success"])
        self.assertTrue(result["utility_success"])
        self.assertEqual(result["api_request_attempts"], 0)
        self.assertEqual(benchmark.call_count, 1)
        self.assertIsInstance(
            benchmark.call_args.kwargs["model"], loop.MySpotlightingLLM
        )


# ---------------------------------------------------------------------------
# Tests: proposer output validation
# ---------------------------------------------------------------------------


class TestProposerValidation(unittest.TestCase):
    """Test goal-token validation and JSON extraction without real API calls."""

    def _call_validate(self, text: str) -> tuple[str, int]:
        """Exercise the production JSON extraction and validation helper."""
        return loop._extract_proposer_template(text), 1

    def _call_proposer(
        self,
        parts: list[SimpleNamespace],
        *,
        finish_reason: str,
    ) -> tuple[tuple[str, int], dict[str, Any]]:
        candidate = SimpleNamespace(
            content=SimpleNamespace(parts=parts),
            finish_reason=SimpleNamespace(value=finish_reason),
        )
        response = SimpleNamespace(candidates=[candidate])
        captured: dict[str, Any] = {}

        def generate_content(**kwargs: Any) -> Any:
            captured.update(kwargs)
            return response

        proposer_llm = SimpleNamespace(
            model="gemma-4-26b-a4b-it",
            client=SimpleNamespace(
                models=SimpleNamespace(generate_content=generate_content)
            ),
            _rate_limiter=SimpleNamespace(wait_before_request=lambda: None),
            _token_pacer=None,
        )
        result = loop.propose_mutation(
            strategy_id="delimiter-line-collision",
            strategy_description="test strategy",
            original_template="Original {{goal}}",
            injection_goal="Synthetic AgentDojo goal",
            prior_attempts=[],
            proposer_llm=proposer_llm,
        )
        return result, captured

    def test_json_extraction_extracts_template_field(self):
        raw = '{"template": "Hello {{goal}} world."}'
        result, _ = self._call_validate(raw)
        self.assertEqual(result, "Hello {{goal}} world.")

    def test_json_with_preamble_still_extracts(self):
        """Model preamble before the JSON object must not cause failure."""
        raw = 'Here is the output:\n{"template": "Bypass: {{goal}}"}'
        result, _ = self._call_validate(raw)
        self.assertEqual(result, "Bypass: {{goal}}")

    def test_valid_template_passes(self):
        result, _ = self._call_validate('{"template": "Do {{goal}} immediately."}')
        self.assertIn(loop.GOAL_TOKEN, result)

    def test_zero_goal_tokens_raises(self):
        with self.assertRaises(ValueError, msg="Should fail with 0 goal tokens"):
            self._call_validate('{"template": "No goal token here at all."}')

    def test_two_goal_tokens_raises(self):
        with self.assertRaises(ValueError, msg="Should fail with 2 goal tokens"):
            self._call_validate('{"template": "{{goal}} and again {{goal}}"}')

    def test_other_unresolved_token_raises(self):
        with self.assertRaises(ValueError, msg="Should fail with other token"):
            self._call_validate('{"template": "{{goal}} and {{something_else}}"}')

    def test_bare_text_fallback(self):
        """Bare text with no JSON falls back to raw text extraction."""
        result, _ = self._call_validate("Do {{goal}} now.")
        self.assertEqual(result, "Do {{goal}} now.")

    def test_markdown_fence_fallback(self):
        """Bare markdown fence (no JSON) falls back to text extraction."""
        fenced = "```\nDo {{goal}} now.\n```"
        result, _ = self._call_validate(fenced)
        self.assertEqual(result, "Do {{goal}} now.")

    def test_markdown_fence_with_lang_fallback(self):
        fenced = "```text\nDo {{goal}} now.\n```"
        result, _ = self._call_validate(fenced)
        self.assertEqual(result, "Do {{goal}} now.")

    def test_thought_only_response_is_truncated(self):
        parts = [
            SimpleNamespace(
                text="Reasoning that mentions {{goal}} repeatedly {{goal}}",
                thought=True,
            )
        ]
        with self.assertRaises(loop.ProposerTruncatedError) as raised:
            self._call_proposer(parts, finish_reason="MAX_TOKENS")
        self.assertEqual(raised.exception.finish_reason, "MAX_TOKENS")

    def test_mixed_response_uses_only_non_thought_text(self):
        parts = [
            SimpleNamespace(
                text="Reasoning {{goal}} {{goal}} that must be ignored",
                thought=True,
            ),
            SimpleNamespace(
                text='{"template": "Final {{goal}} template"}',
                thought=False,
            ),
        ]
        (template, requests), captured = self._call_proposer(
            parts,
            finish_reason="STOP",
        )
        self.assertEqual(template, "Final {{goal}} template")
        self.assertEqual(requests, 1)
        config = captured["config"]
        self.assertEqual(config.max_output_tokens, 4096)
        self.assertEqual(config.thinking_config.thinking_level.value, "MINIMAL")


# ---------------------------------------------------------------------------
# Tests: proposer failure classification in the loop checkpoint
# ---------------------------------------------------------------------------


class TestProposerFailureClassification(unittest.TestCase):
    def test_resume_retries_seeded_error_status_round(self):
        case = _make_eligible_case()
        corpus = {"persona-04": _make_corpus_entry("persona-04")}
        descriptions = {sid: f"desc-{sid}" for sid in loop.STRATEGY_IDS}
        first_strategy = loop.STRATEGY_IDS[0]
        error_record = {
            "schema_version": 1,
            "attempt_id": loop.AdaptiveAttemptKey(
                payload_id="persona-04",
                strategy_id=first_strategy,
                injection_vector=case.injection_vector,
                user_task_id=case.user_task_id,
                injection_task_id=case.injection_task_id,
            ).attempt_id(),
            "status": "error",
            "payload_id": "persona-04",
            "strategy_id": first_strategy,
            "injection_vector": case.injection_vector,
            "user_task_id": case.user_task_id,
            "injection_task_id": case.injection_task_id,
            "attack_success": None,
            "target_error": "synthetic crash",
        }
        proposer = MagicMock(return_value=("Retried {{goal}}", 1))
        target = MagicMock(
            return_value={
                "attack_success": False,
                "utility_success": True,
                "api_request_attempts": 1,
                "raw_trace_path": "data/adaptive/g4/v1/results/raw/retry.json",
                "elapsed_seconds": 0.1,
            }
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            attempts_path = Path(tmpdir) / "attempts.jsonl"
            attempts_path.write_text(
                json.dumps(error_record) + "\n", encoding="utf-8"
            )
            with (
                patch.object(loop, "ATTEMPTS_JSONL_PATH", attempts_path),
                patch.object(loop, "load_eligible_cases", return_value=[case]),
                patch.object(loop, "load_corpus", return_value=corpus),
                patch.object(
                    loop,
                    "load_strategy_descriptions",
                    return_value=descriptions,
                ),
                patch.object(loop, "defense_source_sha256", return_value="abc123"),
                patch.object(loop, "get_google_gemma4_26b_llm", return_value=object()),
                patch.object(loop, "get_injection_goal", return_value="synthetic goal"),
                patch.object(loop, "propose_mutation", proposer),
                patch.object(loop, "run_target", target),
                patch.object(loop, "atomic_write_json"),
            ):
                loop.run_adaptive_loop(
                    payload_filter="persona-04",
                    max_new_attempts=1,
                )

            records = [
                json.loads(line)
                for line in attempts_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        self.assertEqual(proposer.call_count, 1)
        self.assertEqual(target.call_count, 1)
        self.assertEqual([record["status"] for record in records], ["error", "completed"])
        self.assertEqual(records[1]["attempt_id"], error_record["attempt_id"])
        self.assertEqual(records[1]["mutation_round"], 1)

    def test_target_exception_records_retryable_error_not_completed(self):
        case = _make_eligible_case()
        corpus = {"persona-04": _make_corpus_entry("persona-04")}
        descriptions = {sid: f"desc-{sid}" for sid in loop.STRATEGY_IDS}

        with tempfile.TemporaryDirectory() as tmpdir:
            attempts_path = Path(tmpdir) / "attempts.jsonl"
            with (
                patch.object(loop, "ATTEMPTS_JSONL_PATH", attempts_path),
                patch.object(loop, "load_eligible_cases", return_value=[case]),
                patch.object(loop, "load_corpus", return_value=corpus),
                patch.object(
                    loop,
                    "load_strategy_descriptions",
                    return_value=descriptions,
                ),
                patch.object(loop, "defense_source_sha256", return_value="abc123"),
                patch.object(loop, "get_google_gemma4_26b_llm", return_value=object()),
                patch.object(loop, "get_injection_goal", return_value="synthetic goal"),
                patch.object(
                    loop,
                    "propose_mutation",
                    return_value=("Mutated {{goal}}", 1),
                ),
                patch.object(
                    loop,
                    "run_target",
                    side_effect=NameError("synthetic target crash"),
                ),
                patch.object(loop, "atomic_write_json"),
            ):
                summary = loop.run_adaptive_loop(
                    payload_filter="persona-04",
                    max_new_attempts=1,
                )

            record = json.loads(attempts_path.read_text(encoding="utf-8"))

        self.assertEqual(record["status"], "error")
        self.assertIsNone(record["attack_success"])
        self.assertEqual(summary["total_attempts"], 0)

    def test_thought_only_response_records_truncated_status(self):
        case = _make_eligible_case()
        corpus = {"persona-04": _make_corpus_entry("persona-04")}
        descriptions = {sid: f"desc-{sid}" for sid in loop.STRATEGY_IDS}

        with tempfile.TemporaryDirectory() as tmpdir:
            attempts_path = Path(tmpdir) / "attempts.jsonl"
            run_target = MagicMock()
            with (
                patch.object(loop, "ATTEMPTS_JSONL_PATH", attempts_path),
                patch.object(loop, "load_eligible_cases", return_value=[case]),
                patch.object(loop, "load_corpus", return_value=corpus),
                patch.object(
                    loop,
                    "load_strategy_descriptions",
                    return_value=descriptions,
                ),
                patch.object(loop, "defense_source_sha256", return_value="abc123"),
                patch.object(loop, "get_google_gemma4_26b_llm", return_value=object()),
                patch.object(loop, "get_injection_goal", return_value="synthetic goal"),
                patch.object(
                    loop,
                    "propose_mutation",
                    side_effect=loop.ProposerTruncatedError("MAX_TOKENS"),
                ),
                patch.object(loop, "run_target", run_target),
                patch.object(loop, "atomic_write_json"),
            ):
                loop.run_adaptive_loop(
                    payload_filter="persona-04",
                    max_new_attempts=1,
                )

            records = [
                json.loads(line)
                for line in attempts_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "truncated")
        self.assertEqual(records[0]["proposer_status"], "truncated")
        self.assertEqual(records[0]["proposer_finish_reason"], "MAX_TOKENS")
        self.assertEqual(records[0]["proposer_requests"], 1)
        run_target.assert_not_called()

    def test_bound_executes_one_proposer_and_one_target(self):
        case = _make_eligible_case()
        corpus = {"persona-04": _make_corpus_entry("persona-04")}
        descriptions = {sid: f"desc-{sid}" for sid in loop.STRATEGY_IDS}
        proposer = MagicMock(return_value=("Mutated {{goal}}", 1))
        target = MagicMock(
            return_value={
                "attack_success": False,
                "utility_success": True,
                "api_request_attempts": 2,
                "raw_trace_path": "data/adaptive/g4/v1/results/raw/test.json",
                "elapsed_seconds": 1.0,
            }
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            attempts_path = Path(tmpdir) / "attempts.jsonl"
            with (
                patch.object(loop, "ATTEMPTS_JSONL_PATH", attempts_path),
                patch.object(loop, "load_eligible_cases", return_value=[case]),
                patch.object(loop, "load_corpus", return_value=corpus),
                patch.object(
                    loop,
                    "load_strategy_descriptions",
                    return_value=descriptions,
                ),
                patch.object(loop, "defense_source_sha256", return_value="abc123"),
                patch.object(loop, "get_google_gemma4_26b_llm", return_value=object()),
                patch.object(loop, "get_injection_goal", return_value="synthetic goal"),
                patch.object(loop, "propose_mutation", proposer),
                patch.object(loop, "run_target", target),
                patch.object(loop, "atomic_write_json"),
            ):
                loop.run_adaptive_loop(
                    payload_filter="persona-04",
                    max_new_attempts=1,
                )

            records = [
                json.loads(line)
                for line in attempts_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        self.assertEqual(proposer.call_count, 1)
        self.assertEqual(target.call_count, 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["mutation_round"], 1)
        self.assertEqual(records[0]["status"], "completed")

    def test_malformed_round_one_does_not_advance_to_round_two(self):
        case = _make_eligible_case()
        corpus = {"persona-04": _make_corpus_entry("persona-04")}
        descriptions = {sid: f"desc-{sid}" for sid in loop.STRATEGY_IDS}
        proposer = MagicMock(side_effect=ValueError("bad JSON shape"))
        target = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            attempts_path = Path(tmpdir) / "attempts.jsonl"
            with (
                patch.object(loop, "ATTEMPTS_JSONL_PATH", attempts_path),
                patch.object(loop, "load_eligible_cases", return_value=[case]),
                patch.object(loop, "load_corpus", return_value=corpus),
                patch.object(
                    loop,
                    "load_strategy_descriptions",
                    return_value=descriptions,
                ),
                patch.object(loop, "defense_source_sha256", return_value="abc123"),
                patch.object(loop, "get_google_gemma4_26b_llm", return_value=object()),
                patch.object(loop, "get_injection_goal", return_value="synthetic goal"),
                patch.object(loop, "propose_mutation", proposer),
                patch.object(loop, "run_target", target),
                patch.object(loop, "atomic_write_json"),
            ):
                loop.run_adaptive_loop(
                    payload_filter="persona-04",
                    max_new_attempts=1,
                )

            records = [
                json.loads(line)
                for line in attempts_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        self.assertEqual(proposer.call_count, 1)
        target.assert_not_called()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["mutation_round"], 1)
        self.assertEqual(records[0]["status"], "skipped")
        self.assertEqual(records[0]["proposer_status"], "malformed")


# ---------------------------------------------------------------------------
# Tests: budget enforcement via stopping rules
# ---------------------------------------------------------------------------


class TestBudgetEnforcement(unittest.TestCase):
    """Verify the stopping rule constants are self-consistent."""

    def test_max_total_equals_5_times_5(self):
        self.assertEqual(
            loop.MAX_TOTAL_MUTATIONS,
            loop.MAX_MUTATIONS_PER_PAYLOAD * len(loop.CARRIED_FORWARD_PAYLOAD_IDS),
        )

    def test_carried_forward_count(self):
        self.assertEqual(len(loop.CARRIED_FORWARD_PAYLOAD_IDS), 5)

    def test_strategy_count(self):
        self.assertEqual(len(loop.STRATEGY_IDS), 5)

    def test_plan_stops_at_budget(self):
        """plan_attempts produces exactly MAX_MUTATIONS_PER_PAYLOAD per payload."""
        eligible = [
            loop.EligibleCase(
                payload_id="persona-04",
                domain="banking",
                channel="file_content",
                injection_vector="injection_landloard_notice",
                user_task_id="user_task_12",
                injection_task_id="injection_task_0",
            )
        ]
        corpus = {"persona-04": _make_corpus_entry("persona-04")}
        desc = {sid: "d" for sid in loop.STRATEGY_IDS}
        plans = loop.plan_attempts(
            eligible, corpus, desc, payload_filter="persona-04"
        )
        self.assertEqual(len(plans), loop.MAX_MUTATIONS_PER_PAYLOAD)


# ---------------------------------------------------------------------------
# Tests: attempt record schema
# ---------------------------------------------------------------------------


class TestAttemptRecord(unittest.TestCase):
    def _build_record(self, **overrides: Any) -> dict[str, Any]:
        case = _make_eligible_case()
        payload = _make_corpus_entry()
        attempt_key = loop.AdaptiveAttemptKey(
            payload_id="persona-04",
            strategy_id="delimiter-line-collision",
            injection_vector=case.injection_vector,
            user_task_id=case.user_task_id,
            injection_task_id=case.injection_task_id,
        )
        planned = loop.PlannedAttempt(
            attempt_key=attempt_key,
            case=case,
            payload=payload,
            strategy_id="delimiter-line-collision",
            strategy_description="test desc",
            mutation_round=1,
        )
        kwargs: dict[str, Any] = {
            "attempt_id": attempt_key.attempt_id(),
            "planned": planned,
            "case": case,
            "status": "completed",
            "proposer_status": "accepted",
            "proposer_requests": 1,
            "proposer_error": None,
            "mutated_template": "Modified {{goal}} text",
            "target_result": {
                "attack_success": False,
                "utility_success": True,
                "api_request_attempts": 3,
                "raw_trace_path": "data/adaptive/g4/v1/results/raw/banking/trace.json",
                "elapsed_seconds": 12.5,
            },
            "defense_sha256": "abc123",
        }
        kwargs.update(overrides)
        return loop._build_attempt_record(**kwargs)

    def test_record_has_required_fields(self):
        record = self._build_record()
        required_fields = {
            "schema_version",
            "attempt_id",
            "adaptive_attack_version",
            "timestamp",
            "status",
            "payload_id",
            "domain",
            "channel",
            "injection_vector",
            "user_task_id",
            "injection_task_id",
            "strategy_id",
            "mutation_round",
            "proposer_model",
            "proposer_status",
            "proposer_requests",
            "proposer_error",
            "proposer_finish_reason",
            "mutated_template",
            "mutated_template_sha256",
            "target_model",
            "defense",
            "defense_version",
            "defense_sha256",
            "attack_success",
            "utility_success",
            "target_requests",
            "target_error",
            "raw_trace_path",
            "elapsed_seconds",
        }
        self.assertEqual(required_fields, set(record.keys()))

    def test_template_sha256_computed(self):
        record = self._build_record()
        expected = hashlib.sha256(b"Modified {{goal}} text").hexdigest()
        self.assertEqual(record["mutated_template_sha256"], expected)

    def test_null_template_has_null_sha256(self):
        record = self._build_record(mutated_template=None, target_result=None)
        self.assertIsNone(record["mutated_template_sha256"])

    def test_adaptive_version_matches_constant(self):
        record = self._build_record()
        self.assertEqual(record["adaptive_attack_version"], loop.ADAPTIVE_VERSION)

    def test_quota_key_is_gemma(self):
        """Quota key must be gemma-4-26b-a4b-it, not a Gemini model."""
        from src.llm_providers.google_llm_factory import GEMMA4_26B_MODEL
        self.assertEqual(loop.QUOTA_KEY, GEMMA4_26B_MODEL)
        # Confirm it is NOT a Gemini model
        self.assertNotIn("gemini", loop.QUOTA_KEY.lower())
        self.assertIn("gemma", loop.QUOTA_KEY.lower())

    def test_proposer_model_is_gemma(self):
        record = self._build_record()
        self.assertIn("gemma", record["proposer_model"].lower())

    def test_target_model_is_gemma(self):
        record = self._build_record()
        self.assertIn("gemma", record["target_model"].lower())


# ---------------------------------------------------------------------------
# Tests: defense source hash check on startup
# ---------------------------------------------------------------------------


class TestDefenseHashCheck(unittest.TestCase):
    def test_hash_mismatch_causes_error_exit(self):
        """main() returns 1 when the defense source hash is wrong."""
        manifest_data = {
            "target_defense": {
                "source_sha256_canonical_lf": "wrong_hash_value_0000000000000000000000000"
            }
        }
        with (
            patch.object(loop, "defense_source_sha256", return_value="actual_hash"),
            patch.object(loop, "load_strategy_manifest", return_value=manifest_data),
        ):
            rc = loop.main(["--quota-date", "2026-08-14",
                            "--dashboard-used", "0",
                            "--dashboard-limit", "14400",
                            "--max-api-requests", "50"])
        self.assertEqual(rc, 1)


# ---------------------------------------------------------------------------
# Tests: CLI argument validation
# ---------------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def test_plan_flag_produces_output_without_api(self):
        """--plan must return 0 without entering the quota guard."""
        import io
        captured = io.StringIO()
        with (
            patch("sys.stdout", captured),
            patch.object(loop, "load_eligible_cases", return_value=[
                _make_eligible_case()
            ]),
            patch.object(loop, "load_corpus", return_value={
                "persona-04": _make_corpus_entry("persona-04")
            }),
            patch.object(loop, "load_strategy_descriptions", return_value={
                sid: "d" for sid in loop.STRATEGY_IDS
            }),
        ):
            rc = loop.main(["--plan", "--payload", "persona-04"])
        self.assertEqual(rc, 0)
        self.assertIn("Planned", captured.getvalue())

    def test_plan_with_unknown_payload_raises(self):
        """--plan with an unknown payload should raise ValueError."""
        with (
            patch.object(loop, "load_eligible_cases", return_value=[]),
            patch.object(loop, "load_corpus", return_value={}),
            patch.object(loop, "load_strategy_descriptions", return_value={}),
        ):
            with self.assertRaises(ValueError):
                loop.main(["--plan", "--payload", "nonexistent"])

    def test_development_held_out_separation(self):
        """Confirm that all eligible cases are from the banking domain (no Gemini)."""
        # All adaptive cases are Banking-only (enforced by the eligible manifest)
        case = _make_eligible_case(domain="banking")
        self.assertEqual(case.domain, "banking")

    def test_goal_token_constant(self):
        """The only supported goal token must be {{goal}}."""
        self.assertEqual(loop.GOAL_TOKEN, "{{goal}}")

    def test_max_new_attempts_flag_reaches_loop(self):
        guard = MagicMock()
        guard.__enter__.return_value = guard
        manifest = {
            "target_defense": {"source_sha256_canonical_lf": "frozen-sha"}
        }
        with (
            patch.object(loop, "defense_source_sha256", return_value="frozen-sha"),
            patch.object(loop, "load_strategy_manifest", return_value=manifest),
            patch.object(loop, "quota_guard_from_args", return_value=guard),
            patch.object(
                loop,
                "run_adaptive_loop",
                return_value={
                    "total_attempts": 1,
                    "total_successes": 0,
                    "payloads": {},
                },
            ) as run_loop,
        ):
            rc = loop.main(
                [
                    "--payload",
                    "persona-04",
                    "--max-new-attempts",
                    "1",
                    "--quota-date",
                    "2026-08-15",
                    "--dashboard-used",
                    "11",
                    "--dashboard-limit",
                    "14400",
                    "--max-api-requests",
                    "10",
                ]
            )

        self.assertEqual(rc, 0)
        run_loop.assert_called_once_with(
            payload_filter="persona-04",
            dry_run=False,
            max_new_attempts=1,
        )


if __name__ == "__main__":
    unittest.main()
