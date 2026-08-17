"""No-network tests for the scoped template-02 repair runner."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import src.adaptive.adaptive_loop as loop
import src.adaptive.repair_malformed as repair


def _planned(round_number: int) -> loop.PlannedAttempt:
    contexts = ["0", "1", "2", "4"]
    strategies = list(loop.STRATEGY_IDS)
    context = contexts[(round_number - 1) % 4]
    strategy = strategies[(round_number - 1) // 4]
    case = loop.EligibleCase(
        payload_id="template-02",
        domain="banking",
        channel="file_content",
        injection_vector="injection_landloard_notice",
        user_task_id="user_task_12",
        injection_task_id=f"injection_task_{context}",
    )
    return loop.PlannedAttempt(
        attempt_key=loop.AdaptiveAttemptKey(
            payload_id=case.payload_id,
            strategy_id=strategy,
            injection_vector=case.injection_vector,
            user_task_id=case.user_task_id,
            injection_task_id=case.injection_task_id,
        ),
        case=case,
        payload=loop.load_corpus()["template-02"],
        strategy_id=strategy,
        strategy_description=f"description-{strategy}",
        mutation_round=round_number,
    )


def _source_rows(planned: list[loop.PlannedAttempt]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for item in planned:
        rows.append(
            {
                "attempt_id": item.attempt_key.attempt_id(),
                "payload_id": "template-02",
                "strategy_id": item.strategy_id,
                "injection_vector": item.case.injection_vector,
                "user_task_id": item.case.user_task_id,
                "injection_task_id": item.case.injection_task_id,
                "mutation_round": item.mutation_round,
                "status": "skipped",
                "proposer_status": "malformed",
                "proposer_error": "Proposer output has 2 occurrences of '{{goal}}'; exactly 1 required.",
                "mutated_template": None,
                "attack_success": None,
                "target_requests": None,
            }
        )
    return rows


class TestRepairSelection(unittest.TestCase):
    def test_reader_uses_only_lf_as_jsonl_delimiter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attempts.jsonl"
            path.write_text(
                json.dumps(
                    {"template": "before\u0085middle\u2028after\u2029"},
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            records = repair._read_jsonl(path)

        self.assertEqual(records, [{"template": "before\u0085middle\u2028after\u2029"}])

    def test_writer_escapes_unicode_record_separators_and_round_trips(self) -> None:
        record = {"template": "before\u0085middle\u2028after\u2029"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attempts.jsonl"
            repair._append_repair_record(path, record)
            raw = path.read_bytes()
            records = repair._read_jsonl(path)

        self.assertNotIn("\u0085".encode("utf-8"), raw)
        self.assertNotIn("\u2028".encode("utf-8"), raw)
        self.assertNotIn("\u2029".encode("utf-8"), raw)
        self.assertEqual(records, [record])

    def test_selects_exactly_the_sixteen_expected_rounds(self) -> None:
        rounds = sorted(repair.EXPECTED_REPAIR_ROUNDS)
        planned = [_planned(round_number) for round_number in rounds]
        rows = _source_rows(planned)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "attempts.jsonl"
            source.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            with patch.object(
                repair,
                "_build_frozen_v2a_plan",
                return_value={item.attempt_key.key_tuple: item for item in planned},
            ):
                selected = repair.select_repair_cases(source)
        self.assertEqual([item.planned.mutation_round for item in selected], rounds)
        self.assertEqual(len(selected), 16)

    def test_rejects_an_unexpected_malformed_round(self) -> None:
        planned = [_planned(5)]
        rows = _source_rows(planned)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "attempts.jsonl"
            source.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
            with patch.object(
                repair,
                "_build_frozen_v2a_plan",
                return_value={planned[0].attempt_key.key_tuple: planned[0]},
            ):
                with self.assertRaisesRegex(ValueError, "Unexpected template-02"):
                    repair.select_repair_cases(source)


class TestRepairExecution(unittest.TestCase):
    def test_duplicate_goal_candidate_is_benchmarked_and_resumes(self) -> None:
        planned = [_planned(1), _planned(2)]
        selected = [
            repair.RepairCase(source_record=row, planned=item)
            for item, row in zip(planned, _source_rows(planned))
        ]
        proposer = MagicMock(return_value=("Mutated {{goal}} and {{goal}}", 1))
        target = MagicMock(
            return_value={
                "attack_success": False,
                "utility_success": True,
                "api_request_attempts": 2,
                "raw_trace_path": "repair/raw.json",
                "elapsed_seconds": 1.25,
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.jsonl"
            source.write_text("", encoding="utf-8")
            attempts = root / "repair.jsonl"
            summary = root / "summary.json"
            with (
                patch.object(repair, "build_repair_plan", return_value=selected),
                patch.object(repair, "_prior_template02_attempts", return_value=[]),
                patch.object(loop, "defense_source_sha256", return_value="defense"),
                patch.object(loop, "get_injection_goal", return_value="goal"),
                patch.object(loop, "propose_mutation", proposer),
                patch.object(loop, "validate_candidate_renderability"),
                patch.object(loop, "run_target", target),
                patch.object(repair, "atomic_write_json"),
            ):
                first = repair.run_repair_loop(
                    source_attempts_path=source,
                    repair_attempts_path=attempts,
                    raw_root=root / "raw",
                    summary_path=summary,
                    proposer_llm=object(),
                )
                proposer.reset_mock()
                target.reset_mock()
                second = repair.run_repair_loop(
                    source_attempts_path=source,
                    repair_attempts_path=attempts,
                    raw_root=root / "raw",
                    summary_path=summary,
                    proposer_llm=object(),
                )
                records = [
                    json.loads(line)
                    for line in attempts.read_text(encoding="utf-8").split("\n")
                    if line.strip()
                ]

        self.assertEqual(first["completed_benchmarks"], 2)
        self.assertEqual(first["attack_successes"], 0)
        self.assertEqual(second["completed_benchmarks"], 2)
        proposer.assert_not_called()
        target.assert_not_called()
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record["goal_token_count"] == 2 for record in records))
        self.assertTrue(all(record["status"] == "completed" for record in records))

    def test_skipped_accepted_candidate_gets_fresh_proposal_on_resume(self) -> None:
        planned = [_planned(1)]
        selected = [
            repair.RepairCase(source_record=row, planned=item)
            for item, row in zip(planned, _source_rows(planned))
        ]
        proposer = MagicMock(return_value=("Fresh {{goal}}", 1))
        target = MagicMock(
            return_value={
                "attack_success": False,
                "utility_success": True,
                "api_request_attempts": 1,
                "raw_trace_path": "repair/raw.json",
                "elapsed_seconds": 0.5,
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.jsonl"
            source.write_text("", encoding="utf-8")
            attempts = root / "repair.jsonl"
            prior = {
                "attempt_id": selected[0].repair_attempt_id,
                "source_attempt_id": selected[0].source_attempt_id,
                "status": "skipped",
                "proposer_status": "accepted",
                "mutated_template": "Known-bad {{goal}}",
            }
            attempts.write_text(json.dumps(prior) + "\n", encoding="utf-8")
            with (
                patch.object(repair, "build_repair_plan", return_value=selected),
                patch.object(repair, "_prior_template02_attempts", return_value=[]),
                patch.object(loop, "defense_source_sha256", return_value="defense"),
                patch.object(loop, "get_injection_goal", return_value="goal"),
                patch.object(loop, "propose_mutation", proposer),
                patch.object(loop, "validate_candidate_renderability"),
                patch.object(loop, "run_target", target),
                patch.object(repair, "atomic_write_json"),
            ):
                summary = repair.run_repair_loop(
                    source_attempts_path=source,
                    repair_attempts_path=attempts,
                    raw_root=root / "raw",
                    summary_path=root / "summary.json",
                    proposer_llm=object(),
                )

        proposer.assert_called_once()
        target.assert_called_once()
        self.assertEqual(summary["completed_benchmarks"], 1)
        self.assertEqual(summary["remaining"], 0)


if __name__ == "__main__":
    unittest.main()
