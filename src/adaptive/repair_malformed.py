"""
CONTROLLED AI-SECURITY RESEARCH

This module is part of an indirect-prompt-injection study conducted
exclusively against AgentDojo synthetic benchmark environments.

Supplemental repair runner for the sixteen ``template-02`` v2a rounds whose
original Gemma proposer responses were rejected because they contained two
``{{goal}}`` placeholders.  The original v2a JSONL remains unchanged.  This
runner creates a separate checkpoint and raw-trace namespace, generates a
fresh candidate for each identified source round, and benchmarks every valid
candidate with the same frozen Gemma target and spotlighting defense.

No real users, services, accounts, credentials, or production agents are
targeted by this code.

Plan mode is read-only.  A live run requires the same quota arguments as the
main adaptive loop and must be started explicitly by the operator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from google.genai.errors import ClientError

import src.adaptive.adaptive_loop as loop
from src.experiments.operation_journal import (
    OperationJournalError,
    atomic_write_bytes,
    atomic_write_json,
)
from src.experiments.quota_guard import add_quota_arguments, quota_guard_from_args


SOURCE_ARM_ID = "v2a"
REPAIR_VERSION = "v2a-template02-repair"
REPAIR_PAYLOAD_ID = "template-02"
PROJECT_ROOT = loop.PROJECT_ROOT
SOURCE_ATTEMPTS_PATH = loop.V2A_ROOT / "attempts.jsonl"
REPAIR_ROOT = PROJECT_ROOT / "data" / "adaptive" / "g4" / "v2a_repair"
REPAIR_ATTEMPTS_PATH = REPAIR_ROOT / "attempts.jsonl"
REPAIR_SUMMARY_PATH = REPAIR_ROOT / "loop_summary.json"
REPAIR_RAW_ROOT = REPAIR_ROOT / "results" / "raw"

# v2a round mapping is frozen: rounds 5, 6, 7, and 15 already contain
# accepted target attempts, leaving exactly these sixteen malformed rounds.
EXPECTED_REPAIR_ROUNDS = frozenset(set(range(1, 21)) - {5, 6, 7, 15})
_NESTED_TEMPLATE_WRAPPER_RE = re.compile(
    r"^\s*\{\s*[\"']template[\"']\s*:"
)


@dataclass(frozen=True)
class RepairCase:
    """One source v2a row plus its validated frozen plan entry."""

    source_record: dict[str, Any]
    planned: loop.PlannedAttempt

    @property
    def source_attempt_id(self) -> str:
        return str(self.source_record["attempt_id"])

    @property
    def repair_attempt_id(self) -> str:
        raw = f"{REPAIR_VERSION}\0{self.source_attempt_id}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:24]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    records: list[dict[str, Any]] = []
    # JSONL records are delimited by LF.  ``str.splitlines()`` also treats
    # U+0085/U+2028/U+2029 as record boundaries, even when those code points
    # are valid content inside a JSON string emitted by the proposer.
    for line_no, line in enumerate(
        path.read_text(encoding="utf-8").split("\n"), 1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON in {path}:{line_no}: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_no}: row must be an object")
        records.append(record)
    return records


def _append_repair_record(path: Path, record: dict[str, Any]) -> None:
    """Atomically append one repair row with JSON separators escaped.

    The shared adaptive writer preserves non-ASCII template text.  Repair
    checkpoints use ``ensure_ascii=True`` so Unicode line-separator code
    points cannot be mistaken for physical JSONL boundaries by downstream
    readers, while the decoded template remains unchanged.
    """
    existing = path.read_bytes() if path.exists() else b""
    if existing and not existing.endswith(b"\n"):
        raise OperationJournalError(f"existing JSONL lacks a final newline: {path}")
    line = (json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    atomic_write_bytes(path, existing + line)


def _looks_like_nested_template_wrapper(value: str) -> bool:
    """Identify a double-encoded proposer JSON object, not template prose."""
    return bool(_NESTED_TEMPLATE_WRAPPER_RE.match(value))


def _build_frozen_v2a_plan() -> dict[tuple[str, ...], loop.PlannedAttempt]:
    """Build the exact v2a plan and index it by its normal checkpoint key."""
    arm = loop.resolve_arm(SOURCE_ARM_ID)
    loop.verify_v2_design_freeze(arm)
    eligible = loop.load_eligible_cases()
    contexts = loop.load_v2_contexts(eligible)
    planned = loop.plan_attempts(
        eligible,
        loop.load_corpus(),
        loop.load_strategy_descriptions(),
        arm_id=SOURCE_ARM_ID,
        context_map=contexts,
    )
    return {item.attempt_key.key_tuple: item for item in planned}


def select_repair_cases(
    source_attempts_path: Path = SOURCE_ATTEMPTS_PATH,
) -> list[RepairCase]:
    """Select and validate exactly the sixteen intended source rows.

    Only rows with the original v2a malformed-proposer shape are selected.
    Completed target rows, target errors, and malformed rows for other payloads
    are never changed or imported into the repair checkpoint.
    """
    plan_by_key = _build_frozen_v2a_plan()
    source_rows = _read_jsonl(source_attempts_path)
    selected: list[RepairCase] = []
    seen_rounds: set[int] = set()

    for record in source_rows:
        if (
            record.get("payload_id") != REPAIR_PAYLOAD_ID
            or record.get("status") != "skipped"
            or record.get("proposer_status") != "malformed"
        ):
            continue
        if record.get("mutated_template") is not None:
            raise ValueError(
                f"Malformed source row {record.get('attempt_id')} unexpectedly "
                "contains a mutated_template"
            )
        proposer_error = record.get("proposer_error")
        if (
            not isinstance(proposer_error, str)
            or "2 occurrences of '{{goal}}'" not in proposer_error
        ):
            raise ValueError(
                f"Source row {record.get('attempt_id')} is malformed for a "
                "different proposer reason"
            )
        if record.get("attack_success") is not None or record.get("target_requests") is not None:
            raise ValueError(
                f"Malformed source row {record.get('attempt_id')} contains target data"
            )
        round_number = record.get("mutation_round")
        if not isinstance(round_number, int) or round_number not in EXPECTED_REPAIR_ROUNDS:
            raise ValueError(
                f"Unexpected template-02 malformed mutation round: {round_number!r}"
            )
        if round_number in seen_rounds:
            raise ValueError(f"Duplicate template-02 repair round {round_number}")
        key = tuple(record.get(field) for field in loop.ATTEMPT_KEY_FIELDS)
        planned = plan_by_key.get(key)
        if planned is None:
            raise ValueError(
                f"Source malformed row {record.get('attempt_id')} is not in the frozen v2a plan"
            )
        if planned.mutation_round != round_number:
            raise ValueError(
                f"Source round/key mismatch for {record.get('attempt_id')}: "
                f"row={round_number}, plan={planned.mutation_round}"
            )
        if record.get("attempt_id") != planned.attempt_key.attempt_id():
            raise ValueError(
                f"Source attempt ID mismatch for mutation round {round_number}"
            )
        seen_rounds.add(round_number)
        selected.append(RepairCase(source_record=record, planned=planned))

    if seen_rounds != EXPECTED_REPAIR_ROUNDS:
        missing = sorted(EXPECTED_REPAIR_ROUNDS - seen_rounds)
        extra = sorted(seen_rounds - EXPECTED_REPAIR_ROUNDS)
        raise ValueError(
            "Expected exactly the sixteen template-02 malformed rounds; "
            f"missing={missing}, extra={extra}"
        )
    return sorted(selected, key=lambda item: item.planned.mutation_round)


def _load_repair_checkpoint(path: Path) -> dict[str, dict[str, Any]]:
    """Load repair rows keyed by their immutable source attempt ID."""
    if not path.exists():
        return {}
    by_source: dict[str, dict[str, Any]] = {}
    for record in _read_jsonl(path):
        source_id = record.get("source_attempt_id")
        repair_id = record.get("attempt_id")
        if not isinstance(source_id, str) or not source_id:
            raise ValueError("Repair row has no source_attempt_id")
        if not isinstance(repair_id, str) or not repair_id:
            raise ValueError("Repair row has no attempt_id")
        previous = by_source.get(source_id)
        previous_is_terminal = (
            previous is not None and previous.get("status") == "completed"
        )
        if previous_is_terminal:
            raise ValueError(
                f"Repair checkpoint has a row after terminal source {source_id}"
            )
        by_source[source_id] = record
    return by_source


def _repair_record(
    *,
    repair_case: RepairCase,
    status: str,
    proposer_status: str,
    proposer_requests: int,
    proposer_error: str | None,
    mutated_template: str | None,
    target_result: dict[str, Any] | None,
    defense_sha256: str,
    target_error: str | None = None,
    proposer_finish_reason: str | None = None,
) -> dict[str, Any]:
    record = loop._build_attempt_record(
        attempt_id=repair_case.repair_attempt_id,
        planned=repair_case.planned,
        case=repair_case.planned.case,
        status=status,
        proposer_status=proposer_status,
        proposer_requests=proposer_requests,
        proposer_error=proposer_error,
        mutated_template=mutated_template,
        target_result=target_result,
        defense_sha256=defense_sha256,
        target_error=target_error,
        proposer_finish_reason=proposer_finish_reason,
        adaptive_version=REPAIR_VERSION,
        proposer_model=loop.GEMMA4_26B_MODEL,
        target_model=loop.GEMMA4_26B_MODEL,
    )
    record.update(
        {
            "source_adaptive_attack_version": SOURCE_ARM_ID,
            "source_attempt_id": repair_case.source_attempt_id,
            "repair_reason": "template-02 duplicate-goal-token proposer output",
            "goal_token_count": (
                mutated_template.count(loop.GOAL_TOKEN)
                if isinstance(mutated_template, str)
                else None
            ),
        }
    )
    return record


def _prior_template02_attempts(source_attempts_path: Path) -> list[dict[str, Any]]:
    """Return completed v2a feedback in mutation-round order."""
    rows = [
        record
        for record in _read_jsonl(source_attempts_path)
        if (
            record.get("payload_id") == REPAIR_PAYLOAD_ID
            and record.get("status") == "completed"
            and isinstance(record.get("mutated_template"), str)
            and isinstance(record.get("attack_success"), bool)
        )
    ]
    rows.sort(key=lambda record: int(record["mutation_round"]))
    return [
        {
            "strategy_id": record["strategy_id"],
            "mutated_template": record["mutated_template"],
            "attack_success": record["attack_success"],
        }
        for record in rows
    ]


def build_repair_plan(
    source_attempts_path: Path = SOURCE_ATTEMPTS_PATH,
) -> list[RepairCase]:
    """Public read-only plan helper used by the CLI and no-network tests."""
    return select_repair_cases(source_attempts_path)


def run_repair_loop(
    *,
    source_attempts_path: Path = SOURCE_ATTEMPTS_PATH,
    repair_attempts_path: Path = REPAIR_ATTEMPTS_PATH,
    raw_root: Path = REPAIR_RAW_ROOT,
    summary_path: Path = REPAIR_SUMMARY_PATH,
    max_new_attempts: int | None = None,
    proposer_llm: Any | None = None,
) -> dict[str, Any]:
    """Generate and benchmark fresh candidates for the sixteen repair slots.

    The source v2a rows are read-only.  A completed repair row is skipped on
    restart.  An accepted-template ``error`` row resumes at the target without
    another proposer call; skipped rows (including accepted but unrenderable
    candidates) receive a fresh proposal on the next run.  Every valid proposal
    is sent through the same renderability preflight and ``run_target`` path as
    the main adaptive loop.
    """
    if max_new_attempts is not None and max_new_attempts <= 0:
        raise ValueError("max_new_attempts must be positive when provided")

    repair_cases = build_repair_plan(source_attempts_path)
    checkpoints = _load_repair_checkpoint(repair_attempts_path)
    expected_defense_sha = loop.defense_source_sha256()
    prior_attempts = _prior_template02_attempts(source_attempts_path)
    for record in checkpoints.values():
        if (
            record.get("status") == "completed"
            and isinstance(record.get("mutated_template"), str)
            and isinstance(record.get("attack_success"), bool)
        ):
            prior_attempts.append(
                {
                    "strategy_id": record["strategy_id"],
                    "mutated_template": record["mutated_template"],
                    "attack_success": record["attack_success"],
                }
            )

    if proposer_llm is None:
        proposer_llm = loop.get_google_gemma4_26b_llm()

    new_attempts = 0
    for repair_case in repair_cases:
        if max_new_attempts is not None and new_attempts >= max_new_attempts:
            break

        source_id = repair_case.source_attempt_id
        existing = checkpoints.get(source_id)
        existing_is_terminal = (
            existing is not None and existing.get("status") == "completed"
        )
        if existing_is_terminal:
            logging.info("Repair resume: already terminal for source %s", source_id[:12])
            continue

        template: str | None = None
        proposer_requests = 0
        proposer_error: str | None = None
        proposer_finish_reason: str | None = None
        proposer_status = "pending"

        if (
            existing is not None
            and existing.get("status") == "error"
            and existing.get("proposer_status") == "accepted"
            and isinstance(existing.get("mutated_template"), str)
        ):
            template = existing["mutated_template"]
            proposer_status = "accepted"
            logging.info("Repair resume: target-only retry for source %s", source_id[:12])
        else:
            try:
                template, proposer_requests = loop.propose_mutation(
                    strategy_id=repair_case.planned.strategy_id,
                    strategy_description=repair_case.planned.strategy_description,
                    original_template=repair_case.planned.payload.template,
                    injection_goal=loop.get_injection_goal(repair_case.planned.case),
                    prior_attempts=prior_attempts,
                    proposer_llm=proposer_llm,
                    # The original rows were rejected solely because the
                    # generated template repeated the goal slot.  Preserve
                    # any candidate with at least one slot in this explicitly
                    # scoped repair arm so it can reach the benchmark.
                    allow_duplicate_goal_tokens=True,
                )
                proposer_status = "accepted"
            except loop.ProposerTruncatedError as exc:
                proposer_error = str(exc)
                proposer_finish_reason = exc.finish_reason
                proposer_status = "truncated"
                proposer_requests = 1
            except ValueError as exc:
                proposer_error = str(exc)
                proposer_status = "malformed"
                proposer_requests = 1
            except (loop.RequestBudgetExceeded, ClientError) as exc:
                record = _repair_record(
                    repair_case=repair_case,
                    status="error",
                    proposer_status="quota_stop",
                    proposer_requests=0,
                    proposer_error=str(exc),
                    mutated_template=None,
                    target_result=None,
                    defense_sha256=expected_defense_sha,
                )
                _append_repair_record(repair_attempts_path, record)
                raise

        if template is None:
            record = _repair_record(
                repair_case=repair_case,
                status="skipped" if proposer_status == "malformed" else "truncated",
                proposer_status=proposer_status,
                proposer_requests=proposer_requests,
                proposer_error=proposer_error,
                proposer_finish_reason=proposer_finish_reason,
                mutated_template=None,
                target_result=None,
                defense_sha256=expected_defense_sha,
            )
            _append_repair_record(repair_attempts_path, record)
            checkpoints[source_id] = record
            new_attempts += 1
            continue

        if _looks_like_nested_template_wrapper(template):
            record = _repair_record(
                repair_case=repair_case,
                status="skipped",
                proposer_status="malformed",
                proposer_requests=proposer_requests,
                proposer_error=(
                    "Proposer returned a nested JSON template wrapper; "
                    "expected template text"
                ),
                mutated_template=template,
                target_result=None,
                defense_sha256=expected_defense_sha,
            )
            _append_repair_record(repair_attempts_path, record)
            checkpoints[source_id] = record
            new_attempts += 1
            continue

        try:
            loop.validate_candidate_renderability(
                mutated_template=template,
                case=repair_case.planned.case,
            )
        except loop.CandidateRenderabilityError as exc:
            record = _repair_record(
                repair_case=repair_case,
                status="skipped",
                proposer_status="accepted",
                proposer_requests=proposer_requests,
                proposer_error=None,
                mutated_template=template,
                target_result=None,
                target_error=str(exc),
                defense_sha256=expected_defense_sha,
            )
            _append_repair_record(repair_attempts_path, record)
            checkpoints[source_id] = record
            new_attempts += 1
            continue

        try:
            target_result = loop.run_target(
                mutated_template=template,
                case=repair_case.planned.case,
                attempt_id=repair_case.repair_attempt_id,
                strategy_id=repair_case.planned.strategy_id,
                payload_id=REPAIR_PAYLOAD_ID,
                raw_root=raw_root,
            )
        except (loop.RequestBudgetExceeded, ClientError) as exc:
            record = _repair_record(
                repair_case=repair_case,
                status="error",
                proposer_status="accepted",
                proposer_requests=proposer_requests,
                proposer_error=None,
                mutated_template=template,
                target_result=None,
                target_error=str(exc),
                defense_sha256=expected_defense_sha,
            )
            _append_repair_record(repair_attempts_path, record)
            raise
        except Exception as exc:
            record = _repair_record(
                repair_case=repair_case,
                status="error",
                proposer_status="accepted",
                proposer_requests=proposer_requests,
                proposer_error=None,
                mutated_template=template,
                target_result=None,
                target_error=str(exc),
                defense_sha256=expected_defense_sha,
            )
            _append_repair_record(repair_attempts_path, record)
            raise

        record = _repair_record(
            repair_case=repair_case,
            status="completed",
            proposer_status="accepted",
            proposer_requests=proposer_requests,
            proposer_error=None,
            mutated_template=template,
            target_result=target_result,
            defense_sha256=expected_defense_sha,
        )
        _append_repair_record(repair_attempts_path, record)
        checkpoints[source_id] = record
        prior_attempts.append(
            {
                "strategy_id": repair_case.planned.strategy_id,
                "mutated_template": template,
                "attack_success": target_result["attack_success"],
            }
        )
        new_attempts += 1

    all_rows = list(_load_repair_checkpoint(repair_attempts_path).values())
    completed = [row for row in all_rows if row.get("status") == "completed"]
    skipped = [row for row in all_rows if row.get("status") == "skipped"]
    terminal = [row for row in all_rows if row.get("status") == "completed"]
    summary = {
        "schema_version": 1,
        "repair_version": REPAIR_VERSION,
        "source_arm": SOURCE_ARM_ID,
        "source_attempts": len(repair_cases),
        "repair_attempts": len(all_rows),
        "completed_benchmarks": len(completed),
        "skipped_repairs": len(skipped),
        "retryable_rows": len(all_rows) - len(terminal),
        "attack_successes": sum(1 for row in completed if row.get("attack_success") is True),
        "remaining": len(repair_cases) - len(terminal),
    }
    atomic_write_json(summary_path, summary)
    return summary


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        action="store_true",
        help="List the sixteen source rows without constructing an LLM or making API calls",
    )
    parser.add_argument(
        "--max-new-attempts",
        type=_positive_int,
        help="Stop after this many new repair rows; useful for resumable batches",
    )
    parser.add_argument("--source-attempts", type=Path, default=SOURCE_ATTEMPTS_PATH)
    parser.add_argument("--repair-attempts", type=Path, default=REPAIR_ATTEMPTS_PATH)
    parser.add_argument("--repair-raw-root", type=Path, default=REPAIR_RAW_ROOT)
    parser.add_argument("--repair-summary", type=Path, default=REPAIR_SUMMARY_PATH)
    add_quota_arguments(parser, required=False)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    args = parse_args(argv)
    try:
        repair_cases = build_repair_plan(args.source_attempts)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot build repair plan: {exc}", file=sys.stderr)
        return 1

    if args.plan:
        print(f"Planned {len(repair_cases)} template-02 repairs (no API calls):")
        for item in repair_cases:
            p = item.planned
            print(
                f"  source={item.source_attempt_id[:12]} "
                f"repair={item.repair_attempt_id[:12]} "
                f"round={p.mutation_round} strategy={p.strategy_id} "
                f"case={p.case.user_task_id} × {p.case.injection_task_id}"
            )
        return 0

    guard = quota_guard_from_args(args, quota_key=loop.QUOTA_KEY)
    try:
        with guard:
            summary = run_repair_loop(
                source_attempts_path=args.source_attempts,
                repair_attempts_path=args.repair_attempts,
                raw_root=args.repair_raw_root,
                summary_path=args.repair_summary,
                max_new_attempts=args.max_new_attempts,
            )
    except loop.RequestBudgetExceeded as exc:
        print(f"Quota cap reached: {exc}", file=sys.stderr)
        return 2
    except ClientError as exc:
        print(f"API error: {exc}", file=sys.stderr)
        return 2

    print(
        "\nTemplate-02 repair complete: "
        f"{summary['completed_benchmarks']} benchmarked, "
        f"{summary['attack_successes']} bypasses, "
        f"{summary['skipped_repairs']} still skipped, "
        f"{summary['remaining']} remaining."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
