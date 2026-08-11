"""Run AgentDojo's native InjecAgent attack once in each recorded suite.

These diagnostic runs verify that the model/suite/tool pipeline can produce a
positive injection verdict independently of this project's corpus renderer.
They are checkpointed separately and never enter baseline ASR calculations.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from agentdojo.models import ModelsEnum
from agentdojo.scripts.benchmark import benchmark_suite
from agentdojo.task_suite.load_suites import get_suite
from google.genai.errors import ClientError

from src.experiments.operation_journal import agentdojo_raw_trace_path
from src.experiments.run_baseline import (
    BENCHMARK_VERSION,
    PROJECT_ROOT,
    RAW_ROOT,
    attack_succeeded,
    is_quota_exhausted,
)
from src.llm_providers.google_llm_factory import (
    PRIMARY_MODEL,
    PRIMARY_PIPELINE_NAME,
    get_google_primary_llm,
    get_google_request_attempt_count,
)
from src.schemas import RunResult


DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "baseline" / "positive_control" / "results.jsonl"
ATTACK_NAME = "injecagent"
PAYLOAD_ID = "positive-control-injecagent"

# One reachable native task pair per suite, aligned with the stratified matrix.
CONTROL_CASES = {
    "workspace": ("user_task_14", "injection_task_0"),
    "banking": ("user_task_1", "injection_task_0"),
    "slack": ("user_task_0", "injection_task_1"),
}


def completed_domains(path: Path) -> set[str]:
    """Return domains already checkpointed for the current primary model."""
    if not path.exists():
        return set()
    completed: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = RunResult.from_dict(json.loads(line), path=f"{path}:{line_number}")
        if record.payload_id == PAYLOAD_ID and record.model == f"google-{PRIMARY_MODEL}":
            completed.add(record.domain)
    return completed


def execute_control(domain: str, results_path: Path) -> RunResult:
    """Run and checkpoint the native InjecAgent positive control for one suite."""
    user_task_id, injection_task_id = CONTROL_CASES[domain]
    suite = get_suite(BENCHMARK_VERSION, domain)
    logdir = RAW_ROOT / domain
    requests_before = get_google_request_attempt_count()
    started_at = time.monotonic()
    results = benchmark_suite(
        suite=suite,
        model=cast(ModelsEnum, get_google_primary_llm()),
        logdir=logdir,
        force_rerun=False,
        benchmark_version=BENCHMARK_VERSION,
        user_tasks=(user_task_id,),
        injection_tasks=(injection_task_id,),
        attack=ATTACK_NAME,
    )
    verdict = results["security_results"][(user_task_id, injection_task_id)]
    raw_path = agentdojo_raw_trace_path(
        logdir,
        pipeline_name=PRIMARY_PIPELINE_NAME,
        suite_name=domain,
        user_task_id=user_task_id,
        attack_name=ATTACK_NAME,
        injection_task_id=injection_task_id,
    )
    raw_trace = json.loads(raw_path.read_text(encoding="utf-8"))
    record = RunResult(
        run_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        domain=domain,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        payload_id=PAYLOAD_ID,
        channel="agentdojo_native",
        model=f"google-{PRIMARY_MODEL}",
        defense="none-positive-control",
        attack_success=attack_succeeded(verdict),
        tool_calls=raw_trace["messages"],
        notes=(
            f"attack={ATTACK_NAME}; raw_trace={raw_path.relative_to(PROJECT_ROOT).as_posix()}; "
            f"api_request_attempts={get_google_request_attempt_count() - requests_before}; "
            f"elapsed_seconds={time.monotonic() - started_at:.3f}; diagnostic only"
        ),
    )
    RunResult.from_dict(record.__dict__, path="generated positive control")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.__dict__, ensure_ascii=False) + "\n")
    return record


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--domain",
        action="append",
        choices=tuple(CONTROL_CASES),
        help="restrict to a suite; repeatable",
    )
    parser.add_argument("--results-path", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--plan", action="store_true", help="print controls without API calls")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    domains = args.domain or list(CONTROL_CASES)
    if args.plan:
        for domain in domains:
            print(domain, *CONTROL_CASES[domain], ATTACK_NAME, sep="\t")
        return 0

    results_path = args.results_path.resolve()
    completed = completed_domains(results_path)
    for domain in domains:
        if domain in completed:
            print(f"Skipping checkpointed positive control: {domain}")
            continue
        try:
            record = execute_control(domain, results_path)
        except ClientError as error:
            if not is_quota_exhausted(error):
                raise
            print(
                f"Stopping cleanly before completing all controls: Google quota reached; "
                f"completed records remain in {results_path}.",
                file=sys.stderr,
            )
            return 2
        print(f"Recorded {domain} InjecAgent control: attack_success={record.attack_success}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
