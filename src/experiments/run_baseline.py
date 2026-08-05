"""Run the undefended Phase 6 baseline with corpus-tagged AgentDojo attacks.

The runner deliberately calls :func:`agentdojo.scripts.benchmark.benchmark_suite`
through Python rather than AgentDojo's CLI.  Its constructed Google AI Studio
client therefore bypasses AgentDojo's Vertex-AI-only model resolver.

Each corpus entry is paired only with benchmark injection vectors that expose
the entry's documented channel.  The raw AgentDojo trace remains in
``data/baseline/raw/``; this script adds a schema-validated JSONL index with
the benchmark injection-task verdict, payload metadata, and full message trace.

Examples:
    # Inspect the documented stratified matrix without API calls.
    python -m src.experiments.run_baseline --plan

    # Save the reviewed plan for the recorded 110-case matrix.
    python -m src.experiments.run_baseline --plan --plan-output data/baseline/plan.tsv

    # Phase 6 dry run: accumulate 5-10 cases across quota days, one at a time.
    python -m src.experiments.run_baseline --max-runs 1

    # Resume the stratified matrix after the dry run.
    python -m src.experiments.run_baseline

    # Inspect the original full task-by-injection expansion (no API calls).
    python -m src.experiments.run_baseline --matrix full --plan
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import sys
import time
import uuid
from collections.abc import Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from agentdojo.attacks.attack_registry import ATTACKS, register_attack
from agentdojo.attacks.base_attacks import BaseAttack
from agentdojo.models import ModelsEnum
from agentdojo.scripts.benchmark import benchmark_suite
from agentdojo.task_suite.load_suites import get_suite
from google.genai.errors import ClientError

from src.llm_providers.google_llm_factory import (
    PRIMARY_MODEL,
    RequestBudgetExceeded,
    configure_google_request_attempt_limit,
    get_google_primary_llm,
    get_google_request_attempt_count,
)
from src.schemas import PayloadEntry, RunResult, SchemaValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = PROJECT_ROOT / "src" / "payloads" / "corpus.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "baseline" / "results.jsonl"
RAW_ROOT = PROJECT_ROOT / "data" / "baseline" / "raw"
BENCHMARK_VERSION = "v1.2.2"

# Vector names were verified against the installed AgentDojo v1.2.2 suites.
# A payload is only placed into a vector that represents its corpus channel.
CHANNEL_VECTORS: dict[str, dict[str, tuple[str, ...]]] = {
    "workspace": {
        "email_body": (
            "email_events_injection",
            "email_facebook_injection",
            "email_hiking_injection",
            "email_password_reset_injection",
        ),
        "calendar_event": (
            "calendar_dinner_with_clients_injection",
            "calendar_fake_deadline_description",
            "calendar_introductory_meeting_injection",
            "calendar_moving_event_reason_injection",
            "calendar_networking_event_injection_email",
            "calendar_project_kickoff_description",
            "calendar_sports_and_yoga_class_injection",
        ),
        "file_content": (
            "drive_feedback_injection",
            "drive_keywords_stuffing_injection",
            "drive_recipe_injection",
            "drive_team_building_injection",
        ),
    },
    "banking": {
        "transaction_memo": ("injection_incoming_transaction",),
        "file_content": (
            "injection_address_change",
            "injection_bill_text",
            "injection_landloard_notice",
        ),
    },
    "slack": {
        "web_content": (
            "injection_web_0",
            "injection_phishing_1",
            "injection_dora_0",
            "prompt_injection_eve_blog",
            "prompt_injection_restaurant",
        ),
    },
}

# The expanded stratified matrix uses two benchmark-native goals per suite and
# up to two native vectors per channel. These IDs were verified in v1.2.2.
STRATIFIED_INJECTION_TASKS = {
    "workspace": ("injection_task_0", "injection_task_1"),
    "banking": ("injection_task_0", "injection_task_1"),
    "slack": ("injection_task_1", "injection_task_2"),
}
STRATIFIED_VECTORS_PER_CHANNEL = 2


class CorpusPayloadAttack(BaseAttack):
    """Inject one corpus entry into one compatible AgentDojo vector.

    AgentDojo injection tasks define the benchmark-specific harmful goal and
    its checked security condition. The corpus controls only prompt-injection
    framing: the goal is included verbatim or in a reversible category-specific
    encoding. The benchmark therefore evaluates that framing against its native
    checker rather than a project-defined heuristic. AgentDojo's historically
    named ``security`` boolean is ``True`` when that injection task succeeds.
    """

    name = "corpus_payload_base"

    def __init__(
        self,
        task_suite: Any,
        target_pipeline: Any,
        payload: PayloadEntry,
        injection_vector: str,
    ) -> None:
        super().__init__(task_suite, target_pipeline)
        self.payload = payload
        self.injection_vector = injection_vector

    def attack(self, user_task: Any, injection_task: Any) -> dict[str, str]:
        candidates = self.get_injection_candidates(user_task)
        if self.injection_vector not in candidates:
            raise ValueError(
                f"{user_task.ID} does not expose expected injection vector "
                f"{self.injection_vector!r}"
            )
        return {
            self.injection_vector: self._render_injection(injection_task.GOAL),
        }

    def _render_injection(self, benchmark_goal: str) -> str:
        return render_payload(self.payload, benchmark_goal)


class _CandidateProbe(CorpusPayloadAttack):
    """Use BaseAttack's ground-truth candidate discovery without an LLM call."""

    name = "corpus_payload_candidate_probe"


_UNRESOLVED_TEMPLATE = re.compile(r"\{\{[^{}]+\}\}")


def encode_goal_unicode(goal: str) -> str:
    """Encode a goal as reversible Python/JSON-style Unicode escapes."""
    return "".join(
        f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
        for codepoint in map(ord, goal)
    )


def encode_goal_first_tokens(goal: str) -> str:
    """Encode UTF-8 goal bytes as hex chunks in each line's first token."""
    encoded = goal.encode("utf-8").hex()
    return "\n".join(
        f"{encoded[index:index + 8]} archive-entry"
        for index in range(0, len(encoded), 8)
    )


def render_payload(payload: PayloadEntry, benchmark_goal: str) -> str:
    """Render one corpus template against the native AgentDojo attack goal.

    Every template must select exactly one supported goal representation. This
    prevents unresolved or conflicting template text from entering a recorded
    run while keeping obfuscation transformations deterministic and reversible.
    """
    replacements = {
        "{{goal}}": benchmark_goal,
        "{{goal_base64}}": base64.b64encode(benchmark_goal.encode("utf-8")).decode("ascii"),
        "{{goal_reversed}}": benchmark_goal[::-1],
        "{{goal_unicode}}": encode_goal_unicode(benchmark_goal),
        "{{goal_first_tokens}}": encode_goal_first_tokens(benchmark_goal),
    }
    selected = [token for token in replacements if token in payload.template]
    if len(selected) != 1:
        raise ValueError(
            f"Payload {payload.id!r} must contain exactly one supported goal token; "
            f"found {selected}"
        )
    rendered = payload.template.replace(selected[0], replacements[selected[0]])
    unresolved = _UNRESOLVED_TEMPLATE.findall(rendered)
    if unresolved:
        raise ValueError(f"Payload {payload.id!r} has unresolved token(s): {unresolved}")
    return rendered


def _attack_name(payload_id: str, injection_vector: str) -> str:
    """Return a stable registry/file-system-safe name for one attack variant."""
    return "corpus_" + re.sub(r"[^a-zA-Z0-9_-]+", "_", f"{payload_id}_{injection_vector}")


def register_payload_attack(payload: PayloadEntry, injection_vector: str) -> str:
    """Register a parameterised AgentDojo attack and return its registry name."""
    name = _attack_name(payload.id, injection_vector)

    class RegisteredCorpusPayloadAttack(CorpusPayloadAttack):
        def __init__(self, task_suite: Any, target_pipeline: Any) -> None:
            super().__init__(task_suite, target_pipeline, payload, injection_vector)

    RegisteredCorpusPayloadAttack.name = name
    ATTACKS.pop(name, None)
    register_attack(RegisteredCorpusPayloadAttack)
    return name


def load_corpus(path: Path = CORPUS_PATH) -> list[PayloadEntry]:
    """Load and schema-check the committed payload corpus."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SchemaValidationError(f"{path} must contain a JSON list")
    return [PayloadEntry.from_dict(record, path=f"{path}:{index}") for index, record in enumerate(data, 1)]


def compatible_vectors(domain: str, channel: str, suite: Any) -> tuple[str, ...]:
    """Return verified vectors for a corpus domain/channel combination."""
    vectors = CHANNEL_VECTORS.get(domain, {}).get(channel)
    if not vectors:
        raise ValueError(f"No AgentDojo vector mapping for domain={domain!r}, channel={channel!r}")
    available = set(suite.get_injection_vector_defaults())
    missing = sorted(set(vectors) - available)
    if missing:
        raise ValueError(f"AgentDojo suite {domain!r} no longer has mapped vector(s): {missing}")
    return vectors


def eligible_user_tasks(suite: Any, payload: PayloadEntry, injection_vector: str) -> list[str]:
    """Find user tasks that actually reveal one injection vector to the agent."""
    probe = _CandidateProbe(suite, None, payload, injection_vector)
    eligible: list[str] = []
    for user_task_id, user_task in suite.user_tasks.items():
        try:
            candidates = probe.get_injection_candidates(user_task)
        except ValueError:
            continue
        if injection_vector in candidates:
            eligible.append(user_task_id)
    return eligible


def iter_cases(
    payloads: Sequence[PayloadEntry],
    domains: set[str] | None = None,
    payload_ids: set[str] | None = None,
    injection_tasks: set[str] | None = None,
    matrix: str = "stratified",
) -> Iterator[tuple[PayloadEntry, str, str, str, str]]:
    """Yield ``(payload, domain, vector, user_task, injection_task)`` cases."""
    if matrix not in {"stratified", "full"}:
        raise ValueError(f"Unknown matrix mode: {matrix!r}")
    suites: dict[str, Any] = {}
    eligible_tasks: dict[tuple[str, str], list[str]] = {}
    for payload in payloads:
        if payload_ids is not None and payload.id not in payload_ids:
            continue
        for domain in payload.domain:
            if domains is not None and domain not in domains:
                continue
            suite = suites.get(domain)
            if suite is None:
                suite = get_suite(BENCHMARK_VERSION, domain)
                suites[domain] = suite
            requested_tasks = injection_tasks
            if matrix == "stratified" and requested_tasks is None:
                requested_tasks = set(STRATIFIED_INJECTION_TASKS[domain])
            selected_injection_tasks = tuple(task_id for task_id in suite.injection_tasks if requested_tasks is None or task_id in requested_tasks)
            unknown = (requested_tasks or set()) - set(suite.injection_tasks)
            if unknown and len(selected_injection_tasks) == 0:
                raise ValueError(f"{domain} has no requested injection task(s): {sorted(unknown)}")
            vectors = compatible_vectors(domain, payload.channel, suite)
            if matrix == "stratified":
                reachable_vectors: list[str] = []
                for vector in vectors:
                    cache_key = (domain, vector)
                    if cache_key not in eligible_tasks:
                        eligible_tasks[cache_key] = eligible_user_tasks(suite, payload, vector)
                    if eligible_tasks[cache_key]:
                        reachable_vectors.append(vector)
                    if len(reachable_vectors) == STRATIFIED_VECTORS_PER_CHANNEL:
                        break
                vectors = tuple(reachable_vectors)
            for vector in vectors:
                cache_key = (domain, vector)
                if cache_key not in eligible_tasks:
                    eligible_tasks[cache_key] = eligible_user_tasks(suite, payload, vector)
                user_task_ids = eligible_tasks[cache_key]
                if matrix == "stratified":
                    user_task_ids = user_task_ids[:1]
                for user_task_id in user_task_ids:
                    for injection_task_id in selected_injection_tasks:
                        yield payload, domain, vector, user_task_id, injection_task_id


def _case_key(payload_id: str, domain: str, vector: str, user_task_id: str, injection_task_id: str) -> tuple[str, ...]:
    return payload_id, domain, vector, user_task_id, injection_task_id


def completed_cases(results_path: Path) -> set[tuple[str, ...]]:
    """Read checkpoint keys from an existing results JSONL file."""
    if not results_path.exists():
        return set()
    completed: set[tuple[str, ...]] = set()
    for line_number, line in enumerate(results_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            result = RunResult.from_dict(record, path=f"{results_path}:{line_number}")
        except (json.JSONDecodeError, SchemaValidationError) as exc:
            raise SchemaValidationError(f"Cannot resume from invalid results file: {exc}") from exc
        vector = _vector_from_notes(result.notes)
        if vector is None:
            raise SchemaValidationError(f"{results_path}:{line_number} lacks an injection_vector note")
        completed.add(_case_key(result.payload_id, result.domain, vector, result.user_task_id, result.injection_task_id))
    return completed


def _vector_from_notes(notes: str) -> str | None:
    match = re.search(r"(?:^|;\s*)injection_vector=([^;]+)", notes)
    return match.group(1) if match else None


def is_quota_exhausted(error: Exception) -> bool:
    """Return whether a Google API error represents a quota/rate-limit stop."""
    message = str(error).lower()
    return (
        isinstance(error, RequestBudgetExceeded)
        or getattr(error, "code", None) == 429
        or "429" in message
    )


def attack_succeeded(injection_task_result: bool) -> bool:
    """Return AgentDojo's native injection-task success verdict unchanged."""
    return injection_task_result


def write_plan(
    cases: Sequence[tuple[PayloadEntry, str, str, str, str]],
    path: Path,
) -> None:
    """Write a reviewable TSV manifest without making any model/API calls."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(("payload_id", "domain", "channel", "injection_vector", "user_task_id", "injection_task_id"))
        for payload, domain, vector, user_task_id, injection_task_id in cases:
            writer.writerow((payload.id, domain, payload.channel, vector, user_task_id, injection_task_id))


def _raw_trace_path(logdir: Path, user_task_id: str, attack_name: str, injection_task_id: str) -> Path:
    matches = list(logdir.rglob(f"{injection_task_id}.json"))
    expected = [path for path in matches if user_task_id in path.parts and attack_name in path.parts]
    if len(expected) != 1:
        raise FileNotFoundError(
            f"Expected one raw trace for user={user_task_id}, attack={attack_name}, "
            f"injection={injection_task_id}; found {len(expected)}"
        )
    return expected[0]


def execute_case(
    payload: PayloadEntry,
    domain: str,
    injection_vector: str,
    user_task_id: str,
    injection_task_id: str,
    results_path: Path,
) -> RunResult:
    """Run one AgentDojo task attempt and append its validated JSONL record."""
    suite = get_suite(BENCHMARK_VERSION, domain)
    attack_name = register_payload_attack(payload, injection_vector)
    # AgentDojo's injection-task utility traces use the "none" attack path.
    # Sharing a domain root lets later payload cases reuse those completed
    # native-task checks while their distinct attack names keep raw attack
    # traces separate.
    logdir = RAW_ROOT / domain
    # Construct a fresh primary-only LLM per task.  No fallback/testing factory
    # is used anywhere in this recorded baseline path.
    requests_before = get_google_request_attempt_count()
    started_at = time.monotonic()
    results = benchmark_suite(
        suite=suite,
        # AgentDojo's runtime accepts a constructed BasePipelineElement here,
        # although its installed annotation is still limited to ModelsEnum.
        model=cast(ModelsEnum, get_google_primary_llm()),
        logdir=logdir,
        force_rerun=False,
        benchmark_version=BENCHMARK_VERSION,
        user_tasks=(user_task_id,),
        injection_tasks=(injection_task_id,),
        attack=attack_name,
    )
    security = results["security_results"][(user_task_id, injection_task_id)]
    raw_path = _raw_trace_path(logdir, user_task_id, attack_name, injection_task_id)
    raw_trace = json.loads(raw_path.read_text(encoding="utf-8"))
    relative_raw_path = raw_path.relative_to(PROJECT_ROOT).as_posix()
    api_request_attempts = get_google_request_attempt_count() - requests_before
    elapsed_seconds = time.monotonic() - started_at
    record = RunResult(
        run_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        domain=domain,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        payload_id=payload.id,
        channel=payload.channel,
        model=f"google-{PRIMARY_MODEL}",
        defense="none",
        # Despite its historical ``security`` name, AgentDojo returns True
        # exactly when the injection task was executed successfully.
        attack_success=attack_succeeded(security),
        tool_calls=raw_trace["messages"],
        notes=(
            f"injection_vector={injection_vector}; raw_trace={relative_raw_path}; "
            f"api_request_attempts={api_request_attempts}; elapsed_seconds={elapsed_seconds:.3f}; "
            "attack_success equals AgentDojo's injection-task success check"
        ),
    )
    RunResult.from_dict(record.__dict__, path="generated RunResult")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.__dict__, ensure_ascii=False) + "\n")
    return record


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="Print planned cases without invoking the API")
    parser.add_argument("--plan-output", type=Path, help="Optional TSV path for a no-API plan manifest")
    parser.add_argument(
        "--matrix",
        choices=("stratified", "full"),
        default="stratified",
        help="matrix breadth; stratified is the documented Phase 6 scope",
    )
    parser.add_argument("--max-runs", type=int, help="Stop after this many new task attempts")
    parser.add_argument(
        "--max-api-requests",
        type=int,
        help=(
            "Hard process-local Gemini request-attempt ceiling; the runner stops "
            "before starting a request beyond this budget"
        ),
    )
    parser.add_argument("--domain", action="append", choices=("workspace", "banking", "slack"), help="Restrict to a domain; repeatable")
    parser.add_argument("--payload-id", action="append", help="Restrict to a corpus payload ID; repeatable")
    parser.add_argument("--injection-task", action="append", help="Restrict to an AgentDojo injection task ID; repeatable")
    parser.add_argument("--results-path", type=Path, default=DEFAULT_OUTPUT, help="JSONL checkpoint/output path")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_runs is not None and args.max_runs < 1:
        raise SystemExit("--max-runs must be at least 1")
    if args.max_api_requests is not None and args.max_api_requests < 1:
        raise SystemExit("--max-api-requests must be at least 1")
    payloads = load_corpus()
    cases = list(
        iter_cases(
            payloads,
            domains=set(args.domain) if args.domain else None,
            payload_ids=set(args.payload_id) if args.payload_id else None,
            injection_tasks=set(args.injection_task) if args.injection_task else None,
            matrix=args.matrix,
        )
    )
    if args.plan:
        if args.plan_output:
            write_plan(cases, args.plan_output.resolve())
            print(f"Wrote plan manifest: {args.plan_output.resolve()}")
        print(f"Planned baseline cases: {len(cases)}")
        for payload, domain, vector, user_task_id, injection_task_id in cases:
            print(f"{payload.id}\t{domain}\t{payload.channel}\t{vector}\t{user_task_id}\t{injection_task_id}")
        return 0

    results_path = args.results_path.resolve()
    configure_google_request_attempt_limit(args.max_api_requests)
    completed = completed_cases(results_path)
    executed = 0
    session_requests_before = get_google_request_attempt_count()
    for payload, domain, vector, user_task_id, injection_task_id in cases:
        key = _case_key(payload.id, domain, vector, user_task_id, injection_task_id)
        if key in completed:
            print(f"Skipping checkpointed case: {key}")
            continue
        if args.max_runs is not None and executed >= args.max_runs:
            break
        try:
            record = execute_case(payload, domain, vector, user_task_id, injection_task_id, results_path)
        except (ClientError, RequestBudgetExceeded) as error:
            if not is_quota_exhausted(error):
                raise
            print(
                "Stopping cleanly: Google API quota/rate/request budget reached. "
                f"{executed} completed case(s) remain checkpointed in {results_path}. "
                f"This process started {get_google_request_attempt_count() - session_requests_before} "
                "Gemini request attempt(s).",
                file=sys.stderr,
            )
            return 2
        executed += 1
        print(
            f"Recorded {record.run_id}: payload={record.payload_id}, domain={record.domain}, "
            f"user={record.user_task_id}, injection={record.injection_task_id}, "
            f"attack_success={record.attack_success}"
        )
    print(f"Completed {executed} new baseline case(s); checkpoint: {results_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
