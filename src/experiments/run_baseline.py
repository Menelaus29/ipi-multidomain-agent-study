"""Run model-separated Phase 6 AgentDojo attacks, optionally with spotlighting.

The runner deliberately calls :func:`agentdojo.scripts.benchmark.benchmark_suite`
through Python rather than AgentDojo's CLI.  Its constructed Google AI Studio
client therefore bypasses AgentDojo's Vertex-AI-only model resolver.

Each corpus entry is paired only with benchmark injection vectors that expose
the entry's documented channel.  The raw AgentDojo trace remains in
the target-specific raw directory; this script adds a schema-validated JSONL
index with the benchmark injection-task verdict, payload metadata, and full
message trace. Gemini remains under ``data/baseline/``. Gemma 4 is isolated
under ``data/baseline_gemma4/`` and replays the committed Phase 6 110-case plan.

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

    # Inspect the exact 110-case Gemma parity replay (no API calls).
    python -m src.experiments.run_baseline --target gemma4-26b --plan

API execution additionally requires the shared Pacific-date/dashboard quota
arguments. ``--matrix full`` is never selected automatically.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from agentdojo.attacks.attack_registry import ATTACKS, register_attack
from agentdojo.attacks.base_attacks import BaseAttack
from agentdojo.models import ModelsEnum
from agentdojo.scripts.benchmark import benchmark_suite
from agentdojo.task_suite.load_suites import get_suite
from google.genai.errors import ClientError

from src.defenses.my_spotlighting import (
    DEFENSE_NAME as MY_SPOTLIGHTING,
    DEFENSE_VERSION as MY_SPOTLIGHTING_VERSION,
    MySpotlightingLLM,
    defense_source_sha256,
)
from src.llm_providers.google_llm_factory import (
    GEMMA4_26B_MODEL,
    GEMMA4_26B_PIPELINE_NAME,
    GEMMA4_26B_RPD_LIMIT,
    PRIMARY_MODEL,
    PRIMARY_PIPELINE_NAME,
    PRIMARY_RPD_LIMIT,
    RequestBudgetExceeded,
    get_google_gemma4_26b_llm,
    get_google_primary_llm,
    get_google_request_attempt_count,
)
from src.experiments.operation_journal import (
    UNEXPECTED_EXECUTION_EXIT_CODE,
    agentdojo_raw_trace_path,
    atomic_write_bytes,
    atomic_write_json,
    operation_exception_summary,
)
from src.experiments.quota_guard import add_quota_arguments, quota_guard_from_args
from src.schemas import PayloadEntry, RunResult, SchemaValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = PROJECT_ROOT / "src" / "payloads" / "corpus.json"
PHASE6_PLAN_PATH = PROJECT_ROOT / "data" / "baseline" / "plan.tsv"
GEMINI_BASELINE_ROOT = PROJECT_ROOT / "data" / "baseline"
GEMMA4_BASELINE_ROOT = PROJECT_ROOT / "data" / "baseline_gemma4"
CALIBRATED_BASELINE_ROOT = PROJECT_ROOT / "data" / "calibrated_baseline"
DEFENDED_ROOT = PROJECT_ROOT / "data" / "defended"
DEFAULT_OUTPUT = GEMINI_BASELINE_ROOT / "results.jsonl"
RAW_ROOT = GEMINI_BASELINE_ROOT / "raw"
BENCHMARK_VERSION = "v1.2.2"
WINDOWS_MAX_PATH = 260
WINDOWS_PATH_SAFETY_MARGIN = 20
DEFENSE_MODES = ("none", MY_SPOTLIGHTING)
MAX_RETRYABLE_CASE_RETRIES = 3
RETRY_QUEUE_FILENAME = "retry_queue.json"
RETRYABLE_CASES_PENDING_EXIT_CODE = 3


@dataclass(frozen=True)
class BaselineTarget:
    """One explicitly isolated model target for the shared Phase 6 harness."""

    cli_name: str
    model_name: str
    pipeline_name: str
    rpd_limit: int
    output_root: Path


GEMINI_TARGET = BaselineTarget(
    cli_name="gemini",
    model_name=PRIMARY_MODEL,
    pipeline_name=PRIMARY_PIPELINE_NAME,
    rpd_limit=PRIMARY_RPD_LIMIT,
    output_root=GEMINI_BASELINE_ROOT,
)
GEMMA4_TARGET = BaselineTarget(
    cli_name="gemma4-26b",
    model_name=GEMMA4_26B_MODEL,
    pipeline_name=GEMMA4_26B_PIPELINE_NAME,
    rpd_limit=GEMMA4_26B_RPD_LIMIT,
    output_root=GEMMA4_BASELINE_ROOT,
)
BASELINE_TARGETS = {
    target.cli_name: target for target in (GEMINI_TARGET, GEMMA4_TARGET)
}

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
        missing_vector_error: Callable[[str], Exception] = ValueError,
    ) -> None:
        super().__init__(task_suite, target_pipeline)
        self.payload = payload
        self.injection_vector = injection_vector
        self.missing_vector_error = missing_vector_error

    def attack(self, user_task: Any, injection_task: Any) -> dict[str, str]:
        candidates = self.get_injection_candidates(user_task)
        if self.injection_vector not in candidates:
            raise self.missing_vector_error(
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


class BenchmarkTraceError(RuntimeError):
    """Raised when AgentDojo wrote a skipped/errored trace, not a valid run."""

    def __init__(self, raw_path: Path | str, trace_error: object | None = None) -> None:
        # Calibration and clean-control modules import this exception and use
        # its historic one-string constructor.  The baseline retry path adds
        # the raw-path form so it can archive a retryable trace.
        if trace_error is None:
            self.raw_path = None
            self.trace_error = str(raw_path)
            super().__init__(self.trace_error)
            return
        self.raw_path = Path(raw_path)
        self.trace_error = str(trace_error)
        super().__init__(
            f"AgentDojo trace is errored/skipped, not a valid result: {self.raw_path}: "
            f"{self.trace_error}"
        )


class BaselinePreflightError(RuntimeError):
    """Raised before quota reservation when baseline inputs/paths are unsafe."""


def _stop_after_unexpected_execution(error: Exception) -> int:
    """Stop a checkpointed baseline run without continuing after an API-path error."""

    print(
        "Stopping baseline after an unexpected execution error: "
        f"{operation_exception_summary(error)}",
        file=sys.stderr,
    )
    return UNEXPECTED_EXECUTION_EXIT_CODE


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


def safe_attack_name(prefix: str, *parts: str) -> str:
    """Return a stable registry/file-system-safe AgentDojo attack name."""

    return re.sub(r"[^a-zA-Z0-9_-]+", "_", "_".join((prefix, *parts)))


def _attack_name(payload_id: str, injection_vector: str) -> str:
    """Return a stable registry/file-system-safe name for one attack variant."""
    return safe_attack_name("corpus", payload_id, injection_vector)


def register_vector_payload_attack(
    payload: PayloadEntry,
    injection_vector: str,
    *,
    name_prefix: str = "corpus",
    missing_vector_error: Callable[[str], Exception] = ValueError,
) -> str:
    """Register a payload bound to exactly one AgentDojo injection vector."""

    name = safe_attack_name(name_prefix, payload.id, injection_vector)

    class RegisteredCorpusPayloadAttack(CorpusPayloadAttack):
        def __init__(self, task_suite: Any, target_pipeline: Any) -> None:
            super().__init__(
                task_suite,
                target_pipeline,
                payload,
                injection_vector,
                missing_vector_error,
            )

    RegisteredCorpusPayloadAttack.name = name
    ATTACKS.pop(name, None)
    register_attack(RegisteredCorpusPayloadAttack)
    return name


def register_vector_template_attack(
    template: str,
    injection_vector: str,
    *,
    candidate_id: str,
    category: str,
    source: str,
    domains: Sequence[str],
    name_prefix: str,
    missing_vector_error: Callable[[str], Exception] = ValueError,
) -> str:
    """Register a goal-bound template on exactly one AgentDojo vector."""

    payload = PayloadEntry(
        id=candidate_id,
        category=category,
        channel="agentdojo_vector",
        domain=list(domains),
        template=template,
        source=source,
    )
    return register_vector_payload_attack(
        payload,
        injection_vector,
        name_prefix=name_prefix,
        missing_vector_error=missing_vector_error,
    )


def register_payload_attack(payload: PayloadEntry, injection_vector: str) -> str:
    """Register a parameterised AgentDojo attack and return its registry name."""
    return register_vector_payload_attack(payload, injection_vector)


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


def completed_cases(
    results_path: Path,
    *,
    expected_model: str | None = None,
    expected_defense: str | None = None,
    expected_split: str | None = None,
    expected_plan_sha256: str | None = None,
    expected_defense_version: str | None = None,
    expected_defense_sha256: str | None = None,
    expected_attack_sha256_by_case: Mapping[tuple[str, ...], str] | None = None,
) -> set[tuple[str, ...]]:
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
        if expected_model is not None and result.model != expected_model:
            raise SchemaValidationError(
                f"{results_path}:{line_number} has model {result.model!r}; "
                f"expected {expected_model!r}"
            )
        if expected_defense is not None and result.defense != expected_defense:
            raise SchemaValidationError(
                f"{results_path}:{line_number} has defense {result.defense!r}; "
                f"expected {expected_defense!r}"
            )
        vector = _vector_from_notes(result.notes)
        if vector is None:
            raise SchemaValidationError(f"{results_path}:{line_number} lacks an injection_vector note")
        key = _case_key(
            result.payload_id,
            result.domain,
            vector,
            result.user_task_id,
            result.injection_task_id,
        )
        for field, actual, expected in (
            ("split", result.split, expected_split),
            ("plan_sha256", result.plan_sha256, expected_plan_sha256),
            ("defense_version", result.defense_version, expected_defense_version),
            ("defense_sha256", result.defense_sha256, expected_defense_sha256),
        ):
            if expected is not None and actual != expected:
                raise SchemaValidationError(
                    f"{results_path}:{line_number} has {field} {actual!r}; "
                    f"expected {expected!r}"
                )
        if expected_attack_sha256_by_case is not None:
            expected_attack_sha256 = expected_attack_sha256_by_case.get(key)
            if expected_attack_sha256 is None:
                raise SchemaValidationError(
                    f"{results_path}:{line_number} is not present in the current ordered plan"
                )
            if result.attack_sha256 != expected_attack_sha256:
                raise SchemaValidationError(
                    f"{results_path}:{line_number} has attack_sha256 "
                    f"{result.attack_sha256!r}; expected {expected_attack_sha256!r}"
                )
        completed.add(key)
    return completed


def _vector_from_notes(notes: str) -> str | None:
    match = re.search(r"(?:^|;\s*)injection_vector=([^;]+)", notes)
    return match.group(1) if match else None


def _raw_trace_from_notes(notes: str) -> Path | None:
    match = re.search(r"(?:^|;\s*)raw_trace=([^;]+)", notes)
    if match is None:
        return None
    path = Path(match.group(1))
    return path if path.is_absolute() else PROJECT_ROOT / path


def ensure_completed_raw_trace(raw_trace: dict[str, Any], raw_path: Path) -> None:
    """Reject AgentDojo's synthetic verdicts for skipped API-error traces."""
    if raw_trace.get("error"):
        raise BenchmarkTraceError(raw_path, raw_trace["error"])


def is_retryable_agentdojo_trace_error(error: BenchmarkTraceError) -> bool:
    """Return whether an AgentDojo skipped trace records a provider HTTP 5xx."""

    return re.search(r"\b5\d{2}\b", error.trace_error) is not None


def retry_queue_path(results_path: Path) -> Path:
    """Keep invalid-but-retryable work beside its model-specific result index."""

    return results_path.parent / RETRY_QUEUE_FILENAME


def _retry_queue_case_key(
    payload: PayloadEntry,
    domain: str,
    injection_vector: str,
    user_task_id: str,
    injection_task_id: str,
) -> str:
    return "\t".join(
        (payload.id, domain, injection_vector, user_task_id, injection_task_id)
    )


def _load_retry_queue(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        queue = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselinePreflightError(f"retry queue is unreadable: {path}") from exc
    if not isinstance(queue, dict) or any(
        not isinstance(key, str) or not isinstance(value, dict)
        for key, value in queue.items()
    ):
        raise BaselinePreflightError(f"retry queue has invalid structure: {path}")
    return queue


def _write_retry_queue(path: Path, queue: dict[str, dict[str, Any]]) -> None:
    atomic_write_json(path, queue)


def archive_retryable_trace(
    *,
    results_path: Path,
    payload: PayloadEntry,
    domain: str,
    injection_vector: str,
    user_task_id: str,
    injection_task_id: str,
    error: BenchmarkTraceError,
) -> Path:
    """Preserve an invalid raw trace and durably leave its case in the retry queue."""

    if error.raw_path is None or not error.raw_path.is_file():
        raise BaselinePreflightError(
            f"retryable trace disappeared before archival: {error.raw_path}"
        )
    queue_path = retry_queue_path(results_path)
    queue = _load_retry_queue(queue_path)
    case_key = _retry_queue_case_key(
        payload, domain, injection_vector, user_task_id, injection_task_id
    )
    prior = queue.get(case_key, {})
    failures = prior.get("failure_count", 0)
    if not isinstance(failures, int) or failures < 0:
        raise BaselinePreflightError(
            f"retry queue has invalid failure_count for case {case_key!r}"
        )
    failure_count = failures + 1
    digest = hashlib.sha256(case_key.encode("utf-8")).hexdigest()
    archive_path = (
        results_path.parent
        / "retryable_traces"
        / digest
        / f"attempt-{failure_count}.json"
    )
    atomic_write_bytes(archive_path, error.raw_path.read_bytes(), refuse_changed=True)
    queue[case_key] = {
        "case": {
            "payload_id": payload.id,
            "domain": domain,
            "injection_vector": injection_vector,
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
        },
        "failure_count": failure_count,
        "last_error": error.trace_error,
        "last_raw_trace": str(error.raw_path.resolve()),
        "last_archived_trace": str(archive_path.resolve()),
        "last_failure_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
    }
    _write_retry_queue(queue_path, queue)
    return archive_path


def clear_retryable_case(
    results_path: Path,
    payload: PayloadEntry,
    domain: str,
    injection_vector: str,
    user_task_id: str,
    injection_task_id: str,
) -> None:
    """Remove a queue item only after a valid RunResult has been checkpointed."""

    queue_path = retry_queue_path(results_path)
    queue = _load_retry_queue(queue_path)
    case_key = _retry_queue_case_key(
        payload, domain, injection_vector, user_task_id, injection_task_id
    )
    if case_key in queue:
        del queue[case_key]
        _write_retry_queue(queue_path, queue)


def prune_errored_results(results_path: Path) -> int:
    """Atomically remove checkpoint rows whose referenced raw trace has an error."""
    if not results_path.exists():
        return 0
    retained_lines: list[str] = []
    removed = 0
    for line_number, line in enumerate(results_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            result = RunResult.from_dict(record, path=f"{results_path}:{line_number}")
        except (json.JSONDecodeError, SchemaValidationError) as exc:
            raise SchemaValidationError(f"Cannot repair invalid results file: {exc}") from exc
        raw_path = _raw_trace_from_notes(result.notes)
        if raw_path is None or not raw_path.is_file():
            raise SchemaValidationError(
                f"{results_path}:{line_number} has no readable raw_trace reference"
            )
        raw_trace = json.loads(raw_path.read_text(encoding="utf-8"))
        if raw_trace.get("error"):
            removed += 1
        else:
            retained_lines.append(line)
    if removed:
        temporary_path = results_path.with_suffix(results_path.suffix + ".tmp")
        temporary_path.write_text("\n".join(retained_lines) + "\n", encoding="utf-8")
        temporary_path.replace(results_path)
    return removed


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


def case_plan_sha256(
    cases: Sequence[tuple[PayloadEntry, str, str, str, str]],
) -> str:
    """Hash the exact ordered case manifest represented by this invocation."""

    handle = io.StringIO(newline="")
    writer = csv.writer(handle, delimiter="\t")
    writer.writerow(
        (
            "payload_id",
            "domain",
            "channel",
            "injection_vector",
            "user_task_id",
            "injection_task_id",
        )
    )
    for payload, domain, vector, user_task_id, injection_task_id in cases:
        writer.writerow(
            (
                payload.id,
                domain,
                payload.channel,
                vector,
                user_task_id,
                injection_task_id,
            )
        )
    return hashlib.sha256(handle.getvalue().encode("utf-8")).hexdigest()


def defended_attack_sha256_by_case(
    cases: Sequence[tuple[PayloadEntry, str, str, str, str]],
) -> dict[tuple[str, ...], str]:
    """Return the expected rendered-attack hash for every defended plan row."""

    suites: dict[str, Any] = {}
    hashes: dict[tuple[str, ...], str] = {}
    for payload, domain, vector, user_task_id, injection_task_id in cases:
        if domain not in suites:
            suites[domain] = get_suite(BENCHMARK_VERSION, domain)
        suite = suites[domain]
        injection_task = suite.injection_tasks.get(injection_task_id)
        if injection_task is None:
            raise BaselinePreflightError(
                f"unknown injection task {injection_task_id!r} for {domain!r}"
            )
        rendered_attack = render_payload(payload, injection_task.GOAL)
        key = _case_key(
            payload.id, domain, vector, user_task_id, injection_task_id
        )
        hashes[key] = hashlib.sha256(rendered_attack.encode("utf-8")).hexdigest()
    return hashes


def verify_expected_plan_sha256(
    cases: Sequence[tuple[PayloadEntry, str, str, str, str]],
    expected_sha256: str | None,
) -> str:
    """Reject execution when the regenerated ordered plan differs from a frozen plan."""

    actual_sha256 = case_plan_sha256(cases)
    if expected_sha256 is None:
        return actual_sha256
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise BaselinePreflightError(
            "--expected-plan-sha256 must be a lowercase 64-character SHA-256 digest"
        )
    if actual_sha256 != expected_sha256:
        raise BaselinePreflightError(
            "selected case plan does not match --expected-plan-sha256: "
            f"expected={expected_sha256}, actual={actual_sha256}"
        )
    return actual_sha256


def load_committed_phase6_plan(
    payloads: Sequence[PayloadEntry],
    path: Path = PHASE6_PLAN_PATH,
) -> list[tuple[PayloadEntry, str, str, str, str]]:
    """Load the exact committed 110-case Phase 6 manifest without replanning."""

    if not path.is_file():
        raise BaselinePreflightError(f"missing Phase 6 parity manifest: {path}")
    expected_fields = (
        "payload_id",
        "domain",
        "channel",
        "injection_vector",
        "user_task_id",
        "injection_task_id",
    )
    payload_by_id = {payload.id: payload for payload in payloads}
    cases: list[tuple[PayloadEntry, str, str, str, str]] = []
    seen: set[tuple[str, ...]] = set()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != expected_fields:
            raise BaselinePreflightError(
                f"{path} has unexpected columns: {reader.fieldnames}"
            )
        for line_number, row in enumerate(reader, start=2):
            if any(not isinstance(row[field], str) or not row[field] for field in expected_fields):
                raise BaselinePreflightError(f"{path}:{line_number} has an empty field")
            payload = payload_by_id.get(row["payload_id"])
            if payload is None:
                raise BaselinePreflightError(
                    f"{path}:{line_number} references unknown payload {row['payload_id']!r}"
                )
            domain = row["domain"]
            channel = row["channel"]
            vector = row["injection_vector"]
            if domain not in payload.domain or channel != payload.channel:
                raise BaselinePreflightError(
                    f"{path}:{line_number} conflicts with payload {payload.id!r} metadata"
                )
            if vector not in CHANNEL_VECTORS.get(domain, {}).get(channel, ()):
                raise BaselinePreflightError(
                    f"{path}:{line_number} has an incompatible injection vector"
                )
            key = _case_key(
                payload.id,
                domain,
                vector,
                row["user_task_id"],
                row["injection_task_id"],
            )
            if key in seen:
                raise BaselinePreflightError(f"{path}:{line_number} duplicates case {key}")
            seen.add(key)
            cases.append(
                (
                    payload,
                    domain,
                    vector,
                    row["user_task_id"],
                    row["injection_task_id"],
                )
            )
    counts = Counter(domain for _, domain, _, _, _ in cases)
    expected_counts = {"workspace": 52, "banking": 46, "slack": 12}
    if len(cases) != 110 or dict(counts) != expected_counts:
        raise BaselinePreflightError(
            f"{path} is not the committed 110-case Phase 6 manifest: "
            f"rows={len(cases)}, domains={dict(counts)}"
        )
    return cases


def _raw_trace_path(logdir: Path, user_task_id: str, attack_name: str, injection_task_id: str) -> Path:
    matches = list(logdir.rglob(f"{injection_task_id}.json"))
    expected = [path for path in matches if user_task_id in path.parts and attack_name in path.parts]
    if len(expected) != 1:
        raise FileNotFoundError(
            f"Expected one raw trace for user={user_task_id}, attack={attack_name}, "
            f"injection={injection_task_id}; found {len(expected)}"
        )
    return expected[0]


def get_target_llm(target: BaselineTarget) -> Any:
    """Construct the selected model through an existing named provider path."""

    if target == GEMINI_TARGET:
        return get_google_primary_llm()
    if target == GEMMA4_TARGET:
        return get_google_gemma4_26b_llm()
    raise BaselinePreflightError(f"unsupported baseline target: {target.cli_name}")


def target_results_path(
    target: BaselineTarget,
    matrix: str,
    requested: Path | None,
    defense: str = "none",
) -> Path:
    if requested is not None:
        return requested.resolve()
    if defense == "none":
        matrix_root = (
            target.output_root
            if matrix == "stratified"
            else target.output_root / "full"
        )
    else:
        matrix_root = defended_target_root(target)
        if matrix == "full":
            matrix_root /= "full"
    return (matrix_root / "results.jsonl").resolve()


def target_raw_root(
    target: BaselineTarget,
    matrix: str,
    defense: str = "none",
    requested_results: Path | None = None,
) -> Path:
    if defense == "none":
        matrix_root = (
            target.output_root
            if matrix == "stratified"
            else target.output_root / "full"
        )
    elif requested_results is not None:
        matrix_root = requested_results.resolve().parent
    else:
        matrix_root = defended_target_root(target)
        if matrix == "full":
            matrix_root /= "full"
    # The one-letter Gemma trace component retains a 20+ character margin
    # beneath legacy Windows MAX_PATH after AgentDojo appends its full nested
    # model/suite/task/attack path. Gemini keeps its immutable Phase 6 layout.
    raw_component = "r" if target == GEMMA4_TARGET else "raw"
    return (matrix_root / raw_component).resolve()


def defended_target_root(target: BaselineTarget) -> Path:
    """Return a short, model-separated root that stays below Windows MAX_PATH."""

    target_slug = "g4" if target == GEMMA4_TARGET else "g35"
    return DEFENDED_ROOT / target_slug / MY_SPOTLIGHTING_VERSION


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def validate_output_isolation(
    target: BaselineTarget,
    results_path: Path,
    defense: str = "none",
) -> None:
    """Prevent Gemini, calibrated, and Gemma rows from sharing a dataset."""

    resolved = results_path.resolve()
    if defense != "none":
        expected_root = defended_target_root(target)
        if not _is_relative_to(resolved, expected_root):
            raise BaselinePreflightError(
                f"{target.model_name} defended output must remain below "
                f"{expected_root}: {resolved}"
            )
        return
    if target == GEMMA4_TARGET:
        if not _is_relative_to(resolved, GEMMA4_BASELINE_ROOT):
            raise BaselinePreflightError(
                "Gemma baseline output must remain below "
                f"{GEMMA4_BASELINE_ROOT}: {resolved}"
            )
        if _is_relative_to(resolved, GEMINI_BASELINE_ROOT) or _is_relative_to(
            resolved, CALIBRATED_BASELINE_ROOT
        ):
            raise BaselinePreflightError(
                "Gemma baseline output cannot enter a Gemini dataset directory"
            )
    elif _is_relative_to(resolved, GEMMA4_BASELINE_ROOT):
        raise BaselinePreflightError(
            "Gemini baseline output cannot enter the Gemma dataset directory"
        )


def expected_agentdojo_trace_path(
    case: tuple[PayloadEntry, str, str, str, str],
    *,
    target: BaselineTarget,
    raw_root: Path,
) -> Path:
    payload, domain, vector, user_task_id, injection_task_id = case
    return agentdojo_raw_trace_path(
        raw_root / domain,
        pipeline_name=target.pipeline_name,
        suite_name=domain,
        user_task_id=user_task_id,
        attack_name=_attack_name(payload.id, vector),
        injection_task_id=injection_task_id,
    )


def preflight_trace_paths(
    cases: Sequence[tuple[PayloadEntry, str, str, str, str]],
    *,
    target: BaselineTarget,
    raw_root: Path,
) -> int:
    """Validate every deterministic raw path before quota reservation/API use."""

    if not cases:
        raise BaselinePreflightError("baseline plan cannot be empty")
    longest = max(
        (
            expected_agentdojo_trace_path(case, target=target, raw_root=raw_root)
            for case in cases
        ),
        key=lambda path: len(str(path.resolve())),
    )
    length = len(str(longest.resolve()))
    if os.name == "nt" and length + WINDOWS_PATH_SAFETY_MARGIN >= WINDOWS_MAX_PATH:
        raise BaselinePreflightError(
            "baseline raw trace lacks the required Windows MAX_PATH margin: "
            f"length={length}, margin={WINDOWS_PATH_SAFETY_MARGIN}, path={longest.resolve()}"
        )
    return length


def execute_case(
    payload: PayloadEntry,
    domain: str,
    injection_vector: str,
    user_task_id: str,
    injection_task_id: str,
    results_path: Path,
    *,
    target: BaselineTarget = GEMINI_TARGET,
    raw_root: Path = RAW_ROOT,
    force_rerun: bool = False,
    defense: str = "none",
    split: str | None = None,
    plan_sha256: str | None = None,
    defense_sha256: str | None = None,
) -> RunResult:
    """Run one AgentDojo task attempt and append its validated JSONL record."""
    is_defended = defense == MY_SPOTLIGHTING
    if is_defended:
        if split not in {"dev", "holdout"}:
            raise BaselinePreflightError(
                "my_spotlighting execution requires split='dev' or split='holdout'"
            )
        if plan_sha256 is None or re.fullmatch(r"[0-9a-f]{64}", plan_sha256) is None:
            raise BaselinePreflightError(
                "my_spotlighting execution requires the ordered plan SHA-256"
            )
        if defense_sha256 is None:
            defense_sha256 = defense_source_sha256()
        if re.fullmatch(r"[0-9a-f]{64}", defense_sha256) is None:
            raise BaselinePreflightError(
                "my_spotlighting execution requires a valid defense SHA-256"
            )
    elif defense != "none":
        raise BaselinePreflightError(f"unsupported defense mode: {defense!r}")
    elif any(value is not None for value in (split, plan_sha256, defense_sha256)):
        raise BaselinePreflightError(
            "undefended execution must not receive defended-run provenance"
        )

    suite = get_suite(BENCHMARK_VERSION, domain)
    attack_name = register_payload_attack(payload, injection_vector)
    # AgentDojo's injection-task utility traces use the "none" attack path.
    # Sharing a domain root lets later payload cases reuse those completed
    # native-task checks while their distinct attack names keep raw attack
    # traces separate.
    logdir = raw_root / domain
    # Construct a fresh explicit target LLM per task. No fallback/testing
    # factory is used anywhere in either recorded baseline path.
    requests_before = get_google_request_attempt_count()
    started_at = time.monotonic()
    target_llm = get_target_llm(target)
    if is_defended:
        target_llm = MySpotlightingLLM(target_llm)
    results = benchmark_suite(
        suite=suite,
        # AgentDojo's runtime accepts a constructed BasePipelineElement here,
        # although its installed annotation is still limited to ModelsEnum.
        model=cast(ModelsEnum, target_llm),
        logdir=logdir,
        force_rerun=force_rerun,
        benchmark_version=BENCHMARK_VERSION,
        user_tasks=(user_task_id,),
        injection_tasks=(injection_task_id,),
        attack=attack_name,
    )
    security = results["security_results"][(user_task_id, injection_task_id)]
    raw_path = _raw_trace_path(logdir, user_task_id, attack_name, injection_task_id)
    raw_trace = json.loads(raw_path.read_text(encoding="utf-8"))
    ensure_completed_raw_trace(raw_trace, raw_path)
    relative_raw_path = raw_path.relative_to(PROJECT_ROOT).as_posix()
    api_request_attempts = get_google_request_attempt_count() - requests_before
    elapsed_seconds = time.monotonic() - started_at
    rendered_attack = (
        render_payload(payload, suite.injection_tasks[injection_task_id].GOAL)
        if is_defended
        else None
    )
    attack_sha256 = (
        hashlib.sha256(rendered_attack.encode("utf-8")).hexdigest()
        if rendered_attack is not None
        else None
    )
    record = RunResult(
        run_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        domain=domain,
        user_task_id=user_task_id,
        injection_task_id=injection_task_id,
        payload_id=payload.id,
        channel=payload.channel,
        model=f"google-{target.model_name}",
        defense=defense,
        # Despite its historical ``security`` name, AgentDojo returns True
        # exactly when the injection task was executed successfully.
        attack_success=attack_succeeded(security),
        tool_calls=raw_trace["messages"],
        notes=(
            f"injection_vector={injection_vector}; raw_trace={relative_raw_path}; "
            f"api_request_attempts={api_request_attempts}; elapsed_seconds={elapsed_seconds:.3f}; "
            "attack_success equals AgentDojo's injection-task success check"
        ),
        # AgentDojo computes native legitimate-task utility for both defended
        # and undefended injected runs. Preserve that verdict in every new
        # index row; legacy baseline artifacts that serialized null remain
        # valid and immutable.
        utility_success=results["utility_results"][(user_task_id, injection_task_id)],
        split=split if is_defended else None,
        attack_set_version="static-corpus-v1" if is_defended else None,
        attack_sha256=attack_sha256,
        plan_sha256=plan_sha256 if is_defended else None,
        defense_version=MY_SPOTLIGHTING_VERSION if is_defended else None,
        defense_sha256=defense_sha256 if is_defended else None,
    )
    RunResult.from_dict(record.__dict__, path="generated RunResult")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.__dict__, ensure_ascii=False) + "\n")
    return record


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=tuple(BASELINE_TARGETS),
        default=GEMINI_TARGET.cli_name,
        help="explicit model-separated target; defaults to the original Gemini baseline",
    )
    parser.add_argument(
        "--defense",
        choices=DEFENSE_MODES,
        default="none",
        help="select the additive custom defense; defaults to the unchanged undefended path",
    )
    parser.add_argument(
        "--split",
        choices=("dev", "holdout"),
        help=(
            "required for defended API execution so development validation and "
            "held-out evaluation cannot be conflated"
        ),
    )
    parser.add_argument("--plan", action="store_true", help="Print planned cases without invoking the API")
    parser.add_argument("--plan-output", type=Path, help="Optional TSV path for a no-API plan manifest")
    parser.add_argument(
        "--expected-plan-sha256",
        help=(
            "Require the exact ordered selected-case SHA-256 before planning or API execution; "
            "used to bind a live run to a frozen manifest"
        ),
    )
    parser.add_argument(
        "--matrix",
        choices=("stratified", "full"),
        default="stratified",
        help="matrix breadth; stratified is the documented Phase 6 scope",
    )
    parser.add_argument("--max-runs", type=int, help="Stop after this many new task attempts")
    parser.add_argument(
        "--force-rerun",
        action="store_true",
        help="Rerun non-checkpointed AgentDojo traces even if a raw cache file exists",
    )
    parser.add_argument(
        "--max-case-retries",
        type=int,
        default=MAX_RETRYABLE_CASE_RETRIES,
        help=(
            "bounded forced reruns after a retryable AgentDojo 5xx trace "
            f"(default: {MAX_RETRYABLE_CASE_RETRIES}; every retry consumes quota)"
        ),
    )
    parser.add_argument(
        "--prune-errored-results",
        action="store_true",
        help="Remove checkpoint rows backed by errored AgentDojo traces before resuming",
    )
    parser.add_argument("--domain", action="append", choices=("workspace", "banking", "slack"), help="Restrict to a domain; repeatable")
    parser.add_argument("--payload-id", action="append", help="Restrict to a corpus payload ID; repeatable")
    parser.add_argument("--injection-task", action="append", help="Restrict to an AgentDojo injection task ID; repeatable")
    parser.add_argument(
        "--results-path",
        type=Path,
        help="JSONL checkpoint/output path (target-specific default when omitted)",
    )
    add_quota_arguments(parser, required=False)
    return parser.parse_args(argv)


def select_cases(
    args: argparse.Namespace,
    payloads: Sequence[PayloadEntry],
    target: BaselineTarget,
) -> list[tuple[PayloadEntry, str, str, str, str]]:
    """Select cases while making Gemma parity consume the committed manifest."""

    if target == GEMMA4_TARGET and args.matrix == "stratified":
        cases = load_committed_phase6_plan(payloads)
        domains = set(args.domain) if args.domain else None
        payload_ids = set(args.payload_id) if args.payload_id else None
        injection_tasks = set(args.injection_task) if args.injection_task else None
        return [
            case
            for case in cases
            if (domains is None or case[1] in domains)
            and (payload_ids is None or case[0].id in payload_ids)
            and (injection_tasks is None or case[4] in injection_tasks)
        ]
    return list(
        iter_cases(
            payloads,
            domains=set(args.domain) if args.domain else None,
            payload_ids=set(args.payload_id) if args.payload_id else None,
            injection_tasks=set(args.injection_task) if args.injection_task else None,
            matrix=args.matrix,
        )
    )


def run_cases(
    args: argparse.Namespace,
    cases: Sequence[tuple[PayloadEntry, str, str, str, str]],
    *,
    target: BaselineTarget,
    results_path: Path,
    raw_root: Path,
) -> int:
    """Execute checkpointed cases inside an already-entered quota guard."""

    if args.prune_errored_results:
        removed = prune_errored_results(results_path)
        print(f"Pruned {removed} errored/skipped checkpoint row(s) from {results_path}")
    is_defended = args.defense == MY_SPOTLIGHTING
    plan_sha256 = case_plan_sha256(cases) if is_defended else None
    current_defense_sha256 = defense_source_sha256() if is_defended else None
    completed_kwargs: dict[str, Any] = {
        "expected_model": f"google-{target.model_name}"
    }
    if is_defended:
        completed_kwargs.update(
            {
                "expected_defense": args.defense,
                "expected_split": args.split,
                "expected_plan_sha256": plan_sha256,
                "expected_defense_version": MY_SPOTLIGHTING_VERSION,
                "expected_defense_sha256": current_defense_sha256,
                "expected_attack_sha256_by_case": defended_attack_sha256_by_case(
                    cases
                ),
            }
        )
    completed = completed_cases(results_path, **completed_kwargs)
    executed = 0
    deferred_retryable_cases = 0
    session_requests_before = get_google_request_attempt_count()
    for payload, domain, vector, user_task_id, injection_task_id in cases:
        key = _case_key(payload.id, domain, vector, user_task_id, injection_task_id)
        if key in completed:
            print(f"Skipping checkpointed case: {key}")
            continue
        if args.max_runs is not None and executed >= args.max_runs:
            break
        case_retries = 0
        force_rerun = args.force_rerun
        while True:
            try:
                execution_kwargs: dict[str, Any] = {}
                if is_defended:
                    execution_kwargs = {
                        "defense": args.defense,
                        "split": args.split,
                        "plan_sha256": plan_sha256,
                        "defense_sha256": current_defense_sha256,
                    }
                record = execute_case(
                    payload,
                    domain,
                    vector,
                    user_task_id,
                    injection_task_id,
                    results_path,
                    target=target,
                    raw_root=raw_root,
                    force_rerun=force_rerun,
                    **execution_kwargs,
                )
            except (ClientError, RequestBudgetExceeded) as error:
                if is_quota_exhausted(error):
                    print(
                        "Stopping cleanly: Google API quota/rate/request budget reached. "
                        f"{executed} completed case(s) remain checkpointed in {results_path}. "
                        f"This process started {get_google_request_attempt_count() - session_requests_before} "
                        f"{target.model_name} request attempt(s).",
                        file=sys.stderr,
                    )
                    return 2
                return _stop_after_unexpected_execution(error)
            except BenchmarkTraceError as error:
                if not is_retryable_agentdojo_trace_error(error):
                    print(
                        "Stopping cleanly: AgentDojo produced a non-retryable errored/skipped "
                        f"trace; no RunResult was appended. {error}",
                        file=sys.stderr,
                    )
                    return RETRYABLE_CASES_PENDING_EXIT_CODE
                archive_path = archive_retryable_trace(
                    results_path=results_path,
                    payload=payload,
                    domain=domain,
                    injection_vector=vector,
                    user_task_id=user_task_id,
                    injection_task_id=injection_task_id,
                    error=error,
                )
                if case_retries >= args.max_case_retries:
                    deferred_retryable_cases += 1
                    print(
                        "Deferred retryable AgentDojo 5xx trace after "
                        f"{case_retries} forced retry/retries: {key}; archived={archive_path}",
                        file=sys.stderr,
                    )
                    break
                case_retries += 1
                force_rerun = True
                print(
                    "Retrying retryable AgentDojo 5xx trace "
                    f"({case_retries}/{args.max_case_retries}): {key}; archived={archive_path}",
                    file=sys.stderr,
                )
                continue
            except Exception as error:
                return _stop_after_unexpected_execution(error)
            clear_retryable_case(
                results_path,
                payload,
                domain,
                vector,
                user_task_id,
                injection_task_id,
            )
            executed += 1
            print(
                f"Recorded {record.run_id}: payload={record.payload_id}, domain={record.domain}, "
                f"user={record.user_task_id}, injection={record.injection_task_id}, "
                f"attack_success={record.attack_success}"
            )
            break
    print(f"Completed {executed} new baseline case(s); checkpoint: {results_path}")
    if deferred_retryable_cases:
        print(
            f"{deferred_retryable_cases} case(s) remain in {retry_queue_path(results_path)}; "
            "resume with fresh quota inputs to retry them.",
            file=sys.stderr,
        )
        return RETRYABLE_CASES_PENDING_EXIT_CODE
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_runs is not None and args.max_runs < 1:
        raise SystemExit("--max-runs must be at least 1")
    if args.max_case_retries < 0:
        raise SystemExit("--max-case-retries cannot be negative")
    if args.defense == "none" and args.split is not None:
        raise SystemExit("--split is valid only with a defended run")
    if args.defense != "none" and not args.plan and args.split is None:
        raise SystemExit("defended API execution requires --split dev or --split holdout")
    target = BASELINE_TARGETS[args.target]
    payloads = load_corpus()
    cases = select_cases(args, payloads, target)
    selected_plan_sha256 = verify_expected_plan_sha256(
        cases, args.expected_plan_sha256
    )
    if args.plan:
        if args.plan_output:
            write_plan(cases, args.plan_output.resolve())
            print(f"Wrote plan manifest: {args.plan_output.resolve()}")
        print(f"Planned baseline cases: {len(cases)}")
        print(f"Ordered plan SHA-256: {selected_plan_sha256}")
        for payload, domain, vector, user_task_id, injection_task_id in cases:
            print(f"{payload.id}\t{domain}\t{payload.channel}\t{vector}\t{user_task_id}\t{injection_task_id}")
        return 0

    results_path = target_results_path(
        target, args.matrix, args.results_path, args.defense
    )
    raw_root = target_raw_root(
        target, args.matrix, args.defense, args.results_path
    )
    validate_output_isolation(target, results_path, args.defense)
    longest_path = preflight_trace_paths(cases, target=target, raw_root=raw_root)
    print(
        f"Baseline preflight: target={target.model_name}, cases={len(cases)}, "
        f"longest_trace_path={longest_path}, windows_margin={WINDOWS_PATH_SAFETY_MARGIN}"
    )
    with quota_guard_from_args(
        args,
        quota_key=target.model_name,
        study_rpd_limit=target.rpd_limit,
    ):
        exit_code = run_cases(
            args,
            cases,
            target=target,
            results_path=results_path,
            raw_root=raw_root,
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
