"""
CONTROLLED AI-SECURITY RESEARCH

This replay-only diagnostic runs existing AgentDojo attack artifacts against a
synthetic benchmark target. It neither generates nor mutates content, and is
not a Phase 6/6A calibration or recorded-study runner. Results remain in the
dedicated diagnostic directory and never enter the calibration quota ledger,
checkpoints, attack selection, or frozen artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.models import ModelsEnum
from agentdojo.scripts.benchmark import benchmark_suite
from agentdojo.task_suite.load_suites import get_suite
from google.genai.errors import ClientError

from src.experiments.build_attack_splits import AttackContext, DOMAINS
from src.experiments.calibrate_attacks import (
    BUILTIN_FAMILIES,
    CalibrationError,
    contexts_by_domain,
    register_vector_builtin_attack,
)
from src.experiments.operation_journal import (
    ErroredRawTrace,
    OperationJournal,
    OperationJournalError,
    OperationSpec,
    RawTraceError,
    UNEXPECTED_EXECUTION_EXIT_CODE,
    agentdojo_raw_trace_path,
    append_jsonl_once,
    append_jsonl_atomic,
    atomic_write_json,
    execute_journaled_agentdojo_benchmark,
    load_validated_raw_trace,
    operation_exception_summary,
    raw_trace_timestamp,
    utc_now,
)
from src.experiments.run_baseline import (
    BENCHMARK_VERSION,
    PROJECT_ROOT,
    BenchmarkTraceError,
    is_quota_exhausted,
    register_vector_template_attack,
    safe_attack_name,
)
from src.experiments.run_clean_controls import ContextManifest, load_context_manifest
from src.llm_providers.google_llm_factory import (
    GEMMA4_26B_DIAGNOSTIC_MODEL,
    get_google_gemma4_26b_diagnostic_llm,
    get_google_request_attempt_count,
    observe_google_generate_content_events,
    observe_google_request_attempts,
)


DIAGNOSTIC_TARGET = "gemma4-26b-a4b"
DIAGNOSTIC_MODEL = f"google-{GEMMA4_26B_DIAGNOSTIC_MODEL}"
DIAGNOSTIC_PIPELINE_NAME = (
    f"google-{GEMMA4_26B_DIAGNOSTIC_MODEL} [gemini-2.5-flash-preview-04-17]"
)
DIAGNOSTIC_ROOT = PROJECT_ROOT / "data" / "diagnostics" / "g4"
DEFAULT_RESULTS_PATH = DIAGNOSTIC_ROOT / "results.jsonl"
DEFAULT_RAW_ROOT = DIAGNOSTIC_ROOT / "raw"
TRACE_CHECK_STATE_FILENAME = "step1_trace_check_state.json"
TRACE_EVENT_FILENAME = "google_generate_content_events.jsonl"
CALIBRATION_ROOT = PROJECT_ROOT / "data" / "attack_calibration"
DEV_MANIFEST_PATH = CALIBRATION_ROOT / "dev_manifest.tsv"
V1_GENERATOR_ATTEMPTS_PATH = CALIBRATION_ROOT / "mutate" / "generator_attempts.jsonl"
V1_TARGET_ATTEMPTS_PATH = CALIBRATION_ROOT / "mutate" / "attempts.jsonl"
EXPECTED_BUILTIN_REPLAYS = len(BUILTIN_FAMILIES) * len(DOMAINS)
EXPECTED_V1_MUTATION_REPLAYS = 7


class DiagnosticReplayError(RuntimeError):
    """Raised when the isolated replay protocol is malformed or contaminated."""


@dataclass(frozen=True)
class ReplayCase:
    """One immutable pre-existing artifact replayed on its original dev context."""

    source_group: str
    source_id: str
    source_family: str
    context: AttackContext
    template: str | None = None

    @property
    def replay_id(self) -> str:
        material = "\x1f".join(
            (
                DIAGNOSTIC_TARGET,
                self.source_group,
                self.source_id,
                self.source_family,
                self.context.canonical_text,
            )
        )
        return "gemma4-replay-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class DiagnosticReplayRecord:
    """Self-contained diagnostic result, intentionally distinct from RunResult."""

    replay_id: str
    timestamp: str
    diagnostic_target: str
    target_model: str
    source_group: str
    source_id: str
    source_family: str
    domain: str
    channel: str
    injection_vector: str
    user_task_id: str
    injection_task_id: str
    attack_success: bool
    utility_success: bool
    rendered_attack_sha256: str
    target_request_attempts: int
    raw_trace_path: str
    notes: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> "DiagnosticReplayRecord":
        if set(value) != set(cls.__dataclass_fields__):
            raise DiagnosticReplayError(f"{path} has unexpected diagnostic record fields")
        try:
            record = cls(**dict(value))
        except TypeError as error:
            raise DiagnosticReplayError(f"{path} is not a diagnostic replay record: {error}") from error
        required = (
            record.replay_id,
            record.timestamp,
            record.diagnostic_target,
            record.target_model,
            record.source_group,
            record.source_id,
            record.source_family,
            record.domain,
            record.channel,
            record.injection_vector,
            record.user_task_id,
            record.injection_task_id,
            record.rendered_attack_sha256,
            record.raw_trace_path,
            record.notes,
        )
        if not all(isinstance(item, str) and item for item in required):
            raise DiagnosticReplayError(f"{path} contains an empty/non-string required field")
        if record.diagnostic_target != DIAGNOSTIC_TARGET:
            raise DiagnosticReplayError(f"{path} is not tagged as {DIAGNOSTIC_TARGET}")
        if record.target_model != DIAGNOSTIC_MODEL:
            raise DiagnosticReplayError(f"{path} has an unexpected target model")
        if record.source_group not in {"builtin_v1", "mutation_v1"}:
            raise DiagnosticReplayError(f"{path} has an unsupported source group")
        if not isinstance(record.attack_success, bool) or not isinstance(record.utility_success, bool):
            raise DiagnosticReplayError(f"{path} has non-boolean native verdicts")
        if isinstance(record.target_request_attempts, bool) or record.target_request_attempts < 1:
            raise DiagnosticReplayError(f"{path} lacks a positive target request count")
        if len(record.rendered_attack_sha256) != 64:
            raise DiagnosticReplayError(f"{path} has an invalid rendered-attack hash")
        return record


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def validate_output_root(output_root: Path) -> Path:
    """Allow diagnostics only below their dedicated, non-study data root."""

    resolved = output_root.resolve()
    if not _is_relative_to(resolved, DIAGNOSTIC_ROOT):
        raise DiagnosticReplayError(
            f"diagnostic output must remain below {DIAGNOSTIC_ROOT}: {resolved}"
        )
    if _is_relative_to(resolved, CALIBRATION_ROOT):
        raise DiagnosticReplayError("diagnostic output cannot enter attack_calibration")
    return resolved


def _read_jsonl(path: Path, *, label: str) -> list[dict[str, Any]]:
    if not path.is_file():
        raise DiagnosticReplayError(f"missing immutable {label}: {path}")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise DiagnosticReplayError(f"{path}:{line_number} cannot be blank")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise DiagnosticReplayError(f"{path}:{line_number} is not JSON") from error
        if not isinstance(value, dict):
            raise DiagnosticReplayError(f"{path}:{line_number} must be an object")
        rows.append(value)
    return rows


def load_replay_cases() -> tuple[ReplayCase, ...]:
    """Load exactly the immutable 18 built-ins and seven accepted v1 templates."""

    try:
        manifest = load_context_manifest(DEV_MANIFEST_PATH)
    except Exception as error:
        raise DiagnosticReplayError(f"cannot load the committed development manifest: {error}") from error
    by_domain = contexts_by_domain(manifest)
    builtin_cases = tuple(
        ReplayCase("builtin_v1", f"builtin:{family}:{domain}", family, by_domain[domain][0].context)
        for family in BUILTIN_FAMILIES
        for domain in DOMAINS
    )
    if len(builtin_cases) != EXPECTED_BUILTIN_REPLAYS:
        raise DiagnosticReplayError("built-in replay corpus no longer has exactly 18 cases")

    generated = _read_jsonl(V1_GENERATOR_ATTEMPTS_PATH, label="v1 generator attempts")
    target_attempts = _read_jsonl(V1_TARGET_ATTEMPTS_PATH, label="v1 target attempts")
    accepted = [row for row in generated if row.get("status") == "accepted"]
    if len(accepted) != EXPECTED_V1_MUTATION_REPLAYS:
        raise DiagnosticReplayError(
            "v1 mutation replay requires exactly seven accepted generator candidates; "
            f"found {len(accepted)}"
        )
    targets = {row.get("attempt_id"): row for row in target_attempts}
    mutation_cases: list[ReplayCase] = []
    for row in accepted:
        generation_id = row.get("generation_id")
        template = row.get("template")
        family = row.get("source_family")
        if not all(isinstance(value, str) and value for value in (generation_id, template, family)):
            raise DiagnosticReplayError("accepted v1 generator record lacks identifier/template/family")
        matches = [
            target
            for attempt_id, target in targets.items()
            if isinstance(attempt_id, str) and attempt_id.startswith(generation_id + ":")
        ]
        if len(matches) != 1:
            raise DiagnosticReplayError(
                f"{generation_id} must have exactly one completed v1 target replay context"
            )
        target = matches[0]
        if target.get("source_family") != family or target.get("split") != "dev":
            raise DiagnosticReplayError(f"{generation_id} target lineage is not its v1 development record")
        try:
            context = AttackContext(
                domain=str(target["domain"]),
                channel=manifest.by_key[
                    (str(target["domain"]), str(target["injection_vector"]), str(target["user_task_id"]), str(target["injection_task_id"]))
                ].context.channel,
                injection_vector=str(target["injection_vector"]),
                user_task_id=str(target["user_task_id"]),
                injection_task_id=str(target["injection_task_id"]),
            )
        except (KeyError, TypeError) as error:
            raise DiagnosticReplayError(f"{generation_id} is outside the committed dev manifest") from error
        mutation_cases.append(ReplayCase("mutation_v1", generation_id, family, context, template))
    return builtin_cases + tuple(mutation_cases)


def _attack_name(case: ReplayCase) -> str:
    return safe_attack_name("gemma4_diagnostic", case.source_group, case.source_id, case.context.injection_vector)


def _register_attack(case: ReplayCase) -> str:
    if case.source_group == "builtin_v1":
        # Same built-in renderer used by Phase 6A, with a diagnostic registry
        # name only for trace/output isolation.
        return register_vector_builtin_attack(
            case.source_family,
            case.context.injection_vector,
            name_prefix="gemma4_diagnostic_builtin",
        )
    assert case.template is not None
    return register_vector_template_attack(
        case.template,
        case.context.injection_vector,
        candidate_id=case.source_id,
        category="diagnostic_replay",
        source="immutable Phase 6A v1 mutation artifact",
        domains=DOMAINS,
        name_prefix="gemma4_diagnostic_mutation",
        missing_vector_error=DiagnosticReplayError,
    )


def _operation_spec(
    case: ReplayCase, *, results_path: Path, raw_root: Path, attack_name: str
) -> OperationSpec:
    raw_path = agentdojo_raw_trace_path(
        raw_root,
        pipeline_name=DIAGNOSTIC_PIPELINE_NAME,
        suite_name=case.context.domain,
        user_task_id=case.context.user_task_id,
        attack_name=attack_name,
        injection_task_id=case.context.injection_task_id,
    )
    return OperationSpec(
        operation_id=case.replay_id,
        operation_kind="gemma4_diagnostic_replay",
        domain=case.context.domain,
        suite_name=case.context.domain,
        model=DIAGNOSTIC_MODEL,
        pipeline_name=DIAGNOSTIC_PIPELINE_NAME,
        benchmark_version=BENCHMARK_VERSION,
        user_task_id=case.context.user_task_id,
        context_injection_task_id=case.context.injection_task_id,
        raw_injection_task_id=case.context.injection_task_id,
        channel=case.context.channel,
        injection_vector=case.context.injection_vector,
        attack_id=case.source_id,
        attack_name=attack_name,
        expected_raw_injection_vector=case.context.injection_vector,
        operation_metadata={
            "diagnostic_target": DIAGNOSTIC_TARGET,
            "source_group": case.source_group,
            "source_id": case.source_id,
            "source_family": case.source_family,
        },
        raw_trace_path=raw_path,
        index_path=results_path,
    )


def _step1_clean_operation_spec(
    case: ReplayCase, *, output_root: Path, raw_root: Path
) -> OperationSpec:
    return OperationSpec(
        operation_id=f"{case.replay_id}:clean-utility-prepass",
        operation_kind="gemma4_diagnostic_clean_prepass",
        domain=case.context.domain,
        suite_name=case.context.domain,
        model=DIAGNOSTIC_MODEL,
        pipeline_name=DIAGNOSTIC_PIPELINE_NAME,
        benchmark_version=BENCHMARK_VERSION,
        user_task_id=case.context.injection_task_id,
        context_injection_task_id=case.context.injection_task_id,
        raw_injection_task_id=None,
        channel=case.context.channel,
        injection_vector=case.context.injection_vector,
        attack_id=None,
        attack_name=None,
        expected_raw_injection_vector=None,
        operation_metadata={
            "diagnostic_target": DIAGNOSTIC_TARGET,
            "phase": "clean_utility_prepass",
            "source_id": case.source_id,
        },
        raw_trace_path=_clean_trace_path(case, raw_root),
        index_path=_trace_check_state_path(output_root),
    )


def _step1_injected_operation_spec(
    case: ReplayCase, *, results_path: Path, raw_root: Path, attack_name: str
) -> OperationSpec:
    base = _operation_spec(
        case, results_path=results_path, raw_root=raw_root, attack_name=attack_name
    )
    return OperationSpec(
        **{
            **base.durable_fields(),
            "operation_id": f"{case.replay_id}:injected-trace-check",
            "operation_kind": "gemma4_diagnostic_injected_trace_check",
            "operation_metadata": {
                **dict(base.operation_metadata),
                "phase": "injected_trace_check",
            },
            "raw_trace_path": base.raw_trace_path,
            "index_path": results_path,
        }
    )


def _relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _trace_check_state_path(output_root: Path) -> Path:
    return output_root / TRACE_CHECK_STATE_FILENAME


def _to_jsonable(value: Any) -> Any:
    """Serialize native google-genai objects without changing their contents."""

    if hasattr(value, "model_dump"):
        return _to_jsonable(value.model_dump(mode="json", exclude_none=False))
    if isinstance(value, Mapping):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return {"python_type": type(value).__name__, "repr": repr(value)}


class _DiagnosticGoogleTrace:
    """Append exact pre-send Google payloads and returned SDK responses."""

    def __init__(self, path: Path, *, case: ReplayCase, phase: str) -> None:
        self.path = path
        self.case = case
        self.phase = phase
        self.sequence = 0
        self.request_starts = 0

    def __call__(self, event: str, payload: Any) -> None:
        self.sequence += 1
        if event == "request":
            self.request_starts += 1
        append_jsonl_atomic(
            self.path,
            {
                "diagnostic_target": DIAGNOSTIC_TARGET,
                "replay_id": self.case.replay_id,
                "phase": self.phase,
                "sequence": self.sequence,
                "timestamp": utc_now(),
                "event": event,
                "payload": _to_jsonable(payload),
            },
        )


def _build_diagnostic_pipeline() -> tuple[Any, AgentPipeline]:
    model = get_google_gemma4_26b_diagnostic_llm()
    if getattr(model, "model", None) != GEMMA4_26B_DIAGNOSTIC_MODEL:
        raise DiagnosticReplayError("diagnostic target factory returned a different model")
    if getattr(model, "name", None) != DIAGNOSTIC_PIPELINE_NAME:
        raise DiagnosticReplayError("diagnostic target pipeline identity changed unexpectedly")
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=cast(ModelsEnum, model),
            model_id=None,
            defense=None,
            tool_delimiter="tool",
            system_message_name=None,
            system_message=None,
        )
    )
    if pipeline.name != DIAGNOSTIC_PIPELINE_NAME:
        raise DiagnosticReplayError("diagnostic pipeline identity changed unexpectedly")
    return model, pipeline


def _clean_trace_path(case: ReplayCase, raw_root: Path) -> Path:
    return agentdojo_raw_trace_path(
        raw_root,
        pipeline_name=DIAGNOSTIC_PIPELINE_NAME,
        suite_name=case.context.domain,
        user_task_id=case.context.injection_task_id,
        attack_name="none",
        injection_task_id="none",
    )


def _require_windows_trace_path_fits(path: Path) -> None:
    """Fail before a live call when AgentDojo's nested raw path exceeds MAX_PATH."""

    if os.name == "nt" and len(str(path.resolve())) >= 260:
        raise DiagnosticReplayError(
            "diagnostic output root makes the AgentDojo injected trace path too long for Windows; "
            f"use a shorter subdirectory below {DIAGNOSTIC_ROOT}: {path}"
        )


def _stop_after_unexpected_execution(stage: str, error: Exception) -> int:
    print(
        f"Stopping after unexpected {stage} execution error: "
        f"{operation_exception_summary(error)}",
        file=sys.stderr,
    )
    return UNEXPECTED_EXECUTION_EXIT_CODE


def _load_trace_check_state(output_root: Path) -> dict[str, Any] | None:
    path = _trace_check_state_path(output_root)
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise DiagnosticReplayError(f"invalid trace-check state: {path}") from error
    if not isinstance(value, dict):
        raise DiagnosticReplayError(f"invalid trace-check state: {path}")
    return value


def execute_clean_prepass(case: ReplayCase, *, output_root: Path, raw_root: Path) -> dict[str, Any]:
    """Run the same native clean utility pre-pass as AgentDojo's attack benchmark."""

    attack_name = _register_attack(case)
    _require_windows_trace_path_fits(
        _operation_spec(
            case,
            results_path=output_root / "results.jsonl",
            raw_root=raw_root,
            attack_name=attack_name,
        ).raw_trace_path
    )
    spec = _step1_clean_operation_spec(case, output_root=output_root, raw_root=raw_root)
    _require_windows_trace_path_fits(spec.raw_trace_path)
    journal = OperationJournal.open(
        output_root / "operations",
        spec,
        initial_timestamp=raw_trace_timestamp(spec.raw_trace_path),
    )
    try:
        cached_raw = load_validated_raw_trace(spec)
    except ErroredRawTrace as error:
        journal.record_failure(str(error), attempt_index=None)
        cached_raw = None
    if cached_raw is not None:
        journal.ensure_nonzero_inferred_attempts(cached_raw)
        reconstructed = {
            "diagnostic_target": DIAGNOSTIC_TARGET,
            "replay_id": case.replay_id,
            "phase": "clean_utility_prepass",
            "completed_at": journal.timestamp,
            "clean_utility": cached_raw["utility"],
            "clean_security": cached_raw["security"],
            "clean_raw_trace_path": _relative(spec.raw_trace_path),
            "clean_request_attempts": journal.request_attempts,
            "clean_trace_events": 0,
        }
        stored = journal.result_record
        if stored is not None:
            for key, expected in reconstructed.items():
                if key != "clean_trace_events" and stored.get(key) != expected:
                    raise DiagnosticReplayError(
                        f"clean diagnostic journal result disagrees for {key}"
                    )
            state = stored
        else:
            state = reconstructed
        journal.store_result(state)
        atomic_write_json(_trace_check_state_path(output_root), state)
        journal.mark_indexed()
        return state
    if journal.status == "running":
        journal.recover_interrupted_before_request()
    if journal.status == "api_returned":
        raise OperationJournalError(
            "clean diagnostic API returned without a durable raw trace; refusing to repeat ambiguous work"
        )

    model, pipeline = _build_diagnostic_pipeline()
    suite = get_suite(BENCHMARK_VERSION, case.context.domain)
    injection_task = suite.get_injection_task_by_id(case.context.injection_task_id)
    trace = _DiagnosticGoogleTrace(
        output_root / TRACE_EVENT_FILENAME, case=case, phase="clean_utility_prepass"
    )

    def run_clean_task() -> Mapping[str, Any]:
        with OutputLogger(str(raw_root)):
            with observe_google_generate_content_events(trace):
                utility, security = run_task_without_injection_tasks(
                    suite,
                    pipeline,
                    injection_task,
                    raw_root,
                    True,
                    BENCHMARK_VERSION,
                )
        return {"utility": utility, "security": security}

    results, attempt_index = execute_journaled_agentdojo_benchmark(
        journal=journal,
        force_rerun=True,
        benchmark=run_clean_task,
        observe_attempts=observe_google_request_attempts,
        get_attempt_count=get_google_request_attempt_count,
        benchmark_kwargs={},
    )
    try:
        raw_trace = load_validated_raw_trace(spec)
    except (ErroredRawTrace, RawTraceError) as error:
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise BenchmarkTraceError(str(error)) from error
    if raw_trace is None:
        error = BenchmarkTraceError(
            f"AgentDojo did not write clean diagnostic trace: {spec.raw_trace_path}"
        )
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    if (
        raw_trace["utility"] is not results["utility"]
        or raw_trace["security"] is not results["security"]
    ):
        error = BenchmarkTraceError(
            "native AgentDojo verdict disagrees with clean diagnostic raw trace"
        )
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    state = {
        "diagnostic_target": DIAGNOSTIC_TARGET,
        "replay_id": case.replay_id,
        "phase": "clean_utility_prepass",
        "completed_at": journal.timestamp,
        "clean_utility": raw_trace["utility"],
        "clean_security": raw_trace["security"],
        "clean_raw_trace_path": _relative(spec.raw_trace_path),
        "clean_request_attempts": journal.request_attempts,
        "clean_trace_events": trace.sequence,
    }
    journal.store_result(state)
    atomic_write_json(_trace_check_state_path(output_root), state)
    journal.mark_indexed()
    return state


def execute_injected_trace_check(
    case: ReplayCase, *, output_root: Path, results_path: Path, raw_root: Path
) -> DiagnosticReplayRecord:
    """Run only the native injected half after a separately completed clean pass."""

    if results_path.is_file():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            existing = json.loads(line)
            if existing.get("replay_id") == case.replay_id:
                print(
                    f"Step 1 injected check already recorded for {case.replay_id} "
                    f"at {existing.get('timestamp')}; skipping live call. "
                    "Delete the line from results.jsonl to force a genuine rerun."
                )
                return DiagnosticReplayRecord.from_dict(existing, path=str(results_path))

    state = _load_trace_check_state(output_root)
    if state is None or state.get("replay_id") != case.replay_id or state.get("phase") != "clean_utility_prepass":
        raise DiagnosticReplayError(
            "the injected trace check requires a completed clean-utility pre-pass in this output root"
        )
    clean_path = PROJECT_ROOT / str(state.get("clean_raw_trace_path", ""))
    if not clean_path.is_file():
        raise DiagnosticReplayError("the recorded clean-utility trace is missing")

    attack_name = _register_attack(case)
    spec = _step1_injected_operation_spec(
        case, results_path=results_path, raw_root=raw_root, attack_name=attack_name
    )
    _require_windows_trace_path_fits(spec.raw_trace_path)
    journal = OperationJournal.open(
        output_root / "operations",
        spec,
        initial_timestamp=raw_trace_timestamp(spec.raw_trace_path),
    )
    try:
        cached_raw = load_validated_raw_trace(spec)
    except ErroredRawTrace as error:
        journal.record_failure(str(error), attempt_index=None)
        cached_raw = None
    if cached_raw is not None:
        record = _step1_injected_record_from_raw(journal, case, cached_raw)
        journal.store_result(asdict(record))
        append_jsonl_once(results_path, asdict(record), identity_field="replay_id")
        journal.mark_indexed()
        return record
    if journal.status == "running":
        journal.recover_interrupted_before_request()
    if journal.status == "api_returned":
        raise OperationJournalError(
            "injected diagnostic API returned without a durable raw trace; refusing to repeat ambiguous work"
        )

    model, pipeline = _build_diagnostic_pipeline()
    suite = get_suite(BENCHMARK_VERSION, case.context.domain)
    attack = load_attack(attack_name, suite, pipeline)
    user_task = suite.get_user_task_by_id(case.context.user_task_id)
    trace = _DiagnosticGoogleTrace(
        output_root / TRACE_EVENT_FILENAME, case=case, phase="injected_attack"
    )
    # TraceLogger writes directly to this deterministic leaf but, unlike the
    # clean path, AgentDojo does not create a previously unseen attack-name
    # directory itself.  This is diagnostic-output plumbing only; it does not
    # alter the native rendering, model call, tools, or verdict function.
    spec.raw_trace_path.parent.mkdir(parents=True, exist_ok=True)
    # This call is precisely the injected-task half used by
    # benchmark_suite_with_injections, with no custom renderer or scorer.
    def run_injected_task() -> Mapping[str, Any]:
        with OutputLogger(str(raw_root)):
            with observe_google_generate_content_events(trace):
                utility_results, security_results = run_task_with_injection_tasks(
                    suite,
                    pipeline,
                    user_task,
                    attack,
                    raw_root,
                    True,
                    (case.context.injection_task_id,),
                    BENCHMARK_VERSION,
                )
        return {
            "utility_results": utility_results,
            "security_results": security_results,
        }

    results, attempt_index = execute_journaled_agentdojo_benchmark(
        journal=journal,
        force_rerun=True,
        benchmark=run_injected_task,
        observe_attempts=observe_google_request_attempts,
        get_attempt_count=get_google_request_attempt_count,
        benchmark_kwargs={},
    )
    try:
        raw_trace = load_validated_raw_trace(spec)
    except (ErroredRawTrace, RawTraceError) as error:
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise BenchmarkTraceError(str(error)) from error
    if raw_trace is None:
        error = BenchmarkTraceError(
            f"AgentDojo did not write injected diagnostic trace: {spec.raw_trace_path}"
        )
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    # This result object is intentionally formed from AgentDojo's native return
    # values and cross-checked against its unmodified raw trace.
    result_key = (case.context.user_task_id, case.context.injection_task_id)
    utility = results["utility_results"][result_key]
    security = results["security_results"][result_key]
    if raw_trace["security"] is not security or raw_trace["utility"] is not utility:
        error = BenchmarkTraceError(
            "native AgentDojo verdict disagrees with injected diagnostic raw trace"
        )
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    validated = _step1_injected_record_from_raw(journal, case, raw_trace)
    journal.store_result(asdict(validated))
    append_jsonl_once(results_path, asdict(validated), identity_field="replay_id")
    journal.mark_indexed()
    return validated


def _step1_injected_record_from_raw(
    journal: OperationJournal,
    case: ReplayCase,
    raw_trace: Mapping[str, Any],
) -> DiagnosticReplayRecord:
    rendered = raw_trace["injections"].get(case.context.injection_vector)
    if not isinstance(rendered, str) or not rendered:
        raise BenchmarkTraceError("injected diagnostic trace has no rendered attack")
    journal.ensure_nonzero_inferred_attempts(raw_trace)
    record = DiagnosticReplayRecord(
        replay_id=case.replay_id,
        timestamp=journal.timestamp,
        diagnostic_target=DIAGNOSTIC_TARGET,
        target_model=DIAGNOSTIC_MODEL,
        source_group=case.source_group,
        source_id=case.source_id,
        source_family=case.source_family,
        domain=case.context.domain,
        channel=case.context.channel,
        injection_vector=case.context.injection_vector,
        user_task_id=case.context.user_task_id,
        injection_task_id=case.context.injection_task_id,
        attack_success=raw_trace["security"],
        utility_success=raw_trace["utility"],
        rendered_attack_sha256=hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        target_request_attempts=journal.request_attempts,
        raw_trace_path=_relative(journal.spec.raw_trace_path),
        notes=(
            "native AgentDojo verdict; Step 1 injected trace check; no generator; "
            "no calibration quota ledger"
        ),
    )
    return DiagnosticReplayRecord.from_dict(
        asdict(record), path="generated injected diagnostic record"
    )


def _record_from_raw(journal: OperationJournal, case: ReplayCase, raw_trace: Mapping[str, Any]) -> DiagnosticReplayRecord:
    rendered = raw_trace["injections"][case.context.injection_vector]
    if not isinstance(rendered, str) or not rendered:
        raise BenchmarkTraceError("diagnostic raw trace has no rendered injection")
    journal.ensure_nonzero_inferred_attempts(raw_trace)
    record = DiagnosticReplayRecord(
        replay_id=case.replay_id,
        timestamp=journal.timestamp,
        diagnostic_target=DIAGNOSTIC_TARGET,
        target_model=DIAGNOSTIC_MODEL,
        source_group=case.source_group,
        source_id=case.source_id,
        source_family=case.source_family,
        domain=case.context.domain,
        channel=case.context.channel,
        injection_vector=case.context.injection_vector,
        user_task_id=case.context.user_task_id,
        injection_task_id=case.context.injection_task_id,
        attack_success=raw_trace["security"],
        utility_success=raw_trace["utility"],
        rendered_attack_sha256=hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        target_request_attempts=journal.request_attempts,
        raw_trace_path=_relative(journal.spec.raw_trace_path),
        notes="native AgentDojo verdict; replay-only; no generator; no calibration quota ledger",
    )
    return DiagnosticReplayRecord.from_dict(asdict(record), path="generated diagnostic record")


def execute_replay(case: ReplayCase, *, results_path: Path, raw_root: Path, force_rerun: bool = False) -> DiagnosticReplayRecord:
    """Replay exactly one existing artifact using AgentDojo's unchanged verdict path."""

    attack_name = _register_attack(case)
    spec = _operation_spec(case, results_path=results_path, raw_root=raw_root, attack_name=attack_name)
    _require_windows_trace_path_fits(spec.raw_trace_path)
    journal = OperationJournal.open(results_path.parent / "operations", spec, initial_timestamp=raw_trace_timestamp(spec.raw_trace_path))
    try:
        raw_trace = load_validated_raw_trace(spec)
    except ErroredRawTrace as error:
        journal.record_failure(str(error), attempt_index=None)
        raw_trace = None
        force_rerun = True
    except RawTraceError as error:
        raise DiagnosticReplayError(str(error)) from error
    if raw_trace is not None:
        record = _record_from_raw(journal, case, raw_trace)
        journal.store_result(asdict(record))
        append_jsonl_once(results_path, asdict(record), identity_field="replay_id")
        journal.mark_indexed()
        return record

    model = get_google_gemma4_26b_diagnostic_llm()
    if getattr(model, "model", None) != GEMMA4_26B_DIAGNOSTIC_MODEL:
        raise DiagnosticReplayError("diagnostic target factory returned a different model")
    if getattr(model, "name", None) != DIAGNOSTIC_PIPELINE_NAME:
        raise DiagnosticReplayError("diagnostic target pipeline identity changed unexpectedly")
    suite = get_suite(BENCHMARK_VERSION, case.context.domain)
    results, attempt_index = execute_journaled_agentdojo_benchmark(
        journal=journal,
        force_rerun=force_rerun,
        benchmark=benchmark_suite,
        observe_attempts=observe_google_request_attempts,
        get_attempt_count=get_google_request_attempt_count,
        benchmark_kwargs={
            "suite": suite,
            "model": cast(ModelsEnum, model),
            "logdir": raw_root,
            "force_rerun": force_rerun,
            "benchmark_version": BENCHMARK_VERSION,
            "user_tasks": (case.context.user_task_id,),
            "injection_tasks": (case.context.injection_task_id,),
            "attack": attack_name,
        },
    )
    try:
        raw_trace = load_validated_raw_trace(spec)
    except (ErroredRawTrace, RawTraceError) as error:
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise BenchmarkTraceError(str(error)) from error
    if raw_trace is None:
        error = BenchmarkTraceError(f"AgentDojo did not write diagnostic raw trace: {spec.raw_trace_path}")
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    security = results["security_results"][(case.context.user_task_id, case.context.injection_task_id)]
    utility = results["utility_results"][(case.context.user_task_id, case.context.injection_task_id)]
    if raw_trace["security"] is not security or raw_trace["utility"] is not utility:
        error = BenchmarkTraceError("native AgentDojo verdict disagrees with diagnostic raw trace")
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    record = _record_from_raw(journal, case, raw_trace)
    journal.store_result(asdict(record))
    append_jsonl_once(results_path, asdict(record), identity_field="replay_id")
    journal.mark_indexed()
    return record


def load_completed_replays(results_path: Path, *, raw_root: Path) -> set[str]:
    if not results_path.exists():
        return set()
    completed: set[str] = set()
    for line_number, line in enumerate(results_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            record = DiagnosticReplayRecord.from_dict(json.loads(line), path=f"{results_path}:{line_number}")
        except (json.JSONDecodeError, DiagnosticReplayError) as error:
            raise DiagnosticReplayError(f"invalid diagnostic checkpoint: {error}") from error
        raw_path = Path(record.raw_trace_path)
        if not raw_path.is_absolute():
            raw_path = PROJECT_ROOT / raw_path
        if not _is_relative_to(raw_path, raw_root) or not raw_path.is_file():
            raise DiagnosticReplayError(f"{results_path}:{line_number} raw trace escapes diagnostic root")
        if record.replay_id in completed:
            raise DiagnosticReplayError(f"{results_path}:{line_number} duplicates replay ID")
        completed.add(record.replay_id)
    return completed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnostic-target", required=True, choices=(DIAGNOSTIC_TARGET,))
    parser.add_argument("--output-root", type=Path, default=DIAGNOSTIC_ROOT)
    parser.add_argument("--max-runs", type=int, help="Stop after this many new replays")
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument(
        "--stage",
        choices=("all", "clean", "injected"),
        default="all",
        help=(
            "Run the normal replay, or one independently budgeted Step 1 phase. "
            "The injected phase refuses to run until this output root contains a "
            "fresh completed clean phase."
        ),
    )
    parser.add_argument("--plan", action="store_true", help="Validate and print the immutable replay corpus without API calls")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_runs is not None and args.max_runs < 1:
        raise DiagnosticReplayError("--max-runs must be at least 1")
    output_root = validate_output_root(args.output_root)
    cases = load_replay_cases()
    if len(cases) != EXPECTED_BUILTIN_REPLAYS + EXPECTED_V1_MUTATION_REPLAYS:
        raise DiagnosticReplayError("diagnostic replay corpus count changed unexpectedly")
    if args.plan:
        for case in cases:
            print(f"{case.replay_id}\t{case.source_group}\t{case.source_id}\t{case.context.canonical_text}")
        print(f"Planned {len(cases)} isolated {DIAGNOSTIC_TARGET} replays")
        return 0
    results_path = output_root / "results.jsonl"
    raw_root = output_root
    if args.stage != "all":
        if args.max_runs != 1:
            raise DiagnosticReplayError("Step 1 phase runs require --max-runs 1")
        case = cases[0]
        if case.source_group != "builtin_v1" or case.source_family != "direct":
            raise DiagnosticReplayError("Step 1 must use the first direct built-in replay")
        try:
            if args.stage == "clean":
                state = execute_clean_prepass(case, output_root=output_root, raw_root=raw_root)
                print(
                    "Completed fresh clean utility pre-pass: "
                    f"utility={state['clean_utility']} requests={state['clean_request_attempts']}"
                )
                return 0
            record = execute_injected_trace_check(
                case, output_root=output_root, results_path=results_path, raw_root=raw_root
            )
        except ClientError as error:
            if is_quota_exhausted(error):
                print(
                    "Stopping at the Gemma diagnostic quota boundary; no Phase 6A ledger was used.",
                    file=sys.stderr,
                )
                return 2
            return _stop_after_unexpected_execution("Gemma diagnostic", error)
        except (BenchmarkTraceError, OperationJournalError, DiagnosticReplayError) as error:
            print(f"Stopping after an invalid diagnostic trace: {error}", file=sys.stderr)
            return 3
        except Exception as error:
            return _stop_after_unexpected_execution("Gemma diagnostic", error)
        print(f"Recorded {record.replay_id}: attack_success={record.attack_success}")
        return 0
    completed = load_completed_replays(results_path, raw_root=raw_root)
    executed = 0
    for case in cases:
        if case.replay_id in completed:
            print(f"Skipping checkpointed diagnostic replay: {case.replay_id}")
            continue
        if args.max_runs is not None and executed >= args.max_runs:
            break
        try:
            record = execute_replay(case, results_path=results_path, raw_root=raw_root, force_rerun=args.force_rerun)
        except ClientError as error:
            if is_quota_exhausted(error):
                print("Stopping at the Gemma diagnostic quota boundary; no Phase 6A ledger was used.", file=sys.stderr)
                return 2
            return _stop_after_unexpected_execution("Gemma diagnostic", error)
        except (BenchmarkTraceError, OperationJournalError, DiagnosticReplayError) as error:
            print(f"Stopping after an invalid diagnostic trace: {error}", file=sys.stderr)
            return 3
        except Exception as error:
            return _stop_after_unexpected_execution("Gemma diagnostic", error)
        executed += 1
        print(f"Recorded {record.replay_id}: attack_success={record.attack_success}")
    print(f"Completed {executed} new isolated {DIAGNOSTIC_TARGET} replay(s): {results_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
