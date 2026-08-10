"""Run ordered no-injection utility controls for Phase 6A manifests.

The runner never receives an attack or an attack result. It executes the user
task from each candidate context through AgentDojo's clean ``attack=None``
path, records the native utility verdict, and selects the first successful
contexts per domain in the committed candidate order. The canonical
development selection reserves slots for its required domain surfaces before
filling remaining slots in that same order; held-out selection remains the
literal first-success policy.

Results are checkpointed after every completed clean run. A final selection
manifest is written only after every domain reaches ``--per-domain``. Existing
checkpoints are validated against the exact input-manifest SHA-256 before they
are reused.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from agentdojo.models import ModelsEnum
from agentdojo.scripts.benchmark import benchmark_suite
from agentdojo.task_suite.load_suites import get_suite
from google.genai.errors import ClientError

from src.experiments.build_attack_splits import (
    COMMITTED_CANDIDATE_SHA256,
    DOMAINS,
    MANIFEST_COLUMNS,
    MIN_SLACK_WEBPAGE_VECTORS,
    REQUIRED_CHANNELS,
    AttackContext,
)
from src.experiments.calibration_common import (
    relative_or_absolute as _relative_or_absolute,
)
from src.experiments.operation_journal import (
    ErroredRawTrace,
    OperationJournal,
    OperationJournalError,
    OperationSpec,
    RawTraceError,
    agentdojo_raw_trace_path,
    append_jsonl_atomic as _append_jsonl_atomic,
    append_jsonl_once,
    atomic_write_bytes,
    execute_journaled_agentdojo_benchmark,
    load_validated_raw_trace,
    raw_trace_timestamp,
)
from src.experiments.quota_guard import (
    add_quota_arguments,
    quota_guard_from_args,
    validate_quota_count_args,
)
from src.experiments.run_baseline import (
    BENCHMARK_VERSION,
    PROJECT_ROOT,
    BenchmarkTraceError,
    is_quota_exhausted,
)
from src.llm_providers.google_llm_factory import (
    PRIMARY_PIPELINE_NAME,
    RequestBudgetExceeded,
    get_google_primary_llm,
    get_google_request_attempt_count,
    observe_google_request_attempts,
)
from src.schemas import (
    CLEAN_CONTROL_PAYLOAD_ID,
    CLEAN_CONTROL_PRIMARY_MODEL,
    RunResult,
    SchemaValidationError,
)


DEFAULT_RESULTS_PATH = (
    PROJECT_ROOT / "data" / "attack_calibration" / "clean_controls" / "results.jsonl"
)
DEFAULT_RAW_ROOT = (
    PROJECT_ROOT / "data" / "attack_calibration" / "clean_controls" / "raw"
)
DEFAULT_DEV_CANDIDATES = (
    PROJECT_ROOT / "data" / "attack_calibration" / "dev_candidates.tsv"
)
DEFAULT_HOLDOUT_CANDIDATES = (
    PROJECT_ROOT / "data" / "attack_calibration" / "holdout_candidates.tsv"
)
CLEAN_CONTROL_STATE_SCHEMA_VERSION = 1
_CONTROL_STATE_FIELDS = {
    "artifact",
    "schema_version",
    "split",
    "plan_sha256",
    "requested_successes_per_domain",
    "selection_complete",
    "evaluated_candidate_ranks",
    "selected_candidate_ranks",
    "next_unread_candidate_rank",
}


class CleanControlError(RuntimeError):
    """Raised when a control manifest or checkpoint violates the protocol."""


@dataclass(frozen=True)
class RankedContext:
    """One candidate context plus its immutable order in the source manifest."""

    candidate_rank: int
    context: AttackContext

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.context.key


@dataclass(frozen=True)
class ContextManifest:
    """Strictly validated candidate/selection manifest with byte provenance."""

    path: Path
    sha256: str
    rows: tuple[RankedContext, ...]

    @property
    def by_key(self) -> dict[tuple[str, str, str, str], RankedContext]:
        return {row.key: row for row in self.rows}


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def load_context_manifest(path: Path) -> ContextManifest:
    """Load one canonical TSV manifest without changing its declared order."""

    resolved = path.resolve()
    if not resolved.is_file():
        raise CleanControlError(f"context manifest does not exist: {resolved}")
    content = resolved.read_bytes()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CleanControlError(f"context manifest is not UTF-8: {resolved}") from error

    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t")
    if tuple(reader.fieldnames or ()) != MANIFEST_COLUMNS:
        raise CleanControlError(
            f"{resolved} must have columns {MANIFEST_COLUMNS!r}; "
            f"found {tuple(reader.fieldnames or ())!r}"
        )

    rows: list[RankedContext] = []
    seen_keys: set[tuple[str, str, str, str]] = set()
    previous_rank = 0
    for line_number, record in enumerate(reader, start=2):
        values = {
            column: (record.get(column) or "").strip()
            for column in MANIFEST_COLUMNS
        }
        if not all(values.values()):
            raise CleanControlError(f"{resolved}:{line_number} has an empty field")
        try:
            rank = int(values["candidate_rank"])
        except ValueError as error:
            raise CleanControlError(
                f"{resolved}:{line_number}.candidate_rank must be an integer"
            ) from error
        if rank <= previous_rank:
            raise CleanControlError(
                f"{resolved}:{line_number}.candidate_rank must be strictly increasing"
            )
        previous_rank = rank
        context = AttackContext(
            domain=values["domain"],
            channel=values["channel"],
            injection_vector=values["injection_vector"],
            user_task_id=values["user_task_id"],
            injection_task_id=values["injection_task_id"],
        )
        if context.domain not in DOMAINS:
            raise CleanControlError(
                f"{resolved}:{line_number} has unsupported domain {context.domain!r}"
            )
        if context.key in seen_keys:
            raise CleanControlError(
                f"{resolved}:{line_number} duplicates context {context.key!r}"
            )
        seen_keys.add(context.key)
        rows.append(RankedContext(rank, context))

    if not rows:
        raise CleanControlError(f"context manifest is empty: {resolved}")
    return ContextManifest(resolved, _sha256_bytes(content), tuple(rows))


def infer_split(input_path: Path, explicit_split: str | None) -> str:
    """Pin canonical inputs to their split and require labels for custom use."""

    resolved = input_path.resolve()
    canonical_split: str | None = None
    if resolved == DEFAULT_DEV_CANDIDATES.resolve():
        canonical_split = "dev"
    elif resolved == DEFAULT_HOLDOUT_CANDIDATES.resolve():
        canonical_split = "holdout"
    if canonical_split is not None:
        if explicit_split is not None and explicit_split != canonical_split:
            raise CleanControlError(
                f"canonical {canonical_split} candidate manifest cannot be labeled "
                f"as split={explicit_split!r}: {resolved}"
            )
        return canonical_split
    if explicit_split is not None:
        return explicit_split
    raise CleanControlError(
        "--split is required when --input is not the canonical dev or holdout "
        "candidate manifest"
    )


def validate_canonical_source_provenance(
    manifest: ContextManifest,
    *,
    split: str,
) -> None:
    """Reject changed bytes for either committed canonical candidate pool."""

    if split not in COMMITTED_CANDIDATE_SHA256:
        raise CleanControlError(f"unsupported candidate-manifest split: {split!r}")
    canonical_path = (
        DEFAULT_DEV_CANDIDATES if split == "dev" else DEFAULT_HOLDOUT_CANDIDATES
    ).resolve()
    if manifest.path.resolve() != canonical_path:
        return
    expected = COMMITTED_CANDIDATE_SHA256[split]
    if manifest.sha256 != expected:
        raise CleanControlError(
            f"canonical {split} candidate manifest SHA-256 changed: "
            f"expected {expected}, found {manifest.sha256}; use a versioned "
            "candidate manifest for a new ordering"
        )


def _note_value(notes: str, requested_key: str) -> str | None:
    for item in notes.split(";"):
        key, separator, value = item.strip().partition("=")
        if separator and key == requested_key:
            return value
    return None


def _checkpoint_key(result: RunResult) -> tuple[str, str, str, str]:
    vector = _note_value(result.notes, "injection_vector")
    if vector is None:
        raise SchemaValidationError("clean-control row lacks injection_vector provenance")
    return result.domain, vector, result.user_task_id, result.injection_task_id


def load_control_checkpoints(
    path: Path,
    *,
    manifest: ContextManifest,
    split: str,
    raw_root: Path,
) -> dict[tuple[str, str, str, str], RunResult]:
    """Validate and index checkpoints belonging to the requested manifest."""

    if not path.exists():
        return {}
    checkpoints: dict[tuple[str, str, str, str], RunResult] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            raise CleanControlError(f"{path}:{line_number} cannot be blank")
        try:
            raw = json.loads(line)
            result = RunResult.from_clean_control_dict(
                raw, path=f"{path}:{line_number}"
            )
        except (json.JSONDecodeError, SchemaValidationError) as error:
            raise CleanControlError(
                f"cannot resume from invalid clean-control checkpoint: {error}"
            ) from error
        # One shared file intentionally holds both development and holdout
        # controls. Rows from the other split/manifest are ignored only after
        # full schema validation.
        if result.split != split:
            continue
        if result.plan_sha256 != manifest.sha256:
            raise CleanControlError(
                f"{path}:{line_number} has plan_sha256={result.plan_sha256!r}, "
                f"but the current {split} candidate manifest has "
                f"SHA-256={manifest.sha256}; use a versioned checkpoint path "
                "for a changed manifest"
            )
        if result.model != CLEAN_CONTROL_PRIMARY_MODEL:
            raise CleanControlError(
                f"{path}:{line_number} was not produced by the primary model"
            )
        key = _checkpoint_key(result)
        expected = manifest.by_key.get(key)
        if expected is None:
            raise CleanControlError(
                f"{path}:{line_number} references a context absent from {manifest.path}"
            )
        expected_run_id = clean_operation_id(
            expected, manifest_sha256=manifest.sha256, split=split
        )
        if result.run_id != expected_run_id:
            raise CleanControlError(
                f"{path}:{line_number} run_id does not match its deterministic "
                "plan/context identity"
            )
        if result.channel != expected.context.channel:
            raise CleanControlError(
                f"{path}:{line_number} channel disagrees with {manifest.path}"
            )
        if _note_value(result.notes, "candidate_rank") != str(
            expected.candidate_rank
        ):
            raise CleanControlError(
                f"{path}:{line_number} candidate rank disagrees with {manifest.path}"
            )
        raw_reference = _note_value(result.notes, "raw_trace")
        if raw_reference is None:
            raise CleanControlError(
                f"{path}:{line_number} lacks raw_trace provenance"
            )
        raw_path = Path(raw_reference)
        if not raw_path.is_absolute():
            raw_path = PROJECT_ROOT / raw_path
        try:
            raw_path.resolve().relative_to(raw_root.resolve())
        except ValueError as error:
            raise CleanControlError(
                f"{path}:{line_number} raw trace is outside {raw_root}"
            ) from error
        if not raw_path.is_file():
            raise CleanControlError(
                f"{path}:{line_number} raw trace does not exist: {raw_path}"
            )
        raw_spec = OperationSpec(
            operation_id=result.run_id,
            operation_kind="clean_control",
            domain=expected.context.domain,
            suite_name=expected.context.domain,
            model=CLEAN_CONTROL_PRIMARY_MODEL,
            pipeline_name=PRIMARY_PIPELINE_NAME,
            benchmark_version=BENCHMARK_VERSION,
            user_task_id=expected.context.user_task_id,
            context_injection_task_id=expected.context.injection_task_id,
            raw_injection_task_id=None,
            channel=expected.context.channel,
            injection_vector=expected.context.injection_vector,
            attack_id=None,
            attack_name=None,
            expected_raw_injection_vector=None,
            operation_metadata={
                "split": split,
                "manifest_sha256": manifest.sha256,
                "candidate_rank": expected.candidate_rank,
            },
            raw_trace_path=raw_path,
            index_path=path,
        )
        try:
            raw_trace = load_validated_raw_trace(raw_spec)
        except RawTraceError as error:
            raise CleanControlError(str(error)) from error
        if raw_trace is None:
            raise CleanControlError(
                f"{path}:{line_number} raw trace does not exist: {raw_path}"
            )
        if raw_trace.get("security") is not True:
            raise CleanControlError(
                f"{path}:{line_number} clean raw trace has an invalid security verdict"
            )
        if raw_trace.get("user_task_id") != result.user_task_id:
            raise CleanControlError(
                f"{path}:{line_number} raw trace user task disagrees with checkpoint"
            )
        if raw_trace.get("messages") != result.tool_calls:
            raise CleanControlError(
                f"{path}:{line_number} raw messages disagree with checkpoint"
            )
        if raw_trace.get("utility") is not result.utility_success:
            raise CleanControlError(
                f"{path}:{line_number} native utility disagrees with checkpoint"
            )
        if key in checkpoints:
            raise CleanControlError(
                f"{path}:{line_number} duplicates clean-control context {key!r}"
            )
        checkpoints[key] = result
    return checkpoints


def render_selection(rows: Sequence[RankedContext]) -> bytes:
    """Render selected rows with original ranks and canonical LF endings."""

    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(MANIFEST_COLUMNS)
    for row in rows:
        context = row.context
        writer.writerow(
            (
                row.candidate_rank,
                context.domain,
                context.channel,
                context.injection_vector,
                context.user_task_id,
                context.injection_task_id,
            )
        )
    return output.getvalue().encode("utf-8")


def _write_atomic(path: Path, content: bytes, *, refuse_changed: bool) -> bool:
    try:
        return atomic_write_bytes(path, content, refuse_changed=refuse_changed)
    except OperationJournalError as error:
        raise CleanControlError(str(error)) from error


def append_jsonl_atomic(path: Path, record: Mapping[str, Any]) -> None:
    """Append one JSON object by atomically replacing the complete JSONL file."""

    try:
        _append_jsonl_atomic(path, record)
    except OperationJournalError as error:
        raise CleanControlError(str(error)) from error


def clean_operation_id(
    row: RankedContext, *, manifest_sha256: str, split: str
) -> str:
    """Return the stable run ID for one manifest-bound clean operation."""

    context = row.context
    identity = "\0".join(
        (
            "phase-6a-clean-control",
            split,
            manifest_sha256,
            str(row.candidate_rank),
            *context.key,
        )
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, identity))


def render_control_state(
    manifest: ContextManifest,
    checkpoints: Mapping[tuple[str, str, str, str], RunResult],
    *,
    split: str,
    per_domain: int,
) -> bytes:
    """Render deterministic per-domain continuation state from checkpoints."""

    require_development_coverage = _requires_development_coverage(
        manifest, split=split, per_domain=per_domain
    )
    selected, counts = selected_contexts(
        manifest,
        checkpoints,
        per_domain=per_domain,
        require_development_coverage=require_development_coverage,
    )
    selected_ranks = {
        domain: [
            row.candidate_rank
            for row in selected
            if row.context.domain == domain
        ]
        for domain in DOMAINS
    }
    evaluated_ranks = {
        domain: [
            row.candidate_rank
            for row in manifest.rows
            if row.context.domain == domain and row.key in checkpoints
        ]
        for domain in DOMAINS
    }
    next_unread = {
        domain: next(
            (
                row.candidate_rank
                for row in manifest.rows
                if row.context.domain == domain and row.key not in checkpoints
            ),
            None,
        )
        for domain in DOMAINS
    }
    state = {
        "artifact": "phase-6a-clean-control-cursor",
        "schema_version": CLEAN_CONTROL_STATE_SCHEMA_VERSION,
        "split": split,
        "plan_sha256": manifest.sha256,
        "requested_successes_per_domain": per_domain,
        "selection_complete": _all_domains_complete(counts, per_domain),
        "evaluated_candidate_ranks": evaluated_ranks,
        "selected_candidate_ranks": selected_ranks,
        "next_unread_candidate_rank": next_unread,
    }
    return (
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _write_control_state(
    path: Path,
    manifest: ContextManifest,
    checkpoints: Mapping[tuple[str, str, str, str], RunResult],
    *,
    split: str,
    per_domain: int,
) -> None:
    """Atomically replace the derived cursor; JSONL/journals stay authoritative."""

    _write_atomic(
        path,
        render_control_state(
            manifest,
            checkpoints,
            split=split,
            per_domain=per_domain,
        ),
        refuse_changed=False,
    )


def validate_existing_control_state(
    path: Path,
    manifest: ContextManifest,
    *,
    split: str,
    per_domain: int,
) -> None:
    """Validate a cursor structurally while allowing interruption-stale content."""

    if not path.exists():
        return
    if not path.is_file():
        raise CleanControlError(f"clean-control state output is not a file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CleanControlError(f"clean-control state is unreadable: {path}") from error
    if not isinstance(value, Mapping) or set(value) != _CONTROL_STATE_FIELDS:
        raise CleanControlError(f"clean-control state has invalid fields: {path}")
    expected_scalars = {
        "artifact": "phase-6a-clean-control-cursor",
        "schema_version": CLEAN_CONTROL_STATE_SCHEMA_VERSION,
        "split": split,
        "plan_sha256": manifest.sha256,
        "requested_successes_per_domain": per_domain,
    }
    for field, expected in expected_scalars.items():
        if value.get(field) != expected:
            raise CleanControlError(
                f"clean-control state {field} disagrees with this command: {path}"
            )
    if not isinstance(value.get("selection_complete"), bool):
        raise CleanControlError(
            f"clean-control state selection_complete must be boolean: {path}"
        )

    ranks_by_domain = {
        domain: [
            row.candidate_rank
            for row in manifest.rows
            if row.context.domain == domain
        ]
        for domain in DOMAINS
    }
    evaluated = value.get("evaluated_candidate_ranks")
    selected = value.get("selected_candidate_ranks")
    next_unread = value.get("next_unread_candidate_rank")
    for field, mapping in (
        ("evaluated_candidate_ranks", evaluated),
        ("selected_candidate_ranks", selected),
        ("next_unread_candidate_rank", next_unread),
    ):
        if not isinstance(mapping, Mapping) or set(mapping) != set(DOMAINS):
            raise CleanControlError(
                f"clean-control state {field} must cover exactly {DOMAINS}: {path}"
            )
    assert isinstance(evaluated, Mapping)
    assert isinstance(selected, Mapping)
    assert isinstance(next_unread, Mapping)
    for domain in DOMAINS:
        valid_ranks = ranks_by_domain[domain]
        valid_set = set(valid_ranks)
        domain_evaluated = evaluated[domain]
        domain_selected = selected[domain]
        for field, ranks in (
            ("evaluated_candidate_ranks", domain_evaluated),
            ("selected_candidate_ranks", domain_selected),
        ):
            if (
                not isinstance(ranks, list)
                or any(
                    isinstance(rank, bool)
                    or not isinstance(rank, int)
                    or rank not in valid_set
                    for rank in ranks
                )
                or len(ranks) != len(set(ranks))
                or ranks != [rank for rank in valid_ranks if rank in set(ranks)]
            ):
                raise CleanControlError(
                    f"clean-control state {field}.{domain} is invalid: {path}"
                )
        if not set(domain_selected).issubset(set(domain_evaluated)):
            raise CleanControlError(
                f"clean-control selected ranks are not evaluated for {domain}: {path}"
            )
        if len(domain_selected) > per_domain:
            raise CleanControlError(
                f"clean-control selected ranks exceed the requested count for "
                f"{domain}: {path}"
            )
        cursor = next_unread[domain]
        expected_cursor = next(
            (rank for rank in valid_ranks if rank not in set(domain_evaluated)),
            None,
        )
        if cursor != expected_cursor:
            raise CleanControlError(
                f"clean-control next unread rank is invalid for {domain}: {path}"
            )
    expected_complete = all(
        len(selected[domain]) >= per_domain for domain in DOMAINS
    )
    if value["selection_complete"] is not expected_complete:
        raise CleanControlError(
            f"clean-control selection_complete disagrees with selected ranks: {path}"
        )


def _clean_logdir(
    row: RankedContext,
    *,
    manifest_sha256: str,
    split: str,
    raw_root: Path,
) -> Path:
    """Return an AgentDojo log root isolated to one ordered clean context."""

    operation_id = clean_operation_id(
        row, manifest_sha256=manifest_sha256, split=split
    )
    return raw_root / split / row.context.domain / "contexts" / operation_id


def _clean_operation_spec(
    row: RankedContext,
    *,
    manifest_sha256: str,
    split: str,
    results_path: Path,
    raw_root: Path,
) -> OperationSpec:
    context = row.context
    logdir = _clean_logdir(
        row,
        manifest_sha256=manifest_sha256,
        split=split,
        raw_root=raw_root,
    )
    raw_path = agentdojo_raw_trace_path(
        logdir,
        pipeline_name=PRIMARY_PIPELINE_NAME,
        suite_name=context.domain,
        user_task_id=context.user_task_id,
        attack_name=None,
        injection_task_id=None,
    )
    return OperationSpec(
        operation_id=clean_operation_id(
            row, manifest_sha256=manifest_sha256, split=split
        ),
        operation_kind="clean_control",
        domain=context.domain,
        suite_name=context.domain,
        model=CLEAN_CONTROL_PRIMARY_MODEL,
        pipeline_name=PRIMARY_PIPELINE_NAME,
        benchmark_version=BENCHMARK_VERSION,
        user_task_id=context.user_task_id,
        context_injection_task_id=context.injection_task_id,
        raw_injection_task_id=None,
        channel=context.channel,
        injection_vector=context.injection_vector,
        attack_id=None,
        attack_name=None,
        expected_raw_injection_vector=None,
        operation_metadata={
            "split": split,
            "manifest_sha256": manifest_sha256,
            "candidate_rank": row.candidate_rank,
        },
        raw_trace_path=raw_path,
        index_path=results_path,
    )


def preflight_controls(
    *,
    manifest: ContextManifest,
    selection_output: Path,
    per_domain: int,
    split: str,
    results_path: Path,
    raw_root: Path,
    state_output: Path | None = None,
    excluded_keys: set[tuple[str, str, str, str]] | None = None,
    excluded_manifest_path: Path | None = None,
) -> tuple[Path, dict[tuple[str, str, str, str], RunResult]]:
    """Perform the complete read-only clean-control command preflight."""

    if per_domain < 1:
        raise CleanControlError("per_domain must be at least 1")
    if split not in {"dev", "holdout"}:
        raise CleanControlError("clean-control split must be 'dev' or 'holdout'")
    available = Counter(row.context.domain for row in manifest.rows)
    shortages = {
        domain: available[domain]
        for domain in DOMAINS
        if available[domain] < per_domain
    }
    if shortages:
        raise CleanControlError(
            f"manifest cannot supply {per_domain} context(s)/domain: {shortages}"
        )
    excluded = excluded_keys or set()
    overlap = sorted(set(manifest.by_key) & excluded)
    if overlap:
        raise CleanControlError(
            f"input manifest overlaps excluded contexts: {overlap[:3]}"
        )

    cursor_path = state_output or selection_output.with_name(
        f"{selection_output.stem}.state.json"
    )
    file_outputs = {
        "selection output": selection_output.resolve(),
        "results output": results_path.resolve(),
        "state output": cursor_path.resolve(),
    }
    if len(set(file_outputs.values())) != len(file_outputs):
        raise CleanControlError(
            "clean-control selection, results, and state outputs must be distinct"
        )
    source_paths = {"input manifest": manifest.path.resolve()}
    if excluded_manifest_path is not None:
        source_paths["excluded manifest"] = excluded_manifest_path.resolve()
    for output_name, output_path in file_outputs.items():
        if output_path in source_paths.values():
            raise CleanControlError(
                f"{output_name} collides with an input manifest: {output_path}"
            )
        if output_path.exists() and not output_path.is_file():
            raise CleanControlError(f"{output_name} is not a file: {output_path}")
    raw_resolved = raw_root.resolve()
    if raw_resolved.exists() and not raw_resolved.is_dir():
        raise CleanControlError(f"raw root is not a directory: {raw_resolved}")
    for output_name, output_path in file_outputs.items():
        if (
            raw_resolved == output_path
            or raw_resolved in output_path.parents
            or output_path in raw_resolved.parents
        ):
            raise CleanControlError(
                f"{output_name} must not overlap the AgentDojo raw root"
            )
    operations_root = results_path.resolve().parent / "operations"
    for output_name, output_path in file_outputs.items():
        if (
            operations_root == output_path
            or operations_root in output_path.parents
            or output_path in operations_root.parents
        ):
            raise CleanControlError(
                f"{output_name} must not overlap the operation-journal root"
            )

    validate_existing_control_state(
        cursor_path,
        manifest,
        split=split,
        per_domain=per_domain,
    )
    checkpoints = load_control_checkpoints(
        results_path, manifest=manifest, split=split, raw_root=raw_root
    )
    operations_root = results_path.parent / "operations"
    for row in manifest.rows:
        spec = _clean_operation_spec(
            row,
            manifest_sha256=manifest.sha256,
            split=split,
            results_path=results_path,
            raw_root=raw_root,
        )
        try:
            OperationJournal.load_existing(operations_root, spec)
        except OperationJournalError as error:
            raise CleanControlError(str(error)) from error
    return cursor_path, checkpoints


def _validate_clean_native_contract(
    journal: OperationJournal,
    raw_trace: Mapping[str, Any],
    *,
    row: RankedContext,
    manifest_sha256: str,
    split: str,
    native_utility: bool | None,
) -> None:
    """Validate clean journal, context, and AgentDojo-native identity together."""

    context = row.context
    spec = journal.spec
    expected_operation_id = clean_operation_id(
        row, manifest_sha256=manifest_sha256, split=split
    )
    expected_spec = {
        "operation_id": expected_operation_id,
        "operation_kind": "clean_control",
        "domain": context.domain,
        "suite_name": context.domain,
        "model": CLEAN_CONTROL_PRIMARY_MODEL,
        "pipeline_name": PRIMARY_PIPELINE_NAME,
        "benchmark_version": BENCHMARK_VERSION,
        "user_task_id": context.user_task_id,
        "context_injection_task_id": context.injection_task_id,
        "raw_injection_task_id": None,
        "channel": context.channel,
        "injection_vector": context.injection_vector,
        "attack_id": None,
        "attack_name": None,
        "expected_raw_injection_vector": None,
    }
    for field, expected in expected_spec.items():
        found = getattr(spec, field)
        if found != expected:
            raise CleanControlError(
                f"clean-control operation provenance disagrees for {field}: "
                f"expected {expected!r}, found {found!r}"
            )
    expected_metadata = {
        "split": split,
        "manifest_sha256": manifest_sha256,
        "candidate_rank": row.candidate_rank,
    }
    if dict(spec.operation_metadata) != expected_metadata:
        raise CleanControlError(
            "clean-control operation metadata disagrees with plan/context identity"
        )

    expected_raw = {
        "suite_name": context.domain,
        "pipeline_name": PRIMARY_PIPELINE_NAME.replace("/", "_"),
        "benchmark_version": BENCHMARK_VERSION,
        "user_task_id": context.user_task_id,
        "injection_task_id": None,
        "attack_type": None,
        "injections": {},
    }
    for field, expected in expected_raw.items():
        if raw_trace.get(field) != expected:
            raise CleanControlError(
                f"clean-control raw provenance disagrees for {field}: "
                f"expected {expected!r}, found {raw_trace.get(field)!r}"
            )
    if not isinstance(raw_trace.get("messages"), list):
        raise CleanControlError("clean-control raw messages must be a list")
    if not isinstance(raw_trace.get("utility"), bool):
        raise CleanControlError("clean-control raw utility verdict must be boolean")
    if raw_trace.get("security") is not True:
        raise CleanControlError(
            f"clean-control raw trace has an invalid security verdict: "
            f"{journal.spec.raw_trace_path}"
        )
    if native_utility is not None and raw_trace["utility"] is not native_utility:
        raise CleanControlError(
            f"native utility result disagrees with raw trace: {spec.raw_trace_path}"
        )


def _clean_record_from_raw(
    journal: OperationJournal,
    raw_trace: Mapping[str, Any],
    *,
    row: RankedContext,
    manifest_sha256: str,
    split: str,
    native_utility: bool | None = None,
) -> RunResult:
    """Build or validate the pending clean-control index record."""

    _validate_clean_native_contract(
        journal,
        raw_trace,
        row=row,
        manifest_sha256=manifest_sha256,
        split=split,
        native_utility=native_utility,
    )
    journal.ensure_nonzero_inferred_attempts(raw_trace)
    stored = journal.result_record
    if stored is not None:
        try:
            record = RunResult.from_clean_control_dict(
                stored, path=f"{journal.path}.result_record"
            )
        except SchemaValidationError as error:
            raise CleanControlError(str(error)) from error
    else:
        duration = raw_trace.get("duration")
        elapsed = (
            float(duration)
            if isinstance(duration, (int, float)) and not isinstance(duration, bool)
            else 0.0
        )
        context = row.context
        record = RunResult(
            run_id=journal.operation_id,
            timestamp=journal.timestamp,
            domain=context.domain,
            user_task_id=context.user_task_id,
            # Preserve the attack context this clean-capable row supports later.
            injection_task_id=context.injection_task_id,
            payload_id=CLEAN_CONTROL_PAYLOAD_ID,
            channel=context.channel,
            model=CLEAN_CONTROL_PRIMARY_MODEL,
            defense="none",
            attack_success=False,
            tool_calls=list(raw_trace["messages"]),
            notes=(
                f"injection_vector={context.injection_vector}; "
                f"candidate_rank={row.candidate_rank}; "
                f"raw_trace={_relative_or_absolute(journal.spec.raw_trace_path)}; "
                f"api_request_attempts={journal.request_attempts}; "
                f"elapsed_seconds={elapsed:.3f}; "
                "clean control used AgentDojo attack=None"
            ),
            utility_success=bool(raw_trace["utility"]),
            split=split,
            plan_sha256=manifest_sha256,
        )
        RunResult.from_clean_control_dict(
            record.__dict__, path="generated clean control"
        )
        journal.store_result(record.__dict__)

    context = row.context
    recorded_raw = _note_value(record.notes, "raw_trace")
    recorded_raw_path = Path(recorded_raw) if recorded_raw is not None else None
    if recorded_raw_path is not None and not recorded_raw_path.is_absolute():
        recorded_raw_path = PROJECT_ROOT / recorded_raw_path
    if (
        record.run_id != journal.operation_id
        or record.timestamp != journal.timestamp
        or record.domain != context.domain
        or record.user_task_id != context.user_task_id
        or record.injection_task_id != context.injection_task_id
        or record.channel != context.channel
        or record.payload_id != CLEAN_CONTROL_PAYLOAD_ID
        or record.model != CLEAN_CONTROL_PRIMARY_MODEL
        or record.defense != "none"
        or record.attack_success
        or record.attack_set_version is not None
        or record.attack_sha256 is not None
        or record.defense_version is not None
        or record.defense_sha256 is not None
        or record.split != split
        or record.plan_sha256 != manifest_sha256
        or record.utility_success is not raw_trace["utility"]
        or record.tool_calls != raw_trace["messages"]
        or _note_value(record.notes, "injection_vector") != context.injection_vector
        or _note_value(record.notes, "candidate_rank") != str(row.candidate_rank)
        or recorded_raw_path is None
        or recorded_raw_path.resolve() != journal.spec.raw_trace_path.resolve()
        or _note_value(record.notes, "api_request_attempts")
        != str(journal.request_attempts)
    ):
        raise CleanControlError(
            f"operation sidecar result disagrees with clean-control provenance: "
            f"{journal.path}"
        )
    return record


def execute_clean_control(
    row: RankedContext,
    *,
    manifest_sha256: str,
    split: str,
    results_path: Path,
    raw_root: Path,
    force_rerun: bool = False,
) -> RunResult:
    """Execute or durably recover one no-injection AgentDojo control."""

    context = row.context
    spec = _clean_operation_spec(
        row,
        manifest_sha256=manifest_sha256,
        split=split,
        results_path=results_path,
        raw_root=raw_root,
    )
    journal = OperationJournal.open(
        results_path.parent / "operations",
        spec,
        initial_timestamp=raw_trace_timestamp(spec.raw_trace_path),
    )

    cached_failure = False
    try:
        raw_trace = load_validated_raw_trace(spec)
    except ErroredRawTrace as error:
        journal.ensure_nonzero_inferred_attempts(error.trace)
        journal.record_failure(str(error), attempt_index=None)
        cached_failure = True
        raw_trace = None
    except RawTraceError as error:
        raise CleanControlError(str(error)) from error
    if raw_trace is not None:
        record = _clean_record_from_raw(
            journal,
            raw_trace,
            row=row,
            manifest_sha256=manifest_sha256,
            split=split,
        )
        try:
            append_jsonl_once(results_path, record.__dict__, identity_field="run_id")
        except OperationJournalError as error:
            raise CleanControlError(str(error)) from error
        journal.mark_indexed()
        return record

    suite = get_suite(BENCHMARK_VERSION, context.domain)
    model = get_google_primary_llm()
    if getattr(model, "name", None) != PRIMARY_PIPELINE_NAME:
        raise CleanControlError("primary model pipeline identity changed unexpectedly")
    effective_force_rerun = force_rerun or cached_failure
    logdir = _clean_logdir(
        row,
        manifest_sha256=manifest_sha256,
        split=split,
        raw_root=raw_root,
    )
    results, attempt_index = execute_journaled_agentdojo_benchmark(
        journal=journal,
        force_rerun=effective_force_rerun,
        benchmark=benchmark_suite,
        observe_attempts=observe_google_request_attempts,
        get_attempt_count=get_google_request_attempt_count,
        benchmark_kwargs={
            "suite": suite,
            "model": cast(ModelsEnum, model),
            "logdir": logdir,
            "force_rerun": effective_force_rerun,
            "benchmark_version": BENCHMARK_VERSION,
            "user_tasks": (context.user_task_id,),
            "attack": None,
        },
    )

    try:
        raw_trace = load_validated_raw_trace(spec)
    except ErroredRawTrace as error:
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise BenchmarkTraceError(str(error)) from error
    except RawTraceError as error:
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise CleanControlError(str(error)) from error
    if raw_trace is None:
        error = BenchmarkTraceError(
            f"AgentDojo returned without writing the expected raw trace: "
            f"{spec.raw_trace_path}"
        )
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    utility = results["utility_results"][(context.user_task_id, "")]
    if not isinstance(utility, bool):
        error = BenchmarkTraceError(
            f"native utility result is not boolean: {spec.raw_trace_path}"
        )
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error
    if raw_trace["utility"] is not utility:
        error = BenchmarkTraceError(
            f"native utility result disagrees with raw trace: {spec.raw_trace_path}"
        )
        journal.record_failure(str(error), attempt_index=attempt_index)
        raise error

    record = _clean_record_from_raw(
        journal,
        raw_trace,
        row=row,
        manifest_sha256=manifest_sha256,
        split=split,
        native_utility=utility,
    )
    try:
        append_jsonl_once(results_path, record.__dict__, identity_field="run_id")
    except OperationJournalError as error:
        raise CleanControlError(str(error)) from error
    journal.mark_indexed()
    return record


def selected_contexts(
    manifest: ContextManifest,
    checkpoints: Mapping[tuple[str, str, str, str], RunResult],
    *,
    per_domain: int,
    require_development_coverage: bool = False,
) -> tuple[list[RankedContext], Counter[str]]:
    """Select successful checkpoints deterministically in source order.

    The canonical development selection reserves enough slots for any missing
    required surfaces before filling remaining slots with the earliest other
    utility-successful contexts. Holdout selection retains the literal first-
    successful behavior required by Phase 6A.12.
    """

    successful = [
        row
        for row in manifest.rows
        if (result := checkpoints.get(row.key)) is not None
        and result.utility_success
    ]
    if not require_development_coverage:
        selected: list[RankedContext] = []
        counts: Counter[str] = Counter()
        for row in successful:
            domain = row.context.domain
            if counts[domain] >= per_domain:
                continue
            selected.append(row)
            counts[domain] += 1
        return selected, counts

    selected: list[RankedContext] = []
    counts: Counter[str] = Counter()
    for domain in DOMAINS:
        domain_successes = [
            row for row in successful if row.context.domain == domain
        ]
        representatives: list[RankedContext] = []
        if domain == "slack":
            seen_vectors: set[str] = set()
            for row in domain_successes:
                if (
                    row.context.channel == "web_content"
                    and row.context.injection_vector not in seen_vectors
                    and len(seen_vectors) < MIN_SLACK_WEBPAGE_VECTORS
                ):
                    representatives.append(row)
                    seen_vectors.add(row.context.injection_vector)
            missing_slots = max(
                0, MIN_SLACK_WEBPAGE_VECTORS - len(seen_vectors)
            )
        else:
            seen_channels: set[str] = set()
            required_channels = REQUIRED_CHANNELS[domain]
            for row in domain_successes:
                if (
                    row.context.channel in required_channels
                    and row.context.channel not in seen_channels
                ):
                    representatives.append(row)
                    seen_channels.add(row.context.channel)
            missing_slots = len(required_channels - seen_channels)

        available_slots = max(0, per_domain - missing_slots)
        chosen = list(representatives[:available_slots])
        chosen_keys = {row.key for row in chosen}
        for row in domain_successes:
            if len(chosen) >= available_slots:
                break
            if row.key not in chosen_keys:
                chosen.append(row)
                chosen_keys.add(row.key)
        selected.extend(chosen)
        counts[domain] = len(chosen)

    selected.sort(key=lambda row: row.candidate_rank)
    return selected, counts


def _requires_development_coverage(
    manifest: ContextManifest, *, split: str, per_domain: int
) -> bool:
    """Limit the coverage-aware policy to the frozen Phase 6A dev protocol."""

    return (
        split == "dev"
        and per_domain == 6
        and manifest.path.resolve() == DEFAULT_DEV_CANDIDATES.resolve()
        and manifest.sha256 == COMMITTED_CANDIDATE_SHA256["dev"]
    )


def _candidate_advances_development_coverage(
    row: RankedContext,
    manifest: ContextManifest,
    checkpoints: Mapping[tuple[str, str, str, str], RunResult],
) -> bool:
    """Return whether an unevaluated row can fill a missing coverage slot."""

    successful = [
        candidate
        for candidate in manifest.rows
        if candidate.context.domain == row.context.domain
        and (result := checkpoints.get(candidate.key)) is not None
        and result.utility_success
    ]
    domain = row.context.domain
    if domain == "slack":
        seen_vectors = {
            candidate.context.injection_vector
            for candidate in successful
            if candidate.context.channel == "web_content"
        }
        if len(seen_vectors) < MIN_SLACK_WEBPAGE_VECTORS:
            return (
                row.context.channel == "web_content"
                and row.context.injection_vector not in seen_vectors
            )
        return True

    seen_channels = {candidate.context.channel for candidate in successful}
    missing_channels = REQUIRED_CHANNELS[domain] - seen_channels
    return not missing_channels or row.context.channel in missing_channels


def _all_domains_complete(counts: Mapping[str, int], per_domain: int) -> bool:
    return all(counts.get(domain, 0) >= per_domain for domain in DOMAINS)


def run_controls(
    *,
    manifest: ContextManifest,
    selection_output: Path,
    per_domain: int,
    split: str,
    results_path: Path,
    raw_root: Path,
    state_output: Path | None = None,
    excluded_keys: set[tuple[str, str, str, str]] | None = None,
    excluded_manifest_path: Path | None = None,
    force_rerun: bool = False,
) -> int:
    """Resume controls and materialize the completed deterministic selection."""

    cursor_path, checkpoints = preflight_controls(
        manifest=manifest,
        selection_output=selection_output,
        per_domain=per_domain,
        split=split,
        results_path=results_path,
        raw_root=raw_root,
        state_output=state_output,
        excluded_keys=excluded_keys,
        excluded_manifest_path=excluded_manifest_path,
    )
    _write_control_state(
        cursor_path,
        manifest,
        checkpoints,
        split=split,
        per_domain=per_domain,
    )
    require_development_coverage = _requires_development_coverage(
        manifest, split=split, per_domain=per_domain
    )
    selected, counts = selected_contexts(
        manifest,
        checkpoints,
        per_domain=per_domain,
        require_development_coverage=require_development_coverage,
    )
    if _all_domains_complete(counts, per_domain):
        selected, _ = selected_contexts(
            manifest,
            checkpoints,
            per_domain=per_domain,
            require_development_coverage=require_development_coverage,
        )
        content = render_selection(selected)
        _write_atomic(selection_output, content, refuse_changed=True)
        _write_control_state(
            cursor_path,
            manifest,
            checkpoints,
            split=split,
            per_domain=per_domain,
        )
        print(f"Selection already complete: {selection_output}")
        return 0

    while not _all_domains_complete(counts, per_domain):
        row = next(
            (
                candidate
                for candidate in manifest.rows
                if counts[candidate.context.domain] < per_domain
                and candidate.key not in checkpoints
                and (
                    not require_development_coverage
                    or _candidate_advances_development_coverage(
                        candidate, manifest, checkpoints
                    )
                )
            ),
            None,
        )
        if row is None:
            raise CleanControlError(
                "candidate manifest was exhausted before every domain reached "
                f"the requested {per_domain} utility-successful contexts with "
                "the required development coverage"
            )
        domain = row.context.domain
        try:
            result = execute_clean_control(
                row,
                manifest_sha256=manifest.sha256,
                split=split,
                results_path=results_path,
                raw_root=raw_root,
                force_rerun=force_rerun,
            )
        except (ClientError, RequestBudgetExceeded) as error:
            if not is_quota_exhausted(error):
                raise
            print(
                "Stopping cleanly: Gemini quota/request budget reached; "
                f"completed controls remain checkpointed in {results_path}",
                file=sys.stderr,
            )
            return 2
        except BenchmarkTraceError as error:
            print(
                "Stopping cleanly: AgentDojo produced an invalid clean trace; "
                f"no checkpoint was appended. {error}",
                file=sys.stderr,
            )
            return 3
        checkpoints[row.key] = result
        selected, counts = selected_contexts(
            manifest,
            checkpoints,
            per_domain=per_domain,
            require_development_coverage=require_development_coverage,
        )
        _write_control_state(
            cursor_path,
            manifest,
            checkpoints,
            split=split,
            per_domain=per_domain,
        )
        print(
            f"Clean control rank={row.candidate_rank} domain={domain} "
            f"utility_success={result.utility_success}"
        )
        if _all_domains_complete(counts, per_domain):
            selected, _ = selected_contexts(
                manifest,
                checkpoints,
                per_domain=per_domain,
                require_development_coverage=require_development_coverage,
            )
            content = render_selection(selected)
            _write_atomic(selection_output, content, refuse_changed=True)
            print(
                f"Selected {len(selected)} contexts ({per_domain}/domain): "
                f"{selection_output}"
            )
            return 0

    raise AssertionError("unreachable clean-control selection state")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--selection-output", type=Path, required=True)
    parser.add_argument("--per-domain", type=int, required=True)
    parser.add_argument("--exclude", type=Path)
    parser.add_argument("--split", choices=("dev", "holdout"))
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument(
        "--state-output",
        type=Path,
        help=(
            "atomic deterministic continuation state; defaults beside the "
            "selection output as <stem>.state.json"
        ),
    )
    add_quota_arguments(parser)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    validate_quota_count_args(args)
    input_path = args.input.resolve()
    selection_output = args.selection_output.resolve()
    results_path = args.results_path.resolve()
    raw_root = args.raw_root.resolve()
    state_output = args.state_output.resolve() if args.state_output is not None else None
    exclude_path = args.exclude.resolve() if args.exclude is not None else None

    manifest = load_context_manifest(input_path)
    split = infer_split(input_path, args.split)
    validate_canonical_source_provenance(manifest, split=split)
    excluded_keys: set[tuple[str, str, str, str]] = set()
    excluded_manifest_sha256: str | None = None
    if exclude_path is not None:
        excluded_manifest = load_context_manifest(exclude_path)
        excluded_keys = set(excluded_manifest.by_key)
        excluded_manifest_sha256 = excluded_manifest.sha256

    # Reject all deterministic command/state failures before quota reservation.
    preflight_controls(
        manifest=manifest,
        selection_output=selection_output,
        per_domain=args.per_domain,
        split=split,
        results_path=results_path,
        raw_root=raw_root,
        state_output=state_output,
        excluded_keys=excluded_keys,
        excluded_manifest_path=exclude_path,
    )

    # Re-read mutable inputs and state under the shared experiment lock.  A
    # zero-attempt exception here is reconciled by QuotaGuard without retaining
    # the conservative reservation.
    with quota_guard_from_args(args):
        locked_manifest = load_context_manifest(input_path)
        locked_split = infer_split(input_path, args.split)
        validate_canonical_source_provenance(locked_manifest, split=locked_split)
        if locked_manifest.sha256 != manifest.sha256 or locked_split != split:
            raise CleanControlError("input manifest changed during command preflight")
        locked_excluded_keys: set[tuple[str, str, str, str]] = set()
        if exclude_path is not None:
            locked_excluded_manifest = load_context_manifest(exclude_path)
            if locked_excluded_manifest.sha256 != excluded_manifest_sha256:
                raise CleanControlError(
                    "excluded manifest changed during command preflight"
                )
            locked_excluded_keys = set(locked_excluded_manifest.by_key)
        return run_controls(
            manifest=locked_manifest,
            selection_output=selection_output,
            per_domain=args.per_domain,
            split=split,
            results_path=results_path,
            raw_root=raw_root,
            state_output=state_output,
            excluded_keys=locked_excluded_keys,
            excluded_manifest_path=exclude_path,
        )


if __name__ == "__main__":
    raise SystemExit(main())
