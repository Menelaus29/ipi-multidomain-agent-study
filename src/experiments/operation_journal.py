"""Durable recovery state for Phase 6A AgentDojo API operations.

The journal is deliberately benchmark-specific.  It records the immutable
AgentDojo task, model, pipeline, attack, and trace identity before an API call,
then atomically advances the operation through request, raw-trace, result, and
JSONL-index states.  It contains no credentials or arbitrary external targets.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import traceback
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from google.genai.errors import ClientError

from src.llm_providers.google_llm_factory import RequestBudgetExceeded


JOURNAL_SCHEMA_VERSION = 1
MAX_EXCEPTION_TRACEBACK_CHARS = 8000
UNEXPECTED_EXECUTION_EXIT_CODE = 4
_STATUSES = {
    "prepared",
    "running",
    "api_returned",
    "raw_persisted",
    "failed",
    "completed",
    "indexed",
}


class OperationJournalError(RuntimeError):
    """Raised when durable operation state is corrupt or contradicts a run."""


class RawTraceError(OperationJournalError):
    """Raised when an AgentDojo trace cannot be safely reused."""


class RawTraceProvenanceError(RawTraceError):
    """Raised when a raw trace belongs to a different operation."""


class ErroredRawTrace(RawTraceError):
    """Raised for a provenance-valid AgentDojo skipped/errored trace."""

    def __init__(self, message: str, trace: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.trace = dict(trace)


def operation_exception_diagnostic(error: Exception) -> str:
    """Return bounded diagnostic detail suitable for a durable journal."""

    rendered = "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )
    if len(rendered) > MAX_EXCEPTION_TRACEBACK_CHARS:
        rendered = (
            rendered[: MAX_EXCEPTION_TRACEBACK_CHARS - 30]
            + "\n...[traceback truncated]\n"
        )
    return (
        f"exception_type={type(error).__module__}.{type(error).__qualname__}; "
        f"message={error}; traceback=\n{rendered}"
    )


def operation_exception_summary(error: Exception, *, max_chars: int = 300) -> str:
    """Return a single-line exception summary for stderr reporting."""

    message = " ".join(str(error).split())
    summary = f"{type(error).__module__}.{type(error).__qualname__}: {message}"
    if len(summary) > max_chars:
        return summary[: max_chars - 3] + "..."
    return summary


def _is_quota_boundary_exception(error: Exception) -> bool:
    message = str(error).lower()
    return (
        isinstance(error, RequestBudgetExceeded)
        or getattr(error, "code", None) == 429
        or "429" in message
    )


@dataclass(frozen=True)
class OperationSpec:
    """Immutable provenance for one target or clean-control operation."""

    operation_id: str
    operation_kind: str
    domain: str
    suite_name: str
    model: str
    pipeline_name: str
    benchmark_version: str
    user_task_id: str
    context_injection_task_id: str
    raw_injection_task_id: str | None
    channel: str
    injection_vector: str
    attack_id: str | None
    attack_name: str | None
    expected_raw_injection_vector: str | None
    operation_metadata: Mapping[str, Any]
    raw_trace_path: Path
    index_path: Path

    def durable_fields(self) -> dict[str, Any]:
        fields = asdict(self)
        fields["operation_metadata"] = dict(self.operation_metadata)
        fields["raw_trace_path"] = str(self.raw_trace_path.resolve())
        fields["index_path"] = str(self.index_path.resolve())
        return fields


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def agentdojo_raw_trace_path(
    logdir: Path,
    *,
    pipeline_name: str,
    suite_name: str,
    user_task_id: str,
    attack_name: str | None,
    injection_task_id: str | None,
) -> Path:
    """Return AgentDojo's deterministic TraceLogger output path."""

    safe_pipeline = pipeline_name.replace("/", "_")
    attack_component = attack_name or "none"
    injection_component = injection_task_id or "none"
    return (
        logdir
        / safe_pipeline
        / suite_name
        / user_task_id
        / attack_component
        / f"{injection_component}.json"
    )


def atomic_write_bytes(
    path: Path,
    content: bytes,
    *,
    refuse_changed: bool = False,
) -> bool:
    """Atomically replace bytes, optionally preserving an existing artifact.

    This is the shared persistence primitive for Phase 6A state, JSON, and
    JSONL files.  It returns whether bytes were written.
    """

    if path.exists():
        if path.read_bytes() == content:
            return False
        if refuse_changed:
            raise OperationJournalError(
                f"refusing to overwrite changed artifact: {path}"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return True
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(dict(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def atomic_write_json(
    path: Path,
    value: Mapping[str, Any] | list[Any],
    *,
    refuse_changed: bool = False,
) -> bool:
    """Serialize canonical UTF-8 JSON and atomically replace its artifact."""

    content = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return atomic_write_bytes(path, content, refuse_changed=refuse_changed)


def append_jsonl_atomic(path: Path, record: Mapping[str, Any]) -> None:
    """Atomically append one canonical JSONL record without identity semantics."""

    existing = path.read_bytes() if path.exists() else b""
    if existing and not existing.endswith(b"\n"):
        raise OperationJournalError(f"existing JSONL lacks a final newline: {path}")
    line = (
        json.dumps(dict(record), ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    atomic_write_bytes(path, existing + line)


def _validate_timestamp(value: object, *, path: Path) -> str:
    if not isinstance(value, str) or not value:
        raise OperationJournalError(f"{path} timestamp must be a non-empty string")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise OperationJournalError(f"{path} timestamp must be ISO-8601") from error
    return value


def raw_trace_timestamp(path: Path) -> str | None:
    """Read AgentDojo's original evaluation timestamp when safely available."""

    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping):
        return None
    timestamp = value.get("evaluation_timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return timestamp


class OperationJournal:
    """Atomically persisted state for exactly one API-backed operation."""

    def __init__(self, path: Path, spec: OperationSpec, state: dict[str, Any]) -> None:
        self.path = path
        self.spec = spec
        self._state = state

    @staticmethod
    def _path_for(root: Path, spec: OperationSpec) -> Path:
        digest = hashlib.sha256(
            f"{spec.operation_kind}\0{spec.operation_id}".encode("utf-8")
        ).hexdigest()
        return root / f"{digest}.json"

    @classmethod
    def load_existing(
        cls, root: Path, spec: OperationSpec
    ) -> "OperationJournal | None":
        """Validate an existing sidecar without creating or changing state."""

        path = cls._path_for(root, spec)
        if not path.exists():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise OperationJournalError(
                f"operation journal is unreadable: {path}"
            ) from error
        if not isinstance(loaded, dict):
            raise OperationJournalError(f"operation journal must be an object: {path}")
        cls._validate_state(path, loaded, spec.durable_fields())
        return cls(path, spec, loaded)

    @classmethod
    def open(
        cls,
        root: Path,
        spec: OperationSpec,
        *,
        initial_timestamp: str | None = None,
    ) -> "OperationJournal":
        path = cls._path_for(root, spec)
        durable = spec.durable_fields()
        if path.exists():
            existing = cls.load_existing(root, spec)
            assert existing is not None
            return existing

        timestamp = initial_timestamp or utc_now()
        _validate_timestamp(timestamp, path=path)
        state: dict[str, Any] = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            **durable,
            "timestamp": timestamp,
            "updated_at": timestamp,
            "status": "prepared",
            "request_attempts": 0,
            "request_count_source": "provider_observer",
            "api_attempts": [],
            "failures": [],
            "result_record": None,
        }
        journal = cls(path, spec, state)
        journal._persist()
        return journal

    @staticmethod
    def _validate_state(
        path: Path, state: Mapping[str, Any], durable: Mapping[str, Any]
    ) -> None:
        if state.get("schema_version") != JOURNAL_SCHEMA_VERSION:
            raise OperationJournalError(f"unsupported operation journal schema: {path}")
        for key, expected in durable.items():
            if state.get(key) != expected:
                raise OperationJournalError(
                    f"operation journal provenance disagrees for {key}: {path}"
                )
        _validate_timestamp(state.get("timestamp"), path=path)
        if state.get("status") not in _STATUSES:
            raise OperationJournalError(f"invalid operation status in {path}")
        count = state.get("request_attempts")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise OperationJournalError(f"invalid request_attempts in {path}")
        if state.get("request_count_source") not in {
            "provider_observer",
            "raw_trace_inferred_lower_bound",
        }:
            raise OperationJournalError(f"invalid request_count_source in {path}")
        api_attempts = state.get("api_attempts")
        if not isinstance(api_attempts, list):
            raise OperationJournalError(f"invalid api_attempts in {path}")
        for position, attempt in enumerate(api_attempts, 1):
            if not isinstance(attempt, Mapping):
                raise OperationJournalError(
                    f"invalid API attempt {position} in {path}"
                )
            request_count = attempt.get("request_attempts")
            if (
                isinstance(request_count, bool)
                or not isinstance(request_count, int)
                or request_count < 0
                or attempt.get("status")
                not in {"running", "api_returned", "failed"}
            ):
                raise OperationJournalError(
                    f"invalid API attempt {position} in {path}"
                )
        failures = state.get("failures")
        if not isinstance(failures, list):
            raise OperationJournalError(f"invalid failures in {path}")
        if any(not isinstance(failure, Mapping) for failure in failures):
            raise OperationJournalError(f"invalid failure history in {path}")
        result = state.get("result_record")
        if result is not None and not isinstance(result, dict):
            raise OperationJournalError(f"invalid result_record in {path}")
        api_response = state.get("api_response_record")
        if api_response is not None and not isinstance(api_response, dict):
            raise OperationJournalError(f"invalid api_response_record in {path}")
        if state.get("status") == "raw_persisted" and api_response is None:
            raise OperationJournalError(
                f"raw-persisted operation lacks api_response_record: {path}"
            )
        if state.get("status") in {"completed", "indexed"} and result is None:
            raise OperationJournalError(
                f"completed operation journal lacks result_record: {path}"
            )

    def _persist(self) -> None:
        self._state["updated_at"] = utc_now()
        atomic_write_bytes(self.path, _canonical_json(self._state))

    @property
    def operation_id(self) -> str:
        return str(self._state["operation_id"])

    @property
    def timestamp(self) -> str:
        return str(self._state["timestamp"])

    @property
    def request_attempts(self) -> int:
        return int(self._state["request_attempts"])

    @property
    def result_record(self) -> dict[str, Any] | None:
        value = self._state.get("result_record")
        return dict(value) if isinstance(value, dict) else None

    @property
    def api_response_record(self) -> dict[str, Any] | None:
        value = self._state.get("api_response_record")
        return dict(value) if isinstance(value, dict) else None

    @property
    def status(self) -> str:
        return str(self._state["status"])

    @property
    def failure_records(self) -> tuple[dict[str, Any], ...]:
        failures = self._state["failures"]
        assert isinstance(failures, list)
        return tuple(dict(failure) for failure in failures)

    def validate_provider_request_accounting(
        self,
        *,
        reusable_statuses: frozenset[str],
    ) -> None:
        """Validate observer-backed request totals for a reusable completion."""

        attempts = self._state["api_attempts"]
        assert isinstance(attempts, list)
        observed = sum(int(attempt["request_attempts"]) for attempt in attempts)
        reusable_completion = any(
            attempt.get("status") in reusable_statuses
            and int(attempt["request_attempts"]) > 0
            for attempt in attempts
        )
        if (
            self._state.get("request_count_source") != "provider_observer"
            or not attempts
            or observed != self.request_attempts
            or self.request_attempts < 1
            or not reusable_completion
        ):
            raise OperationJournalError(
                f"provider request-attempt accounting is inconsistent: {self.path}"
            )

    def ensure_nonzero_inferred_attempts(self, raw_trace: Mapping[str, Any]) -> None:
        """Recover a conservative nonzero count for a pre-journal raw cache."""

        if self.request_attempts:
            return
        api_attempts = self._state["api_attempts"]
        assert isinstance(api_attempts, list)
        if api_attempts:
            # A journaled provider observer is authoritative even when it
            # recorded zero because AgentDojo failed before the provider call.
            return
        messages = raw_trace.get("messages")
        assistant_messages = 0
        if isinstance(messages, list):
            assistant_messages = sum(
                1
                for message in messages
                if isinstance(message, Mapping) and message.get("role") == "assistant"
            )
        self._state["request_attempts"] = max(1, assistant_messages)
        self._state["request_count_source"] = "raw_trace_inferred_lower_bound"
        self._persist()

    def begin_api_attempt(self, *, force_rerun: bool) -> tuple[int, int]:
        """Start a retryable API attempt and return (attempt index, base count)."""

        if self.status not in {"prepared", "failed"}:
            raise OperationJournalError(
                f"operation cannot start an API attempt from state "
                f"{self.status}: {self.path}"
            )

        attempts = self._state["api_attempts"]
        assert isinstance(attempts, list)
        base_count = self.request_attempts
        attempts.append(
            {
                "attempt_number": len(attempts) + 1,
                "started_at": utc_now(),
                "completed_at": None,
                "force_rerun": force_rerun,
                "request_attempts_before": base_count,
                "request_attempts": 0,
                "status": "running",
                "error": None,
            }
        )
        self._state["status"] = "running"
        self._persist()
        return len(attempts) - 1, base_count

    def observe_request_count(
        self,
        *,
        attempt_index: int,
        base_count: int,
        process_count_before: int,
        process_count_now: int,
    ) -> None:
        delta = process_count_now - process_count_before
        if delta < 0:
            raise OperationJournalError("provider request counter moved backwards")
        attempts = self._state["api_attempts"]
        assert isinstance(attempts, list)
        attempt = attempts[attempt_index]
        attempt["request_attempts"] = delta
        self._state["request_attempts"] = base_count + delta
        self._state["request_count_source"] = "provider_observer"
        self._persist()

    def mark_api_returned(self, *, attempt_index: int) -> None:
        attempts = self._state["api_attempts"]
        assert isinstance(attempts, list)
        attempts[attempt_index]["status"] = "api_returned"
        attempts[attempt_index]["completed_at"] = utc_now()
        self._state["status"] = "api_returned"
        self._persist()

    def store_api_response(
        self, record: Mapping[str, Any], *, attempt_index: int
    ) -> None:
        """Atomically retain a provider response before separate raw persistence."""

        if self.request_attempts < 1:
            raise OperationJournalError(
                "cannot store an API response without a provider request attempt"
            )
        attempts = self._state["api_attempts"]
        assert isinstance(attempts, list)
        attempt = attempts[attempt_index]
        if attempt.get("status") != "running":
            raise OperationJournalError("API attempt is not running")
        attempt["status"] = "api_returned"
        attempt["completed_at"] = utc_now()
        self._state["api_response_record"] = dict(record)
        self._state["status"] = "api_returned"
        self._persist()

    def mark_raw_persisted(self) -> None:
        """Record that the durable API response also exists at its raw path."""

        if not isinstance(self._state.get("api_response_record"), dict):
            raise OperationJournalError(
                "cannot mark raw persistence without an API response"
            )
        if not self.spec.raw_trace_path.is_file():
            raise OperationJournalError(
                f"cannot mark missing raw response persisted: {self.spec.raw_trace_path}"
            )
        self._state["status"] = "raw_persisted"
        self._persist()

    def recover_interrupted_before_request(self) -> None:
        """Close a running zero-request attempt so the operation can resume."""

        if self.status != "running":
            return
        attempts = self._state["api_attempts"]
        assert isinstance(attempts, list)
        if not attempts or attempts[-1].get("status") != "running":
            raise OperationJournalError(
                "running operation has no matching running API attempt"
            )
        if attempts[-1].get("request_attempts") != 0:
            raise OperationJournalError(
                "provider request started without a durable response; "
                "refusing to repeat ambiguous API work"
            )
        self.record_failure(
            "operation was interrupted before its provider request started",
            attempt_index=len(attempts) - 1,
        )

    def record_failure(self, message: str, *, attempt_index: int | None) -> None:
        failures = self._state["failures"]
        assert isinstance(failures, list)
        fingerprint = hashlib.sha256(message.encode("utf-8")).hexdigest()
        if not failures or failures[-1].get("fingerprint") != fingerprint:
            failure = {
                "timestamp": utc_now(),
                "fingerprint": fingerprint,
                "error": message,
                "request_attempts": self.request_attempts,
                "raw_trace_path": self._state["raw_trace_path"],
            }
            if isinstance(self._state.get("result_record"), dict):
                failure["discarded_result_record"] = self._state["result_record"]
            failures.append(failure)
        if attempt_index is not None:
            attempts = self._state["api_attempts"]
            assert isinstance(attempts, list)
            attempts[attempt_index]["status"] = "failed"
            attempts[attempt_index]["completed_at"] = utc_now()
            attempts[attempt_index]["error"] = message
        self._state["status"] = "failed"
        # A pending index record is valid only while its raw trace is valid.
        # Preserve it in failure history above, but never replay it after a
        # failed-cache detection and force-rerun.
        self._state["result_record"] = None
        self._persist()

    def store_result(self, record: Mapping[str, Any]) -> None:
        self._state["result_record"] = dict(record)
        self._state["status"] = "completed"
        self._persist()

    def mark_indexed(self) -> None:
        if not isinstance(self._state.get("result_record"), dict):
            raise OperationJournalError("cannot index an operation without a result")
        self._state["status"] = "indexed"
        self._persist()


def load_validated_raw_trace(spec: OperationSpec) -> dict[str, Any] | None:
    """Load a completed trace only when every AgentDojo identity field matches."""

    path = spec.raw_trace_path
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RawTraceError(f"raw trace is unreadable: {path}") from error
    if not isinstance(value, dict):
        raise RawTraceError(f"raw trace must be a JSON object: {path}")

    expected = {
        "suite_name": spec.suite_name,
        "pipeline_name": spec.pipeline_name.replace("/", "_"),
        "benchmark_version": spec.benchmark_version,
        "user_task_id": spec.user_task_id,
        "injection_task_id": spec.raw_injection_task_id,
        "attack_type": spec.attack_name,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise RawTraceProvenanceError(
                f"raw trace provenance disagrees for {key}: expected "
                f"{expected_value!r}, found {value.get(key)!r}: {path}"
            )

    injections = value.get("injections")
    if spec.expected_raw_injection_vector is None:
        if injections != {}:
            raise RawTraceProvenanceError(
                f"clean-control raw trace contains injections: {path}"
            )
    elif not isinstance(injections, Mapping) or set(injections) != {
        spec.expected_raw_injection_vector
    }:
        raise RawTraceProvenanceError(
            f"raw trace injection vector disagrees with operation context: {path}"
        )

    if value.get("error"):
        raise ErroredRawTrace(
            f"AgentDojo trace is errored/skipped, not a valid completion: "
            f"{path}: {value['error']}",
            value,
        )
    if not isinstance(value.get("messages"), list):
        raise RawTraceError(f"raw trace messages must be a JSON list: {path}")
    if not isinstance(value.get("utility"), bool) or not isinstance(
        value.get("security"), bool
    ):
        # AgentDojo can leave behind a provenance-valid but incomplete cache
        # when evaluation does not reach its verdict-writing step.  It cannot
        # be reused as a result, but it is safe to journal as a failed attempt
        # and force-rerun the same immutable operation on resume.
        raise ErroredRawTrace(
            f"AgentDojo trace lacks boolean utility/security verdicts and is "
            f"not a valid completion: {path}",
            value,
        )
    return value


def execute_journaled_agentdojo_benchmark(
    *,
    journal: OperationJournal,
    force_rerun: bool,
    benchmark: Callable[..., Mapping[str, Any]],
    observe_attempts: Callable[[Callable[[int], None]], Any],
    get_attempt_count: Callable[[], int],
    benchmark_kwargs: Mapping[str, Any],
) -> tuple[Mapping[str, Any], int]:
    """Run one AgentDojo call while durably recording provider attempts.

    Result construction and benchmark-specific verdict interpretation remain in
    the caller; this shared operation only owns the identical API/journal
    boundary used by calibrated targets and clean controls.
    """

    # AgentDojo's TraceLogger writes directly to its fully expanded
    # attack-specific path.  A new attack name therefore needs its own parent
    # directory before the benchmark begins; otherwise the model call can run
    # but trace persistence fails before a reusable verdict is recorded.
    journal.spec.raw_trace_path.parent.mkdir(parents=True, exist_ok=True)
    attempt_index, base_count = journal.begin_api_attempt(force_rerun=force_rerun)
    requests_before = get_attempt_count()

    def observe(process_count: int) -> None:
        journal.observe_request_count(
            attempt_index=attempt_index,
            base_count=base_count,
            process_count_before=requests_before,
            process_count_now=process_count,
        )

    try:
        with observe_attempts(observe):
            result = benchmark(**dict(benchmark_kwargs))
    except (ClientError, RequestBudgetExceeded) as error:
        detail = (
            str(error)
            if _is_quota_boundary_exception(error)
            else operation_exception_diagnostic(error)
        )
        journal.record_failure(
            f"benchmark call failed before a reusable completion: {detail}",
            attempt_index=attempt_index,
        )
        raise
    except Exception as error:
        journal.record_failure(
            "benchmark call failed before a reusable completion: "
            + operation_exception_diagnostic(error),
            attempt_index=attempt_index,
        )
        raise
    journal.mark_api_returned(attempt_index=attempt_index)
    return result, attempt_index


def append_jsonl_once(
    path: Path,
    record: Mapping[str, Any],
    *,
    identity_field: str,
) -> bool:
    """Atomically append a record once, accepting an identical prior append."""

    identity = record.get(identity_field)
    if not isinstance(identity, str) or not identity:
        raise OperationJournalError(
            f"record lacks non-empty identity field {identity_field!r}"
        )
    existing = path.read_bytes() if path.exists() else b""
    if existing and not existing.endswith(b"\n"):
        raise OperationJournalError(f"existing JSONL lacks a final newline: {path}")
    try:
        existing_text = existing.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OperationJournalError(f"existing JSONL is not UTF-8: {path}") from error
    for line_number, line in enumerate(existing_text.splitlines(), 1):
        try:
            current = json.loads(line)
        except json.JSONDecodeError as error:
            raise OperationJournalError(
                f"existing JSONL is invalid at {path}:{line_number}"
            ) from error
        if isinstance(current, Mapping) and current.get(identity_field) == identity:
            if dict(current) != dict(record):
                raise OperationJournalError(
                    f"JSONL identity {identity!r} has conflicting content: {path}"
                )
            return False
    encoded = (
        json.dumps(dict(record), ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    atomic_write_bytes(path, existing + encoded)
    return True
