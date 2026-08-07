"""Dashboard-aware request quota guard for recorded Gemini experiments.

The guard reserves a conservative process budget in a persistent, Pacific-date
ledger before an experiment can make its first API request. A cross-platform
file lock is held for the complete guarded run, so two experiment processes
cannot consume the same quota allowance concurrently.

Future API runners should register the shared arguments with
``add_quota_arguments()`` and enter ``quota_guard_from_args(args)`` before
constructing an LLM. Mixed-mode runners may register the arguments with
``required=False`` for no-network stages; entering the guard still rejects any
missing value.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, TextIO
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from filelock import FileLock, Timeout

from src.llm_providers.google_llm_factory import (
    configure_google_request_attempt_limit,
    get_google_request_attempt_count,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER_PATH = PROJECT_ROOT / "data" / "quota_ledger.jsonl"
PACIFIC_TIME_ZONE = "America/Los_Angeles"
STUDY_RPD_LIMIT = 500
EXPERIMENT_RESERVE = 25
LEDGER_SCHEMA_VERSION = 1

_LEDGER_FIELDS = {
    "schema_version",
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
}


class QuotaGuardError(RuntimeError):
    """Base error for invalid or unsafe quota-guard state."""


class QuotaValidationError(QuotaGuardError):
    """Raised when supplied dashboard or ledger values are invalid."""


class ConcurrentQuotaRunError(QuotaGuardError):
    """Raised when another guarded experiment already owns the ledger lock."""


def add_quota_arguments(
    parser: argparse.ArgumentParser, *, required: bool = True
) -> None:
    """Register the four quota arguments shared by all new API runners.

    ``required=False`` is intended only for commands that also expose a
    no-network mode (for example, attack freezing). Any code path that enters
    :func:`quota_guard_from_args` still requires all four values.
    """

    parser.add_argument(
        "--quota-date",
        required=required,
        help="Current quota date in America/Los_Angeles (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--dashboard-used",
        required=required,
        type=int,
        help="Current Gemini RPD usage shown by the dashboard",
    )
    parser.add_argument(
        "--dashboard-limit",
        required=required,
        type=int,
        help="Current Gemini RPD limit shown by the dashboard",
    )
    parser.add_argument(
        "--max-api-requests",
        required=required,
        type=int,
        help="Requested hard request-attempt cap for this process",
    )


def _pacific_zone() -> ZoneInfo:
    try:
        return ZoneInfo(PACIFIC_TIME_ZONE)
    except ZoneInfoNotFoundError as error:
        raise QuotaValidationError(
            "America/Los_Angeles timezone data is unavailable; install the "
            "project's pinned tzdata dependency"
        ) from error


def pacific_quota_date(now_utc: datetime | None = None) -> str:
    """Return the current Google RPD date in ``America/Los_Angeles``."""

    current = now_utc or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise QuotaValidationError("The quota clock must be timezone-aware")
    return current.astimezone(_pacific_zone()).date().isoformat()


def _utc_timestamp(now_utc: datetime) -> str:
    if now_utc.tzinfo is None or now_utc.utcoffset() is None:
        raise QuotaValidationError("The quota clock must be timezone-aware")
    return now_utc.astimezone(timezone.utc).isoformat()


def _require_count(value: object, name: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise QuotaValidationError(f"{name} must be an integer")
    minimum = 1 if positive else 0
    if value < minimum:
        qualifier = "positive" if positive else "nonnegative"
        raise QuotaValidationError(f"{name} must be {qualifier}")
    return value


def _validate_quota_date(value: object, expected: str) -> str:
    if not isinstance(value, str):
        raise QuotaValidationError("quota_date must use YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise QuotaValidationError("quota_date must use YYYY-MM-DD") from error
    normalized = parsed.isoformat()
    if value != normalized:
        raise QuotaValidationError("quota_date must use canonical YYYY-MM-DD")
    if normalized != expected:
        raise QuotaValidationError(
            f"quota_date {normalized} is stale or wrong; current "
            f"America/Los_Angeles date is {expected}"
        )
    return normalized


def _validate_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise QuotaValidationError(f"Ledger field {field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise QuotaValidationError(
            f"Ledger field {field} must be an ISO-8601 timestamp"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QuotaValidationError(
            f"Ledger field {field} must be timezone-aware"
        )
    return value


def _optional_timestamp(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _validate_timestamp(value, field)


def _validate_ledger_record(record: object, line_number: int) -> dict[str, Any]:
    path = f"quota ledger line {line_number}"
    if not isinstance(record, Mapping):
        raise QuotaValidationError(f"{path} must be a JSON object")
    missing = sorted(_LEDGER_FIELDS - set(record))
    extra = sorted(set(record) - _LEDGER_FIELDS)
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        raise QuotaValidationError(f"{path} has invalid fields: {'; '.join(detail)}")

    validated = dict(record)
    schema_version = _require_count(
        record["schema_version"], f"{path}.schema_version"
    )
    if schema_version != LEDGER_SCHEMA_VERSION:
        raise QuotaValidationError(
            f"{path}.schema_version must be {LEDGER_SCHEMA_VERSION}"
        )
    quota_date = record["quota_date"]
    if not isinstance(quota_date, str):
        raise QuotaValidationError(f"{path}.quota_date must use YYYY-MM-DD")
    try:
        parsed_date = date.fromisoformat(quota_date)
    except ValueError as error:
        raise QuotaValidationError(
            f"{path}.quota_date must use YYYY-MM-DD"
        ) from error
    if quota_date != parsed_date.isoformat():
        raise QuotaValidationError(
            f"{path}.quota_date must use canonical YYYY-MM-DD"
        )

    _validate_timestamp(record["reserved_at"], f"{path}.reserved_at")
    _optional_timestamp(record["reconciled_at"], f"{path}.reconciled_at")
    _optional_timestamp(
        record["interruption_resolved_at"],
        f"{path}.interruption_resolved_at",
    )
    for field in (
        "dashboard_used",
        "dashboard_limit",
        "effective_limit",
        "known_used_before",
        "requested_cap",
        "reserved_attempts",
    ):
        _require_count(
            record[field],
            f"{path}.{field}",
            positive=field
            in {
                "dashboard_limit",
                "effective_limit",
                "requested_cap",
                "reserved_attempts",
            },
        )
    for field in ("actual_attempts", "resolution_dashboard_used"):
        value = record[field]
        if value is not None:
            _require_count(value, f"{path}.{field}")

    if record["dashboard_used"] > record["dashboard_limit"]:
        raise QuotaValidationError(
            f"{path}.dashboard_used cannot exceed dashboard_limit"
        )
    if record["effective_limit"] > STUDY_RPD_LIMIT:
        raise QuotaValidationError(
            f"{path}.effective_limit exceeds the study ceiling"
        )
    if record["reserved_attempts"] > record["requested_cap"]:
        raise QuotaValidationError(
            f"{path}.reserved_attempts cannot exceed requested_cap"
        )

    reconciled = record["reconciled_at"] is not None
    has_actual = record["actual_attempts"] is not None
    resolved = record["interruption_resolved_at"] is not None
    has_resolution_count = record["resolution_dashboard_used"] is not None
    if reconciled != has_actual:
        raise QuotaValidationError(
            f"{path} must populate reconciled_at and actual_attempts together"
        )
    if resolved != has_resolution_count:
        raise QuotaValidationError(
            f"{path} must populate interruption resolution fields together"
        )
    if reconciled and resolved:
        raise QuotaValidationError(
            f"{path} cannot be both reconciled and interruption-resolved"
        )
    if has_actual and record["actual_attempts"] > record["reserved_attempts"]:
        raise QuotaValidationError(
            f"{path}.actual_attempts cannot exceed reserved_attempts"
        )
    return validated


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise QuotaValidationError(
                    f"quota ledger line {line_number} cannot be blank"
                )
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as error:
                raise QuotaValidationError(
                    f"quota ledger line {line_number} is invalid JSON"
                ) from error
            records.append(_validate_ledger_record(raw, line_number))
    return records


def _write_ledger_atomic(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    """Replace the ledger atomically while its separate lock is held."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(
                    json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
                )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _is_open_reservation(record: Mapping[str, Any]) -> bool:
    return (
        record["reconciled_at"] is None
        and record["interruption_resolved_at"] is None
    )


def _record_used_ceiling(record: Mapping[str, Any]) -> int:
    known_before = int(record["known_used_before"])
    if record["actual_attempts"] is not None:
        return known_before + int(record["actual_attempts"])
    if record["resolution_dashboard_used"] is not None:
        return max(known_before, int(record["resolution_dashboard_used"]))
    return known_before + int(record["reserved_attempts"])


def _ledger_known_used(records: Sequence[Mapping[str, Any]], quota_date: str) -> int:
    return max(
        (
            _record_used_ceiling(record)
            for record in records
            if record["quota_date"] == quota_date
        ),
        default=0,
    )


class QuotaGuard(AbstractContextManager["QuotaGuard"]):
    """Reserve, enforce, and reconcile one process's Gemini request budget."""

    def __init__(
        self,
        *,
        quota_date: str,
        dashboard_used: int,
        dashboard_limit: int,
        max_api_requests: int,
        ledger_path: Path = DEFAULT_LEDGER_PATH,
        now_utc: Callable[[], datetime] | None = None,
        configure_attempt_limit: Callable[[int | None], None] = (
            configure_google_request_attempt_limit
        ),
        get_attempt_count: Callable[[], int] = get_google_request_attempt_count,
        output: TextIO = sys.stdout,
    ) -> None:
        self.supplied_quota_date = quota_date
        self.dashboard_used = dashboard_used
        self.dashboard_limit = dashboard_limit
        self.max_api_requests = max_api_requests
        self.ledger_path = Path(ledger_path)
        self.lock_path = self.ledger_path.with_name(self.ledger_path.name + ".lock")
        self._now_utc = now_utc or (lambda: datetime.now(timezone.utc))
        self._configure_attempt_limit = configure_attempt_limit
        self._get_attempt_count = get_attempt_count
        self._output = output
        self._lock = FileLock(str(self.lock_path))
        self._entered = False
        self._record_index: int | None = None
        self._attempts_before: int | None = None
        self._effective_cap: int | None = None
        self._effective_limit: int | None = None
        self._known_used: int | None = None

    @property
    def effective_cap(self) -> int:
        if self._effective_cap is None:
            raise QuotaGuardError("QuotaGuard has not been entered")
        return self._effective_cap

    @property
    def effective_limit(self) -> int:
        if self._effective_limit is None:
            raise QuotaGuardError("QuotaGuard has not been entered")
        return self._effective_limit

    @property
    def known_used(self) -> int:
        if self._known_used is None:
            raise QuotaGuardError("QuotaGuard has not been entered")
        return self._known_used

    def __enter__(self) -> "QuotaGuard":
        if self._entered:
            raise QuotaGuardError("QuotaGuard instances cannot be re-entered")

        current = self._now_utc()
        expected_date = pacific_quota_date(current)
        quota_date = _validate_quota_date(self.supplied_quota_date, expected_date)
        dashboard_used = _require_count(self.dashboard_used, "dashboard_used")
        dashboard_limit = _require_count(
            self.dashboard_limit, "dashboard_limit", positive=True
        )
        requested_cap = _require_count(
            self.max_api_requests, "max_api_requests", positive=True
        )
        if dashboard_used > dashboard_limit:
            raise QuotaValidationError(
                "dashboard_used cannot exceed dashboard_limit"
            )

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._lock.acquire(timeout=0)
        except Timeout as error:
            raise ConcurrentQuotaRunError(
                f"Another experiment process holds quota lock {self.lock_path}"
            ) from error

        try:
            records = _read_ledger(self.ledger_path)
            timestamp = _utc_timestamp(current)

            # Acquiring the whole-run lock proves that same-day open records are
            # abandoned. This invocation's freshly supplied dashboard value
            # resolves them without guessing their actual attempt count.
            resolved_any = False
            for record in records:
                if (
                    record["quota_date"] == quota_date
                    and _is_open_reservation(record)
                ):
                    record["interruption_resolved_at"] = timestamp
                    record["resolution_dashboard_used"] = dashboard_used
                    resolved_any = True
            if resolved_any:
                _write_ledger_atomic(self.ledger_path, records)

            effective_limit = min(STUDY_RPD_LIMIT, dashboard_limit)
            ledger_used = _ledger_known_used(records, quota_date)
            known_used = max(dashboard_used, ledger_used)
            available = effective_limit - known_used - EXPERIMENT_RESERVE
            effective_cap = min(requested_cap, available)
            if effective_cap <= 0:
                raise QuotaValidationError(
                    "No positive experiment budget remains: "
                    f"effective_limit={effective_limit}, known_used={known_used}, "
                    f"reserve={EXPERIMENT_RESERVE}"
                )

            attempts_before = _require_count(
                self._get_attempt_count(), "process request-attempt count"
            )
            self._configure_attempt_limit(attempts_before + effective_cap)

            print(
                "Gemini quota budget: "
                f"requested={requested_cap}, effective={effective_cap}, "
                f"daily_limit={effective_limit}, known_used={known_used}, "
                f"reserve={EXPERIMENT_RESERVE}",
                file=self._output,
            )

            record = {
                "schema_version": LEDGER_SCHEMA_VERSION,
                "quota_date": quota_date,
                "reserved_at": timestamp,
                "dashboard_used": dashboard_used,
                "dashboard_limit": dashboard_limit,
                "effective_limit": effective_limit,
                "known_used_before": known_used,
                "requested_cap": requested_cap,
                "reserved_attempts": effective_cap,
                "reconciled_at": None,
                "actual_attempts": None,
                "interruption_resolved_at": None,
                "resolution_dashboard_used": None,
            }
            records.append(record)
            _write_ledger_atomic(self.ledger_path, records)

            self._record_index = len(records) - 1
            self._attempts_before = attempts_before
            self._effective_cap = effective_cap
            self._effective_limit = effective_limit
            self._known_used = known_used
            self._entered = True
            return self
        except BaseException:
            self._lock.release()
            raise

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        if not self._entered:
            return False
        try:
            if exc_type is None:
                if self._attempts_before is None or self._record_index is None:
                    raise QuotaGuardError("QuotaGuard reconciliation state is incomplete")
                attempts_after = _require_count(
                    self._get_attempt_count(), "process request-attempt count"
                )
                actual_attempts = attempts_after - self._attempts_before
                if actual_attempts < 0:
                    raise QuotaGuardError(
                        "Process request-attempt count decreased during the guarded run"
                    )
                if actual_attempts > self.effective_cap:
                    raise QuotaGuardError(
                        "Process exceeded its reserved request-attempt cap"
                    )

                records = _read_ledger(self.ledger_path)
                if self._record_index >= len(records):
                    raise QuotaGuardError("Quota reservation disappeared from the ledger")
                record = records[self._record_index]
                if not _is_open_reservation(record):
                    raise QuotaGuardError(
                        "Quota reservation was modified before reconciliation"
                    )
                record["reconciled_at"] = _utc_timestamp(self._now_utc())
                record["actual_attempts"] = actual_attempts
                _write_ledger_atomic(self.ledger_path, records)
        finally:
            self._entered = False
            self._lock.release()
        return False


def quota_guard_from_args(
    args: argparse.Namespace,
    *,
    ledger_path: Path = DEFAULT_LEDGER_PATH,
    now_utc: Callable[[], datetime] | None = None,
    configure_attempt_limit: Callable[[int | None], None] = (
        configure_google_request_attempt_limit
    ),
    get_attempt_count: Callable[[], int] = get_google_request_attempt_count,
    output: TextIO = sys.stdout,
) -> QuotaGuard:
    """Construct a guard from parsed arguments, rejecting omitted values."""

    names = (
        "quota_date",
        "dashboard_used",
        "dashboard_limit",
        "max_api_requests",
    )
    missing = [name for name in names if getattr(args, name, None) is None]
    if missing:
        rendered = ", ".join("--" + name.replace("_", "-") for name in missing)
        raise QuotaValidationError(
            f"API execution requires quota argument(s): {rendered}"
        )
    return QuotaGuard(
        quota_date=args.quota_date,
        dashboard_used=args.dashboard_used,
        dashboard_limit=args.dashboard_limit,
        max_api_requests=args.max_api_requests,
        ledger_path=ledger_path,
        now_utc=now_utc,
        configure_attempt_limit=configure_attempt_limit,
        get_attempt_count=get_attempt_count,
        output=output,
    )
