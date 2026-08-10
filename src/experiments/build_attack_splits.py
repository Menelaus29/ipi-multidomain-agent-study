"""Build deterministic pre-API development and holdout candidate manifests.

The source universe is the context-only projection of Phase 6's full
AgentDojo matrix. Payload IDs are deliberately discarded: calibration attacks
are frozen later and are evaluated against contexts, not corpus payload rows.

This module never constructs an LLM or invokes ``benchmark_suite``. Existing
manifest files are treated as prospective protocol artifacts: an identical
rerun is accepted, while different bytes are rejected instead of overwritten.

Example::

    python -m src.experiments.build_attack_splits --plan --seed 20260807 \
        --dev-output data/attack_calibration/dev_candidates.tsv \
        --holdout-output data/attack_calibration/holdout_candidates.tsv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import tempfile
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from src.experiments.run_baseline import PROJECT_ROOT, iter_cases, load_corpus


DEFAULT_SEED = 20260807
DEV_CANDIDATES_PER_DOMAIN = 20
MIN_HOLDOUT_CANDIDATES_PER_DOMAIN = 20
DOMAINS = ("workspace", "banking", "slack")
REQUIRED_CHANNELS = {
    "workspace": frozenset({"file_content", "email_body", "calendar_event"}),
    "banking": frozenset({"file_content", "transaction_memo"}),
    "slack": frozenset({"web_content"}),
}
MIN_SLACK_WEBPAGE_VECTORS = 2

DEFAULT_BASELINE_PLAN = PROJECT_ROOT / "data" / "baseline" / "plan.tsv"
DEFAULT_DEV_OUTPUT = PROJECT_ROOT / "data" / "attack_calibration" / "dev_candidates.tsv"
DEFAULT_HOLDOUT_OUTPUT = (
    PROJECT_ROOT / "data" / "attack_calibration" / "holdout_candidates.tsv"
)

# Prospective candidate-pool hashes committed in Phase 6A.7 and recorded in
# docs/baseline_null_analysis.md.  Runtime consumers use these values to reject
# a silently edited/reordered canonical source manifest.  A new candidate-pool
# version must use new paths and hashes rather than changing these constants in
# place after calibration has begun.
COMMITTED_CANDIDATE_SHA256 = {
    "dev": "1b5e2542ba5fc20ad04b5b8062e9150a8ce1a4c85231653255991f17446cf725",
    "holdout": "08ecfcb1c5b95ba59753c4e4ffa6dc8c228f9e51bc1029fc7316565e7178882a",
}

BASELINE_COLUMNS = (
    "payload_id",
    "domain",
    "channel",
    "injection_vector",
    "user_task_id",
    "injection_task_id",
)
MANIFEST_COLUMNS = (
    "candidate_rank",
    "domain",
    "channel",
    "injection_vector",
    "user_task_id",
    "injection_task_id",
)


class SplitPlanError(RuntimeError):
    """Raised when candidate manifests cannot satisfy the prospective plan."""


@dataclass(frozen=True)
class AttackContext:
    """One payload-independent AgentDojo attack context."""

    domain: str
    channel: str
    injection_vector: str
    user_task_id: str
    injection_task_id: str

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Return the disjointness key declared by build-guide step 6A.6."""

        return (
            self.domain,
            self.injection_vector,
            self.user_task_id,
            self.injection_task_id,
        )

    @property
    def canonical_text(self) -> str:
        return "\x1f".join(self.key)


def _register_context(
    contexts: dict[tuple[str, str, str, str], AttackContext],
    context: AttackContext,
    *,
    source: str,
) -> None:
    if context.domain not in DOMAINS:
        raise SplitPlanError(f"{source} has unsupported domain {context.domain!r}")
    if not all(
        (
            context.channel,
            context.injection_vector,
            context.user_task_id,
            context.injection_task_id,
        )
    ):
        raise SplitPlanError(f"{source} has an empty context field: {context!r}")
    previous = contexts.get(context.key)
    if previous is not None and previous.channel != context.channel:
        raise SplitPlanError(
            f"{source} maps context key {context.key!r} to both "
            f"{previous.channel!r} and {context.channel!r}"
        )
    contexts[context.key] = context


def load_baseline_contexts(path: Path = DEFAULT_BASELINE_PLAN) -> set[AttackContext]:
    """Load and validate the immutable 110-row Phase 6 plan."""

    if not path.is_file():
        raise SplitPlanError(f"baseline plan does not exist: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != BASELINE_COLUMNS:
            raise SplitPlanError(
                f"{path} must have columns {BASELINE_COLUMNS!r}; "
                f"found {tuple(reader.fieldnames or ())!r}"
            )
        contexts: dict[tuple[str, str, str, str], AttackContext] = {}
        planned_cases: set[tuple[str, str, str, str, str]] = set()
        row_count = 0
        for row_count, row in enumerate(reader, start=1):
            values = {column: (row.get(column) or "").strip() for column in BASELINE_COLUMNS}
            if not all(values.values()):
                raise SplitPlanError(f"{path}:{row_count + 1} has an empty field")
            planned_key = (
                values["payload_id"],
                values["domain"],
                values["injection_vector"],
                values["user_task_id"],
                values["injection_task_id"],
            )
            if planned_key in planned_cases:
                raise SplitPlanError(
                    f"{path}:{row_count + 1} duplicates planned case {planned_key!r}"
                )
            planned_cases.add(planned_key)
            _register_context(
                contexts,
                AttackContext(
                    domain=values["domain"],
                    channel=values["channel"],
                    injection_vector=values["injection_vector"],
                    user_task_id=values["user_task_id"],
                    injection_task_id=values["injection_task_id"],
                ),
                source=f"{path}:{row_count + 1}",
            )
    if row_count != 110:
        raise SplitPlanError(f"{path} must contain exactly 110 rows; found {row_count}")
    return set(contexts.values())


def collect_full_matrix_contexts() -> set[AttackContext]:
    """Project the existing full baseline matrix onto unique contexts."""

    contexts: dict[tuple[str, str, str, str], AttackContext] = {}
    for payload, domain, vector, user_task_id, injection_task_id in iter_cases(
        load_corpus(), matrix="full"
    ):
        _register_context(
            contexts,
            AttackContext(
                domain=domain,
                channel=payload.channel,
                injection_vector=vector,
                user_task_id=user_task_id,
                injection_task_id=injection_task_id,
            ),
            source="full AgentDojo matrix",
        )
    if not contexts:
        raise SplitPlanError("full AgentDojo matrix produced no eligible contexts")
    return set(contexts.values())


def seeded_order(contexts: Iterable[AttackContext], seed: int) -> list[AttackContext]:
    """Return a platform-stable order keyed by the declared integer seed."""

    prefix = f"attack-split-seed={seed}\x00".encode("ascii")

    def ordering_key(context: AttackContext) -> tuple[bytes, str]:
        digest = hashlib.sha256(prefix + context.canonical_text.encode("utf-8")).digest()
        return digest, context.canonical_text

    return sorted(contexts, key=ordering_key)


def _keys(contexts: Iterable[AttackContext]) -> set[tuple[str, str, str, str]]:
    return {context.key for context in contexts}


def _assert_coverage(contexts: Sequence[AttackContext], *, label: str) -> None:
    counts = Counter(context.domain for context in contexts)
    for domain in DOMAINS:
        minimum = (
            DEV_CANDIDATES_PER_DOMAIN
            if label == "development"
            else MIN_HOLDOUT_CANDIDATES_PER_DOMAIN
        )
        if counts[domain] < minimum:
            raise SplitPlanError(
                f"{label} pool has {counts[domain]} {domain} contexts; needs at least {minimum}"
            )
        channels = {context.channel for context in contexts if context.domain == domain}
        missing_channels = REQUIRED_CHANNELS[domain] - channels
        if missing_channels:
            raise SplitPlanError(
                f"{label} {domain} pool is missing channel(s): {sorted(missing_channels)}"
            )
    slack_vectors = {
        context.injection_vector for context in contexts if context.domain == "slack"
    }
    if len(slack_vectors) < MIN_SLACK_WEBPAGE_VECTORS:
        raise SplitPlanError(
            f"{label} Slack pool covers {len(slack_vectors)} webpage vector(s); "
            f"needs at least {MIN_SLACK_WEBPAGE_VECTORS}"
        )


def build_candidate_sets(
    full_contexts: Iterable[AttackContext],
    baseline_contexts: Iterable[AttackContext],
    *,
    seed: int = DEFAULT_SEED,
) -> tuple[list[AttackContext], list[AttackContext]]:
    """Select development contexts and order the disjoint holdout pool."""

    full_list = list(full_contexts)
    baseline_list = list(baseline_contexts)
    full_by_key = {context.key: context for context in full_list}
    baseline_by_key = {context.key: context for context in baseline_list}
    if len(full_by_key) != len(full_list):
        raise SplitPlanError("full matrix contains duplicate context keys")
    if len(baseline_by_key) != len(baseline_list):
        raise SplitPlanError("Phase 6 context collection contains duplicate keys")
    missing_from_full = sorted(set(baseline_by_key) - set(full_by_key))
    if missing_from_full:
        raise SplitPlanError(
            f"Phase 6 contains context(s) absent from the full matrix: {missing_from_full[:3]}"
        )
    for key, baseline in baseline_by_key.items():
        if full_by_key[key].channel != baseline.channel:
            raise SplitPlanError(
                f"Phase 6/full-matrix channel disagreement for {key!r}: "
                f"{baseline.channel!r} versus {full_by_key[key].channel!r}"
            )

    dev_keys = set(baseline_by_key)
    for domain in DOMAINS:
        domain_count = sum(key[0] == domain for key in dev_keys)
        needed = max(0, DEV_CANDIDATES_PER_DOMAIN - domain_count)
        eligible = (
            context
            for context in full_by_key.values()
            if context.domain == domain and context.key not in dev_keys
        )
        additions = seeded_order(eligible, seed)[:needed]
        if len(additions) != needed:
            raise SplitPlanError(
                f"full matrix cannot supply {DEV_CANDIDATES_PER_DOMAIN} "
                f"development contexts for {domain}"
            )
        dev_keys.update(context.key for context in additions)

    dev = seeded_order((full_by_key[key] for key in dev_keys), seed)
    excluded_holdout_keys = set(baseline_by_key) | dev_keys
    holdout = seeded_order(
        (
            context
            for key, context in full_by_key.items()
            if key not in excluded_holdout_keys
        ),
        seed,
    )

    if _keys(dev) & _keys(holdout):
        raise SplitPlanError("development and holdout candidate pools overlap")
    if set(baseline_by_key) & _keys(holdout):
        raise SplitPlanError("holdout pool contains a Phase 6 context")
    _assert_coverage(dev, label="development")
    _assert_coverage(holdout, label="holdout")
    return dev, holdout


def render_manifest(contexts: Sequence[AttackContext]) -> bytes:
    """Serialize one manifest with canonical UTF-8 and LF line endings."""

    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(MANIFEST_COLUMNS)
    for rank, context in enumerate(contexts, start=1):
        writer.writerow(
            (
                rank,
                context.domain,
                context.channel,
                context.injection_vector,
                context.user_task_id,
                context.injection_task_id,
            )
        )
    return output.getvalue().encode("utf-8")


def _check_existing(path: Path, expected: bytes) -> None:
    if path.exists() and path.read_bytes() != expected:
        raise SplitPlanError(
            f"refusing to overwrite changed prospective manifest: {path}; "
            "use versioned output paths for a new ordering"
        )


def _write_atomic_if_missing(path: Path, content: bytes) -> bool:
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        return True
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def write_manifests(
    dev_path: Path,
    dev_content: bytes,
    holdout_path: Path,
    holdout_content: bytes,
) -> tuple[bool, bool]:
    """Check both prospective artifacts before atomically writing either one."""

    if dev_path.resolve() == holdout_path.resolve():
        raise SplitPlanError("development and holdout outputs must be different files")
    _check_existing(dev_path, dev_content)
    _check_existing(holdout_path, holdout_content)
    return (
        _write_atomic_if_missing(dev_path, dev_content),
        _write_atomic_if_missing(holdout_path, holdout_content),
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        action="store_true",
        help="build candidate manifests without constructing an LLM or making API calls",
    )
    parser.add_argument(
        "--seed",
        type=int,
        choices=(DEFAULT_SEED,),
        default=DEFAULT_SEED,
        help=f"fixed prospective split seed (must be {DEFAULT_SEED})",
    )
    parser.add_argument("--baseline-plan", type=Path, default=DEFAULT_BASELINE_PLAN)
    parser.add_argument("--dev-output", type=Path, default=DEFAULT_DEV_OUTPUT)
    parser.add_argument("--holdout-output", type=Path, default=DEFAULT_HOLDOUT_OUTPUT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.plan:
        raise SystemExit("--plan is required; this script only creates no-API manifests")

    baseline = load_baseline_contexts(args.baseline_plan.resolve())
    full = collect_full_matrix_contexts()
    dev, holdout = build_candidate_sets(full, baseline, seed=args.seed)
    dev_content = render_manifest(dev)
    holdout_content = render_manifest(holdout)
    wrote_dev, wrote_holdout = write_manifests(
        args.dev_output.resolve(),
        dev_content,
        args.holdout_output.resolve(),
        holdout_content,
    )

    dev_counts = Counter(context.domain for context in dev)
    holdout_counts = Counter(context.domain for context in holdout)
    print(
        f"Development candidates: {len(dev)} "
        + ", ".join(f"{domain}={dev_counts[domain]}" for domain in DOMAINS)
    )
    print(
        f"Holdout candidates: {len(holdout)} "
        + ", ".join(f"{domain}={holdout_counts[domain]}" for domain in DOMAINS)
    )
    print(f"Seed: {args.seed}")
    print(f"Development manifest: {args.dev_output.resolve()} ({'written' if wrote_dev else 'unchanged'})")
    print(f"Holdout manifest: {args.holdout_output.resolve()} ({'written' if wrote_holdout else 'unchanged'})")
    print(f"Development SHA-256: {hashlib.sha256(dev_content).hexdigest()}")
    print(f"Holdout SHA-256: {hashlib.sha256(holdout_content).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
