"""Compute the paired 160-fresh Gemma Banking defense comparison offline."""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
from pathlib import Path
from typing import Any, Sequence

from src.schemas import RunResult


CASE_FIELDS = (
    "payload_id",
    "domain",
    "channel",
    "injection_vector",
    "user_task_id",
    "injection_task_id",
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRESH_PLAN = PROJECT_ROOT / "data/baseline_gemma4/banking_followup/plan_fresh160.tsv"
FRESH_RESULTS = PROJECT_ROOT / "data/defended/g4/v1/fresh160/results.jsonl"
UNDEFENDED_RESULTS = PROJECT_ROOT / "data/baseline_gemma4/full/results.jsonl"
DISCOVERY_PLAN = PROJECT_ROOT / "data/baseline/plan.tsv"
PLAN_SHA256 = "0fcf3aadc5700ef5e1c40b5d5b5fc7242c7eaeb8a1225b525f1305e20cdf6f6b"
DISCOVERY_SHA256 = "d000809142e1624c7085cf3d01b5c3c782ca09c64c76f89bb9315c8c0ba6d050"
MODEL = "google-gemma-4-26b-a4b-it"
DEFENSE = "my_spotlighting"
SEED = 20260805
RESAMPLES = 10_000


def _key(row: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(row[field]) for field in CASE_FIELDS)


def _read_plan(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != CASE_FIELDS:
            raise ValueError(f"unexpected plan columns: {reader.fieldnames}")
        rows = [dict(row) for row in reader]
    return rows


def _raw_note(notes: str, name: str) -> Path:
    match = re.search(rf"(?:^|;\s*){re.escape(name)}=([^;]+)", notes)
    if match is None:
        raise ValueError(f"missing {name} in notes")
    path = Path(match.group(1))
    return path if path.is_absolute() else PROJECT_ROOT / path


def _read_index(path: Path, *, calibrated: bool) -> dict[tuple[str, ...], tuple[RunResult, dict[str, Any]]]:
    output: dict[tuple[str, ...], tuple[RunResult, dict[str, Any]]] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        raw_record = json.loads(line)
        result = (
            RunResult.from_calibrated_dict(raw_record, path=f"{path}:{line_number}")
            if calibrated
            else RunResult.from_dict(raw_record, path=f"{path}:{line_number}")
        )
        vector_match = re.search(r"(?:^|;\s*)injection_vector=([^;]+)", result.notes)
        if vector_match is None:
            raise ValueError(f"{path}:{line_number} lacks injection_vector")
        key = (
            result.payload_id,
            result.domain,
            result.channel,
            vector_match.group(1),
            result.user_task_id,
            result.injection_task_id,
        )
        if key in output:
            raise ValueError(f"duplicate result key: {key}")
        trace_path = _raw_note(result.notes, "raw_trace")
        if not trace_path.is_file():
            raise ValueError(f"missing raw trace: {trace_path}")
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        if trace.get("error") is not None:
            raise ValueError(f"errored raw trace: {trace_path}")
        if trace.get("security") != result.attack_success:
            raise ValueError(f"index/raw attack verdict mismatch: {trace_path}")
        if result.utility_success is not None and trace.get("utility") != result.utility_success:
            raise ValueError(f"index/raw utility verdict mismatch: {trace_path}")
        output[key] = (result, trace)
    return output


def _percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _paired_bootstrap(values: list[float], *, seed: int, resamples: int) -> tuple[float, float]:
    rng = random.Random(seed)
    n = len(values)
    estimates: list[float] = []
    for _ in range(resamples):
        total = 0.0
        for _ in range(n):
            total += values[rng.randrange(n)]
        estimates.append(total / n)
    return _percentile(estimates, 0.025), _percentile(estimates, 0.975)


def _write_chart(path: Path, *, undefended_asr: float, defended_asr: float, undefended_utility: float, defended_utility: float) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("matplotlib is required for the before/after chart") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    figure, axes = plt.subplots(1, 2, figsize=(10, 4.8))
    labels = ["Undefended", "my_spotlighting"]
    colors = ["#6b7280", "#2563eb"]
    for axis, title, values in (
        (axes[0], "Native attack success rate", [undefended_asr, defended_asr]),
        (axes[1], "Legitimate-task utility rate", [undefended_utility, defended_utility]),
    ):
        bars = axis.bar(labels, values, color=colors, width=0.62)
        axis.set_ylim(0, 1)
        axis.set_ylabel("Rate")
        axis.set_title(title)
        axis.grid(axis="y", alpha=0.25)
        for bar, value in zip(bars, values):
            axis.text(bar.get_x() + bar.get_width() / 2, value + 0.025, f"{value:.1%}", ha="center")
    figure.suptitle("Gemma Banking defense before/after — 160-fresh partition only", fontsize=13)
    figure.tight_layout(rect=(0, 0, 1, 0.91))
    figure.savefig(path, dpi=180, format="png")
    plt.close(figure)


def summarize(*, plan_path: Path = FRESH_PLAN, defended_path: Path = FRESH_RESULTS, undefended_path: Path = UNDEFENDED_RESULTS, output_csv: Path = PROJECT_ROOT / "data/defended/g4/v1/summary.csv", chart_path: Path = PROJECT_ROOT / "report/figures/gemma_banking_fresh160_before_after.png") -> dict[str, Any]:
    plan_rows = _read_plan(plan_path)
    if len(plan_rows) != 160:
        raise ValueError(f"fresh plan must contain 160 rows, found {len(plan_rows)}")
    import hashlib
    if hashlib.sha256(plan_path.read_bytes()).hexdigest() != PLAN_SHA256:
        raise ValueError("fresh plan hash mismatch")
    if hashlib.sha256(DISCOVERY_PLAN.read_bytes()).hexdigest() != DISCOVERY_SHA256:
        raise ValueError("discovery reference plan hash mismatch")
    discovery_triples = {
        (row["payload_id"], row["user_task_id"], row["injection_task_id"])
        for row in _read_plan(DISCOVERY_PLAN)
        if row["domain"] == "banking"
    }
    fresh_triples = {
        (row["payload_id"], row["user_task_id"], row["injection_task_id"])
        for row in plan_rows
    }
    if discovery_triples & fresh_triples:
        raise ValueError("fresh160 plan contains a replication triple")
    defended = _read_index(defended_path, calibrated=True)
    undefended = _read_index(undefended_path, calibrated=False)
    plan_keys = [_key(row) for row in plan_rows]
    if set(defended) != set(plan_keys) or len(defended) != 160:
        raise ValueError("defended index does not equal fresh160 plan")
    if not set(plan_keys).issubset(undefended):
        raise ValueError("undefended index is missing matching fresh160 cases")
    pairs: list[dict[str, Any]] = []
    for key in plan_keys:
        defended_result, defended_trace = defended[key]
        undefended_result, undefended_trace = undefended[key]
        if undefended_result.model != MODEL or defended_result.model != MODEL:
            raise ValueError(f"wrong model for {key}")
        if defended_result.defense != DEFENSE:
            raise ValueError(f"wrong defended arm for {key}")
        if defended_trace.get("security") != defended_result.attack_success:
            raise ValueError(f"defended trace mismatch for {key}")
        pairs.append({
            "key": key,
            "undefended_attack": bool(undefended_trace["security"]),
            "defended_attack": bool(defended_trace["security"]),
            "undefended_utility": bool(undefended_trace["utility"]),
            "defended_utility": bool(defended_trace["utility"]),
        })
    undefended_asr = sum(pair["undefended_attack"] for pair in pairs) / 160
    defended_asr = sum(pair["defended_attack"] for pair in pairs) / 160
    undefended_utility = sum(pair["undefended_utility"] for pair in pairs) / 160
    defended_utility = sum(pair["defended_utility"] for pair in pairs) / 160
    asr_reduction_values = [int(pair["undefended_attack"]) - int(pair["defended_attack"]) for pair in pairs]
    utility_change_values = [int(pair["defended_utility"]) - int(pair["undefended_utility"]) for pair in pairs]
    asr_ci = _paired_bootstrap(asr_reduction_values, seed=SEED, resamples=RESAMPLES)
    utility_ci = _paired_bootstrap(utility_change_values, seed=SEED, resamples=RESAMPLES)
    absolute_reduction = undefended_asr - defended_asr
    relative_reduction = absolute_reduction / undefended_asr if undefended_asr else None
    utility_change = defended_utility - undefended_utility
    row = {
        "partition": "160-fresh",
        "study_id": "gemma4-banking-defense-fresh160-v1",
        "model": MODEL,
        "defense": DEFENSE,
        "plan_sha256": PLAN_SHA256,
        "reference_plan_sha256": DISCOVERY_SHA256,
        "n": 160,
        "undefended_attack_successes": sum(pair["undefended_attack"] for pair in pairs),
        "defended_attack_successes": sum(pair["defended_attack"] for pair in pairs),
        "undefended_asr": f"{undefended_asr:.10f}",
        "defended_asr": f"{defended_asr:.10f}",
        "absolute_asr_reduction": f"{absolute_reduction:.10f}",
        "relative_asr_reduction": f"{relative_reduction:.10f}" if relative_reduction is not None else "",
        "undefended_utility_successes": sum(pair["undefended_utility"] for pair in pairs),
        "defended_utility_successes": sum(pair["defended_utility"] for pair in pairs),
        "undefended_utility_rate": f"{undefended_utility:.10f}",
        "defended_utility_rate": f"{defended_utility:.10f}",
        "utility_change": f"{utility_change:.10f}",
        "paired_bootstrap_resamples": RESAMPLES,
        "paired_bootstrap_seed": SEED,
        "paired_asr_reduction_ci_low": f"{asr_ci[0]:.10f}",
        "paired_asr_reduction_ci_high": f"{asr_ci[1]:.10f}",
        "paired_utility_change_ci_low": f"{utility_ci[0]:.10f}",
        "paired_utility_change_ci_high": f"{utility_ci[1]:.10f}",
        "scope_label": "160-fresh partition only",
    }
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    _write_chart(chart_path, undefended_asr=undefended_asr, defended_asr=defended_asr, undefended_utility=undefended_utility, defended_utility=defended_utility)
    return row


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=FRESH_PLAN)
    parser.add_argument("--defended", type=Path, default=FRESH_RESULTS)
    parser.add_argument("--undefended", type=Path, default=UNDEFENDED_RESULTS)
    parser.add_argument("--output-csv", type=Path, default=PROJECT_ROOT / "data/defended/g4/v1/summary.csv")
    parser.add_argument("--chart", type=Path, default=PROJECT_ROOT / "report/figures/gemma_banking_fresh160_before_after.png")
    args = parser.parse_args(argv)
    row = summarize(plan_path=args.plan.resolve(), defended_path=args.defended.resolve(), undefended_path=args.undefended.resolve(), output_csv=args.output_csv.resolve(), chart_path=args.chart.resolve())
    print(json.dumps(row, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
