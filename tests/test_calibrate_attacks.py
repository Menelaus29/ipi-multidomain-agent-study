"""No-network tests for Phase 6A AgentDojo attack calibration."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from contextlib import nullcontext, redirect_stderr
from dataclasses import asdict, replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.experiments import calibrate_attacks
from src.experiments.build_attack_splits import DOMAINS
from src.experiments.run_clean_controls import load_context_manifest
from src.schemas import CalibrationAttempt, FrozenAttack, PayloadEntry


def _dev_rows() -> list[tuple[object, ...]]:
    rows: list[tuple[object, ...]] = []
    rank = 1
    workspace_channels = (
        "file_content",
        "email_body",
        "calendar_event",
        "file_content",
        "email_body",
        "calendar_event",
    )
    banking_channels = (
        "file_content",
        "transaction_memo",
        "file_content",
        "transaction_memo",
        "file_content",
        "transaction_memo",
    )
    for context_index in range(6):
        for domain in DOMAINS:
            channel = (
                workspace_channels[context_index]
                if domain == "workspace"
                else banking_channels[context_index]
                if domain == "banking"
                else "web_content"
            )
            rows.append(
                (
                    rank,
                    domain,
                    channel,
                    f"{domain}_vector_{context_index}",
                    f"user_task_{context_index}",
                    f"injection_task_{context_index}",
                )
            )
            rank += 1
    return rows


def _write_manifest(path: Path, rows: list[tuple[object, ...]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(
            (
                "candidate_rank",
                "domain",
                "channel",
                "injection_vector",
                "user_task_id",
                "injection_task_id",
            )
        )
        writer.writerows(rows)


def _write_dev_manifest(path: Path) -> None:
    _write_manifest(path, _dev_rows())


def _write_holdout_candidates(path: Path) -> None:
    _write_manifest(
        path,
        [
            (
                index,
                domain,
                "web_content" if domain == "slack" else "file_content",
                f"holdout_{domain}_vector",
                f"holdout_user_task_{index}",
                f"holdout_injection_task_{index}",
            )
            for index, domain in enumerate(DOMAINS, 1)
        ],
    )


def _attempt(
    attempt_id: str,
    *,
    domain: str = "workspace",
    family: str = "direct",
    success: bool = True,
    mutation_round: int = 0,
    raw_path: Path | None = None,
    rendered_length: int = 10,
    rendered_text: str | None = None,
) -> CalibrationAttempt:
    index = DOMAINS.index(domain)
    if rendered_text is not None:
        rendered_length = len(rendered_text.encode("utf-8"))
    return CalibrationAttempt(
        attempt_id=attempt_id,
        timestamp="2026-08-07T00:00:00+00:00",
        split="dev",
        source_family=family,
        seed_id=(f"builtin:{family}" if mutation_round == 0 else f"seed:{family}"),
        parent_attempt_id=None,
        mutation_round=mutation_round,
        attacker_model=(
            "agentdojo-builtin"
            if mutation_round == 0
            else "google-gemini-3.5-flash-lite"
        ),
        target_model="google-gemini-3.5-flash-lite",
        domain=domain,
        user_task_id="user_task_0",
        injection_task_id="injection_task_0",
        injection_vector=f"{domain}_vector_0",
        rendered_attack_sha256=(
            calibrate_attacks.sha256_text(rendered_text)
            if rendered_text is not None
            else "a" * 64
        ),
        attack_success=success,
        utility_success=True,
        generator_request_attempts=0 if mutation_round == 0 else 1,
        target_request_attempts=1,
        raw_trace_path=str(raw_path or Path("raw.json")),
        notes=(
            f"source_category=test; rendered_utf8_bytes={rendered_length}; "
            "attack_success equals AgentDojo's native injection-task verdict"
        ),
    )


def _generator(
    *,
    identifier: str = "mutation:seed:r01",
    family: str = "family-a",
    mutation_round: int = 1,
    template: str = "REVISION {{goal}}",
) -> calibrate_attacks.GeneratorAttempt:
    return calibrate_attacks.GeneratorAttempt(
        generation_id=identifier,
        timestamp="2026-08-07T00:00:00+00:00",
        seed_id="seed",
        source_family=family,
        source_category="category-a",
        mutation_round=mutation_round,
        parent_attempt_id=None,
        attacker_model="google-gemini-3.5-flash-lite",
        generator_request_attempts=1,
        status="accepted",
        template=template,
        template_sha256=calibrate_attacks.sha256_text(template),
        raw_trace_path="generator.json",
        notes="validated",
    )


def _seed(
    seed_id: str,
    family: str,
    *,
    seed_kind: str = "empirical",
) -> calibrate_attacks.Seed:
    return calibrate_attacks.Seed(
        seed_id=seed_id,
        source_family=family,
        source_category=family,
        template=f"seed {seed_id} {{{{goal}}}}",
        seed_kind=seed_kind,
        initial_feedback_attempt_id=None,
        source_provenance_sha256=calibrate_attacks.sha256_text(seed_id),
    )


def _generator_for_seed(
    seed: calibrate_attacks.Seed,
    mutation_round: int,
    *,
    status: str = "accepted",
    request_attempts: int = 1,
) -> calibrate_attacks.GeneratorAttempt:
    template = (
        f"proposal {seed.seed_id} round {mutation_round} {{{{goal}}}}"
        if status == "accepted"
        else None
    )
    return calibrate_attacks.GeneratorAttempt(
        generation_id=calibrate_attacks.generation_id(seed.seed_id, mutation_round),
        timestamp=f"2026-08-07T00:00:{mutation_round:02d}+00:00",
        seed_id=seed.seed_id,
        source_family=seed.source_family,
        source_category=seed.source_category,
        mutation_round=mutation_round,
        parent_attempt_id=None,
        attacker_model="google-gemini-3.5-flash-lite",
        generator_request_attempts=request_attempts,
        status=status,
        template=template,
        template_sha256=(
            calibrate_attacks.sha256_text(template) if template is not None else None
        ),
        raw_trace_path=f"generator-{seed.seed_id}-{mutation_round}.json",
        notes="test generator record",
    )


def _generation_attempts(
    generation: calibrate_attacks.GeneratorAttempt,
    *,
    successes: tuple[bool, bool, bool] = (True, True, True),
) -> dict[str, CalibrationAttempt]:
    attempts: dict[str, CalibrationAttempt] = {}
    for domain, success in zip(DOMAINS, successes, strict=True):
        identifier = calibrate_attacks.mutation_attempt_id(generation, domain)
        attempt = _attempt(
            identifier,
            domain=domain,
            family=generation.source_family,
            success=success,
            mutation_round=generation.mutation_round,
        )
        attempts[identifier] = replace(
            attempt,
            seed_id=generation.seed_id,
            parent_attempt_id=generation.parent_attempt_id,
            attacker_model=generation.attacker_model,
            generator_request_attempts=generation.generator_request_attempts,
        )
    return attempts


def _empirical_payloads() -> list[PayloadEntry]:
    return [
        PayloadEntry(
            id=payload_id,
            category=category,
            channel="file_content",
            domain=list(DOMAINS),
            template=f"{category} {{{{goal}}}}",
            source="test corpus",
        )
        for category, payload_id in calibrate_attacks.EMPIRICAL_REPRESENTATIVES
    ]


def _builtin_attempt_matrix(
    root: Path,
    *,
    scores: dict[str, int] | None = None,
    renderings: dict[tuple[str, str], str] | None = None,
    package_versions: dict[str, str] | None = None,
) -> dict[str, CalibrationAttempt]:
    root.mkdir(parents=True, exist_ok=True)
    scores = scores or {
        "direct": 3,
        "ignore_previous": 2,
        "system_message": 1,
    }
    renderings = renderings or {}
    package_versions = package_versions or {}
    attempts: dict[str, CalibrationAttempt] = {}
    for family in calibrate_attacks.BUILTIN_FAMILIES:
        for domain_index, domain in enumerate(DOMAINS):
            rendered = renderings.get(
                (family, domain), f"{family} {domain} frame NATIVE GOAL"
            )
            raw_path = root / f"{family}-{domain}.json"
            raw_path.write_text(
                json.dumps(
                    {
                        "injections": {f"{domain}_vector_0": rendered},
                        "agentdojo_package_version": package_versions.get(
                            family, "0.1-test"
                        ),
                    }
                ),
                encoding="utf-8",
            )
            identifier = calibrate_attacks.builtin_attempt_id(family, domain)
            attempts[identifier] = _attempt(
                identifier,
                domain=domain,
                family=family,
                success=domain_index < scores.get(family, 0),
                raw_path=raw_path,
                rendered_text=rendered,
            )
    return attempts


class DevelopmentBoundaryTests(unittest.TestCase):
    def test_manifest_requires_six_per_domain_and_rejects_holdout_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            valid = root / "dev_manifest.tsv"
            dev_candidates = root / "dev_candidates.tsv"
            holdout_candidates = root / "holdout_candidates.tsv"
            _write_dev_manifest(valid)
            _write_dev_manifest(dev_candidates)
            _write_holdout_candidates(holdout_candidates)
            with patch.object(calibrate_attacks, "load_baseline_contexts", return_value=set()):
                manifest = calibrate_attacks.validate_development_manifest(
                    valid,
                    dev_candidates_path=dev_candidates,
                    holdout_candidates_path=holdout_candidates,
                    baseline_plan_path=root / "baseline.tsv",
                )
            self.assertEqual(18, len(manifest.rows))

            holdout = root / "holdout_manifest.tsv"
            _write_dev_manifest(holdout)
            with self.assertRaisesRegex(calibrate_attacks.CalibrationError, "held-out"):
                calibrate_attacks.validate_development_manifest(holdout)

            short = root / "dev_short.tsv"
            _write_dev_manifest(short)
            lines = short.read_text(encoding="utf-8").splitlines()
            short.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            with (
                patch.object(calibrate_attacks, "load_baseline_contexts", return_value=set()),
                self.assertRaisesRegex(calibrate_attacks.CalibrationError, "six"),
            ):
                calibrate_attacks.validate_development_manifest(
                    short,
                    dev_candidates_path=dev_candidates,
                    holdout_candidates_path=holdout_candidates,
                    baseline_plan_path=root / "baseline.tsv",
                )

    def test_manifest_must_exactly_match_ordered_development_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selected = root / "dev_manifest.tsv"
            dev_candidates = root / "dev_candidates.tsv"
            holdout_candidates = root / "holdout_candidates.tsv"
            rows = _dev_rows()
            changed = list(rows)
            changed[0] = (*changed[0][:-1], "injection_task_changed")
            _write_manifest(selected, changed)
            _write_manifest(dev_candidates, rows)
            _write_holdout_candidates(holdout_candidates)

            with (
                patch.object(calibrate_attacks, "load_baseline_contexts", return_value=set()),
                self.assertRaisesRegex(calibrate_attacks.CalibrationError, "exactly match"),
            ):
                calibrate_attacks.validate_development_manifest(
                    selected,
                    dev_candidates_path=dev_candidates,
                    holdout_candidates_path=holdout_candidates,
                    baseline_plan_path=root / "baseline.tsv",
                )

    def test_manifest_rejects_holdout_overlap_and_phase6_holdout_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selected = root / "dev_manifest.tsv"
            dev_candidates = root / "dev_candidates.tsv"
            holdout_candidates = root / "holdout_candidates.tsv"
            rows = _dev_rows()
            _write_manifest(selected, rows)
            _write_manifest(dev_candidates, rows)

            # A selected development row may not also appear in holdout.
            _write_manifest(holdout_candidates, [rows[0]])
            with (
                patch.object(calibrate_attacks, "load_baseline_contexts", return_value=set()),
                self.assertRaisesRegex(calibrate_attacks.CalibrationError, "overlap"),
            ):
                calibrate_attacks.validate_development_manifest(
                    selected,
                    dev_candidates_path=dev_candidates,
                    holdout_candidates_path=holdout_candidates,
                    baseline_plan_path=root / "baseline.tsv",
                )

            # Phase 6 reuse is allowed for development, but never for holdout.
            _write_holdout_candidates(holdout_candidates)
            holdout = load_context_manifest(holdout_candidates).rows[0].context
            development = load_context_manifest(selected).rows[0].context
            with patch.object(
                calibrate_attacks,
                "load_baseline_contexts",
                return_value={holdout},
            ), self.assertRaisesRegex(calibrate_attacks.CalibrationError, "Phase 6"):
                calibrate_attacks.validate_development_manifest(
                    selected,
                    dev_candidates_path=dev_candidates,
                    holdout_candidates_path=holdout_candidates,
                    baseline_plan_path=root / "baseline.tsv",
                )

            with patch.object(
                calibrate_attacks,
                "load_baseline_contexts",
                return_value={development},
            ):
                calibrate_attacks.validate_development_manifest(
                    selected,
                    dev_candidates_path=dev_candidates,
                    holdout_candidates_path=holdout_candidates,
                    baseline_plan_path=root / "baseline.tsv",
                )

    def test_manifest_enforces_required_surface_and_slack_vector_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            holdout_candidates = root / "holdout_candidates.tsv"
            _write_holdout_candidates(holdout_candidates)
            cases = {
                "workspace": lambda row: (
                    row[0], row[1], "file_content", row[3], row[4], row[5]
                ),
                "banking": lambda row: (
                    row[0], row[1], "file_content", row[3], row[4], row[5]
                ),
                "Slack": lambda row: (
                    row[0], row[1], row[2], "slack_vector_one", row[4], row[5]
                ),
            }
            for label, transform in cases.items():
                with self.subTest(label=label):
                    rows = _dev_rows()
                    domain = label.lower()
                    rows = [
                        transform(row) if row[1] == domain else row for row in rows
                    ]
                    selected = root / f"selected-{domain}.tsv"
                    dev_candidates = root / f"candidates-{domain}.tsv"
                    _write_manifest(selected, rows)
                    _write_manifest(dev_candidates, rows)
                    with (
                        patch.object(
                            calibrate_attacks,
                            "load_baseline_contexts",
                            return_value=set(),
                        ),
                        self.assertRaisesRegex(
                            calibrate_attacks.CalibrationError,
                            "surface|Slack webpage vectors",
                        ),
                    ):
                        calibrate_attacks.validate_development_manifest(
                            selected,
                            dev_candidates_path=dev_candidates,
                            holdout_candidates_path=holdout_candidates,
                            baseline_plan_path=root / "baseline.tsv",
                        )

    def test_rotation_uses_all_six_slots_and_rotates_first_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dev.tsv"
            _write_dev_manifest(path)
            manifest = load_context_manifest(path)
            observed = [
                calibrate_attacks.rotating_contexts(
                    manifest, seed_index=0, mutation_round=round_number
                )[0].context
                for round_number in range(1, 7)
            ]

        self.assertEqual(
            ["workspace", "banking", "slack", "workspace", "banking", "slack"],
            [context.domain for context in observed],
        )
        self.assertEqual(
            [f"user_task_{index}" for index in range(6)],
            [context.user_task_id for context in observed],
        )

    def test_cli_does_not_expose_an_alternate_or_heldout_manifest(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                calibrate_attacks.parse_args(
                    ["--stage", "freeze", "--dev-manifest", "holdout.tsv"]
                )


class GoalTemplateTests(unittest.TestCase):
    def test_supported_tokens_render_and_multiple_or_unknown_tokens_fail(self) -> None:
        goals = ("send synthetic message", "transfer synthetic funds")
        for token in calibrate_attacks.SUPPORTED_GOAL_TOKENS:
            selected = calibrate_attacks.validate_goal_bound_template(
                f"prefix {token} suffix", goals
            )
            self.assertEqual(token, selected)

        invalid = (
            "no goal token",
            "{{goal}}{{goal}}",
            "{{goal}} and {{goal_base64}}",
            "{{goal}} plus {{unsupported}}",
        )
        for template in invalid:
            with self.subTest(template=template):
                with self.assertRaises(ValueError):
                    calibrate_attacks.validate_goal_bound_template(template, goals)

    def test_vector_bound_builtin_keeps_only_manifest_vector(self) -> None:
        class FakeSuite:
            def get_injection_vector_defaults(self) -> list[str]:
                return ["chosen", "other"]

        delegate = SimpleNamespace(
            attack=lambda _user, _task: {"chosen": "A", "other": "B"}
        )
        with patch.object(calibrate_attacks, "load_attack", return_value=delegate):
            name = calibrate_attacks.register_vector_builtin_attack("direct", "chosen")
            attack = calibrate_attacks.ATTACKS[name](FakeSuite(), object())
        attack.get_injection_candidates = lambda _user: ["chosen", "other"]
        rendered = attack.attack(SimpleNamespace(ID="user_task_0"), object())
        self.assertEqual({"chosen": "A"}, rendered)


class BuiltinAndSeedTests(unittest.TestCase):
    def test_builtin_ranking_and_exact_eight_seed_construction_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            attempts: dict[str, CalibrationAttempt] = {}
            scores = {
                "direct": 3,
                "ignore_previous": 2,
                "system_message": 1,
                "important_instructions": 0,
                "tool_knowledge": 0,
                "injecagent": 0,
            }
            for family_index, family in enumerate(calibrate_attacks.BUILTIN_FAMILIES):
                for domain_index, domain in enumerate(DOMAINS):
                    raw_path = root / f"{family}-{domain}.json"
                    rendered = f"{family} frame NATIVE GOAL"
                    raw_path.write_text(
                        json.dumps(
                            {
                                "injections": {
                                    f"{domain}_vector_0": rendered
                                },
                                "agentdojo_package_version": "0.1-test",
                            }
                        ),
                        encoding="utf-8",
                    )
                    identifier = calibrate_attacks.builtin_attempt_id(family, domain)
                    attempts[identifier] = _attempt(
                        identifier,
                        domain=domain,
                        family=family,
                        success=domain_index < scores[family],
                        raw_path=raw_path,
                        rendered_text=rendered,
                    )

            empirical = [
                PayloadEntry(
                    id=payload_id,
                    category=category,
                    channel="file_content",
                    domain=list(DOMAINS),
                    template=f"{category} {{{{goal}}}}",
                    source="test corpus",
                )
                for category, payload_id in calibrate_attacks.EMPIRICAL_REPRESENTATIVES
            ]
            suite = SimpleNamespace(
                injection_tasks={"injection_task_0": SimpleNamespace(GOAL="NATIVE GOAL")}
            )
            with (
                patch.object(calibrate_attacks, "load_corpus", return_value=empirical),
                patch.object(calibrate_attacks, "get_suite", return_value=suite),
            ):
                seeds_one = calibrate_attacks.construct_seeds(
                    attempts=attempts, goals=("NATIVE GOAL",)
                )
                seeds_two = calibrate_attacks.construct_seeds(
                    attempts=attempts, goals=("NATIVE GOAL",)
                )

        self.assertEqual(
            ["direct", "ignore_previous", "system_message"],
            [seed.source_family for seed in seeds_one[:3]],
        )
        self.assertEqual(8, len(seeds_one))
        self.assertEqual(8, len({seed.seed_id for seed in seeds_one}))
        self.assertEqual(
            [asdict(seed) for seed in seeds_one],
            [asdict(seed) for seed in seeds_two],
        )

    def test_existing_seed_artifact_is_reconstructed_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            seed_path = root / "seeds.v1.json"
            attempts = _builtin_attempt_matrix(root)
            suite = SimpleNamespace(
                injection_tasks={"injection_task_0": SimpleNamespace(GOAL="NATIVE GOAL")}
            )
            with (
                patch.object(
                    calibrate_attacks, "load_corpus", return_value=_empirical_payloads()
                ),
                patch.object(calibrate_attacks, "get_suite", return_value=suite),
            ):
                expected = calibrate_attacks.ensure_canonical_seed_artifact(
                    seed_path,
                    attempts=attempts,
                    goals=("NATIVE GOAL",),
                    require_existing=False,
                )
                original = seed_path.read_bytes()
                stored = json.loads(original)
                stored[0]["template"] = "tampered {{goal}}"
                seed_path.write_bytes(calibrate_attacks._canonical_json_bytes(stored))
                with self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError, "does not match"
                ):
                    calibrate_attacks.ensure_canonical_seed_artifact(
                        seed_path,
                        attempts=attempts,
                        goals=("NATIVE GOAL",),
                        require_existing=False,
                    )
                self.assertEqual(8, len(expected))
                self.assertNotEqual(original, seed_path.read_bytes())

    def test_seed_artifact_rejects_changed_corpus_and_builtin_source_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            seed_path = root / "seeds.v1.json"
            attempts = _builtin_attempt_matrix(root)
            corpus = _empirical_payloads()
            suite = SimpleNamespace(
                injection_tasks={"injection_task_0": SimpleNamespace(GOAL="NATIVE GOAL")}
            )
            with (
                patch.object(calibrate_attacks, "load_corpus", return_value=corpus),
                patch.object(calibrate_attacks, "get_suite", return_value=suite),
            ):
                calibrate_attacks.ensure_canonical_seed_artifact(
                    seed_path,
                    attempts=attempts,
                    goals=("NATIVE GOAL",),
                    require_existing=False,
                )

            changed_corpus = list(corpus)
            changed_corpus[0] = replace(
                changed_corpus[0], template="changed corpus {{goal}}"
            )
            with (
                patch.object(
                    calibrate_attacks, "load_corpus", return_value=changed_corpus
                ),
                patch.object(calibrate_attacks, "get_suite", return_value=suite),
                self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError, "does not match"
                ),
            ):
                calibrate_attacks.ensure_canonical_seed_artifact(
                    seed_path,
                    attempts=attempts,
                    goals=("NATIVE GOAL",),
                    require_existing=False,
                )

            identifier = calibrate_attacks.builtin_attempt_id("direct", "workspace")
            changed_rendering = "changed built-in source NATIVE GOAL"
            raw_path = Path(attempts[identifier].raw_trace_path)
            raw_path.write_text(
                json.dumps(
                    {
                        "injections": {"workspace_vector_0": changed_rendering},
                        "agentdojo_package_version": "0.1-test",
                    }
                ),
                encoding="utf-8",
            )
            changed_attempts = dict(attempts)
            changed_attempts[identifier] = replace(
                attempts[identifier],
                rendered_attack_sha256=calibrate_attacks.sha256_text(changed_rendering),
                notes=(
                    "source_category=test; rendered_utf8_bytes="
                    f"{len(changed_rendering.encode('utf-8'))}; "
                    "attack_success equals AgentDojo's native injection-task verdict"
                ),
            )
            with (
                patch.object(calibrate_attacks, "load_corpus", return_value=corpus),
                patch.object(calibrate_attacks, "get_suite", return_value=suite),
                self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError, "does not match"
                ),
            ):
                calibrate_attacks.ensure_canonical_seed_artifact(
                    seed_path,
                    attempts=changed_attempts,
                    goals=("NATIVE GOAL",),
                    require_existing=False,
                )

    def test_builtin_ranking_uses_one_canonical_rendering_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            renderings = {
                ("direct", "workspace"): "D NATIVE GOAL",
                ("direct", "banking"): "D" * 500 + " NATIVE GOAL",
                ("direct", "slack"): "D" * 500 + " NATIVE GOAL",
                ("ignore_previous", "workspace"): "IGNORE NATIVE GOAL",
                ("ignore_previous", "banking"): "I NATIVE GOAL",
                ("ignore_previous", "slack"): "I NATIVE GOAL",
            }
            attempts = _builtin_attempt_matrix(
                root,
                scores={"direct": 2, "ignore_previous": 2},
                renderings=renderings,
            )
            ranked_one = calibrate_attacks.rank_builtin_families(attempts)
            ranked_two = calibrate_attacks.rank_builtin_families(attempts)

        self.assertEqual(ranked_one, ranked_two)
        self.assertEqual("direct", ranked_one[0].family)
        self.assertEqual(
            len(renderings[("direct", "workspace")].encode("utf-8")),
            ranked_one[0].rendered_utf8_length,
        )
        self.assertLess(
            ranked_one[0].rendered_utf8_length,
            ranked_one[1].rendered_utf8_length,
        )

    def test_builtin_screen_skips_only_validated_checkpoint_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dev.tsv"
            _write_dev_manifest(path)
            manifest = load_context_manifest(path)
            existing_id = calibrate_attacks.builtin_attempt_id("direct", "workspace")
            existing = _attempt(existing_id)
            executed: list[str] = []

            def fake_execute(**kwargs: object) -> CalibrationAttempt:
                identifier = str(kwargs["attempt_id"])
                executed.append(identifier)
                domain = str(kwargs["context"].domain)  # type: ignore[union-attr]
                family = str(kwargs["source_family"])
                return _attempt(identifier, domain=domain, family=family)

            with (
                patch.object(
                    calibrate_attacks,
                    "load_calibration_attempts",
                    return_value={existing_id: existing},
                ),
                patch.object(
                    calibrate_attacks,
                    "register_vector_builtin_attack",
                    return_value="attack",
                ),
                patch.object(
                    calibrate_attacks,
                    "execute_target_attempt",
                    side_effect=fake_execute,
                ),
            ):
                status = calibrate_attacks.run_builtin_screen(
                    manifest=manifest,
                    output_root=Path(temporary_directory) / "builtin",
                )

        self.assertEqual(0, status)
        self.assertEqual(17, len(executed))
        self.assertNotIn(existing_id, executed)


class GeneratorTests(unittest.TestCase):
    def test_compact_mutation_attack_name_matches_registered_attack(self) -> None:
        generation = "mutation:builtin:ignore_previous:r04"
        vector = "injection_web_0"
        registered = calibrate_attacks.register_vector_template_attack(
            "Follow {{goal}}",
            vector,
            candidate_id=generation,
        )

        self.assertEqual(
            calibrate_attacks.mutation_attack_name(generation, vector), registered
        )

    def test_refusal_malformed_goal_token_and_duplicate_are_logged_not_accepted(self) -> None:
        goals = ("GOAL",)
        duplicate = calibrate_attacks.sha256_text("same {{goal}}")
        cases = (
            ("I cannot assist with that.", "refused"),
            ("not json", "malformed"),
            ('{"template":"missing token"}', "invalid_goal_token"),
            ('{"template":"same {{goal}}"}', "duplicate"),
            ('{"template":"new {{goal}}"}', "accepted"),
        )
        for text, expected in cases:
            with self.subTest(expected=expected):
                status, _, _, _ = calibrate_attacks.classify_generator_output(
                    text, goals=goals, duplicate_hashes={duplicate}
                )
                self.assertEqual(expected, status)

    def test_feedback_prompt_contains_only_transcript_and_native_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            raw_path = Path(temporary_directory) / "raw.json"
            messages = [{"role": "assistant", "content": [{"type": "text", "content": "observable"}]}]
            raw_path.write_text(
                json.dumps(
                    {
                        "messages": messages,
                        "utility": True,
                        "security": False,
                        "defense": "must-not-leak",
                        "injections": {"vector": "must-not-leak"},
                    }
                ),
                encoding="utf-8",
            )
            attempt = _attempt("feedback", raw_path=raw_path, success=False)
            seed = calibrate_attacks.Seed(
                seed_id="seed",
                source_family="family",
                source_category="category",
                template="original {{goal}}",
                seed_kind="empirical",
                initial_feedback_attempt_id=None,
                source_provenance_sha256="c" * 64,
            )
            system, user = calibrate_attacks.build_generator_prompt(
                seed=seed,
                mutation_round=2,
                parent_attempt=attempt,
                base_template="previous {{goal}}",
            )
            decoded = json.loads(user)

        self.assertEqual(
            {"messages": messages, "attack_success": False},
            decoded["development_feedback"],
        )
        self.assertEqual("previous {{goal}}", decoded["seed_template"])
        self.assertNotIn("heldout", system.lower())
        serialized_feedback = json.dumps(decoded["development_feedback"])
        self.assertNotIn("utility", serialized_feedback)
        self.assertNotIn("defense", serialized_feedback)
        self.assertNotIn("injections", serialized_feedback)

    def test_raw_generator_response_is_recovered_without_repeating_llm_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            raw_root = root / "raw"
            seed = calibrate_attacks.Seed(
                seed_id="empirical:direct-01",
                source_family="direct_override",
                source_category="direct_override",
                template="seed {{goal}}",
                seed_kind="empirical",
                initial_feedback_attempt_id=None,
                source_provenance_sha256="c" * 64,
            )
            identifier = calibrate_attacks.generation_id(seed.seed_id, 1)
            system, user_prompt = calibrate_attacks.build_generator_prompt(
                seed=seed,
                mutation_round=1,
                parent_attempt=None,
                base_template=seed.template,
            )
            messages = calibrate_attacks._generator_request_messages(
                system, user_prompt
            ) + [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "text",
                            "content": '{"template":"recovered {{goal}}"}',
                        }
                    ],
                    "tool_calls": [],
                }
            ]
            raw_path = raw_root / f"{calibrate_attacks._safe_attack_name(identifier)}.json"
            raw_path.parent.mkdir(parents=True)
            raw_path.write_text(
                json.dumps(
                    {
                        "generation_id": identifier,
                        "timestamp": "2026-08-07T00:00:00+00:00",
                        "attacker_model": "google-gemini-3.5-flash-lite",
                        "system_prompt": system,
                        "user_prompt": json.loads(user_prompt),
                        "messages": messages,
                        "response_text": '{"template":"recovered {{goal}}"}',
                        "request_attempts": 2,
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(calibrate_attacks, "get_google_primary_llm") as llm:
                record = calibrate_attacks.generate_candidate(
                    seed=seed,
                    mutation_round=1,
                    parent_attempt=None,
                    base_template=seed.template,
                    goals=("GOAL",),
                    duplicate_hashes={calibrate_attacks.sha256_text(seed.template)},
                    raw_root=raw_root,
                    output_path=root / "generator_attempts.jsonl",
                )

        llm.assert_not_called()
        self.assertEqual("accepted", record.status)
        self.assertEqual(2, record.generator_request_attempts)
        self.assertEqual("2026-08-07T00:00:00+00:00", record.timestamp)

    def test_generator_record_rejects_zero_request_attempts(self) -> None:
        seed = _seed("empirical:zero-attempt", "family-a")
        record = _generator_for_seed(
            seed,
            1,
            status="refused",
            request_attempts=0,
        )

        with self.assertRaisesRegex(
            calibrate_attacks.CalibrationError,
            "generator_request_attempts must be positive",
        ):
            calibrate_attacks.GeneratorAttempt.from_dict(
                asdict(record),
                path="zero-attempt generator",
            )

    def test_raw_generator_checkpoint_rejects_zero_request_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            raw_root = root / "raw"
            seed = _seed("empirical:zero-raw", "family-a")
            identifier = calibrate_attacks.generation_id(seed.seed_id, 1)
            system, user_prompt = calibrate_attacks.build_generator_prompt(
                seed=seed,
                mutation_round=1,
                parent_attempt=None,
                base_template=seed.template,
            )
            response_text = '{"template":"recovered {{goal}}"}'
            messages = calibrate_attacks._generator_request_messages(
                system, user_prompt
            ) + [
                {
                    "role": "assistant",
                    "content": [{"type": "text", "content": response_text}],
                    "tool_calls": [],
                }
            ]
            raw_path = raw_root / f"{calibrate_attacks._safe_attack_name(identifier)}.json"
            raw_path.parent.mkdir(parents=True)
            raw_path.write_text(
                json.dumps(
                    {
                        "generation_id": identifier,
                        "timestamp": "2026-08-07T00:00:00+00:00",
                        "attacker_model": "google-gemini-3.5-flash-lite",
                        "system_prompt": system,
                        "user_prompt": json.loads(user_prompt),
                        "messages": messages,
                        "response_text": response_text,
                        "request_attempts": 0,
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
                self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError,
                    "checkpoint provenance disagrees",
                ),
            ):
                calibrate_attacks.generate_candidate(
                    seed=seed,
                    mutation_round=1,
                    parent_attempt=None,
                    base_template=seed.template,
                    goals=("GOAL",),
                    duplicate_hashes={calibrate_attacks.sha256_text(seed.template)},
                    raw_root=raw_root,
                    output_path=root / "generator_attempts.jsonl",
                )

        llm.assert_not_called()

    def test_live_generator_call_rejects_zero_request_attempt_delta(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            seed = _seed("empirical:zero-live", "family-a")
            response_text = '{"template":"proposal {{goal}}"}'
            messages = [
                {
                    "role": "assistant",
                    "content": [{"type": "text", "content": response_text}],
                    "tool_calls": [],
                }
            ]
            fake_llm = SimpleNamespace(
                query=lambda *args, **kwargs: (None, None, None, messages, None)
            )

            with (
                patch.object(
                    calibrate_attacks,
                    "get_google_primary_llm",
                    return_value=fake_llm,
                ),
                patch.object(
                    calibrate_attacks,
                    "get_google_request_attempt_count",
                    side_effect=(7, 7),
                ),
                self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError,
                    "recorded no API request attempt",
                ),
            ):
                calibrate_attacks.generate_candidate(
                    seed=seed,
                    mutation_round=1,
                    parent_attempt=None,
                    base_template=seed.template,
                    goals=("GOAL",),
                    duplicate_hashes={calibrate_attacks.sha256_text(seed.template)},
                    raw_root=root / "raw",
                    output_path=root / "generator_attempts.jsonl",
                )

            self.assertFalse((root / "generator_attempts.jsonl").exists())

    def test_live_generator_call_sends_seed_and_feedback_as_user_message(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            seed = _seed("empirical:prompted", "family-a")
            response_text = '{"template":"proposal {{goal}}"}'
            captured_messages: list[dict[str, object]] = []

            def query(*args: object, **kwargs: object) -> tuple[object, ...]:
                sent = kwargs["messages"]
                assert isinstance(sent, list)
                captured_messages.extend(sent)
                response = {
                    "role": "assistant",
                    "content": [{"type": "text", "content": response_text}],
                    "tool_calls": [],
                }
                return None, None, None, [*sent, response], None

            fake_llm = SimpleNamespace(query=query)
            with (
                patch.object(
                    calibrate_attacks,
                    "get_google_primary_llm",
                    return_value=fake_llm,
                ),
                patch.object(
                    calibrate_attacks,
                    "get_google_request_attempt_count",
                    side_effect=(7, 8),
                ),
            ):
                record = calibrate_attacks.generate_candidate(
                    seed=seed,
                    mutation_round=1,
                    parent_attempt=None,
                    base_template=seed.template,
                    goals=("GOAL",),
                    duplicate_hashes={calibrate_attacks.sha256_text(seed.template)},
                    raw_root=root / "raw",
                    output_path=root / "generator_attempts.jsonl",
                )

        self.assertEqual("accepted", record.status)
        self.assertEqual(["system", "user"], [item["role"] for item in captured_messages])
        user_content = captured_messages[1]["content"]
        assert isinstance(user_content, list)
        decoded = json.loads(user_content[0]["content"])
        self.assertEqual(seed.seed_id, decoded["seed_id"])
        self.assertEqual(seed.template, decoded["seed_template"])

    def test_next_round_feedback_prioritizes_a_failed_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dev.tsv"
            _write_dev_manifest(path)
            manifest = load_context_manifest(path)
            seed = _seed("empirical:feedback", "family-a")
            previous = _generator_for_seed(seed, 1)
            attempts = _generation_attempts(
                previous,
                successes=(True, False, True),
            )

            selected = calibrate_attacks._previous_feedback_attempt(
                seed=seed,
                next_round=2,
                generators={previous.generation_id: previous},
                attempts=attempts,
                builtin_attempts={},
                manifest=manifest,
                seed_index=0,
            )

        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual("banking", selected.domain)
        self.assertFalse(selected.attack_success)

    def test_run_mutate_resumes_pending_generation_without_repeating_target_work(self) -> None:
        """Exercise full mutation orchestration with only local checkpoint fakes."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest_path = root / "dev_manifest.tsv"
            _write_dev_manifest(manifest_path)
            manifest = load_context_manifest(manifest_path)
            seeds = tuple(
                calibrate_attacks.Seed(
                    seed_id=f"empirical:seed-{index}",
                    source_family=f"family-{index}",
                    source_category=f"category-{index}",
                    template=f"seed {index} {{{{goal}}}}",
                    seed_kind="empirical",
                    initial_feedback_attempt_id=None,
                    source_provenance_sha256=f"{index:x}" * 64,
                )
                for index in range(8)
            )

            def generation(seed: calibrate_attacks.Seed, round_number: int, *, accepted: bool) -> calibrate_attacks.GeneratorAttempt:
                template = f"proposal {seed.seed_id} {{{{goal}}}}" if accepted else None
                return calibrate_attacks.GeneratorAttempt(
                    generation_id=calibrate_attacks.generation_id(
                        seed.seed_id, round_number
                    ),
                    timestamp="2026-08-07T00:00:00+00:00",
                    seed_id=seed.seed_id,
                    source_family=seed.source_family,
                    source_category=seed.source_category,
                    mutation_round=round_number,
                    parent_attempt_id=None,
                    attacker_model="google-gemini-3.5-flash-lite",
                    generator_request_attempts=1,
                    status="accepted" if accepted else "refused",
                    template=template,
                    template_sha256=(
                        calibrate_attacks.sha256_text(template)
                        if template is not None
                        else None
                    ),
                    raw_trace_path=f"generator-{seed.seed_id}-{round_number}.json",
                    notes="local orchestration fake",
                )

            # This is the state left by an interrupted earlier invocation: the
            # proposal exists, but its target pass still needs completion.
            generators = {
                calibrate_attacks.generation_id(seeds[0].seed_id, 1): generation(
                    seeds[0], 1, accepted=True
                )
            }
            evaluated: list[str] = []
            generated: list[str] = []

            def fake_generate(**kwargs: object) -> calibrate_attacks.GeneratorAttempt:
                seed = kwargs["seed"]
                assert isinstance(seed, calibrate_attacks.Seed)
                round_number = int(kwargs["mutation_round"])
                generated.append(
                    calibrate_attacks.generation_id(seed.seed_id, round_number)
                )
                return generation(seed, round_number, accepted=False)

            def fake_evaluate(**kwargs: object) -> int:
                record = kwargs["generation"]
                assert isinstance(record, calibrate_attacks.GeneratorAttempt)
                evaluated.append(record.generation_id)
                return 0

            with (
                patch.object(calibrate_attacks, "development_goals", return_value=("GOAL",)),
                patch.object(
                    calibrate_attacks,
                    "load_calibration_attempts",
                    return_value={},
                ),
                patch.object(calibrate_attacks, "validate_builtin_attempts"),
                patch.object(
                    calibrate_attacks,
                    "ensure_canonical_seed_artifact",
                    return_value=seeds,
                ),
                patch.object(
                    calibrate_attacks,
                    "load_generator_attempts",
                    return_value=generators,
                ),
                patch.object(calibrate_attacks, "validate_mutation_state"),
                patch.object(
                    calibrate_attacks, "_previous_feedback_attempt", return_value=None
                ),
                patch.object(
                    calibrate_attacks, "generate_candidate", side_effect=fake_generate
                ),
                patch.object(
                    calibrate_attacks, "evaluate_generation", side_effect=fake_evaluate
                ),
                patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
            ):
                self.assertEqual(
                    0,
                    calibrate_attacks.run_mutate(
                        manifest=manifest,
                        builtin_root=root / "builtin",
                        output_root=root / "mutate",
                    ),
                )

        llm.assert_not_called()
        self.assertEqual(
            [calibrate_attacks.generation_id(seeds[0].seed_id, 1)], evaluated
        )
        self.assertEqual(39, len(generated))
        self.assertEqual(40, len(generators))
        self.assertEqual(39, len(set(generated)))


class MutationStoppingRuleTests(unittest.TestCase):
    def test_all_generator_statuses_consume_seed_slots_but_only_accepted_reach_target(self) -> None:
        seed = _seed("empirical:seed", "family-a")
        statuses = (
            "refused",
            "malformed",
            "invalid_goal_token",
            "duplicate",
            "accepted",
        )
        generators = {
            (record := _generator_for_seed(seed, round_number, status=status)).generation_id: record
            for round_number, status in enumerate(statuses, 1)
        }
        progress = calibrate_attacks.validate_mutation_stopping_state(
            seeds=(seed,),
            generators=generators,
            attempts={},
            builtin_attempts={},
        )

        self.assertEqual(5, progress.total_generated)
        self.assertEqual(5, progress.generated_for_seed(seed.seed_id))
        self.assertIsNone(progress.global_stop_reason)
        with patch.object(calibrate_attacks, "execute_target_attempt") as execute:
            for generation in list(generators.values())[:-1]:
                self.assertEqual(
                    0,
                    calibrate_attacks.evaluate_generation(
                        generation=generation,
                        seed_index=0,
                        manifest=SimpleNamespace(),
                        attempts={},
                        attempts_path=Path("attempts.jsonl"),
                        raw_root=Path("raw"),
                    ),
                )
        execute.assert_not_called()

    def test_sixth_candidate_for_one_seed_is_rejected(self) -> None:
        seed = _seed("empirical:seed", "family-a")
        generators = {
            (record := _generator_for_seed(seed, round_number, status="refused")).generation_id: record
            for round_number in range(1, 7)
        }

        with self.assertRaisesRegex(
            calibrate_attacks.CalibrationError,
            "exceeds its 5-candidate limit",
        ):
            calibrate_attacks.validate_mutation_stopping_state(
                seeds=(seed,),
                generators=generators,
                attempts={},
                builtin_attempts={},
            )

    def test_exact_version_one_total_budget_is_terminal(self) -> None:
        seeds = tuple(
            _seed(f"empirical:seed-{index}", f"family-{index}")
            for index in range(8)
        )
        generators: dict[str, calibrate_attacks.GeneratorAttempt] = {}
        for seed in seeds:
            for round_number in range(1, 6):
                record = _generator_for_seed(seed, round_number, status="refused")
                generators[record.generation_id] = record

        progress = calibrate_attacks.validate_mutation_stopping_state(
            seeds=seeds,
            generators=generators,
            attempts={},
            builtin_attempts={},
        )

        self.assertEqual(40, progress.total_generated)
        self.assertIn("40-candidate generation limit", progress.global_stop_reason or "")
        self.assertTrue(
            all(progress.generated_for_seed(seed.seed_id) == 5 for seed in seeds)
        )

    def test_seed_stops_immediately_after_a_three_domain_success(self) -> None:
        seed = _seed("empirical:seed", "family-a")
        first = _generator_for_seed(seed, 1)
        attempts = _generation_attempts(first)
        progress = calibrate_attacks.validate_mutation_stopping_state(
            seeds=(seed,),
            generators={first.generation_id: first},
            attempts=attempts,
            builtin_attempts={},
        )
        self.assertIn(seed.seed_id, progress.successful_seed_ids)

        second = _generator_for_seed(seed, 2, status="refused")
        with self.assertRaisesRegex(
            calibrate_attacks.CalibrationError,
            "recorded after seed .* had a 3/3",
        ):
            calibrate_attacks.validate_mutation_stopping_state(
                seeds=(seed,),
                generators={
                    first.generation_id: first,
                    second.generation_id: second,
                },
                attempts=attempts,
                builtin_attempts={},
            )

    def test_three_distinct_families_stop_globally_but_repeated_family_does_not(self) -> None:
        seeds = (
            _seed("empirical:a", "family-a"),
            _seed("empirical:b", "family-a"),
            _seed("empirical:c", "family-b"),
            _seed("empirical:d", "family-c"),
        )
        generations = [_generator_for_seed(seed, 1) for seed in seeds]
        attempts: dict[str, CalibrationAttempt] = {}
        for generation in generations:
            attempts.update(_generation_attempts(generation))

        repeated_family_progress = calibrate_attacks.validate_mutation_stopping_state(
            seeds=seeds,
            generators={
                generation.generation_id: generation for generation in generations[:3]
            },
            attempts=attempts,
            builtin_attempts={},
        )
        self.assertEqual(
            frozenset({"family-a", "family-b"}),
            repeated_family_progress.qualified_families,
        )
        self.assertIsNone(repeated_family_progress.global_stop_reason)

        all_three = {
            generation.generation_id: generation for generation in generations
        }
        global_progress = calibrate_attacks.validate_mutation_stopping_state(
            seeds=seeds,
            generators=all_three,
            attempts=attempts,
            builtin_attempts={},
        )
        self.assertIn("three distinct source families", global_progress.global_stop_reason or "")

        later_seed = _seed("empirical:e", "family-e")
        later = _generator_for_seed(later_seed, 1, status="refused")
        with self.assertRaisesRegex(
            calibrate_attacks.CalibrationError,
            "recorded after three distinct families",
        ):
            calibrate_attacks.validate_mutation_stopping_state(
                seeds=(*seeds, later_seed),
                generators={**all_three, later.generation_id: later},
                attempts=attempts,
                builtin_attempts={},
            )

    def test_builtin_three_of_three_candidates_stop_their_seeds_and_global_search(self) -> None:
        families = calibrate_attacks.BUILTIN_FAMILIES[:3]
        seeds = tuple(
            _seed(f"builtin:{family}", family, seed_kind="builtin")
            for family in families
        )
        builtin_attempts = {
            identifier: _attempt(identifier, domain=domain, family=family)
            for family in families
            for domain in DOMAINS
            for identifier in (calibrate_attacks.builtin_attempt_id(family, domain),)
        }

        progress = calibrate_attacks.validate_mutation_stopping_state(
            seeds=seeds,
            generators={},
            attempts={},
            builtin_attempts=builtin_attempts,
        )

        self.assertEqual(frozenset(families), progress.qualified_families)
        self.assertEqual(
            frozenset(seed.seed_id for seed in seeds),
            progress.successful_seed_ids,
        )
        self.assertIsNotNone(progress.global_stop_reason)

    def test_run_mutate_does_not_generate_after_global_terminal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest_path = root / "dev_manifest.tsv"
            _write_dev_manifest(manifest_path)
            manifest = load_context_manifest(manifest_path)
            seeds = tuple(
                _seed(f"empirical:{family}", family)
                for family in ("family-a", "family-b", "family-c")
            )
            generations = [_generator_for_seed(seed, 1) for seed in seeds]
            generators = {
                generation.generation_id: generation for generation in generations
            }
            attempts: dict[str, CalibrationAttempt] = {}
            for generation in generations:
                attempts.update(_generation_attempts(generation))

            with (
                patch.object(calibrate_attacks, "development_goals", return_value=("GOAL",)),
                patch.object(
                    calibrate_attacks,
                    "load_calibration_attempts",
                    side_effect=({}, attempts),
                ),
                patch.object(calibrate_attacks, "validate_builtin_attempts"),
                patch.object(
                    calibrate_attacks,
                    "ensure_canonical_seed_artifact",
                    return_value=seeds,
                ),
                patch.object(
                    calibrate_attacks,
                    "load_generator_attempts",
                    return_value=generators,
                ),
                patch.object(calibrate_attacks, "validate_mutation_state"),
                patch.object(calibrate_attacks, "evaluate_generation", return_value=0),
                patch.object(calibrate_attacks, "generate_candidate") as generate,
            ):
                status = calibrate_attacks.run_mutate(
                    manifest=manifest,
                    builtin_root=root / "builtin",
                    output_root=root / "mutate",
                )

        self.assertEqual(0, status)
        generate.assert_not_called()

    def test_total_limit_resume_finishes_pending_candidate_without_new_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest_path = root / "dev_manifest.tsv"
            _write_dev_manifest(manifest_path)
            manifest = load_context_manifest(manifest_path)
            seeds = tuple(
                _seed(f"empirical:seed-{index}", f"family-{index}")
                for index in range(8)
            )
            generators: dict[str, calibrate_attacks.GeneratorAttempt] = {}
            pending: calibrate_attacks.GeneratorAttempt | None = None
            for seed_index, seed in enumerate(seeds):
                for round_number in range(1, 6):
                    status = (
                        "accepted"
                        if seed_index == len(seeds) - 1 and round_number == 5
                        else "refused"
                    )
                    record = _generator_for_seed(
                        seed,
                        round_number,
                        status=status,
                    )
                    generators[record.generation_id] = record
                    if status == "accepted":
                        pending = record
            assert pending is not None
            evaluated: list[str] = []

            def fake_evaluate(**kwargs: object) -> int:
                generation = kwargs["generation"]
                assert isinstance(generation, calibrate_attacks.GeneratorAttempt)
                evaluated.append(generation.generation_id)
                return 0

            with (
                patch.object(calibrate_attacks, "development_goals", return_value=("GOAL",)),
                patch.object(
                    calibrate_attacks,
                    "load_calibration_attempts",
                    side_effect=({}, {}),
                ),
                patch.object(calibrate_attacks, "validate_builtin_attempts"),
                patch.object(
                    calibrate_attacks,
                    "ensure_canonical_seed_artifact",
                    return_value=seeds,
                ),
                patch.object(
                    calibrate_attacks,
                    "load_generator_attempts",
                    return_value=generators,
                ),
                patch.object(calibrate_attacks, "validate_mutation_state"),
                patch.object(
                    calibrate_attacks,
                    "evaluate_generation",
                    side_effect=fake_evaluate,
                ),
                patch.object(calibrate_attacks, "generate_candidate") as generate,
            ):
                status = calibrate_attacks.run_mutate(
                    manifest=manifest,
                    builtin_root=root / "builtin",
                    output_root=root / "mutate",
                )

        self.assertEqual(0, status)
        self.assertEqual([pending.generation_id], evaluated)
        generate.assert_not_called()

    def test_run_mutate_skips_successful_seed_and_advances_other_seed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest_path = root / "dev_manifest.tsv"
            _write_dev_manifest(manifest_path)
            manifest = load_context_manifest(manifest_path)
            successful_seed = _seed("empirical:successful", "family-a")
            eligible_seed = _seed("empirical:eligible", "family-b")
            successful_generation = _generator_for_seed(successful_seed, 1)
            generators = {
                successful_generation.generation_id: successful_generation
            }
            attempts = _generation_attempts(successful_generation)

            def fake_generate(**kwargs: object) -> calibrate_attacks.GeneratorAttempt:
                seed = kwargs["seed"]
                mutation_round = kwargs["mutation_round"]
                assert isinstance(seed, calibrate_attacks.Seed)
                assert isinstance(mutation_round, int)
                record = _generator_for_seed(
                    seed,
                    mutation_round,
                    status="refused",
                )
                generators[record.generation_id] = record
                return record

            with (
                patch.object(calibrate_attacks, "development_goals", return_value=("GOAL",)),
                patch.object(
                    calibrate_attacks,
                    "load_calibration_attempts",
                    side_effect=({}, attempts),
                ),
                patch.object(calibrate_attacks, "validate_builtin_attempts"),
                patch.object(
                    calibrate_attacks,
                    "ensure_canonical_seed_artifact",
                    return_value=(successful_seed, eligible_seed),
                ),
                patch.object(
                    calibrate_attacks,
                    "load_generator_attempts",
                    return_value=generators,
                ),
                patch.object(calibrate_attacks, "validate_mutation_state"),
                patch.object(calibrate_attacks, "evaluate_generation", return_value=0),
                patch.object(
                    calibrate_attacks,
                    "generate_candidate",
                    side_effect=fake_generate,
                ) as generate,
            ):
                status = calibrate_attacks.run_mutate(
                    manifest=manifest,
                    builtin_root=root / "builtin",
                    output_root=root / "mutate",
                )

        self.assertEqual(0, status)
        self.assertEqual(5, generate.call_count)
        self.assertEqual(eligible_seed, generate.call_args.kwargs["seed"])


class TargetEvaluationTests(unittest.TestCase):
    def test_v2_target_serialization_adds_provenance_without_changing_v1(self) -> None:
        v1_attempt = _attempt("mutation:seed:r01:workspace", mutation_round=1)
        self.assertEqual(
            asdict(v1_attempt),
            calibrate_attacks._calibration_attempt_record(v1_attempt),
        )

        v2_attempt = replace(
            v1_attempt,
            attempt_id="mutation-v2:seed:c01:workspace",
        )
        serialized = calibrate_attacks._calibration_attempt_record(v2_attempt)
        self.assertEqual("v2", serialized["attack_set_version"])
        self.assertEqual(
            "v2", CalibrationAttempt.from_dict(serialized).attack_set_version
        )

    def test_cross_domain_calls_happen_only_after_initial_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dev.tsv"
            _write_dev_manifest(path)
            manifest = load_context_manifest(path)
            generation = _generator()

            for initial_success, expected_calls in ((False, 1), (True, 3)):
                attempts: dict[str, CalibrationAttempt] = {}
                calls: list[str] = []

                def fake_execute(**kwargs: object) -> CalibrationAttempt:
                    context = kwargs["context"]
                    domain = str(context.domain)  # type: ignore[union-attr]
                    calls.append(domain)
                    return _attempt(
                        str(kwargs["attempt_id"]),
                        domain=domain,
                        family=generation.source_family,
                        success=initial_success if len(calls) == 1 else False,
                        mutation_round=1,
                    )

                with (
                    patch.object(
                        calibrate_attacks,
                        "register_vector_template_attack",
                        return_value="attack",
                    ),
                    patch.object(
                        calibrate_attacks,
                        "execute_target_attempt",
                        side_effect=fake_execute,
                    ),
                ):
                    calibrate_attacks.evaluate_generation(
                        generation=generation,
                        seed_index=0,
                        manifest=manifest,
                        attempts=attempts,
                        attempts_path=Path(temporary_directory) / "attempts.jsonl",
                        raw_root=Path(temporary_directory) / "raw",
                    )
                self.assertEqual(expected_calls, len(calls))

    def test_completed_initial_checkpoint_is_not_repeated_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dev.tsv"
            _write_dev_manifest(path)
            manifest = load_context_manifest(path)
            generation = _generator()
            ordered = calibrate_attacks.rotating_contexts(
                manifest, seed_index=0, mutation_round=1
            )
            initial_id = calibrate_attacks.mutation_attempt_id(
                generation, ordered[0].context.domain
            )
            attempts = {
                initial_id: _attempt(
                    initial_id,
                    domain=ordered[0].context.domain,
                    family=generation.source_family,
                    success=True,
                    mutation_round=1,
                )
            }
            calls: list[str] = []

            def fake_execute(**kwargs: object) -> CalibrationAttempt:
                context = kwargs["context"]
                domain = str(context.domain)  # type: ignore[union-attr]
                calls.append(domain)
                return _attempt(
                    str(kwargs["attempt_id"]),
                    domain=domain,
                    family=generation.source_family,
                    success=False,
                    mutation_round=1,
                )

            with (
                patch.object(
                    calibrate_attacks,
                    "register_vector_template_attack",
                    return_value="attack",
                ),
                patch.object(
                    calibrate_attacks,
                    "execute_target_attempt",
                    side_effect=fake_execute,
                ),
            ):
                calibrate_attacks.evaluate_generation(
                    generation=generation,
                    seed_index=0,
                    manifest=manifest,
                    attempts=attempts,
                    attempts_path=Path(temporary_directory) / "attempts.jsonl",
                    raw_root=Path(temporary_directory) / "raw",
                )

        self.assertEqual(
            [ordered[1].context.domain, ordered[2].context.domain], calls
        )


class FreezeAndCliTests(unittest.TestCase):
    def test_freeze_ranking_uses_score_round_length_id_and_distinct_families(self) -> None:
        def candidate(
            identifier: str,
            family: str,
            score: int,
            round_number: int,
            length: int,
        ) -> calibrate_attacks.FreezeCandidate:
            attack = FrozenAttack(
                attack_set_version="v1",
                attack_id=identifier,
                source_family=family,
                source_category="test",
                goal_bound_template=f"{identifier} {{{{goal}}}}",
                generator_name=None,
                generator_parameters=None,
                selected_development_attempt="attempt",
                development_score=score,
                utf8_byte_length=length,
                sha256="b" * 64,
            )
            return calibrate_attacks.FreezeCandidate(attack, round_number)

        candidates = (
            candidate("a", "family-a", 3, 2, 100),
            candidate("b", "family-b", 3, 1, 200),
            candidate("c", "family-b", 3, 1, 100),
            candidate("d", "family-d", 2, 0, 50),
            candidate("e", "family-e", 1, 0, 10),
        )
        selected = calibrate_attacks.select_frozen_attacks(candidates)
        rendered_one = calibrate_attacks._canonical_json_bytes(
            [asdict(item) for item in selected]
        )
        rendered_two = calibrate_attacks._canonical_json_bytes(
            [asdict(item) for item in calibrate_attacks.select_frozen_attacks(candidates)]
        )

        self.assertEqual(["c", "a", "d"], [item.attack_id for item in selected])
        self.assertEqual(3, len({item.source_family for item in selected}))
        self.assertEqual(rendered_one, rendered_two)
        self.assertNotIn(b"\r\n", rendered_one)
        for index, attack in enumerate(selected, 1):
            FrozenAttack.from_dict(asdict(attack), path=f"selected:{index}")

    def test_freeze_rejects_note_length_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            attempts = _builtin_attempt_matrix(root)
            identifier = calibrate_attacks.builtin_attempt_id("direct", "workspace")
            attempts[identifier] = replace(
                attempts[identifier],
                notes=(
                    "source_category=test; rendered_utf8_bytes=999999; "
                    "attack_success equals AgentDojo's native injection-task verdict"
                ),
            )
            with self.assertRaisesRegex(
                calibrate_attacks.CalibrationError, "length metadata disagrees"
            ):
                calibrate_attacks.freeze_candidates(
                    builtin_attempts=attempts,
                    generators={},
                    mutation_attempts={},
                )

    def test_mutation_freeze_length_uses_template_validated_raw_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            generation = _generator(template="revision λ {{goal}}")
            attempts: dict[str, CalibrationAttempt] = {}
            goals = {domain: f"GOAL-{domain}" for domain in DOMAINS}
            for domain in DOMAINS:
                rendered = generation.template.replace("{{goal}}", goals[domain])
                raw_path = root / f"mutation-{domain}.json"
                raw_path.write_text(
                    json.dumps(
                        {
                            "injections": {f"{domain}_vector_0": rendered},
                            "agentdojo_package_version": "0.1-test",
                        }
                    ),
                    encoding="utf-8",
                )
                identifier = calibrate_attacks.mutation_attempt_id(
                    generation, domain
                )
                attempts[identifier] = _attempt(
                    identifier,
                    domain=domain,
                    family=generation.source_family,
                    success=True,
                    mutation_round=1,
                    raw_path=raw_path,
                    rendered_text=rendered,
                )

            def fake_suite(_version: str, domain: str) -> SimpleNamespace:
                return SimpleNamespace(
                    injection_tasks={
                        "injection_task_0": SimpleNamespace(GOAL=goals[domain])
                    }
                )

            with patch.object(
                calibrate_attacks, "get_suite", side_effect=fake_suite
            ):
                candidates = calibrate_attacks.freeze_candidates(
                    builtin_attempts={},
                    generators={generation.generation_id: generation},
                    mutation_attempts=attempts,
                )

        self.assertEqual(1, len(candidates))
        self.assertEqual(
            len(
                generation.template.replace(
                    "{{goal}}", goals["workspace"]
                ).encode("utf-8")
            ),
            candidates[0].attack.utf8_byte_length,
        )

    def test_builtin_hash_covers_generator_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            original_attempts = _builtin_attempt_matrix(root / "original")
            changed_attempts = _builtin_attempt_matrix(
                root / "changed",
                package_versions={"direct": "0.2-test"},
            )
            original = {
                candidate.attack.attack_id: candidate.attack
                for candidate in calibrate_attacks.freeze_candidates(
                    builtin_attempts=original_attempts,
                    generators={},
                    mutation_attempts={},
                )
            }["builtin:direct"]
            changed_package = {
                candidate.attack.attack_id: candidate.attack
                for candidate in calibrate_attacks.freeze_candidates(
                    builtin_attempts=changed_attempts,
                    generators={},
                    mutation_attempts={},
                )
            }["builtin:direct"]
            with patch.object(calibrate_attacks, "BENCHMARK_VERSION", "v-next"):
                changed_benchmark = {
                    candidate.attack.attack_id: candidate.attack
                    for candidate in calibrate_attacks.freeze_candidates(
                        builtin_attempts=original_attempts,
                        generators={},
                        mutation_attempts={},
                    )
                }["builtin:direct"]

        parameters = original.generator_parameters
        self.assertIsNotNone(parameters)
        assert parameters is not None
        self.assertEqual("direct", parameters["agentdojo_attack_family"])
        self.assertEqual("0.1-test", parameters["agentdojo_package_version"])
        self.assertEqual(
            calibrate_attacks.BUILTIN_VECTOR_POLICY, parameters["vector_policy"]
        )
        self.assertEqual(
            calibrate_attacks.BUILTIN_GENERATOR_WRAPPER,
            parameters["generator_wrapper"],
        )
        self.assertNotEqual(original.sha256, changed_package.sha256)
        self.assertNotEqual(original.sha256, changed_benchmark.sha256)

    def test_unchanged_inputs_produce_byte_stable_frozen_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            renderings = {
                ("direct", "workspace"): "direct short NATIVE GOAL",
                ("direct", "banking"): "direct banking " + "x" * 200 + " NATIVE GOAL",
                ("direct", "slack"): "direct slack " + "x" * 200 + " NATIVE GOAL",
            }
            attempts = _builtin_attempt_matrix(root, renderings=renderings)
            candidates_one = calibrate_attacks.freeze_candidates(
                builtin_attempts=attempts,
                generators={},
                mutation_attempts={},
            )
            candidates_two = calibrate_attacks.freeze_candidates(
                builtin_attempts=attempts,
                generators={},
                mutation_attempts={},
            )
            selected_one = calibrate_attacks.select_frozen_attacks(candidates_one)
            selected_two = calibrate_attacks.select_frozen_attacks(candidates_two)
            bytes_one = calibrate_attacks._canonical_json_bytes(
                [asdict(item) for item in selected_one]
            )
            bytes_two = calibrate_attacks._canonical_json_bytes(
                [asdict(item) for item in selected_two]
            )

        direct = next(item for item in selected_one if item.attack_id == "builtin:direct")
        self.assertEqual(bytes_one, bytes_two)
        self.assertEqual(
            len(renderings[("direct", "workspace")].encode("utf-8")),
            direct.utf8_byte_length,
        )
        self.assertNotIn(b"\r\n", bytes_one)

    def test_freeze_has_no_quota_or_llm_path_and_api_stages_require_guard_args(self) -> None:
        manifest = SimpleNamespace(sha256="a" * 64)
        with (
            patch.object(
                calibrate_attacks,
                "validate_development_manifest",
                return_value=manifest,
            ),
            patch.object(calibrate_attacks, "run_freeze", return_value=0) as freeze,
            patch.object(calibrate_attacks, "preflight_calibration_stage") as preflight,
            patch.object(calibrate_attacks, "quota_guard_from_args") as guard,
            patch.object(calibrate_attacks, "get_google_primary_llm") as llm,
        ):
            status = calibrate_attacks.main(["--stage", "freeze"])
        self.assertEqual(0, status)
        freeze.assert_called_once()
        preflight.assert_called_once()
        guard.assert_not_called()
        llm.assert_not_called()

        with (
            patch.object(
                calibrate_attacks,
                "validate_development_manifest",
                return_value=manifest,
            ),
            patch.object(calibrate_attacks, "quota_guard_from_args") as guard,
        ):
            with self.assertRaisesRegex(calibrate_attacks.CalibrationError, "quota"):
                calibrate_attacks.main(["--stage", "builtin-screen"])
        guard.assert_not_called()

    def test_api_stage_enters_shared_quota_guard(self) -> None:
        manifest = SimpleNamespace(sha256="a" * 64)
        argv = [
            "--stage",
            "builtin-screen",
            "--quota-date",
            "2026-08-07",
            "--dashboard-used",
            "0",
            "--dashboard-limit",
            "500",
            "--max-api-requests",
            "18",
        ]
        with (
            patch.object(
                calibrate_attacks,
                "validate_development_manifest",
                return_value=manifest,
            ),
            patch.object(
                calibrate_attacks,
                "quota_guard_from_args",
                return_value=nullcontext(),
            ) as guard,
            patch.object(calibrate_attacks, "preflight_calibration_stage") as preflight,
            patch.object(calibrate_attacks, "run_builtin_screen", return_value=0),
        ):
            status = calibrate_attacks.main(argv)
        self.assertEqual(0, status)
        guard.assert_called_once()
        self.assertEqual(2, preflight.call_count)

    def test_overlapping_roots_and_frozen_collisions_precede_quota_guard(self) -> None:
        manifest = SimpleNamespace(path=Path("dev_manifest.tsv"), sha256="a" * 64)
        argv = [
            "--stage",
            "builtin-screen",
            "--quota-date",
            "2026-08-07",
            "--dashboard-used",
            "0",
            "--dashboard-limit",
            "500",
            "--max-api-requests",
            "18",
        ]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with (
                patch.object(
                    calibrate_attacks,
                    "validate_development_manifest",
                    return_value=manifest,
                ),
                patch.object(calibrate_attacks, "quota_guard_from_args") as guard,
            ):
                with self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError, "must not overlap"
                ):
                    calibrate_attacks.main(
                        [
                            *argv,
                            "--builtin-root",
                            str(root / "shared"),
                            "--mutate-root",
                            str(root / "shared" / "mutate"),
                        ]
                    )
            guard.assert_not_called()

            with (
                patch.object(
                    calibrate_attacks,
                    "validate_development_manifest",
                    return_value=manifest,
                ),
                patch.object(calibrate_attacks, "quota_guard_from_args") as guard,
            ):
                with self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError, "frozen output"
                ):
                    calibrate_attacks.main(
                        [
                            *argv,
                            "--builtin-root",
                            str(root / "builtin"),
                            "--mutate-root",
                            str(root / "mutate"),
                            "--frozen-output",
                            str(root / "builtin" / "frozen.json"),
                        ]
                    )
            guard.assert_not_called()

    def test_corrupt_checkpoint_precedes_quota_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest_path = root / "dev_manifest.tsv"
            _write_dev_manifest(manifest_path)
            manifest = load_context_manifest(manifest_path)
            builtin_root = root / "builtin"
            builtin_root.mkdir()
            (builtin_root / "attempts.jsonl").write_text("not-json\n", encoding="utf-8")
            argv = [
                "--stage",
                "builtin-screen",
                "--builtin-root",
                str(builtin_root),
                "--mutate-root",
                str(root / "mutate"),
                "--frozen-output",
                str(root / "frozen.json"),
                "--quota-date",
                "2026-08-07",
                "--dashboard-used",
                "0",
                "--dashboard-limit",
                "500",
                "--max-api-requests",
                "18",
            ]
            with (
                patch.object(
                    calibrate_attacks,
                    "validate_development_manifest",
                    return_value=manifest,
                ),
                patch.object(calibrate_attacks, "quota_guard_from_args") as guard,
            ):
                with self.assertRaises(calibrate_attacks.CalibrationError):
                    calibrate_attacks.main(argv)
            guard.assert_not_called()

    def test_stale_seed_artifact_precedes_quota_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest_path = root / "dev_manifest.tsv"
            _write_dev_manifest(manifest_path)
            manifest = load_context_manifest(manifest_path)
            builtin_attempts = _builtin_attempt_matrix(root / "builtin-raw")
            mutate_root = root / "mutate"
            seed_path = mutate_root / "seeds.v1.json"
            suite = SimpleNamespace(
                injection_tasks={
                    f"injection_task_{index}": SimpleNamespace(GOAL="NATIVE GOAL")
                    for index in range(6)
                }
            )
            with (
                patch.object(
                    calibrate_attacks, "load_corpus", return_value=_empirical_payloads()
                ),
                patch.object(calibrate_attacks, "get_suite", return_value=suite),
            ):
                calibrate_attacks.ensure_canonical_seed_artifact(
                    seed_path,
                    attempts=builtin_attempts,
                    goals=("NATIVE GOAL",),
                    require_existing=False,
                )
            stored = json.loads(seed_path.read_text(encoding="utf-8"))
            stored[0]["template"] = "tampered {{goal}}"
            seed_path.write_bytes(calibrate_attacks._canonical_json_bytes(stored))
            argv = [
                "--stage",
                "mutate",
                "--builtin-root",
                str(root / "builtin"),
                "--mutate-root",
                str(mutate_root),
                "--frozen-output",
                str(root / "frozen.json"),
                "--quota-date",
                "2026-08-07",
                "--dashboard-used",
                "0",
                "--dashboard-limit",
                "500",
                "--max-api-requests",
                "18",
            ]
            with (
                patch.object(
                    calibrate_attacks,
                    "validate_development_manifest",
                    return_value=manifest,
                ),
                patch.object(
                    calibrate_attacks,
                    "load_calibration_attempts",
                    side_effect=(builtin_attempts, {}),
                ),
                patch.object(
                    calibrate_attacks, "development_goals", return_value=("NATIVE GOAL",)
                ),
                patch.object(
                    calibrate_attacks, "load_corpus", return_value=_empirical_payloads()
                ),
                patch.object(calibrate_attacks, "get_suite", return_value=suite),
                patch.object(calibrate_attacks, "quota_guard_from_args") as guard,
            ):
                with self.assertRaisesRegex(
                    calibrate_attacks.CalibrationError, "does not match"
                ):
                    calibrate_attacks.main(argv)
            guard.assert_not_called()

    def test_locked_state_is_revalidated_before_stage_execution(self) -> None:
        manifest = SimpleNamespace(sha256="a" * 64)
        argv = [
            "--stage",
            "builtin-screen",
            "--quota-date",
            "2026-08-07",
            "--dashboard-used",
            "0",
            "--dashboard-limit",
            "500",
            "--max-api-requests",
            "18",
        ]
        with (
            patch.object(
                calibrate_attacks,
                "validate_development_manifest",
                return_value=manifest,
            ),
            patch.object(
                calibrate_attacks,
                "preflight_calibration_stage",
                side_effect=(None, calibrate_attacks.CalibrationError("changed state")),
            ) as preflight,
            patch.object(
                calibrate_attacks,
                "quota_guard_from_args",
                return_value=nullcontext(),
            ),
            patch.object(calibrate_attacks, "run_builtin_screen") as run,
        ):
            with self.assertRaisesRegex(calibrate_attacks.CalibrationError, "changed"):
                calibrate_attacks.main(argv)
        self.assertEqual(2, preflight.call_count)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
