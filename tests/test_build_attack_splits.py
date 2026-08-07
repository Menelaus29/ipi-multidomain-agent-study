"""No-API tests for the prospective Phase 6A candidate split builder."""

from __future__ import annotations

import csv
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.experiments import build_attack_splits


def _fake_context(domain: str, index: int) -> build_attack_splits.AttackContext:
    channels = {
        "workspace": ("file_content", "email_body", "calendar_event"),
        "banking": ("file_content", "transaction_memo"),
        "slack": ("web_content",),
    }
    channel = channels[domain][index % len(channels[domain])]
    vector_prefix = {
        "file_content": "file",
        "email_body": "email",
        "calendar_event": "calendar",
        "transaction_memo": "transaction",
        "web_content": "web",
    }[channel]
    return build_attack_splits.AttackContext(
        domain=domain,
        channel=channel,
        injection_vector=f"{vector_prefix}_vector_{index % 5}",
        user_task_id=f"user_task_{index}",
        injection_task_id=f"injection_task_{index % 3}",
    )


def _fake_universe(per_domain: int = 50) -> list[build_attack_splits.AttackContext]:
    return [
        _fake_context(domain, index)
        for domain in build_attack_splits.DOMAINS
        for index in range(per_domain)
    ]


class CandidateSelectionTests(unittest.TestCase):
    def test_same_seed_produces_byte_identical_disjoint_manifests(self) -> None:
        full = _fake_universe()
        baseline = [
            context
            for context in full
            if int(context.user_task_id.removeprefix("user_task_")) < 3
        ]

        first_dev, first_holdout = build_attack_splits.build_candidate_sets(
            full, baseline, seed=20260807
        )
        second_dev, second_holdout = build_attack_splits.build_candidate_sets(
            reversed(full), reversed(baseline), seed=20260807
        )

        self.assertEqual(
            build_attack_splits.render_manifest(first_dev),
            build_attack_splits.render_manifest(second_dev),
        )
        self.assertEqual(
            build_attack_splits.render_manifest(first_holdout),
            build_attack_splits.render_manifest(second_holdout),
        )
        self.assertEqual(
            {"workspace": 20, "banking": 20, "slack": 20},
            {
                domain: sum(context.domain == domain for context in first_dev)
                for domain in build_attack_splits.DOMAINS
            },
        )
        self.assertEqual(90, len(first_holdout))
        self.assertFalse(
            {context.key for context in first_dev}
            & {context.key for context in first_holdout}
        )
        self.assertFalse(
            {context.key for context in baseline}
            & {context.key for context in first_holdout}
        )

    def test_seed_changes_the_platform_stable_order(self) -> None:
        contexts = _fake_universe(per_domain=4)
        first = build_attack_splits.seeded_order(contexts, 20260807)
        second = build_attack_splits.seeded_order(contexts, 20260808)
        self.assertNotEqual(first, second)
        self.assertEqual(first, build_attack_splits.seeded_order(reversed(contexts), 20260807))

    def test_required_surface_and_slack_vector_coverage_is_enforced(self) -> None:
        full = [
            context
            for context in _fake_universe()
            if not (context.domain == "workspace" and context.channel == "calendar_event")
        ]
        with self.assertRaisesRegex(build_attack_splits.SplitPlanError, "calendar_event"):
            build_attack_splits.build_candidate_sets(full, [], seed=20260807)

    def test_duplicate_or_missing_full_matrix_contexts_are_rejected(self) -> None:
        full = _fake_universe()
        with self.assertRaisesRegex(build_attack_splits.SplitPlanError, "duplicate"):
            build_attack_splits.build_candidate_sets([*full, full[0]], [])
        absent = build_attack_splits.AttackContext(
            domain="workspace",
            channel="email_body",
            injection_vector="absent",
            user_task_id="user_task_absent",
            injection_task_id="injection_task_absent",
        )
        with self.assertRaisesRegex(build_attack_splits.SplitPlanError, "absent"):
            build_attack_splits.build_candidate_sets(full, [absent])


class ManifestIOTests(unittest.TestCase):
    def test_candidate_manifests_are_pinned_to_lf_on_checkout(self) -> None:
        attributes = (build_attack_splits.PROJECT_ROOT / ".gitattributes").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "/data/attack_calibration/dev_candidates.tsv text eol=lf",
            attributes.splitlines(),
        )
        self.assertIn(
            "/data/attack_calibration/holdout_candidates.tsv text eol=lf",
            attributes.splitlines(),
        )

    def test_manifest_has_canonical_header_ranks_and_lf_bytes(self) -> None:
        contexts = build_attack_splits.seeded_order(_fake_universe(per_domain=2), 20260807)
        content = build_attack_splits.render_manifest(contexts)
        self.assertTrue(content.startswith(b"candidate_rank\tdomain\tchannel\t"))
        self.assertNotIn(b"\r\n", content)
        rows = list(csv.DictReader(content.decode("utf-8").splitlines(), delimiter="\t"))
        self.assertEqual(list(range(1, len(rows) + 1)), [int(row["candidate_rank"]) for row in rows])

    def test_identical_rerun_is_accepted_but_changed_manifest_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            dev_path = root / "dev.tsv"
            holdout_path = root / "holdout.tsv"
            first = build_attack_splits.write_manifests(
                dev_path, b"dev\n", holdout_path, b"holdout\n"
            )
            second = build_attack_splits.write_manifests(
                dev_path, b"dev\n", holdout_path, b"holdout\n"
            )
            self.assertEqual((True, True), first)
            self.assertEqual((False, False), second)
            with self.assertRaisesRegex(build_attack_splits.SplitPlanError, "refusing"):
                build_attack_splits.write_manifests(
                    dev_path, b"changed\n", holdout_path, b"holdout\n"
                )
            self.assertEqual(b"dev\n", dev_path.read_bytes())

    def test_baseline_reader_requires_the_committed_110_row_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "plan.tsv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
                writer.writerow(build_attack_splits.BASELINE_COLUMNS)
                for index in range(110):
                    writer.writerow(
                        (
                            f"payload-{index}",
                            "workspace",
                            "email_body",
                            "email_events_injection",
                            "user_task_14",
                            "injection_task_0",
                        )
                    )
            contexts = build_attack_splits.load_baseline_contexts(path)
        self.assertEqual(1, len(contexts))


class NoApiBoundaryTests(unittest.TestCase):
    def test_full_context_projection_deduplicates_payload_rows_without_an_llm(self) -> None:
        payload_a = SimpleNamespace(channel="email_body")
        payload_b = SimpleNamespace(channel="email_body")
        rows = [
            (payload_a, "workspace", "email_events_injection", "user_task_14", "injection_task_0"),
            (payload_b, "workspace", "email_events_injection", "user_task_14", "injection_task_0"),
        ]
        with (
            patch.object(build_attack_splits, "load_corpus", return_value=[payload_a, payload_b]),
            patch.object(build_attack_splits, "iter_cases", return_value=iter(rows)) as iterator,
        ):
            contexts = build_attack_splits.collect_full_matrix_contexts()
        self.assertEqual(1, len(contexts))
        iterator.assert_called_once_with([payload_a, payload_b], matrix="full")

    def test_cli_requires_explicit_plan_mode(self) -> None:
        with self.assertRaisesRegex(SystemExit, "--plan is required"):
            build_attack_splits.main([])

    def test_cli_rejects_a_seed_other_than_the_fixed_protocol_seed(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as raised:
                build_attack_splits.parse_args(["--plan", "--seed", "20260805"])
        self.assertEqual(2, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
