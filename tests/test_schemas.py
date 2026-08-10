"""No-network tests for the Phase 6A schema extensions."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from src.analysis.validate_schema import main, validate_file
from src.schemas import (
    CLEAN_CONTROL_PAYLOAD_ID,
    CLEAN_CONTROL_PRIMARY_MODEL,
    CalibrationAttempt,
    FrozenAttack,
    GoalAchievabilityControl,
    RunResult,
    SchemaValidationError,
    V2GeneratorAttempt,
)


SHA256_A = "a" * 64
SHA256_B = "b" * 64
SHA256_C = "c" * 64
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def calibration_attempt_record() -> dict[str, object]:
    return {
        "attempt_id": "attempt-001",
        "timestamp": "2026-08-06T00:00:00+00:00",
        "split": "dev",
        "source_family": "important_instructions",
        "seed_id": "builtin-important-instructions",
        "parent_attempt_id": None,
        "mutation_round": 0,
        "attacker_model": "none-for-deterministic-seed",
        "target_model": "google-gemini-3.5-flash-lite",
        "domain": "workspace",
        "user_task_id": "user_task_14",
        "injection_task_id": "injection_task_0",
        "injection_vector": "email_events_injection",
        "rendered_attack_sha256": SHA256_A,
        "attack_success": False,
        "utility_success": True,
        "generator_request_attempts": 0,
        "target_request_attempts": 3,
        "raw_trace_path": "data/attack_calibration/raw/attempt-001.json",
        "notes": "",
    }


def frozen_attack_record() -> dict[str, object]:
    return {
        "attack_set_version": "v1",
        "attack_id": "attack-001",
        "source_family": "important_instructions",
        "source_category": "builtin",
        "goal_bound_template": "Important: execute {{goal}}",
        "generator_name": None,
        "generator_parameters": None,
        "selected_development_attempt": "attempt-001",
        "development_score": 3,
        "utf8_byte_length": 27,
        "sha256": SHA256_B,
    }


def v2_generator_record() -> dict[str, object]:
    template = "Important trusted update: execute {{goal}}"
    return {
        "generation_id": "mutation-v2:builtin:direct:c01",
        "timestamp": "2026-08-08T00:00:00+00:00",
        "attack_set_version": "v2",
        "seed_id": "builtin:direct",
        "source_family": "direct",
        "source_category": "agentdojo_builtin",
        "candidate_number": 1,
        "depth": 1,
        "branch_index": 1,
        "parent_generation_id": None,
        "feedback_attempt_id": "builtin:direct:workspace",
        "target_domain": "workspace",
        "target_user_task_id": "user_task_14",
        "target_injection_task_id": "injection_task_0",
        "target_injection_vector": "email_events_injection",
        "attacker_model": "google-gemini-3.5-flash-lite",
        "generator_request_attempts": 1,
        "status": "accepted",
        "template": template,
        "template_sha256": hashlib.sha256(template.encode("utf-8")).hexdigest(),
        "response_normalization": "fenced_json",
        "prompt_sha256": SHA256_A,
        "raw_trace_path": "data/attack_calibration/mutate_v2/raw/generator/c01.json",
        "notes": "",
    }


def goal_control_record() -> dict[str, object]:
    return {
        "control_id": "goal-control-v2:builtin:direct",
        "timestamp": "2026-08-08T00:00:00+00:00",
        "attack_set_version": "v2",
        "seed_id": "builtin:direct",
        "domain": "workspace",
        "injection_task_id": "injection_task_0",
        "source_context_user_task_id": "user_task_14",
        "source_context_injection_vector": "email_events_injection",
        "goal_sha256": SHA256_B,
        "target_model": "google-gemini-3.5-flash-lite",
        "goal_achievable": True,
        "target_request_attempts": 2,
        "raw_trace_path": "data/attack_calibration/mutate_v2/raw/goal_controls/control.json",
        "notes": "",
    }


def legacy_run_result_record() -> dict[str, object]:
    return {
        "run_id": "run-001",
        "timestamp": "2026-08-06T00:00:00+00:00",
        "domain": "workspace",
        "user_task_id": "user_task_14",
        "injection_task_id": "injection_task_0",
        "payload_id": "direct-01",
        "channel": "email_body",
        "model": "google-gemini-3.5-flash-lite",
        "defense": "none",
        "attack_success": False,
        "tool_calls": [],
        "notes": "",
    }


def clean_control_record() -> dict[str, object]:
    record = legacy_run_result_record()
    record.update(
        {
            "payload_id": CLEAN_CONTROL_PAYLOAD_ID,
            "model": CLEAN_CONTROL_PRIMARY_MODEL,
            "utility_success": True,
            "split": "dev",
            "plan_sha256": SHA256_B,
        }
    )
    return record


class CalibrationAttemptTests(unittest.TestCase):
    def test_valid_development_attempt(self) -> None:
        attempt = CalibrationAttempt.from_dict(calibration_attempt_record())
        self.assertEqual("dev", attempt.split)
        self.assertIsNone(attempt.parent_attempt_id)

    def test_held_out_attempt_is_rejected(self) -> None:
        record = calibration_attempt_record()
        record["split"] = "holdout"
        with self.assertRaisesRegex(SchemaValidationError, "held-out"):
            CalibrationAttempt.from_dict(record)

    def test_invalid_hash_and_negative_counts_are_rejected(self) -> None:
        invalid_hash = calibration_attempt_record()
        invalid_hash["rendered_attack_sha256"] = "ABC"
        with self.assertRaisesRegex(SchemaValidationError, "SHA-256"):
            CalibrationAttempt.from_dict(invalid_hash)

        negative_count = calibration_attempt_record()
        negative_count["generator_request_attempts"] = -1
        with self.assertRaisesRegex(SchemaValidationError, "at least 0"):
            CalibrationAttempt.from_dict(negative_count)

    def test_v2_attempt_requires_explicit_attack_set_provenance(self) -> None:
        record = calibration_attempt_record()
        record["attempt_id"] = "mutation-v2:builtin:direct:c01:workspace"
        record["attack_set_version"] = "v2"
        attempt = CalibrationAttempt.from_dict(record)
        self.assertEqual("v2", attempt.attack_set_version)

        for version in (None, "v1"):
            with self.subTest(version=version):
                malformed = dict(record)
                if version is None:
                    malformed.pop("attack_set_version")
                else:
                    malformed["attack_set_version"] = version
                with self.assertRaisesRegex(
                    SchemaValidationError, "attack_set_version must be 'v2'"
                ):
                    CalibrationAttempt.from_dict(malformed)

    def test_existing_v1_attempt_records_validate_without_new_field(self) -> None:
        path = PROJECT_ROOT / "data" / "attack_calibration" / "mutate" / "attempts.jsonl"
        self.assertTrue(path.is_file())
        with redirect_stdout(StringIO()):
            self.assertEqual(0, validate_file(path, "calibration-attempt"))


class V2GeneratorAttemptTests(unittest.TestCase):
    def test_valid_v2_generator_record(self) -> None:
        record = V2GeneratorAttempt.from_dict(v2_generator_record())
        self.assertEqual("v2", record.attack_set_version)
        self.assertEqual("accepted", record.status)

    def test_malformed_v2_generator_records_are_rejected(self) -> None:
        cases = {
            "version": ("attack_set_version", "v1", "must be 'v2'"),
            "status": ("status", "unknown", "status is invalid"),
            "requests": (
                "generator_request_attempts",
                0,
                "at least 1",
            ),
            "template_hash": ("template_sha256", SHA256_C, "does not match"),
        }
        for name, (field, value, message) in cases.items():
            with self.subTest(name=name):
                malformed = v2_generator_record()
                malformed[field] = value
                with self.assertRaisesRegex(SchemaValidationError, message):
                    V2GeneratorAttempt.from_dict(malformed)


class GoalAchievabilityControlTests(unittest.TestCase):
    def test_valid_goal_control_record(self) -> None:
        record = GoalAchievabilityControl.from_dict(goal_control_record())
        self.assertTrue(record.goal_achievable)
        self.assertEqual("v2", record.attack_set_version)

    def test_malformed_goal_control_records_are_rejected(self) -> None:
        cases = {
            "version": ("attack_set_version", "v1", "must be 'v2'"),
            "identity": ("control_id", "goal-control-v2:other", "seed provenance"),
            "verdict": ("goal_achievable", 1, "must be a boolean"),
            "requests": ("target_request_attempts", 0, "at least 1"),
            "goal_hash": ("goal_sha256", "not-a-hash", "SHA-256"),
        }
        for name, (field, value, message) in cases.items():
            with self.subTest(name=name):
                malformed = goal_control_record()
                malformed[field] = value
                with self.assertRaisesRegex(SchemaValidationError, message):
                    GoalAchievabilityControl.from_dict(malformed)


class FrozenAttackTests(unittest.TestCase):
    def test_valid_template_and_generator_records(self) -> None:
        template = FrozenAttack.from_dict(frozen_attack_record())
        self.assertIsNotNone(template.goal_bound_template)

        generator_record = frozen_attack_record()
        generator_record["goal_bound_template"] = None
        generator_record["generator_name"] = "important_instructions"
        generator_record["generator_parameters"] = {"include_model_name": True}
        generator = FrozenAttack.from_dict(generator_record)
        self.assertEqual(
            {"include_model_name": True}, generator.generator_parameters
        )

    def test_exactly_one_attack_representation_is_required(self) -> None:
        both = frozen_attack_record()
        both["generator_name"] = "important_instructions"
        both["generator_parameters"] = {}
        with self.assertRaisesRegex(SchemaValidationError, "not both"):
            FrozenAttack.from_dict(both)

        neither = frozen_attack_record()
        neither["goal_bound_template"] = None
        with self.assertRaisesRegex(SchemaValidationError, "must define either"):
            FrozenAttack.from_dict(neither)

    def test_score_length_and_hash_are_bounded(self) -> None:
        invalid_score = frozen_attack_record()
        invalid_score["development_score"] = 4
        with self.assertRaisesRegex(SchemaValidationError, "at most 3"):
            FrozenAttack.from_dict(invalid_score)

        invalid_length = frozen_attack_record()
        invalid_length["utf8_byte_length"] = 0
        with self.assertRaisesRegex(SchemaValidationError, "at least 1"):
            FrozenAttack.from_dict(invalid_length)

        invalid_hash = frozen_attack_record()
        invalid_hash["sha256"] = SHA256_B.upper()
        with self.assertRaisesRegex(SchemaValidationError, "lowercase"):
            FrozenAttack.from_dict(invalid_hash)


class RunResultExtensionTests(unittest.TestCase):
    def test_legacy_record_validates_unchanged(self) -> None:
        result = RunResult.from_dict(legacy_run_result_record())
        self.assertIsNone(result.utility_success)
        self.assertIsNone(result.attack_set_version)

    def test_explicit_null_optional_fields_are_legacy_compatible(self) -> None:
        record = legacy_run_result_record()
        record.update(
            {
                "utility_success": None,
                "split": None,
                "attack_set_version": None,
                "attack_sha256": None,
                "plan_sha256": None,
                "defense_version": None,
                "defense_sha256": None,
            }
        )
        self.assertIsNone(RunResult.from_dict(record).split)

    def test_calibrated_undefended_provenance_is_complete(self) -> None:
        record = legacy_run_result_record()
        record.update(
            {
                "utility_success": True,
                "split": "holdout",
                "attack_set_version": "v1",
                "attack_sha256": SHA256_A,
                "plan_sha256": SHA256_B,
            }
        )
        result = RunResult.from_dict(record)
        self.assertEqual("holdout", result.split)

        record.pop("plan_sha256")
        with self.assertRaisesRegex(SchemaValidationError, "incomplete"):
            RunResult.from_dict(record)

    def test_calibrated_context_rejects_an_entirely_missing_bundle(self) -> None:
        with self.assertRaisesRegex(SchemaValidationError, "incomplete"):
            RunResult.from_calibrated_dict(legacy_run_result_record())

    def test_clean_control_accepts_split_and_utility_before_attack_freeze(self) -> None:
        record = clean_control_record()
        result = RunResult.from_clean_control_dict(record)
        self.assertEqual("dev", result.split)
        self.assertIsNone(result.attack_set_version)

    def test_clean_control_rejects_attack_provenance(self) -> None:
        record = clean_control_record()
        record.update(
            {
                "attack_set_version": "v1",
                "attack_sha256": SHA256_A,
            }
        )
        with self.assertRaisesRegex(SchemaValidationError, "must not populate"):
            RunResult.from_clean_control_dict(record)

    def test_clean_control_rejects_defense_provenance(self) -> None:
        record = clean_control_record()
        record.update(
            {
                "defense_version": "v1",
                "defense_sha256": SHA256_C,
            }
        )
        with self.assertRaisesRegex(SchemaValidationError, "must not populate"):
            RunResult.from_clean_control_dict(record)

    def test_clean_control_requires_exact_identity_and_provenance_bundle(self) -> None:
        cases = {
            "plan_sha256": (None, "plan_sha256"),
            "payload_id": ("direct-01", "payload_id"),
            "model": ("google-gemini-3.1-flash-lite", "primary model"),
            "utility_success": (None, "utility_success"),
            "split": (None, "split"),
            "attack_success": (True, "attack_success=false"),
            "defense": ("none-positive-control", "defense='none'"),
        }
        for field, (value, message) in cases.items():
            with self.subTest(field=field):
                record = clean_control_record()
                record[field] = value
                with self.assertRaisesRegex(SchemaValidationError, message):
                    RunResult.from_clean_control_dict(record)

    def test_general_run_that_only_resembles_a_control_is_rejected(self) -> None:
        record = legacy_run_result_record()
        record.update(
            {
                "utility_success": True,
                "split": "dev",
                "plan_sha256": SHA256_B,
            }
        )
        with self.assertRaisesRegex(SchemaValidationError, "payload_id"):
            RunResult.from_clean_control_dict(record)

    def test_plan_hash_without_a_run_context_is_rejected(self) -> None:
        record = legacy_run_result_record()
        record["plan_sha256"] = SHA256_B
        with self.assertRaisesRegex(SchemaValidationError, "requires split"):
            RunResult.from_dict(record)

    def test_defended_rows_require_complete_defense_provenance(self) -> None:
        record = legacy_run_result_record()
        record.update(
            {
                "defense": "my_spotlighting",
                "utility_success": True,
                "split": "holdout",
                "attack_set_version": "v1",
                "attack_sha256": SHA256_A,
                "plan_sha256": SHA256_B,
                "defense_version": "v1",
                "defense_sha256": SHA256_C,
            }
        )
        self.assertEqual("v1", RunResult.from_dict(record).defense_version)

        record.pop("defense_sha256")
        with self.assertRaisesRegex(SchemaValidationError, "populated together"):
            RunResult.from_dict(record)

    def test_undefended_rows_reject_defense_provenance(self) -> None:
        record = legacy_run_result_record()
        record.update(
            {
                "utility_success": True,
                "split": "dev",
                "attack_set_version": "v1",
                "attack_sha256": SHA256_A,
                "plan_sha256": SHA256_B,
                "defense_version": "v1",
                "defense_sha256": SHA256_C,
            }
        )
        with self.assertRaisesRegex(SchemaValidationError, "must not populate"):
            RunResult.from_dict(record)


class ValidateSchemaTests(unittest.TestCase):
    def test_auto_infers_new_record_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            attempts_path = root / "attempts.jsonl"
            attempts_path.write_text(
                json.dumps(calibration_attempt_record()) + "\n", encoding="utf-8"
            )
            attacks_path = root / "frozen_attacks.v1.json"
            attacks_path.write_text(
                json.dumps([frozen_attack_record()]), encoding="utf-8"
            )
            generators_path = root / "generator_attempts.jsonl"
            generators_path.write_text(
                json.dumps(v2_generator_record()) + "\n", encoding="utf-8"
            )
            controls_path = root / "goal_controls.jsonl"
            controls_path.write_text(
                json.dumps(goal_control_record()) + "\n", encoding="utf-8"
            )
            with redirect_stdout(StringIO()):
                self.assertEqual(0, validate_file(attempts_path))
                self.assertEqual(0, validate_file(attacks_path))
                self.assertEqual(0, validate_file(generators_path))
                self.assertEqual(0, validate_file(controls_path))

    def test_schema_flag_and_legacy_kind_alias_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(legacy_run_result_record()) + "\n", encoding="utf-8"
            )
            attacks_path = root / "frozen_attacks.v1.json"
            attacks_path.write_text(
                json.dumps([frozen_attack_record()]), encoding="utf-8"
            )
            with redirect_stdout(StringIO()):
                self.assertEqual(0, main([str(results_path), "--schema", "run"]))
                self.assertEqual(0, main([str(results_path), "--kind", "run"]))
                self.assertEqual(
                    0, main([str(attacks_path), "--schema", "frozen-attack"])
                )

    def test_explicit_v2_schema_kinds_are_registered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            generators_path = root / "generators.jsonl"
            generators_path.write_text(
                json.dumps(v2_generator_record()) + "\n", encoding="utf-8"
            )
            controls_path = root / "controls.jsonl"
            controls_path.write_text(
                json.dumps(goal_control_record()) + "\n", encoding="utf-8"
            )
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    0,
                    validate_file(generators_path, "v2-generator-attempt"),
                )
                self.assertEqual(
                    0,
                    validate_file(controls_path, "goal-achievability-control"),
                )

    def test_explicit_run_contexts_enforce_applicable_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            missing_provenance_path = root / "calibrated.jsonl"
            missing_provenance_path.write_text(
                json.dumps(legacy_run_result_record()) + "\n", encoding="utf-8"
            )
            clean_control = legacy_run_result_record()
            clean_control.update(
                {
                    "payload_id": "none-clean-control",
                    "utility_success": True,
                    "split": "holdout",
                    "plan_sha256": SHA256_B,
                }
            )
            clean_control_path = root / "controls.jsonl"
            clean_control_path.write_text(
                json.dumps(clean_control) + "\n", encoding="utf-8"
            )
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(
                    1,
                    main(
                        [
                            str(missing_provenance_path),
                            "--schema",
                            "calibrated-run",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    main(
                        [
                            str(clean_control_path),
                            "--schema",
                            "clean-control-run",
                        ]
                    ),
                )


if __name__ == "__main__":
    unittest.main()
