"""Regression checks for immutable baseline indexes and raw traces."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.schemas import RunResult


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FROZEN_INDEXES = {
    "data/baseline/results.jsonl": (
        "903f5d385f87a328e9fd067ba3da1f26d50fdc02a4050cc3e40abfd75dc7264d",
        110,
    ),
    "data/baseline_gemma4/results.jsonl": (
        "ec2aba1b7153c355193e899743a54d133e823d9a775a0798882daa6ae67a85bc",
        110,
    ),
    "data/baseline_gemma4/full/results.jsonl": (
        "f21366cb3e712ecdd966fe8de378f98b45681983f805386c244b04991cca4619",
        180,
    ),
}
FROZEN_TREE_SHA256 = (
    "869c0e1790f4ecfebd7f4fd28196ef50edc32b74ddfb69d29c616a4ce320ffe2"
)


def _frozen_files() -> list[Path]:
    files = list((PROJECT_ROOT / "data" / "baseline").rglob("*"))
    files.extend(
        [
            PROJECT_ROOT / "data" / "baseline_gemma4" / "results.jsonl",
            PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "results.jsonl",
        ]
    )
    files.extend((PROJECT_ROOT / "data" / "baseline_gemma4" / "r").rglob("*"))
    files.extend(
        (PROJECT_ROOT / "data" / "baseline_gemma4" / "full" / "r").rglob("*")
    )
    return sorted({path for path in files if path.is_file()})


def _tree_sha256(files: list[Path]) -> str:
    entries = []
    for path in files:
        relative = path.relative_to(PROJECT_ROOT).as_posix()
        entries.append(f"{relative}\t{hashlib.sha256(path.read_bytes()).hexdigest()}")
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


class FrozenBaselineArtifactTests(unittest.TestCase):
    def test_frozen_indexes_retain_hashes_null_utility_and_schema_compatibility(self) -> None:
        for relative, (expected_sha256, expected_rows) in FROZEN_INDEXES.items():
            with self.subTest(index=relative):
                path = PROJECT_ROOT / relative
                self.assertEqual(expected_sha256, hashlib.sha256(path.read_bytes()).hexdigest())
                rows = [
                    json.loads(line)
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                self.assertEqual(expected_rows, len(rows))
                self.assertTrue(all(row.get("utility_success") is None for row in rows))
                for line_number, row in enumerate(rows, 1):
                    RunResult.from_dict(row, path=f"{relative}:{line_number}")

    def test_all_protected_baseline_files_and_raw_traces_are_byte_stable(self) -> None:
        files = _frozen_files()

        self.assertEqual(433, len(files))
        self.assertEqual(FROZEN_TREE_SHA256, _tree_sha256(files))


if __name__ == "__main__":
    unittest.main()
