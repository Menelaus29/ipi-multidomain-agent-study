"""Regression tests for Phase 9 offline validation boundaries."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.analysis.summarize_phase9_fresh160 import summarize


class Phase9ValidationTests(unittest.TestCase):
    def test_summary_rejects_a_defended_index_as_the_undefended_arm(self) -> None:
        defended = Path("data/defended/g4/v1/fresh160/results.jsonl")
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            with self.assertRaisesRegex(ValueError, "contains defense"):
                summarize(
                    undefended_path=defended,
                    output_csv=temporary / "summary.csv",
                    chart_path=temporary / "summary.png",
                )


if __name__ == "__main__":
    unittest.main()
