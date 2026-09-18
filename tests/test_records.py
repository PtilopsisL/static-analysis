#!/usr/bin/env python3
"""Compare extracted records with the checked-in standard answer."""
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/src/fixtures.c"
EXPECTED = ROOT / "tests/records.json"
EXTRACTOR = Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract"))
CLANG = os.environ.get("CLANG", shutil.which("clang-21") or shutil.which("clang"))
RECORD_FIELDS = {"args", "result", "syscall"}


def canonical(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def pretty(records):
    return json.dumps(
        [json.loads(record) for record in sorted(records.elements())],
        ensure_ascii=False,
        indent=2,
    )


class StandardRecordsTest(unittest.TestCase):
    def test_records_match_standard_answer(self):
        if not EXTRACTOR.is_file():
            self.skipTest("build syscall-extract before running tests")
        if not CLANG:
            self.skipTest("clang is required to analyze the fixture")

        expected = json.loads(EXPECTED.read_text())
        self.assertIsInstance(expected, list)
        for record in expected:
            self.assertEqual(set(record), RECORD_FIELDS)

        with tempfile.TemporaryDirectory() as temporary:
            build_dir = Path(temporary)
            compdb = build_dir / "compile_commands.json"
            compdb.write_text(json.dumps([{
                "directory": str(build_dir),
                "file": str(SOURCE),
                "arguments": [
                    CLANG,
                    "-DCOMPDB_PIDFD=17",
                    "-c",
                    str(SOURCE),
                    "-o",
                    str(build_dir / "fixtures.o"),
                ],
            }]))
            result = subprocess.run(
                [str(EXTRACTOR), f"--compdb={compdb}", "--all-functions"],
                capture_output=True,
                text=True,
                check=True,
            )

        actual = json.loads(result.stdout)["records"]
        for record in actual:
            self.assertEqual(set(record), RECORD_FIELDS)

        expected_records = Counter(map(canonical, expected))
        actual_records = Counter(map(canonical, actual))
        if expected_records != actual_records:
            missing = expected_records - actual_records
            unexpected = actual_records - expected_records
            self.fail(
                "records do not match the standard answer\n"
                f"missing:\n{pretty(missing)}\n"
                f"unexpected:\n{pretty(unexpected)}"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
