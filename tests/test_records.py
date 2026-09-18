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
SOURCES = sorted((ROOT / "tests/src").glob("*.c"))
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
            compdb.write_text(json.dumps([
                {
                    "directory": str(build_dir),
                    "file": str(source),
                    "arguments": [
                        CLANG,
                        "-DCOMPDB_PIDFD=17",
                        "-c",
                        str(source),
                        "-o",
                        str(build_dir / (source.stem + ".o")),
                    ],
                }
                for source in SOURCES
            ]))
            actual_by_key = {}
            for unit_index in range(len(SOURCES)):
                result = subprocess.run(
                    [
                        str(EXTRACTOR),
                        f"--compdb={compdb}",
                        f"--unit-index={unit_index}",
                        "--all-functions",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                for record in json.loads(result.stdout)["records"]:
                    actual_by_key.setdefault(canonical(record), record)

        actual = list(actual_by_key.values())
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
