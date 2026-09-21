#!/usr/bin/env python3
"""Run paired LTP coverage contracts with JSON-backed expected records."""
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests/future_cases"
EXTRACTOR = Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract"))
CLANG = os.environ.get("CLANG", shutil.which("clang-21") or shutil.which("clang"))


def canonical(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load_cases():
    sources = {path.stem: path for path in CASES.glob("*.c")}
    answers = {path.stem: path for path in CASES.glob("*.json")}
    if set(sources) != set(answers):
        missing_source = sorted(set(answers) - set(sources))
        missing_answer = sorted(set(sources) - set(answers))
        raise RuntimeError(
            f"unpaired future cases: missing C={missing_source}, "
            f"missing JSON={missing_answer}"
        )

    result = []
    for name in sorted(sources):
        expected_by_function = json.loads(answers[name].read_text())
        if not isinstance(expected_by_function, dict) or not expected_by_function:
            raise RuntimeError(f"{answers[name]} must contain a non-empty object")
        for function, records in expected_by_function.items():
            if not isinstance(function, str) or not isinstance(records, list):
                raise RuntimeError(f"invalid future case {name}:{function}")
            result.append((name, sources[name], function, records))
    return result


FUTURE_CASES = load_cases()


class FutureCaseLayoutTests(unittest.TestCase):
    def test_future_cases_are_paired(self):
        self.assertTrue(FUTURE_CASES)


class FutureLtpCoverageContracts(unittest.TestCase):
    def setUp(self):
        if not EXTRACTOR.is_file():
            self.skipTest("build syscall-extract before running tests")
        if not CLANG:
            self.skipTest("clang is required")

    def assert_future_case(self, source, function, expected):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compdb = directory / "compile_commands.json"
            compdb.write_text(json.dumps([{
                "directory": str(directory),
                "file": str(source),
                "arguments": [
                    CLANG,
                    "--target=x86_64-linux-gnu",
                    "-std=gnu11",
                    "-c",
                    str(source),
                    "-o",
                    str(directory / (source.stem + ".o")),
                ],
            }]))
            result = subprocess.run(
                [
                    str(EXTRACTOR),
                    "--compdb",
                    str(compdb),
                    "--unit-index",
                    "0",
                    "--function",
                    function,
                    "--libc-profile",
                    "glibc-linux-x86_64",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = json.loads(result.stdout)["records"]
            self.assertEqual(
                Counter(map(canonical, actual)),
                Counter(map(canonical, expected)),
            )


def make_future_test(source, function, expected):
    def test(self):
        self.assert_future_case(source, function, expected)

    return test


for case_name, case_source, case_function, case_expected in FUTURE_CASES:
    test_name = f"test_future_{case_name}_{case_function}"
    setattr(
        FutureLtpCoverageContracts,
        test_name,
        make_future_test(case_source, case_function, case_expected),
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
