#!/usr/bin/env python3
"""Run every paired C/JSON extraction case and compare records by function."""
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests/cases"
EXTRACTOR = Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract"))
CLANG = os.environ.get("CLANG", shutil.which("clang-21") or shutil.which("clang"))


def canonical(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def pretty(records):
    return json.dumps(
        [json.loads(record) for record in sorted(records.elements())],
        ensure_ascii=False,
        indent=2,
    )


class ExtractionCasesTest(unittest.TestCase):
    def run_extractor(self, compdb, unit_index, option):
        result = subprocess.run(
            [
                str(EXTRACTOR),
                f"--compdb={compdb}",
                f"--unit-index={unit_index}",
                option,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            self.fail(f"extractor failed\n{result.stderr}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"extractor returned invalid JSON: {error}\n{result.stdout}")

    def test_source_answer_pairs(self):
        if not EXTRACTOR.is_file():
            self.skipTest("build syscall-extract before running tests")
        if not CLANG:
            self.skipTest("clang is required to analyze the cases")

        sources = {path.stem: path for path in CASES.glob("*.c")}
        answers = {path.stem: path for path in CASES.glob("*.json")}
        self.assertEqual(
            set(sources),
            set(answers),
            "every tests/cases source and answer must have the same basename",
        )
        self.assertTrue(sources, "no tests/cases/*.c and .json pairs found")

        cases = []
        for name in sorted(sources):
            expected_by_function = json.loads(answers[name].read_text())
            self.assertIsInstance(expected_by_function, dict)
            self.assertTrue(expected_by_function, f"{answers[name]} has no functions")
            for function, records in expected_by_function.items():
                self.assertIsInstance(function, str)
                self.assertIsInstance(records, list, f"{name}:{function} must be a list")
            cases.append((name, sources[name], expected_by_function))

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
                        str(build_dir / (name + ".o")),
                    ],
                }
                for name, source, _ in cases
            ]))

            for unit_index, (name, source, expected_by_function) in enumerate(cases):
                with self.subTest(case=name, mode="all-functions"):
                    batch = self.run_extractor(compdb, unit_index, "--all-functions")
                    actual_functions = {
                        entry["function"] for entry in batch["functions"]
                    }
                    self.assertEqual(actual_functions, set(expected_by_function))

                for function, expected in expected_by_function.items():
                    with self.subTest(case=name, function=function):
                        data = self.run_extractor(
                            compdb, unit_index, f"--function={function}"
                        )
                        self.assertEqual(data["source"], str(source))
                        self.assertEqual(data["compilation_unit"]["index"], unit_index)
                        self.assertEqual(data["compilation_unit"]["file"], str(source))
                        self.assertIn("-c", data["compilation_unit"]["command"])
                        self.assertEqual(
                            [entry["function"] for entry in data["functions"]],
                            [function],
                        )

                        expected_records = Counter(map(canonical, expected))
                        actual_records = Counter(map(canonical, data["records"]))
                        if expected_records != actual_records:
                            missing = expected_records - actual_records
                            unexpected = actual_records - expected_records
                            self.fail(
                                f"{name}:{function} records do not match\n"
                                f"missing:\n{pretty(missing)}\n"
                                f"unexpected:\n{pretty(unexpected)}"
                            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
