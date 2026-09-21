#!/usr/bin/env python3
"""Run paired C/JSON contracts for the opt-in glibc wrapper profile."""
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests/libc_cases"
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
            f"unpaired libc cases: missing C={missing_source}, "
            f"missing JSON={missing_answer}"
        )

    result = []
    for name in sorted(sources):
        document = json.loads(answers[name].read_text())
        variants = document.get("variants") if isinstance(document, dict) else None
        if not isinstance(variants, dict) or not variants:
            raise RuntimeError(f"{answers[name]} must contain non-empty variants")
        for variant_name, variant in variants.items():
            if not isinstance(variant, dict):
                raise RuntimeError(f"invalid libc variant {name}:{variant_name}")
            target = variant.get("target")
            profile = variant.get("profile")
            functions = variant.get("functions")
            if not isinstance(target, str) or not isinstance(profile, str):
                raise RuntimeError(f"invalid options for {name}:{variant_name}")
            if not isinstance(functions, dict) or not functions:
                raise RuntimeError(f"invalid functions for {name}:{variant_name}")
            for function, records in functions.items():
                if not isinstance(function, str) or not isinstance(records, list):
                    raise RuntimeError(
                        f"invalid expected records for {name}:{variant_name}:{function}"
                    )
                result.append(
                    (name, sources[name], variant_name, target, profile,
                     function, records)
                )
    return result


LIBC_CASES = load_cases()


class LibcCaseLayoutTests(unittest.TestCase):
    def test_libc_cases_are_paired(self):
        self.assertTrue(LIBC_CASES)


class LibcWrapperModelTests(unittest.TestCase):
    def setUp(self):
        if not EXTRACTOR.is_file():
            self.skipTest("build syscall-extract before running tests")
        if not CLANG:
            self.skipTest("clang is required")

    def assert_libc_case(self, source, target, profile, function, expected):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compdb = directory / "compile_commands.json"
            compdb.write_text(json.dumps([{
                "directory": str(directory),
                "file": str(source),
                "arguments": [
                    CLANG,
                    f"--target={target}",
                    "-std=gnu11",
                    "-c",
                    str(source),
                    "-o",
                    str(directory / (source.stem + ".o")),
                ],
            }]))
            command = [
                str(EXTRACTOR),
                "--compdb",
                str(compdb),
                "--unit-index",
                "0",
                "--function",
                function,
            ]
            if profile != "none":
                command.extend(("--libc-profile", profile))
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data["libc_profile"], profile)
            self.assertEqual(
                Counter(map(canonical, data["records"])),
                Counter(map(canonical, expected)),
            )


def make_libc_test(source, target, profile, function, expected):
    def test(self):
        self.assert_libc_case(source, target, profile, function, expected)

    return test


for (case_name, case_source, case_variant, case_target, case_profile,
     case_function, case_expected) in LIBC_CASES:
    test_name = f"test_{case_name}_{case_variant}_{case_function}"
    setattr(
        LibcWrapperModelTests,
        test_name,
        make_libc_test(
            case_source,
            case_target,
            case_profile,
            case_function,
            case_expected,
        ),
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
