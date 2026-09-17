#!/usr/bin/env python3
"""Regression checks for analysis of saved preprocessed translation units."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract"))
CLANG = os.environ.get("CLANG", shutil.which("clang-21") or shutil.which("clang"))


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EXTRACTOR.is_file():
            raise unittest.SkipTest("build syscall-extract before running tests")
        if not CLANG:
            raise unittest.SkipTest("clang is required to prepare the test artifact")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.artifact_dir = Path(cls.temporary.name)
        cls.artifact = cls.artifact_dir / "fixtures.i"
        subprocess.run(
            [
                CLANG,
                "-save-temps=obj",
                "-dD",
                "-c",
                str(ROOT / "tests/fixtures.c"),
                "-o",
                str(cls.artifact_dir / "fixtures.o"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def extract(self, function, syscall="pidfd_getfd", extra=()):
        command = [str(EXTRACTOR), f"--function={function}", f"--syscall={syscall}", *extra, str(self.artifact)]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_constant_error(self):
        result = self.extract("constant_error")
        record, = result["records"]
        self.assertEqual(set(record), {"syscall", "args", "result"})
        self.assertEqual(record["args"], [0, 0, 1])
        self.assertEqual(record["result"], {
            "ret": {"op": "==", "value": -1},
            "errno": {"op": "==", "value": 22},
        })
        self.assertEqual(result["source"], str(ROOT / "tests/fixtures.c"))
        self.assertEqual(result["target_source"], "bitcode")

    def test_conditional_assertion_becomes_result_constraint(self):
        record, = self.extract("guarded_error")["records"]
        self.assertEqual(record["result"]["ret"], {"op": "==", "value": -1})
        self.assertEqual(record["result"]["errno"]["value"], 22)

    def test_errno_is_not_reused_after_opaque_call(self):
        record, = self.extract("stale_errno")["records"]
        self.assertEqual(record["result"], {"ret": {"op": "==", "value": -1}})

    def test_array_fields_stay_paired_and_default_zero_means_success(self):
        records = self.extract("table_pairs", "pidfd_open")["records"]
        self.assertEqual([record["args"] for record in records], [[-1, 0], [123, 1], [456, 0]])
        self.assertEqual([record["result"].get("errno", {}).get("value") for record in records], [22, 3, None])
        self.assertEqual(records[2]["result"], {"ret": {"op": ">=", "value": 0}})

    def test_unknown_inputs_are_filtered(self):
        self.assertEqual(self.extract("unknown_argument")["records"], [])

    def test_opaque_pointer_write_is_filtered(self):
        self.assertEqual(self.extract("opaque_pointer_write")["records"], [])

    def test_unsigned_flag_is_not_a_negative_json_number(self):
        record, = self.extract("unsigned_flag", "openat2")["records"]
        self.assertEqual(record["args"][2]["pointee"], {"flags": 1 << 63, "mode": 0, "resolve": 0})
        self.assertEqual(record["args"][3], 24)

    def test_loop_limit_filters_incomplete_analysis(self):
        result = self.extract("limited_loop", extra=("--loop-limit=2",))
        self.assertEqual(result["records"], [])
        self.assertEqual(result["functions"][0]["status"], "unsupported")

    def test_unsupported_control_filters_incomplete_analysis(self):
        result = self.extract("unsupported_control")
        self.assertEqual(result["records"], [])
        self.assertEqual(result["functions"][0]["status"], "unsupported")

    def test_errno_belongs_to_latest_call(self):
        first, second = self.extract("separate_calls")["records"]
        self.assertNotIn("errno", first["result"])
        self.assertEqual(second["result"]["errno"]["value"], 22)

    def test_reaching_assignment(self):
        record, = self.extract("reassignment")["records"]
        self.assertEqual(record["args"], [9, 0, 1])

    def test_all_functions_only_uses_original_source(self):
        result = subprocess.run(
            [str(EXTRACTOR), "--all-functions", str(self.artifact)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        names = {function["function"] for function in data["functions"]}
        self.assertIn("constant_error", names)
        self.assertNotIn("syscall", names)
        self.assertGreater(len(data["records"]), 1)

    def test_plain_preprocessed_input_falls_back_to_syscall_number(self):
        plain = self.artifact_dir / "plain"
        plain.mkdir()
        subprocess.run(
            [
                CLANG,
                "-save-temps=obj",
                "-c",
                str(ROOT / "tests/fixtures.c"),
                "-o",
                str(plain / "fixtures.o"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run(
            [str(EXTRACTOR), "--function=constant_error", str(plain / "fixtures.i")],
            capture_output=True,
            text=True,
            check=True,
        )
        record, = json.loads(result.stdout)["records"]
        self.assertEqual(record["syscall"], "number:438")


if __name__ == "__main__":
    unittest.main(verbosity=2)
