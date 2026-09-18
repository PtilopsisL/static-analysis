#!/usr/bin/env python3
"""Regression checks for source analysis using compile_commands.json."""
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
            raise unittest.SkipTest("clang is required to analyze the fixture")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.build_dir = Path(cls.temporary.name)
        cls.compdb = cls.build_dir / "compile_commands.json"
        cls.compdb.write_text(json.dumps([{
            "directory": str(cls.build_dir),
            "file": str(ROOT / "tests/src/fixtures.c"),
            "arguments": [
                CLANG,
                "-DCOMPDB_PIDFD=17",
                "-c",
                str(ROOT / "tests/src/fixtures.c"),
                "-o",
                str(cls.build_dir / "fixtures.o"),
            ],
        }]))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def extract(self, function, syscall="pidfd_getfd", extra=()):
        command = [
            str(EXTRACTOR),
            f"--compdb={self.compdb}",
            f"--function={function}",
            f"--syscall={syscall}",
            *extra,
        ]
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
        self.assertEqual(result["source"], str(ROOT / "tests/src/fixtures.c"))
        self.assertEqual(result["compilation_unit"]["index"], 0)

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

    def test_loop_is_analyzed_by_clang(self):
        result = self.extract("limited_loop")
        self.assertEqual([record["args"][0] for record in result["records"]], list(range(5)))

    def test_general_control_flow_is_analyzed_by_clang(self):
        result = self.extract("unsupported_control")
        self.assertEqual(result["records"][0]["args"], [0, 0, 1])
        self.assertEqual(result["functions"][0]["status"], "extracted")

    def test_errno_belongs_to_latest_call(self):
        first, second = self.extract("separate_calls")["records"]
        self.assertNotIn("errno", first["result"])
        self.assertEqual(second["result"]["errno"]["value"], 22)

    def test_reaching_assignment(self):
        record, = self.extract("reassignment")["records"]
        self.assertEqual(record["args"], [9, 0, 1])

    def test_all_functions_only_uses_original_source(self):
        result = subprocess.run(
            [str(EXTRACTOR), f"--compdb={self.compdb}", "--all-functions"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        names = {function["function"] for function in data["functions"]}
        self.assertIn("constant_error", names)
        self.assertNotIn("syscall", names)
        self.assertGreater(len(data["records"]), 1)

    def test_command_is_preserved_in_output(self):
        result = self.extract("constant_error")
        self.assertEqual(result["compilation_unit"]["file"], str(ROOT / "tests/src/fixtures.c"))
        self.assertIn("-c", result["compilation_unit"]["command"])

    def test_real_command_line_defines_are_used(self):
        record, = self.extract("command_line_define")["records"]
        self.assertEqual(record["args"], [17, 0, 1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
