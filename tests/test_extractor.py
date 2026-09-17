#!/usr/bin/env python3
"""Regression checks for incorrect labels, plus unmodified kernel integration."""
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from run_demo import analyze

KERNEL = Path(os.environ.get("LINUX_SOURCE", "/home/hengyul/linux"))
EXTRACTOR = Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract"))


class ExtractionTests(unittest.TestCase):
    def extract(self, function, syscall="pidfd_getfd", extra=()):
        return analyze(EXTRACTOR, KERNEL, ROOT / "tests/fixtures.c", function, syscall, extra)

    def test_constant_error(self):
        result = self.extract("constant_error")
        record, = result["records"]
        self.assertEqual(set(record), {"syscall", "args", "result"})
        self.assertEqual(record["args"], [0, 0, 1])
        self.assertEqual(record["result"], {
            "ret": {"op": "==", "value": -1},
            "errno": {"op": "==", "value": 22, "name": "EINVAL"},
        })

    def test_conditional_assertion_becomes_result_constraint(self):
        record, = self.extract("guarded_error")["records"]
        self.assertEqual(record["result"]["ret"], {"op": "==", "value": -1})
        self.assertEqual(record["result"]["errno"]["name"], "EINVAL")

    def test_errno_is_not_reused_after_opaque_call(self):
        record, = self.extract("stale_errno")["records"]
        self.assertEqual(record["result"], {"ret": {"op": "==", "value": -1}})

    def test_array_fields_stay_paired_and_default_zero_means_success(self):
        result = self.extract("table_pairs", "pidfd_open")
        records = result["records"]
        self.assertEqual([r["args"] for r in records], [[-1, 0], [123, 1], [456, 0]])
        self.assertEqual([r["result"].get("errno", {}).get("name") for r in records],
                         ["EINVAL", "ESRCH", None])
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

    def test_unsupported_control_filters_incomplete_analysis(self):
        result = self.extract("unsupported_control")
        self.assertEqual(result["records"], [])

    def test_errno_belongs_to_latest_call(self):
        first, second = self.extract("separate_calls")["records"]
        self.assertNotIn("errno", first["result"])
        self.assertEqual(second["result"]["errno"]["name"], "EINVAL")

    def test_reaching_assignment(self):
        record, = self.extract("reassignment")["records"]
        self.assertEqual(record["args"], [9, 0, 1])

    def test_unmodified_pidfd_test(self):
        path = KERNEL / "tools/testing/selftests/pidfd/pidfd_getfd_test.c"
        result = analyze(EXTRACTOR, KERNEL, path, "flags_set", "pidfd_getfd")
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["args"], [0, 0, 1])
        self.assertEqual(result["records"][0]["result"]["errno"]["name"], "EINVAL")

    def test_unmodified_openat2_table(self):
        path = KERNEL / "tools/testing/selftests/filesystems/openat2/openat2_test.c"
        result = analyze(EXTRACTOR, KERNEL, path, "openat2_flag_validation", "openat2")
        records = result["records"]
        self.assertEqual(len(records), 25)
        self.assertTrue(all(set(r) == {"syscall", "args", "result"} for r in records))
        normal = [r["result"] for r in records]
        self.assertEqual(sum(n.get("errno", {}).get("name") == "EINVAL" for n in normal), 20)
        self.assertEqual(sum(n == {"ret": {"op": ">=", "value": 0}} for n in normal), 5)
        self.assertEqual(records[-1]["args"][2]["pointee"]["flags"], 1 << 63)


if __name__ == "__main__":
    unittest.main(verbosity=2)
