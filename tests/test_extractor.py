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

    def test_compound_constraints_keep_the_stronger_bound(self):
        record, = self.extract("compound_constraint_strengthening")["records"]
        self.assertEqual(record["args"], [600, 0, 0])
        self.assertEqual(record["result"], {"ret": {"op": ">=", "value": 1}})

    def test_unrepresentable_range_is_not_weakened(self):
        self.assertEqual(self.extract("unrepresentable_range")["records"], [])

    def test_unconstrained_success_alternative_emits_nothing(self):
        self.assertEqual(self.extract("unconstrained_success_alternative")["records"], [])

    def test_reassigned_predicate_does_not_reuse_initializer(self):
        self.assertEqual(self.extract("reassigned_predicate_variable")["records"], [])

    def test_plain_exp_seen_names_are_not_an_assertion(self):
        self.assertEqual(self.extract("assertion_temporary_lookalike")["records"], [])

    def test_nested_possible_failure_is_not_a_definite_failure_guard(self):
        self.assertEqual(self.extract("nested_possible_failure")["records"], [])

    def test_unmodeled_syscall_invalidates_errno_owner(self):
        record, = self.extract("unmodeled_syscall_number")["records"]
        self.assertEqual(record["args"], [606, 0, 0])
        self.assertEqual(record["result"], {"ret": {"op": "==", "value": -1}})

    def test_signedness_changing_cast_is_not_reinterpreted(self):
        self.assertEqual(self.extract("unsigned_cast_ordering")["records"], [])

    def test_subcondition_of_failure_guard_is_not_treated_as_full_guard(self):
        self.assertEqual(self.extract("compound_failure_condition")["records"], [])

    def test_no_success_condition_when_both_branches_fail(self):
        self.assertEqual(self.extract("both_branches_fail")["records"], [])

    def test_later_assignment_does_not_erase_an_earlier_assertion(self):
        record, = self.extract("predicate_reassigned_after_assertion")["records"]
        self.assertEqual(record["args"], [610, 0, 0])
        self.assertEqual(record["result"], {"ret": {"op": "==", "value": 0}})

    def test_cfg_proves_failure_after_nested_control_flow(self):
        record, = self.extract("definite_failure_via_cfg")["records"]
        self.assertEqual(record["args"], [611, 0, 0])
        self.assertEqual(record["result"], {"ret": {"op": "==", "value": 0}})

    def test_opaque_write_invalidates_predicate_provenance(self):
        self.assertEqual(
            self.extract("predicate_invalidated_by_opaque_write")["records"], []
        )

    def test_unknown_noreturn_is_not_a_failure_oracle(self):
        self.assertEqual(
            self.extract("unknown_noreturn_is_not_failure")["records"], []
        )

    def test_predicate_assignment_tracks_the_new_value(self):
        record, = self.extract("predicate_assignment_tracks_new_value")["records"]
        self.assertEqual(record["args"], [614, 0, 0])
        self.assertEqual(record["result"], {"ret": {"op": "==", "value": 0}})

    def test_unrepresentable_intermediate_domain_can_be_refined(self):
        record, = self.extract("domain_refinement_becomes_projectable")["records"]
        self.assertEqual(record["args"], [615, 0, 0])
        self.assertEqual(record["result"], {"ret": {"op": "==", "value": 5}})

    def test_clang_path_constraint_is_the_primary_domain(self):
        record, = self.extract("clang_path_constraint_strengthens_assertion")[
            "records"
        ]
        self.assertEqual(record["args"], [616, 0, 0])
        self.assertEqual(record["result"], {"ret": {"op": ">=", "value": 1}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
