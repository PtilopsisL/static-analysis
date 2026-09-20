"""Counterexamples that the independent wrapper oracle must reject."""
import copy
from pathlib import Path
import tempfile
import unittest

from compare import compare_records, compare_trace, matches, normalize_event, validate_layouts
from run import identity, load_contracts


def memory(kind, phases=1, size=0, **options):
    return {"type": "pointer", "memory": {"type": kind, "phases": phases, "size": size,
            "length_arg": 0, "limit_to_result": False, "nullable": False, "fields": [], **options}}


def layout(number, name, args, selector_arg=0, mask=0, value=0):
    return {"nr": number, "name": name,
            "args": [{"type": arg} if isinstance(arg, str) else arg for arg in args],
            "selector": {"arg": selector_arg, "mask": mask, "value": value}}


# Synthetic observations for comparator unit tests; not used by the runner.
LAYOUTS = [layout(3, "close", ["s32"]), layout(290, "eventfd2", ["u32", "s32"]),
           layout(257, "openat", ["s32", memory("cstring", size=256, nullable=True), "s32", "u32"]),
           layout(16, "ioctl", ["s32", "u32", memory("s32", phases=3)], 2, 0xFFFFFFFF, 21531)]


def event(number, args, result, snapshots=None):
    return {"nr": number, "args": args + [0] * (6 - len(args)),
            "raw_result": result, "is_error": -4095 <= result < 0,
            "snapshots": snapshots or {}}


def trace(events, results, layouts=LAYOUTS):
    return {"schema_version": 2, "arch": "x86_64", "complete": True, "layouts": copy.deepcopy(layouts),
            "errno_before": 123, "events": events,
            "returns": [{"slot": index, "ret": result, "errno": error}
                        for index, (result, error) in enumerate(results)]}


class ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contracts = load_contracts()

    def open_close(self):
        return trace([
            event(257, [0xFFFFFF9C, 0x123400, 0, 0], 5, {"1": {"before": "696e70757400"}}),
            event(3, [5], 0),
        ], [(5, 123), (0, 123)])

    def ioctl_followup(self):
        return trace([
            event(16, [9, 21531, 0x567800], 0, {"2": {"before": "00000000", "after": "03000000"}}),
            event(290, [3, 0], 5),
        ], [(0, 123), (5, 123)])

    def test_valid_fd_dependency_and_signed_dirfd(self):
        self.assertEqual(compare_trace(self.open_close(), self.contracts["probe_open_close"]), [])

    def test_unused_registers_and_upper_int_bits_are_not_arguments(self):
        observed = self.open_close()
        observed["events"][0]["args"][4:] = [123, 456]
        observed["events"][1]["args"][0] |= 0xFEDCBA98 << 32
        self.assertEqual(compare_trace(observed, self.contracts["probe_open_close"]), [])

    def test_pointer_address_does_not_replace_content(self):
        observed = self.open_close()
        observed["events"][0]["args"][1] += 4096
        self.assertEqual(compare_trace(observed, self.contracts["probe_open_close"]), [])
        observed["events"][0]["snapshots"]["1"]["before"] = "77726f6e6700"
        self.assertTrue(compare_trace(observed, self.contracts["probe_open_close"]))

    def test_wrong_syscall_cannot_match(self):
        observed = self.open_close()
        observed["events"][0]["nr"] = 2  # open, not openat
        with self.assertRaisesRegex(ValueError, "unknown or ambiguous"):
            compare_trace(observed, self.contracts["probe_open_close"])

    def test_extra_and_missing_syscalls_cannot_match(self):
        for remove in (False, True):
            with self.subTest(remove=remove):
                observed = self.open_close()
                if remove:
                    observed["events"].pop()
                else:
                    observed["events"].append(event(3, [-1 & 0xFFFFFFFF], -9))
                self.assertTrue(compare_trace(observed, self.contracts["probe_open_close"]))

    def test_wrong_fd_dependency_cannot_match(self):
        observed = self.open_close()
        observed["events"][1]["args"][0] = 9
        self.assertTrue(compare_trace(observed, self.contracts["probe_open_close"]))

    def test_wrapper_must_return_the_kernel_fd(self):
        observed = self.open_close()
        observed["returns"][0]["ret"] = 6
        self.assertTrue(compare_trace(observed, self.contracts["probe_open_close"]))

    def test_dropped_creation_mode_cannot_match(self):
        observed = trace([event(257, [0xFFFFFF9C, 0x1000, 193, 416], 5,
                                     {"1": {"before": "6372656174656400"}})], [(5, 123)])
        contract = self.contracts["probe_open_create"]
        self.assertEqual(compare_trace(observed, contract), [])
        observed["events"][0]["args"][3] = 0
        self.assertTrue(compare_trace(observed, contract))

    def test_unnecessary_mode_must_be_ignored(self):
        observed = self.open_close()
        observed["events"] = observed["events"][:1]
        observed["returns"] = observed["returns"][:1]
        contract = self.contracts["probe_open_ignored_mode"]
        self.assertEqual(compare_trace(observed, contract), [])
        observed["events"][0]["args"][3] = 0o777
        self.assertTrue(compare_trace(observed, contract))

    def test_success_does_not_clear_errno_in_these_wrappers(self):
        observed = self.open_close()
        observed["returns"][0]["errno"] = 0
        self.assertTrue(compare_trace(observed, self.contracts["probe_open_close"]))

    def test_kernel_error_is_distinct_from_libc_return(self):
        observed = trace([event(3, [0xFFFFFFFF], -9)], [(-1, 9)])
        contract = self.contracts["probe_close_failure"]
        self.assertEqual(compare_trace(observed, contract), [])
        observed["returns"][0]["ret"] = -9
        self.assertTrue(compare_trace(observed, contract))

    def test_inconsistent_error_flag_is_invalid(self):
        observed = event(3, [0xFFFFFFFF], -9)
        observed["is_error"] = False
        with self.assertRaises(ValueError):
            normalize_event(observed, LAYOUTS)

    def test_stale_output_cannot_match(self):
        observed = self.ioctl_followup()
        contract = self.contracts["probe_ioctl_followup"]
        self.assertEqual(compare_trace(observed, contract), [])
        observed["events"][1]["args"][0] = 0
        self.assertTrue(compare_trace(observed, contract))

    def test_entry_and_exit_memory_are_distinct(self):
        observed = self.ioctl_followup()
        observed["events"][0]["snapshots"]["2"] = {"before": "03000000", "after": "00000000"}
        self.assertTrue(compare_trace(observed, self.contracts["probe_ioctl_followup"]))

    def test_incomplete_memory_snapshot_is_not_a_pass(self):
        observed = self.ioctl_followup()
        del observed["events"][0]["snapshots"]["2"]["after"]
        with self.assertRaises(ValueError):
            compare_trace(observed, self.contracts["probe_ioctl_followup"])

    def test_incomplete_or_wrong_abi_trace_is_not_empty_success(self):
        for field, value in (("complete", False), ("arch", "aarch64")):
            with self.subTest(field=field):
                observed = trace([], [(42, 123)])
                observed[field] = value
                self.assertTrue(compare_trace(observed, self.contracts["probe_no_syscall"]))

    def test_explicit_empty_trace_control(self):
        self.assertEqual(compare_trace(trace([], [(42, 123)]), self.contracts["probe_no_syscall"]), [])

    def test_missing_positive_static_records_is_failure(self):
        self.assertTrue(compare_records([], self.contracts["probe_eventfd"]["records"]))

    def test_one_successful_witness_does_not_validate_a_weaker_predicate(self):
        expected = self.contracts["probe_eventfd"]["records"]
        weaker = copy.deepcopy(expected)
        weaker[0]["result"]["ret"]["value"] = -100
        self.assertTrue(compare_records(weaker, expected))

    def test_stale_static_record_and_duplicate_are_rejected(self):
        expected = self.contracts["probe_ioctl_followup"]["records"]
        stale = copy.deepcopy(self.contracts["probe_eventfd"]["records"][0])
        stale["args"][0] = 0
        self.assertTrue(compare_records([*expected, stale], expected))
        self.assertTrue(compare_records(expected * 2, expected))


class GenericLayoutTests(unittest.TestCase):
    def decode(self, observed, description):
        validate_layouts([description])
        return normalize_event(observed, [description])

    def test_new_number_and_all_scalar_widths(self):
        desc = layout(123456, "synthetic", ["s32", "u32", "s64", "u64", "pointer"])
        observed = event(123456, [2**64 - 1] * 5, 0)
        self.assertEqual(self.decode(observed, desc)["args"], [-1, 2**32 - 1, -1, 2**64 - 1, 2**64 - 1])

    def test_binary_buffer_length_from_argument(self):
        desc = layout(123456, "synthetic", [memory("bytes", length_arg=2), "u32"])
        observed = event(123456, [0x1000, (99 << 32) | 3], 3, {"0": {"before": "00ff61"}})
        self.assertEqual(self.decode(observed, desc)["args"], [{"before": {"hex": "00ff61"}}, 3])
        observed["snapshots"]["0"]["before"] = "00ff"
        with self.assertRaisesRegex(ValueError, "snapshot size"):
            self.decode(observed, desc)

    def test_output_buffer_uses_actual_returned_length_including_errors(self):
        desc = layout(123456, "synthetic", [memory("bytes", phases=3, length_arg=2, limit_to_result=True), "u64"])
        observed = event(123456, [0x1000, 4], 2, {"0": {"before": "00000000", "after": "6162"}})
        self.assertEqual(self.decode(observed, desc)["args"][0],
                         {"before": {"hex": "00000000"}, "after": {"hex": "6162"}})
        for result in (-9, 0, 6):
            size = min(4, max(0, result))
            observed = event(123456, [0x1000, 4], result,
                             {"0": {"before": "00000000", "after": "61" * size}})
            self.decode(observed, desc)

    def test_fixed_struct_fields_offsets_and_padding(self):
        fields = [{"name": "count", "type": "s32", "offset": 0, "size": 0},
                  {"name": "tag", "type": "bytes", "offset": 6, "size": 2}]
        desc = layout(123456, "synthetic", [memory("struct", phases=2, size=8, fields=fields)])
        observed = event(123456, [0x1000], 0, {"0": {"after": "ffffffffabcd00ff"}})
        value = self.decode(observed, desc)["args"][0]
        self.assertEqual(value, {"after": {"count": -1, "tag": {"hex": "00ff"}}})
        self.assertTrue(matches(value, {"after": {"count": {"ref": "n"}, "tag": {"hex": "00ff"}}}, {"n": -1}))
        fields[0]["offset"] = 7
        with self.assertRaisesRegex(ValueError, "struct field"):
            self.decode(observed, desc)

    def test_nullable_pointer_does_not_invent_a_buffer(self):
        desc = layout(123456, "synthetic", [memory("s32", phases=3, nullable=True)])
        observed = event(123456, [0], -14, {"0": {"before": None, "after": None}})
        self.assertEqual(self.decode(observed, desc)["args"], [0])
        observed["args"][0] = 0x1000
        with self.assertRaisesRegex(ValueError, "byte snapshot"):
            self.decode(observed, desc)
        observed["args"][0] = 0
        observed["snapshots"]["0"]["before"] = "00000000"
        with self.assertRaisesRegex(ValueError, "null pointer"):
            self.decode(observed, desc)

    def test_selector_uses_observed_register_not_expected_values(self):
        descriptions = [layout(123456, "one", ["u32"], 1, 0xFFFFFFFF, 1),
                        layout(123456, "two", ["u32"], 1, 0xFFFFFFFF, 2)]
        validate_layouts(descriptions)
        observed = event(123456, [(99 << 32) | 2], 0)
        self.assertEqual(normalize_event(observed, descriptions)["syscall"], "two")
        observed["args"][0] = 3
        with self.assertRaisesRegex(ValueError, "unknown or ambiguous"):
            normalize_event(observed, descriptions)
        with self.assertRaisesRegex(ValueError, "unknown or ambiguous"):
            normalize_event(event(123456, [1], 0), descriptions * 2)

    def test_missing_extra_and_corrupt_snapshots_are_errors(self):
        desc = layout(123456, "synthetic", [memory("s32", phases=3)])
        for snapshots in ({}, {"0": {"before": "00000000"}},
                          {"0": {"before": "00000000", "after": "000000"}},
                          {"0": {"before": "00000000", "after": "not hex"}},
                          {"0": {"before": "00000000", "after": "00000000"}, "1": {}}):
            with self.subTest(snapshots=snapshots), self.assertRaises(ValueError):
                self.decode(event(123456, [0x1000], 0, snapshots), desc)

    def test_bad_strings_are_not_silently_truncated(self):
        desc = layout(123456, "synthetic", [memory("cstring", size=4)])
        for encoded in ("", "6162", "61006200", "6162636400", "ff00"):
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                self.decode(event(123456, [0x1000], 0, {"0": {"before": encoded}}), desc)

    def test_invalid_dynamic_layout_is_rejected(self):
        for desc in (layout(123456, "bad", [memory("bytes", length_arg=2), "s32"]),
                     layout(123456, "bad", [memory("cstring", size=4, length_arg=2), "u32"]),
                     layout(123456, "bad", [memory("bytes", phases=4)])):
            with self.subTest(desc=desc), self.assertRaises(ValueError):
                validate_layouts([desc])

    def test_three_results_and_missing_middle_slot(self):
        observed = trace([], [(1, 123), (2, 123), (3, 123)], layouts=[])
        contract = {"events": [], "returns": [{"ret": n, "errno": 123} for n in (1, 2, 3)], "records": []}
        self.assertEqual(compare_trace(observed, contract), [])
        observed["returns"].pop(1)
        self.assertTrue(compare_trace(observed, contract))


class IdentityTests(unittest.TestCase):
    def test_pinned_libc_and_interposed_symbol_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            library = Path(temporary) / "libc.so.6"
            library.write_bytes(b"test identity only, not an executable")
            observed = {"arch": "x86_64", "libc_version": "fixture",
                        "libc_path": str(library),
                        "loaded_objects": [str(library)],
                        "symbols": {"new_wrapper": str(library)}}
            profile = identity(observed, ["new_wrapper"])
            self.assertEqual(identity(observed, ["new_wrapper"], profile["libc_sha256"]), profile)
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                identity(observed, ["new_wrapper"], "0" * 64)
            with self.assertRaisesRegex(ValueError, "declared tested symbols"):
                identity(observed, ["omitted_wrapper"])
            empty = {**observed, "symbols": {}}
            self.assertEqual(identity(empty, [])["libc_sha256"], profile["libc_sha256"])
            other = Path(temporary) / "override.so"
            other.write_bytes(b"different identity")
            observed["symbols"]["new_wrapper"] = str(other)
            with self.assertRaisesRegex(ValueError, "identified libc"):
                identity(observed, ["new_wrapper"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
