"""An unavailable observer or missing analyzer records must never pass a run."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run
from test_comparison import LAYOUTS, event, trace


def description():
    return {"schema_version": 2, "arch": "x86_64", "layouts": LAYOUTS, "probes": [
        {"name": "probe_direct_close", "symbols": ["syscall"], "result_count": 1,
         "event_limit": 64, "snapshot_limit": 4096}]}


class RunnerStatusTests(unittest.TestCase):
    def exercise(self, runtime, analysis=None):
        observed = trace([event(3, [0xFFFFFFFF], -9)], [(-1, 9)])
        observed["probe"] = "probe_direct_close"

        def build(directory, compiler, timeout):
            directory.mkdir()
            executable = directory / "observer"
            executable.write_bytes(b"fake observer used only with mocked processes")
            return executable, directory / "compile_commands.json"

        def process(command, directory, timeout):
            is_analysis = command[0] == "fake-extractor"
            body = analysis if is_analysis else observed
            return {"command": command, "returncode": 0 if is_analysis else runtime,
                    "timed_out": False, "stderr": "denied" if runtime else "",
                    "stdout": json.dumps(body)}

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(run, "build", side_effect=build), \
                patch.object(run, "process", side_effect=process), \
                patch.object(run, "checked_process", return_value={"stdout": "fake clang"}), \
                patch.object(run, "describe", side_effect=lambda *args: description()), \
                patch.object(run, "identity", side_effect=lambda *args: {"libc_sha256": "test", "symbols": {}}), \
                patch.object(run.platform, "system", return_value="Linux"), \
                patch.object(run.platform, "machine", return_value="x86_64"), \
                redirect_stdout(io.StringIO()):
            output = Path(temporary) / "results"
            contracts = {"probe_direct_close": run.load_contracts()["probe_direct_close"]}
            report = run.run_suite(output, "fake-clang", contracts,
                                   extractor=Path("fake-extractor") if analysis is not None else None)
            self.assertEqual(json.loads((output / "summary.json").read_text()), report)
            return report

    def test_ptrace_failure_is_an_error_not_a_skip_or_pass(self):
        report = self.exercise(runtime=1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["runtime_counts"], {"error": 1})
        self.assertEqual(report["analysis_counts"], {"not_run": 1})

    def test_runtime_only_is_explicitly_distinguished(self):
        report = self.exercise(runtime=0)
        self.assertEqual(report["status"], "runtime_only_passed")
        self.assertFalse(report["analysis_requested"])

    def test_requested_positive_analysis_cannot_pass_with_empty_records(self):
        report = self.exercise(runtime=0, analysis={
            "schema_version": 2, "functions": [{"function": "probe_direct_close"}], "records": []})
        self.assertEqual(report["runtime_counts"], {"passed": 1})
        self.assertEqual(report["analysis_counts"], {"mismatch": 1})
        self.assertEqual(report["status"], "failed")

    def test_no_selected_cases_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = run.run_suite(Path(temporary) / "results", "unused", {})
        self.assertEqual(report["status"], "error")

    def test_unregistered_or_uncontracted_probe_cannot_pass(self):
        contract = run.load_contracts()["probe_direct_close"]
        for contracts in ({}, {"probe_other": contract}, {"probe_direct_close": contract, "probe_other": contract}):
            with self.subTest(contracts=list(contracts)), self.assertRaisesRegex(ValueError, "registration mismatch"):
                run.validate_description(description(), contracts)

    def test_result_count_must_match_contract(self):
        desc = description()
        desc["probes"][0]["result_count"] = 2
        with self.assertRaisesRegex(ValueError, "result_count"):
            run.validate_description(desc, {"probe_direct_close": run.load_contracts()["probe_direct_close"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
