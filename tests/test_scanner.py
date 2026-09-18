#!/usr/bin/env python3
"""Compilation database scanning and process-isolation regression tests."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scan_artifacts import Runner, unit_status

EXTRACTOR = Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract"))
CLANG = os.environ.get("CLANG", shutil.which("clang-21") or shutil.which("clang"))


class StatusTests(unittest.TestCase):
    def test_extracted_wins_when_at_least_one_function_has_records(self):
        self.assertEqual(unit_status([{"status": "no_records"}, {"status": "extracted"}]), "extracted")

    def test_no_extracted_function_means_no_records(self):
        self.assertEqual(unit_status([{"status": "no_records"}]), "no_records")


class RunnerTests(unittest.TestCase):
    def run_fake(self, body, timeout=2, memory=256, output=1):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executable = directory / "fake-analyzer"
            executable.write_text("#!" + sys.executable + "\n" + body)
            executable.chmod(0o700)
            output_dir = directory / "output"
            output_dir.mkdir()
            source = directory / "source.c"
            source.write_text("void source(void) {}\n")
            compdb = directory / "compile_commands.json"
            compdb.write_text(json.dumps([{
                "directory": str(directory),
                "file": str(source),
                "arguments": ["clang", "-c", str(source)],
            }]))
            runner = Runner(executable, output_dir, timeout, memory, output)
            return runner.run(compdb, 0, output_dir / "unit")

    def test_timeout_is_classified(self):
        metadata, data = self.run_fake("import time\ntime.sleep(5)\n", timeout=0.15)
        self.assertIsNone(data)
        self.assertEqual(metadata["status"], "resource_limit")
        self.assertEqual(metadata["reason"], "wall_time_limit")

    def test_memory_limit_is_classified(self):
        metadata, data = self.run_fake("value = bytearray(512 * 1024 * 1024)\n", memory=128)
        self.assertIsNone(data)
        self.assertEqual(metadata["reason"], "address_space_limit")

    def test_parse_error_is_classified(self):
        metadata, data = self.run_fake(
            "import sys\nprint('source.i:1: error: invalid syntax', file=sys.stderr)\nsys.exit(1)\n"
        )
        self.assertIsNone(data)
        self.assertEqual(metadata["status"], "parse_failed")

    def test_output_limit_is_classified(self):
        metadata, data = self.run_fake("import os\nwhile True: os.write(1, b'x' * 65536)\n")
        self.assertIsNone(data)
        self.assertEqual(metadata["status"], "resource_limit")
        self.assertEqual(metadata["reason"], "output_size_limit")

    def test_crash_is_not_reported_as_parse_failure(self):
        metadata, data = self.run_fake("import os\nos.abort()\n")
        self.assertIsNone(data)
        self.assertEqual(metadata["status"], "analysis_failed")


class EndToEndTests(unittest.TestCase):
    def test_scan_reports_success_and_parse_failure(self):
        if not EXTRACTOR.is_file() or not CLANG:
            self.skipTest("built extractor and clang are required")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            broken = directory / "broken.c"
            broken.write_text("this is not valid C;\n")
            compdb = directory / "compile_commands.json"
            compdb.write_text(json.dumps([
                {
                    "directory": str(directory),
                    "file": str(ROOT / "tests/fixtures.c"),
                    "arguments": [CLANG, "-DCOMPDB_PIDFD=23", "-c", str(ROOT / "tests/fixtures.c"), "-o", str(directory / "fixtures-a.o")],
                },
                {
                    "directory": str(directory),
                    "file": str(ROOT / "tests/fixtures.c"),
                    "arguments": [CLANG, "-DCOMPDB_PIDFD=31", "-c", str(ROOT / "tests/fixtures.c"), "-o", str(directory / "fixtures-b.o")],
                },
                {
                    "directory": str(directory),
                    "file": str(broken),
                    "arguments": [CLANG, "-c", str(broken), "-o", str(directory / "broken.o")],
                },
            ]))
            output = directory / "scan"
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scan_artifacts.py"),
                    str(compdb),
                    "--extractor",
                    str(EXTRACTOR),
                    "--output",
                    str(output),
                    "--jobs",
                    "2",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = {
                row["index"]: row
                for row in map(json.loads, (output / "units.jsonl").read_text().splitlines())
            }
            self.assertEqual(set(rows), {0, 1, 2})
            self.assertEqual(rows[2]["status"], "parse_failed")
            self.assertEqual(rows[0]["status"], "extracted")
            self.assertEqual(rows[1]["status"], "extracted")
            functions = [json.loads(line) for line in (output / "functions.jsonl").read_text().splitlines()]
            self.assertTrue(any(row["function"] == "constant_error" for row in functions))
            records = [json.loads(line) for line in (output / "records.jsonl").read_text().splitlines()]
            self.assertTrue(any(record["syscall"] == "pidfd_getfd" for record in records))
            configured = {
                (record["unit_index"], record["args"][0])
                for record in records
                if record["args"] in ([23, 0, 1], [31, 0, 1])
            }
            self.assertEqual(configured, {(0, 23), (1, 31)})
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["compilation_units"], 3)
            self.assertEqual(summary["processed_units"], 3)
            self.assertEqual(sum(summary["unit_status_counts"].values()), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
