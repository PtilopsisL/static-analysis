"""Coverage, build-configuration and process-isolation regression tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from build_flags import Configuration, FlagResolver, StaticMake, sanitize_flags
from scan_selftests import Runner, aggregate_status, lexical_entries

KERNEL = Path(os.environ.get("LINUX_SOURCE", "/home/hengyul/linux"))
EXTRACTOR = Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract"))


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source_dir = self.root / "tools/testing/selftests/example"
        self.source_dir.mkdir(parents=True)

    def test_make_flags_and_target_specific_define(self):
        (self.source_dir / "Makefile").write_text(
            "BASE = -Iinclude -DCOUNT=7\nCFLAGS += $(BASE)\n"
            "ifeq ($(ARCH),x86_64)\nCFLAGS += -m64\nelse\nCFLAGS += -m32\nendif\n"
            "sample: CFLAGS += -DTHIS_TARGET\nother: CFLAGS += -DWRONG_TARGET\n")
        make = StaticMake(self.source_dir, {"ARCH": "x86_64"}, "sample")
        make.read(self.source_dir / "Makefile")
        flags = make.flags()
        self.assertIn("-DCOUNT=7", flags)
        self.assertIn("-m64", flags)
        self.assertIn("-DTHIS_TARGET", flags)
        self.assertNotIn("-m32", flags)
        self.assertNotIn("-DWRONG_TARGET", flags)

    def test_shell_expressions_are_never_executed(self):
        marker = self.root / "must-not-exist"
        (self.source_dir / "Makefile").write_text(f"CFLAGS += $(shell touch {marker}) -DSAFE\n")
        make = StaticMake(self.source_dir, {}, "sample")
        make.read(self.source_dir / "Makefile")
        flags, warnings = sanitize_flags(make.flags(), self.source_dir, self.source_dir / "sample.c")
        self.assertFalse(marker.exists())
        self.assertEqual(flags, ["-DSAFE"])
        self.assertTrue(warnings)
        self.assertIn("make function not evaluated: shell", make.warnings)

    def test_compile_database_preserves_variants_and_working_directory(self):
        source = self.source_dir / "sample.c"
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([
            {"directory": str(self.source_dir), "file": "sample.c",
             "arguments": ["cc", "-Iinclude", "-DVARIANT=1", "-c", "sample.c", "-o", "one.o"]},
            {"directory": str(self.source_dir), "file": "sample.c",
             "command": "cc -Iinclude -DVARIANT=2 -c sample.c -o two.o"},
        ]))
        configs = FlagResolver(self.root, [database]).resolve(source)
        self.assertEqual(len(configs), 2)
        self.assertEqual({c.origin for c in configs}, {"compile_commands"})
        self.assertIn("-I" + str(self.source_dir / "include"), configs[0].arguments)
        self.assertNotIn("-o", configs[0].arguments)
        self.assertNotEqual(configs[0].to_dict()["id"], configs[1].to_dict()["id"])

    def test_unsafe_frontend_options_are_not_loaded(self):
        flags, warnings = sanitize_flags(
            ["clang", "-Xclang", "-load", "-Xclang", "untrusted.so", "-fplugin=bad.so", "-DOK"],
            self.source_dir, self.source_dir / "sample.c")
        self.assertEqual(flags, ["-DOK"])
        self.assertTrue(warnings)

    def test_missing_include_is_reported(self):
        (self.source_dir / "Makefile").write_text("include generated.mk\nCFLAGS += -DOK\n")
        config, = FlagResolver(self.root).resolve(self.source_dir / "sample.c")
        self.assertIn("-DOK", config.arguments)
        self.assertTrue(any("make include missing" in message for message in config.warnings))

    def test_bpf_program_uses_bpf_flags_and_target(self):
        bpf = self.root / "tools/testing/selftests/bpf"
        (bpf / "progs").mkdir(parents=True)
        (bpf / "Makefile").write_text("CFLAGS += -DUSERSPACE_ONLY\nBPF_CFLAGS = -D__TARGET_ARCH_x86 -DBPF_PROGRAM\n")
        config, = FlagResolver(self.root).resolve(bpf / "progs/example.c")
        self.assertIn("-DBPF_PROGRAM", config.arguments)
        self.assertNotIn("-DUSERSPACE_ONLY", config.arguments)
        self.assertTrue(any(x in ("--target=bpfel", "--target=bpfeb") for x in config.arguments))


class DiscoveryTests(unittest.TestCase):
    def test_lexical_candidates_skip_comments_strings_and_definitions(self):
        text = ('// TEST(fake)\nconst char *s = "TEST(fake2)";\n'
                '#define GENERATED(x) \\\n TEST(x)\n'
                'TEST(actual) {}\nTEST_F(group, member) {}\n'
                '#if 0\nTEST(inactive) {}\n#endif\nint main(void) {}\n')
        entries = lexical_entries(text, "example.c")
        self.assertEqual([e["function"] for e in entries], ["actual", "group_member", "inactive", "main"])
        self.assertTrue(all(e["discovery"] == "lexical_candidate" for e in entries))

    def test_ast_discovery_excludes_generated_harness_helpers(self):
        path = KERNEL / "tools/testing/selftests/filesystems/openat2/openat2_test.c"
        command = [str(EXTRACTOR), "--discover", str(path), "--",
                   "-I" + str(KERNEL / "tools/testing/selftests"), "-I" + str(KERNEL / "tools/include")]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        names = {e["function"] for e in json.loads(result.stdout)["entries"]}
        self.assertEqual(names, {"openat2_struct_argument_sizes", "openat2_flag_validation",
                                "openat2_regular_flag", "legacy_openat_ignores_o_regular"})

    def test_opaque_libc_call_does_not_emit_a_record(self):
        path = KERNEL / "tools/testing/selftests/filesystems/openat2/openat2_test.c"
        command = [str(EXTRACTOR), "--function=legacy_openat_ignores_o_regular", str(path), "--",
                   "-I" + str(KERNEL / "tools/testing/selftests"), "-I" + str(KERNEL / "tools/include")]
        data = json.loads(subprocess.run(command, capture_output=True, text=True, check=True).stdout)
        self.assertEqual(data, {"records": []})

    def test_file_with_records_and_a_failed_entry_is_partial(self):
        self.assertEqual(aggregate_status([{"status": "extracted"}, {"status": "resource_limit"}], 1), "partial")


class RunnerTests(unittest.TestCase):
    def run_fake(self, body, timeout=2, memory=256, output=1):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executable = directory / "fake-analyzer"
            executable.write_text("#!" + sys.executable + "\n" + body)
            executable.chmod(0o700)
            runner = Runner(executable, directory, timeout, memory, output)
            return runner.run(directory / "source.c", Configuration(str(directory), [], "test"), directory / "artifact")

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
        metadata, data = self.run_fake("import sys\nprint('source.c:1: error: missing header', file=sys.stderr)\nsys.exit(1)\n")
        self.assertIsNone(data)
        self.assertEqual(metadata["status"], "parse_failed")

    def test_error_before_long_warning_tail_is_classified(self):
        metadata, data = self.run_fake("import sys\nprint('source.c:1: error: missing header', file=sys.stderr)\nprint('warning: unrelated note\\n' * 4000, file=sys.stderr)\nsys.exit(1)\n")
        self.assertIsNone(data)
        self.assertEqual(metadata["status"], "parse_failed")
        self.assertNotIn("error:", metadata["diagnostic_tail"])

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
    def test_inventory_keeps_success_parse_error_scripts_and_support_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "kernel/tools/testing/selftests/example"
            source.mkdir(parents=True)
            (source / "Makefile").write_text("CFLAGS += -DEXPECTED_FLAG=7\n")
            (source / "main.c").write_text("#if EXPECTED_FLAG != 7\n#error wrong flags\n#endif\nint main(void) { return 0; }\n")
            (source / "broken.c").write_text("#include <missing_test_header_xyz.h>\nTEST(unparsed) {}\n")
            (source / "script.py").write_text("raise Exception('must not execute')\n")
            (source / "helper.h").write_text("/* header */\n")
            output = directory / "scan"
            command = [sys.executable, "-B", str(ROOT / "scan_selftests.py"), "--kernel", str(directory / "kernel"),
                       "--extractor", str(EXTRACTOR), "--output", str(output), "--jobs", "2"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            files = {r["path"]: r for r in map(json.loads, (output / "files.jsonl").read_text().splitlines())}
            self.assertEqual(len(files), 5)
            self.assertEqual(files["example/main.c"]["tests"][0]["function"], "main")
            self.assertEqual(files["example/main.c"]["status"], "not_applicable")
            self.assertEqual(files["example/broken.c"]["status"], "parse_failed")
            self.assertEqual(files["example/broken.c"]["tests"][0]["function"], "unparsed")
            self.assertEqual(files["example/script.py"]["status"], "unsupported")
            self.assertEqual(files["example/helper.h"]["status"], "not_applicable")
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["inventory_files"], summary["processed_files"])
            self.assertEqual(sum(summary["file_status_counts"].values()), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
