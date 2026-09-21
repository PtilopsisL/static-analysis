#!/usr/bin/env python3
"""The opt-in glibc profile must model only its declared ABI boundary."""
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

SOURCE = r"""
#define O_RDONLY 0
#define O_CREAT 0100
extern void test__fail(void);
#define EXPECT_OP(expected, seen, op) do { \
  __typeof__(expected) e = (expected);       \
  __typeof__(seen) s = (seen);               \
  if (!(e op s)) test__fail();               \
} while (0)
#define EXPECT_EQ(expected, seen) EXPECT_OP(expected, seen, ==)
#define EXPECT_GE(seen, minimum) EXPECT_OP(seen, minimum, >=)

extern int *__errno_location(void) __attribute__((const));
#define errno (*__errno_location())
extern int close(int);
extern int eventfd(unsigned, int);
extern int open(const char *, int, ...);
extern int ioctl(int, unsigned long, ...);

static void close_success(void) {
  int result = close(9);
  EXPECT_EQ(0, result);
}

static void renamed_eventfd(void) {
  int fd = eventfd(3, 0);
  EXPECT_GE(fd, 0);
}

static void open_nomode(void) {
  int fd = open("input", O_RDONLY);
  EXPECT_GE(fd, 0);
}

static void open_create(void) {
  int fd = open("created", O_CREAT, 0640);
  EXPECT_GE(fd, 0);
}

static void open_ignored_mode(void) {
  int fd = open("input", O_RDONLY, 0777);
  EXPECT_GE(fd, 0);
}

static void open_unknown_flags(int flags) {
  int fd = open("input", flags, 0600);
  EXPECT_GE(fd, 0);
}

static void ioctl_output_is_unknown(void) {
  int available = 0;
  int result = ioctl(9, 0x541b, &available);
  EXPECT_EQ(0, result);
  int fd = eventfd((unsigned)available, 0);
  EXPECT_GE(fd, 0);
}
"""

USER_DEFINITION = r"""
#define EXPECT_EQ(expected, seen) do { if ((expected) != (seen)) {} } while (0)
int close(int fd) { return fd; }
static void user_close(void) {
  int result = close(9);
  EXPECT_EQ(9, result);
}
"""

INCOMPATIBLE_DECLARATION = r"""
#define EXPECT_EQ(expected, seen) do { if ((expected) != (seen)) {} } while (0)
extern long close(long);
static void incompatible_close(void) {
  long result = close(9);
  EXPECT_EQ(0L, result);
}
"""


class LibcWrapperModelTests(unittest.TestCase):
    def setUp(self):
        if not EXTRACTOR.is_file():
            self.skipTest("build syscall-extract before running tests")
        if not CLANG:
            self.skipTest("clang is required")

    def extract(self, source, function, profile=None, target="x86_64-linux-gnu"):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            input_path = directory / "input.c"
            input_path.write_text(source)
            compdb = directory / "compile_commands.json"
            compdb.write_text(json.dumps([{
                "directory": str(directory),
                "file": str(input_path),
                "arguments": [CLANG, f"--target={target}", "-std=gnu11", "-c",
                              str(input_path), "-o", str(directory / "input.o")],
            }]))
            command = [str(EXTRACTOR), "--compdb", str(compdb),
                       "--function", function]
            if profile:
                command.extend(("--libc-profile", profile))
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

    def records(self, function, **options):
        return self.extract(SOURCE, function, **options)["records"]

    def test_profile_is_explicit(self):
        self.assertEqual(self.records("close_success"), [])
        data = self.extract(SOURCE, "close_success",
                            profile="glibc-linux-x86_64")
        self.assertEqual(data["libc_profile"], "glibc-linux-x86_64")
        self.assertEqual(data["records"], [{
            "syscall": "close", "args": [9],
            "result": {"ret": {"op": "==", "value": 0}},
        }])

    def test_profile_requires_matching_abi(self):
        self.assertEqual(self.records("close_success",
                                      profile="glibc-linux-x86_64",
                                      target="aarch64-linux-gnu"), [])

    def test_user_definition_is_not_replaced(self):
        data = self.extract(USER_DEFINITION, "user_close",
                            profile="glibc-linux-x86_64")
        self.assertEqual(data["records"], [])

    def test_incompatible_external_declaration_is_not_replaced(self):
        data = self.extract(INCOMPATIBLE_DECLARATION, "incompatible_close",
                            profile="glibc-linux-x86_64")
        self.assertEqual(data["records"], [])

    def test_renamed_wrapper(self):
        self.assertEqual(self.records("renamed_eventfd",
                                      profile="glibc-linux-x86_64"), [{
            "syscall": "eventfd2", "args": [3, 0],
            "result": {"ret": {"op": ">=", "value": 0}},
        }])

    def test_open_argument_transformations(self):
        expectations = {
            "open_nomode": [-100, "input", 0, 0],
            "open_create": [-100, "created", 64, 416],
            "open_ignored_mode": [-100, "input", 0, 0],
        }
        for function, arguments in expectations.items():
            with self.subTest(function=function):
                self.assertEqual(self.records(function,
                                              profile="glibc-linux-x86_64"), [{
                    "syscall": "openat", "args": arguments,
                    "result": {"ret": {"op": ">=", "value": 0}},
                }])

    def test_unknown_open_flags_are_not_guessed(self):
        self.assertEqual(self.records("open_unknown_flags",
                                      profile="glibc-linux-x86_64"), [])

    def test_output_invalidation_prevents_stale_followup(self):
        self.assertEqual(self.records("ioctl_output_is_unknown",
                                      profile="glibc-linux-x86_64"), [{
            "syscall": "ioctl", "args": [9, 21531, {"pointee": 0}],
            "result": {"ret": {"op": "==", "value": 0}},
        }])


if __name__ == "__main__":
    unittest.main(verbosity=2)
