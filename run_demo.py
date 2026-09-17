#!/usr/bin/env python3
"""Extract compact syscall inputs and result constraints from Linux selftests."""
import argparse
import errno
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
CASES = [
    ("pidfd/pidfd_getfd_test.c", "flags_set", "pidfd_getfd"),
    ("filesystems/openat2/openat2_test.c", "openat2_flag_validation", "openat2"),
]


def add_errno_name(record):
    constraint = record.get("result", {}).get("errno")
    if constraint and isinstance(constraint.get("value"), int):
        name = errno.errorcode.get(constraint["value"])
        if name:
            constraint["name"] = name


def result_text(record):
    parts = []
    for field in ("ret", "errno"):
        constraint = record["result"].get(field)
        if constraint:
            value = constraint.get("name", constraint["value"])
            parts.append(f"{field} {constraint['op']} {value}")
    return " and ".join(parts)


def analyze(extractor, kernel, source, function, syscall, extra=()):
    command = [str(extractor), f"--function={function}", f"--syscall={syscall}",
               *extra, str(source), "--", "-std=gnu11",
               f"-I{kernel / 'tools/testing/selftests'}", f"-I{kernel / 'tools/include'}"]
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode:
        raise RuntimeError(f"Analyzer failed ({proc.returncode}):\n{proc.stderr}")
    result = json.loads(proc.stdout)
    for record in result["records"]:
        add_errno_name(record)
    return result


def make_report(records):
    lines = ["# syscall 静态提取结果", "",
             "结果来自源码断言；分析过程没有执行 syscall 或 selftest。", "",
             "| syscall 输入 | 结果约束 |", "|---|---|"]
    for record in records:
        args = json.dumps(record["args"], ensure_ascii=False, separators=(",", ":"))
        call = f"{record['syscall']}({args[1:-1]})"
        lines.append(f"| `{call}` | `{result_text(record)}` |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--extractor", type=Path, default=ROOT / "build/syscall-extract")
    parser.add_argument("--output", type=Path, default=ROOT / "out")
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    records = []
    seen = set()
    for relative, function, syscall in CASES:
        source = kernel / "tools/testing/selftests" / relative
        for record in analyze(args.extractor.resolve(), kernel, source, function, syscall)["records"]:
            key = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if key not in seen:
                seen.add(key)
                records.append(record)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "dataset.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n")
    (args.output / "report.md").write_text(make_report(records))
    print(f"Extracted {len(records)} concrete records.")
    print(f"Dataset: {args.output.resolve() / 'dataset.json'}")
    print(f"Report:  {args.output.resolve() / 'report.md'}")


if __name__ == "__main__":
    main()
