#!/usr/bin/env python3
"""Inventory Linux selftests, discover entries and report every analysis outcome."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import errno
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

from build_flags import FlagResolver

ROOT = Path(__file__).resolve().parent
STATUS_TEXT = {
    "extracted": "已提取（所选函数内未发现已知缺口）", "partial": "部分提取",
    "unsupported": "不支持 / 未识别入口", "parse_failed": "解析失败",
    "resource_limit": "资源超限", "analysis_failed": "分析器失败",
    "not_applicable": "非独立分析对象", "inactive_configuration": "不在当前预处理配置中",
}
TEST_MACROS = r"TEST_F_TIMEOUT|TEST_F_SIGNAL|TEST_SIGNAL|TEST_F|TEST"


def mask_c_text(text):
    pattern = r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    text = re.sub(pattern, lambda m: re.sub(r"[^\n]", " ", m.group()), text)
    # A macro definition is not an invocation; suppress whole continued directives.
    return re.sub(r"(?m)^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", lambda m: re.sub(r"[^\n]", " ", m.group()), text)


def lexical_entries(text, relative):
    """Fallback candidates only, including inactive #if branches; never claim AST proof."""
    masked = mask_c_text(text)
    entries = []
    for match in re.finditer(r"\b(" + TEST_MACROS + r")\s*\(\s*([A-Za-z_]\w*)\s*(?:,\s*([A-Za-z_]\w*))?", masked):
        macro, first, second = match.groups()
        if macro.startswith("TEST_F"):
            if not second: continue
            name = first + "_" + second
        else: name = first
        entries.append({"function": name, "framework": "kselftest_harness", "macro": macro,
                        "source": {"file": relative, "line": masked.count("\n", 0, match.start()) + 1},
                        "discovery": "lexical_candidate"})
    for match in re.finditer(r"\bmain\s*\([^;{}]*\)\s*\{", masked):
        entries.append({"function": "main", "framework": "main", "macro": "",
                        "source": {"file": relative, "line": masked.count("\n", 0, match.start()) + 1},
                        "discovery": "lexical_candidate"})
    if relative.startswith("bpf/prog_tests/"):
        for match in re.finditer(r"\bvoid\s+((?:serial_)?test_\w+)\s*\(\s*(?:void)?\s*\)\s*\{", masked):
            entries.append({"function": match.group(1), "framework": "bpf_test_progs", "macro": "",
                            "source": {"file": relative, "line": masked.count("\n", 0, match.start()) + 1},
                            "discovery": "lexical_candidate"})
    unique = {}
    for entry in entries: unique[(entry["function"], entry["source"]["line"])] = entry
    return list(unique.values())


def file_language(path):
    if path.is_symlink(): return "symlink"
    if path.suffix == ".c": return "c"
    if path.suffix in {".cc", ".cpp", ".cxx"}: return "c++"
    if path.suffix in {".h", ".hpp"}: return "header"
    if path.suffix in {".S", ".s"}: return "assembly"
    if path.suffix in {".sh", ".bash"}: return "shell"
    if path.suffix == ".py": return "python"
    if path.suffix == ".pkt": return "packetdrill"
    if not path.suffix:
        try:
            with path.open("rb") as stream: first = stream.read(128)
            if first.startswith(b"#!"): return "script"
        except OSError: pass
    return "support_file"


def aggregate_status(tests, records=0):
    statuses = {t["status"] for t in tests}
    relevant = statuses - {"not_applicable", "inactive_configuration"}
    if records:
        return "extracted" if relevant == {"extracted"} else "partial"
    for status in ("resource_limit", "analysis_failed", "parse_failed", "unsupported", "partial"):
        if status in relevant: return status
    return "not_applicable"


class Runner:
    def __init__(self, extractor, output, timeout, memory_mb, output_mb):
        self.extractor = Path(extractor).resolve()
        self.output = Path(output).resolve()
        self.timeout, self.memory_mb, self.output_mb = timeout, memory_mb, output_mb
        self.lock = threading.Lock()
        self.active = set()
        self.stopping = threading.Event()

    def stop(self):
        self.stopping.set()
        with self.lock:
            for process in self.active:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass

    def run(self, source, config, artifact_dir, function=None):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_path, error_path = artifact_dir / "output.json", artifact_dir / "stderr.txt"
        selector = [f"--function={function}"] if function else ["--discover"]
        command = [str(self.extractor), *selector, str(source), "--", *config.arguments]
        wrapper = [sys.executable, "-B", str(ROOT / "limit_worker.py"),
                   "--memory-mb", str(self.memory_mb), "--output-mb", str(self.output_mb),
                   "--cpu-seconds", str(self.timeout), "--", *command]
        metadata = {"command": command, "directory": config.directory,
                    "output": str(output_path.relative_to(self.output)),
                    "stderr": str(error_path.relative_to(self.output))}
        started = time.monotonic()
        if self.stopping.is_set(): return {**metadata, "status": "analysis_failed", "reason": "scan_interrupted"}, None
        try:
            with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
                process = subprocess.Popen(wrapper, cwd=config.directory, stdout=stdout, stderr=stderr,
                                           start_new_session=True)
                with self.lock: self.active.add(process)
                try:
                    code = process.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                    metadata.update(status="resource_limit", reason="wall_time_limit")
                    code = process.returncode
                finally:
                    with self.lock: self.active.discard(process)
            metadata.update(returncode=code, elapsed_seconds=round(time.monotonic()-started, 3))
            # Keep full bounded logs on disk, and a small tail in the coverage manifest.
            memory_error = compiler_error = False
            with error_path.open("rb") as stream:
                # Classify the entire log: later warnings can push the actual
                # error out of the short diagnostic tail saved in the manifest.
                carry = b""
                for chunk in iter(lambda: stream.read(65536), b""):
                    diagnostic = carry + chunk
                    memory_error |= bool(re.search(rb"out of memory|bad_alloc|cannot allocate memory|failed to map segment|memoryerror", diagnostic, re.I))
                    compiler_error |= bool(re.search(rb"(?:fatal )?error:", diagnostic))
                    carry = diagnostic[-128:]
                stream.seek(max(0, error_path.stat().st_size-6000))
                error = stream.read().decode(errors="replace")
            if error: metadata["diagnostic_tail"] = error
            if "status" in metadata: return metadata, None
            if code:
                if code in (-signal.SIGXCPU, -signal.SIGXFSZ) or max(output_path.stat().st_size, error_path.stat().st_size) >= self.output_mb * 1024**2:
                    reason = "cpu_time_limit" if code == -signal.SIGXCPU else "output_size_limit"
                    metadata.update(status="resource_limit", reason=reason)
                elif memory_error:
                    metadata.update(status="resource_limit", reason="address_space_limit")
                elif code > 0 and compiler_error:
                    metadata.update(status="parse_failed", reason="compiler_diagnostics")
                else:
                    metadata.update(status="analysis_failed", reason="analyzer_exit")
                return metadata, None
            try:
                data = json.loads(output_path.read_text())
            except (ValueError, OSError) as error:
                metadata.update(status="analysis_failed", reason="invalid_analyzer_json", detail=str(error))
                return metadata, None
            metadata.update(status="ok")
            return metadata, data
        except (OSError, ValueError) as error:
            metadata.update(status="analysis_failed", reason="process_launch_failed", detail=str(error),
                            elapsed_seconds=round(time.monotonic()-started, 3))
            return metadata, None


def scan_c_file(path, relative, resolver, runner):
    text = path.read_text(errors="replace")
    candidates = lexical_entries(text, relative)
    result = {"path": relative, "language": "c", "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "lexical_candidates": candidates, "configurations": [], "tests": [], "record_count": 0}
    file_id = hashlib.sha256(relative.encode()).hexdigest()[:16]
    for config in resolver.resolve(path):
        info = config.to_dict()
        config_dir = runner.output / "artifacts" / file_id / info["id"]
        metadata, discovery = runner.run(path, config, config_dir / "discovery")
        info["discovery"] = metadata
        result["configurations"].append(info)
        base = {"file": relative, "configuration": info["id"]}
        if discovery is None:
            for candidate in candidates or [{"function": "<entry-discovery>", "discovery": "unavailable"}]:
                result["tests"].append({**base, **candidate, "status": metadata["status"],
                                        "reasons": [metadata["reason"]], "record_count": 0,
                                        "artifact": metadata["output"]})
            continue
        entries = discovery.get("entries", [])
        info["target"] = discovery.get("target")
        info["functions_in_main_file"] = discovery.get("functions_in_main_file")
        active_keys = {(entry["function"], entry["source"]["line"]) for entry in entries}
        for candidate in candidates:
            if (candidate["function"], candidate["source"]["line"]) not in active_keys:
                result["tests"].append({**base, **candidate, "status": "inactive_configuration",
                                        "reasons": ["lexical_candidate_absent_from_active_ast"], "record_count": 0})
        if not entries:
            result["tests"].append({**base, "function": "<entry-discovery>", "status": "unsupported",
                                    "reasons": ["no_supported_test_entry_identified"], "record_count": 0,
                                    "discovery": "clang_ast", "artifact": metadata["output"]})
        for entry in entries:
            name = entry["function"]
            entry_id = hashlib.sha256(name.encode()).hexdigest()[:16]
            metadata, data = runner.run(path, config, config_dir / entry_id, name)
            row = {**base, **entry, "target": discovery.get("target"), "artifact": metadata["output"],
                   "execution": metadata, "record_count": 0}
            if data is None:
                row.update(status=metadata["status"], reasons=[metadata["reason"]])
            else:
                records = data.get("records", [])
                row.update(status="extracted" if records else "not_applicable",
                           reasons=[] if records else ["no_concrete_normalized_records"],
                           record_count=len(records),
                           configuration_confidence=info["confidence"])
                result["record_count"] += row["record_count"]
            result["tests"].append(row)
    result["status"] = aggregate_status(result["tests"], result["record_count"])
    result["test_status_counts"] = dict(Counter(r["status"] for r in result["tests"]))
    return result


def scan_file(path, root, resolver, runner):
    relative = path.relative_to(root).as_posix()
    language = file_language(path)
    if language == "c": return scan_c_file(path, relative, resolver, runner)
    supported_asset = language in {"header", "support_file", "symlink"}
    return {"path": relative, "language": language,
            "status": "not_applicable" if supported_asset else "unsupported",
            "reasons": ["not_a_standalone_c_translation_unit" if supported_asset else "language_not_supported"],
            "entry_discovery": "not_attempted", "configurations": [], "tests": [], "record_count": 0}


def make_report(summary, files):
    lines = ["# Linux selftests 全量扫描报告", "",
             f"扫描范围：`{summary['selftests']}`", "",
             f"清单内文件 **{summary['inventory_files']}** 个，完成处理 **{summary['processed_files']}** 个，"
             f"条目/配置记录 **{summary['test_entries']}** 个，提取调用记录 **{summary['records']}** 条。", "",
             "本报告统计扫描覆盖，不代表所有内核行为已被证明。"
             "词法候选包含未启用的条件编译分支；`<entry-discovery>` 是入口发现失败/无已知入口的占位项，不是真实测试。", "",
             "| 状态 | 文件数 | 测试/入口配置条目数 |", "|---|---:|---:|"]
    for status, label in STATUS_TEXT.items():
        lines.append(f"| {label} (`{status}`) | {summary['file_status_counts'].get(status, 0)} | {summary['test_status_counts'].get(status, 0)} |")
    lines += ["", "## 编译参数来源", "",
              "| 来源 | 配置数 |", "|---|---:|"]
    for origin, count in summary["configuration_origins"].items(): lines.append(f"| {origin} | {count} |")
    lines += ["", "`compile_commands` 来自已有构建记录；`static_make` 是只读 Makefile 推导，"
              "未执行 make、shell 展开或生成头文件。每条配置保存完整参数、来源、警告及日志。"
              "能通过解析不等于复现了真实构建配置。", "",
              "## 目录覆盖", "", "| 顶层目录 | 文件 | C 文件 | 提取记录 | 解析失败文件 | 资源超限文件 |", "|---|---:|---:|---:|---:|---:|"]
    directories = {}
    for file in files:
        directory = file["path"].split("/")[0] if "/" in file["path"] else "(root)"
        counter = directories.setdefault(directory, Counter())
        counter["files"] += 1; counter["c"] += file["language"] == "c"
        counter["records"] += file["record_count"]; counter[file["status"]] += 1
    for directory, count in sorted(directories.items()):
        lines.append(f"| {directory} | {count['files']} | {count['c']} | {count['records']} | {count['parse_failed']} | {count['resource_limit']} |")
    lines += ["", "## 使用明细", "",
              "- `files.jsonl`：每个清单文件一条；包含配置来源、状态、原因、入口信息和日志路径。",
              "- `tests.jsonl`：每个入口/编译配置一条；没有记录也会报告原因。",
              "- `records.jsonl`：去重后的 syscall 输入及最终 `ret` / `errno` 约束。",
              "- `artifacts/`：逐配置发现结果、逐入口精简结果和编译诊断。",
              "- `summary.json`：机器可读汇总及本次资源预算。", "",
              "发现支持 TEST/TEST_F 等 kselftest 宏、普通 main，以及 BPF prog_tests 的命名入口。"
              "自定义框架、fixture variant 组合、其他配置分支和非 C 语言的内部用例尚未完整枚举，均通过状态或范围说明保留。",
              "未知参数、分析不完整或无法规范为 `ret` / `errno` 的调用不会进入结果。", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--extractor", type=Path, default=ROOT / "build/syscall-extract")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compile-commands", action="append", type=Path, default=[])
    parser.add_argument("--include", action="append", default=[], help="Selftests-relative glob; repeatable")
    parser.add_argument("--extra-arg", action="append", default=[], help="Extra Clang flag (use --extra-arg=-I/path)")
    parser.add_argument("--target", help="Clang target triple for fallback configurations")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=10, help="Seconds per discovery/analysis process")
    parser.add_argument("--memory-mb", type=int, default=768, help="Per-process address space limit")
    parser.add_argument("--output-mb", type=int, default=16, help="Per-process stdout/stderr file limit")
    args = parser.parse_args()
    if args.jobs < 1 or args.timeout <= 0 or args.memory_mb < 64 or args.output_mb < 1:
        parser.error("Invalid process/resource limits")
    kernel = args.kernel.resolve(); root = kernel / "tools/testing/selftests"
    if not root.is_dir(): parser.error(f"Selftests directory not found: {root}")
    if not args.extractor.is_file(): parser.error("Build syscall-extract before scanning")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output = (args.output or ROOT / "out" / ("scan-" + stamp)).resolve()
    if output.is_relative_to(root): parser.error("Use an output directory outside the analyzed selftests tree")
    if output.exists(): parser.error(f"Output already exists; choose a new directory: {output}")
    databases = args.compile_commands or ([kernel / "compile_commands.json"] if (kernel / "compile_commands.json").is_file() else [])
    resolver = FlagResolver(kernel, databases, args.extra_arg, args.target)
    output.mkdir(parents=True)
    inventory = sorted(p for p in root.rglob("*") if (p.is_file() or p.is_symlink()) and
                       (not args.include or any(fnmatch.fnmatchcase(p.relative_to(root).as_posix(), pattern) for pattern in args.include)))
    (output / "inventory.json").write_text(json.dumps([p.relative_to(root).as_posix() for p in inventory], indent=2) + "\n")
    summary = {"schema_version": 1, "state": "running", "kernel": str(kernel), "selftests": str(root),
               "started_at": datetime.now(timezone.utc).isoformat(), "inventory_files": len(inventory),
               "processed_files": 0, "test_entries": 0, "records": 0,
               "limits": {"jobs": args.jobs, "timeout_seconds": args.timeout,
                          "address_space_mb": args.memory_mb, "output_mb": args.output_mb},
               "include": args.include, "compilation_databases": [str(p) for p in databases],
               "configuration_errors": resolver.database_errors}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    runner = Runner(args.extractor, output, args.timeout, args.memory_mb, args.output_mb)
    file_counts, test_counts, origins, languages = Counter(), Counter(), Counter(), Counter()
    rows = []; seen_records = set(); last_progress = time.monotonic(); started = last_progress
    print(f"Inventory: {len(inventory)} files; output: {output}", flush=True)
    pool = ThreadPoolExecutor(max_workers=args.jobs)
    futures = {pool.submit(scan_file, path, root, resolver, runner): path for path in inventory}
    try:
        with (output / "files.jsonl").open("w") as file_stream, (output / "tests.jsonl").open("w") as test_stream, (output / "records.jsonl").open("w") as record_stream:
            for future in as_completed(futures):
                path = futures[future]
                try: row = future.result()
                except Exception as error:
                    row = {"path": path.relative_to(root).as_posix(), "language": file_language(path),
                           "status": "analysis_failed", "reasons": ["scanner_exception"], "detail": repr(error),
                           "tests": [], "configurations": [], "record_count": 0}
                file_stream.write(json.dumps(row, ensure_ascii=False) + "\n"); file_stream.flush()
                file_counts[row["status"]] += 1; languages[row["language"]] += 1
                for config in row["configurations"]: origins[config["origin"]] += 1
                for test in row["tests"]:
                    test_counts[test["status"]] += 1
                    test_stream.write(json.dumps(test, ensure_ascii=False) + "\n")
                    if test["record_count"]:
                        data = json.loads((output / test["artifact"]).read_text())
                        for record in data["records"]:
                            constraint = record.get("result", {}).get("errno")
                            if constraint and isinstance(constraint.get("value"), int):
                                name = errno.errorcode.get(constraint["value"])
                                if name: constraint["name"] = name
                            key = json.dumps(record, ensure_ascii=False, sort_keys=True,
                                             separators=(",", ":"))
                            if key not in seen_records:
                                seen_records.add(key)
                                record_stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                test_stream.flush(); record_stream.flush()
                rows.append({k: v for k, v in row.items() if k in {"path", "language", "status", "record_count"}})
                summary["processed_files"] += 1
                summary["test_entries"] += len(row["tests"])
                summary["records"] = len(seen_records)
                if time.monotonic()-last_progress > 10 or summary["processed_files"] == len(inventory):
                    print(f"Processed {summary['processed_files']}/{len(inventory)} files; {summary['records']} records; statuses={dict(file_counts)}", flush=True)
                    last_progress = time.monotonic()
        summary["state"] = "complete"
    except KeyboardInterrupt:
        runner.stop(); summary["state"] = "interrupted"
        for future in futures: future.cancel()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        summary.update(file_status_counts=dict(file_counts), test_status_counts=dict(test_counts),
                       configuration_origins=dict(origins), language_counts=dict(languages),
                       elapsed_seconds=round(time.monotonic()-started, 2),
                       finished_at=datetime.now(timezone.utc).isoformat())
        (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        (output / "report.md").write_text(make_report(summary, rows))
    print(f"Scan {summary['state']}: {output / 'report.md'}", flush=True)
    return 0 if summary["state"] == "complete" else 130


if __name__ == "__main__":
    raise SystemExit(main())
