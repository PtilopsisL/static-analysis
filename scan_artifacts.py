#!/usr/bin/env python3
"""Analyze Clang preprocessed artifacts without rebuilding the target project."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
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


ROOT = Path(__file__).resolve().parent


class Runner:
    """Run one analyzer process with bounded resources and classify failures."""

    def __init__(self, extractor, output, timeout, memory_mb, output_mb):
        self.extractor = Path(extractor).resolve()
        self.output = Path(output).resolve()
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.output_mb = output_mb
        self.lock = threading.Lock()
        self.active = set()
        self.stopping = threading.Event()

    def stop(self):
        self.stopping.set()
        with self.lock:
            for process in self.active:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def run(self, artifact, artifact_dir, analyzer_args=()):
        artifact = Path(artifact).resolve()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        output_path = artifact_dir / "output.json"
        error_path = artifact_dir / "stderr.txt"
        command = [str(self.extractor), "--all-functions", *analyzer_args, str(artifact)]
        wrapper = [
            sys.executable,
            "-B",
            str(ROOT / "limit_worker.py"),
            "--memory-mb",
            str(self.memory_mb),
            "--output-mb",
            str(self.output_mb),
            "--cpu-seconds",
            str(self.timeout),
            "--",
            *command,
        ]
        metadata = {
            "command": command,
            "output": str(output_path.relative_to(self.output)),
            "stderr": str(error_path.relative_to(self.output)),
        }
        started = time.monotonic()
        if self.stopping.is_set():
            return {**metadata, "status": "analysis_failed", "reason": "scan_interrupted"}, None
        try:
            with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
                process = subprocess.Popen(
                    wrapper,
                    cwd=artifact.parent,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                with self.lock:
                    self.active.add(process)
                try:
                    code = process.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    metadata.update(status="resource_limit", reason="wall_time_limit")
                    code = process.returncode
                finally:
                    with self.lock:
                        self.active.discard(process)

            metadata.update(
                returncode=code,
                elapsed_seconds=round(time.monotonic() - started, 3),
            )
            memory_error = compiler_error = False
            with error_path.open("rb") as stream:
                carry = b""
                for chunk in iter(lambda: stream.read(65536), b""):
                    diagnostic = carry + chunk
                    memory_error |= bool(
                        re.search(
                            rb"out of memory|bad_alloc|cannot allocate memory|failed to map segment|memoryerror",
                            diagnostic,
                            re.I,
                        )
                    )
                    compiler_error |= bool(re.search(rb"(?:fatal )?error:", diagnostic))
                    carry = diagnostic[-128:]
                stream.seek(max(0, error_path.stat().st_size - 6000))
                diagnostic_tail = stream.read().decode(errors="replace")
            if diagnostic_tail:
                metadata["diagnostic_tail"] = diagnostic_tail

            if "status" in metadata:
                return metadata, None
            if code:
                size_limit = max(output_path.stat().st_size, error_path.stat().st_size) >= self.output_mb * 1024**2
                if code in (-signal.SIGXCPU, -signal.SIGXFSZ) or size_limit:
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
                if data.get("schema_version") != 1:
                    raise ValueError("unsupported analyzer schema")
                if not isinstance(data.get("functions"), list) or not isinstance(data.get("records"), list):
                    raise ValueError("missing analyzer arrays")
            except (ValueError, OSError, AttributeError) as error:
                metadata.update(status="analysis_failed", reason="invalid_analyzer_json", detail=str(error))
                return metadata, None
            metadata["status"] = "ok"
            return metadata, data
        except (OSError, ValueError) as error:
            metadata.update(
                status="analysis_failed",
                reason="process_launch_failed",
                detail=str(error),
                elapsed_seconds=round(time.monotonic() - started, 3),
            )
            return metadata, None


def artifact_status(functions):
    statuses = {function.get("status") for function in functions}
    if "extracted" in statuses:
        return "extracted"
    if "unsupported" in statuses:
        return "unsupported"
    return "no_records"


def analyze_artifact(path, root, runner, analyzer_args):
    relative = path.relative_to(root).as_posix()
    artifact_id = hashlib.sha256(relative.encode()).hexdigest()[:16]
    metadata, data = runner.run(path, runner.output / "artifacts" / artifact_id, analyzer_args)
    row = {
        "path": relative,
        "language": "c++" if path.suffix == ".ii" else "c",
        "size_bytes": path.stat().st_size,
        "bitcode": path.with_suffix(".bc").is_file(),
        "execution": metadata,
        "record_count": 0,
    }
    if data is None:
        row.update(status=metadata["status"], reason=metadata["reason"])
        return row, [], []

    functions = []
    for function in data["functions"]:
        functions.append(
            {
                **function,
                "artifact": relative,
                "translation_unit_source": data.get("source"),
                "target": data.get("target"),
            }
        )
    records = data["records"]
    row.update(
        status=artifact_status(functions),
        source=data.get("source"),
        target=data.get("target"),
        target_source=data.get("target_source"),
        warnings=data.get("warnings", []),
        function_count=len(functions),
        function_status_counts=dict(Counter(function["status"] for function in functions)),
        record_count=len(records),
    )
    if not functions:
        row["reason"] = "no_original_source_functions"
    return row, functions, records


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path, help="Directory containing .i/.ii files")
    parser.add_argument("--extractor", type=Path, default=ROOT / "build/syscall-extract")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--include", action="append", default=[], help="Artifact-root-relative glob; repeatable")
    parser.add_argument("--target", help="Override the target triple for every artifact")
    parser.add_argument("--syscall", action="append", default=[], help="Only emit this syscall; repeatable")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=20, help="Seconds per translation unit")
    parser.add_argument("--memory-mb", type=int, default=1024, help="Per-process address space limit")
    parser.add_argument("--output-mb", type=int, default=16, help="Per-process stdout/stderr file limit")
    args = parser.parse_args()
    if args.jobs < 1 or args.timeout <= 0 or args.memory_mb < 64 or args.output_mb < 1:
        parser.error("invalid process/resource limits")

    root = args.artifact_root.resolve()
    if not root.is_dir():
        parser.error(f"artifact directory not found: {root}")
    if not args.extractor.is_file():
        parser.error("build syscall-extract before scanning")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output = (args.output or ROOT / "out" / ("scan-" + stamp)).resolve()
    if output == root or output.is_relative_to(root):
        parser.error("use an output directory outside the artifact tree")
    if output.exists():
        parser.error(f"output already exists: {output}")

    artifacts = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in {".i", ".ii"}
        and (
            not args.include
            or any(fnmatch.fnmatchcase(path.relative_to(root).as_posix(), pattern) for pattern in args.include)
        )
    )
    output.mkdir(parents=True)
    analyzer_args = []
    if args.target:
        analyzer_args.append("--target=" + args.target)
    analyzer_args.extend("--syscall=" + syscall for syscall in args.syscall)

    started = time.monotonic()
    summary = {
        "schema_version": 1,
        "state": "running",
        "artifact_root": str(root),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": len(artifacts),
        "processed_artifacts": 0,
        "functions": 0,
        "records": 0,
        "limits": {
            "jobs": args.jobs,
            "timeout_seconds": args.timeout,
            "address_space_mb": args.memory_mb,
            "output_mb": args.output_mb,
        },
        "include": args.include,
        "target_override": args.target,
        "syscall_filter": args.syscall,
        "scope": "Only .i/.ii artifacts present in the artifact tree are counted.",
    }
    write_json(output / "summary.json", summary)

    runner = Runner(args.extractor, output, args.timeout, args.memory_mb, args.output_mb)
    artifact_counts = Counter()
    function_counts = Counter()
    seen_records = set()
    last_progress = time.monotonic()
    print(f"Artifacts: {len(artifacts)}; output: {output}", flush=True)
    pool = ThreadPoolExecutor(max_workers=args.jobs)
    futures = {
        pool.submit(analyze_artifact, path, root, runner, analyzer_args): path
        for path in artifacts
    }
    try:
        with (
            (output / "artifacts.jsonl").open("w") as artifact_stream,
            (output / "functions.jsonl").open("w") as function_stream,
            (output / "records.jsonl").open("w") as record_stream,
        ):
            for future in as_completed(futures):
                path = futures[future]
                try:
                    row, functions, records = future.result()
                except Exception as error:
                    row = {
                        "path": path.relative_to(root).as_posix(),
                        "language": "c++" if path.suffix == ".ii" else "c",
                        "status": "analysis_failed",
                        "reason": "scanner_exception",
                        "detail": repr(error),
                        "record_count": 0,
                    }
                    functions, records = [], []

                artifact_stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                artifact_stream.flush()
                artifact_counts[row["status"]] += 1
                for function in functions:
                    function_counts[function["status"]] += 1
                    function_stream.write(json.dumps(function, ensure_ascii=False) + "\n")
                function_stream.flush()
                for record in records:
                    key = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    if key in seen_records:
                        continue
                    seen_records.add(key)
                    record_stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                record_stream.flush()

                summary["processed_artifacts"] += 1
                summary["functions"] += len(functions)
                summary["records"] = len(seen_records)
                if time.monotonic() - last_progress > 10 or summary["processed_artifacts"] == len(artifacts):
                    print(
                        f"Processed {summary['processed_artifacts']}/{len(artifacts)} artifacts; "
                        f"{summary['records']} records; statuses={dict(artifact_counts)}",
                        flush=True,
                    )
                    last_progress = time.monotonic()
        summary["state"] = "complete"
    except KeyboardInterrupt:
        runner.stop()
        summary["state"] = "interrupted"
        for future in futures:
            future.cancel()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        summary.update(
            artifact_status_counts=dict(artifact_counts),
            function_status_counts=dict(function_counts),
            elapsed_seconds=round(time.monotonic() - started, 2),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        write_json(output / "summary.json", summary)
    print(f"Scan {summary['state']}: {output}", flush=True)
    return 0 if summary["state"] == "complete" else 130


if __name__ == "__main__":
    raise SystemExit(main())
