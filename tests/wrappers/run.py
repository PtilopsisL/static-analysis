#!/usr/bin/env python3
"""Build executable libc probes, observe them, and optionally check the extractor."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile

from compare import compare_records, compare_trace, normalize_event, unsigned, validate_layouts


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def process(command, directory, timeout):
    environment = os.environ.copy()
    # No injected loader hooks; bind PLT entries before entering a probe.
    for variable in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_DEBUG", "LD_DEBUG_OUTPUT"):
        environment.pop(variable, None)
    environment.update(LC_ALL="C", LD_BIND_NOW="1")
    with subprocess.Popen(command, cwd=directory, env=environment,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = child.communicate()
            return {"command": command, "returncode": child.returncode,
                    "stdout": stdout, "stderr": stderr, "timed_out": True}
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate()
            raise
    return {"command": command, "returncode": child.returncode,
            "stdout": stdout, "stderr": stderr, "timed_out": False}


def checked_process(command, directory, timeout):
    result = process(command, directory, timeout)
    if result["timed_out"] or result["returncode"]:
        raise RuntimeError(json.dumps(result, indent=2))
    return result


def load_contracts():
    contracts = json.loads((HERE / "cases.json").read_text())
    if not isinstance(contracts, dict) or not contracts:
        raise ValueError("at least one wrapper test contract is required")
    for name, contract in contracts.items():
        if not name.startswith("probe_") or not name.replace("_", "").isalnum():
            raise ValueError(f"invalid probe name: {name}")
        for field in ("events", "returns", "records"):
            if not isinstance(contract.get(field), list):
                raise ValueError(f"{name}.{field} must be an explicit expected list")
    return contracts


def build(directory, compiler, timeout):
    directory.mkdir()
    flags = ["--target=x86_64-linux-gnu", "-std=gnu11", "-D_GNU_SOURCE", "-O0", "-g",
             "-fno-builtin", "-Wall", "-Wextra", "-Werror"]
    entries = []
    logs = []
    objects = []
    for source in (HERE / "probes.c", HERE / "trace.c"):
        obj = directory / (source.stem + ".o")
        command = [compiler, *flags, "-c", str(source), "-o", str(obj)]
        entries.append({"directory": str(directory), "file": str(source), "arguments": command})
        logs.append(checked_process(command, directory, timeout))
        objects.append(str(obj))
    executable = directory / "wrapper-trace"
    logs.append(checked_process([compiler, "--target=x86_64-linux-gnu", *objects,
                                 "-Wl,-z,now", "-ldl", "-o", str(executable)], directory, timeout))
    write_json(directory / "compile_commands.json", entries)
    write_json(directory / "build.json", logs)
    return executable, directory / "compile_commands.json"


def describe(executable, directory, timeout):
    result = checked_process([str(executable), "--describe"], directory, timeout)
    write_json(directory / "description-process.json", result)
    description = json.loads(result["stdout"])
    write_json(directory / "description.json", description)
    return description


def validate_description(description, contracts):
    if description.get("schema_version") != 2 or description.get("arch") != "x86_64":
        raise ValueError("unsupported probe description schema or architecture")
    validate_layouts(description["layouts"])
    probes = description["probes"]
    by_name = {probe["name"]: probe for probe in probes}
    if len(by_name) != len(probes):
        raise ValueError("duplicate probe registrations")
    if by_name.keys() != contracts.keys():
        raise ValueError(f"probe/contract registration mismatch: without contract={sorted(by_name.keys() - contracts.keys())}; "
                         f"without probe={sorted(contracts.keys() - by_name.keys())}")
    for name, probe in by_name.items():
        symbols = probe["symbols"]
        if (not isinstance(symbols, list) or any(not isinstance(symbol, str) or not symbol for symbol in symbols) or
                len(set(symbols)) != len(symbols)):
            raise ValueError(f"{name}: invalid tested symbol list")
        if not unsigned(probe["result_count"]) or probe["result_count"] != len(contracts[name]["returns"]):
            raise ValueError(f"{name}: declared result_count differs from expected returns")
        for limit in ("event_limit", "snapshot_limit"):
            if not unsigned(probe[limit]) or not probe[limit]:
                raise ValueError(f"{name}: invalid {limit}")
    return by_name


def identity(trace, expected_symbols, expected_hash=None):
    symbols = {name: str(Path(path).resolve(strict=True)) for name, path in trace["symbols"].items()}
    libc = Path(trace["libc_path"]).resolve(strict=True)
    if set(symbols) != set(expected_symbols) or any(path != str(libc) for path in symbols.values()):
        raise ValueError("declared tested symbols do not all resolve to the identified libc object")
    digest = sha256(libc)
    if expected_hash is not None and digest != expected_hash:
        raise ValueError(f"libc fingerprint mismatch: expected {expected_hash}, got {digest}")
    objects = {}
    for name in trace["loaded_objects"]:
        path = Path(name)
        if path.is_absolute():
            resolved = path.resolve(strict=True)
            objects[str(resolved)] = sha256(resolved)
        elif not name.startswith("linux-vdso"):
            raise ValueError(f"cannot identify loaded object: {name}")
    if str(libc) not in objects:
        raise ValueError("resolved libc is absent from loaded object list")
    return {"arch": trace["arch"], "libc_version": trace["libc_version"],
            "libc_path": str(libc), "libc_sha256": digest,
            "symbols": symbols, "loaded_objects": objects}


def check_analysis(extractor, compdb, name, contract, directory, timeout):
    result = process([str(extractor), "--compdb", str(compdb), "--unit-index", "0",
                      "--function", name, "--libc-profile", "glibc-linux-x86_64"],
                     directory, timeout)
    write_json(directory / "analysis-process.json", result)
    if result["timed_out"] or result["returncode"]:
        return {"status": "error", "errors": ["extractor failed; see analysis-process.json"]}
    data = json.loads(result["stdout"])
    write_json(directory / "analysis.json", data)
    if data.get("schema_version") != 2 or not isinstance(data.get("records"), list):
        raise ValueError("invalid extractor output")
    if [function["function"] for function in data["functions"]] != [name]:
        raise ValueError("extractor did not analyze the selected probe")
    errors = compare_records(data["records"], contract["records"])
    return {"status": "mismatch" if errors else "passed", "errors": errors,
            "expected_records": len(contract["records"]), "actual_records": len(data["records"])}


def run_suite(output, compiler, contracts, timeout=15, extractor=None, libc_sha256=None, all_contracts=None):
    output = Path(output).resolve()
    output.mkdir(exist_ok=False)
    report = {"schema_version": 1, "status": "running", "scope": "linux-x86_64-glibc",
              "analysis_requested": extractor is not None, "cases": {},
              "environment": {"kernel": platform.release(), "machine": platform.machine()},
              "source_sha256": {path.name: sha256(path) for path in
                                (HERE / "probes.c", HERE / "probes.h", HERE / "trace.c",
                                 HERE / "compare.py", HERE / "run.py", HERE / "cases.json")}}
    write_json(output / "summary.json", report)
    write_json(output / "contracts.json", contracts)
    try:
        if not contracts:
            raise ValueError("no probes selected")
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("only native Linux x86-64 is supported")
        version = checked_process([compiler, "--version"], output, timeout)
        report["environment"]["compiler"] = version["stdout"]
        executable, compdb = build(output / "build", compiler, timeout)
        report["binary_sha256"] = sha256(executable)
        description = describe(executable, output, timeout)
        registered = validate_description(description, contracts if all_contracts is None else all_contracts)
        if contracts.keys() - registered.keys():
            raise ValueError("selected probes are not registered")
        for name, contract in contracts.items():
            directory = output / name
            directory.mkdir()
            # Fixtures only create files under this fresh per-case directory.
            workspace = directory / "work"
            workspace.mkdir()
            row = {"runtime": {"status": "error"}, "analysis": {"status": "not_run"}}
            report["cases"][name] = row
            try:
                observed = process([str(executable), name], workspace, timeout)
                write_json(directory / "runtime-process.json", observed)
                if observed["timed_out"] or observed["returncode"]:
                    raise RuntimeError("observer failed; see runtime-process.json")
                trace = json.loads(observed["stdout"])
                write_json(directory / "trace.json", trace)
                if trace.get("probe") != name:
                    raise ValueError("observer returned a different probe")
                if trace.get("layouts") != description["layouts"]:
                    raise ValueError("trace layouts differ from the compiled probe descriptions")
                current_identity = identity(trace, registered[name]["symbols"], libc_sha256)
                row["symbols"] = current_identity.pop("symbols")
                previous = report["environment"].get("libc")
                if previous is not None and current_identity != previous:
                    raise ValueError("libc identity changed between probes")
                report["environment"]["libc"] = current_identity
                errors = compare_trace(trace, contract)
                write_json(directory / "normalized.json", [normalize_event(event, trace["layouts"]) for event in trace["events"]])
                row["runtime"] = {"status": "mismatch" if errors else "passed", "errors": errors}
            except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RuntimeError) as error:
                row["runtime"] = {"status": "error", "errors": [str(error)]}
            if extractor is not None:
                # Static diagnostics are useful even when runtime observation fails.
                try:
                    row["analysis"] = check_analysis(extractor, compdb, name, contract, directory, timeout)
                except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
                    row["analysis"] = {"status": "error", "errors": [str(error)]}
            print(f"{name}: runtime={row['runtime']['status']} analysis={row['analysis']['status']}", flush=True)
            write_json(output / "summary.json", report)
        failed = any(row["runtime"]["status"] != "passed" or
                     (extractor is not None and row["analysis"]["status"] != "passed")
                     for row in report["cases"].values())
        report["status"] = "failed" if failed else ("passed" if extractor else "runtime_only_passed")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RuntimeError) as error:
        report.update(status="error", error=str(error))
    except KeyboardInterrupt:
        report.update(status="interrupted")
    finally:
        report["runtime_counts"] = dict(Counter(row["runtime"]["status"] for row in report["cases"].values()))
        report["analysis_counts"] = dict(Counter(row["analysis"]["status"] for row in report["cases"].values()))
        write_json(output / "summary.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New artifact directory; defaults to a new directory under /tmp")
    parser.add_argument("--clang", default=os.environ.get("CLANG", shutil.which("clang-21") or shutil.which("clang")))
    parser.add_argument("--case", action="append", dest="cases", help="Probe name; repeatable")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--check-analysis", action="store_true", help="Require exact extractor records as well as runtime agreement")
    parser.add_argument("--extractor", type=Path, default=Path(os.environ.get("SYSCALL_EXTRACTOR", ROOT / "build/syscall-extract")))
    parser.add_argument("--libc-sha256", help="Require this previously observed libc binary fingerprint")
    args = parser.parse_args()
    if not args.clang or args.timeout <= 0:
        parser.error("clang and a positive timeout are required")
    compiler = shutil.which(args.clang)
    if not compiler:
        parser.error("clang executable not found")
    contracts = load_contracts()
    all_contracts = contracts
    if args.cases:
        if set(args.cases) - contracts.keys():
            parser.error("unknown probe name")
        contracts = {name: value for name, value in contracts.items() if name in args.cases}
    if args.check_analysis and not args.extractor.is_file():
        parser.error("build syscall-extract or supply --extractor")
    output = args.output
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="libc-wrappers-")) / "results"
    if output.exists():
        parser.error("output directory must not exist")
    report = run_suite(output, compiler, contracts, args.timeout,
                       args.extractor.resolve() if args.check_analysis else None, args.libc_sha256, all_contracts)
    print(f"{report['status']}: {output.resolve()}")
    return 0 if report["status"] in ("passed", "runtime_only_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
