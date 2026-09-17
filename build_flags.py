"""Read compilation databases and a deliberately limited, non-executing Make subset.

Never run make, compiler commands from a database, $(shell), recipes, or plugins.
All inferred configurations carry their provenance and unresolved inputs.
"""
from dataclasses import asdict, dataclass, field
import fnmatch
import glob
import hashlib
import json
from pathlib import Path
import platform
import re
import shlex
import sys


@dataclass
class Configuration:
    directory: str
    arguments: list[str]
    origin: str
    provenance: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    variant: str = ""

    def to_dict(self):
        result = asdict(self)
        result["id"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()[:16]
        result["confidence"] = "recorded_build_command" if self.origin == "compile_commands" else "best_effort_static_make"
        return result


ARCH_TARGETS = {
    "arm64": "aarch64-linux-gnu", "aarch64": "aarch64-linux-gnu",
    "arm": "arm-linux-gnueabihf", "powerpc": "powerpc64le-linux-gnu",
    "riscv": "riscv64-linux-gnu", "s390": "s390x-linux-gnu",
    "sparc64": "sparc64-linux-gnu", "mips": "mipsel-linux-gnu",
    "x86": "x86_64-linux-gnu", "x86_64": "x86_64-linux-gnu",
}


def split_top(text, separator=","):
    parts, start, depth = [], 0, 0
    for i, char in enumerate(text):
        if char in "({": depth += 1
        elif char in ")}": depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:i]); start = i + 1
    return parts + [text[start:]]


def sanitize_flags(tokens, directory, source):
    """Keep frontend options. Drop outputs, linking, dependencies and code loaders."""
    result, warnings = [], []
    pair = {"-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros",
            "-D", "-U", "-isysroot", "--sysroot", "-target", "--target", "-x"}
    drop_pair = {"-o", "-MF", "-MT", "-MQ", "-MJ", "-Xlinker", "-L", "-l", "-B"}
    drop = {"-c", "-S", "-E", "-M", "-MM", "-MD", "-MMD", "-MP", "-MG", "-shared", "-static", "-pie", "-no-pie", "-Werror"}
    path_pair = {"-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-isysroot", "--sysroot"}
    i = 0
    while i < len(tokens):
        token = tokens[i]; i += 1
        if token in {"-Xclang", "-Xpreprocessor", "-load", "-plugin", "-include-pch"}:
            warnings.append(f"unsupported frontend passthrough removed: {token}")
            i += i < len(tokens)
            continue
        if token.startswith(("-fplugin", "-fpass-plugin", "-specs=", "--specs=")):
            warnings.append(f"code-loading option removed: {token}"); continue
        if token.startswith("@"):
            warnings.append(f"response file requires explicit expansion: {token}"); continue
        if token in drop_pair:
            i += i < len(tokens); continue
        if token in drop or token.startswith(("-Wl,", "-Wa,", "-l", "-L", "-Werror=", "-fsanitize", "-fno-sanitize")):
            continue
        if token in pair:
            if i >= len(tokens) or tokens[i].startswith("__UNRESOLVED") or tokens[i].startswith("-"):
                warnings.append(f"missing or unresolved argument for {token}"); continue
            value = tokens[i]; i += 1
            if "__UNRESOLVED" in value:
                warnings.append(f"unresolved {token} operand"); continue
            if token in path_pair and not Path(value).is_absolute():
                value = str((Path(directory) / value).resolve())
            result.extend([token, value]); continue
        if "__UNRESOLVED" in token or "$" in token:
            warnings.append(f"unresolved option omitted: {token}"); continue
        if token.startswith(("-I", "-D", "-U")) and len(token) > 2:
            if token.startswith("-I") and not Path(token[2:]).is_absolute():
                token = "-I" + str((Path(directory) / token[2:]).resolve())
            result.append(token); continue
        if token.startswith(("--target=", "--sysroot=", "-std=", "-O", "-m", "-f", "-W")) or token in {"-pthread", "-nostdinc", "-nostdinc++", "-ansi"}:
            result.append(token); continue
        if token.startswith("-"):
            warnings.append(f"unrecognized option omitted: {token}")
        # Source files, object files and compiler/wrapper executable names are not options.
    return result, sorted(set(warnings))


class StaticMake:
    """Resolve simple assignments/includes/conditions without invoking GNU make."""
    def __init__(self, directory, variables, target):
        self.directory = Path(directory)
        self.values = {k: (v, True) for k, v in variables.items()}
        self.target = target
        self.warnings = set()
        self.files = []
        self.target_assignments = []
        self.loaded = set()

    def unknown(self, description):
        self.warnings.add(description)
        return "__UNRESOLVED__"

    def variable(self, name, depth):
        if depth > 24: return self.unknown(f"recursive variable: {name}")
        if name not in self.values:
            # User extension variables are intentionally empty unless passed explicitly.
            if name in {"USERCFLAGS", "USERLDFLAGS", "CROSS_COMPILE", "LLVM_PREFIX", "LLVM_SUFFIX", "EXTRA_CFLAGS"}:
                return ""
            return self.unknown(f"undefined make variable: {name}")
        value, immediate = self.values[name]
        return value if immediate else self.expand(value, depth + 1)

    def expand(self, text, depth=0):
        if depth > 24: return self.unknown("make expansion depth exceeded")
        result, i = [], 0
        while i < len(text):
            if text[i:i+2] not in ("$(", "${"):
                result.append(text[i]); i += 1; continue
            start = i + 2; end = start; nesting = 1
            opener, closer = text[i+1], ")" if text[i+1] == "(" else "}"
            while end < len(text) and nesting:
                if text[end] == opener: nesting += 1
                elif text[end] == closer: nesting -= 1
                end += 1
            if nesting:
                result.append(self.unknown("unbalanced make expression")); break
            body = text[start:end-1].strip()
            if "$" in body and not re.match(r"[\w-]+\s", body):
                body = self.expand(body, depth+1)
            if re.fullmatch(r"[\w.-]+", body):
                result.append(self.variable(body, depth + 1))
            else:
                match = re.match(r"([\w-]+)\s+(.*)", body, re.S)
                if not match:
                    result.append(self.unknown(f"unsupported make expansion: {body[:100]}"))
                else:
                    function, rest = match.groups()
                    if function not in {"strip", "abspath", "realpath", "dir", "notdir", "wildcard", "addprefix", "addsuffix", "filter", "filter-out", "subst", "patsubst"}:
                        result.append(self.unknown(f"make function not evaluated: {function}"))
                    else:
                        args = [self.expand(a, depth+1) for a in split_top(rest)]
                        if any("__UNRESOLVED" in a for a in args):
                            result.append("__UNRESOLVED__")
                        elif function == "strip": result.append(" ".join(args[0].split()))
                        elif function in {"abspath", "realpath"}:
                            result.append(" ".join(str((self.directory / p).resolve()) for p in args[0].split()))
                        elif function == "dir": result.append(" ".join(str(Path(p).parent) + "/" for p in args[0].split()))
                        elif function == "notdir": result.append(" ".join(Path(p).name for p in args[0].split()))
                        elif function == "wildcard":
                            result.append(" ".join(str(Path(p).relative_to(self.directory)) if Path(p).is_relative_to(self.directory) else p
                                                   for pattern in args[0].split() for p in sorted(glob.glob(str(self.directory / pattern)))))
                        elif function in {"addprefix", "addsuffix"} and len(args) == 2:
                            result.append(" ".join(args[0]+p if function == "addprefix" else p+args[0] for p in args[1].split()))
                        elif function in {"filter", "filter-out"} and len(args) == 2:
                            result.append(" ".join(p for p in args[1].split() if
                                                   any(fnmatch.fnmatchcase(p, q.replace("%", "*")) for q in args[0].split()) == (function == "filter")))
                        elif function == "subst" and len(args) == 3: result.append(args[2].replace(args[0], args[1]))
                        elif function == "patsubst" and len(args) == 3:
                            pattern = "^" + re.escape(args[0]).replace("%", "(.*)") + "$"
                            result.append(" ".join(re.sub(pattern, args[1].replace("%", r"\1"), p) for p in args[2].split()))
                        else: result.append(self.unknown(f"unsupported make function arguments: {function}"))
            i = end
        return "".join(result)

    def condition(self, kind, value):
        if kind in {"ifdef", "ifndef"}:
            name = self.expand(value.strip())
            if "__UNRESOLVED" in name: return None
            truth = name in self.values and bool(self.variable(name, 0))
            return truth if kind == "ifdef" else not truth
        value = value.strip()
        if value.startswith("(") and value.endswith(")"):
            args = split_top(value[1:-1])
        else:
            try: args = shlex.split(value)
            except ValueError: return None
        if len(args) != 2: return None
        args = [self.expand(x.strip()) for x in args]
        if any("__UNRESOLVED" in x for x in args): return None
        equal = args[0] == args[1]
        return equal if kind == "ifeq" else not equal

    def assign(self, name, op, value):
        if op == "?=" and name in self.values: return
        if op in {":=", "::="}: self.values[name] = (self.expand(value), True)
        elif op == "+=" and name in self.values:
            prior, immediate = self.values[name]
            self.values[name] = (prior + " " + (self.expand(value) if immediate else value), immediate)
        else: self.values[name] = (value, False)

    def read(self, path, depth=0):
        path = Path(path).resolve()
        if path in self.loaded: return
        if depth > 12:
            self.warnings.add("make include depth exceeded"); return
        self.loaded.add(path)
        if not path.is_file():
            self.warnings.add(f"make include missing: {path}"); return
        self.files.append(str(path))
        self.values["MAKEFILE_LIST"] = (" ".join(self.files), True)
        text = re.sub(r"\\\n", " ", path.read_text(errors="replace"))
        active, conditions, in_define = True, [], False
        for lineno, raw in enumerate(text.splitlines(), 1):
            if raw.startswith("\t"): continue
            line = re.split(r"(?<!\\)#", raw, maxsplit=1)[0].strip()
            if line.startswith("define "): in_define = True; continue
            if line == "endef": in_define = False; continue
            if in_define or not line: continue
            cond = re.match(r"(ifeq|ifneq|ifdef|ifndef)\s+(.*)", line)
            if cond:
                truth = self.condition(*cond.groups()) if active else False
                if active and truth is None: self.warnings.add(f"unresolved conditional: {path}:{lineno}")
                conditions.append((active, truth)); active = active and truth is True; continue
            if line == "else":
                if conditions:
                    parent, truth = conditions[-1]; active = parent and truth is False
                continue
            if line.startswith("else "):
                # Chained make conditionals require a full make evaluator.
                self.warnings.add(f"chained conditional omitted: {path}:{lineno}"); active = False; continue
            if line == "endif":
                if conditions: active = conditions.pop()[0]
                continue
            if not active: continue
            include = re.match(r"-?include\s+(.+)", line)
            if include:
                expanded = self.expand(include.group(1))
                if "__UNRESOLVED" not in expanded:
                    for include_path in expanded.split(): self.read(self.directory / include_path, depth+1)
                continue
            target = re.match(r"(.+?):\s*(CFLAGS|CPPFLAGS|CLANG_FLAGS|TARGET_ARCH|BPF_CFLAGS)\s*(\+=|:=|\?=|=)\s*(.*)", line)
            if target:
                self.target_assignments.append(target.groups()); continue
            assignment = re.match(r"(?:export\s+|override\s+)?([\w.-]+)\s*(::=|:=|\+=|\?=|=)\s*(.*)", line)
            if assignment: self.assign(*assignment.groups())
        if conditions: self.warnings.add(f"unbalanced Makefile conditionals: {path}")

    def flags(self, names=("CFLAGS", "CPPFLAGS", "CLANG_FLAGS", "TARGET_ARCH")):
        for targets, name, op, value in self.target_assignments:
            patterns = self.expand(targets).split()
            if any(fnmatch.fnmatchcase(self.target, Path(p).name.replace("%", "*")) or
                   fnmatch.fnmatchcase(self.target+".o", Path(p).name.replace("%", "*")) for p in patterns):
                self.assign(name, op, value)
        values = [self.variable(v, 0) for v in names if v in self.values]
        try: return shlex.split(" ".join(values))
        except ValueError:
            self.warnings.add("unbalanced quoting in inferred compiler flags"); return []


class FlagResolver:
    def __init__(self, kernel, databases=(), extra_args=(), target=None):
        self.kernel = Path(kernel).resolve()
        self.selftests = self.kernel / "tools/testing/selftests"
        self.extra_args, self.target = list(extra_args), target
        self.commands = {}
        self.database_errors = []
        for database in databases:
            path = Path(database).resolve()
            try:
                entries = json.loads(path.read_text())
                if not isinstance(entries, list): raise ValueError("expected a JSON array")
                for entry in entries:
                    directory = Path(entry.get("directory", path.parent))
                    if not directory.is_absolute(): directory = path.parent / directory
                    directory = directory.resolve()
                    source = (directory / entry["file"]).resolve()
                    tokens = entry.get("arguments")
                    if tokens is None: tokens = shlex.split(entry["command"])
                    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens): raise ValueError("invalid command arguments")
                    flags, warnings = sanitize_flags(tokens, directory, source)
                    self.commands.setdefault(source, []).append(Configuration(
                        str(directory), flags + self.extra_args, "compile_commands", [str(path)], warnings,
                        str(entry.get("output", ""))))
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.database_errors.append(f"{path}: {error}")

    def resolve(self, source):
        source = Path(source).resolve()
        if source in self.commands:
            unique = {}
            for config in self.commands[source]: unique[config.to_dict()["id"]] = config
            return list(unique.values())
        directory = source.parent
        while directory != self.selftests and not (directory / "Makefile").is_file():
            directory = directory.parent
        machine = platform.machine()
        arch = {"aarch64": "arm64", "ppc64le": "powerpc", "riscv64": "riscv"}.get(machine, machine)
        relative = source.relative_to(self.selftests)
        inferred_target = self.target
        if not inferred_target and relative.parts[0] in ARCH_TARGETS:
            inferred_target = ARCH_TARGETS[relative.parts[0]]
            arch = relative.parts[0]
        if not inferred_target and relative.parts[0] == "kvm" and len(relative.parts) > 1 and relative.parts[1] in ARCH_TARGETS:
            arch = relative.parts[1]; inferred_target = ARCH_TARGETS[arch]
        variables = {
            "top_srcdir": str(self.kernel), "selfdir": str(self.selftests),
            "CURDIR": str(directory), "OUTPUT": str(directory), "src": str(directory),
            "ARCH": arch, "SRCARCH": "x86" if arch in {"x86_64", "i386"} else arch,
            "SUBARCH": arch, "uname_M": machine, "LLVM": "1", "MAKELEVEL": "0",
            "KHDR_INCLUDES": f"-isystem {self.kernel / 'usr/include'}",
            "TOOLS_INCLUDES": f"-isystem {self.kernel / 'tools/include/uapi'}",
            "CFLAGS": "", "CPPFLAGS": "", "CLANG_FLAGS": "", "TARGET_ARCH": "",
        }
        parser = StaticMake(directory, variables, source.stem)
        parser.read(directory / "Makefile")
        bpf_program = (relative.parts[:2] == ("bpf", "progs") or source.name.endswith(".bpf.c"))
        if bpf_program:
            tokens = parser.flags(("BPF_CFLAGS", "CLANG_CFLAGS"))
            inferred_target = self.target or ("bpfel" if sys.byteorder == "little" else "bpfeb")
            parser.warnings.add("BPF target inferred; generated BPF headers and compiler system includes may be required")
            if "BPF_CFLAGS" not in parser.values:
                parser.warnings.add("BPF_CFLAGS unavailable in nearest Makefile")
        else:
            tokens = parser.flags()
        flags, warnings = sanitize_flags(tokens, directory, source)
        # The common selftest include is needed even if a Make expression was unresolved.
        baseline = [f"-I{self.selftests}", f"-I{self.kernel / 'tools/include'}"]
        if not any(x.startswith("-std=") for x in flags): baseline.insert(0, "-std=gnu11")
        if inferred_target and not any(x.startswith("--target") or x == "-target" for x in flags):
            baseline.append("--target=" + inferred_target)
        warnings += list(parser.warnings)
        warnings += self.database_errors
        if not (self.kernel / "usr/include").is_dir(): warnings.append("generated kernel usr/include is absent; system headers may be used")
        return [Configuration(str(directory), baseline + flags + self.extra_args, "static_make",
                              parser.files, sorted(set(warnings)), "inferred")]
