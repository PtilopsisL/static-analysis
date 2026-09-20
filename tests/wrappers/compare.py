"""Independent Linux x86-64 trace decoder and fixture-contract comparisons."""
from collections import Counter
import json


# These are encoding primitives, not a syscall-name/number or wrapper model table.
WIDTHS = {"s32": 4, "u32": 4, "s64": 8, "u64": 8, "pointer": 8}


def unsigned(value, bits=64):
    return type(value) is int and 0 <= value < 2**bits


def scalar(value, kind):
    bits = WIDTHS[kind] * 8
    value &= (1 << bits) - 1
    return value - (1 << bits) if kind.startswith("s") and value >= 1 << (bits - 1) else value


def validate_layouts(layouts):
    if not isinstance(layouts, list):
        raise ValueError("missing syscall layouts")
    for layout in layouts:
        args = layout["args"]
        selector = layout["selector"]
        if (not unsigned(layout["nr"]) or not isinstance(layout["name"], str) or
                not layout["name"] or not isinstance(args, list) or len(args) > 6 or
                not unsigned(selector["arg"]) or selector["arg"] > len(args) or
                not unsigned(selector["mask"]) or not unsigned(selector["value"]) or
                selector["value"] & ~selector["mask"] or
                (not selector["arg"] and (selector["mask"] or selector["value"]))):
            raise ValueError("invalid syscall layout")
        for arg in args:
            if arg["type"] not in WIDTHS:
                raise ValueError("invalid argument encoding")
            memory = arg.get("memory")
            if memory is None:
                continue
            kind = memory["type"]
            length_arg = memory["length_arg"]
            if (arg["type"] != "pointer" or type(memory["phases"]) is not int or
                    memory["phases"] not in (1, 2, 3) or not unsigned(memory["size"]) or
                    not unsigned(length_arg) or length_arg > len(args) or
                    type(memory["nullable"]) is not bool or
                    type(memory["limit_to_result"]) is not bool or
                    not isinstance(memory["fields"], list) or
                    (memory["fields"] and kind != "struct") or
                    (memory["limit_to_result"] and not memory["phases"] & 2) or
                    kind not in ("s32", "u32", "s64", "u64", "cstring", "bytes", "struct")):
                raise ValueError("invalid memory layout")
            if length_arg and args[length_arg - 1]["type"] not in ("u32", "u64"):
                raise ValueError("memory length requires an unsigned argument")
            if (length_arg or memory["limit_to_result"]) and kind != "bytes":
                raise ValueError("dynamic length is only supported for bytes")
            if kind in ("cstring", "struct") and not memory["size"]:
                raise ValueError("memory layout requires a size bound")
            if kind == "struct":
                fields = memory["fields"]
                if not fields or len({field["name"] for field in fields}) != len(fields):
                    raise ValueError("empty or duplicate struct fields")
                for field in fields:
                    width = field["size"] if field["type"] == "bytes" else WIDTHS.get(field["type"], 0)
                    if (not isinstance(field["name"], str) or not field["name"] or
                            field["type"] == "pointer" or not unsigned(width) or not width or
                            not unsigned(field["offset"]) or field["offset"] + width > memory["size"]):
                        raise ValueError("invalid struct field")


def decode_bytes(data, kind, fields=()):
    if kind == "cstring":
        if not data or data[-1] or b"\0" in data[:-1]:
            raise ValueError("invalid terminated string snapshot")
        return data[:-1].decode("utf-8")
    if kind == "bytes":
        return {"hex": data.hex()}
    if kind == "struct":
        decoded = {}
        for field in fields:
            width = field["size"] if field["type"] == "bytes" else WIDTHS[field["type"]]
            start = field["offset"]
            decoded[field["name"]] = decode_bytes(data[start:start + width], field["type"])
        return decoded
    if len(data) != WIDTHS[kind]:
        raise ValueError("invalid scalar snapshot size")
    return int.from_bytes(data, "little", signed=kind.startswith("s"))


def normalize_memory(event, index, layout):
    memory = layout["args"][index]["memory"]
    kind = memory["type"]
    snapshots = event["snapshots"][str(index)]
    phases = [name for bit, name in ((1, "before"), (2, "after")) if memory["phases"] & bit]
    if set(snapshots) != set(phases):
        raise ValueError("missing or unexpected memory snapshot phase")
    if not event["args"][index] and memory["nullable"]:
        if any(value is not None for value in snapshots.values()):
            raise ValueError("non-null snapshot of a null pointer")
        return 0
    size = WIDTHS.get(kind, memory["size"])
    if memory["length_arg"]:
        length_index = memory["length_arg"] - 1
        size = scalar(event["args"][length_index], layout["args"][length_index]["type"])
    values = {}
    for phase in phases:
        encoded = snapshots[phase]
        if not isinstance(encoded, str):
            raise ValueError("missing byte snapshot")
        data = bytes.fromhex(encoded)
        if data.hex() != encoded:
            raise ValueError("non-canonical byte snapshot")
        expected_size = size
        if phase == "after" and memory["limit_to_result"]:
            expected_size = min(size, max(0, event["raw_result"]))
        if (kind == "cstring" and len(data) > size) or (kind != "cstring" and len(data) != expected_size):
            raise ValueError("incorrect memory snapshot size")
        values[phase] = decode_bytes(data, kind, memory["fields"])
    return values["before"] if kind == "cstring" and phases == ["before"] else values


def normalize_event(event, layouts):
    if len(event["args"]) != 6 or any(not unsigned(value) for value in event["args"]):
        raise ValueError("incomplete or invalid syscall argument registers")
    raw_result = event["raw_result"]
    if not unsigned(event["nr"]) or type(raw_result) is not int or not -2**63 <= raw_result < 2**63:
        raise ValueError("invalid syscall number or result")
    if type(event["is_error"]) is not bool or event["is_error"] != (-4095 <= raw_result < 0):
        raise ValueError("inconsistent x86-64 syscall error flag")
    candidates = []
    for layout in layouts:
        selector = layout["selector"]
        if layout["nr"] == event["nr"] and (not selector["arg"] or
                event["args"][selector["arg"] - 1] & selector["mask"] == selector["value"]):
            candidates.append(layout)
    if len(candidates) != 1:
        raise ValueError(f"unknown or ambiguous layout for observed syscall {event['nr']}")
    layout = candidates[0]
    expected_snapshots = {str(i) for i, arg in enumerate(layout["args"]) if arg.get("memory")}
    if set(event["snapshots"]) != expected_snapshots:
        raise ValueError("missing or unexpected argument snapshots")
    args = [normalize_memory(event, i, layout) if arg.get("memory") else scalar(event["args"][i], arg["type"])
            for i, arg in enumerate(layout["args"])]
    return {"syscall": layout["name"], "args": args, "raw_result": raw_result}


def matches(actual, expected, bindings):
    if isinstance(expected, dict) and set(expected) == {"ref"}:
        name = expected["ref"]
        return name in bindings and type(actual) is type(bindings[name]) and actual == bindings[name]
    if isinstance(expected, dict) and set(expected) == {"op", "value"}:
        value = expected["value"]
        if type(actual) is not int or type(value) is not int:
            return False
        predicates = {
            "==": lambda: actual == value,
            "!=": lambda: actual != value,
            ">=": lambda: actual >= value,
            ">": lambda: actual > value,
            "<=": lambda: actual <= value,
            "<": lambda: actual < value,
        }
        if expected["op"] not in predicates:
            raise ValueError(f"unsupported predicate: {expected}")
        return predicates[expected["op"]]()
    if isinstance(expected, dict):
        return (isinstance(actual, dict) and actual.keys() == expected.keys() and
                all(matches(actual[key], value, bindings) for key, value in expected.items()))
    if isinstance(expected, list):
        return (isinstance(actual, list) and len(actual) == len(expected) and
                all(matches(a, e, bindings) for a, e in zip(actual, expected)))
    return type(actual) is type(expected) and actual == expected


def compare_trace(trace, contract):
    """Require a complete window and exact event order; return all mismatches."""
    errors = []
    if trace.get("schema_version") != 2 or trace.get("arch") != "x86_64":
        return ["unsupported observation schema or architecture"]
    if trace.get("complete") is not True:
        return ["incomplete trace window"]
    if trace.get("errno_before") != 123:
        errors.append("initial errno sentinel was not established")
    validate_layouts(trace["layouts"])
    actual = [normalize_event(event, trace["layouts"]) for event in trace["events"]]
    expected = contract["events"]
    if len(actual) != len(expected):
        errors.append(f"event count: expected {len(expected)}, got {len(actual)}")
    bindings = {}
    for index, (observed, wanted) in enumerate(zip(actual, expected)):
        where = f"event[{index}]"
        if observed["syscall"] != wanted["syscall"]:
            errors.append(f"{where}: expected {wanted['syscall']}, got {observed['syscall']}")
        if len(observed["args"]) != len(wanted["args"]):
            errors.append(f"{where}: argument count mismatch")
        for arg_index, (value, expectation) in enumerate(zip(observed["args"], wanted["args"])):
            if not matches(value, expectation, bindings):
                errors.append(f"{where}.args[{arg_index}]: expected {expectation!r}, got {value!r}")
        if not matches(observed["raw_result"], wanted["raw_result"], bindings):
            errors.append(f"{where}.raw_result: expected {wanted['raw_result']!r}, got {observed['raw_result']}")
        if "bind" in wanted:
            if wanted["bind"] in bindings:
                raise ValueError("duplicate fixture binding")
            bindings[wanted["bind"]] = observed["raw_result"]
    returns = trace["returns"]
    if len(returns) != len(contract["returns"]):
        errors.append("wrapper result count mismatch")
    for index, (observed, wanted) in enumerate(zip(returns, contract["returns"])):
        if (not unsigned(observed["slot"]) or type(observed["ret"]) is not int or
                not -2**63 <= observed["ret"] < 2**63 or type(observed["errno"]) is not int or
                not -2**31 <= observed["errno"] < 2**31):
            raise ValueError("invalid wrapper result")
        if observed["slot"] != index:
            errors.append(f"returns[{index}]: missing or reordered result slot")
        for field in ("ret", "errno"):
            if not matches(observed[field], wanted[field], bindings):
                errors.append(f"returns[{index}].{field}: expected {wanted[field]!r}, got {observed[field]}")
    return errors


def compare_records(actual, expected):
    """Exact oracle comparison: a witness alone cannot establish a range."""
    canonical = lambda record: json.dumps(record, sort_keys=True, separators=(",", ":"))
    observed = Counter(map(canonical, actual))
    wanted = Counter(map(canonical, expected))
    errors = []
    for kind, records in (("missing", wanted - observed), ("unexpected", observed - wanted)):
        for record in records.elements():
            errors.append(f"{kind} record: {record}")
    return errors
