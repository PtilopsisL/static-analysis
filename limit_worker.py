#!/usr/bin/env python3
"""Apply child-only limits before exec; safe to launch from scanner threads."""
import argparse
import math
import os
import resource
import signal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-mb", type=int, required=True)
    parser.add_argument("--output-mb", type=int, required=True)
    parser.add_argument("--cpu-seconds", type=float, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (args.memory_mb * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (args.output_mb * 1024**2,) * 2)
    cpu = max(1, math.ceil(args.cpu_seconds))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    # Python ignores SIGXFSZ by default; restore the normal child behavior.
    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
    os.execv(command[0], command)


if __name__ == "__main__":
    main()
