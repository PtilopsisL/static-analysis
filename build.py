#!/usr/bin/env python3
"""Build only this analyzer, using the installed LLVM/Clang development files."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-config", default="llvm-config")
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    build = args.build_dir or root / "build"
    llvm_dir = Path(subprocess.check_output(
        [args.llvm_config, "--cmakedir"], text=True).strip())
    subprocess.run([
        "cmake", "-S", str(root), "-B", str(build),
        "-DCMAKE_BUILD_TYPE=Release", f"-DLLVM_DIR={llvm_dir}",
        f"-DClang_DIR={llvm_dir.parent / 'clang'}",
    ], check=True)
    subprocess.run(["cmake", "--build", str(build), "-j2"], check=True)


if __name__ == "__main__":
    main()
