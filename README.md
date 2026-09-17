# syscall-static-extractor

一个基于 Clang LibTooling 的小型静态分析原型：从 Linux kselftest 的 C AST 中关联 syscall 参数和结果断言。
分析的是未修改的测试源文件。分析时不运行 syscall、不运行 selftests、不构建内核或 syz-executor。

## 使用

本机需要 CMake、C++ 编译器、LLVM/Clang 开发库和 Python 3；Python 无第三方依赖。
本次开发环境为 LLVM/Clang 21，目标 x86_64 Linux。

```sh
python3 build.py
python3 -m unittest discover -s tests -v
python3 run_demo.py --kernel /home/hengyul/linux
```

结果：`out/dataset.json`（仅含 syscall、参数和结果约束）、`out/report.md`（相同内容的表格）。
如果源码目录不同，运行测试前设置任务专用环境变量 `LINUX_SOURCE`。
可以通过 `SYSCALL_EXTRACTOR` 指定已有的提取器二进制。

直接分析单个函数：

```sh
build/syscall-extract \
  --function=flags_set --syscall=pidfd_getfd \
  /home/hengyul/linux/tools/testing/selftests/pidfd/pidfd_getfd_test.c \
  -- -std=gnu11 \
  -I/home/hengyul/linux/tools/testing/selftests \
  -I/home/hengyul/linux/tools/include
```

## 扫描整个 Linux selftests

```sh
python3 scan_selftests.py --kernel /home/hengyul/linux --jobs 4
```

默认输出到一个新的 `out/scan-时间戳/` 目录，不覆盖已有扫描结果。
整个目录的文件都会进入清单；对 C 文件解析当前编译配置的 AST，自动发现 `TEST`、`TEST_F`、
`TEST_SIGNAL`、`TEST_F_SIGNAL`、`TEST_F_TIMEOUT`、普通 `main` 和 BPF prog_tests 的命名入口。
宏展开产生的注册函数和 wrapper 不会当作独立用例。

可指定已有的编译数据库、额外参数、扫描范围及资源预算：

```sh
python3 scan_selftests.py \
  --kernel /home/hengyul/linux \
  --compile-commands /path/to/compile_commands.json \
  --extra-arg=-I/path/to/generated/headers \
  --jobs 4 --timeout 10 --memory-mb 768 --output-mb 16

python3 scan_selftests.py --kernel /home/hengyul/linux \
  --include 'pidfd/*.c' --include 'filesystems/openat2/*.c'
```

`--compile-commands` 和 `--include` 均可重复。编译数据库保留同一源文件的多条不同构建配置；
未提供时自动查找内核根目录的 `compile_commands.json`。
缺少编译记录的文件会读取最近的 Makefile 及其可解析的 include，支持简单赋值、变量引用、条件和目标专用 CFLAGS。
Makefile 推导标记为 `best_effort_static_make`，无法解析的表达式和缺失头文件会写入配置警告。
不会运行 Makefile、`$(shell ...)`、构建命令或生成头文件。成功通过 C 解析不表示推导参数与实际构建完全相同。
跨架构目录会根据目录推断目标 triple；需要相应 sysroot/头文件才能成功解析，缺失时明确报告 `parse_failed`。
BPF 内核程序使用 `BPF_CFLAGS` / `CLANG_CFLAGS` 和 BPF 目标，与宿主机测试驱动的 CFLAGS 分开处理。
可用 `--target` 指定 Makefile 回退配置的目标。

每个发现/分析子进程默认最多 10 秒、768 MiB 地址空间、16 MiB 单个输出文件，且禁止生成 core dump。
超时、内存不足、输出超限或分析器崩溃只影响相应用例，其他文件继续扫描。
`--memory-mb` 是进程地址空间上限，不是 RSS；`--jobs` 控制并发进程数。

扫描输出：

| 文件 | 内容 |
|---|---|
| `inventory.json` | 本次范围内的完整文件清单 |
| `summary.json` / `report.md` | 机器可读汇总 / 可读覆盖报告 |
| `files.jsonl` | 逐文件状态、参数来源、配置警告和用例信息 |
| `tests.jsonl` | 逐入口/配置状态及明确原因 |
| `records.jsonl` | 去重后的 syscall 输入和最终 `ret` / `errno` 约束 |
| `artifacts/` | 逐文件发现结果、逐用例精简结果和编译诊断 |

状态解释：

| 状态 | 含义 |
|---|---|
| `extracted` | 至少提取到一条具体且可规范化的记录 |
| `partial` | 同一文件的不同入口或配置同时存在提取结果和失败状态 |
| `unsupported` | 不支持该语言/结构，或没有可识别入口/可关联的 syscall 断言 |
| `parse_failed` | 编译参数、头文件或 C 语法等导致解析失败 |
| `resource_limit` | 时间、地址空间、输出大小或循环展开预算耗尽 |
| `analysis_failed` | 分析器崩溃、输出损坏或扫描器内部异常 |
| `not_applicable` | 头文件/资源文件，或入口没有具体且可规范化的记录 |
| `inactive_configuration` | 文本中存在的候选入口不在当前预处理配置的 AST 中 |

解析失败时仍会保留词法发现的候选用例；候选不是 AST 证明的入口。
未识别入口时生成 `<entry-discovery>` 占位项，避免把无输出误报为成功。
脚本、汇编等会得到文件级“不支持”状态，内部测试函数暂不枚举。
fixture variant 的组合、未知自定义测试框架和未提供的其他构建配置尚不保证完整枚举。
无法形成具体参数和规范结果约束的调用不会进入 `records.jsonl`。

只列出一个文件中当前配置下的测试入口：

```sh
build/syscall-extract --discover \
  /home/hengyul/linux/tools/testing/selftests/filesystems/openat2/openat2_test.c \
  -- -I/home/hengyul/linux/tools/testing/selftests -I/home/hengyul/linux/tools/include
```

## 当前验证范围

- `pidfd_getfd_test.c` 的 `flags_set`：常量参数和 `ret` / `errno` 配对。
- `openat2_test.c` 的 `openat2_flag_validation`：25 行结构体参数表、零初始化、字段访问、有限循环、条件分支。
- 从真实函数体识别 `return syscall(...)` 和 `ret >= 0 ? ret : -errno` 包装。
- `EXPECT/ASSERT_EQ/NE/GE/GT/LE/LT/TRUE/FALSE` 的实际宏展开。
- 将可归约的当前调用条件合并进最终结果，成功返回值保留为 `ret >= 0`。
- 未知外部调用会使 errno 来源失效，并使其指针参数指向的内容变为未知。

原有 demo 的真实源码提取结果为 26 条记录：pidfd_getfd 1 条；openat2 25 条（20 条 EINVAL、5 条返回非负 fd）。
回归及集成检查共 30 项：原有 13 项覆盖条件断言、errno 来源、参数表配对、未知值、指针写入、无符号宽整数和分析范围限制；
新增 17 项覆盖全目录清单、AST 入口发现、编译参数来源、不执行 Makefile 命令、状态分类和资源隔离。

提取器使用结构化 AST 遍历、常量求值、局部符号状态、有限循环展开和简单函数内联。
没有使用正则表达式硬编码测试表内容，也没有执行测试来取得标签。

## 数据含义和限制

每条记录只包含 `syscall`、`args` 和 `result`。`result` 将源码中的相关断言合并为
`ret` / `errno` 约束；Python 输出层为已知 errno 数值增加 `EINVAL` 等名称。
未知参数、分析不完整、断言无法规范化或结果约束互相冲突的记录会被过滤。
路径、源码位置、调用前缀、fixture、wrapper、原始谓词和分析诊断不进入结果。
记录是从测试断言恢复的输入/结果场景，不是内核行为证明，也不保证脱离测试环境后可独立复现。

这不是完备或经过形式化验证的 C 分析器。它只支持明确记录的一小部分 C 语法与 kselftest 模式。
不支持任意循环、并发、一般跨函数控制流或 syscall 输出内存推导；默认每个循环最多展开 128 次。
未知调用和分支合并可能使输入变为未知并导致记录被过滤。循环中的未知 continue/skip 分支
不保证穷举所有路径。可执行结果仍会受权限、资源、内核版本、配置和文件系统等影响。

当前命令使用本机系统 UAPI 头文件与仓库 selftest/helper 头文件，没有生成新的内核 headers。
跨架构使用时需显式传入正确编译参数，且不能直接采用 Python 主机的 errno 名称映射。

## 目录

- `src/main.cpp`：Clang AST 分析器。
- `run_demo.py`：运行两个真实测试文件的分析并生成 JSON / Markdown。
- `tests/fixtures.c`：用于检查错误关联的微型 C 输入，仅做静态分析。
- `tests/test_extractor.py`：回归测试与真实源码集成检查。
- `scan_selftests.py`：全目录清单、入口发现、资源隔离及覆盖报告。
- `build_flags.py`：编译数据库读取和不执行命令的 Makefile 参数推导。
- `limit_worker.py`：在独立进程内设置分析资源上限。
- `tests/test_scanner.py`：扫描、参数来源、状态与资源限制测试。

下一步适合扩展 `read` 等 syscall 的输出内存关联，以及更完整的 fixture 和路径分析。
