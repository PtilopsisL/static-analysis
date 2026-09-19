# syscall-static-extractor

一个基于 Clang Static Analyzer 的 syscall 测试场景提取器。唯一输入是：

1. 原始 C/C++ 源码；
2. `compile_commands.json` 中该源码对应的真实 Clang 编译命令。

工具不再读取 `.i/.ii` 或 `.bc`，也没有这类输入的回退路径。Clang 使用编译数据库中的工作目录、目标架构、宏、头文件路径和语言选项重新建立 AST，并负责函数内联、分支、循环、路径约束与内存状态；自定义 checker 只补充 syscall、`errno` 和测试断言的领域语义。被分析程序不会被链接或执行。

## 构建

需要 CMake、C++ 编译器和 LLVM/Clang 开发库。本仓库使用 LLVM/Clang 21 开发和验证。

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm \
  -DClang_DIR=/usr/lib/llvm-21/lib/cmake/clang
cmake --build build -j2
cmake --build build --target test
```

## 准备输入

目标项目需要生成 `compile_commands.json`，其中的命令必须是实际使用的 Clang 命令。例如 CMake 项目可以使用：

```sh
cmake -S /path/to/project -B /path/to/project-build \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++
cmake --build /path/to/project-build
```

其他构建系统可以直接导出或捕获 compilation database。工具不推导 Makefile，也不猜测缺失的 include、宏、target 或编译配置。

`compile_commands.json` 中同一源码的不同命令视为不同编译单元，分别分析，不会合并成一个假想配置。

## 分析单个编译单元

按编译数据库中的零起始索引选择命令，并指定顶层函数：

```sh
build/syscall-extract \
  --compdb /path/to/build/compile_commands.json \
  --unit-index 42 \
  --function openat2_flag_validation
```

分析该编译单元中的所有源码函数：

```sh
build/syscall-extract \
  --compdb /path/to/build/compile_commands.json \
  --unit-index 42 \
  --all-functions
```

可用过滤项：

```text
--function=NAME   指定顶层分析函数
--all-functions   分析该编译单元中的所有函数
--syscall=NAME    只输出指定 syscall；可重复
```

输出同时记录选中的命令索引、工作目录、源码和完整命令行，便于确认实际分析配置。

## 批量扫描 compilation database

```sh
python3 scan_artifacts.py /path/to/build/compile_commands.json \
  --jobs 4 \
  --timeout 20 \
  --memory-mb 1024
```

也可以过滤源文件或 syscall：

```sh
python3 scan_artifacts.py /path/to/build/compile_commands.json \
  --include '*/openat2/*' \
  --syscall openat2 \
  --output /path/to/new-output
```

`--include` 同时匹配数据库中记录的 `file` 和规范化后的绝对源码路径。输出目录必须不存在；默认创建 `out/scan-时间戳/`。

| 文件 | 内容 |
|---|---|
| `records.jsonl` | 全局去重后的 `args`、`result` 和 `syscall` |
| `units.jsonl` | 每条编译命令的状态、统计和进程日志位置 |
| `functions.jsonl` | 每个顶层函数的状态和记录数 |
| `summary.json` | 扫描范围、资源预算和状态汇总 |
| `units/` | 每个分析进程的有界 stdout/stderr |

编译单元状态：

| 状态 | 含义 |
|---|---|
| `extracted` | 至少提取到一条具体记录 |
| `no_records` | 分析成功，但没有可证明且可规范化的记录 |
| `parse_failed` | 真实编译命令无法重新解析源码 |
| `resource_limit` | 达到超时、地址空间或输出大小限制 |
| `analysis_failed` | 分析器异常退出或输出损坏 |

每条 compilation database 记录是独立隔离单元；一个单元失败不会中止其他单元。诊断信息保存在 `units.jsonl` 和 `functions.jsonl`，不会进入最终 records。

## 数据与正确性语义

核心提取器的一条记录形如：

```json
{
  "syscall": "openat2",
  "args": [-100, ".", {"pointee": {"flags": 0, "mode": 0, "resolve": 0}}, 24],
  "result": {"ret": {"op": ">=", "value": 0}}
}
```

结果采用保守的欠近似：允许漏掉无法证明的场景，但不为未知值猜常量。只有 syscall 参数和关联断言都能在同一路径上具体化时才输出；未知参数、被不透明调用修改的内存、不可规范化断言和不可满足约束都会被过滤。同一返回值上的多个原子约束只有在能安全合并为当前 schema 可表示的单个约束时才保留；例如 `ret >= 0 && ret >= 1` 可归一化为 `ret >= 1`，而 `0 <= ret && ret < 10` 会保守过滤，而不是静默丢掉其中一半。

当前 checker 处理：

- 直接或经可内联 wrapper 调用的 libc `syscall`；
- Clang 能分析的分支、循环、数组/结构体初始化和局部内存；
- 通过宏展开来源识别常见 `EXPECT_*` / `ASSERT_*` / `CHECK_OP` 断言，并识别已知的失败分支；不依赖 `__exp` / `__seen` 之类临时变量名；
- syscall 返回值以及紧随其后的 `errno` 约束；
- 指向具体结构体和字符串的 syscall 参数快照。

控制流能力来自 Clang Static Analyzer，不再由项目内手写求值器逐种实现。syscall 和测试框架的特殊行为仍属于领域模型；扩展其他断言框架或 API 时，应增加语义模型，而不是复制一套 C/C++ 执行器。
predicate 临时值的来源随 analyzer 的 bind event 保存在 `ProgramState` 中，重新赋值或内存失效会自然覆盖该来源。已知 failure API 被建模为 sink；分支是否确定失败由 Clang CFG 上的可达性决定，而不是递归解释 AST 语句。

## 目录

- `src/main.cpp`：编译数据库驱动、Static Analyzer checker 和结果收集。
- `scan_artifacts.py`：compilation database 批量扫描、隔离和汇总。
- `limit_worker.py`：分析子进程资源限制。
- `tests/src/fixtures.c`：静态分析回归输入。
- `tests/records.json`：无序严格比较的标准 records。
- `tests/`：核心提取和批量扫描测试。
