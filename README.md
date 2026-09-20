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

结果采用保守的欠近似：允许漏掉无法证明的场景，但不为未知值猜常量。每次可建模的 syscall 都建立一个包含独立 `ret` / `errno` symbol 的 event；comparison 和 bind event 只传播该 event 的 provenance，不解释 C 表达式来合成比较约束。断言适配器把成功条件交给 Clang `assume()`，已知 failure API 被建模为 sink；到达正常函数出口时，checker 直接读取 Clang `ProgramState` 中的 `RangeSet`，再把范围投影到输出 schema。对取负等可逆且保持有符号整数语义的派生 symbol，投影层会把 Clang 已求得的范围映射回 event 字段；signedness 改变、narrowing 或其他无法证明可逆的转换会被过滤，不存在 AST 比较式回退。

同一 assertion 的成功路径按 event 聚合，并且仅在另一字段范围相同时对 `ret` 或 `errno` 做精确并集。因此 `A || true` 会自然并成无约束而不输出，`ret` / `errno` 的分支相关性也不会被错误交叉组合。范围只在输出边界投影成当前 schema 的单个比较式：例如 `ret >= 0 && ret >= 1` 可投影为 `ret >= 1`，最终仍为 `0 <= ret && ret < 10` 时会保守过滤；中间范围若继续被 `ret == 5` 收窄，则可以精确输出。未知参数、被不透明调用修改的内存、不可规范化断言和不可满足约束同样都会被过滤。

当前 checker 处理：

- 直接或经可内联 wrapper 调用的 libc `syscall`；
- Clang 能分析的分支、循环、数组/结构体初始化和局部内存；
- 通过宏展开来源识别常见 `EXPECT_*` / `ASSERT_*` / `CHECK_OP` 断言，并为 `ksft_test_result` 和 nolibc 风格 syscall assertion helper 提供薄语义适配；不依赖 `__exp` / `__seen` 之类临时变量名；
- syscall 返回值以及紧随其后的 `errno` 约束；
- 指向具体结构体和字符串的 syscall 参数快照。

控制流能力来自 Clang Static Analyzer，不再由项目内手写求值器逐种实现。syscall 和测试框架的特殊行为仍属于领域模型；扩展其他断言框架或 API 时，应增加只负责提交 Clang 假设和标记 event provenance 的薄适配器，而不是复制一套 C/C++ 执行器。predicate 临时值的来源随 analyzer 的 bind event 按 `TypedValueRegion` 保存在 `ProgramState` 中，重新赋值会替换与父/子 region 重叠的旧来源，opaque invalidation 则通过 `RegionChanges` 清除受影响的来源；comparison concrete 化时的桥接信息以 `(Expr, LocationContext)` 求值点保存，并仅在 Clang 当前路径证明短路 RHS 确实执行时合并。普通 guard 只有在对应路径实际到达已知 failure sink 后才成为 oracle。

`argument_ranges` 测试定义了 argument domain 的目标表示：单值仍直接写成 JSON 值；其他情况写成 `{"domain": [...]}`。`domain` 的列表元素之间为 OR，数字表示一个离散点，比较对象中的字段为 AND。例如 `[1, 2, 4, 8, {">": 20, "<=": 30}]` 表示 `{1, 2, 4, 8}` 与 `20 < arg <= 30` 的并集。只有其他参数和 result 相同、无需保留跨参数相关性时，才能把这些候选合并到同一条 record。

## 目录

- `src/main.cpp`：编译数据库驱动、Static Analyzer checker 和结果收集。
- `scan_artifacts.py`：compilation database 批量扫描、隔离和汇总。
- `limit_worker.py`：分析子进程资源限制。
- `tests/cases/*.c`：按函数组织的静态分析输入。
- `tests/cases/*.json`：与同名 C 文件配对、按函数名索引的预期 records。
- `tests/test_records.py`：自动批量发现所有 C/JSON 测试对并逐函数比较。
- `tests/test_scanner.py`：批量扫描、进程隔离和资源限制测试。
