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
--libc-profile=glibc-linux-x86_64
                  显式启用 Linux x86-64/glibc wrapper 模型
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
  --libc-profile glibc-linux-x86_64 \
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

结果采用保守的欠近似：允许漏掉无法证明的场景，但不为未知值猜常量。每次可建模的 syscall 都建立一个包含独立 `ret` / `errno` symbol 的 event；comparison 和 bind event 只传播该 event 的 provenance，不解释 C 表达式来合成比较约束。framework adapter 只把调用、状态写入和终止行为分类为 `Pass / Fail / Skip` 等 outcome effect；report/counter boundary 关闭当前 outcome epoch，harness status write 则保留到 test 结束。checker 只观察 Clang 实际探索到的 accepted path，并直接读取其 `ProgramState` 中的 `RangeSet`，不会从失败分支反向构造成功状态。对取负等可逆且保持有符号整数语义的派生 symbol，投影层会把 Clang 已求得的范围映射回 event 字段；signedness 改变、narrowing 或其他无法证明可逆的转换会被过滤，不存在 AST 比较式回退。

同一 assertion 的成功路径按 event 聚合，并且仅在另一字段范围相同时对 `ret` 或 `errno` 做精确并集。因此 `A || true` 会自然并成无约束而不输出，`ret` / `errno` 的分支相关性也不会被错误交叉组合。范围只在输出边界投影成当前 schema 的单个比较式：例如 `ret >= 0 && ret >= 1` 可投影为 `ret >= 1`，最终仍为 `0 <= ret && ret < 10` 时会保守过滤；中间范围若继续被 `ret == 5` 收窄，则可以精确输出。未知参数、被不透明调用修改的内存、不可规范化断言和不可满足约束同样都会被过滤。

当前 checker 处理：

- 直接或经可内联 wrapper 调用的 libc `syscall`；
- 在显式选择 `glibc-linux-x86_64` profile 时，对经过审核的外部 libc
  wrapper 使用分析期语义模型；
- Clang 能分析的分支、循环、数组/结构体初始化和局部内存；
- 通过统一的 outcome-effect dispatcher 为 ksft、BPF、nolibc 和 LTP 提供薄语义适配，并把 `struct __test_metadata::exit_code` 的已知状态写入识别为 harness outcome；不匹配 `EXPECT_*` / `ASSERT_*` / `CHECK_OP` 等宏名，也不依赖 `_metadata`、`__exp` 或 `__seen` 等变量名；
- LTP 风格的 `TEST` / `TST_RET` / `TST_ERR` 传播、`TST_EXP_*` 结果路径和单个具体 errno 的 `tst_errno_in_set`；`TFAIL` / `TBROK` 作为拒绝路径，`TCONF` 只跳过路径而不形成 oracle，`TPASS` / `TINFO` 等不会被误判为失败；
- syscall 返回值以及紧随其后的 `errno` 约束；
- 指向具体结构体和字符串的 syscall 参数快照。

控制流能力来自 Clang Static Analyzer，不再由项目内手写求值器逐种实现。syscall 和测试框架的特殊行为仍属于领域模型；扩展其他框架或 API 时，应增加只负责声明 outcome effect、boundary policy 或 framework state transfer 的薄适配器，而不是复制一套 C/C++ 执行器。predicate 临时值的来源随 analyzer 的 bind event 按 `TypedValueRegion` 保存在 `ProgramState` 中，重新赋值会替换与父/子 region 重叠的旧来源，opaque invalidation 则通过 `RegionChanges` 清除受影响的来源；comparison concrete 化时的桥接信息以 `(Expr, LocationContext)` 求值点保存，并仅在 Clang 当前路径证明短路 RHS 确实执行时合并。outcome epoch 管理生命周期，candidate marker 管理 effect 与 event 的归属；accepted alternatives 只在同一 observation group 内做精确并集，避免把条件 assertion 的 bypass path 混入该 assertion。

## libc wrapper 分析模型

默认 `--libc-profile=none`，提取器不会仅凭函数名称猜测最终链接的 libc。
选择 `--libc-profile=glibc-linux-x86_64` 表示调用者确认该编译单元最终使用这一
libc/ABI 组合。输出中的 `libc_profile` 字段记录本次选择。

当前原型在分析阶段把一组简单 wrapper 规范化为现有的 syscall `Invocation`：

- 同名直接调用：`close`、`write` 和 `ioctl`；
- 改名调用：`eventfd → eventfd2`；
- 参数转换：`open/openat → openat`，补充 `AT_FDCWD`，并按具体 flags 决定
  使用调用方 mode 还是 0。

模型只匹配 Linux x86-64 LP64、没有可见函数体的全局 C 函数，以及经过检查的
glibc 声明类型。源码中可见的同名用户实现、不同 ABI 或不兼容声明不会被替换。
`open/openat` 的 flags 必须在当前路径上为具体值；不能确定是否需要 mode 时不生成
记录。模型以保守欠近似为原则，不会为未知参数猜值。

模型还声明已知输出内存：`ioctl` 的第三个参数在调用后失效为未知值，防止后续
syscall 错误地复用调用前内容。当前处理是保守失效，并不尝试推断任意 request
的具体输出。

这些是分析期模型，不参与目标程序的编译或链接。`tests/wrappers` 仍调用并用 ptrace
观测真实 glibc，然后把运行事件与使用该 profile 得到的静态 records 做严格比较。
模型的适用声明仍是一项外部假设；动态对照覆盖已测试输入，不构成所有 glibc 版本和
所有输入的形式化等价证明。

`argument_ranges` 测试定义了 argument domain 的目标表示：单值仍直接写成 JSON 值；其他情况写成 `{"domain": [...]}`。`domain` 的列表元素之间为 OR，数字表示一个离散点，比较对象中的字段为 AND。例如 `[1, 2, 4, 8, {">": 20, "<=": 30}]` 表示 `{1, 2, 4, 8}` 与 `20 < arg <= 30` 的并集。只有其他参数和 result 相同、无需保留跨参数相关性时，才能把这些候选合并到同一条 record。

## 目录

- `src/main.cpp`：编译数据库驱动、Static Analyzer checker 和结果收集。
- `scan_artifacts.py`：compilation database 批量扫描、隔离和汇总。
- `limit_worker.py`：分析子进程资源限制。
- `tests/cases/*.c`：按函数组织的静态分析输入。
- `tests/cases/*.json`：与同名 C 文件配对、按函数名索引的预期 records。
- `tests/test_records.py`：自动批量发现所有 C/JSON 测试对并逐函数比较。
- `tests/test_scanner.py`：批量扫描、进程隔离和资源限制测试。
