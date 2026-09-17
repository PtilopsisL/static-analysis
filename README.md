# syscall-static-extractor

一个基于 Clang AST 的静态 syscall 场景提取器。它从目标项目真实构建留下的预处理翻译单元中，关联 syscall 参数和 `ret` / `errno` 断言。

本仓库不构建目标项目，不推导 Makefile，不查找目标项目头文件，也不运行被分析程序。Clang 只把已经预处理的 `.i/.ii` 文本解析成内存 AST；不再执行预处理、代码生成或链接。

## 构建分析器

需要 CMake、C++ 编译器和 LLVM/Clang 开发库。本次开发和验证使用 LLVM/Clang 21。

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm \
  -DClang_DIR=/usr/lib/llvm-21/lib/cmake/clang
cmake --build build -j2
python3 -m unittest discover -s tests -v
```

LLVM 安装路径不同时，按 `llvm-config --cmakedir` 的结果调整两个 CMake 路径。

## 在目标项目中准备 artifact

目标项目必须使用 Clang，并在自己的完整构建命令中加入：

```text
-save-temps=obj
```

建议同时加入 `-dD`：

```text
-save-temps=obj -dD
```

示意命令：

```sh
make CC=clang CXX=clang++ \
  CFLAGS+=' -save-temps=obj -dD' \
  CXXFLAGS+=' -save-temps=obj -dD'
```

具体变量由目标项目决定；使用 `HOSTCC`、BPF 编译参数或其他编译器变量的项目，需要把参数传给对应的 Clang 调用。推荐使用目标项目自己的独立输出目录。

正常编译会留下：

| 后缀 | 内容 | 本仓库用途 |
|---|---|---|
| `.i` | 预处理后的 C | 主要输入 |
| `.ii` | 预处理后的 C++ | 主要输入 |
| `.bc` | LLVM bitcode | 可选；自动读取 target triple |
| `.s` | 汇编 | 忽略 |
| `.o` | 目标文件 | 忽略；供目标项目正常链接 |

普通 `.i` 中 `__NR_openat2` 已经展开成数字，因此记录会使用 `number:437`。`-dD` 会在 `.i` 中保留宏定义，分析器可自动把纯整数形式的 `__NR_*` 映射回 syscall 名称。没有 `-dD` 仍然可以分析。

若需要完整覆盖，应进行一次干净的完整构建。增量构建目录只能代表本次实际重新编译的翻译单元；不同配置也必须使用不同输出路径，避免中间文件相互覆盖。

## 分析单个翻译单元

分析指定函数：

```sh
build/syscall-extract \
  --function=openat2_flag_validation \
  /path/to/build/openat2_test.i
```

分析原始源文件中定义的所有函数：

```sh
build/syscall-extract --all-functions /path/to/build/openat2_test.i
```

常用选项：

```text
--function=NAME       指定入口；可重复
--all-functions       分析原始源文件中的全部函数
--syscall=NAME        只输出指定 syscall；可重复
--target=TRIPLE       覆盖目标架构
--bitcode=FILE.bc     指定用于读取 target 的 bitcode
--source-file=PATH    覆盖从 #line 标记识别的原始源码路径
--loop-limit=N        有限循环最大展开次数
```

`--function` 和 `--all-functions` 二选一。同目录同名 `.bc` 存在时会自动读取其中的 target triple；否则使用本机 target，并在输出中标明 `target_source`。

分析器利用 `.i/.ii` 中的 `#line` 标记识别原始源文件。`--all-functions` 不会把展开进来的系统头文件函数作为入口，也不依赖 `TEST`、`TEST_F`、BPF `test_*` 等仓库专用命名规则。

## 批量扫描 artifact

```sh
python3 scan_artifacts.py /path/to/target-build-output \
  --jobs 4 \
  --timeout 20 \
  --memory-mb 1024
```

可指定扫描范围和过滤条件：

```sh
python3 scan_artifacts.py /path/to/artifacts \
  --include 'openat2/*.i' \
  --syscall openat2 \
  --target x86_64-linux-gnu \
  --output /path/to/new-output
```

输出目录必须不存在，并且不能位于 artifact 输入树内。默认创建 `out/scan-时间戳/`。

| 文件 | 内容 |
|---|---|
| `records.jsonl` | 全局去重后的 syscall 参数和结果约束 |
| `artifacts.jsonl` | 每个 `.i/.ii` 的 target、状态、警告和日志位置 |
| `functions.jsonl` | 每个原始源码函数的状态和记录数 |
| `summary.json` | 扫描范围、资源预算和状态计数 |
| `artifacts/` | 每个分析进程的完整有界 stdout/stderr |

状态含义：

| 状态 | 含义 |
|---|---|
| `extracted` | 至少提取到一条具体、可规范化记录 |
| `no_records` | 解析成功，但没有具体记录 |
| `unsupported` | 函数包含当前求值器不支持的控制流或表达式 |
| `parse_failed` | `.i/.ii` 无法重新建立 AST |
| `resource_limit` | 超时、地址空间或输出大小超限 |
| `analysis_failed` | 分析器崩溃、异常退出或输出损坏 |

批量扫描以翻译单元为隔离单位：每个 `.i/.ii` 只建立一次 AST，再分析其中全部候选函数。一个翻译单元失败不会中止其他任务。

## 数据语义

每条最终记录只包含：

```json
{
  "syscall": "openat2",
  "args": [-100, ".", {"pointee": {"flags": 0, "mode": 0, "resolve": 0}}, 24],
  "result": {"ret": {"op": ">=", "value": 0}}
}
```

结果来自源码中可关联的断言，不是内核行为证明。未知参数、分析不完整、断言无法规范化或结果约束冲突的调用不会进入 `records.jsonl`。

当前求值器支持常量、局部符号状态、结构体和数组初始化、有限循环、简单分支、少量直线 wrapper，以及展开后的常见 `EXPECT` / `ASSERT` 结构。它不支持任意循环、并发、一般跨函数控制流或 syscall 输出内存推导。

普通预处理输出会丢失宏调用身份，所以核心不会判断函数原来是否由某个测试框架宏生成。批量扫描只声明覆盖输入目录中实际存在的 artifact，不声明覆盖目标仓库全部源码或全部构建配置。

## 目录

- `src/main.cpp`：预处理翻译单元的 AST 解析和符号求值核心。
- `scan_artifacts.py`：通用 artifact 批量扫描、聚合和状态报告。
- `limit_worker.py`：分析子进程资源限制。
- `tests/fixtures.c`：只用于测试 artifact 生成和静态分析的微型输入。
- `tests/`：提取、target 识别、批量扫描和资源隔离测试。
