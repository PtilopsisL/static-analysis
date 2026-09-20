# libc wrapper 运行对照测试

这是独立的实验测试目录。它不修改提取器，也不执行 `tests/cases/` 中的输入。
目前支持原生 Linux x86-64 LP64、glibc、Clang，以及支持
`PTRACE_GET_SYSCALL_INFO` 的内核（Linux 5.3+）。只跟踪测试自己创建的子进程，
不使用 sudo；如果沙箱禁止 ptrace，需要在允许 ptrace 的环境中运行。

## 运行

仅验证真实 libc 行为与独立测试契约的一致性：

```sh
python3 -B tests/wrappers/run.py
```

同时严格检查静态分析结果：

```sh
python3 -B tests/wrappers/run.py --check-analysis \
  --extractor build/syscall-extract \
  --output /tmp/libc-wrapper-analysis
```

`--output` 必须是尚不存在的目录；省略时在 `/tmp` 下创建并打印产物位置。
当前提取器尚未实现 libc wrapper，因此第二条命令应报告 wrapper 的缺失记录，
并以非零状态退出。这不是预期失败豁免，后续实现必须让这些检查通过。

单个用例、固定 libc 二进制身份，以及比较器的反例测试：

```sh
python3 -B tests/wrappers/run.py --case probe_open_create
python3 -B tests/wrappers/run.py --libc-sha256 PREVIOUS_LIBC_SHA256
python3 -B -m unittest discover -s tests/wrappers -p 'test_*.py' -v
```

指纹取自上一次 `summary.json` 的 `environment.libc.libc_sha256`。
不传指纹时，测试测量并记录本次实际 libc；这不表示所有 glibc 版本都被认证。
目录没有 `__init__.py`，因此现有顶层 unittest discovery 不会隐式执行这些实验。

## 测试如何工作

- `probes.c` 使用真实头文件，每个 `probe_*` 函数就是静态分析的入口。
  用例准备在独立函数中执行：创建临时文件、准备 fd 9 或含三个字节的 pipe。
  所有文件创建都发生在运行器新建的对应测试工作目录。
- `run.py` 真正执行 Clang 编译命令，并把原命令写入 compilation database。
  同一份源码、宏、target、语言选项和 include 环境被交给提取器。
  当前固定 `-O0 -fno-builtin`；该配置本身也是测试适用范围的一部分。
- `trace.c` 在 fork 后的子进程中，用两个地址经过校验的 `int3` 边界限定待测函数。
  父进程记录区间内的全部 syscall，不按期望名字筛选。
  程序启动、fixture 准备和退出不进入区间；立即绑定避免首次 PLT 解析混入测量。
- syscall 入口记录编号、六个原始参数槽以及受支持的内存快照；出口记录内核原始
  返回值及内存变化。采集规则由 `probes.c` 声明，例如路径在入口读取、
  `FIONREAD` 的整数在入口和出口读取；原始快照保存为十六进制字节，不保存期望值。
  wrapper 结果和 errno 由 probe 立即保存，父进程在结束边界读取。
- `compare.py` 根据编译后的 syscall 描述解码，没有 syscall 名称表，也不导入提取器模型。
  它比较有意义的参数位、字符串内容、入/出内存、原始结果、wrapper 结果和 fd 绑定。
  未使用的参数槽、32 位参数的高位和随机指针地址不作为语义差异。
- `cases.json` 分别给出运行契约与静态 records。静态结果必须精确匹配，防止一个
  实测成功值让错误的宽泛范围也通过。`records` 非空就必须提取出对应记录；
  `records: []` 明确要求无记录。三个预期列表都必须提供，不能省略检查。

两组直接 `syscall()` 用例校验错误转换和内存观测；无 syscall 用例校验空窗口。
wrapper 用例覆盖 close 成败、eventfd 改名、open/openat 参数补充、显式 mode、
无用 mode 的忽略、ENOENT、open→close 依赖，以及 ioctl 输出被后续 eventfd 使用。
最后一个用例中，静态入口看不到 pipe 准备过程，因此应只提取有依据的 ioctl 记录，
不能把初始化的 0 沿用成 eventfd 参数，也不能从本次运行反推常量 3。
扩展验收用例还覆盖 `write` 输入缓冲区，以及同一 probe 中连续三次 `close` 的返回值。

比较器反例测试会改错 syscall、mode、fd 依赖、errno、内存阶段和静态范围，
并确认额外调用、缺失记录、重复记录、快照不完整和 libc 身份不匹配无法通过。

## 新增样例：只修改两个文件

在现有观测能力范围内，只需修改 `probes.c` 和 `cases.json`，不需要改
`probes.h`、`trace.c`、`compare.py`、`run.py` 或逐个补充 Python 测试。

1. 在 `probes.c` 写 `probe_*`，立即用 `CAPTURE(槽位, 返回值)` 保存每次 wrapper
   的结果，用 `EXPECT_EQ` / `EXPECT_GE` 写需要静态提取的断言。槽位从 0 连续编号；
   重复写入、越界会终止测试，漏写会在比较时失败。准备工作放入独立的 prepare 函数。
2. 在同一文件的 `wrapper_probes` 中添加 `PROBE(函数名, prepare或NULL, 返回值数量,
   "被测libc符号", ...)`。例如三次调用用数量 3；无被测符号时省略最后的符号参数。
   返回值存储按声明动态分配，不再固定两个槽位。必须列全实际被测的 libc 符号；
   runner 检查这些符号是否来自本次识别的 libc，但不会自动从 C 函数体推断符号列表。
3. 若涉及新的内核 syscall 或新的参数布局，在同一文件的 `wrapper_syscalls` 中
   声明编号（用 `__NR_*`）、名称、有效参数个数和类型；已有布局直接复用。
   这是内核 ABI / 内存读取描述，不是“某 wrapper 应当调用什么”的转换模型。
4. 在 `cases.json` 添加同名对象，保留三个预期列表：`events` 是内核调用及内存变化，
   `returns` 是 wrapper 返回值及 errno，`records` 是静态提取器应输出的记录。
   运行器会检查整个注册表和 JSON 键名一一对应，以及声明的返回值数量是否一致；
   即使使用 `--case`，也不会跳过注册完整性检查。

例如 `write` 的内核布局只需在 `probes.c` 中声明：

```c
static const struct wrapper_memory write_memory = {
    .type = "bytes", .phases = WRAPPER_ENTRY, .length_arg = 3};
/* 添加到 wrapper_syscalls 数组中： */
{.nr = __NR_write, .name = "write", .arg_count = 3,
 .args = {{"s32", NULL}, {"pointer", &write_memory}, {"u64", NULL}}},
```

长度索引 `length_arg` 从 1 开始，这里由第 3 个实际参数决定读取长度；0 表示固定 `size`。
运行时 `write(9, "abc", 3)` 对应的预期参数是
`[9, {"before": {"hex": "616263"}}, 3]`，没有把指针地址或字符串终止符当作传入字节。

可用的通用描述：

- 参数：`s32` / `u32` / `s64` / `u64` / `pointer`；仅对声明了 memory 的指针读取内容。
- 内存：四种整数、`cstring`、`bytes`、`struct`；`phases` 选择入口、出口或两者。
  `cstring` 的 `size` 是包含终止符的扫描上限，解码为 UTF-8；任意二进制内容使用 `bytes`。
  仅入口字符串规范化为字符串；其他快照保留 `before` / `after`，二进制值使用 `{"hex": "..."}`。
- `bytes` 支持固定长度或从无符号参数取长度；`limit_to_result = 1` 把出口长度再限制为
  `min(缓冲区长度, max(实际内核返回值, 0))`，适合只观测 `read` 写出的有效字节。
- `struct` 使用真实 C 类型的 `sizeof` 和 `offsetof` 指定字段布局；字段可以是整数或固定字节。
  原始快照包含完整结构体，比较时只解码显式声明的字段，不比较填充字节。
- `nullable = 1` 允许空指针并记录为 JSON null 快照、规范化为数值 0，不虚构内存内容。
- 同一 syscall 的不同命令可用 `selector_arg`、`selector_mask`、`selector_value` 区分，
  参数索引从 1 开始。匹配依据是实际编号和实际参数，不是 JSON 期望或事件位置。

`PROBE` 的默认上限是 64 个事件、每个快照 4096 字节；需要调整时只需在 `probes.c`
更改该宏，或用 `struct wrapper_probe` 显式初始化单个样例的上限。
新 syscall 没有描述、描述匹配歧义、快照缺失或越界都会失败，不会被静默忽略。
ABI 描述和 JSON 预期都需要人工审核；它们本身也可能写错，运行通过不能替代审核。

## 产物与状态

每次运行保留 `summary.json`、独立契约快照、编译数据库及构建命令。
编译出的 observer 通过 `--describe` 导出注册表、符号和采集描述，保存为 `description.json`；
原始跟踪使用 schema 2，并携带相同的 layouts，运行器会检查两者一致。
每个用例保存原始跟踪、规范化事件、运行进程诊断，以及开启静态对照时的分析输出。
summary 记录源码/二进制 SHA-256、编译器、内核、实际 libc 版本、符号来源和已加载
对象的 SHA-256（包括动态加载器；vDSO 不作为磁盘对象散列）。

运行失败、意外信号、区间未完成、读取失败和达到事件/字符串/时间上限均不会通过。
运行器为进程组设置超时；采集器还设置父进程死亡信号和 `PTRACE_O_EXITKILL`。

`runtime_only_passed` 只表示运行契约通过，静态状态明确为 `not_run`。
只有启用 `--check-analysis` 且两个层面都通过，整体状态才是 `passed`。
任何请求执行的检查失败都会导致非零退出码，不自动更新预期，也不把环境故障记为通过。

## 范围与后续

这是固定输入、单线程、正常返回 wrapper 的可重复观测，不是全输入形式化证明。
目前可描述整数、字符串、平坦字节缓冲区和固定布局结构体；不支持一般指针图、32 位 ABI、
取消点竞态、线程创建、信号重启或 vDSO 分支控制。`O_TMPFILE` 和错误注入也尚未覆盖，
需要另加样例或相应观测机制，不能由当前结果推断。涉及新机制时仍可能需要
扩展测试基础设施，“只改两个文件”不意味着已经能覆盖所有 libc 接口。

当前 x86-64/glibc 契约的审核依据包括 glibc 的
[open64 实现](https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/open64.c)、
[openat 实现](https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/openat.c) 和
[syscalls.list](https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/syscalls.list)。
这些上游链接用于说明模型来源，本次实际执行对象以记录的本机二进制指纹为准。
采集接口参考 [ptrace 文档](https://man7.org/linux/man-pages/man2/ptrace.2.html)。
