/* Executable fixtures: also analyzed, unchanged, using their real compile command. */
#include "probes.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct wrapper_result *wrapper_results;
size_t wrapper_result_capacity;

#define CAPTURE(index, value) do {                          \
  size_t capture_slot = (index);                          \
  long captured_result = (value);                         \
  int saved_errno = errno;                               \
  if (capture_slot >= wrapper_result_capacity ||          \
      wrapper_results[capture_slot].present) abort();     \
  wrapper_results[capture_slot].ret = captured_result;     \
  wrapper_results[capture_slot].error = saved_errno;       \
  wrapper_results[capture_slot].present = 1;              \
} while (0)
#define EXPECT_EQ(expected, actual) do {          \
  if (!((expected) == (actual))) abort();          \
} while (0)
#define EXPECT_GE(actual, minimum) do {           \
  if (!((actual) >= (minimum))) abort();           \
} while (0)

/* Setup is outside both the trace window and the analyzed top-level function. */
static void require(int condition) {
  if (!condition)
    _exit(110);
}

static void move_to_nine(int fd) {
  require(fd >= 0);
  if (fd != 9) {
    require(dup2(fd, 9) == 9);
    require(close(fd) == 0);
  }
}

static void prepare_fd(void) {
  move_to_nine(open("/dev/null", O_RDONLY));
}

static void prepare_write_fd(void) {
  move_to_nine(open("/dev/null", O_WRONLY));
}

static void prepare_file(void) {
  int fd = open("input", O_WRONLY | O_CREAT | O_EXCL, 0600);
  require(fd >= 0);
  require(write(fd, "abc", 3) == 3);
  require(close(fd) == 0);
}

static void prepare_directory(void) {
  prepare_file();
  move_to_nine(open(".", O_RDONLY | O_DIRECTORY));
}

static void prepare_pipe(void) {
  int fds[2];
  require(pipe(fds) == 0);
  require(write(fds[1], "abc", 3) == 3);
  require(close(fds[1]) == 0);
  move_to_nine(fds[0]);
}

void probe_direct_close(void) {
  long result = syscall(__NR_close, -1);
  CAPTURE(0, result);
  EXPECT_EQ(-1, result);
  EXPECT_EQ(EBADF, errno);
}

void probe_close_success(void) {
  int result = close(9);
  CAPTURE(0, result);
  EXPECT_EQ(0, result);
}

void probe_close_failure(void) {
  int result = close(-1);
  CAPTURE(0, result);
  EXPECT_EQ(-1, result);
  EXPECT_EQ(EBADF, errno);
}

void probe_eventfd(void) {
  int fd = eventfd(3, 0);
  CAPTURE(0, fd);
  EXPECT_GE(fd, 0);
}

void probe_open_nomode(void) {
  int fd = open("input", O_RDONLY);
  CAPTURE(0, fd);
  EXPECT_GE(fd, 0);
}

void probe_open_create(void) {
  int fd = open("created", O_WRONLY | O_CREAT | O_EXCL, 0640);
  CAPTURE(0, fd);
  EXPECT_GE(fd, 0);
}

void probe_open_ignored_mode(void) {
  int fd = open("input", O_RDONLY, 0777);
  CAPTURE(0, fd);
  EXPECT_GE(fd, 0);
}

void probe_open_missing(void) {
  int fd = open("missing", O_RDONLY);
  CAPTURE(0, fd);
  EXPECT_EQ(-1, fd);
  EXPECT_EQ(ENOENT, errno);
}

void probe_openat_nomode(void) {
  int fd = openat(9, "input", O_RDONLY);
  CAPTURE(0, fd);
  EXPECT_GE(fd, 0);
}

void probe_open_close(void) {
  int fd = open("input", O_RDONLY);
  CAPTURE(0, fd);
  if (fd < 0)
    return;
  int result = close(fd);
  CAPTURE(1, result);
  EXPECT_EQ(0, result);
}

void probe_direct_ioctl(void) {
  int available = 0;
  long result = syscall(__NR_ioctl, 9, FIONREAD, &available);
  CAPTURE(0, result);
  EXPECT_EQ(0, result);
}

void probe_ioctl(void) {
  int available = 0;
  int result = ioctl(9, FIONREAD, &available);
  CAPTURE(0, result);
  EXPECT_EQ(0, result);
}

void probe_ioctl_followup(void) {
  int available = 0;
  int result = ioctl(9, FIONREAD, &available);
  CAPTURE(0, result);
  EXPECT_EQ(0, result);
  int fd = eventfd((unsigned)available, 0);
  CAPTURE(1, fd);
  EXPECT_GE(fd, 0);
}

/* Proves that an empty trace is observable and is not a collector failure. */
void probe_no_syscall(void) {
  CAPTURE(0, 42);
}

/* Extension checks: a previously unknown syscall/buffer and >2 result slots. */
void probe_write_buffer(void) {
  ssize_t result = write(9, "abc", 3);
  CAPTURE(0, result);
  EXPECT_EQ(3, result);
}

void probe_close_three(void) {
  int first = close(9);
  CAPTURE(0, first);
  EXPECT_EQ(0, first);
  int second = close(9);
  CAPTURE(1, second);
  EXPECT_EQ(-1, second);
  EXPECT_EQ(EBADF, errno);
  int third = close(-1);
  CAPTURE(2, third);
  EXPECT_EQ(-1, third);
  EXPECT_EQ(EBADF, errno);
}

/* Kernel ABI descriptions used by the generic observer. Matching always uses
 * the actual syscall number (and optional command), never event order. */
static const struct wrapper_memory path_memory = {
    .type = "cstring", .phases = WRAPPER_ENTRY, .size = 256, .nullable = 1};
static const struct wrapper_memory available_memory = {
    .type = "s32", .phases = WRAPPER_ENTRY | WRAPPER_EXIT};
static const struct wrapper_memory write_memory = {
    .type = "bytes", .phases = WRAPPER_ENTRY, .length_arg = 3};

const struct wrapper_syscall wrapper_syscalls[] = {
    {.nr = __NR_close, .name = "close", .arg_count = 1, .args = {{"s32", NULL}}},
    {.nr = __NR_eventfd2, .name = "eventfd2", .arg_count = 2,
     .args = {{"u32", NULL}, {"s32", NULL}}},
    {.nr = __NR_openat, .name = "openat", .arg_count = 4,
     .args = {{"s32", NULL}, {"pointer", &path_memory}, {"s32", NULL}, {"u32", NULL}}},
    {.nr = __NR_ioctl, .name = "ioctl", .arg_count = 3,
     .args = {{"s32", NULL}, {"u32", NULL}, {"pointer", &available_memory}},
     .selector_arg = 2, .selector_mask = UINT32_MAX, .selector_value = FIONREAD},
    {.nr = __NR_write, .name = "write", .arg_count = 3,
     .args = {{"s32", NULL}, {"pointer", &write_memory}, {"u64", NULL}}},
};
const size_t wrapper_syscall_count = sizeof(wrapper_syscalls) / sizeof(wrapper_syscalls[0]);

#define PROBE(name, setup, count, ...) {                     \
  #name, name, setup, count,                                \
  (const char *const[]){__VA_ARGS__},                        \
  sizeof((const char *const[]){__VA_ARGS__}) / sizeof(char *), \
  64, 4096                                                  \
}
const struct wrapper_probe wrapper_probes[] = {
    PROBE(probe_direct_close, NULL, 1, "syscall"),
    PROBE(probe_close_success, prepare_fd, 1, "close"),
    PROBE(probe_close_failure, NULL, 1, "close"),
    PROBE(probe_eventfd, NULL, 1, "eventfd"),
    PROBE(probe_open_nomode, prepare_file, 1, "open"),
    PROBE(probe_open_create, NULL, 1, "open"),
    PROBE(probe_open_ignored_mode, prepare_file, 1, "open"),
    PROBE(probe_open_missing, NULL, 1, "open"),
    PROBE(probe_openat_nomode, prepare_directory, 1, "openat"),
    PROBE(probe_open_close, prepare_file, 2, "open", "close"),
    PROBE(probe_direct_ioctl, prepare_pipe, 1, "syscall"),
    PROBE(probe_ioctl, prepare_pipe, 1, "ioctl"),
    PROBE(probe_ioctl_followup, prepare_pipe, 2, "ioctl", "eventfd"),
    PROBE(probe_no_syscall, NULL, 1),
    PROBE(probe_write_buffer, prepare_write_fd, 1, "write"),
    PROBE(probe_close_three, prepare_fd, 3, "close"),
};
const unsigned wrapper_probe_count =
    sizeof(wrapper_probes) / sizeof(wrapper_probes[0]);
