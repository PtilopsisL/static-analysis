/* Analysis inputs only: these functions must never be compiled and executed. */
#define _GNU_SOURCE
#include "kselftest_harness.h"
#include <errno.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

extern void unrelated_call(void);
extern int unknown_value(void);
extern void mutate(int *value);

static long getfd(int pidfd, int fd, unsigned flags) {
  return syscall(__NR_pidfd_getfd, pidfd, fd, flags);
}

static long normalized(int pid, unsigned flags) {
  long ret = syscall(__NR_pidfd_open, pid, flags);
  return ret >= 0 ? ret : -errno;
}

TEST(constant_error) {
  ASSERT_EQ(-1, getfd(0, 0, 1));
  EXPECT_EQ(errno, EINVAL);
}

TEST(guarded_error) {
  long ret = getfd(0, 0, 1);
  if (ret < 0)
    EXPECT_EQ(errno, EINVAL);
}

TEST(stale_errno) {
  long ret = getfd(0, 0, 1);
  EXPECT_EQ(ret, -1);
  unrelated_call();
  EXPECT_EQ(errno, EIO);
}

TEST(table_pairs) {
  struct sample {
    int pid;
    unsigned flags;
    int error;
  } cases[] = {
      {.pid = -1, .flags = 0, .error = -EINVAL},
      {.pid = 123, .flags = 1, .error = -ESRCH},
      {.pid = 456, .flags = 0},
  };
  for (int i = 0; i < 3; i++) {
    struct sample *sample = &cases[i];
    long ret = normalized(sample->pid, sample->flags);
    if (sample->error < 0) {
      EXPECT_EQ(sample->error, ret);
    } else {
      EXPECT_GE(ret, 0);
    }
  }
}

TEST(unknown_argument) {
  int pidfd = unknown_value();
  ASSERT_EQ(-1, getfd(pidfd, 0, 1));
}

TEST(opaque_pointer_write) {
  int pidfd = 123;
  mutate(&pidfd);
  ASSERT_EQ(-1, getfd(pidfd, 0, 1));
}

TEST(unsigned_flag) {
  struct open_how how = {.flags = 1ULL << 63};
  long ret = syscall(__NR_openat2, -100, ".", &how, sizeof(how));
  EXPECT_EQ(ret, -1);
  EXPECT_EQ(errno, EINVAL);
}

TEST(limited_loop) {
  for (int i = 0; i < 5; i++)
    EXPECT_EQ(getfd(i, 0, 1), -1);
}

TEST(unsupported_control) {
  EXPECT_EQ(getfd(0, 0, 1), -1);
  while (unknown_value())
    unrelated_call();
}

TEST(separate_calls) {
  long first = getfd(1, 2, 1);
  long second = getfd(3, 4, 1);
  EXPECT_EQ(first, -1);
  EXPECT_EQ(second, -1);
  EXPECT_EQ(errno, EINVAL);
}

TEST(reassignment) {
  int pidfd = 1;
  pidfd = 9;
  EXPECT_EQ(getfd(pidfd, 0, 1), -1);
}
