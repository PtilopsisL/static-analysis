/* Analysis inputs only: these functions must never be linked or executed. */
#define __NR_pidfd_open 434
#define __NR_pidfd_getfd 438

extern long syscall(long number, ...);
extern int unknown_value(void);

#define TEST(name) static void name(void)
#define EXPECT_EQ(expected, seen)                                              \
  do {                                                                         \
    __typeof__(expected) __expected = (expected);                              \
    __typeof__(seen) __seen = (seen);                                          \
    if (!(__expected == __seen)) {                                             \
    }                                                                          \
  } while (0)

TEST(dependency_from_return_value) {
  long fd = syscall(__NR_pidfd_open, 100, 0);
  EXPECT_EQ(syscall(__NR_pidfd_getfd, fd, 3, 0), -1);
}

TEST(dependency_with_failure_guard) {
  long fd = syscall(__NR_pidfd_open, 200, 0);
  if (fd < 0)
    return;

  EXPECT_EQ(syscall(__NR_pidfd_getfd, fd, 4, 0), -1);
}

TEST(dependency_chain) {
  long pidfd = syscall(__NR_pidfd_open, 300, 0);
  long copied_fd = syscall(__NR_pidfd_getfd, pidfd, 5, 0);
  EXPECT_EQ(syscall(__NR_pidfd_getfd, copied_fd, 6, 0), -1);
}

TEST(dependency_multiple_resources) {
  long first_fd = syscall(__NR_pidfd_open, 400, 0);
  long second_fd = syscall(__NR_pidfd_open, 401, 0);
  EXPECT_EQ(syscall(__NR_pidfd_getfd, first_fd, second_fd, 0), -1);
}

TEST(dependency_with_argument_domain) {
  long fd = syscall(__NR_pidfd_open, 500, 0);
  int target_fd = unknown_value();

  if (0 < target_fd && target_fd <= 8)
    EXPECT_EQ(syscall(__NR_pidfd_getfd, fd, target_fd, 0), -1);
}

TEST(dependency_through_alias) {
  long fd = syscall(__NR_pidfd_open, 600, 0);
  int alias = (int)fd;
  EXPECT_EQ(syscall(__NR_pidfd_getfd, alias, 7, 0), -1);
}

TEST(reassignment_removes_dependency) {
  long fd = syscall(__NR_pidfd_open, 700, 0);
  fd = 8;
  EXPECT_EQ(syscall(__NR_pidfd_getfd, fd, 9, 0), -1);
}

TEST(dependency_different_setups_stay_separate) {
  long fd;
  if (unknown_value())
    fd = syscall(__NR_pidfd_open, 800, 0);
  else
    fd = syscall(__NR_pidfd_open, 801, 0);

  EXPECT_EQ(syscall(__NR_pidfd_getfd, fd, 10, 0), -1);
}
