/* Analysis inputs only: these functions must never be linked or executed. */
#define __NR_pidfd_getfd 438

extern long syscall(long number, ...);
extern int unknown_value(void);

#define TEST(name) static void name(void)
#define EXPECT_EQ(expected, seen)                                         \
  do {                                                                    \
    __typeof__(expected) __expected = (expected);                          \
    __typeof__(seen) __seen = (seen);                                     \
    if (!(__expected == __seen)) {                                        \
    }                                                                     \
  } while (0)

static long getfd(int pidfd, int fd, unsigned flags) {
  return syscall(__NR_pidfd_getfd, pidfd, fd, flags);
}

TEST(argument_loop_range) {
  for (int pidfd = 0; pidfd < 5; pidfd++)
    EXPECT_EQ(getfd(pidfd, 0, 1), -1);
}

TEST(argument_strict_open_range) {
  int pidfd = unknown_value();
  if (0 < pidfd && pidfd < 10)
    EXPECT_EQ(getfd(pidfd, 0, 1), -1);
}

TEST(argument_mixed_open_closed_range) {
  int pidfd = unknown_value();
  if (0 <= pidfd && pidfd < 10)
    EXPECT_EQ(getfd(pidfd, 0, 1), -1);
}

TEST(argument_equality_stays_concrete) {
  int pidfd = unknown_value();
  long ret = getfd(pidfd, 0, 1);
  if (pidfd == 5)
    EXPECT_EQ(ret, -1);
}

TEST(argument_not_equal_constraint) {
  int pidfd = unknown_value();
  if (pidfd != 5)
    EXPECT_EQ(getfd(pidfd, 0, 1), -1);
}

TEST(argument_disjoint_ranges) {
  int pidfd = unknown_value();
  if (pidfd < 0 || pidfd > 10)
    EXPECT_EQ(getfd(pidfd, 0, 1), -1);
}

TEST(argument_range_result_correlation) {
  int pidfd = unknown_value();
  long ret = getfd(pidfd, 0, 1);
  if (0 < pidfd && pidfd < 10)
    EXPECT_EQ(ret, -1);
  else if (20 <= pidfd && pidfd <= 30)
    EXPECT_EQ(ret, 0);
}

TEST(argument_range_is_narrowed_at_assertion) {
  int pidfd = unknown_value();
  if (0 <= pidfd && pidfd <= 10) {
    long ret = getfd(pidfd, 0, 1);
    if (pidfd == 5)
      EXPECT_EQ(ret, -1);
  }
}

TEST(argument_discrete_values_stay_concrete) {
  int pidfd = unknown_value();
  long ret = getfd(pidfd, 0, 1);
  if (pidfd == 1 || pidfd == 2 || pidfd == 4 || pidfd == 8 || pidfd == 16)
    EXPECT_EQ(ret, -1);
}

TEST(argument_values_and_range_union) {
  int pidfd = unknown_value();
  if (pidfd == 1 || pidfd == 2 || pidfd == 4 || pidfd == 8 ||
      (20 < pidfd && pidfd <= 30))
    EXPECT_EQ(getfd(pidfd, 0, 1), -1);
}
