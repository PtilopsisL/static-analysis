/* Analysis inputs only: these functions must never be linked or executed. */
#define __NR_pidfd_open 434
#define __NR_pidfd_getfd 438
#define __NR_openat2 437
#define EIO 5
#define ESRCH 3
#define EINVAL 22
#define KSFT_FAIL 1
#define errno (*__errno_location())

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);
extern int fprintf(void *stream, const char *format, ...);
extern int puts(const char *string);
extern void *stderr;

struct open_how {
  unsigned long long flags;
  unsigned long long mode;
  unsigned long long resolve;
};

#define TEST(name) static void name(void)
#define EXPECT_OP(expected, seen, op)                                      \
  do {                                                                    \
    __typeof__(expected) __exp = (expected);                              \
    __typeof__(seen) __seen = (seen);                                     \
    if (!(__exp op __seen)) {                                             \
    }                                                                     \
  } while (0)
#define EXPECT_EQ(expected, seen) EXPECT_OP(expected, seen, ==)
#define ASSERT_EQ(expected, seen) EXPECT_EQ(expected, seen)
#define EXPECT_GE(expected, seen) EXPECT_OP(expected, seen, >=)
#define TH_LOG(message)                                                    \
  do {                                                                    \
    if (1)                                                                \
      fprintf(stderr, "# %s:%d:%s:" message, __FILE__, __LINE__, __func__); \
  } while (0)

extern void unrelated_call(void);
extern int unknown_value(void);
extern void mutate(int *value);
extern void abort(void) __attribute__((noreturn));
extern void exit_success(void) __attribute__((noreturn));
extern void ksft_test_result(int condition, const char *format, ...);

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
  if (ret < 0) {
    TH_LOG("expected failure");
    EXPECT_EQ(errno, EINVAL);
  }
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

#ifdef COMPDB_PIDFD
TEST(command_line_define) {
  EXPECT_EQ(getfd(COMPDB_PIDFD, 0, 1), -1);
}
#endif


/* Correctness regressions: these cases must not be weakened into false records. */
TEST(compound_constraint_strengthening) {
  long ret = getfd(600, 0, 0);
  ksft_test_result(ret >= 0 && ret >= 1, "stronger lower bound\n");
}

TEST(unrepresentable_range) {
  long ret = getfd(601, 0, 0);
  ksft_test_result(ret >= 0 && ret < 10, "bounded range\n");
}

TEST(unconstrained_success_alternative) {
  long ret = getfd(602, 0, 0);
  ksft_test_result(ret == 0 || 1, "always succeeds\n");
}

TEST(reassigned_predicate_variable) {
  long ret = getfd(603, 0, 0);
  int ok = ret == 0;
  ok = 1;
  if (!ok)
    abort();
}

TEST(assertion_temporary_lookalike) {
  long __exp = getfd(604, 0, 0);
  long __seen = 0;
  if (!(__exp == __seen)) {
  }
}

TEST(nested_possible_failure) {
  long ret = getfd(605, 0, 0);
  if (ret != 0) {
    if (unknown_value())
      abort();
  }
}

static void unmodeled_syscall_number(long number) {
  long ret = getfd(606, 0, 0);
  EXPECT_EQ(ret, -1);
  syscall(number, 0);
  EXPECT_EQ(errno, EINVAL);
}

TEST(unsigned_cast_ordering) {
  unsigned long ret = (unsigned long)getfd(607, 0, 0);
  ksft_test_result(ret < 5, "unsigned result is small\n");
}

static int compound_failure_condition(long gate) {
  long ret = getfd(608, 0, 0);
  if (ret != 0 && gate)
    return KSFT_FAIL;
  return 0;
}

static int both_branches_fail(void) {
  long ret = getfd(609, 0, 0);
  if (ret == 0)
    return KSFT_FAIL;
  else
    return KSFT_FAIL;
}

TEST(predicate_reassigned_after_assertion) {
  long ret = getfd(610, 0, 0);
  int ok = ret == 0;
  if (!ok)
    abort();
  ok = 1;
}

TEST(definite_failure_via_cfg) {
  long ret = getfd(611, 0, 0);
  if (ret != 0) {
    if (unknown_value())
      puts("first path");
    else
      puts("second path");
    abort();
  }
}

TEST(predicate_invalidated_by_opaque_write) {
  long ret = getfd(612, 0, 0);
  int ok = ret == 0;
  mutate(&ok);
  if (!ok)
    abort();
}

TEST(unknown_noreturn_is_not_failure) {
  long ret = getfd(613, 0, 0);
  if (ret != 0)
    exit_success();
}

TEST(predicate_assignment_tracks_new_value) {
  long ret = getfd(614, 0, 0);
  int ok = 1;
  ok = ret == 0;
  if (!ok)
    abort();
}
