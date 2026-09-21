/* Analysis cases only: these functions must never be linked or executed. */
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

struct predicate_box {
  int ok;
};

#define TEST(name) static void name(void)
#define EXPECT_OP(expected, seen, op)                                      \
  do {                                                                    \
    __typeof__(expected) __exp = (expected);                              \
    __typeof__(seen) __seen = (seen);                                     \
    if (!(__exp op __seen)) {                                             \
      test__fail();                                                       \
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
extern void mutate_predicate_box(struct predicate_box *box);
extern void abort(void) __attribute__((noreturn));
extern void exit_success(void) __attribute__((noreturn));
extern void test__fail(void);
extern void test__report_pass(void);
extern void test__report_fail(void);

#define ksft_test_result(condition, format, ...)                           \
  do {                                                                    \
    (void)(format);                                                       \
    if (condition)                                                        \
      test__report_pass();                                                \
    else                                                                  \
      test__report_fail();                                                \
  } while (0)

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
  if (ret != 0 && gate) {
    test__fail();
    return KSFT_FAIL;
  }
  return 0;
}

static int both_branches_fail(void) {
  long ret = getfd(609, 0, 0);
  if (ret == 0) {
    test__fail();
    return KSFT_FAIL;
  } else {
    test__fail();
    return KSFT_FAIL;
  }
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

TEST(domain_refinement_becomes_projectable) {
  long ret = getfd(615, 0, 0);
  ksft_test_result(ret >= 0 && ret < 10 && ret == 5,
                   "bounded result is refined to a point\n");
}

TEST(clang_path_constraint_strengthens_assertion) {
  long ret = getfd(616, 0, 0);
  if (ret >= 1)
    ksft_test_result(ret >= 0, "non-negative result\n");
}

TEST(clang_selects_feasible_disjunct) {
  long ret = getfd(617, 0, 0);
  if (ret >= 2)
    ksft_test_result(ret == 1 || ret == 2, "expected result alternative\n");
}

TEST(clang_unions_success_paths) {
  long ret = getfd(618, 0, 0);
  ksft_test_result(ret < 0 || ret == 0, "expected non-positive result\n");
}

TEST(success_paths_preserve_result_errno_correlation) {
  long ret = getfd(619, 0, 0);
  ksft_test_result((ret == -1 && errno == EINVAL) ||
                       (ret == -2 && errno == EIO),
                   "expected correlated failure\n");
}

TEST(errno_range_uses_integer_type_limits) {
  getfd(620, 0, 0);
  ksft_test_result(errno != 0, "expected non-zero errno\n");
}

TEST(short_circuit_eval_site_is_fresh) {
  for (int i = 0; i < 2; ++i) {
    long ret = getfd(621 + i, 0, 0);
    int ok = ret != 0 || ret == 0;
    if (i == 1)
      ksft_test_result(ok, "tautology remains independent of prior event\n");
  }
}

TEST(field_predicate_tracks_event) {
  long ret = getfd(623, 0, 0);
  struct predicate_box box;
  box.ok = ret == 0;
  if (!box.ok)
    abort();
}

TEST(parent_write_invalidates_field_provenance) {
  long ret = getfd(624, 0, 0);
  struct predicate_box box;
  box.ok = ret == 0;
  mutate_predicate_box(&box);
  if (!box.ok)
    abort();
}

TEST(whole_object_write_invalidates_field_provenance) {
  long ret = getfd(625, 0, 0);
  struct predicate_box box;
  box.ok = ret == 0;
  box = (struct predicate_box){.ok = 1};
  if (!box.ok)
    abort();
}

TEST(array_element_predicate_tracks_event) {
  long ret = getfd(626, 0, 0);
  int ok[2];
  ok[1] = ret == 0;
  if (!ok[1])
    abort();
}
