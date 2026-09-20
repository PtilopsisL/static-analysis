/*
 * Analysis-only LTP semantic contracts.  This is a deliberately small,
 * self-contained subset of the current LTP macros; it must not be linked or
 * executed.  Keeping the macro control flow here is important because the
 * extractor sees the expansion rather than a normalized assertion.
 */
#define __NR_pidfd_getfd 438
#define EINVAL 22
#define ENOSYS 38
#define errno (*__errno_location())

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);

extern long TST_RET;
extern int TST_ERR;
extern int TST_PASS;

enum tst_res_flags {
  TPASS = 0,
  TFAIL = 1,
  TBROK = 2,
  TWARN = 4,
  TINFO = 16,
  TCONF = 32,
  TERRNO = 0x100,
  TTERRNO = 0x200,
};

extern void tst_res_(const char *file, int line, int type,
                     const char *format, ...);
extern void tst_brk_(const char *file, int line, int type,
                     const char *format, ...);
extern int tst_errno_in_set(int error, const int *expected, int count);

#define tst_res(type, format, ...)                                            \
  tst_res_(__FILE__, __LINE__, (type), (format), ##__VA_ARGS__)
#define tst_brk(type, format, ...)                                            \
  tst_brk_(__FILE__, __LINE__, (type), (format), ##__VA_ARGS__)

#define TEST(call)                                                            \
  do {                                                                        \
    errno = 0;                                                                \
    TST_RET = (call);                                                         \
    TST_ERR = errno;                                                          \
  } while (0)

#define TST_EXP_PASS(call)                                                    \
  do {                                                                        \
    TEST(call);                                                               \
    TST_PASS = 0;                                                             \
    if (TST_RET == -1) {                                                      \
      tst_res(TFAIL | TTERRNO, "call failed");                              \
      break;                                                                  \
    }                                                                         \
    if (TST_RET != 0) {                                                       \
      tst_res(TFAIL | TTERRNO, "invalid return value");                     \
      break;                                                                  \
    }                                                                         \
    TST_PASS = 1;                                                             \
    tst_res(TPASS, "call passed");                                          \
  } while (0)

#define TST_EXP_POSITIVE(call)                                                \
  do {                                                                        \
    TEST(call);                                                               \
    TST_PASS = 0;                                                             \
    if (TST_RET == -1) {                                                      \
      tst_res(TFAIL | TTERRNO, "call failed");                              \
      break;                                                                  \
    }                                                                         \
    if (TST_RET < 0) {                                                        \
      tst_res(TFAIL | TTERRNO, "invalid return value");                     \
      break;                                                                  \
    }                                                                         \
    TST_PASS = 1;                                                             \
    tst_res(TPASS, "call returned a non-negative value");                   \
  } while (0)

#define TST_EXP_FAILURE(call, expected_error, success_condition)              \
  do {                                                                        \
    int expected_error__ = (expected_error);                                  \
    TEST(call);                                                               \
    TST_PASS = 0;                                                             \
    if (success_condition) {                                                  \
      tst_res(TFAIL, "call succeeded");                                     \
      break;                                                                  \
    }                                                                         \
    if (TST_RET != -1) {                                                      \
      tst_res(TFAIL | TTERRNO, "invalid return value");                     \
      break;                                                                  \
    }                                                                         \
    if (!tst_errno_in_set(TST_ERR, &expected_error__, 1)) {                   \
      tst_res(TFAIL | TTERRNO, "unexpected errno");                         \
      break;                                                                  \
    }                                                                         \
    TST_PASS = 1;                                                             \
    tst_res(TPASS | TTERRNO, "call failed as expected");                    \
  } while (0)

#define TST_EXP_FAIL(call, expected_error)                                    \
  TST_EXP_FAILURE(call, expected_error, TST_RET == 0)
#define TST_EXP_FAIL2(call, expected_error)                                   \
  TST_EXP_FAILURE(call, expected_error, TST_RET >= 0)

#define TST_EXP_EQ_LI(left, right)                                            \
  do {                                                                        \
    long long left__ = (left);                                                \
    long long right__ = (right);                                              \
    if (left__ != right__)                                                    \
      tst_res(TFAIL, "values differ");                                      \
    else                                                                      \
      tst_res(TPASS, "values are equal");                                   \
  } while (0)

#define TST_EXP_EXPR(expression)                                              \
  tst_res((expression) ? TPASS : TFAIL, "expression result")

/* Matches the relevant control flow of LTP's generated tst_syscall macro. */
#define tst_syscall(number, ...)                                              \
  ({                                                                          \
    long syscall_result__;                                                    \
    if ((number) == -1) {                                                     \
      errno = ENOSYS;                                                         \
      syscall_result__ = -1;                                                  \
    } else {                                                                  \
      syscall_result__ = syscall((number), ##__VA_ARGS__);                    \
    }                                                                         \
    if (syscall_result__ == -1 && errno == ENOSYS)                            \
      tst_brk(TCONF, "syscall is not supported");                           \
    syscall_result__;                                                         \
  })

static void ltp_exp_pass(void) {
  TST_EXP_PASS(syscall(__NR_pidfd_getfd, 701, 70, 0));
}

static void ltp_exp_positive(void) {
  TST_EXP_POSITIVE(syscall(__NR_pidfd_getfd, 702, 71, 0));
}

static void ltp_exp_fail(void) {
  TST_EXP_FAIL(syscall(__NR_pidfd_getfd, 703, 72, 0), EINVAL);
}

static void ltp_exp_fail2(void) {
  TST_EXP_FAIL2(syscall(__NR_pidfd_getfd, 704, 73, 0), EINVAL);
}

static void ltp_test_result_and_errno(void) {
  TEST(syscall(__NR_pidfd_getfd, 705, 74, 0));
  if (TST_RET != -1) {
    tst_res(TFAIL, "unexpected return value");
    return;
  }
  if (TST_ERR != EINVAL) {
    tst_res(TFAIL | TTERRNO, "unexpected errno");
    return;
  }
  tst_res(TPASS | TTERRNO, "failed as expected");
}

static void ltp_tst_brk_failure_guard(void) {
  TEST(syscall(__NR_pidfd_getfd, 706, 75, 0));
  if (TST_RET < 0)
    tst_brk(TBROK | TTERRNO, "unexpected syscall failure");
  tst_res(TPASS, "call passed");
}

static void ltp_exp_eq_li(void) {
  long result = syscall(__NR_pidfd_getfd, 707, 76, 0);
  TST_EXP_EQ_LI(result, -1);
}

static void ltp_exp_expr(void) {
  long result = syscall(__NR_pidfd_getfd, 708, 77, 0);
  TST_EXP_EXPR(result != -1);
}

static void ltp_tst_syscall_fail(void) {
  TST_EXP_FAIL(tst_syscall(__NR_pidfd_getfd, 709, 78, 0), EINVAL);
}

/* Informational and configuration results must not become test assertions. */
static void ltp_info_is_not_assertion(void) {
  long result = syscall(__NR_pidfd_getfd, 710, 79, 0);
  tst_res(TINFO, "observed result %ld", result);
}

static void ltp_tconf_is_not_failure(void) {
  long result = syscall(__NR_pidfd_getfd, 711, 80, 0);
  if (result == -1)
    tst_brk(TCONF | TTERRNO, "optional operation is unsupported");
}
