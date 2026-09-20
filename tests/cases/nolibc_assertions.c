/* Analysis cases expressed through nolibc-style assertion helpers. */
#define __NR_pidfd_getfd 438
#define EFAULT 14
#define errno (*__errno_location())

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);
extern void nolibc_test_failure(void);

static int expect_syseq(long expression, long expected) {
  int failed = expression != expected;
  if (failed)
    nolibc_test_failure();
  return failed;
}

static int expect_syszr(long expression) {
  int failed = expression != 0;
  if (failed)
    nolibc_test_failure();
  return failed;
}

static int expect_syserr(long expression, long expected, int expected_errno) {
  int saved_errno = errno;
  int failed = expression != expected || saved_errno != expected_errno;
  if (failed)
    nolibc_test_failure();
  return failed;
}

#define EXPECT_SYSEQ(condition, expression, expected) \
  do {                                                \
    if (condition)                                    \
      expect_syseq((expression), (expected));         \
  } while (0)

#define EXPECT_SYSZR(condition, expression) \
  do {                                      \
    if (condition)                          \
      expect_syszr((expression));           \
  } while (0)

#define EXPECT_SYSER(condition, expression, expected, expected_errno) \
  do {                                                                  \
    if (condition)                                                      \
      expect_syserr((expression), (expected), (expected_errno));        \
  } while (0)

static void nolibc_equal(void) {
  EXPECT_SYSEQ(1, syscall(__NR_pidfd_getfd, 501, 50, 0), -1);
}

static void nolibc_zero(void) {
  EXPECT_SYSZR(1, syscall(__NR_pidfd_getfd, 502, 51, 0));
}

static void nolibc_error(void) {
  EXPECT_SYSER(1, syscall(__NR_pidfd_getfd, 503, 52, 0), -1, EFAULT);
}
