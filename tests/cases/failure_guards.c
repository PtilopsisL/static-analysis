/* Analysis cases expressed as branches whose other arm is a known failure. */
#define __NR_pidfd_getfd 438
#define EINVAL 22
#define KSFT_FAIL 1
#define errno (*__errno_location())

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);
extern void ksft_exit_fail_msg(const char *format, ...)
    __attribute__((noreturn));
extern void abort(void) __attribute__((noreturn));
extern void test__fail(void);

static void ksft_failure_guard(void) {
  long result = syscall(__NR_pidfd_getfd, 201, 20, 0);
  if (result != -1)
    ksft_exit_fail_msg("pidfd_getfd unexpectedly succeeded");
  if (errno != EINVAL)
    ksft_exit_fail_msg("unexpected errno");
}

static void abort_failure_guard(void) {
  long result = syscall(__NR_pidfd_getfd, 202, 21, 0);
  if (result < 0)
    abort();
}

static int failure_return_guard(void) {
  long result = syscall(__NR_pidfd_getfd, 203, 22, 0);
  if (result != 0) {
    test__fail();
    return KSFT_FAIL;
  }
  return 0;
}

static void direct_syscall_guard(void) {
  if (syscall(__NR_pidfd_getfd, 204, 23, 0) == -1)
    ksft_exit_fail_msg("pidfd_getfd unexpectedly failed");
}
