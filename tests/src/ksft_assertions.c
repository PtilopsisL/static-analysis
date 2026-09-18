/* Expected records expressed through the non-harness kselftest API. */
#define __NR_pidfd_getfd 438
#define EINVAL 22
#define errno (*__errno_location())

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);
extern void ksft_test_result(int condition, const char *format, ...);

static void ksft_equality(void) {
  long result = syscall(__NR_pidfd_getfd, 301, 30, 0);
  ksft_test_result(result == 0, "pidfd_getfd returns zero\n");
}

static void ksft_ordering(void) {
  long result = syscall(__NR_pidfd_getfd, 302, 31, 0);
  ksft_test_result(result >= 0, "pidfd_getfd succeeds\n");
}

static void ksft_compound_result(void) {
  long result = syscall(__NR_pidfd_getfd, 303, 32, 0);
  ksft_test_result(result == -1 && errno == EINVAL,
                   "pidfd_getfd rejects its arguments\n");
}
