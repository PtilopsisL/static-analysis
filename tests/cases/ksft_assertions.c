/* Analysis cases expressed through the non-harness kselftest API. */
#define __NR_pidfd_getfd 438
#define EINVAL 22
#define ENOSYS 38
#define errno (*__errno_location())

#include "ksft_real.h"

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);

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

/* Some selftests call the underlying reporters directly instead of using the
 * ksft_test_result() macro.  The branch containing pass is the oracle. */
static void ksft_reporter_true_branch(void) {
  long result = syscall(__NR_pidfd_getfd, 304, 33, 0);
  if (result == -1 && errno == EINVAL)
    ksft_test_result_pass("pidfd_getfd rejects its arguments\n");
  else
    ksft_test_result_fail("pidfd_getfd returned an unexpected result\n");
}

static void ksft_reporter_false_branch(void) {
  long result = syscall(__NR_pidfd_getfd, 305, 34, 0);
  if (result != 0)
    ksft_test_result_fail("pidfd_getfd did not return zero\n");
  else
    ksft_test_result_pass("pidfd_getfd returned zero\n");
}

/* A real kselftest main commonly terminates through ksft_finished(), so the
 * successful assertion must be committed before the noreturn exit. */
static void ksft_result_then_finished(void) {
  ksft_set_plan(1);
  long result = syscall(__NR_pidfd_getfd, 306, 35, 0);
  ksft_test_result(result == 0, "pidfd_getfd returns zero\n");
  ksft_finished();
}

/* ksft_exit() itself can carry the condition that defines success. */
static void ksft_exit_condition(void) {
  long result = syscall(__NR_pidfd_getfd, 307, 36, 0);
  ksft_exit(result == -1 && errno == EINVAL);
}

/* A skipped outcome is not evidence that its branch is the expected syscall
 * result, even when the other branch is an explicit failure. */
static void ksft_skip_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 308, 37, 0);
  if (result == -1 && errno == ENOSYS)
    ksft_test_result_skip("pidfd_getfd is unavailable\n");
  else
    ksft_test_result_fail("pidfd_getfd did not produce the skip condition\n");
}

static void ksft_exit_skip_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 309, 38, 0);
  if (result == -1 && errno == ENOSYS)
    ksft_exit_skip("pidfd_getfd is unavailable\n");
  else
    ksft_exit_fail();
}
