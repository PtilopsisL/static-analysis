/* Analysis cases expressed through the non-harness kselftest API. */
#define __NR_pidfd_getfd 438
#define EINVAL 22
#define ENOSYS 38
#define NULL ((void *)0)
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

static void ksft_direct_exit_pass(void) {
  long result = syscall(__NR_pidfd_getfd, 310, 39, 0);
  if (result != 0)
    ksft_exit_fail();
  ksft_exit_pass();
}

static void ksft_counter_pass_fail(void) {
  long result = syscall(__NR_pidfd_getfd, 311, 40, 0);
  if (result == 0)
    ksft_inc_pass_cnt();
  else
    ksft_inc_fail_cnt();
}

static void ksft_counter_pass_error(void) {
  long result = syscall(__NR_pidfd_getfd, 312, 41, 0);
  if (result == 0)
    ksft_inc_pass_cnt();
  else
    ksft_inc_error_cnt();
}

static void ksft_counter_xfail_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 313, 42, 0);
  if (result == -1 && errno == ENOSYS)
    ksft_inc_xfail_cnt();
  else
    ksft_inc_fail_cnt();
}

static void ksft_counter_xpass_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 314, 43, 0);
  if (result == 0)
    ksft_inc_xpass_cnt();
  else
    ksft_inc_fail_cnt();
}

static void ksft_counter_skip_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 315, 44, 0);
  if (result == -1 && errno == ENOSYS)
    ksft_inc_xskip_cnt();
  else
    ksft_inc_fail_cnt();
}

static void ksft_xfail_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 316, 45, 0);
  if (result == -1 && errno == ENOSYS)
    ksft_test_result_xfail("pidfd_getfd is expected to be unavailable\n");
  else
    ksft_test_result_fail("pidfd_getfd unexpectedly avoided XFAIL\n");
}

static void ksft_xpass_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 317, 46, 0);
  if (result == 0)
    ksft_test_result_xpass("pidfd_getfd unexpectedly passed\n");
  else
    ksft_test_result_fail("pidfd_getfd failed\n");
}

static void ksft_exit_xfail_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 318, 47, 0);
  if (result == -1 && errno == ENOSYS)
    ksft_exit_xfail();
  else
    ksft_exit_fail();
}

static void ksft_exit_xpass_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 319, 48, 0);
  if (result == 0)
    ksft_exit_xpass();
  else
    ksft_exit_fail();
}

static void ksft_result_report_pass_fail(void) {
  long result = syscall(__NR_pidfd_getfd, 320, 49, 0);
  int outcome;
  if (result == 0)
    outcome = KSFT_PASS;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_report(outcome, "pidfd_getfd result\n");
}

static void ksft_result_code_pass_fail(void) {
  long result = syscall(__NR_pidfd_getfd, 321, 50, 0);
  int outcome;
  if (result == 0)
    outcome = KSFT_PASS;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_code(outcome, "pidfd_getfd", NULL);
}

static void ksft_result_report_skip_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 324, 53, 0);
  int outcome;
  if (result == -1 && errno == ENOSYS)
    outcome = KSFT_SKIP;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_report(outcome, "pidfd_getfd result\n");
}

static void ksft_result_report_xfail_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 325, 54, 0);
  int outcome;
  if (result == -1 && errno == ENOSYS)
    outcome = KSFT_XFAIL;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_report(outcome, "pidfd_getfd result\n");
}

static void ksft_result_report_xpass_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 326, 55, 0);
  int outcome;
  if (result == 0)
    outcome = KSFT_XPASS;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_report(outcome, "pidfd_getfd result\n");
}

static void ksft_result_code_skip_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 327, 56, 0);
  int outcome;
  if (result == -1 && errno == ENOSYS)
    outcome = KSFT_SKIP;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_code(outcome, "pidfd_getfd", NULL);
}

static void ksft_result_code_xfail_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 328, 57, 0);
  int outcome;
  if (result == -1 && errno == ENOSYS)
    outcome = KSFT_XFAIL;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_code(outcome, "pidfd_getfd", NULL);
}

static void ksft_result_code_xpass_is_not_oracle(void) {
  long result = syscall(__NR_pidfd_getfd, 329, 58, 0);
  int outcome;
  if (result == 0)
    outcome = KSFT_XPASS;
  else
    outcome = KSFT_FAIL;
  ksft_test_result_code(outcome, "pidfd_getfd", NULL);
}

static void ksft_error_reporter_is_failure(void) {
  long result = syscall(__NR_pidfd_getfd, 330, 59, 0);
  if (result == 0)
    ksft_test_result_pass("pidfd_getfd passed\n");
  else
    ksft_test_result_error("pidfd_getfd encountered an error\n");
}

/* Counter updates and result reporters are nonterminal.  A prior outcome must
 * not prevent extraction from a later, independent test. */
static void ksft_counter_failure_then_later_test(void) {
  ksft_inc_fail_cnt();

  long result = syscall(__NR_pidfd_getfd, 331, 62, 0);
  if (result == 0)
    ksft_inc_pass_cnt();
  else
    ksft_inc_fail_cnt();
}

static void ksft_failure_reporter_then_later_test(void) {
  ksft_test_result_fail("an earlier test failed\n");
  ksft_test_result_error("an earlier test encountered an error\n");

  long result = syscall(__NR_pidfd_getfd, 332, 63, 0);
  if (result == 0)
    ksft_test_result_pass("later pidfd_getfd passed\n");
  else
    ksft_test_result_fail("later pidfd_getfd failed\n");
}

static void ksft_nonpass_reporters_then_later_test(void) {
  ksft_test_result_skip("an earlier test was skipped\n");
  ksft_test_result_xfail("an earlier test was expected to fail\n");
  ksft_test_result_xpass("an earlier test unexpectedly passed\n");

  long result = syscall(__NR_pidfd_getfd, 333, 64, 0);
  if (result == 0)
    ksft_test_result_pass("later pidfd_getfd passed\n");
  else
    ksft_test_result_fail("later pidfd_getfd failed\n");
}

/* A later skip belongs to the second test and must not suppress the already
 * completed first test. */
static void ksft_sequential_skip_scope(void) {
  long first = syscall(__NR_pidfd_getfd, 322, 51, 0);
  if (first == 0)
    ksft_test_result_pass("first pidfd_getfd passed\n");
  else
    ksft_test_result_fail("first pidfd_getfd failed\n");

  long second = syscall(__NR_pidfd_getfd, 323, 52, 0);
  if (second == -1 && errno == ENOSYS)
    ksft_test_result_skip("second pidfd_getfd is unavailable\n");
  else
    ksft_test_result_pass("second pidfd_getfd is available\n");
}
