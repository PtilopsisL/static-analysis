/* Analysis cases for kselftest_harness.h's statement-based SKIP macro. */
#define __NR_pidfd_getfd 438
#define EINVAL 22
#define ENOSYS 38
#define errno (*__errno_location())

#include "ksft_harness_real.h"

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);
extern void abort(void) __attribute__((noreturn));

static void harness_expect_uses_status_write(void) {
  struct __test_metadata metadata = {0};
  struct __test_metadata *_metadata = &metadata;
  long result = syscall(__NR_pidfd_getfd, 403, 62, 0);

  EXPECT_EQ(0, result);
}

static void harness_unknown_macro_name_uses_same_effect(void) {
  struct __test_metadata metadata = {0};
  struct __test_metadata *_metadata = &metadata;
  long result = syscall(__NR_pidfd_getfd, 404, 63, 0);

  VERIFY_SAME(-1, result);
  VERIFY_SAME(EINVAL, errno);
}

static void harness_guarded_expect(void) {
  struct __test_metadata metadata = {0};
  struct __test_metadata *_metadata = &metadata;
  long result = syscall(__NR_pidfd_getfd, 405, 64, 0);

  if (result < 0)
    VERIFY_SAME(EINVAL, errno);
}

static void harness_both_branches_fail(void) {
  struct __test_metadata metadata = {0};
  struct __test_metadata *_metadata = &metadata;
  long result = syscall(__NR_pidfd_getfd, 406, 65, 0);

  if (result == 0)
    _metadata->exit_code = KSFT_FAIL;
  else
    _metadata->exit_code = KSFT_FAIL;
}

struct unrelated_metadata {
  int exit_code;
  int trigger;
};

static void unrelated_exit_code_is_not_framework_effect(void) {
  struct unrelated_metadata metadata = {0};
  long result = syscall(__NR_pidfd_getfd, 407, 66, 0);

  if (result != 0)
    metadata.exit_code = KSFT_FAIL;
}

static void harness_skip_return_is_not_oracle(void) {
  struct __test_metadata metadata = {0};
  struct __test_metadata *_metadata = &metadata;
  long result = syscall(__NR_pidfd_getfd, 401, 60, 0);

  if (result == -1 && errno == ENOSYS)
    SKIP(return, "pidfd_getfd is unavailable");
  abort();
}

static void harness_skip_goto_is_not_oracle(void) {
  struct __test_metadata metadata = {0};
  struct __test_metadata *_metadata = &metadata;
  long result = syscall(__NR_pidfd_getfd, 402, 61, 0);

  if (result == -1 && errno == ENOSYS)
    SKIP(goto skipped, "pidfd_getfd is unavailable");
  abort();

skipped:
  return;
}
