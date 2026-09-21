/* Analysis cases for kselftest_harness.h's statement-based SKIP macro. */
#define __NR_pidfd_getfd 438
#define ENOSYS 38
#define errno (*__errno_location())

#include "ksft_harness_real.h"

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);
extern void abort(void) __attribute__((noreturn));

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
