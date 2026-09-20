/* Analysis cases for assertion expansions that use arbitrary temporaries. */
#define __NR_pidfd_getfd 438
#define EINVAL 22
#define errno (*__errno_location())

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);

#define CHECK_OP(expected, seen, op)           \
  do {                                         \
    __typeof__(expected) wanted = (expected);  \
    __typeof__(seen) observed = (seen);        \
    if (!(wanted op observed)) {               \
    }                                          \
  } while (0)

static void arbitrary_temporary_names(void) {
  long result = syscall(__NR_pidfd_getfd, 101, 10, 0);
  CHECK_OP(-1, result, ==);
  CHECK_OP(EINVAL, errno, ==);
}

static void syscall_as_assertion_operand(void) {
  CHECK_OP(0, syscall(__NR_pidfd_getfd, 102, 11, 0), !=);
}

static void reversed_comparison_with_cast(void) {
  CHECK_OP(0, (long)syscall(__NR_pidfd_getfd, 103, 12, 0), <=);
}

static void negated_result(void) {
  long result = -syscall(__NR_pidfd_getfd, 104, 13, 0);
  CHECK_OP(1, result, ==);
}
