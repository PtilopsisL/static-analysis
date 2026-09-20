/* Analysis cases expressed through the BPF selftest assertion style. */
#define __NR_pidfd_getfd 438
#define EPROTO 71
#define errno (*__errno_location())

extern int *__errno_location(void) __attribute__((const));
extern long syscall(long number, ...);
extern void bpf_test_failure(const char *name);

#define ASSERT_EQ(actual, expected, name)      \
  ({                                           \
    __typeof__(actual) ___act = (actual);      \
    __typeof__(expected) ___exp = (expected);  \
    int ___ok = ___act == ___exp;              \
    if (!___ok)                                \
      bpf_test_failure(name);                  \
    ___ok;                                     \
  })

#define ASSERT_NEQ(actual, expected, name)     \
  ({                                           \
    __typeof__(actual) ___act = (actual);      \
    __typeof__(expected) ___exp = (expected);  \
    int ___ok = ___act != ___exp;              \
    if (!___ok)                                \
      bpf_test_failure(name);                  \
    ___ok;                                     \
  })

#define ASSERT_OK(result, name)                 \
  ({                                            \
    long long ___res = (result);                \
    int ___ok = ___res == 0;                    \
    if (!___ok)                                 \
      bpf_test_failure(name);                   \
    ___ok;                                      \
  })

#define ASSERT_ERR(result, name)                \
  ({                                            \
    long long ___res = (result);                \
    int ___ok = ___res < 0;                     \
    if (!___ok)                                 \
      bpf_test_failure(name);                   \
    ___ok;                                      \
  })

static void bpf_equal_with_errno(void) {
  long result = syscall(__NR_pidfd_getfd, 401, 40, 0);
  ASSERT_EQ(result, -1, "error");
  ASSERT_EQ(errno, EPROTO, "errno");
}

static void bpf_not_equal(void) {
  long result = syscall(__NR_pidfd_getfd, 402, 41, 0);
  ASSERT_NEQ(result, 0, "not zero");
}

static void bpf_ok(void) {
  long result = syscall(__NR_pidfd_getfd, 403, 42, 0);
  ASSERT_OK(result, "success");
}

static void bpf_err(void) {
  long result = syscall(__NR_pidfd_getfd, 404, 43, 0);
  ASSERT_ERR(result, "failure");
}
