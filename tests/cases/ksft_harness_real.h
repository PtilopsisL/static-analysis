/* Minimal faithful shape of kselftest_harness.h's SKIP(statement, ...) API. */
#ifndef TESTS_CASES_KSFT_HARNESS_REAL_H
#define TESTS_CASES_KSFT_HARNESS_REAL_H

#define KSFT_SKIP 4
#define KSFT_FAIL 1

struct __test_metadata {
  int exit_code;
  int trigger;
};

#define __HARNESS_EXPECT(expected, seen, op)                                 \
  do {                                                                       \
    __typeof__(expected) __expected = (expected);                            \
    __typeof__(seen) __seen = (seen);                                        \
    if (!(__expected op __seen)) {                                           \
      _metadata->exit_code = KSFT_FAIL;                                      \
      _metadata->trigger = 1;                                                \
    }                                                                        \
  } while (0)

#define EXPECT_EQ(expected, seen) __HARNESS_EXPECT(expected, seen, ==)
/* Deliberately does not use an EXPECT_/ASSERT_ name. */
#define VERIFY_SAME(expected, seen) __HARNESS_EXPECT(expected, seen, ==)

#define SKIP(statement, format, ...)                                        \
  do {                                                                      \
    (void)(format);                                                         \
    _metadata->exit_code = KSFT_SKIP;                                       \
    _metadata->trigger = 0;                                                 \
    statement;                                                              \
  } while (0)

#endif
