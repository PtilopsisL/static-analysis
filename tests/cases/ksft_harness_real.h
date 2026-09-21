/* Minimal faithful shape of kselftest_harness.h's SKIP(statement, ...) API. */
#ifndef TESTS_CASES_KSFT_HARNESS_REAL_H
#define TESTS_CASES_KSFT_HARNESS_REAL_H

#define KSFT_SKIP 4

struct __test_metadata {
  int exit_code;
  int trigger;
};

#define SKIP(statement, format, ...)                                        \
  do {                                                                      \
    (void)(format);                                                         \
    _metadata->exit_code = KSFT_SKIP;                                       \
    _metadata->trigger = 0;                                                 \
    statement;                                                              \
  } while (0)

#endif
