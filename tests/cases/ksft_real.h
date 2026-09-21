/* Minimal faithful shape of the non-harness API in Linux kselftest.h. */
#ifndef TESTS_CASES_KSFT_REAL_H
#define TESTS_CASES_KSFT_REAL_H

#define KSFT_PASS 0
#define KSFT_FAIL 1
#define KSFT_SKIP 4

extern void exit(int status) __attribute__((noreturn));

static unsigned int ksft_pass_count;
static unsigned int ksft_fail_count;
static unsigned int ksft_skip_count;
static unsigned int ksft_plan;

static inline void ksft_test_result_pass(const char *format, ...)
{
  (void)format;
  ksft_pass_count++;
}

static inline void ksft_test_result_fail(const char *format, ...)
{
  (void)format;
  ksft_fail_count++;
}

static inline void ksft_test_result_skip(const char *format, ...)
{
  (void)format;
  ksft_skip_count++;
}

static inline void ksft_set_plan(unsigned int plan)
{
  ksft_plan = plan;
}

static inline __attribute__((noreturn)) void ksft_exit_pass(void)
{
  exit(KSFT_PASS);
}

static inline __attribute__((noreturn)) void ksft_exit_fail(void)
{
  exit(KSFT_FAIL);
}

static inline __attribute__((noreturn))
void ksft_exit_skip(const char *format, ...)
{
  (void)format;
  exit(KSFT_SKIP);
}

/* Keep this expansion aligned with tools/testing/selftests/kselftest.h. */
#define ksft_test_result(condition, format, ...)                             \
  do {                                                                      \
    if (!!(condition))                                                      \
      ksft_test_result_pass(format, ##__VA_ARGS__);                         \
    else                                                                    \
      ksft_test_result_fail(format, ##__VA_ARGS__);                         \
  } while (0)

#define ksft_exit(condition)                                                 \
  do {                                                                      \
    if (!!(condition))                                                      \
      ksft_exit_pass();                                                     \
    else                                                                    \
      ksft_exit_fail();                                                     \
  } while (0)

#define ksft_finished()                                                     \
  ksft_exit(ksft_plan == ksft_pass_count)

#endif
