/* Minimal faithful shape of the non-harness API in Linux kselftest.h. */
#ifndef TESTS_CASES_KSFT_REAL_H
#define TESTS_CASES_KSFT_REAL_H

#define KSFT_PASS 0
#define KSFT_FAIL 1
#define KSFT_XFAIL 2
#define KSFT_XPASS 3
#define KSFT_SKIP 4

extern void exit(int status) __attribute__((noreturn));

static unsigned int ksft_pass_count;
static unsigned int ksft_fail_count;
static unsigned int ksft_xfail_count;
static unsigned int ksft_xpass_count;
static unsigned int ksft_xskip_count;
static unsigned int ksft_error_count;
static unsigned int ksft_plan;

static inline void ksft_inc_pass_cnt(void) { ksft_pass_count++; }
static inline void ksft_inc_fail_cnt(void) { ksft_fail_count++; }
static inline void ksft_inc_xfail_cnt(void) { ksft_xfail_count++; }
static inline void ksft_inc_xpass_cnt(void) { ksft_xpass_count++; }
static inline void ksft_inc_xskip_cnt(void) { ksft_xskip_count++; }
static inline void ksft_inc_error_cnt(void) { ksft_error_count++; }

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
  ksft_xskip_count++;
}

static inline void ksft_test_result_xfail(const char *format, ...)
{
  (void)format;
  ksft_xfail_count++;
}

static inline void ksft_test_result_xpass(const char *format, ...)
{
  (void)format;
  ksft_xpass_count++;
}

static inline void ksft_test_result_error(const char *format, ...)
{
  (void)format;
  ksft_error_count++;
}

static inline void ksft_test_result_code(int exit_code,
                                         const char *test_name,
                                         const char *format, ...)
{
  (void)test_name;
  (void)format;
  switch (exit_code) {
  case KSFT_PASS:
    ksft_pass_count++;
    break;
  case KSFT_XFAIL:
    ksft_xfail_count++;
    break;
  case KSFT_XPASS:
    ksft_xpass_count++;
    break;
  case KSFT_SKIP:
    ksft_xskip_count++;
    break;
  case KSFT_FAIL:
  default:
    ksft_fail_count++;
    break;
  }
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

static inline __attribute__((noreturn)) void ksft_exit_xfail(void)
{
  exit(KSFT_XFAIL);
}

static inline __attribute__((noreturn)) void ksft_exit_xpass(void)
{
  exit(KSFT_XPASS);
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

#define ksft_test_result_report(result, format, ...)                        \
  do {                                                                      \
    switch (result) {                                                       \
    case KSFT_PASS:                                                         \
      ksft_test_result_pass(format, ##__VA_ARGS__);                         \
      break;                                                                \
    case KSFT_FAIL:                                                         \
      ksft_test_result_fail(format, ##__VA_ARGS__);                         \
      break;                                                                \
    case KSFT_XFAIL:                                                        \
      ksft_test_result_xfail(format, ##__VA_ARGS__);                        \
      break;                                                                \
    case KSFT_XPASS:                                                        \
      ksft_test_result_xpass(format, ##__VA_ARGS__);                        \
      break;                                                                \
    case KSFT_SKIP:                                                         \
      ksft_test_result_skip(format, ##__VA_ARGS__);                         \
      break;                                                                \
    }                                                                       \
  } while (0)

#define ksft_exit(condition)                                                 \
  do {                                                                      \
    if (!!(condition))                                                      \
      ksft_exit_pass();                                                     \
    else                                                                    \
      ksft_exit_fail();                                                     \
  } while (0)

#define ksft_finished()                                                     \
  ksft_exit(ksft_plan == ksft_pass_count + ksft_xpass_count +              \
                               ksft_xfail_count + ksft_xskip_count)

#endif
