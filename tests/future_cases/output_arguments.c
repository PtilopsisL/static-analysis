/* Future contracts for output-only memory and output-value dependencies. */
#define __NR_sysfs 139
#define __NR_timer_create 222
#define __NR_timer_delete 226

extern long syscall(long number, ...);
extern void test__fail(void);

#define EXPECT_EQ(expected, seen) do { \
  if ((expected) != (seen)) test__fail(); \
} while (0)

static void pure_output_buffer(void) {
  char output[40];
  long result = syscall(__NR_sysfs, 2, 0, output);
  EXPECT_EQ(0, result);
}

static void timer_output_dependency(void) {
  int timer_id;
  long created = syscall(__NR_timer_create, 0, 0, &timer_id);
  EXPECT_EQ(0, created);

  long deleted = syscall(__NR_timer_delete, timer_id);
  EXPECT_EQ(0, deleted);
}
