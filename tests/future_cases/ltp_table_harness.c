/* Future contract for synthesizing each .tcnt + .test(n) invocation. */
#define __NR_pidfd_getfd 438

extern long syscall(long number, ...);
extern void test__fail(void);

static struct test_case {
  int pidfd;
  int target_fd;
} cases[] = {
  {10, 100},
  {20, 200},
};

static void run(unsigned int n) {
  long result = syscall(__NR_pidfd_getfd,
                        cases[n].pidfd, cases[n].target_fd, 0);
  if (result != -1)
    test__fail();
}

struct tst_test {
  unsigned int tcnt;
  void (*test)(unsigned int n);
};

static struct tst_test test = {
  .tcnt = sizeof(cases) / sizeof(cases[0]),
  .test = run,
};
