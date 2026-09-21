/* Analysis-only glibc wrapper model contracts. Never link or execute. */
#define O_RDONLY 0
#define O_CREAT 0100

extern void test__fail(void);
#define EXPECT_OP(expected, seen, op) do { \
  __typeof__(expected) e = (expected);       \
  __typeof__(seen) s = (seen);               \
  if (!(e op s)) test__fail();               \
} while (0)
#define EXPECT_EQ(expected, seen) EXPECT_OP(expected, seen, ==)
#define EXPECT_GE(seen, minimum) EXPECT_OP(seen, minimum, >=)

extern int *__errno_location(void) __attribute__((const));
#define errno (*__errno_location())
extern int close(int);
extern int eventfd(unsigned, int);
extern int open(const char *, int, ...);
extern int ioctl(int, unsigned long, ...);

static void close_success(void) {
  int result = close(9);
  EXPECT_EQ(0, result);
}

static void renamed_eventfd(void) {
  int fd = eventfd(3, 0);
  EXPECT_GE(fd, 0);
}

static void open_nomode(void) {
  int fd = open("input", O_RDONLY);
  EXPECT_GE(fd, 0);
}

static void open_create(void) {
  int fd = open("created", O_CREAT, 0640);
  EXPECT_GE(fd, 0);
}

static void open_ignored_mode(void) {
  int fd = open("input", O_RDONLY, 0777);
  EXPECT_GE(fd, 0);
}

static void open_unknown_flags(int flags) {
  int fd = open("input", flags, 0600);
  EXPECT_GE(fd, 0);
}

static void ioctl_output_is_unknown(void) {
  int available = 0;
  int result = ioctl(9, 0x541b, &available);
  EXPECT_EQ(0, result);
  int fd = eventfd((unsigned)available, 0);
  EXPECT_GE(fd, 0);
}
