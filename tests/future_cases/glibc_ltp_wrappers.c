/*
 * Future analysis contracts only: these functions must never be linked or
 * executed. The declarations mirror common glibc and LTP wrapper shapes.
 */
#define O_RDONLY 0
typedef long ssize_t;
typedef unsigned long size_t;

enum safe_write_opts {
  SAFE_WRITE_ANY = 0,
  SAFE_WRITE_ALL = 1,
  SAFE_WRITE_RETRY = 2,
};

extern void test__fail(void);
#define EXPECT_EQ(expected, seen) do { \
  if ((expected) != (seen)) test__fail(); \
} while (0)
#define EXPECT_GE(seen, minimum) do { \
  if ((seen) < (minimum)) test__fail(); \
} while (0)

extern int fcntl(int fd, int command, ...);
extern int getpid(void);
extern int access(const char *path, int mode);
extern int kill(int pid, int signal);

extern int safe_close(const char *file, int line, void (*cleanup)(void), int fd);
extern int safe_open(const char *file, int line, void (*cleanup)(void),
                     const char *path, int flags, ...);
extern ssize_t safe_write(const char *file, int line, void (*cleanup)(void),
                          enum safe_write_opts strict, int fd,
                          const void *buffer, size_t count);

static void libc_fcntl(void) {
  int result = fcntl(9, 4, 04000);
  EXPECT_EQ(0, result);
}

static void libc_fcntl_getfd(void) {
  int result = fcntl(9, 1);
  EXPECT_GE(result, 0);
}

static void libc_getpid(void) {
  int result = getpid();
  EXPECT_GE(result, 0);
}

static void libc_access(void) {
  int result = access("input", 4);
  EXPECT_EQ(0, result);
}

static void libc_kill(void) {
  int result = kill(123, 9);
  EXPECT_EQ(0, result);
}

static void ltp_safe_close(void) {
  int fd = 9;
  safe_close(__FILE__, __LINE__, 0, fd);
}

static void ltp_safe_open(void) {
  int fd = safe_open(__FILE__, __LINE__, 0, "input", O_RDONLY);
  EXPECT_GE(fd, 0);
}

static void ltp_safe_write(void) {
  ssize_t written = safe_write(__FILE__, __LINE__, 0, SAFE_WRITE_ANY,
                               9, "abc", 3);
  EXPECT_GE(written, 0);
}

static void ltp_safe_write_all(void) {
  safe_write(__FILE__, __LINE__, 0, SAFE_WRITE_ALL, 9, "abc", 3);
}

static void ltp_safe_write_retry_is_conservative(void) {
  safe_write(__FILE__, __LINE__, 0, SAFE_WRITE_RETRY, 9, "abc", 3);
}
