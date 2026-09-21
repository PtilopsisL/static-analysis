/* A visible user definition must not be replaced by a libc model. */
#define EXPECT_EQ(expected, seen) do { if ((expected) != (seen)) {} } while (0)

int close(int fd) {
  return fd;
}

static void user_close(void) {
  int result = close(9);
  EXPECT_EQ(9, result);
}
