/* An ABI-incompatible declaration must not be replaced by a libc model. */
#define EXPECT_EQ(expected, seen) do { if ((expected) != (seen)) {} } while (0)

extern long close(long);

static void incompatible_close(void) {
  long result = close(9);
  EXPECT_EQ(0L, result);
}
