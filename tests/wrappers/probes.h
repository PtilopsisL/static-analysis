#ifndef WRAPPER_PROBES_H
#define WRAPPER_PROBES_H

#include <stddef.h>
#include <stdint.h>

/* The driver observes this storage only after the end breakpoint. */
#define WRAPPER_ERRNO_SENTINEL 123
struct wrapper_result {
  long ret;
  int error;
  int present;
};
extern struct wrapper_result *wrapper_results;
extern size_t wrapper_result_capacity;

enum wrapper_phase { WRAPPER_ENTRY = 1, WRAPPER_EXIT = 2 };

/* Observation descriptions contain layout information, never expected values.
 * Scalar types: s32/u32/s64/u64. Memory: those types, cstring, bytes, struct.
 * Struct fields are scalars or fixed-size bytes; offsets come from offsetof(). */
struct wrapper_field {
  const char *name;
  const char *type;
  size_t offset;
  size_t size; /* bytes fields only */
};
struct wrapper_memory {
  const char *type;
  unsigned phases;
  size_t size; /* fixed byte count, struct size, or string scan bound */
  unsigned length_arg; /* 1-based unsigned syscall argument, 0 = fixed size */
  int limit_to_result; /* exit byte count capped by nonnegative syscall return */
  int nullable;
  const struct wrapper_field *fields;
  size_t field_count;
};
struct wrapper_argument {
  const char *type; /* scalar type or pointer */
  const struct wrapper_memory *memory; /* NULL means no dereference */
};
struct wrapper_syscall {
  uint64_t nr;
  const char *name;
  unsigned arg_count;
  struct wrapper_argument args[6];
  /* Optional selector for command-dependent layouts, such as ioctl. */
  unsigned selector_arg; /* 1-based, 0 = no selector */
  uint64_t selector_mask;
  uint64_t selector_value;
};
extern const struct wrapper_syscall wrapper_syscalls[];
extern const size_t wrapper_syscall_count;

struct wrapper_probe {
  const char *name;
  void (*run)(void);
  void (*prepare)(void);
  size_t result_count;
  const char *const *symbols;
  size_t symbol_count;
  size_t event_limit;
  size_t snapshot_limit;
};
extern const struct wrapper_probe wrapper_probes[];
extern const unsigned wrapper_probe_count;

#endif
