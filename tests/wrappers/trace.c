/* Native Linux x86-64 observer. No extractor code or wrapper models are linked. */
#include "probes.h"

#include <dlfcn.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <inttypes.h>
#include <link.h>
#include <linux/audit.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__) || defined(__ILP32__) || !defined(__GLIBC__)
#error "This observer supports only Linux x86-64 LP64 with glibc"
#endif
_Static_assert(sizeof(long) == 8 && sizeof(int) == 4, "unsupported ABI");

struct snapshot {
  unsigned char *bytes;
  size_t size;
  int present, is_null;
};
struct event {
  uint64_t nr, args[6];
  int64_t ret;
  unsigned is_error;
  const struct wrapper_syscall *layout;
  struct snapshot snapshots[6][2];
};
static struct event *events;
static size_t event_count;
static volatile sig_atomic_t child_pid = -1;

extern const char wrapper_begin_trap[], wrapper_end_trap[];
__attribute__((noinline)) static void begin_window(void) {
  __asm__ volatile(".globl wrapper_begin_trap\nwrapper_begin_trap: int3" ::: "memory");
}
__attribute__((noinline)) static void end_window(void) {
  __asm__ volatile(".globl wrapper_end_trap\nwrapper_end_trap: int3" ::: "memory");
}

static void timeout_handler(int signal_number) {
  (void)signal_number;
  if (child_pid > 0)
    kill(child_pid, SIGKILL);
  _exit(124);
}

static void fail(const char *message) {
  fprintf(stderr, "%s (errno=%d: %s)\n", message, errno, strerror(errno));
  if (child_pid > 0) {
    kill(child_pid, SIGKILL);
    waitpid(child_pid, NULL, 0);
  }
  exit(1);
}

static int wait_child(void) {
  int status;
  pid_t result;
  do {
    result = waitpid(child_pid, &status, 0);
  } while (result < 0 && errno == EINTR);
  if (result != child_pid)
    fail("waitpid failed");
  if (WIFEXITED(status) || WIFSIGNALED(status))
    child_pid = -1;
  return status;
}

/* Aligned reads avoid crossing a mapping boundary when reading a final byte. */
static void read_memory(uintptr_t address, void *destination, size_t size) {
  unsigned char *output = destination;
  while (size) {
    uintptr_t aligned = address & ~(uintptr_t)(sizeof(long) - 1);
    size_t offset = address - aligned;
    size_t count = sizeof(long) - offset;
    if (count > size)
      count = size;
    errno = 0;
    long value = ptrace(PTRACE_PEEKDATA, child_pid, (void *)aligned, NULL);
    if (value == -1 && errno)
      fail("incomplete tracee memory snapshot");
    memcpy(output, (unsigned char *)&value + offset, count);
    output += count;
    address += count;
    size -= count;
  }
}

static size_t scalar_size(const char *type) {
  if (!type)
    return 0;
  if (!strcmp(type, "s32") || !strcmp(type, "u32"))
    return 4;
  if (!strcmp(type, "s64") || !strcmp(type, "u64"))
    return 8;
  return 0;
}

static void validate_registry(void) {
  for (unsigned i = 0; i < wrapper_probe_count; ++i) {
    const struct wrapper_probe *p = &wrapper_probes[i];
    if (!p->name || !p->run || !p->event_limit || !p->snapshot_limit ||
        (p->symbol_count && !p->symbols))
      fail("invalid probe description");
    for (unsigned j = 0; j < i; ++j)
      if (!strcmp(p->name, wrapper_probes[j].name))
        fail("duplicate probe name");
    for (size_t j = 0; j < p->symbol_count; ++j) {
      if (!p->symbols[j] || !*p->symbols[j])
        fail("empty tested symbol");
      for (size_t k = 0; k < j; ++k)
        if (!strcmp(p->symbols[j], p->symbols[k]))
          fail("duplicate tested symbol");
    }
  }
  for (size_t i = 0; i < wrapper_syscall_count; ++i) {
    const struct wrapper_syscall *s = &wrapper_syscalls[i];
    if (!s->name || !*s->name || s->arg_count > 6 || s->selector_arg > s->arg_count ||
        (s->selector_value & ~s->selector_mask) ||
        (!s->selector_arg && (s->selector_mask || s->selector_value)))
      fail("invalid syscall description");
    for (unsigned j = 0; j < s->arg_count; ++j) {
      const struct wrapper_argument *a = &s->args[j];
      if (!a->type || (!scalar_size(a->type) && strcmp(a->type, "pointer")))
        fail("invalid argument type");
      const struct wrapper_memory *m = a->memory;
      if (!m)
        continue;
      if (strcmp(a->type, "pointer") || !m->type || !m->phases || (m->phases & ~3u) ||
          m->length_arg > s->arg_count ||
          (m->field_count && (!m->fields || strcmp(m->type, "struct"))) ||
          (m->limit_to_result && !(m->phases & WRAPPER_EXIT)))
        fail("invalid memory description");
      if (m->length_arg && (!s->args[m->length_arg - 1].type ||
          (strcmp(s->args[m->length_arg - 1].type, "u32") &&
           strcmp(s->args[m->length_arg - 1].type, "u64"))))
        fail("memory length requires an unsigned argument");
      if ((m->length_arg || m->limit_to_result) && strcmp(m->type, "bytes"))
        fail("dynamic length is only supported for bytes");
      if (scalar_size(m->type) || !strcmp(m->type, "bytes"))
        continue;
      if (!strcmp(m->type, "cstring")) {
        if (!m->size)
          fail("string requires a scan bound");
        continue;
      }
      if (strcmp(m->type, "struct") || !m->size || !m->field_count || !m->fields)
        fail("invalid memory encoding");
      for (size_t k = 0; k < m->field_count; ++k) {
        const struct wrapper_field *f = &m->fields[k];
        size_t width = scalar_size(f->type);
        if (!width && f->type && !strcmp(f->type, "bytes"))
          width = f->size;
        if (!f->name || !*f->name || !width || f->offset > m->size || width > m->size - f->offset)
          fail("invalid struct field description");
        for (size_t n = 0; n < k; ++n)
          if (!strcmp(f->name, m->fields[n].name))
            fail("duplicate struct field name");
      }
    }
  }
}

static const struct wrapper_syscall *find_layout(const struct event *event) {
  const struct wrapper_syscall *found = NULL;
  for (size_t i = 0; i < wrapper_syscall_count; ++i) {
    const struct wrapper_syscall *s = &wrapper_syscalls[i];
    if (s->nr != event->nr || (s->selector_arg &&
        (event->args[s->selector_arg - 1] & s->selector_mask) != s->selector_value))
      continue;
    if (found)
      fail("ambiguous syscall descriptions");
    found = s;
  }
  return found;
}

static void capture_memory(struct event *event, unsigned phase, size_t limit) {
  if (!event->layout)
    return; /* Preserve the raw unexpected syscall; comparison will reject it. */
  for (unsigned i = 0; i < event->layout->arg_count; ++i) {
    const struct wrapper_memory *m = event->layout->args[i].memory;
    if (!m || !(m->phases & phase))
      continue;
    struct snapshot *snapshot = &event->snapshots[i][phase == WRAPPER_EXIT];
    snapshot->present = 1;
    if (!event->args[i] && m->nullable) {
      snapshot->is_null = 1;
      continue;
    }
    size_t size = scalar_size(m->type);
    if (!size)
      size = m->size;
    if (m->length_arg) {
      size = event->args[m->length_arg - 1];
      if (!strcmp(event->layout->args[m->length_arg - 1].type, "u32"))
        size &= UINT32_MAX;
    }
    if (phase == WRAPPER_EXIT && m->limit_to_result) {
      size_t returned = event->ret < 0 ? 0 : (size_t)event->ret;
      if (size > returned)
        size = returned;
    }
    if (size > limit || (size && event->args[i] > UINTPTR_MAX - (size - 1)))
      fail("memory snapshot bound exceeded");
    snapshot->bytes = calloc(size ? size : 1, 1);
    if (!snapshot->bytes)
      fail("allocating memory snapshot failed");
    snapshot->size = size;
    if (!strcmp(m->type, "cstring")) {
      size_t j;
      for (j = 0; j < size; ++j) {
        read_memory(event->args[i] + j, &snapshot->bytes[j], 1);
        if (!snapshot->bytes[j]) {
          snapshot->size = j + 1;
          break;
        }
      }
      if (j == size)
        fail("unterminated string snapshot");
    } else {
      read_memory(event->args[i], snapshot->bytes, size);
    }
  }
}

static int is_boundary(int status, const char *address) {
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
    return 0;
  struct user_regs_struct registers;
  if (ptrace(PTRACE_GETREGS, child_pid, NULL, &registers) < 0)
    fail("PTRACE_GETREGS failed");
  return registers.rip == (uintptr_t)address + 1;
}

static void json_string(const char *text) {
  putchar('"');
  for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
    if (*p == '"' || *p == '\\') {
      putchar('\\');
      putchar(*p);
    } else if (*p < 32 || *p >= 127) {
      printf("\\u%04x", *p);
    } else {
      putchar(*p);
    }
  }
  putchar('"');
}

static int print_object(struct dl_phdr_info *info, size_t size, void *context) {
  (void)size;
  unsigned *count = context;
  if (info->dlpi_name && *info->dlpi_name) {
    if ((*count)++)
      putchar(',');
    json_string(info->dlpi_name);
  }
  return 0;
}

static void print_layouts(void) {
  putchar('[');
  for (size_t i = 0; i < wrapper_syscall_count; ++i) {
    const struct wrapper_syscall *s = &wrapper_syscalls[i];
    printf("%s{\"nr\":%" PRIu64 ",\"name\":", i ? "," : "", s->nr);
    json_string(s->name);
    printf(",\"selector\":{\"arg\":%u,\"mask\":%" PRIu64 ",\"value\":%" PRIu64 "},\"args\":[",
           s->selector_arg, s->selector_mask, s->selector_value);
    for (unsigned j = 0; j < s->arg_count; ++j) {
      const struct wrapper_memory *m = s->args[j].memory;
      printf("%s{\"type\":", j ? "," : "");
      json_string(s->args[j].type);
      if (m) {
        printf(",\"memory\":{\"type\":");
        json_string(m->type);
        printf(",\"phases\":%u,\"size\":%zu,\"length_arg\":%u,"
               "\"limit_to_result\":%s,\"nullable\":%s,\"fields\":[",
               m->phases, m->size, m->length_arg,
               m->limit_to_result ? "true" : "false", m->nullable ? "true" : "false");
        for (size_t k = 0; k < m->field_count; ++k) {
          const struct wrapper_field *f = &m->fields[k];
          printf("%s{\"name\":", k ? "," : "");
          json_string(f->name);
          printf(",\"type\":");
          json_string(f->type);
          printf(",\"offset\":%zu,\"size\":%zu}", f->offset, f->size);
        }
        printf("]}");
      }
      putchar('}');
    }
    printf("]}");
  }
  putchar(']');
}

static void print_symbols(const struct wrapper_probe *probe) {
  putchar('[');
  for (size_t i = 0; i < probe->symbol_count; ++i) {
    if (i)
      putchar(',');
    json_string(probe->symbols[i]);
  }
  putchar(']');
}

static void describe(void) {
  printf("{\"schema_version\":2,\"arch\":\"x86_64\",\"probes\":[");
  for (unsigned i = 0; i < wrapper_probe_count; ++i) {
    const struct wrapper_probe *p = &wrapper_probes[i];
    printf("%s{\"name\":", i ? "," : "");
    json_string(p->name);
    printf(",\"result_count\":%zu,\"event_limit\":%zu,\"snapshot_limit\":%zu,\"symbols\":",
           p->result_count, p->event_limit, p->snapshot_limit);
    print_symbols(p);
    putchar('}');
  }
  printf("],\"layouts\":");
  print_layouts();
  printf("}\n");
}

static void print_identity(const struct wrapper_probe *probe) {
  printf("\"libc_version\":");
  json_string(gnu_get_libc_version());
  Dl_info anchor;
  if (!dladdr((void *)gnu_get_libc_version, &anchor) || !anchor.dli_fname)
    fail("unable to identify loaded libc");
  printf(",\"libc_path\":");
  json_string(anchor.dli_fname);
  printf(",\"symbols\":{");
  for (size_t i = 0; i < probe->symbol_count; ++i) {
    Dl_info info;
    void *symbol = dlsym(RTLD_DEFAULT, probe->symbols[i]);
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname)
      fail("unable to identify loaded libc symbol");
    if (i)
      putchar(',');
    json_string(probe->symbols[i]);
    putchar(':');
    json_string(info.dli_fname);
  }
  printf("},\"loaded_objects\":[");
  unsigned count = 0;
  dl_iterate_phdr(print_object, &count);
  putchar(']');
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: wrapper-trace PROBE | --describe\n");
    return 2;
  }
  validate_registry();
  if (!strcmp(argv[1], "--describe")) {
    describe();
    return 0;
  }
  const struct wrapper_probe *probe = NULL;
  for (unsigned i = 0; i < wrapper_probe_count; ++i)
    if (!strcmp(argv[1], wrapper_probes[i].name))
      probe = &wrapper_probes[i];
  if (!probe) {
    fprintf(stderr, "unknown probe: %s\n", argv[1]);
    return 2;
  }

  events = calloc(probe->event_limit, sizeof(*events));
  wrapper_results = calloc(probe->result_count ? probe->result_count : 1, sizeof(*wrapper_results));
  wrapper_result_capacity = probe->result_count;
  if (!events || !wrapper_results)
    fail("allocating probe storage failed");

  signal(SIGALRM, timeout_handler);
  alarm(8);
  pid_t parent = getpid();
  child_pid = fork();
  if (child_pid < 0)
    fail("fork failed");
  if (!child_pid) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
      _exit(111);
    if (probe->prepare)
      probe->prepare();
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      perror("PTRACE_TRACEME");
      _exit(112);
    }
    errno = WRAPPER_ERRNO_SENTINEL;
    begin_window();
    probe->run();
    end_window();
    /* Process exit releases all fixture-owned descriptors outside the window. */
    _exit(0);
  }

  int status = wait_child();
  if (!is_boundary(status, wrapper_begin_trap))
    fail("tracee did not reach the start boundary (setup or ptrace failed)");
  if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
             (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) < 0)
    fail("PTRACE_SETOPTIONS failed");

  int in_syscall = 0;
  for (;;) {
    if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) < 0)
      fail("PTRACE_SYSCALL failed");
    status = wait_child();
    if (is_boundary(status, wrapper_end_trap)) {
      if (in_syscall)
        fail("end boundary inside a syscall");
      break;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80))
      fail("unexpected signal or exit inside trace window");
    struct __ptrace_syscall_info info = {0};
    long size = ptrace(PTRACE_GET_SYSCALL_INFO, child_pid, sizeof(info), &info);
    if (size < 0)
      fail("PTRACE_GET_SYSCALL_INFO failed (Linux >= 5.3 required)");
    if (size < (long)offsetof(struct __ptrace_syscall_info, entry) ||
        info.arch != AUDIT_ARCH_X86_64)
      fail("incomplete syscall info or unsupported syscall ABI");
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
      if (size < (long)(offsetof(struct __ptrace_syscall_info, entry) + sizeof(info.entry)) ||
          in_syscall || event_count == probe->event_limit || (info.entry.nr & 0x40000000))
        fail("invalid syscall entry or event limit exceeded");
      struct event *event = &events[event_count];
      event->nr = info.entry.nr;
      memcpy(event->args, info.entry.args, sizeof(event->args));
      event->layout = find_layout(event);
      capture_memory(event, WRAPPER_ENTRY, probe->snapshot_limit);
      in_syscall = 1;
    } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
      if (size < (long)(offsetof(struct __ptrace_syscall_info, exit.is_error) + sizeof(info.exit.is_error)) ||
          !in_syscall)
        fail("invalid syscall exit");
      struct event *event = &events[event_count++];
      event->ret = info.exit.rval;
      event->is_error = info.exit.is_error;
      capture_memory(event, WRAPPER_EXIT, probe->snapshot_limit);
      in_syscall = 0;
    } else {
      fail("unexpected syscall stop kind");
    }
  }

  read_memory((uintptr_t)wrapper_results, wrapper_results,
              probe->result_count * sizeof(*wrapper_results));
  if (ptrace(PTRACE_DETACH, child_pid, NULL, NULL) < 0)
    fail("PTRACE_DETACH failed");
  status = wait_child();
  child_pid = -1;
  if (!WIFEXITED(status) || WEXITSTATUS(status))
    fail("tracee did not exit cleanly");
  alarm(0);

  printf("{\"schema_version\":2,\"arch\":\"x86_64\",\"probe\":");
  json_string(probe->name);
  printf(",\"errno_before\":%d,", WRAPPER_ERRNO_SENTINEL);
  print_identity(probe);
  printf(",\"layouts\":");
  print_layouts();
  printf(",\"events\":[");
  for (size_t i = 0; i < event_count; ++i) {
    const struct event *event = &events[i];
    if (i)
      putchar(',');
    printf("{\"nr\":%" PRIu64 ",\"args\":[", event->nr);
    for (unsigned j = 0; j < 6; ++j)
      printf("%s%" PRIu64, j ? "," : "", event->args[j]);
    printf("],\"raw_result\":%" PRId64 ",\"is_error\":%s,\"snapshots\":{",
           event->ret, event->is_error ? "true" : "false");
    unsigned written = 0;
    for (unsigned j = 0; j < 6; ++j) {
      if (!event->snapshots[j][0].present && !event->snapshots[j][1].present)
        continue;
      printf("%s\"%u\":{", written++ ? "," : "", j);
      unsigned phases = 0;
      for (unsigned k = 0; k < 2; ++k) {
        const struct snapshot *snapshot = &event->snapshots[j][k];
        if (!snapshot->present)
          continue;
        printf("%s\"%s\":", phases++ ? "," : "", k ? "after" : "before");
        if (snapshot->is_null) {
          printf("null");
        } else {
          putchar('"');
          for (size_t n = 0; n < snapshot->size; ++n)
            printf("%02x", snapshot->bytes[n]);
          putchar('"');
        }
      }
      putchar('}');
    }
    printf("}}");
  }
  printf("],\"returns\":[");
  size_t written = 0;
  for (size_t i = 0; i < probe->result_count; ++i) {
    if (!wrapper_results[i].present)
      continue;
    printf("%s{\"slot\":%zu,\"ret\":%ld,\"errno\":%d}",
           written++ ? "," : "", i, wrapper_results[i].ret, wrapper_results[i].error);
  }
  printf("],\"complete\":true}\n");
  for (size_t i = 0; i < event_count; ++i)
    for (unsigned j = 0; j < 6; ++j)
      for (unsigned k = 0; k < 2; ++k)
        free(events[i].snapshots[j][k].bytes);
  free(events);
  free(wrapper_results);
  return 0;
}
