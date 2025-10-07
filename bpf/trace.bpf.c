// clang-format off
#include "vmlinux.h"
#include "include/bpf_helpers.h"
// clang-format on

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
  bpf_printk("Process called execve!\n");
  return 0;
}

char LICENSE[] SEC("license") = "GPL";