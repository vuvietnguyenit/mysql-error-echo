#include "vmlinux.h"
#include "include/bpf_helpers.h"
#include <bpf/bpf_tracing.h>


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("Process called execve!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";