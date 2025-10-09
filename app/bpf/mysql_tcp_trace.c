// tcp_sendmsg.bpf.c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct data_t {
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  size_t size;
  char msg[64];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg,
               size_t size) {
  struct data_t data = {};
  struct iov_iter iter = {};
  struct iovec iov = {};
  const struct iovec *iovp = NULL;
  void *base = NULL;

  // --- Socket info using CO-RE reads ---
  data.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  data.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  data.dport = bpf_ntohs(data.dport);

  if (data.sport != 3306)
    return 0;

  data.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data.size = size;

  // --- Read message content ---
  bpf_core_read(&iter, sizeof(iter), &msg->msg_iter);
  bpf_core_read(&iovp, sizeof(iovp), &iter.__iov);
  if (iovp) {
    bpf_printk("MSG: %s\n", iovp);
    bpf_core_read(&iov, sizeof(iov), iovp);
    base = iov.iov_base;
    if (base)
      bpf_probe_read_user(&data.msg, sizeof(data.msg), base);
  }

  // Debug (optional)
  bpf_printk("tcp_sendmsg: sport=%d dport=%d size=%lu\n", data.sport,
             data.dport, data.size);

  // Emit perf event
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
