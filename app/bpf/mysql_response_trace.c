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
  char msg[400];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 1024); // required on older kernels
} events SEC(".maps");

// Define your port filter here or set dynamically
#define PORT_FILTER 3306

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  struct data_t data = {};
  struct iov_iter iter = {};
  const struct iovec *iovp = NULL;
  struct iovec iov = {};
  void *base = NULL;
  unsigned char buf[32]; // dump first 32 bytes

  // Read socket info (CO-RE safe)
  data.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  data.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  if (data.sport != PORT_FILTER)
    return 0;

  bpf_printk("Hello im here");
  data.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data.size = size;

  // Read the iov_iter structure from msg->msg_iter
  bpf_core_read(&iter, sizeof(iter), &msg->msg_iter);
  bpf_printk("iter type: %d\n", iter.iter_type);

  // Try to read __iov pointer inside iov_iter
  bpf_core_read(&iovp, sizeof(*iovp), &iter.__iov);
  if (!iovp)
    return 0;

  bpf_printk("iovp string: %s\n", iovp);
  bpf_probe_read_user(buf, sizeof(buf), iovp);
  for (int i = 0; i < 32; i++) {
    bpf_printk("%02x ", buf[i]);
  }
  bpf_printk("\n");
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
