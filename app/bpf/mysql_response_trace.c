// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MYSQL_ERRMSG_SIZE                                                      \
  512 // we need to ensure that msg data of MySQL protocol does not exceed this
      // size
#define PORT_FILTER 3306
#define ERR_BUF_SIZE 32 // only need small amount to check for 0xFF

struct data_t {
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u32 size;
  char msg[MYSQL_ERRMSG_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16 MB buffer
} events SEC(".maps");
static __always_inline void send_mysql_event(__u32 saddr, __u32 daddr,
                                             __u16 sport, __u16 dport,
                                             const struct iovec *pack,
                                             size_t size) {
  if (size > MYSQL_ERRMSG_SIZE) {
    bpf_printk("Warning: size %d exceeds MYSQL_ERRMSG_SIZE, truncating\n",
               size);
    size = MYSQL_ERRMSG_SIZE;
  }
  bpf_printk("size %d", size);

  struct data_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return;

  e->saddr = saddr;
  e->daddr = daddr;
  e->sport = sport;
  e->dport = dport;
  e->size = size;
  bpf_probe_read_user(e->msg, size, pack);
  bpf_ringbuf_submit(e, 0);
}

// Return 1 if the buffer contains 0xFF, else 0
static __always_inline int contains_ff(const unsigned char *data) {
  for (int i = 0; i < sizeof(data); i++) {
    if (data[i] == 0xff)
      return 1;
  }
  return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  struct data_t data = {};
  struct iov_iter iter = {};
  const struct iovec *iovp = NULL;
  unsigned char mysql_err_buf_check[ERR_BUF_SIZE];

  // Read socket info (CO-RE safe)
  data.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  data.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  if (data.sport != PORT_FILTER)
    return 0;

  data.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data.size = size;

  // Read the iov_iter structure from msg->msg_iter
  bpf_core_read(&iter, sizeof(iter), &msg->msg_iter);
  // Try to read __iov pointer inside iov_iter
  bpf_core_read(&iovp, sizeof(*iovp), &iter.__iov);
  if (!iovp)
    return 0;

  bpf_probe_read_user(mysql_err_buf_check, sizeof(mysql_err_buf_check), iovp);
  if (contains_ff(mysql_err_buf_check)) {
    send_mysql_event(data.saddr, data.daddr, data.sport, data.dport, iovp,
                     data.size);
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
